use std::{
    future::Future,
    io, mem,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Stream};
use http::{response, Request, Response};
use quinn::{CertificateChain, EndpointBuilder, PrivateKey, RecvStream, SendStream};
use quinn_proto::{Side, StreamId};
use rustls::TLSError;

use crate::{
    body::{Body, BodyReader, BodyWriter},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HttpFrame},
        headers::Header,
        ErrorCode,
    },
    streams::Reset,
    try_take, Error, Settings,
};

pub struct Builder {
    config: quinn::ServerConfigBuilder,
    listen: Option<SocketAddr>,
    settings: Settings,
}

impl Default for Builder {
    fn default() -> Self {
        let mut config = quinn::ServerConfigBuilder::default();
        config.protocols(&[crate::ALPN]);

        Self {
            config,
            listen: None,
            settings: Settings::default(),
        }
    }
}

impl Builder {
    pub fn with_quic_config(mut config: quinn::ServerConfigBuilder) -> Self {
        config.protocols(&[crate::ALPN]);
        Self {
            config,
            listen: None,
            settings: Settings::default(),
        }
    }

    pub fn listen<S: ToSocketAddrs>(&mut self, socket: S) -> Result<&mut Self, io::Error> {
        self.listen = Some(
            socket
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no socket found"))?,
        );
        Ok(self)
    }

    pub fn certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<&mut Self, TLSError> {
        self.config.certificate(cert_chain, key)?;
        Ok(self)
    }

    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    pub fn endpoint(
        self,
        endpoint: EndpointBuilder,
    ) -> Result<(Server, IncomingConnection), quinn::EndpointError> {
        let listen = self
            .listen
            .unwrap_or_else(|| "[::]:4433".parse().expect("valid listen address"));
        let (_, incoming) = endpoint.bind(&listen)?;

        Ok((
            Server,
            IncomingConnection {
                incoming,
                settings: self.settings,
            },
        ))
    }

    pub fn build(self) -> Result<(Server, IncomingConnection), quinn::EndpointError> {
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.listen(self.config.build());

        let listen = self
            .listen
            .unwrap_or_else(|| "[::]:4433".parse().expect("valid listen address"));
        let (_, incoming) = endpoint_builder.bind(&listen)?;

        Ok((
            Server,
            IncomingConnection {
                incoming,
                settings: self.settings,
            },
        ))
    }
}

pub struct Server;

pub struct IncomingConnection {
    incoming: quinn::Incoming,
    settings: Settings,
}

impl Stream for IncomingConnection {
    type Item = Connecting;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(
            ready!(Pin::new(&mut self.incoming).poll_next(cx)).map(|c| Connecting {
                connecting: c,
                settings: self.settings.clone(),
            }),
        )
    }
}

pub struct Connecting {
    connecting: quinn::Connecting,
    settings: Settings,
}

impl Future for Connecting {
    type Output = Result<IncomingRequest, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let quinn::NewConnection {
            connection,
            bi_streams,
            uni_streams,
            ..
        } = ready!(Pin::new(&mut self.connecting).poll(cx))?;
        let conn_ref = ConnectionRef::new(
            connection,
            Side::Server,
            uni_streams,
            bi_streams,
            self.settings.clone(),
        )?;
        tokio::spawn(ConnectionDriver(conn_ref.clone()));
        Poll::Ready(Ok(IncomingRequest(conn_ref)))
    }
}

pub struct IncomingRequest(ConnectionRef);

impl Stream for IncomingRequest {
    type Item = RecvRequest;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.0.h3.lock().unwrap().next_request(cx) {
            Some((s, r)) => Poll::Ready(Some(RecvRequest::new(r, s, self.0.clone()))),
            None => Poll::Pending
        }
    }
}

enum RecvRequestState {
    Receiving(FrameStream, SendStream),
    Decoding(DecodeHeaders),
    Finished,
}

pub struct RecvRequest {
    state: RecvRequestState,
    conn: ConnectionRef,
    stream_id: StreamId,
    streams: Option<(FrameStream, SendStream)>,
}

impl RecvRequest {
    fn new(recv: RecvStream, send: SendStream, conn: ConnectionRef) -> Self {
        Self {
            conn,
            stream_id: send.id(),
            streams: None,
            state: RecvRequestState::Receiving(FrameDecoder::stream(recv), send),
        }
    }

    fn build_request(&self, headers: Header) -> Result<Request<()>, Error> {
        let (method, uri, headers) = headers.into_request_parts()?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(http::version::Version::HTTP_3)
            .body(())
            .unwrap();
        *request.headers_mut() = headers;
        Ok(request)
    }

    pub fn reject(mut self) {
        let state = mem::replace(&mut self.state, RecvRequestState::Finished);
        if let RecvRequestState::Receiving(recv, mut send) = state {
            recv.reset(ErrorCode::REQUEST_REJECTED);
            send.reset(ErrorCode::REQUEST_REJECTED.into());
        }
    }
}

impl Future for RecvRequest {
    type Output = Result<(Request<()>, BodyReader, Sender), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                RecvRequestState::Receiving(ref mut frames, _) => {
                    match ready!(Pin::new(frames).poll_next(cx)) {
                        None => return Poll::Ready(Err(Error::peer("received an empty request"))),
                        Some(Ok(HttpFrame::Reserved)) => (),
                        Some(Ok(HttpFrame::Headers(f))) => {
                            let decode = DecodeHeaders::new(f, self.conn.clone(), self.stream_id);
                            match mem::replace(&mut self.state, RecvRequestState::Decoding(decode))
                            {
                                RecvRequestState::Receiving(f, s) => self.streams = Some((f, s)),
                                _ => unreachable!("Invalid state"),
                            }
                        }
                        Some(x) => {
                            let (code, error) = match x {
                                Err(e) => (e.code(), e.into()),
                                Ok(_) => (
                                    ErrorCode::FRAME_UNEXPECTED,
                                    Error::peer("first frame is not headers"),
                                ),
                            };
                            match mem::replace(&mut self.state, RecvRequestState::Finished) {
                                RecvRequestState::Receiving(recv, _) => recv.reset(code),
                                _ => unreachable!(),
                            }
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                RecvRequestState::Decoding(ref mut decode) => {
                    let header = ready!(Pin::new(decode).poll(cx))?;
                    self.state = RecvRequestState::Finished;
                    let (recv, send) = try_take(&mut self.streams, "Recv request invalid state")?;
                    return Poll::Ready(Ok((
                        self.build_request(header)?,
                        BodyReader::new(recv, self.conn.clone(), self.stream_id, false),
                        Sender {
                            send,
                            stream_id: self.stream_id,
                            conn: self.conn.clone(),
                        },
                    )));
                }
                RecvRequestState::Finished => {
                    return Poll::Ready(Err(Error::peer("polled after ready")));
                }
            };
        }
    }
}

pub struct Sender {
    send: SendStream,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl Sender {
    pub async fn send_response<T: Into<Body>>(
        self,
        response: Response<T>,
    ) -> Result<BodyWriter, Error> {
        let (
            response::Parts {
                status, headers, ..
            },
            body,
        ) = response.into_parts();

        let send = SendHeaders::new(
            Header::response(status, headers),
            &self.conn,
            self.send,
            self.stream_id,
        )?
        .await?;
        let send = match body.into() {
            Body::None => send,
            Body::Buf(payload) => WriteFrame::new(send, DataFrame { payload }).await?,
        };
        Ok(BodyWriter::new(send, self.conn, self.stream_id, true))
    }

    pub fn cancel(mut self) {
        self.send.reset(ErrorCode::REQUEST_REJECTED.into());
    }
}
