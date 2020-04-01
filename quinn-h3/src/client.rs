use std::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Stream};
use http::{request, Request, Response};
use quinn::{Certificate, Endpoint};
use quinn_proto::{Side, StreamId};
use tracing::trace;

use crate::{
    body::{Body, BodyReader, BodyWriter},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HttpFrame},
        headers::Header,
        settings::Settings,
        ErrorCode,
    },
    streams::Reset,
    Error, ZeroRttAccepted,
};

#[derive(Clone)]
pub struct Builder {
    settings: Settings,
    client_config: quinn::ClientConfigBuilder,
}

impl Default for Builder {
    fn default() -> Self {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(&[crate::ALPN]);

        Self {
            client_config,
            settings: Settings::new(),
        }
    }
}

impl Builder {
    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    pub fn build(self) -> Result<Client, quinn::EndpointError> {
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.default_client_config(self.client_config.build());
        let (endpoint, _) = endpoint_builder.bind(&"[::]:0".parse().unwrap())?;

        Ok(Client {
            endpoint,
            settings: self.settings,
        })
    }

    pub fn add_certificate_authority(
        &mut self,
        cert: Certificate,
    ) -> Result<&mut Self, webpki::Error> {
        self.client_config.add_certificate_authority(cert)?;
        Ok(self)
    }

    pub fn with_quic_config(mut client_config: quinn::ClientConfigBuilder) -> Self {
        client_config.protocols(&[crate::ALPN]);
        Self {
            client_config,
            settings: Settings::new(),
        }
    }

    pub fn endpoint(self, endpoint: Endpoint) -> Client {
        Client {
            endpoint,
            settings: self.settings,
        }
    }
}

pub struct Client {
    endpoint: Endpoint,
    settings: Settings,
}

impl Client {
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            settings: self.settings.clone(),
            connecting: self.endpoint.connect(addr, server_name)?,
        })
    }

    pub fn connect_with(
        &self,
        client_config: quinn::ClientConfig,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            settings: self.settings.clone(),
            connecting: self
                .endpoint
                .connect_with(client_config, addr, server_name)?,
        })
    }
}

pub struct Connecting {
    connecting: quinn::Connecting,
    settings: Settings,
}

impl Connecting {
    pub fn into_0rtt(self) -> Result<(Connection, ZeroRttAccepted), Self> {
        let Self {
            connecting,
            settings,
        } = self;
        match connecting.into_0rtt() {
            Err(connecting) => Err(Self {
                connecting,
                settings,
            }),
            Ok((new_conn, zero_rtt)) => {
                let quinn::NewConnection {
                    connection,
                    uni_streams,
                    bi_streams,
                    ..
                } = new_conn;
                let conn_ref =
                    ConnectionRef::new(connection, Side::Client, uni_streams, bi_streams, settings);
                tokio::spawn(ConnectionDriver(conn_ref.clone()));
                Ok((Connection(conn_ref), zero_rtt))
            }
        }
    }
}

impl Future for Connecting {
    type Output = Result<Connection, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let quinn::NewConnection {
            connection,
            uni_streams,
            bi_streams,
            ..
        } = ready!(Pin::new(&mut self.connecting).poll(cx))?;
        let conn_ref = ConnectionRef::new(
            connection,
            Side::Client,
            uni_streams,
            bi_streams,
            self.settings.clone(),
        );
        tokio::spawn(ConnectionDriver(conn_ref.clone()));
        Poll::Ready(Ok(Connection(conn_ref)))
    }
}


pub struct Connection(ConnectionRef);

impl Connection {
    pub async fn send_request<T: Into<Body>>(
        &self,
        request: Request<T>,
    ) -> Result<(RecvResponse, BodyWriter), Error> {
        let (request, body) = request.into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            ..
        } = request;
        let (send, recv) = self.0.quic.open_bi().await?;

        if recv.is_0rtt() && !method.is_idempotent() {
            return Err(Error::internal("non-idempotent method tried on 0RTT"));
        }

        let stream_id = send.id();
        let send = SendHeaders::new(
            Header::request(method, uri, headers),
            &self.0,
            send,
            stream_id,
        )?
        .await?;

        let recv = RecvResponse::new(FrameDecoder::stream(recv), self.0.clone(), stream_id);
        match body.into() {
            Body::Buf(payload) => {
                let send = WriteFrame::new(send, DataFrame { payload }).await?;
                Ok((
                    recv,
                    BodyWriter::new(send, self.0.clone(), stream_id, false),
                ))
            }
            Body::None => Ok((
                recv,
                BodyWriter::new(send, self.0.clone(), stream_id, false),
            )),
        }
    }

    pub fn close(self) {
        trace!("connection closed by user");
        self.0
            .quic
            .close(ErrorCode::NO_ERROR.into(), b"Connection closed");
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.quic.force_key_update();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.0
            .quic
            .close(ErrorCode::NO_ERROR.into(), b"Connection closed");
    }
}
pub struct RecvResponse {
    state: RecvResponseState,
    conn: ConnectionRef,
    stream_id: StreamId,
    recv: Option<FrameStream>,
}

enum RecvResponseState {
    Receiving(FrameStream),
    Decoding(DecodeHeaders),
    Finished,
}

impl RecvResponse {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        Self {
            conn,
            stream_id,
            recv: None,
            state: RecvResponseState::Receiving(recv),
        }
    }

    pub fn cancel(mut self) {
        let recv = match mem::replace(&mut self.state, RecvResponseState::Finished) {
            RecvResponseState::Receiving(recv) => recv,
            RecvResponseState::Decoding(_) => self.recv.take().expect("cancel recv"),
            _ => return,
        };
        self.conn.h3.lock().unwrap().cancel_request(self.stream_id);
        recv.reset(ErrorCode::REQUEST_CANCELLED);
    }
}

impl Future for RecvResponse {
    type Output = Result<(Response<()>, BodyReader), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                RecvResponseState::Finished => {
                    return Poll::Ready(Err(crate::Error::internal(
                        "recv response polled after finish",
                    )))
                }
                RecvResponseState::Receiving(ref mut recv) => {
                    let frame = ready!(Pin::new(recv).poll_next(cx));

                    trace!("client got {:?}", frame);
                    match frame {
                        None => return Poll::Ready(Err(Error::peer("received an empty response"))),
                        Some(Err(e)) => return Poll::Ready(Err(e.into())),
                        Some(Ok(f)) => match f {
                            HttpFrame::Reserved => (),
                            HttpFrame::Headers(h) => {
                                let decode =
                                    DecodeHeaders::new(h, self.conn.clone(), self.stream_id);
                                match mem::replace(
                                    &mut self.state,
                                    RecvResponseState::Decoding(decode),
                                ) {
                                    RecvResponseState::Receiving(r) => self.recv = Some(r),
                                    _ => unreachable!(),
                                };
                            }
                            _ => {
                                match mem::replace(&mut self.state, RecvResponseState::Finished) {
                                    RecvResponseState::Receiving(recv) => {
                                        recv.reset(ErrorCode::FRAME_UNEXPECTED);
                                    }
                                    _ => unreachable!(),
                                }
                                return Poll::Ready(Err(Error::peer("first frame is not headers")));
                            }
                        },
                    }
                }
                RecvResponseState::Decoding(ref mut decode) => {
                    let headers = ready!(Pin::new(decode).poll(cx))?;
                    let response = build_response(headers);
                    match response {
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(r) => {
                            self.state = RecvResponseState::Finished;
                            return Poll::Ready(Ok((
                                r,
                                BodyReader::new(
                                    self.recv.take().unwrap(),
                                    self.conn.clone(),
                                    self.stream_id,
                                    true,
                                ),
                            )));
                        }
                    }
                }
            }
        }
    }
}

fn build_response(header: Header) -> Result<Response<()>, Error> {
    let (status, headers) = header.into_response_parts()?;
    let mut response = Response::builder()
        .status(status)
        .version(http::version::Version::HTTP_3)
        .body(())
        .unwrap();
    *response.headers_mut() = headers;
    Ok(response)
}

#[cfg(test)]
impl Connection {
    pub(crate) fn inner(&self) -> &ConnectionRef {
        &self.0
    }
}
