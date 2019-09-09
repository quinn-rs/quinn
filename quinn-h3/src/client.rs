use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use futures::{
    future::{Either, IntoFuture},
    try_ready, Async, Future, Poll, Stream,
};
use http::{request, HeaderMap, Request, Response};
use quinn::{Endpoint, EndpointBuilder, EndpointDriver, EndpointError, OpenBi, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio_io::io::Shutdown;

use crate::{
    body::{Body, BodyWriter, RecvBody, SendBody},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream},
    headers::{DecodeHeaders, SendHeaders},
    proto::{frame::HttpFrame, headers::Header},
    try_take, Error, Settings,
};

#[derive(Clone, Debug, Default)]
pub struct Builder {
    endpoint: EndpointBuilder,
    log: Option<Logger>,
    settings: Settings,
}

impl Builder {
    pub fn new(endpoint: EndpointBuilder) -> Self {
        Self {
            endpoint,
            log: None,
            settings: Settings::default(),
        }
    }

    pub fn logger(&mut self, log: Logger) -> &mut Self {
        self.log = Some(log);
        self
    }

    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    pub fn bind<T: ToSocketAddrs>(
        self,
        addr: T,
    ) -> Result<(EndpointDriver, Client), EndpointError> {
        let (endpoint_driver, endpoint, _) = self.endpoint.bind(addr)?;
        Ok((
            endpoint_driver,
            Client {
                endpoint,
                settings: self.settings,
                log: self
                    .log
                    .unwrap_or_else(|| Logger::root(slog::Discard, o!())),
            },
        ))
    }
}

pub struct Client {
    endpoint: Endpoint,
    log: Logger,
    settings: Settings,
}

impl Client {
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            log: self.log.clone(),
            settings: self.settings.clone(),
            connecting: self.endpoint.connect(addr, server_name)?,
        })
    }
}

pub struct Connection(ConnectionRef);

impl Connection {
    pub fn request<T: Into<Body>>(&self, request: Request<T>) -> RequestBuilder<T> {
        RequestBuilder {
            request,
            trailers: None,
            conn: self.0.clone(),
        }
    }

    pub fn close(self, error_code: u32, reason: &[u8]) {
        self.0.quic.close(error_code.into(), reason);
    }
}

pub struct Connecting {
    connecting: quinn::Connecting,
    log: Logger,
    settings: Settings,
}

impl Future for Connecting {
    type Item = (quinn::ConnectionDriver, ConnectionDriver, Connection);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let quinn::NewConnection {
            driver,
            connection,
            streams,
            ..
        } = try_ready!(self.connecting.poll());
        let conn_ref = ConnectionRef::new(connection, self.settings.clone())?;
        Ok(Async::Ready((
            driver,
            ConnectionDriver::new(conn_ref.clone(), streams, self.log.clone()),
            Connection(conn_ref),
        )))
    }
}

pub struct RequestBuilder<T> {
    conn: ConnectionRef,
    request: Request<T>,
    trailers: Option<HeaderMap>,
}

impl<T> RequestBuilder<T>
where
    T: Into<Body>,
{
    pub fn trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }

    pub fn send(self) -> SendRequest {
        SendRequest::new(
            self.request,
            self.trailers,
            self.conn.quic.open_bi(),
            self.conn,
        )
    }

    pub fn stream(self) -> impl Future<Item = (BodyWriter, RecvResponse), Error = Error> {
        let (
            request::Parts {
                method,
                uri,
                headers,
                ..
            },
            body,
        ) = self.request.into_parts();

        let (conn, trailers) = (self.conn, self.trailers);

        conn.quic
            .open_bi()
            .map_err(Into::into)
            .and_then(move |(send, recv)| {
                let stream_id = send.id();
                let send_headers = SendHeaders::new(
                    Header::request(method, uri, headers),
                    &conn,
                    send,
                    stream_id,
                );
                match send_headers {
                    Err(e) => Either::A(Err(e).into_future()),
                    Ok(f) => Either::B(f.and_then(move |send| {
                        let writer = BodyWriter::new(send, conn.clone(), stream_id, trailers);
                        let recv = RecvResponse::new(FrameDecoder::stream(recv), conn, stream_id);
                        match body.into() {
                            Body::Buf(b) => Either::A(
                                tokio_io::io::write_all(writer, b)
                                    .map_err(Into::into)
                                    .and_then(move |(writer, _)| Ok((writer, recv)).into_future()),
                            ),
                            Body::None => Either::B(Ok((writer, recv)).into_future()),
                        }
                    })),
                }
            })
    }
}

enum SendRequestState {
    Opening(OpenBi),
    Sending(SendHeaders),
    SendingBody(SendBody),
    SendingTrailers(SendHeaders),
    Sent(Shutdown<SendStream>),
    Receiving(FrameStream),
    Decoding(DecodeHeaders),
    Ready(Header),
    Finished,
}

pub struct SendRequest {
    header: Option<Header>,
    body: Option<Body>,
    trailers: Option<Header>,
    state: SendRequestState,
    conn: ConnectionRef,
    stream_id: Option<StreamId>,
    recv: Option<FrameStream>,
}

impl SendRequest {
    fn new<T: Into<Body>>(
        req: Request<T>,
        trailers: Option<HeaderMap>,
        open_bi: OpenBi,
        conn: ConnectionRef,
    ) -> Self {
        let (
            request::Parts {
                method,
                uri,
                headers,
                ..
            },
            body,
        ) = req.into_parts();

        Self {
            conn,
            header: Some(Header::request(method, uri, headers)),
            body: Some(body.into()),
            trailers: trailers.map(Header::trailer),
            state: SendRequestState::Opening(open_bi),
            stream_id: None,
            recv: None,
        }
    }

    fn build_response(&mut self, header: Header) -> Result<Response<RecvBody>, Error> {
        build_response(
            header,
            self.conn.clone(),
            try_take(&mut self.recv, "recv is none")?,
            try_take(&mut self.stream_id, "stream is none")?,
        )
    }
}

impl Future for SendRequest {
    type Item = Response<RecvBody>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendRequestState::Opening(ref mut o) => {
                    let (send, recv) = try_ready!(o.poll());
                    self.recv = Some(FrameDecoder::stream(recv));
                    self.stream_id = Some(send.id());
                    self.state = SendRequestState::Sending(SendHeaders::new(
                        try_take(&mut self.header, "header none")?,
                        &self.conn,
                        send,
                        self.stream_id.unwrap(),
                    )?);
                }
                SendRequestState::Sending(ref mut send) => {
                    let send = try_ready!(send.poll());
                    self.state = match self.body.take() {
                        None => SendRequestState::Sent(tokio_io::io::shutdown(send)),
                        Some(b) => SendRequestState::SendingBody(SendBody::new(send, b)),
                    };
                }
                SendRequestState::SendingBody(ref mut send_body) => {
                    let send = try_ready!(send_body.poll());
                    self.state = match self.trailers.take() {
                        None => SendRequestState::Sent(tokio_io::io::shutdown(send)),
                        Some(t) => SendRequestState::SendingTrailers(SendHeaders::new(
                            t,
                            &self.conn,
                            send,
                            self.stream_id.unwrap(),
                        )?),
                    }
                }
                SendRequestState::SendingTrailers(ref mut send_trailers) => {
                    let send = try_ready!(send_trailers.poll());
                    self.state = SendRequestState::Sent(tokio_io::io::shutdown(send));
                }
                SendRequestState::Sent(ref mut shut) => {
                    try_ready!(shut.poll());
                    let recv = try_take(&mut self.recv, "Invalid receive state")?;
                    self.state = SendRequestState::Receiving(recv);
                }
                SendRequestState::Receiving(ref mut frames) => match try_ready!(frames.poll()) {
                    None => return Err(Error::peer("received an empty response")),
                    Some(f) => match f {
                        HttpFrame::Headers(h) => {
                            let stream_id =
                                self.stream_id.ok_or(Error::Internal("Stream id is none"))?;
                            let decode = DecodeHeaders::new(h, self.conn.clone(), stream_id);
                            match mem::replace(&mut self.state, SendRequestState::Decoding(decode))
                            {
                                SendRequestState::Receiving(frames) => self.recv = Some(frames),
                                _ => unreachable!(),
                            };
                        }
                        _ => return Err(Error::peer("first frame is not headers")),
                    },
                },
                SendRequestState::Decoding(ref mut decode) => {
                    let header = try_ready!(decode.poll());
                    self.state = SendRequestState::Ready(header);
                }
                SendRequestState::Ready(_) => {
                    match mem::replace(&mut self.state, SendRequestState::Finished) {
                        SendRequestState::Ready(h) => {
                            return Ok(Async::Ready(self.build_response(h)?));
                        }
                        _ => unreachable!(),
                    }
                }
                _ => return Err(Error::Poll),
            }
        }
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
}

impl Future for RecvResponse {
    type Item = Response<RecvBody>;
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.state {
            RecvResponseState::Finished => {
                Err(crate::Error::Internal("recv response polled after finish"))
            }
            RecvResponseState::Receiving(ref mut recv) => match try_ready!(recv.poll()) {
                None => return Err(Error::peer("received an empty response")),
                Some(f) => match f {
                    HttpFrame::Headers(h) => {
                        let decode = DecodeHeaders::new(h, self.conn.clone(), self.stream_id);
                        self.recv = match mem::replace(
                            &mut self.state,
                            RecvResponseState::Decoding(decode),
                        ) {
                            RecvResponseState::Receiving(r) => Some(r),
                            _ => unreachable!(),
                        };
                        Ok(Async::NotReady)
                    }
                    _ => return Err(Error::peer("first frame is not headers")),
                },
            },
            RecvResponseState::Decoding(ref mut decode) => {
                let headers = try_ready!(decode.poll());
                let response = build_response(
                    headers,
                    self.conn.clone(),
                    self.recv.take().unwrap(),
                    self.stream_id,
                );
                match response {
                    Err(e) => Err(e).into(),
                    Ok(r) => {
                        self.state = RecvResponseState::Finished;
                        Ok(Async::Ready(r))
                    }
                }
            }
        }
    }
}

fn build_response(
    header: Header,
    conn: ConnectionRef,
    recv: FrameStream,
    stream_id: StreamId,
) -> Result<Response<RecvBody>, Error> {
    let (status, headers) = header.into_response_parts()?;
    let mut response = Response::builder()
        .status(status)
        .version(http::version::Version::HTTP_3)
        .body(RecvBody::new(recv, conn, stream_id))
        .unwrap();
    *response.headers_mut() = headers;
    Ok(response)
}
