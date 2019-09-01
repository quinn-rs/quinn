use std::mem;
use std::net::ToSocketAddrs;

use futures::{
    future::{Either, IntoFuture},
    task, try_ready, Async, Future, Poll, Stream,
};
use http::{response, HeaderMap, Request, Response};
use quinn::{EndpointBuilder, EndpointDriver, EndpointError, RecvStream, SendStream};
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
    ) -> Result<(EndpointDriver, Server, IncomingConnection), EndpointError> {
        let (endpoint_driver, _endpoint, incoming) = self.endpoint.bind(addr)?;
        Ok((
            endpoint_driver,
            Server,
            IncomingConnection {
                incoming,
                settings: self.settings.clone(),
                log: self
                    .log
                    .unwrap_or_else(|| Logger::root(slog::Discard, o!())),
            },
        ))
    }
}

pub struct Server;

pub struct IncomingConnection {
    log: Logger,
    incoming: quinn::Incoming,
    settings: Settings,
}

impl Stream for IncomingConnection {
    type Item = Connecting;
    type Error = ();
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(Async::Ready(match try_ready!(self.incoming.poll()) {
            None => None,
            Some(connecting) => Some(Connecting {
                connecting,
                log: self.log.clone(),
                settings: self.settings.clone(),
            }),
        }))
    }
}

pub struct Connecting {
    connecting: quinn::Connecting,
    log: Logger,
    settings: Settings,
}

impl Future for Connecting {
    type Item = (quinn::ConnectionDriver, ConnectionDriver, IncomingRequest);
    type Error = crate::Error;

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
            IncomingRequest(conn_ref),
        )))
    }
}

pub struct IncomingRequest(ConnectionRef);

impl Stream for IncomingRequest {
    type Item = RecvRequest;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (send, recv) = {
            let conn = &mut self.0.h3.lock().unwrap();
            match conn.requests.pop_front() {
                Some(s) => s,
                None => {
                    conn.requests_task = Some(task::current());
                    return Ok(Async::NotReady);
                }
            }
        };
        Ok(Async::Ready(Some(RecvRequest::new(
            recv,
            send,
            self.0.clone(),
        ))))
    }
}

enum RecvRequestState {
    Receiving(FrameStream, SendStream),
    Decoding(DecodeHeaders),
    Ready,
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

    fn build_request(
        &self,
        headers: Header,
        recv: FrameStream,
    ) -> Result<Request<RecvBody>, Error> {
        let (method, uri, headers) = headers.into_request_parts()?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(http::version::Version::HTTP_3)
            .body(RecvBody::new(recv, self.conn.clone(), self.stream_id))
            .unwrap();
        *request.headers_mut() = headers;
        Ok(request)
    }
}

impl Future for RecvRequest {
    type Item = (Request<RecvBody>, Sender);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                RecvRequestState::Receiving(ref mut frames, _) => match try_ready!(frames.poll()) {
                    None => return Err(Error::peer("received an empty request")),
                    Some(HttpFrame::Headers(f)) => {
                        let decode = DecodeHeaders::new(f, self.conn.clone(), self.stream_id);
                        match mem::replace(&mut self.state, RecvRequestState::Decoding(decode)) {
                            RecvRequestState::Receiving(f, s) => self.streams = Some((f, s)),
                            _ => unreachable!("Invalid state"),
                        }
                    }
                    Some(_) => return Err(Error::peer("first frame is not headers")),
                },
                RecvRequestState::Decoding(ref mut decode) => {
                    let header = try_ready!(decode.poll());
                    self.state = RecvRequestState::Ready;
                    let (recv, send) = try_take(&mut self.streams, "Recv request invalid state")?;
                    return Ok(Async::Ready((
                        self.build_request(header, recv)?,
                        Sender {
                            send,
                            stream_id: self.stream_id,
                            conn: self.conn.clone(),
                        },
                    )));
                }
                RecvRequestState::Ready => return Err(Error::peer("polled after ready")),
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
    pub fn response<T>(self, response: Response<T>) -> RespBuilder<T> {
        RespBuilder {
            response,
            sender: self,
            trailers: None,
        }
    }
}

pub struct RespBuilder<T> {
    sender: Sender,
    response: Response<T>,
    trailers: Option<HeaderMap>,
}

impl<T> RespBuilder<T>
where
    T: Into<Body>,
{
    pub fn trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }

    pub fn send(self) -> impl Future<Item = (), Error = Error> {
        let Sender {
            send,
            stream_id,
            conn,
        } = self.sender;
        match SendResponse::new(self.response, self.trailers, send, stream_id, conn) {
            Err(e) => Either::A(Err(e).into_future()),
            Ok(f) => Either::B(f),
        }
    }

    pub fn stream(self) -> impl Future<Item = BodyWriter, Error = Error> {
        let Sender {
            send,
            stream_id,
            conn,
        } = self.sender;

        let (
            response::Parts {
                status, headers, ..
            },
            body,
        ) = self.response.into_parts();

        let trailers = self.trailers;

        match SendHeaders::new(Header::response(status, headers), &conn, send, stream_id) {
            Err(e) => Either::A(Err(e).into_future()),
            Ok(f) => Either::B(f.and_then(move |send| {
                let writer = BodyWriter::new(send, conn, stream_id, trailers);
                match body.into() {
                    Body::Buf(b) => Either::A(
                        tokio_io::io::write_all(writer, b)
                            .map_err(Into::into)
                            .and_then(|(writer, _)| Ok(writer).into_future()),
                    ),
                    Body::None => Either::B(Ok(writer).into_future()),
                }
            })),
        }
    }
}

enum SendResponseState {
    SendingHeader(SendHeaders),
    SendingBody(SendBody),
    SendingTrailers(SendHeaders),
    Closing(Shutdown<SendStream>),
}

pub struct SendResponse {
    state: SendResponseState,
    body: Option<Body>,
    trailer: Option<Header>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl SendResponse {
    fn new<T: Into<Body>>(
        response: Response<T>,
        trailers: Option<HeaderMap>,
        send: SendStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Result<Self, Error> {
        let (
            response::Parts {
                status, headers, ..
            },
            body,
        ) = response.into_parts();

        let headers = Header::response(status, headers);
        let state =
            SendResponseState::SendingHeader(SendHeaders::new(headers, &conn, send, stream_id)?);

        Ok(Self {
            conn,
            state,
            stream_id,
            body: Some(body.into()),
            trailer: trailers.map(Header::trailer),
        })
    }
}

impl Future for SendResponse {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendResponseState::SendingHeader(ref mut write) => {
                    let send = try_ready!(write.poll());
                    mem::replace(
                        &mut self.state,
                        SendResponseState::SendingBody(SendBody::new(
                            send,
                            try_take(&mut self.body, "send body data")?,
                        )),
                    );
                }
                SendResponseState::SendingBody(ref mut body) => {
                    let send = try_ready!(body.poll());
                    let state = match self.trailer.take() {
                        None => SendResponseState::Closing(tokio_io::io::shutdown(send)),
                        Some(trailer) => SendResponseState::SendingTrailers(SendHeaders::new(
                            trailer,
                            &self.conn,
                            send,
                            self.stream_id,
                        )?),
                    };
                    mem::replace(&mut self.state, state);
                }
                SendResponseState::SendingTrailers(ref mut write) => {
                    let send = try_ready!(write.poll());
                    mem::replace(
                        &mut self.state,
                        SendResponseState::Closing(tokio_io::io::shutdown(send)),
                    );
                }
                SendResponseState::Closing(ref mut shut) => {
                    let _ = try_ready!(shut.poll());
                    return Ok(Async::Ready(()));
                }
            }
        }
    }
}
