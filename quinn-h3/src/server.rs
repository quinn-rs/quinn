use std::mem;
use std::net::ToSocketAddrs;

use bytes::Bytes;
use futures::task;
use futures::{try_ready, Async, Future, Poll, Stream};
use http::{response, HeaderMap, Request, Response};
use quinn::{EndpointBuilder, EndpointDriver, EndpointError, RecvStream, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio::io::{Shutdown, WriteAll};

use crate::{
    body::{Body, RecvBody, SendBody},
    connection::{ConnectionDriver, ConnectionRef},
    frame::FrameStream,
    proto::{
        frame::{HeadersFrame, HttpFrame},
        headers::Header,
    },
    try_take, Error, Settings,
};

pub struct ServerBuilder<'a> {
    endpoint: EndpointBuilder<'a>,
    log: Option<Logger>,
    settings: Settings,
}

impl<'a> ServerBuilder<'a> {
    pub fn new(endpoint: EndpointBuilder<'a>) -> Self {
        Self {
            endpoint: endpoint,
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
                log: self.log.unwrap_or(Logger::root(slog::Discard, o!())),
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
        let (driver, conn, incoming) = try_ready!(self.connecting.poll());
        let conn_ref = ConnectionRef::new(conn.clone(), self.settings.clone())?;
        Ok(Async::Ready((
            driver,
            ConnectionDriver::new(conn_ref.clone(), incoming, self.log.clone()),
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
        return Ok(Async::Ready(Some(RecvRequest::new(
            recv,
            send,
            self.0.clone(),
        ))));
    }
}

enum RecvRequestState {
    Receiving(FrameStream<RecvStream>, SendStream),
    Decoding(HeadersFrame),
    Ready,
}

pub struct RecvRequest {
    state: RecvRequestState,
    conn: ConnectionRef,
    stream_id: StreamId,
    streams: Option<(FrameStream<RecvStream>, SendStream)>,
}

impl RecvRequest {
    fn new(recv: RecvStream, send: SendStream, conn: ConnectionRef) -> Self {
        Self {
            conn,
            stream_id: send.id(),
            streams: None,
            state: RecvRequestState::Receiving(FrameStream::new(recv), send),
        }
    }
}

impl Future for RecvRequest {
    type Item = RequestReady;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                RecvRequestState::Receiving(ref mut frames, _) => match try_ready!(frames.poll()) {
                    None => return Err(Error::peer("recieved an empty request")),
                    Some(HttpFrame::Headers(f)) => {
                        match mem::replace(&mut self.state, RecvRequestState::Decoding(f)) {
                            RecvRequestState::Receiving(f, s) => self.streams = Some((f, s)),
                            _ => unreachable!("Invalid state"),
                        }
                    }
                    Some(_) => return Err(Error::peer("first frame is not headers")),
                },
                RecvRequestState::Decoding(ref mut frame) => {
                    let result = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        conn.decode_header(&self.stream_id, frame)
                    };

                    match result {
                        Ok(None) => return Ok(Async::NotReady),
                        Err(e) => {
                            return Err(Error::peer(format!("decoding header failed: {:?}", e)))
                        }
                        Ok(Some(decoded)) => {
                            self.state = RecvRequestState::Ready;
                            let (frame_stream, send) =
                                try_take(&mut self.streams, "Recv request invalid state")?;
                            return Ok(Async::Ready(RequestReady::build(
                                decoded,
                                frame_stream,
                                send,
                                self.stream_id,
                                self.conn.clone(),
                            )?));
                        }
                    }
                }
                RecvRequestState::Ready => return Err(Error::peer("polled after ready")),
            };
        }
    }
}

pub struct RequestReady {
    request: Request<()>,
    frame_stream: FrameStream<RecvStream>,
    send: SendStream,
    stream_id: StreamId,
    conn: ConnectionRef,
}

impl RequestReady {
    fn build(
        headers: Header,
        frame_stream: FrameStream<RecvStream>,
        send: SendStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Result<Self, Error> {
        let (method, uri, headers) = headers.into_request_parts()?;
        let mut request = Request::builder();
        request.method(method);
        request.uri(uri);
        request.version(http::version::Version::HTTP_2); // TODO change once available
        match request.headers_mut() {
            Some(h) => *h = headers,
            None => return Err(Error::peer("invalid header")),
        }

        let request = request
            .body(())
            .map_err(|e| Error::Peer(format!("invalid request: {:?}", e)))?;

        Ok(Self {
            request,
            frame_stream,
            conn,
            stream_id,
            send,
        })
    }

    pub fn request<'a>(&'a self) -> &'a Request<()> {
        &self.request
    }

    pub fn body(self) -> RecvBodyServer {
        RecvBodyServer::new(
            self.send,
            self.frame_stream,
            self.conn.clone(),
            self.stream_id,
        )
    }

    pub fn send_response<T: Into<Body>>(self, response: Response<T>) -> SendResponse {
        SendResponse::new(response, self.send, self.stream_id, self.conn)
    }

    pub fn send_response_trailers<T: Into<Body>>(
        self,
        response: Response<T>,
        trailer: HeaderMap,
    ) -> SendResponse {
        SendResponse::with_trailers(
            response,
            Some(trailer),
            self.send,
            self.stream_id,
            self.conn,
        )
    }
}

pub struct RecvBodyServer {
    body: RecvBody,
    send: Option<SendStream>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBodyServer {
    pub(crate) fn new(
        send: SendStream,
        recv: FrameStream<RecvStream>,
        conn: ConnectionRef,
        stream_id: StreamId,
    ) -> Self {
        Self {
            stream_id,
            conn: conn.clone(),
            send: Some(send),
            body: RecvBody::with_capacity(recv, 10240, 1024000, conn, stream_id),
        }
    }
}

impl Future for RecvBodyServer {
    type Item = ReadyBody;
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (body, trailers) = try_ready!(self.body.poll());
        Ok(Async::Ready(ReadyBody {
            trailers,
            body: Some(body),
            send: try_take(&mut self.send, "send none")?,
            conn: self.conn.clone(),
            stream_id: self.stream_id,
        }))
    }
}

pub struct ReadyBody {
    send: SendStream,
    body: Option<Bytes>,
    trailers: Option<HeaderMap>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl ReadyBody {
    pub fn take_body(&mut self) -> Option<Bytes> {
        self.body.take()
    }

    pub fn send_response<T: Into<Body>>(self, response: Response<T>) -> SendResponse {
        SendResponse::new(response, self.send, self.stream_id, self.conn)
    }

    pub fn send_response_trailers<T: Into<Body>>(
        self,
        response: Response<T>,
        trailer: HeaderMap,
    ) -> SendResponse {
        SendResponse::with_trailers(
            response,
            Some(trailer),
            self.send,
            self.stream_id,
            self.conn,
        )
    }
}

enum SendResponseState {
    Encoding,
    SendingHeader(WriteAll<SendStream, Vec<u8>>),
    SendingBody(SendBody),
    SendingTrailers(WriteAll<SendStream, Vec<u8>>),
    Closing(Shutdown<SendStream>),
}

pub struct SendResponse {
    state: SendResponseState,
    header: Option<Header>,
    body: Option<Body>,
    trailer: Option<Header>,
    send: Option<SendStream>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl SendResponse {
    fn new<T: Into<Body>>(
        response: Response<T>,
        send: SendStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Self {
        Self::with_trailers(response, None, send, stream_id, conn)
    }

    fn with_trailers<T: Into<Body>>(
        response: Response<T>,
        trailers: Option<HeaderMap>,
        send: SendStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Self {
        let (
            response::Parts {
                status, headers, ..
            },
            body,
        ) = response.into_parts();

        Self {
            conn,
            stream_id,
            body: Some(body.into()),
            send: Some(send),
            trailer: trailers.map(|t| Header::trailer(t)),
            header: Some(Header::response(status, headers)),
            state: SendResponseState::Encoding,
        }
    }
}

impl Future for SendResponse {
    type Item = ();
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendResponseState::Encoding => {
                    let header = try_take(&mut self.header, "polled after finished")?;
                    let block = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        conn.encode_header(&self.stream_id, header)?
                    };

                    let mut encoded = Vec::new();
                    block.encode(&mut encoded);

                    let send = try_take(&mut self.send, "polled after finished")?;
                    mem::replace(
                        &mut self.state,
                        SendResponseState::SendingHeader(tokio::io::write_all(send, encoded)),
                    );
                }
                SendResponseState::SendingHeader(ref mut write) => {
                    let (send, _) = try_ready!(write.poll());
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
                        None => SendResponseState::Closing(tokio::io::shutdown(send)),
                        Some(trailer) => {
                            let block = {
                                let conn = &mut self.conn.h3.lock().unwrap().inner;
                                conn.encode_header(&self.stream_id, trailer)?
                            };

                            let mut encoded = Vec::new();
                            block.encode(&mut encoded);

                            SendResponseState::SendingTrailers(tokio::io::write_all(send, encoded))
                        }
                    };
                    mem::replace(&mut self.state, state);
                }
                SendResponseState::SendingTrailers(ref mut write) => {
                    let (send, _) = try_ready!(write.poll());
                    mem::replace(
                        &mut self.state,
                        SendResponseState::Closing(tokio::io::shutdown(send)),
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
