use std::mem;
use std::net::ToSocketAddrs;

use futures::task;
use futures::{try_ready, Async, Future, Poll, Stream};
use http::{response, HeaderMap, Request, Response};
use quinn::{EndpointBuilder, EndpointDriver, EndpointError, RecvStream, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio_io::io::{Shutdown, WriteAll};

use crate::{
    body::{Body, RecvBody, SendBody},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream},
    headers::DecodeHeaders,
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

    fn build_request(headers: Header) -> Result<Request<()>, Error> {
        let (method, uri, headers) = headers.into_request_parts()?;
        let mut request = Request::builder();
        request.method(method);
        request.uri(uri);
        request.version(http::version::Version::HTTP_3);
        match request.headers_mut() {
            Some(h) => *h = headers,
            None => return Err(Error::peer("invalid header")),
        }

        Ok(request
            .body(())
            .map_err(|e| Error::Peer(format!("invalid request: {:?}", e)))?)
    }
}

impl Future for RecvRequest {
    type Item = (Request<()>, RecvBody, Sender);
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
                        Self::build_request(header)?,
                        Receiver::new(recv, self.conn.clone(), self.stream_id),
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
            trailer: trailers.map(Header::trailer),
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
                        conn.encode_header(self.stream_id, header)?
                    };

                    let mut encoded = Vec::new();
                    block.encode(&mut encoded);

                    let send = try_take(&mut self.send, "polled after finished")?;
                    mem::replace(
                        &mut self.state,
                        SendResponseState::SendingHeader(tokio_io::io::write_all(send, encoded)),
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
                        None => SendResponseState::Closing(tokio_io::io::shutdown(send)),
                        Some(trailer) => {
                            let block = {
                                let conn = &mut self.conn.h3.lock().unwrap().inner;
                                conn.encode_header(self.stream_id, trailer)?
                            };

                            let mut encoded = Vec::new();
                            block.encode(&mut encoded);

                            SendResponseState::SendingTrailers(tokio_io::io::write_all(
                                send, encoded,
                            ))
                        }
                    };
                    mem::replace(&mut self.state, state);
                }
                SendResponseState::SendingTrailers(ref mut write) => {
                    let (send, _) = try_ready!(write.poll());
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
