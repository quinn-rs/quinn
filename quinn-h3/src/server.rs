use std::mem;
use std::net::ToSocketAddrs;

use futures::task;
use futures::{try_ready, Async, Future, Poll, Stream};
use http::{response, Request, Response};
use quinn::{EndpointBuilder, EndpointDriver, EndpointError, RecvStream, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio::io::{Shutdown, WriteAll};

use crate::{
    connection::{ConnectionDriver, ConnectionRef},
    frame::FrameStream,
    proto::{
        frame::{HeadersFrame, HttpFrame},
        headers::Header,
    },
    Error, Settings,
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
                            let (frame_stream, send) = match mem::replace(&mut self.streams, None) {
                                Some(x) => x,
                                None => return Err(Error::Internal("Recv request invalid state")),
                            };
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

    pub fn send_response(self, response: Response<()>) -> SendResponse {
        SendResponse::new(response, self.send, self.stream_id, self.conn)
    }
}

enum SendResponseState {
    Encoding(StreamId),
    Sending(WriteAll<SendStream, Vec<u8>>),
    Closing(Shutdown<SendStream>),
}

pub struct SendResponse {
    state: SendResponseState,
    header: Option<Header>,
    send: Option<SendStream>,
    conn: ConnectionRef,
}

impl SendResponse {
    fn new(
        response: Response<()>,
        send: SendStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Self {
        let (
            response::Parts {
                status, headers, ..
            },
            _body,
        ) = response.into_parts();

        Self {
            conn,
            send: Some(send),
            header: Some(Header::response(status, headers)),
            state: SendResponseState::Encoding(stream_id),
        }
    }
}

impl Future for SendResponse {
    type Item = ();
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendResponseState::Encoding(ref id) => {
                    let header = self
                        .header
                        .take()
                        .ok_or(Error::Internal("polled after finished"))?;

                    let block = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        conn.encode_header(id, header)?
                    };

                    let mut encoded = Vec::new();
                    block.encode(&mut encoded);

                    let send = self
                        .send
                        .take()
                        .ok_or(Error::Internal("polled after finished"))?;

                    mem::replace(
                        &mut self.state,
                        SendResponseState::Sending(tokio::io::write_all(send, encoded)),
                    );
                }
                SendResponseState::Sending(ref mut write) => {
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
