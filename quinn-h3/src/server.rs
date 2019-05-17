use std::mem;
use std::net::ToSocketAddrs;

use futures::task;
use futures::{try_ready, Async, Future, Poll, Stream};
use quinn::{EndpointBuilder, EndpointDriver, EndpointError, RecvStream, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};

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
                            return Ok(Async::Ready(RequestReady {
                                headers: decoded,
                                frame_stream,
                                send: Some(send),
                                conn: self.conn.clone(),
                            }));
                        }
                    }
                }
                RecvRequestState::Ready => return Err(Error::peer("polled after ready")),
            };
        }
    }
}

pub struct RequestReady {
    headers: Header,
    frame_stream: FrameStream<RecvStream>,
    send: Option<SendStream>,
    conn: ConnectionRef,
}

impl RequestReady {
    pub fn headers<'a>(&'a self) -> &'a Header {
        &self.headers
    }
}
