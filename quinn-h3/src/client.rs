use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use futures::{try_ready, Async, Future, Poll, Stream};
use http::Request;
use quinn::{
    Endpoint, EndpointBuilder, EndpointDriver, EndpointError, OpenBi, RecvStream, SendStream,
};
use slog::{self, o, Logger};
use tokio::io::{self, Shutdown, WriteAll};

use crate::{
    connection::{ConnectionDriver, ConnectionRef},
    frame::FrameStream,
    proto::frame::{HeadersFrame, HttpFrame},
    Error, Settings,
};

pub struct ClientBuilder<'a> {
    endpoint: EndpointBuilder<'a>,
    log: Option<Logger>,
    settings: Settings,
}

impl<'a> ClientBuilder<'a> {
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
    ) -> Result<(EndpointDriver, Client), EndpointError> {
        let (endpoint_driver, endpoint, _) = self.endpoint.bind(addr)?;
        Ok((
            endpoint_driver,
            Client {
                endpoint,
                settings: self.settings,
                log: self.log.unwrap_or(Logger::root(slog::Discard, o!())),
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
    pub fn send_request(&self, request: Request<()>) -> SendRequest {
        SendRequest::new(request, self.0.quic.open_bi(), self.0.clone())
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
        let (driver, conn, incoming) = try_ready!(self.connecting.poll());
        let conn_ref = ConnectionRef::new(conn.clone(), self.settings.clone())?;
        Ok(Async::Ready((
            driver,
            ConnectionDriver::new(conn_ref.clone(), incoming, self.log.clone()),
            Connection(conn_ref),
        )))
    }
}

enum SendRequestState {
    Opening(OpenBi),
    Sending(WriteAll<SendStream, Vec<u8>>),
    Sent(Shutdown<SendStream>),
    Receiving(FrameStream<RecvStream>),
    Ready(HeadersFrame),
    Finished,
}

pub struct SendRequest {
    req: Request<()>,
    state: SendRequestState,
    conn: ConnectionRef,
    recv: Option<FrameStream<RecvStream>>,
}

impl SendRequest {
    fn new(req: Request<()>, open_bi: OpenBi, conn: ConnectionRef) -> Self {
        Self {
            req,
            conn,
            state: SendRequestState::Opening(open_bi),
            recv: None,
        }
    }
}

impl Future for SendRequest {
    type Item = RecvResponse;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendRequestState::Opening(ref mut o) => {
                    let (send, recv) = try_ready!(o.poll());
                    self.recv = Some(FrameStream::new(recv));

                    let header = {
                        let mut conn = self.conn.inner.lock().unwrap();
                        conn.encode_header(&send.id(), self.req.headers())?
                    };
                    let mut encoded_header = vec![];
                    header.encode(&mut encoded_header);

                    let send = io::write_all(send, encoded_header);
                    self.state = SendRequestState::Sending(send);
                }
                SendRequestState::Sending(ref mut send) => {
                    let (send, _) = try_ready!(send.poll());
                    let shut = io::shutdown(send);
                    self.state = SendRequestState::Sent(shut);
                }
                SendRequestState::Sent(ref mut shut) => {
                    try_ready!(shut.poll());
                    self.state = match mem::replace(&mut self.recv, None) {
                        Some(r) => SendRequestState::Receiving(r),
                        None => return Err(Error::Internal("Invalid receive state")),
                    }
                }
                SendRequestState::Receiving(ref mut frames) => match try_ready!(frames.poll()) {
                    None => return Err(Error::peer("recieved an empty response")),
                    Some(f) => match f {
                        HttpFrame::Headers(headers) => {
                            match mem::replace(&mut self.state, SendRequestState::Ready(headers)) {
                                SendRequestState::Receiving(frames) => self.recv = Some(frames),
                                _ => unreachable!(),
                            };
                        }
                        _ => return Err(Error::peer("first frame is not headers")),
                    },
                },
                SendRequestState::Ready(_) => {
                    match mem::replace(&mut self.state, SendRequestState::Finished) {
                        SendRequestState::Ready(h) => {
                            return Ok(Async::Ready(RecvResponse {
                                headers: h,
                                frames: mem::replace(&mut self.recv, None).unwrap(),
                            }))
                        }
                        _ => unreachable!(),
                    }
                }
                _ => self.state = SendRequestState::Finished,
            }
        }
    }
}

pub struct RecvResponse {
    headers: HeadersFrame,
    frames: FrameStream<RecvStream>,
}
