use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use futures::{try_ready, Async, Future, Poll, Stream};
use http::{request::Parts, Request, Response};
use quinn::{
    Endpoint, EndpointBuilder, EndpointDriver, EndpointError, OpenBi, RecvStream, SendStream,
};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio::io::{self, Shutdown, WriteAll};

use crate::{
    body::RecvBody,
    connection::{ConnectionDriver, ConnectionRef},
    frame::FrameStream,
    proto::{
        frame::{HeadersFrame, HttpFrame},
        headers::Header,
    },
    try_take, Error, Settings,
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
    pub fn send_request<T>(&self, request: Request<T>) -> SendRequest<T> {
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
    Decoding(HeadersFrame),
    Ready(Header),
    Finished,
}

pub struct SendRequest<T> {
    header: Option<Header>,
    body: T,
    state: SendRequestState,
    conn: ConnectionRef,
    stream_id: Option<StreamId>,
    recv: Option<FrameStream<RecvStream>>,
}

impl<T> SendRequest<T> {
    fn new(req: Request<T>, open_bi: OpenBi, conn: ConnectionRef) -> Self {
        let (
            Parts {
                method,
                uri,
                headers,
                ..
            },
            body,
        ) = req.into_parts();

        Self {
            body,
            conn,
            header: Some(Header::request(method, uri, headers)),
            state: SendRequestState::Opening(open_bi),
            stream_id: None,
            recv: None,
        }
    }
}

impl<T> Future for SendRequest<T> {
    type Item = RecvResponse;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendRequestState::Opening(ref mut o) => {
                    let (send, recv) = try_ready!(o.poll());
                    self.recv = Some(FrameStream::new(recv));
                    self.stream_id = Some(send.id());

                    let header_block = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        let header = try_take(&mut self.header, "header none")?;
                        conn.encode_header(&send.id(), header)?
                    };
                    let mut encoded_header = vec![];
                    header_block.encode(&mut encoded_header);

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
                    let recv = try_take(&mut self.recv, "Invalid receive state")?;
                    self.state = SendRequestState::Receiving(recv);
                }
                SendRequestState::Receiving(ref mut frames) => match try_ready!(frames.poll()) {
                    None => return Err(Error::peer("recieved an empty response")),
                    Some(f) => match f {
                        HttpFrame::Headers(headers) => {
                            match mem::replace(&mut self.state, SendRequestState::Decoding(headers))
                            {
                                SendRequestState::Receiving(frames) => self.recv = Some(frames),
                                _ => unreachable!(),
                            };
                        }
                        _ => return Err(Error::peer("first frame is not headers")),
                    },
                },
                SendRequestState::Decoding(ref mut frame) => {
                    let stream_id = self.stream_id.ok_or(Error::Internal("Stream id is none"))?;
                    let result = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        conn.decode_header(&stream_id, frame)
                    };

                    match result {
                        Ok(None) => return Ok(Async::NotReady),
                        Ok(Some(decoded)) => {
                            self.state = SendRequestState::Ready(decoded);
                        }
                        Err(e) => {
                            return Err(Error::peer(format!("decoding header failed: {:?}", e)))
                        }
                    }
                }
                SendRequestState::Ready(_) => {
                    match mem::replace(&mut self.state, SendRequestState::Finished) {
                        SendRequestState::Ready(h) => {
                            return Ok(Async::Ready(RecvResponse::build(
                                h,
                                try_take(&mut self.recv, "Recv is none")?,
                                try_take(&mut self.stream_id, "stream is none")?,
                                self.conn.clone(),
                            )?));
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
    response: Response<()>,
    recv: FrameStream<RecvStream>,
    stream_id: StreamId,
    conn: ConnectionRef,
}

impl RecvResponse {
    fn build(
        header: Header,
        recv: FrameStream<RecvStream>,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Result<Self, Error> {
        let (status, headers) = header.into_response_parts()?;
        let mut response = Response::builder();
        response.status(status);
        response.version(http::version::Version::HTTP_2); // TODO change once available
        *response
            .headers_mut()
            .ok_or(Error::peer("invalid response"))? = headers;

        Ok(Self {
            recv,
            conn,
            stream_id: stream_id,
            response: response
                .body(())
                .or(Err(Error::Internal("failed to build response")))?,
        })
    }

    pub fn response<'a>(&'a self) -> &'a Response<()> {
        &self.response
    }

    pub fn body(self) -> RecvBody {
        RecvBody::with_capacity(self.recv, 10240, 1024000, self.conn.clone(), self.stream_id)
    }
}
