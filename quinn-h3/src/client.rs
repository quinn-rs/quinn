use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use futures::{try_ready, Async, Future, Poll, Stream};
use http::{request::Parts, HeaderMap, Request, Response};
use quinn::{Endpoint, EndpointBuilder, EndpointDriver, EndpointError, OpenBi, SendStream};
use quinn_proto::StreamId;
use slog::{self, o, Logger};
use tokio_io::io::{Shutdown, WriteAll};

use crate::{
    body::{Body, RecvBody, RecvBodyStream, SendBody},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream},
    headers::DecodeHeaders,
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
    pub fn send_request<T: Into<Body>>(&self, request: Request<T>) -> SendRequest {
        SendRequest::new(request, None, self.0.quic.open_bi(), self.0.clone())
    }

    pub fn send_request_trailers<T: Into<Body>>(
        &self,
        request: Request<T>,
        trailers: HeaderMap,
    ) -> SendRequest {
        SendRequest::new(
            request,
            Some(trailers),
            self.0.quic.open_bi(),
            self.0.clone(),
        )
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
    SendingBody(SendBody),
    SendingTrailers(WriteAll<SendStream, Vec<u8>>),
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
            Parts {
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
}

impl Future for SendRequest {
    type Item = RecvResponse;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendRequestState::Opening(ref mut o) => {
                    let (send, recv) = try_ready!(o.poll());
                    self.recv = Some(FrameDecoder::stream(recv));
                    self.stream_id = Some(send.id());

                    let header_block = {
                        let conn = &mut self.conn.h3.lock().unwrap().inner;
                        let header = try_take(&mut self.header, "header none")?;
                        conn.encode_header(send.id(), header)?
                    };
                    let mut encoded_header = vec![];
                    header_block.encode(&mut encoded_header);

                    let send = tokio_io::io::write_all(send, encoded_header);
                    self.state = SendRequestState::Sending(send);
                }
                SendRequestState::Sending(ref mut send) => {
                    let (send, _) = try_ready!(send.poll());
                    self.state = match self.body.take() {
                        None => SendRequestState::Sent(tokio_io::io::shutdown(send)),
                        Some(b) => SendRequestState::SendingBody(SendBody::new(send, b)),
                    };
                }
                SendRequestState::SendingBody(ref mut send_body) => {
                    let send = try_ready!(send_body.poll());
                    self.state = match self.trailers.take() {
                        None => SendRequestState::Sent(tokio_io::io::shutdown(send)),
                        Some(t) => {
                            let block = {
                                let conn = &mut self.conn.h3.lock().unwrap().inner;
                                conn.encode_header(send.id(), t)?
                            };
                            let mut encoded_header = vec![];
                            block.encode(&mut encoded_header);
                            let write = tokio_io::io::write_all(send, encoded_header);
                            SendRequestState::SendingTrailers(write)
                        }
                    }
                }
                SendRequestState::SendingTrailers(ref mut send_trailers) => {
                    let (send, _) = try_ready!(send_trailers.poll());
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
    recv: FrameStream,
    stream_id: StreamId,
    conn: ConnectionRef,
}

impl RecvResponse {
    fn build(
        header: Header,
        recv: FrameStream,
        stream_id: StreamId,
        conn: ConnectionRef,
    ) -> Result<Self, Error> {
        let (status, headers) = header.into_response_parts()?;
        let mut response = Response::builder();
        response.status(status);
        response.version(http::version::Version::HTTP_3);
        *response
            .headers_mut()
            .ok_or_else(|| Error::peer("invalid response"))? = headers;

        Ok(Self {
            recv,
            conn,
            stream_id,
            response: response
                .body(())
                .or(Err(Error::Internal("failed to build response")))?,
        })
    }

    pub fn response<'a>(&'a self) -> &'a Response<()> {
        &self.response
    }

    pub fn body(self) -> RecvBody {
        RecvBody::with_capacity(
            self.recv,
            10_240,
            1_024_000,
            self.conn.clone(),
            self.stream_id,
        )
    }

    pub fn body_stream(self) -> RecvBodyStream {
        RecvBodyStream::new(self.recv, self.conn, self.stream_id)
    }
}
