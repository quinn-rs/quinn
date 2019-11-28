use std::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Stream};
use http::{request, HeaderMap, Request, Response};
use quinn::{Endpoint, OpenBi};
use quinn_proto::{Side, StreamId};

use crate::{
    body::{Body, BodyWriter, RecvBody},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HttpFrame},
        headers::Header,
        ErrorCode,
    },
    streams::Reset,
    try_take, Error, Settings,
};

#[derive(Clone, Debug, Default)]
pub struct Builder {
    settings: Settings,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            settings: Settings::default(),
        }
    }

    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
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

    pub fn close(self) {
        self.0
            .quic
            .close(ErrorCode::NO_ERROR.into(), b"Connection closed");
    }
}

pub struct Connecting {
    connecting: quinn::Connecting,
    settings: Settings,
}

impl Future for Connecting {
    type Output = Result<(quinn::ConnectionDriver, ConnectionDriver, Connection), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let quinn::NewConnection {
            driver,
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
        )?;
        Poll::Ready(Ok((
            driver,
            ConnectionDriver(conn_ref.clone()),
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

    pub async fn stream(self) -> Result<(BodyWriter, RecvResponse), Error> {
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
        let (send, recv) = conn.quic.open_bi().await?;

        let stream_id = send.id();
        let send = SendHeaders::new(
            Header::request(method, uri, headers),
            &conn,
            send,
            stream_id,
        )?
        .await?;

        let recv = RecvResponse::new(FrameDecoder::stream(recv), conn.clone(), stream_id);
        match body.into() {
            Body::Buf(payload) => {
                let send = WriteFrame::new(send, DataFrame { payload }).await?;
                Ok((
                    BodyWriter::new(send, conn, stream_id, trailers, false),
                    recv,
                ))
            }
            Body::None => Ok((
                BodyWriter::new(send, conn.clone(), stream_id, trailers, false),
                recv,
            )),
        }
    }
}

enum SendRequestState {
    Opening(OpenBi),
    Sending(SendHeaders),
    SendingBody(WriteFrame),
    SendingTrailers(SendHeaders),
    Receiving(FrameStream),
    Decoding(DecodeHeaders),
    Aborted,
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
        if conn.h3.lock().unwrap().inner.is_closing() {
            return Self {
                conn,
                header: None,
                body: None,
                stream_id: None,
                recv: None,
                state: SendRequestState::Aborted,
                trailers: trailers.map(Header::trailer),
            };
        }

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

    pub fn cancel(mut self) {
        match self.state {
            SendRequestState::Sending(send) => {
                send.reset(ErrorCode::REQUEST_CANCELLED);
            }
            SendRequestState::SendingBody(write) => {
                write.reset(ErrorCode::REQUEST_CANCELLED);
            }
            SendRequestState::SendingTrailers(send) => {
                send.reset(ErrorCode::REQUEST_CANCELLED);
            }
            SendRequestState::Receiving(recv) => {
                recv.reset(ErrorCode::REQUEST_CANCELLED);
            }
            _ => (),
        }

        if let Some(recv) = self.recv.take() {
            recv.reset(ErrorCode::REQUEST_CANCELLED);
        }
    }
}

impl Future for SendRequest {
    type Output = Result<Response<RecvBody>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                SendRequestState::Aborted => return Poll::Ready(Err(Error::Aborted)),
                SendRequestState::Opening(ref mut o) => {
                    let (send, recv) = ready!(Pin::new(o).poll(cx))?;

                    self.conn
                        .h3
                        .lock()
                        .unwrap()
                        .inner
                        .request_initiated(send.id());

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
                    let send = ready!(Pin::new(send).poll(cx))?;
                    self.state = match self.body.take() {
                        Some(Body::Buf(payload)) => SendRequestState::SendingBody(WriteFrame::new(
                            send,
                            DataFrame { payload },
                        )),
                        _ => {
                            let recv = try_take(&mut self.recv, "Invalid receive state")?;
                            SendRequestState::Receiving(recv)
                        }
                    };
                }
                SendRequestState::SendingBody(ref mut send_body) => {
                    let send = ready!(Pin::new(send_body).poll(cx))?;
                    self.state = match self.trailers.take() {
                        None => {
                            let recv = try_take(&mut self.recv, "Invalid receive state")?;
                            SendRequestState::Receiving(recv)
                        }
                        Some(t) => SendRequestState::SendingTrailers(SendHeaders::new(
                            t,
                            &self.conn,
                            send,
                            self.stream_id
                                .ok_or_else(|| Error::internal("stream_id is none"))?,
                        )?),
                    }
                }
                SendRequestState::SendingTrailers(ref mut send_trailers) => {
                    let _ = ready!(Pin::new(send_trailers).poll(cx))?; // send dropped
                    let recv = try_take(&mut self.recv, "Invalid receive state")?;
                    self.state = SendRequestState::Receiving(recv);
                }
                SendRequestState::Receiving(ref mut frames) => {
                    match ready!(Pin::new(frames).poll_next(cx)) {
                        None => return Poll::Ready(Err(Error::peer("received an empty response"))),
                        Some(Err(e)) => return Poll::Ready(Err(e.into())),
                        Some(Ok(f)) => match f {
                            HttpFrame::Headers(h) => {
                                let stream_id =
                                    self.stream_id.ok_or(Error::internal("Stream id is none"))?;
                                let decode = DecodeHeaders::new(h, self.conn.clone(), stream_id);
                                if let SendRequestState::Receiving(frames) = mem::replace(
                                    &mut self.state,
                                    SendRequestState::Decoding(decode),
                                ) {
                                    self.recv = Some(frames);
                                }
                            }
                            _ => {
                                match mem::replace(&mut self.state, SendRequestState::Finished) {
                                    SendRequestState::Receiving(recv) => {
                                        recv.reset(ErrorCode::FRAME_UNEXPECTED)
                                    }
                                    _ => unreachable!(),
                                }
                                return Poll::Ready(Err(Error::peer("first frame is not headers")));
                            }
                        },
                    }
                }
                SendRequestState::Decoding(ref mut decode) => {
                    let header = ready!(Pin::new(decode).poll(cx))?;
                    self.state = SendRequestState::Finished;
                    return Poll::Ready(Ok(self.build_response(header)?));
                }
                _ => return Poll::Ready(Err(Error::Poll)),
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

    pub fn cancel(self) {
        if let RecvResponseState::Receiving(recv) = self.state {
            recv.reset(ErrorCode::REQUEST_CANCELLED);
        }
    }
}

impl Future for RecvResponse {
    type Output = Result<Response<RecvBody>, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                RecvResponseState::Finished => {
                    return Poll::Ready(Err(crate::Error::internal(
                        "recv response polled after finish",
                    )))
                }
                RecvResponseState::Receiving(ref mut recv) => {
                    match ready!(Pin::new(recv).poll_next(cx)) {
                        None => return Poll::Ready(Err(Error::peer("received an empty response"))),
                        Some(Err(e)) => return Poll::Ready(Err(e.into())),
                        Some(Ok(f)) => match f {
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
                    let response = build_response(
                        headers,
                        self.conn.clone(),
                        self.recv.take().unwrap(),
                        self.stream_id,
                    );
                    match response {
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(r) => {
                            self.state = RecvResponseState::Finished;
                            return Poll::Ready(Ok(r));
                        }
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
        .body(RecvBody::new(recv, conn, stream_id, true))
        .unwrap();
    *response.headers_mut() = headers;
    Ok(response)
}
