use std::{
    cmp, fmt,
    io::{self, ErrorKind},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{
    io::{AsyncRead, AsyncWrite},
    ready,
    stream::Stream,
};
use http::HeaderMap;
use quinn::SendStream;
use quinn_proto::StreamId;
use std::future::Future;

use crate::{
    connection::ConnectionRef,
    frame::{FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HeadersFrame, HttpFrame},
        headers::Header,
        ErrorCode,
    },
    streams::Reset,
    try_take, Error,
};

pub enum Body {
    None,
    Buf(Bytes),
}

impl From<()> for Body {
    fn from(_: ()) -> Self {
        Body::None
    }
}

impl From<Bytes> for Body {
    fn from(buf: Bytes) -> Self {
        Body::Buf(buf)
    }
}

impl From<&str> for Body {
    fn from(buf: &str) -> Self {
        Body::Buf(Bytes::copy_from_slice(buf.as_bytes()))
    }
}

pub struct RecvBody {
    recv: FrameStream,
    conn: ConnectionRef,
    stream_id: StreamId,
    finish_request: bool,
}

#[must_use = "body must be read or canceled"] // else, request might never be finished
impl RecvBody {
    pub(crate) fn new(
        recv: FrameStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        finish_request: bool,
    ) -> Self {
        RecvBody {
            conn,
            stream_id,
            recv,
            finish_request,
        }
    }

    pub fn read_to_end(self, capacity: usize, size_limit: usize) -> ReadToEnd {
        ReadToEnd::new(
            self.recv,
            capacity,
            size_limit,
            self.conn,
            self.stream_id,
            self.finish_request,
        )
    }

    pub fn cancel(self) {
        self.recv.reset(ErrorCode::REQUEST_CANCELLED);
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }

    pub fn into_reader(self) -> BodyReader {
        BodyReader::new(self.recv, self.conn, self.stream_id, self.finish_request)
    }

    pub fn into_stream(self) -> RecvBodyStream {
        RecvBodyStream::new(self.recv, self.conn, self.stream_id, self.finish_request)
    }
}

impl fmt::Debug for RecvBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecvBody {{ stream_id: {:?} }}", self.stream_id)
    }
}

pub struct ReadToEnd {
    state: ReadToEndState,
    body: Option<Bytes>,
    conn: ConnectionRef,
    stream_id: StreamId,
    finish_request: bool,
}

impl ReadToEnd {
    pub(crate) fn new(
        recv: FrameStream,
        capacity: usize,
        size_limit: usize,
        conn: ConnectionRef,
        stream_id: StreamId,
        finish_request: bool,
    ) -> Self {
        Self {
            conn,
            stream_id,
            body: None,
            state: ReadToEndState::Receiving(recv, BytesMut::with_capacity(capacity), size_limit),
            finish_request,
        }
    }

    pub fn cancel(mut self) {
        let state = mem::replace(&mut self.state, ReadToEndState::Finished);
        if let ReadToEndState::Receiving(recv, _, _) = state {
            recv.reset(ErrorCode::REQUEST_CANCELLED);
        }
    }
}

enum ReadToEndState {
    Receiving(FrameStream, BytesMut, usize),
    Decoding(DecodeHeaders),
    Finished,
}

impl Future for ReadToEnd {
    type Output = Result<(Option<Bytes>, Option<HeaderMap>), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                ReadToEndState::Receiving(ref mut recv, ref mut body, size_limit) => {
                    match ready!(Pin::new(recv).poll_next(cx)) {
                        Some(Err(e)) => return Poll::Ready(Err(e.into())),
                        Some(Ok(HttpFrame::Data(d))) => {
                            if d.payload.len() + body.len() >= size_limit {
                                return Poll::Ready(Err(Error::Overflow));
                            }
                            body.extend(d.payload);
                        }
                        Some(Ok(HttpFrame::Headers(t))) => {
                            let decode_trailer =
                                DecodeHeaders::new(t, self.conn.clone(), self.stream_id);
                            let old_state = mem::replace(
                                &mut self.state,
                                ReadToEndState::Decoding(decode_trailer),
                            );
                            match old_state {
                                ReadToEndState::Receiving(_, b, _) => self.body = Some(b.freeze()),
                                _ => unreachable!(),
                            };
                        }
                        None => {
                            let body = match mem::replace(&mut self.state, ReadToEndState::Finished)
                            {
                                ReadToEndState::Receiving(_, b, _) => match b.len() {
                                    0 => None,
                                    _ => Some(b.freeze()),
                                },
                                _ => unreachable!(),
                            };
                            return Poll::Ready(Ok((body, None)));
                        }
                        Some(x) => {
                            let (err_code, error) = match x {
                                Ok(_) => (
                                    ErrorCode::FRAME_UNEXPECTED,
                                    Poll::Ready(Err(Error::peer("invalid frame type in data"))),
                                ),
                                Err(e) => (e.code(), Poll::Ready(Err(e.into()))),
                            };
                            match mem::replace(&mut self.state, ReadToEndState::Finished) {
                                ReadToEndState::Receiving(recv, _, _) => {
                                    recv.reset(err_code);
                                }
                                _ => unreachable!(),
                            };
                            return error;
                        }
                    }
                }
                ReadToEndState::Decoding(ref mut trailer) => {
                    let trailer = ready!(Pin::new(trailer).poll(cx))?;
                    self.state = ReadToEndState::Finished;
                    return Poll::Ready(Ok((
                        Some(try_take(&mut self.body, "body absent")?),
                        Some(trailer.into_fields()),
                    )));
                }
                _ => return Poll::Ready(Err(Error::Poll)),
            }
        }
    }
}

impl Drop for ReadToEnd {
    fn drop(&mut self) {
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }
}

pub struct RecvBodyStream {
    recv: Option<FrameStream>,
    trailers: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
    finish_request: bool,
}

impl RecvBodyStream {
    pub(crate) fn new(
        recv: FrameStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        finish_request: bool,
    ) -> Self {
        RecvBodyStream {
            conn,
            stream_id,
            finish_request,
            recv: Some(recv),
            trailers: None,
        }
    }

    pub fn has_trailers(&self) -> bool {
        self.trailers.is_some()
    }

    pub fn trailers(mut self) -> Option<DecodeHeaders> {
        let trailers = self.trailers.take();
        let Self {
            conn, stream_id, ..
        } = &self;
        trailers.map(|t| DecodeHeaders::new(t, conn.clone(), *stream_id))
    }

    pub fn cancel(mut self) {
        self.recv
            .take()
            .unwrap()
            .reset(ErrorCode::REQUEST_CANCELLED);
    }
}

impl Stream for RecvBodyStream {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let res = ready!(Pin::new(&mut self.recv.as_mut().unwrap()).poll_next(cx));
        match res {
            None => Poll::Ready(None),
            Some(Ok(HttpFrame::Data(d))) => Poll::Ready(Some(Ok(d.payload))),
            Some(Ok(HttpFrame::Headers(d))) => {
                self.trailers = Some(d);
                Poll::Ready(None)
            }
            Some(Ok(_)) => {
                self.recv.take().unwrap().reset(ErrorCode::FRAME_UNEXPECTED);
                Poll::Ready(Some(Err(Error::peer("invalid frame type in data"))))
            }
            Some(Err(e)) => {
                self.recv.take().unwrap().reset(e.code());
                Poll::Ready(Some(Err(e.into())))
            }
        }
    }
}

impl Drop for RecvBodyStream {
    fn drop(&mut self) {
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }
}

pub struct BodyReader {
    recv: Option<FrameStream>,
    trailers: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
    buf: Option<Bytes>,
    finish_request: bool,
}

impl BodyReader {
    pub(crate) fn new(
        recv: FrameStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        finish_request: bool,
    ) -> Self {
        BodyReader {
            conn,
            stream_id,
            finish_request,
            buf: None,
            trailers: None,
            recv: Some(recv),
        }
    }

    fn buf_read(&mut self, buf: &mut [u8]) -> usize {
        match self.buf {
            None => 0,
            Some(ref mut b) => {
                let size = cmp::min(buf.len(), b.len());
                buf[..size].copy_from_slice(&b.split_to(size));
                if b.is_empty() {
                    self.buf = None;
                }
                size
            }
        }
    }

    fn buf_put(&mut self, buf: Bytes) {
        assert!(self.buf.is_none());
        self.buf = Some(buf)
    }

    pub fn trailers(&mut self) -> Option<DecodeHeaders> {
        let trailers = self.trailers.take();
        let Self {
            conn, stream_id, ..
        } = &self;
        trailers.map(|t| DecodeHeaders::new(t, conn.clone(), *stream_id))
    }

    pub fn cancel(mut self) {
        if let Some(recv) = self.recv.take() {
            recv.reset(ErrorCode::REQUEST_CANCELLED);
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let size = self.buf_read(buf);
        if size == buf.len() {
            return Poll::Ready(Ok(size));
        }

        match Pin::new(self.recv.as_mut().unwrap()).poll_next(cx) {
            Poll::Ready(None) => Poll::Ready(Ok(size)),
            Poll::Pending => {
                if size > 0 {
                    Poll::Ready(Ok(size))
                } else {
                    Poll::Ready(Err(io::Error::new(ErrorKind::WouldBlock, "stream blocked")))
                }
            }
            Poll::Ready(Some(Err(e))) => {
                self.recv.take().unwrap().reset(e.code());
                Poll::Ready(Err(io::Error::new(
                    ErrorKind::Other,
                    format!("read error: {:?}", e),
                )))
            }
            Poll::Ready(Some(Ok(HttpFrame::Data(mut d)))) => {
                if d.payload.len() >= buf.len() - size {
                    let tail = d.payload.split_off(buf.len() - size);
                    self.buf_put(tail);
                }
                buf[size..size + d.payload.len()].copy_from_slice(&d.payload);
                Poll::Ready(Ok(size + d.payload.len()))
            }
            Poll::Ready(Some(Ok(HttpFrame::Headers(d)))) => {
                self.trailers = Some(d);
                Poll::Ready(Ok(size))
            }
            Poll::Ready(Some(Ok(_))) => {
                self.recv.take().unwrap().reset(ErrorCode::FRAME_UNEXPECTED);
                Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "received an invalid frame type",
                )))
            }
        }
    }
}

impl tokio::io::AsyncRead for BodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncRead::poll_read(self, cx, buf)
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }
}

pub struct BodyWriter {
    state: BodyWriterState,
    conn: ConnectionRef,
    stream_id: StreamId,
    trailers: Option<HeaderMap>,
    finish_request: bool,
}

impl BodyWriter {
    pub(crate) fn new(
        send: SendStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        trailers: Option<HeaderMap>,
        finish_request: bool,
    ) -> Self {
        Self {
            conn,
            stream_id,
            trailers,
            state: BodyWriterState::Idle(send),
            finish_request,
        }
    }

    pub async fn trailers(mut self, trailers: HeaderMap) -> Result<(), Error> {
        match mem::replace(&mut self.state, BodyWriterState::Finished) {
            BodyWriterState::Idle(send) => {
                Self::_trailers(trailers, &self.conn, send, self.stream_id).await
            }
            _ => panic!("cannot send trailers while not in idle state"),
        }
    }

    pub async fn close(mut self) -> Result<(), Error> {
        let trailers = self.trailers.take();
        let state = mem::replace(&mut self.state, BodyWriterState::Finished);

        match (trailers, state) {
            (Some(t), BodyWriterState::Idle(send)) => {
                Self::_trailers(t, &self.conn, send, self.stream_id).await
            }
            (None, BodyWriterState::Idle(mut send)) => send.finish().await.map_err(Into::into),
            _ => panic!("cannot close while not in idle state"),
        }
    }

    pub fn cancel(mut self) {
        let state = mem::replace(&mut self.state, BodyWriterState::Finished);
        match state {
            BodyWriterState::Idle(mut send) => {
                send.reset(ErrorCode::REQUEST_CANCELLED.into());
            }
            BodyWriterState::Writing(write) => {
                write.reset(ErrorCode::REQUEST_CANCELLED);
            }
            _ => (),
        }
    }

    async fn _trailers(
        trailers: HeaderMap,
        conn: &ConnectionRef,
        send: SendStream,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        let mut stream =
            SendHeaders::new(Header::trailer(trailers), conn, send, stream_id)?.await?;
        stream.finish().await.map_err(Into::into)
    }
}

enum BodyWriterState {
    Idle(SendStream),
    Writing(WriteFrame),
    Finished,
}

impl AsyncWrite for BodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            match self.state {
                BodyWriterState::Finished => panic!(),
                BodyWriterState::Idle(_) => {
                    let frame = DataFrame {
                        payload: Bytes::copy_from_slice(buf),
                    };
                    self.state = match mem::replace(&mut self.state, BodyWriterState::Finished) {
                        BodyWriterState::Idle(send) => {
                            BodyWriterState::Writing(WriteFrame::new(send, frame))
                        }
                        _ => unreachable!(),
                    }
                }
                BodyWriterState::Writing(ref mut write) => {
                    let send = ready!(Pin::new(write).poll(cx))?;
                    self.state = BodyWriterState::Idle(send);
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.state {
            BodyWriterState::Finished => Poll::Ready(Ok(())),
            BodyWriterState::Idle(ref mut send) => {
                ready!(Pin::new(send).poll_flush(cx))?;
                self.state = BodyWriterState::Finished;
                Poll::Ready(Ok(()))
            }
            BodyWriterState::Writing(ref mut write) => {
                let send = ready!(Pin::new(write).poll(cx))?;
                self.state = BodyWriterState::Idle(send);
                Poll::Pending
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.state {
            BodyWriterState::Finished => Poll::Ready(Ok(())),
            BodyWriterState::Idle(ref mut send) => {
                ready!(Pin::new(send).poll_close(cx))?;
                self.state = BodyWriterState::Finished;
                Poll::Ready(Ok(()))
            }
            BodyWriterState::Writing(ref mut write) => {
                let send = ready!(Pin::new(write).poll(cx))?;
                self.state = BodyWriterState::Idle(send);
                Poll::Pending
            }
        }
    }
}

impl tokio::io::AsyncWrite for BodyWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_close(self, cx)
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        if self.finish_request {
            self.conn
                .h3
                .lock()
                .unwrap()
                .inner
                .request_finished(self.stream_id);
        }
    }
}
