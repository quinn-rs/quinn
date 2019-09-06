use std::{
    cmp, fmt,
    io::{self, ErrorKind},
    mem,
};

use bytes::{Bytes, BytesMut};
use futures::{future::Either, try_ready, Async, Future, IntoFuture, Poll, Stream};
use http::HeaderMap;
use quinn::SendStream;
use quinn_proto::StreamId;
use tokio_io::{AsyncRead, AsyncWrite};

use crate::{
    connection::ConnectionRef,
    frame::{FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HeadersFrame, HttpFrame},
        headers::Header,
    },
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
        Body::Buf(buf.into())
    }
}

pub(crate) struct SendBody {
    state: SendBodyState,
    send: Option<SendStream>,
    body: Option<Body>,
}

impl SendBody {
    pub fn new<T: Into<Body>>(send: SendStream, body: T) -> Self {
        Self {
            send: Some(send),
            state: SendBodyState::Initial,
            body: Some(body.into()),
        }
    }
}

pub enum SendBodyState {
    Initial,
    SendingBuf(WriteFrame),
    Finished,
}

impl Future for SendBody {
    type Item = SendStream;
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                SendBodyState::Initial => match try_take(&mut self.body, "body")? {
                    Body::None => return Ok(Async::Ready(try_take(&mut self.send, "send")?)),
                    Body::Buf(b) => {
                        let send = try_take(&mut self.send, "SendBody stream")?;
                        mem::replace(
                            &mut self.state,
                            SendBodyState::SendingBuf(WriteFrame::new(
                                send,
                                DataFrame { payload: b.into() },
                            )),
                        );
                    }
                },
                SendBodyState::SendingBuf(ref mut b) => {
                    let send = try_ready!(b.poll());
                    mem::replace(&mut self.state, SendBodyState::Finished);
                    return Ok(Async::Ready(send));
                }
                SendBodyState::Finished => {
                    return Err(Error::Internal("SendBody polled while finished"));
                }
            }
        }
    }
}

pub struct RecvBody {
    recv: FrameStream,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBody {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        RecvBody {
            conn,
            stream_id,
            recv,
        }
    }

    pub fn read_to_end(self, capacity: usize, size_limit: usize) -> ReadToEnd {
        ReadToEnd::new(self.recv, capacity, size_limit, self.conn, self.stream_id)
    }

    pub fn into_reader(self) -> BodyReader {
        BodyReader::new(self.recv, self.conn, self.stream_id)
    }

    pub fn into_stream(self) -> RecvBodyStream {
        RecvBodyStream::new(self.recv, self.conn, self.stream_id)
    }
}

impl fmt::Debug for RecvBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecvBody {{ stream_id: {:?} }}", self.stream_id)
    }
}

pub struct ReadToEnd {
    state: RecvBodyState,
    size_limit: usize,
    body: Option<Bytes>,
    recv: FrameStream,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl ReadToEnd {
    pub(crate) fn new(
        recv: FrameStream,
        capacity: usize,
        size_limit: usize,
        conn: ConnectionRef,
        stream_id: StreamId,
    ) -> Self {
        Self {
            conn,
            stream_id,
            recv,
            size_limit,
            body: None,
            state: RecvBodyState::Receiving(BytesMut::with_capacity(capacity)),
        }
    }
}

enum RecvBodyState {
    Receiving(BytesMut),
    Decoding(DecodeHeaders),
    Finished,
}

impl Future for ReadToEnd {
    type Item = (Option<Bytes>, Option<HeaderMap>);
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                RecvBodyState::Receiving(ref mut body) => match try_ready!(self.recv.poll()) {
                    Some(HttpFrame::Data(d)) => {
                        if d.payload.len() + body.len() >= self.size_limit {
                            return Err(Error::Overflow);
                        }
                        body.extend(d.payload);
                    }
                    Some(HttpFrame::Headers(t)) => {
                        let decode_trailer =
                            DecodeHeaders::new(t, self.conn.clone(), self.stream_id);
                        let old_state =
                            mem::replace(&mut self.state, RecvBodyState::Decoding(decode_trailer));
                        match old_state {
                            RecvBodyState::Receiving(b) => self.body = Some(b.into()),
                            _ => unreachable!(),
                        };
                    }
                    None => {
                        let body = match mem::replace(&mut self.state, RecvBodyState::Finished) {
                            RecvBodyState::Receiving(b) => match b.len() {
                                0 => None,
                                _ => Some(b.into()),
                            },
                            _ => unreachable!(),
                        };
                        return Ok(Async::Ready((body, None)));
                    }
                    _ => return Err(Error::peer("invalid frame type in data")),
                },
                RecvBodyState::Decoding(ref mut trailer) => {
                    let trailer = try_ready!(trailer.poll());
                    self.state = RecvBodyState::Finished;
                    return Ok(Async::Ready((
                        Some(try_take(&mut self.body, "body absent")?),
                        Some(trailer.into_fields()),
                    )));
                }
                _ => return Err(Error::Poll),
            }
        }
    }
}

pub struct RecvBodyStream {
    recv: FrameStream,
    trailers: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBodyStream {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        RecvBodyStream {
            recv,
            conn,
            stream_id,
            trailers: None,
        }
    }

    pub fn has_trailers(&self) -> bool {
        self.trailers.is_some()
    }

    pub fn trailers(self) -> Option<DecodeHeaders> {
        let (trailers, conn, stream_id) = (self.trailers, self.conn, self.stream_id);
        trailers.map(|t| DecodeHeaders::new(t, conn, stream_id))
    }
}

impl Stream for RecvBodyStream {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.recv.poll()) {
            Some(HttpFrame::Data(d)) => Ok(Async::Ready(Some(d.payload))),
            Some(HttpFrame::Headers(d)) => {
                self.trailers = Some(d);
                Ok(Async::Ready(None))
            }
            None => Ok(Async::Ready(None)),
            _ => Err(Error::peer("invalid frame type in data")),
        }
    }
}

pub struct BodyReader {
    recv: FrameStream,
    trailers: Option<HeadersFrame>,
    conn: ConnectionRef,
    stream_id: StreamId,
    buf: Option<Bytes>,
}

impl BodyReader {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        BodyReader {
            recv,
            conn,
            stream_id,
            trailers: None,
            buf: None,
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

    pub fn trailers(self) -> Option<DecodeHeaders> {
        let (trailers, conn, stream_id) = (self.trailers, self.conn, self.stream_id);
        trailers.map(|t| DecodeHeaders::new(t, conn, stream_id))
    }
}

impl AsyncRead for BodyReader {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl io::Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let size = self.buf_read(buf);
        if size == buf.len() {
            return Ok(size);
        }

        match self.recv.poll() {
            Err(err) => Err(io::Error::new(ErrorKind::Other, Error::from(err))),
            Ok(Async::NotReady) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(io::Error::new(ErrorKind::WouldBlock, "stream blocked"))
                }
            }
            Ok(Async::Ready(r)) => match r {
                None => Ok(size),
                Some(HttpFrame::Data(mut d)) => {
                    if d.payload.len() >= buf.len() - size {
                        let tail = d.payload.split_off(buf.len() - size);
                        self.buf_put(tail);
                    }
                    buf[size..size + d.payload.len()].copy_from_slice(&d.payload);
                    Ok(size + d.payload.len())
                }
                Some(HttpFrame::Headers(d)) => {
                    self.trailers = Some(d);
                    Ok(size)
                }
                _ => Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "received an invalid frame type",
                )),
            },
        }
    }
}

pub struct BodyWriter {
    state: BodyWriterState,
    send: Option<SendStream>,
    conn: ConnectionRef,
    stream_id: StreamId,
    trailers: Option<HeaderMap>,
}

impl BodyWriter {
    pub(crate) fn new(
        send: SendStream,
        conn: ConnectionRef,
        stream_id: StreamId,
        trailers: Option<HeaderMap>,
    ) -> Self {
        Self {
            state: BodyWriterState::Idle,
            send: Some(send),
            conn,
            stream_id,
            trailers,
        }
    }

    pub fn trailers(mut self, trailers: HeaderMap) -> impl Future<Item = (), Error = Error> {
        match self.state {
            BodyWriterState::Idle => {
                let send = self.send.take().expect("send is none");
                Self::_trailers(trailers, &self.conn, send, self.stream_id)
            }
            _ => panic!("cannot send trailers while not in idle state"),
        }
    }

    pub fn close(mut self) -> impl Future<Item = (), Error = Error> {
        match (self.trailers.take(), self.state) {
            (Some(t), BodyWriterState::Idle) => {
                let send = self.send.take().expect("send is none");
                Either::A(Self::_trailers(t, &self.conn, send, self.stream_id))
            }
            (None, BodyWriterState::Idle) => Either::B(
                tokio_io::io::shutdown(self.send.take().unwrap())
                    .map_err(Into::into)
                    .map(|_| ()),
            ),
            _ => panic!("cannot close while not in idle state"),
        }
    }

    fn _trailers(
        trailers: HeaderMap,
        conn: &ConnectionRef,
        send: SendStream,
        stream_id: StreamId,
    ) -> impl Future<Item = (), Error = Error> {
        match SendHeaders::new(Header::trailer(trailers), conn, send, stream_id) {
            Err(e) => Either::A(Err(e).into_future()),
            Ok(f) => Either::B(
                f.and_then(|send| tokio_io::io::shutdown(send).map_err(Into::into).map(|_| ())),
            ),
        }
    }
}

enum BodyWriterState {
    Idle,
    Writing(WriteFrame),
    Finished,
}

impl io::Write for BodyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.state {
                BodyWriterState::Finished => panic!(),
                BodyWriterState::Idle => {
                    let frame = DataFrame {
                        payload: buf.into(),
                    };
                    let send = self.send.take().expect("send is none");
                    mem::replace(
                        &mut self.state,
                        BodyWriterState::Writing(WriteFrame::new(send, frame)),
                    );
                }
                BodyWriterState::Writing(ref mut write) => match write.poll() {
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            format!("{:?}", e),
                        ))
                    }
                    Ok(Async::Ready(send)) => {
                        self.send = Some(send);
                        mem::replace(&mut self.state, BodyWriterState::Idle);
                        return Ok(buf.len());
                    }
                    Ok(Async::NotReady) => {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked"));
                    }
                },
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for BodyWriter {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.state {
            BodyWriterState::Finished => Ok(Async::Ready(())),
            BodyWriterState::Idle => {
                self.state = BodyWriterState::Finished;
                self.send.take().expect("send is none").shutdown()
            }
            BodyWriterState::Writing(ref mut write) => {
                let mut send = try_ready!(write.poll());
                self.state = BodyWriterState::Finished;
                send.shutdown()
            }
        }
    }
}
