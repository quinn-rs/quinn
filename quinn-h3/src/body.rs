use std::{
    cmp,
    io::{self, ErrorKind},
    mem,
};

use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll, Stream};
use http::HeaderMap;
use quinn::SendStream;
use quinn_proto::StreamId;
use tokio_io::{io::WriteAll, AsyncRead};

use crate::{
    connection::ConnectionRef,
    frame::FrameStream,
    headers::DecodeHeaders,
    proto::frame::{DataFrame, HeadersFrame, HttpFrame},
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
    SendingBuf(WriteAll<SendStream, Bytes>),
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

                        let mut buf = Vec::new();
                        DataFrame { payload: b }.encode(&mut buf); // TODO unecessary copy

                        mem::replace(
                            &mut self.state,
                            SendBodyState::SendingBuf(tokio_io::io::write_all(send, buf.into())),
                        );
                    }
                },
                SendBodyState::SendingBuf(ref mut b) => {
                    let (send, _) = try_ready!(b.poll());
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
    state: RecvBodyState,
    capacity: usize,
    max_size: usize,
    body: Option<Bytes>,
    recv: FrameStream,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBody {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        Self {
            conn,
            stream_id,
            recv,
            body: None,
            max_size: RECV_BODY_MAX_SIZE_DEFAULT,
            capacity: RECV_BODY_CAPACITY_DEFAULT,
            state: RecvBodyState::Initial,
        }
    }

    pub fn with_capacity(mut self, capacity: usize, max_size: usize) -> Self {
        match &self.state {
            RecvBodyState::Initial => (),
            _ => panic!("cannot change capacity once polled"),
        }

        self.max_size = max_size;
        self.capacity = capacity;

        self
    }
}

const RECV_BODY_MAX_SIZE_DEFAULT: usize = 20 * 1024 * 1024; // 20 MB
const RECV_BODY_CAPACITY_DEFAULT: usize = 1024 * 1024;

enum RecvBodyState {
    Initial,
    Receiving(BytesMut),
    Decoding(DecodeHeaders),
    Finished,
}

impl Future for RecvBody {
    type Item = (Option<Bytes>, Option<HeaderMap>);
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                RecvBodyState::Initial => {
                    self.state = RecvBodyState::Receiving(BytesMut::with_capacity(self.capacity))
                }
                RecvBodyState::Receiving(ref mut body) => match try_ready!(self.recv.poll()) {
                    Some(HttpFrame::Data(d)) => {
                        if d.payload.len() + body.len() >= self.max_size {
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
            Ok(Async::NotReady) => Err(io::Error::new(ErrorKind::WouldBlock, "stream blocked")),
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
