use std::mem;

use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll, Stream};
use http::HeaderMap;
use quinn::SendStream;
use quinn_proto::StreamId;
use tokio_io::io::WriteAll;

use crate::{
    connection::ConnectionRef,
    frame::FrameStream,
    headers::DecodeHeaders,
    proto::frame::{DataFrame, HttpFrame, HeadersFrame},
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
    max_size: usize,
    body: Option<Bytes>,
    recv: FrameStream,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBody {
    pub(crate) fn with_capacity(
        recv: FrameStream,
        capacity: usize,
        max_size: usize,
        conn: ConnectionRef,
        stream_id: StreamId,
    ) -> Self {
        if capacity < 1 {
            panic!("capacity cannot be 0");
        }

        Self {
            max_size,
            conn,
            stream_id,
            state: RecvBodyState::Receiving(BytesMut::with_capacity(capacity)),
            body: None,
            recv,
        }
    }
}

enum RecvBodyState {
    Receiving(BytesMut),
    Decoding(DecodeHeaders),
    Finished,
}

impl Future for RecvBody {
    type Item = (Bytes, Option<HeaderMap>);
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
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
                            RecvBodyState::Receiving(b) => b.into(),
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
                        try_take(&mut self.body, "body absent")?,
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
            Some(HttpFrame::Data(d)) => {
                Ok(Async::Ready(Some(d.payload)))
            }
            Some(HttpFrame::Headers(d)) => {
                self.trailers = Some(d);
                Ok(Async::Ready(None))
            }
            None => {
                Ok(Async::Ready(None))
            }
            _ => Err(Error::peer("invalid frame type in data")),
        }
    }
}
