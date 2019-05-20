use std::mem;

use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll, Stream};
use quinn::{RecvStream, SendStream};
use tokio::io::WriteAll;

use crate::{
    frame::FrameStream,
    proto::frame::{DataFrame, HttpFrame},
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
                            SendBodyState::SendingBuf(tokio::io::write_all(send, buf.into())),
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
    max_size: usize,
    buf: BytesMut,
    recv: FrameStream<RecvStream>,
}

impl RecvBody {
    pub fn with_capacity(recv: FrameStream<RecvStream>, capacity: usize, max_size: usize) -> Self {
        if capacity < 1 {
            panic!("capacity cannot be 0");
        }

        Self {
            max_size,
            buf: BytesMut::with_capacity(capacity),
            recv: recv,
        }
    }
}

impl Future for RecvBody {
    type Item = Bytes;
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.buf.capacity() < 1 {
            return Err(Error::Internal("RecvBody polled after finished"));
        }

        match try_ready!(self.recv.poll()) {
            Some(HttpFrame::Data(d)) => {
                if d.payload.len() + self.buf.len() >= self.max_size {
                    return Err(Error::Overflow);
                }
                self.buf.extend(d.payload);
            }
            None => {
                return Ok(Async::Ready(
                    mem::replace(&mut self.buf, BytesMut::with_capacity(0)).into(),
                ));
            }
            _ => return Err(Error::peer("invalid frame type in data")),
        }
        Ok(Async::NotReady)
    }
}
