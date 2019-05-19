use std::mem;

use quinn::SendStream;
use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll};
use tokio::io::WriteAll;

use crate::{proto::frame::DataFrame, try_take, Error};

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
        Ok(Async::NotReady)
    }
}
