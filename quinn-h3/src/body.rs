use std::mem;

use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll, Stream};
use http::HeaderMap;
use quinn::{RecvStream, SendStream};
use quinn_proto::StreamId;
use tokio::io::WriteAll;

use crate::{
    connection::ConnectionRef,
    frame::FrameStream,
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
    state: RecvBodyState,
    max_size: usize,
    body: Option<Bytes>,
    recv: FrameStream<RecvStream>,
    conn: ConnectionRef,
    stream_id: StreamId,
}

impl RecvBody {
    pub(crate) fn with_capacity(
        recv: FrameStream<RecvStream>,
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
            recv: recv,
        }
    }
}

enum RecvBodyState {
    Receiving(BytesMut),
    Decoding(HeadersFrame),
    Finished,
}

impl Future for RecvBody {
    type Item = (Bytes, Option<HeaderMap>);
    type Error = crate::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.state {
            RecvBodyState::Receiving(ref mut body) => match try_ready!(self.recv.poll()) {
                Some(HttpFrame::Data(d)) => {
                    if d.payload.len() + body.len() >= self.max_size {
                        return Err(Error::Overflow);
                    }
                    body.extend(d.payload);
                }
                Some(HttpFrame::Headers(d)) => {
                    match mem::replace(&mut self.state, RecvBodyState::Decoding(d)) {
                        RecvBodyState::Receiving(b) => self.body = Some(b.into()),
                        _ => unreachable!(),
                    };
                }
                None => {
                    match mem::replace(&mut self.state, RecvBodyState::Finished) {
                        RecvBodyState::Receiving(b) => self.body = Some(b.into()),
                        _ => unreachable!(),
                    };
                }
                _ => return Err(Error::peer("invalid frame type in data")),
            },
            RecvBodyState::Decoding(ref frame) => {
                let result = {
                    let conn = &mut self.conn.h3.lock().unwrap().inner;
                    conn.decode_header(&self.stream_id, frame)
                };

                match result {
                    Ok(None) => return Ok(Async::NotReady),
                    Err(e) => return Err(Error::peer(format!("decoding header failed: {:?}", e))),
                    Ok(Some(decoded)) => {
                        self.state = RecvBodyState::Finished;
                        return Ok(Async::Ready((
                            try_take(&mut self.body, "body absent")?,
                            Some(decoded.into_fields()),
                        )));
                    }
                }
            }
            _ => return Err(Error::Poll),
        }

        Ok(Async::NotReady)
    }
}
