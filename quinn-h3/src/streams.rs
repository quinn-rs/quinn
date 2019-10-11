use std::{convert::TryFrom, io, mem, pin::Pin, task::Context};

use bytes::Bytes;
use futures::{
    io::{AsyncRead, AsyncWrite},
    ready, Future, Poll,
};
use quinn::{OpenUni, RecvStream, SendStream};
use quinn_proto::VarInt;

use crate::{
    connection::ConnectionRef,
    frame::{FrameDecoder, FrameStream},
    proto::{ErrorCode, StreamType},
    Error,
};

pub enum NewUni {
    Control(FrameStream),
    Push(PushStream),
    Encoder(RecvStream),
    Decoder(RecvStream),
}

impl TryFrom<(StreamType, RecvStream)> for NewUni {
    type Error = Error;
    fn try_from(value: (StreamType, RecvStream)) -> Result<Self, Self::Error> {
        let (ty, recv) = value;
        Ok(match ty {
            StreamType::CONTROL => NewUni::Control(FrameDecoder::stream(recv)),
            StreamType::PUSH => NewUni::Push(PushStream(FrameDecoder::stream(recv))),
            StreamType::ENCODER => NewUni::Encoder(recv),
            StreamType::DECODER => NewUni::Decoder(recv),
            _ => return Err(Error::UnknownStream(ty.0)),
        })
    }
}

pub struct RecvUni {
    inner: Option<(RecvStream, Vec<u8>, usize)>,
}

impl RecvUni {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            inner: Some((recv, vec![0u8; VarInt::MAX.size()], 0)),
        }
    }
}

impl Future for RecvUni {
    type Output = Result<NewUni, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.inner {
                None => panic!("polled after resolved"),
                Some((ref mut recv, ref mut buf, ref mut len)) => {
                    match ready!(Pin::new(recv).poll_read(cx, &mut buf[..*len + 1]))? {
                        0 => {
                            return Poll::Ready(Err(Error::Peer(format!(
                                "Uni stream closed before type received",
                            ))))
                        }
                        _ => {
                            *len += 1;
                            let mut cur = io::Cursor::new(&buf);
                            if let Ok(ty) = StreamType::decode(&mut cur) {
                                match mem::replace(&mut self.inner, None) {
                                    Some((recv, _, _)) => {
                                        return Poll::Ready(NewUni::try_from((ty, recv)))
                                    }
                                    _ => unreachable!(),
                                };
                            };
                        }
                    }
                }
            }
        }
    }
}

pub struct PushStream(FrameStream);

pub struct SendControlStream {
    conn: ConnectionRef,
    state: SendControlStreamState,
    send: Option<SendStream>,
}

impl SendControlStream {
    pub(super) fn new(conn: ConnectionRef) -> Self {
        Self {
            state: SendControlStreamState::Opening(conn.quic.open_uni()),
            send: None,
            conn,
        }
    }
}

enum SendControlStreamState {
    Opening(OpenUni),
    Idle,
    Sending(SendStream, Bytes),
}

impl Future for SendControlStream {
    type Output = Result<(), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                SendControlStreamState::Opening(ref mut o) => {
                    let send = ready!(Pin::new(o).poll(cx))?;
                    self.state =
                        SendControlStreamState::Sending(send, StreamType::CONTROL.encoded());
                }
                SendControlStreamState::Idle => {
                    let pending = self.conn.h3.lock().unwrap().inner.pending_control();
                    if let Some(data) = pending {
                        self.state =
                            SendControlStreamState::Sending(self.send.take().unwrap(), data);
                    }
                    return Poll::Pending;
                }
                SendControlStreamState::Sending(ref mut send, ref mut data) => {
                    let wrote = ready!(Pin::new(send).poll_write(cx, &data))?;
                    data.advance(wrote);
                    if data.is_empty() {
                        match mem::replace(&mut self.state, SendControlStreamState::Idle) {
                            SendControlStreamState::Sending(send, _) => self.send = Some(send),
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }
    }
}

pub trait Reset {
    fn reset(self, code: ErrorCode);
}
