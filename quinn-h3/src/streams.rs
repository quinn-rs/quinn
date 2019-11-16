use std::{collections::VecDeque, convert::TryFrom, io, mem, pin::Pin, task::Context};

use bytes::Bytes;
use futures::{
    io::{AsyncRead, AsyncWrite},
    ready, Future, Poll,
};
use quinn::{OpenUni, RecvStream, SendStream};
use quinn_proto::VarInt;

use crate::{
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
                    match ready!(Pin::new(recv).poll_read(cx, &mut buf[..=*len]))? {
                        0 => {
                            return Poll::Ready(Err(Error::Peer(
                                "Uni stream closed before type received".into(),
                            )))
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

pub struct SendUni {
    ty: StreamType,
    state: SendUniState,
    data: VecDeque<Bytes>,
}

impl SendUni {
    pub(super) fn new(ty: StreamType, quic: quinn::Connection) -> Self {
        Self {
            ty,
            state: SendUniState::New(quic),
            data: VecDeque::with_capacity(2),
        }
    }
}

enum SendUniState {
    New(quinn::Connection),
    Opening(OpenUni),
    Idle(SendStream),
    Sending(SendStream, Bytes),
    Transitive,
}

impl SendUni {
    pub fn push(&mut self, data: Bytes) {
        self.data.push_back(data);
    }
}

/// Send all buffers from self.data, return `Poll::Ready(Ok(()))` when there is nothing more to be done
impl Future for SendUni {
    type Output = Result<(), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let is_empty = self.data.is_empty();
        loop {
            match self.state {
                SendUniState::New(ref mut c) => {
                    if is_empty {
                        return Poll::Ready(Ok(()));
                    }
                    self.state = SendUniState::Opening(c.open_uni());
                }
                SendUniState::Opening(ref mut o) => {
                    let send = ready!(Pin::new(o).poll(cx))?;
                    self.state = SendUniState::Sending(send, self.ty.encoded());
                }
                SendUniState::Idle(_) => match self.data.pop_front() {
                    Some(d) => match mem::replace(&mut self.state, SendUniState::Transitive) {
                        SendUniState::Idle(s) => self.state = SendUniState::Sending(s, d),
                        _ => unreachable!(),
                    },
                    None => return Poll::Ready(Ok(())),
                },
                SendUniState::Sending(ref mut send, ref mut data) => {
                    let wrote = ready!(Pin::new(send).poll_write(cx, data))?;
                    data.advance(wrote);
                    if data.is_empty() {
                        self.state = match mem::replace(&mut self.state, SendUniState::Transitive) {
                            SendUniState::Sending(s, _) => match self.data.pop_front() {
                                Some(d) => SendUniState::Sending(s, d),
                                None => SendUniState::Idle(s),
                            },
                            _ => unreachable!(),
                        };
                    }
                }
                _ => panic!("SendUni state machine fault"),
            }
        }
    }
}

pub trait Reset {
    fn reset(self, code: ErrorCode);
}
