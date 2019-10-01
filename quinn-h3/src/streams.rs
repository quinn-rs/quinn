use std::{convert::TryFrom, io, mem, pin::Pin, task::Context};

use bytes::BytesMut;
use futures::{io::AsyncRead, ready, Future, Poll};
use quinn::RecvStream;
use quinn_proto::VarInt;

use crate::{
    frame::{FrameDecoder, FrameStream},
    proto::StreamType,
    Error,
};

pub enum NewUni {
    Control(ControlStream),
    Push(PushStream),
    Encoder(RecvStream),
    Decoder(RecvStream),
}

impl TryFrom<(StreamType, RecvStream)> for NewUni {
    type Error = Error;
    fn try_from(value: (StreamType, RecvStream)) -> Result<Self, Self::Error> {
        let (ty, recv) = value;
        Ok(match ty {
            StreamType::CONTROL => NewUni::Control(ControlStream(FrameDecoder::stream(recv))),
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

pub struct ControlStream(FrameStream);

pub struct PushStream(FrameStream);
