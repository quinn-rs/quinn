use std::{
    future::Future,
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{io::AsyncWrite, ready};
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::AsyncRead;
use tokio_util::codec::{Decoder, FramedRead};

use super::proto::frame::{self, FrameHeader, HttpFrame, IntoPayload, PartialData};
use crate::{proto::ErrorCode, streams::Reset};

pub type FrameStream = FramedRead<RecvStream, FrameDecoder>;

impl Reset for FrameStream {
    fn reset(self, error_code: ErrorCode) {
        let _ = self.into_inner().stop(error_code.0.into());
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    partial: Option<PartialData>,
    expected: Option<usize>,
}

impl FrameDecoder {
    pub fn stream<T: AsyncRead>(stream: T) -> FramedRead<T, Self> {
        FramedRead::new(
            stream,
            FrameDecoder {
                expected: None,
                partial: None,
            },
        )
    }
}

macro_rules! decode {
    ($buf:ident, $dec:expr) => {{
        let mut cur = io::Cursor::new(&$buf);
        let decoded = $dec(&mut cur);
        (cur.position() as usize, decoded)
    }};
}

impl Decoder for FrameDecoder {
    type Item = HttpFrame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        if let Some(ref mut partial) = self.partial {
            let (pos, frame) = decode!(src, |cur| HttpFrame::Data(partial.decode_data(cur)));
            src.advance(pos);

            if partial.remaining() == 0 {
                self.partial = None;
            }

            return Ok(Some(frame));
        }

        if let Some(min) = self.expected {
            if src.len() < min {
                return Ok(None);
            }
        }

        let (pos, decoded) = decode!(src, |cur| HttpFrame::decode(cur));

        match decoded {
            Err(frame::Error::IncompleteData) => {
                let (pos, decoded) = decode!(src, |cur| PartialData::decode(cur));
                let (partial, frame) = decoded?;
                src.advance(pos);
                self.expected = None;
                self.partial = Some(partial);
                if frame.len() > 0 {
                    Ok(Some(HttpFrame::Data(frame)))
                } else {
                    Ok(None)
                }
            }
            Err(frame::Error::Incomplete(min)) => {
                self.expected = Some(min);
                Ok(None)
            }
            Err(e) => return Err(e.into()),
            Ok(frame) => {
                src.advance(pos);
                self.expected = None;
                Ok(Some(frame))
            }
        }
    }
}

pub struct WriteFrame {
    state: WriteFrameState,
    payload: Option<Bytes>,
}

enum WriteFrameState {
    Header(SendStream, Bytes),
    Payload(SendStream, Bytes),
    Finished,
}

impl WriteFrame {
    pub(crate) fn new<T>(send: SendStream, frame: T) -> Self
    where
        T: FrameHeader + IntoPayload,
    {
        let mut buf = Vec::with_capacity(VarInt::MAX.size() * 2);
        frame.encode_header(&mut buf);

        Self {
            payload: Some(frame.into_payload()),
            state: WriteFrameState::Header(send, buf.into()),
        }
    }

    pub fn reset(self, err_code: ErrorCode) {
        if let WriteFrameState::Header(mut s, _) | WriteFrameState::Payload(mut s, _) = self.state {
            s.reset(err_code.into());
        }
    }
}

impl Future for WriteFrame {
    type Output = Result<SendStream, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                WriteFrameState::Finished => panic!("polled after finished"),
                WriteFrameState::Header(ref mut send, ref mut h) => {
                    let wrote = ready!(Pin::new(send).poll_write(cx, h))?;
                    h.advance(wrote);
                    if h.is_empty() {
                        self.state = match mem::replace(&mut self.state, WriteFrameState::Finished)
                        {
                            WriteFrameState::Header(s, _) => {
                                WriteFrameState::Payload(s, self.payload.take().unwrap())
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                WriteFrameState::Payload(ref mut send, ref mut p) => {
                    let wrote = ready!(Pin::new(send).poll_write(cx, p))?;
                    p.advance(wrote);
                    let send = match mem::replace(&mut self.state, WriteFrameState::Finished) {
                        WriteFrameState::Payload(s, _) => s,
                        _ => unreachable!(),
                    };
                    self.state = WriteFrameState::Finished;
                    return Poll::Ready(Ok(send));
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Proto(frame::Error),
    Io(io::Error),
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Io(_) => ErrorCode::GENERAL_PROTOCOL_ERROR,
            Error::Proto(_) => ErrorCode::FRAME_ERROR,
        }
    }
}

impl From<frame::Error> for Error {
    fn from(err: frame::Error) -> Self {
        Error::Proto(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame;

    #[test]
    fn one_frame() {
        let frame = frame::HeadersFrame {
            encoded: b"salut"[..].into(),
        };

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(HttpFrame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = frame::HeadersFrame {
            encoded: b"salut"[..].into(),
        };

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf.into()), Ok(None));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let frames = [
            HttpFrame::Headers(frame::HeadersFrame {
                encoded: b"header"[..].into(),
            }),
            HttpFrame::Data(frame::DataFrame {
                payload: b"body"[..].into(),
            }),
            HttpFrame::Headers(frame::HeadersFrame {
                encoded: b"trailer"[..].into(),
            }),
        ];

        let mut buf = BytesMut::with_capacity(64);
        for frame in frames.iter() {
            frame.encode(&mut buf);
        }
        buf.truncate(buf.len() - 1);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(HttpFrame::Headers(_))));
        assert_matches!(decoder.decode(&mut buf), Ok(Some(HttpFrame::Data(_))));
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }
}
