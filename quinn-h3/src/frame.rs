use std::io;

use bytes::{Bytes, BytesMut};
use futures::{try_ready, Async, Future, Poll};
use quinn::{RecvStream, SendStream, VarInt};
use tokio_codec::{Decoder, FramedRead};
use tokio_io::{io::WriteAll, AsyncRead};

use super::proto::frame::{self, DataFrame, FrameHeader, HttpFrame, PartialData};

pub type FrameStream = FramedRead<RecvStream, FrameDecoder>;

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
        if src.len() == 0 {
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
            Err(e) => Err(e)?,
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
    Header(WriteAll<SendStream, Bytes>),
    Payload(WriteAll<SendStream, Bytes>),
    Finished,
}

impl WriteFrame {
    pub fn new(send: SendStream, frame: DataFrame) -> Self {
        let mut buf = Vec::with_capacity(VarInt::MAX.size() * 2);
        frame.encode_header(&mut buf);

        Self {
            state: WriteFrameState::Header(tokio_io::io::write_all(send, buf.into())),
            payload: Some(frame.payload),
        }
    }
}

impl Future for WriteFrame {
    type Item = SendStream;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                WriteFrameState::Finished => panic!(),
                WriteFrameState::Header(ref mut write) => {
                    let (send, _) = try_ready!(write.poll());
                    self.state = WriteFrameState::Payload(tokio_io::io::write_all(
                        send,
                        self.payload.take().unwrap(),
                    ));
                }
                WriteFrameState::Payload(ref mut write) => {
                    let (send, _) = try_ready!(write.poll());
                    self.state = WriteFrameState::Finished;
                    return Ok(Async::Ready(send));
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
