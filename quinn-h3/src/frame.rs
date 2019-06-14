use std::io;

use bytes::BytesMut;
use quinn::RecvStream;
use tokio_codec::{Decoder, FramedRead};
use tokio_io::AsyncRead;

use super::proto::frame::{self, HttpFrame};

pub type FrameStream = FramedRead<RecvStream, FrameDecoder>;

#[derive(Default)]
pub struct FrameDecoder {
    expected: Option<usize>,
}

impl FrameDecoder {
    pub fn stream<T: AsyncRead>(stream: T) -> FramedRead<T, Self> {
        FramedRead::new(stream, FrameDecoder { expected: None })
    }
}

impl Decoder for FrameDecoder {
    type Item = HttpFrame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() == 0 {
            return Ok(None);
        }
        if let Some(min) = self.expected {
            if src.len() < min {
                return Ok(None);
            }
        }

        let (pos, decoded) = {
            let mut cur = io::Cursor::new(&src);
            let decoded = HttpFrame::decode(&mut cur);
            (cur.position() as usize, decoded)
        };

        match decoded {
            Err(frame::Error::Incomplete(min)) => {
                self.expected = Some(min);
                Ok(None)
            }
            Err(e) => Err(e)?,
            Ok(frame) => {
                src.advance(pos);
                Ok(Some(frame))
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
