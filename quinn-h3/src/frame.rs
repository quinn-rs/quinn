use std::io;

use bytes::{Buf, BytesMut};
use quinn::RecvStream;
use tokio::io::AsyncRead;
use tokio_util::codec::{Decoder, FramedRead};

use super::proto::frame::{self, FrameHeader, HttpFrame, PartialData};
use crate::{proto::ErrorCode, streams::Reset};

pub type FrameStream = FramedRead<RecvStream, FrameDecoder>;

impl Reset for FrameStream {
    fn reset(&mut self, error_code: ErrorCode) {
        let _ = self.get_mut().stop(error_code.0.into());
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    partial: Option<PartialData>,
    expected: Option<usize>,
}

impl FrameDecoder {
    pub fn stream<T: AsyncRead>(stream: T) -> FramedRead<T, Self> {
        FramedRead::with_capacity(
            stream,
            FrameDecoder {
                expected: None,
                partial: None,
            },
            65535,
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
            Err(frame::Error::UnknownFrame(_)) => {
                src.advance(pos);
                self.expected = None;
                Ok(None)
            }
            Err(frame::Error::Incomplete(min)) => {
                self.expected = Some(min);
                Ok(None)
            }
            Err(e) => Err(e.into()),
            Ok(frame) => {
                src.advance(pos);
                self.expected = None;
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

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Io(_) => ErrorCode::GENERAL_PROTOCOL_ERROR,
            Error::Proto(frame::Error::Settings(_)) => ErrorCode::SETTINGS_ERROR,
            Error::Proto(frame::Error::UnsupportedFrame(_)) => ErrorCode::FRAME_UNEXPECTED,
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
        assert_matches!(decoder.decode(&mut buf), Ok(None));
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
