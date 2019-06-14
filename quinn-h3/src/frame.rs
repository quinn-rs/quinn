use std::io;

use bytes::BytesMut;
use futures::{Async, Poll, Stream};
use tokio_io::AsyncRead;

use super::proto::frame::{self, HttpFrame};

pub struct FrameStream<R> {
    recv: R,
    buf: BytesMut,
    finished: bool,
}

impl<R> FrameStream<R>
where
    R: AsyncRead,
{
    const READ_SIZE: usize = 1024 * 10;

    pub(crate) fn new(recv: R) -> Self {
        Self {
            recv,
            buf: BytesMut::new(),
            finished: false,
        }
    }
}

impl<R> Stream for FrameStream<R>
where
    R: AsyncRead,
{
    type Item = HttpFrame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.finished {
            // TODO this resizing is fairly ineficient
            self.buf.resize(self.buf.len() + Self::READ_SIZE, 0);
            let start = self.buf.len() - Self::READ_SIZE;

            let size = match self.recv.poll_read(&mut self.buf[start..])? {
                Async::NotReady => 0,
                Async::Ready(size) => {
                    if size == 0 {
                        self.finished = true;
                    }
                    size
                }
            };
            self.buf.truncate(self.buf.len() - Self::READ_SIZE + size);
        } else if self.buf.len() == 0 {
            return Ok(Async::Ready(None));
        }

        let (pos, decoded) = {
            let mut cur = io::Cursor::new(&mut self.buf);
            let decoded = HttpFrame::decode(&mut cur);
            (cur.position() as usize, decoded)
        };

        match decoded {
            Err(frame::Error::Incomplete(_)) => match self.buf.len() {
                Self::READ_SIZE => Err(Error::Overflow),
                _ => Ok(Async::NotReady),
            },
            Err(e) => Err(e)?,
            Ok(f) => {
                self.buf.advance(pos);
                Ok(Async::Ready(Some(f)))
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Overflow,
    Proto(frame::Error),
    Io(std::io::Error),
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
    use tokio_mockstream::MockStream;

    use super::*;
    use crate::proto::frame;

    #[test]
    fn one_frame() {
        let frame = frame::HeadersFrame {
            encoded: b"salut"[..].into(),
        };
        let mut buf = vec![];
        frame.encode(&mut buf);
        let mut reader = FrameStream::new(MockStream::new(&buf));
        assert_matches!(reader.poll(), Ok(Async::Ready(Some(HttpFrame::Headers(_)))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = frame::HeadersFrame {
            encoded: b"salut"[..].into(),
        };
        let mut buf = vec![];
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut reader = FrameStream::new(MockStream::new(&buf));
        assert_matches!(reader.poll(), Ok(Async::NotReady));
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
        let mut buf = vec![];
        for frame in frames.iter() {
            frame.encode(&mut buf);
        }
        buf.truncate(buf.len() - 1);
        let mut reader = FrameStream::new(MockStream::new(&buf));
        assert_matches!(reader.poll(), Ok(Async::Ready(Some(HttpFrame::Headers(_)))));
        assert_matches!(reader.poll(), Ok(Async::Ready(Some(HttpFrame::Data(_)))));
        assert_matches!(reader.poll(), Ok(Async::NotReady));
    }

    #[test]
    fn frame_too_big() {
        let frame = frame::HeadersFrame {
            encoded: [0u8; FrameStream::<MockStream>::READ_SIZE][..].into(),
        };
        let mut buf = vec![];
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut reader = FrameStream::new(MockStream::new(&buf));
        assert_matches!(reader.poll(), Err(Error::Overflow));
    }

}
