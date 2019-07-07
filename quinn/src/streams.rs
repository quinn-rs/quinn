use std::io;
use std::str;

use bytes::Bytes;
use err_derive::Error;
use futures::sync::oneshot;
use futures::{task, try_ready};
use futures::{Async, Future, Poll};
use proto::{ConnectionError, StreamId};
use tokio_io::{AsyncRead, AsyncWrite};

use crate::connection::ConnectionRef;

/// A stream initiated by a remote peer.
pub enum NewStream {
    /// A unidirectional stream.
    Uni(RecvStream),
    /// A bidirectional stream.
    Bi(SendStream, RecvStream),
}

impl NewStream {
    /// Assume this is a unidirectional stream
    ///
    /// Panics if this is actually a bidirectional stream. Useful if the behavior of the peer is
    /// guaranteed, e.g. by setting `TransportConfig::stream_window_bidi` to 0.
    pub fn unwrap_uni(self) -> RecvStream {
        match self {
            NewStream::Uni(x) => x,
            NewStream::Bi(_, _) => panic!("unexpected bidirectional stream"),
        }
    }

    /// Assume this is a bidirectional stream
    ///
    /// Panics if this is actually a unidirectional stream. Useful if the behavior of the peer is
    /// guaranteed, e.g. by setting `TransportConfig::stream_window_uni` to 0.
    pub fn unwrap_bi(self) -> (SendStream, RecvStream) {
        match self {
            NewStream::Uni(_) => panic!("unexpected unirectional stream"),
            NewStream::Bi(x, y) => (x, y),
        }
    }
}

/// A stream that can only be used to send data
///
/// If dropped, streams that haven't been explicitly `reset` will continue to (re)transmit
/// previously written data until it has been fully acknowledged or the connection is closed.
pub struct SendStream {
    conn: ConnectionRef,
    stream: StreamId,
    is_0rtt: bool,
    finishing: Option<oneshot::Receiver<Option<WriteError>>>,
    finished: bool,
}

impl SendStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            finishing: None,
            finished: false,
        }
    }

    /// Write bytes to the stream.
    ///
    /// Returns the number of bytes written on success. Congestion and flow control may cause this
    /// to be shorter than `buf.len()`, indicating that only a prefix of `buf` was written.
    pub fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> {
        use proto::WriteError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        let n = match conn.inner.write(self.stream, buf) {
            Ok(n) => n,
            Err(Blocked) => {
                if let Some(ref x) = conn.error {
                    return Err(WriteError::ConnectionClosed(x.clone()));
                }
                conn.blocked_writers.insert(self.stream, task::current());
                return Ok(Async::NotReady);
            }
            Err(Stopped { error_code }) => {
                return Err(WriteError::Stopped { error_code });
            }
            Err(UnknownStream) => {
                return Err(WriteError::UnknownStream);
            }
        };
        conn.notify();
        Ok(Async::Ready(n))
    }

    /// Shut down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub fn poll_finish(&mut self) -> Poll<(), WriteError> {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        if self.finishing.is_none() {
            conn.inner.finish(self.stream).map_err(|e| match e {
                proto::FinishError::UnknownStream => WriteError::UnknownStream,
                proto::FinishError::Stopped { error_code } => WriteError::Stopped { error_code },
            })?;
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            conn.finishing.insert(self.stream, send);
            conn.notify();
        }
        let r = self.finishing.as_mut().unwrap().poll().unwrap();
        match r {
            Async::Ready(None) => {
                self.finished = true;
                Ok(Async::Ready(()))
            }
            Async::Ready(Some(e)) => Err(e),
            Async::NotReady => Ok(Async::NotReady),
        }
    }

    /// Shut down the stream gracefully
    ///
    /// See `poll_finish` for details.
    pub fn finish(self) -> Finish {
        Finish { stream: self }
    }

    /// Close the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped,
    /// and previously transmitted data will no longer be retransmitted if lost. If `poll_finish`
    /// was called previously and all data has already been transmitted at least once, the peer
    /// may still receive all written data.
    pub fn reset(&mut self, error_code: u64) {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return;
        }
        conn.inner.reset(self.stream, error_code);
        conn.notify();
    }

    #[doc(hidden)]
    pub fn id(&self) -> StreamId {
        self.stream
    }
}

impl io::Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.poll_write(buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(e) => Err(e.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for SendStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.poll_finish().map_err(Into::into)
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if !self.finished && self.finishing.is_none() {
            // Errors indicate that the stream was already reset, which is fine.
            if conn.inner.finish(self.stream).is_ok() {
                conn.notify();
            }
        }
    }
}

/// Future produced by `SendStream::finish`
pub struct Finish {
    stream: SendStream,
}

impl Future for Finish {
    type Item = ();
    type Error = WriteError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.stream.poll_finish()
    }
}

/// A stream that can only be used to receive data
///
/// `stop(0)` is implicitly called on drop unless:
/// - `ReadError::Finished` has been emitted, or
/// - `stop` was called explicitly
pub struct RecvStream {
    conn: ConnectionRef,
    stream: StreamId,
    is_0rtt: bool,
    all_data_read: bool,
    any_data_read: bool,
}

impl RecvStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            all_data_read: false,
            any_data_read: false,
        }
    }

    /// Read data contiguously from the stream.
    ///
    /// Returns the number of bytes read into `buf` on success, or `None` if the stream was
    /// finished.
    ///
    /// Applications involving bulk data transfer should consider using unordered reads for
    /// improved performance.
    ///
    /// # Panics
    /// - If called after `poll_read_unordered` was called on the same stream.
    ///   This is forbidden because an unordered read could consume a segment of data from a
    ///   location other than the start of the receive buffer, making it impossible for future
    pub fn poll_read(&mut self, buf: &mut [u8]) -> Poll<Option<usize>, ReadError> {
        self.any_data_read = true;
        use proto::ReadError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }
        match conn.inner.read(self.stream, buf) {
            Ok(Some(n)) => Ok(Async::Ready(Some(n))),
            Ok(None) => {
                self.all_data_read = true;
                Ok(Async::Ready(None))
            }
            Err(Blocked) => {
                if let Some(ref x) = conn.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                conn.blocked_readers.insert(self.stream, task::current());
                Ok(Async::NotReady)
            }
            Err(Reset { error_code }) => {
                self.all_data_read = true;
                Err(ReadError::Reset { error_code })
            }
            Err(UnknownStream) => Err(ReadError::UnknownStream),
        }
    }

    /// Read a segment of data from any offset in the stream.
    ///
    /// Returns a segment of data and their offset in the stream, or `None` if the stream was
    /// finished. Segments may be received in any order and may overlap.
    ///
    /// Unordered reads have reduced overhead and higher throughput, and should therefore be
    /// preferred when applicable.
    pub fn poll_read_unordered(&mut self) -> Poll<Option<(Bytes, u64)>, ReadError> {
        self.any_data_read = true;
        use proto::ReadError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }
        match conn.inner.read_unordered(self.stream) {
            Ok(Some((bytes, offset))) => Ok(Async::Ready(Some((bytes, offset)))),
            Ok(None) => {
                self.all_data_read = true;
                Ok(Async::Ready(None))
            }
            Err(Blocked) => {
                if let Some(ref x) = conn.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                conn.blocked_readers.insert(self.stream, task::current());
                Ok(Async::NotReady)
            }
            Err(Reset { error_code }) => {
                self.all_data_read = true;
                Err(ReadError::Reset { error_code })
            }
            Err(UnknownStream) => Err(ReadError::UnknownStream),
        }
    }

    /// Convenience method to read all remaining data into a buffer
    ///
    /// The returned future fails with `ReadToEnd::TooLong` if it's longer than `size_limit`
    /// bytes. Uses unordered reads to be more efficient than using `AsyncRead` would
    /// allow. `size_limit` should be set to limit worst-case memory use.
    ///
    /// If unordered reads have already been made, the resulting buffer may have gaps containing
    /// arbitrary data.
    pub fn read_to_end(self, size_limit: usize) -> ReadToEnd {
        ReadToEnd {
            stream: self,
            size_limit,
            read: Vec::new(),
            start: u64::max_value(),
            end: 0,
        }
    }

    /// Close the receive stream immediately.
    ///
    /// The peer is notified and will cease transmitting on this stream, as if it had reset the
    /// stream itself. Further data may still be received on this stream if it was already in
    /// flight. Once called, a `ReadError::Reset` should be expected soon, although a peer might
    /// manage to finish the stream before it receives the reset, and a misbehaving peer might
    /// ignore the request entirely and continue sending until halted by flow control.
    ///
    /// Has no effect if the incoming stream already finished, even if the local application hasn't
    /// yet read all buffered data.
    pub fn stop(&mut self, error_code: u64) {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return;
        }
        conn.inner.stop_sending(self.stream, error_code);
        conn.notify();
        self.all_data_read = true;
    }
}

/// Future produced by `read_to_end`
pub struct ReadToEnd {
    stream: RecvStream,
    read: Vec<(Bytes, u64)>,
    start: u64,
    end: u64,
    size_limit: usize,
}

impl Future for ReadToEnd {
    type Item = Vec<u8>;
    type Error = ReadToEndError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match try_ready!(self.stream.poll_read_unordered()) {
                Some((data, offset)) => {
                    self.start = self.start.min(offset);
                    let end = data.len() as u64 + offset;
                    if (end - self.start) > self.size_limit as u64 {
                        return Err(ReadToEndError::TooLong);
                    }
                    self.end = self.end.max(end);
                    self.read.push((data, offset));
                }
                None => {
                    let mut buffer = vec![0; (self.end - self.start) as usize];
                    for (data, offset) in self.read.drain(..) {
                        let offset = (offset - self.start) as usize;
                        buffer[offset..offset + data.len()].copy_from_slice(&data);
                    }
                    return Ok(Async::Ready(buffer));
                }
            }
        }
    }
}

/// Error from the ReadToEnd future
#[derive(Debug, Error)]
pub enum ReadToEndError {
    /// An error occurred during reading
    #[error(display = "read error")]
    Read(ReadError),
    /// The stream is larger than the user-supplied limit
    #[error(display = "stream too long")]
    TooLong,
}

impl From<ReadError> for ReadToEndError {
    fn from(e: ReadError) -> ReadToEndError {
        ReadToEndError::Read(e)
    }
}

impl io::Read for RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.poll_read(buf) {
            Ok(Async::Ready(Some(n))) => Ok(n),
            Ok(Async::Ready(None)) => Ok(0),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(e) => Err(e.into()),
        }
    }
}

impl AsyncRead for RecvStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if !self.all_data_read {
            conn.inner.stop_sending(self.stream, 0);
            conn.notify();
        }
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream.
    #[error(display = "stream reset by peer: error {}", error_code)]
    Reset {
        /// The error code supplied by the peer.
        error_code: u64,
    },
    /// The connection was closed.
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
    /// This was a 0-RTT stream and the server rejected it.
    ///
    /// Can only occur on clients for 0-RTT streams (opened using `Connecting::into_0rtt()`).
    #[error(display = "0-RTT rejected")]
    ZeroRttRejected,
}

impl From<ReadError> for io::Error {
    fn from(x: ReadError) -> Self {
        use self::ReadError::*;
        let kind = match x {
            ConnectionClosed(e) => {
                return e.into();
            }
            Reset { .. } | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            UnknownStream => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, x)
    }
}

/// Errors that arise from writing to a stream
#[derive(Debug, Error, Clone)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream.
    #[error(display = "sending stopped by peer: error {}", error_code)]
    Stopped {
        /// The error code supplied by the peer.
        error_code: u64,
    },
    /// The connection was closed.
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
    /// This was a 0-RTT stream and the server rejected it.
    ///
    /// Can only occur on clients for 0-RTT streams (opened using `Connecting::into_0rtt()`).
    #[error(display = "0-RTT rejected")]
    ZeroRttRejected,
}

impl From<WriteError> for io::Error {
    fn from(x: WriteError) -> Self {
        use self::WriteError::*;
        let kind = match x {
            ConnectionClosed(e) => {
                return e.into();
            }
            Stopped { .. } | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            UnknownStream => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, x)
    }
}
