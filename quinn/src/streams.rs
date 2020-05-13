use std::{
    future::Future,
    io,
    mem::MaybeUninit,
    pin::Pin,
    str,
    task::{Context, Poll},
};

use bytes::Bytes;
use err_derive::Error;
use futures::{
    channel::oneshot,
    io::{AsyncRead, AsyncWrite},
    ready, FutureExt,
};
use proto::{ConnectionError, StreamId};

use crate::{connection::ConnectionRef, VarInt};

/// A stream that can only be used to send data
///
/// If dropped, streams that haven't been explicitly `reset` will continue to (re)transmit
/// previously written data until it has been fully acknowledged or the connection is closed.
#[derive(Debug)]
pub struct SendStream<S>
where
    S: proto::crypto::Session,
{
    conn: ConnectionRef<S>,
    stream: StreamId,
    is_0rtt: bool,
    finishing: Option<oneshot::Receiver<Option<WriteError>>>,
}

impl<S> SendStream<S>
where
    S: proto::crypto::Session,
{
    pub(crate) fn new(conn: ConnectionRef<S>, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            finishing: None,
        }
    }

    /// Write bytes to the stream
    ///
    /// Yields the number of bytes written on success. Congestion and flow control may cause this to
    /// be shorter than `buf.len()`, indicating that only a prefix of `buf` was written.
    pub fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, S> {
        Write { stream: self, buf }
    }

    /// Convenience method to write an entire buffer to the stream
    pub fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> WriteAll<'a, S> {
        WriteAll { stream: self, buf }
    }

    fn poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, WriteError>> {
        use proto::WriteError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        if let Some(ref x) = conn.error {
            return Poll::Ready(Err(WriteError::ConnectionClosed(x.clone())));
        }
        let n = match conn.inner.write(self.stream, buf) {
            Ok(n) => n,
            Err(Blocked) => {
                conn.blocked_writers.insert(self.stream, cx.waker().clone());
                return Poll::Pending;
            }
            Err(Stopped(error_code)) => {
                return Poll::Ready(Err(WriteError::Stopped(error_code)));
            }
            Err(UnknownStream) => {
                return Poll::Ready(Err(WriteError::UnknownStream));
            }
        };
        conn.wake();
        Poll::Ready(Ok(n))
    }

    /// Shut down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub fn finish(&mut self) -> Finish<'_, S> {
        Finish { stream: self }
    }

    #[doc(hidden)]
    pub fn poll_finish(&mut self, cx: &mut Context) -> Poll<Result<(), WriteError>> {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        if self.finishing.is_none() {
            conn.inner.finish(self.stream).map_err(|e| match e {
                proto::FinishError::UnknownStream => WriteError::UnknownStream,
                proto::FinishError::Stopped(error_code) => WriteError::Stopped(error_code),
            })?;
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            conn.finishing.insert(self.stream, send);
            conn.wake();
        }
        match self
            .finishing
            .as_mut()
            .unwrap()
            .poll_unpin(cx)
            .map(|x| x.unwrap())
        {
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // To ensure that finished streams can be detected even after the connection is
                // closed, we must only check for connection errors after determining that the
                // stream has not yet been finished. Note that this relies on holding the connection
                // lock so that it is impossible for the stream to become finished between the above
                // poll call and this check.
                if let Some(ref x) = conn.error {
                    return Poll::Ready(Err(WriteError::ConnectionClosed(x.clone())));
                }
                Poll::Pending
            }
        }
    }

    /// Close the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped,
    /// and previously transmitted data will no longer be retransmitted if lost. If `poll_finish`
    /// was called previously and all data has already been transmitted at least once, the peer
    /// may still receive all written data.
    pub fn reset(&mut self, error_code: VarInt) {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return;
        }
        conn.inner.reset(self.stream, error_code);
        conn.wake();
    }

    #[doc(hidden)]
    pub fn id(&self) -> StreamId {
        self.stream
    }
}

impl<S> AsyncWrite for SendStream<S>
where
    S: proto::crypto::Session,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        SendStream::poll_write(self.get_mut(), cx, buf).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().poll_finish(cx).map_err(Into::into)
    }
}

impl<S> tokio::io::AsyncWrite for SendStream<S>
where
    S: proto::crypto::Session,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}

impl<S> Drop for SendStream<S>
where
    S: proto::crypto::Session,
{
    fn drop(&mut self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if self.finishing.is_none() {
            // Errors indicate that the stream was already finished or reset, which is fine.
            if conn.inner.finish(self.stream).is_ok() {
                conn.wake();
            }
        }
    }
}

/// Future produced by `SendStream::finish`
pub struct Finish<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut SendStream<S>,
}

impl<S> Future for Finish<'_, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<(), WriteError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.get_mut().stream.poll_finish(cx)
    }
}

/// A stream that can only be used to receive data
///
/// `stop(0)` is implicitly called on drop unless:
/// - `ReadError::Finished` has been emitted, or
/// - `stop` was called explicitly
#[derive(Debug)]
pub struct RecvStream<S>
where
    S: proto::crypto::Session,
{
    conn: ConnectionRef<S>,
    stream: StreamId,
    is_0rtt: bool,
    all_data_read: bool,
    any_data_read: bool,
}

impl<S> RecvStream<S>
where
    S: proto::crypto::Session,
{
    pub(crate) fn new(conn: ConnectionRef<S>, stream: StreamId, is_0rtt: bool) -> Self {
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
    /// Yields the number of bytes read into `buf` on success, or `None` if the stream was finished.
    ///
    /// Applications involving bulk data transfer should consider using unordered reads for
    /// improved performance.
    ///
    /// # Panics
    /// - If used after `read_unordered` on the same stream.
    ///   This is forbidden because an unordered read could consume a segment of data from a
    ///   location other than the start of the receive buffer, making it impossible for future
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, S> {
        Read { stream: self, buf }
    }

    /// Read an exact number of bytes contiguously from the stream.
    ///
    /// See `read` for details.
    pub fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, S> {
        ReadExact {
            stream: self,
            off: 0,
            buf,
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, ReadError>> {
        self.any_data_read = true;
        use proto::ReadError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }
        match conn.inner.read(self.stream, buf) {
            Ok(Some(n)) => {
                // Flow control credit may have been issued
                conn.wake();
                Poll::Ready(Ok(Some(n)))
            }
            Ok(None) => {
                self.all_data_read = true;
                Poll::Ready(Ok(None))
            }
            Err(Blocked) => {
                if let Some(ref x) = conn.error {
                    return Poll::Ready(Err(ReadError::ConnectionClosed(x.clone())));
                }
                conn.blocked_readers.insert(self.stream, cx.waker().clone());
                Poll::Pending
            }
            Err(Reset(error_code)) => {
                self.all_data_read = true;
                Poll::Ready(Err(ReadError::Reset(error_code)))
            }
            Err(UnknownStream) => Poll::Ready(Err(ReadError::UnknownStream)),
            Err(IllegalOrderedRead) => Poll::Ready(Err(ReadError::IllegalOrderedRead)),
        }
    }

    /// Read a segment of data from any offset in the stream.
    ///
    /// Yields a segment of data and their offset in the stream, or `None` if the stream was
    /// finished. Segments may be received in any order and may overlap.
    ///
    /// Unordered reads have reduced overhead and higher throughput, and should therefore be
    /// preferred when applicable.
    pub fn read_unordered(&mut self) -> ReadUnordered<'_, S> {
        ReadUnordered { stream: self }
    }

    fn poll_read_unordered(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Option<(Bytes, u64)>, ReadError>> {
        self.any_data_read = true;
        use proto::ReadError::*;
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }
        match conn.inner.read_unordered(self.stream) {
            Ok(Some((bytes, offset))) => {
                // Flow control credit may have been issued
                conn.wake();
                Poll::Ready(Ok(Some((bytes, offset))))
            }
            Ok(None) => {
                self.all_data_read = true;
                Poll::Ready(Ok(None))
            }
            Err(Blocked) => {
                if let Some(ref x) = conn.error {
                    return Poll::Ready(Err(ReadError::ConnectionClosed(x.clone())));
                }
                conn.blocked_readers.insert(self.stream, cx.waker().clone());
                Poll::Pending
            }
            Err(Reset(error_code)) => {
                self.all_data_read = true;
                Poll::Ready(Err(ReadError::Reset(error_code)))
            }
            Err(UnknownStream) => Poll::Ready(Err(ReadError::UnknownStream)),
            Err(IllegalOrderedRead) => Poll::Ready(Err(ReadError::IllegalOrderedRead)),
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
    pub fn read_to_end(self, size_limit: usize) -> ReadToEnd<S> {
        ReadToEnd {
            stream: self,
            size_limit,
            read: Vec::new(),
            start: u64::max_value(),
            end: 0,
        }
    }

    /// Stop accepting data
    ///
    /// Discards unread data and notifies the peer to stop transmitting. Once stopped, a stream
    /// cannot be read from any further.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), UnknownStream> {
        let mut conn = self.conn.lock().unwrap();
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return Ok(());
        }
        conn.inner.stop(self.stream, error_code)?;
        conn.wake();
        self.all_data_read = true;
        Ok(())
    }

    /// Check if this stream has been opened during 0-RTT.
    ///
    /// In which case any non-idempotent request should be considered dangerous at the application
    /// level. Because read data is subject to replay attacks.
    pub fn is_0rtt(&self) -> bool {
        self.is_0rtt
    }
}

/// Future produced by `read_to_end`
pub struct ReadToEnd<S>
where
    S: proto::crypto::Session,
{
    stream: RecvStream<S>,
    read: Vec<(Bytes, u64)>,
    start: u64,
    end: u64,
    size_limit: usize,
}

impl<S> Future for ReadToEnd<S>
where
    S: proto::crypto::Session,
{
    type Output = Result<Vec<u8>, ReadToEndError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match ready!(self.stream.poll_read_unordered(cx))? {
                Some((data, offset)) => {
                    self.start = self.start.min(offset);
                    let end = data.len() as u64 + offset;
                    if (end - self.start) > self.size_limit as u64 {
                        return Poll::Ready(Err(ReadToEndError::TooLong));
                    }
                    self.end = self.end.max(end);
                    self.read.push((data, offset));
                }
                None => {
                    if self.end == 0 {
                        // Never received anything
                        return Poll::Ready(Ok(Vec::new()));
                    }
                    let start = self.start;
                    let mut buffer = vec![0; (self.end - start) as usize];
                    for (data, offset) in self.read.drain(..) {
                        let offset = (offset - start) as usize;
                        buffer[offset..offset + data.len()].copy_from_slice(&data);
                    }
                    return Poll::Ready(Ok(buffer));
                }
            }
        }
    }
}

/// Error from the ReadToEnd future
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadToEndError {
    /// An error occurred during reading
    #[error(display = "read error: {}", 0)]
    Read(ReadError),
    /// The stream is larger than the user-supplied limit
    #[error(display = "stream too long")]
    TooLong,
}

impl From<ReadError> for ReadToEndError {
    fn from(x: ReadError) -> Self {
        ReadToEndError::Read(x)
    }
}

impl<S> AsyncRead for RecvStream<S>
where
    S: proto::crypto::Session,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(
            match ready!(RecvStream::poll_read(self.get_mut(), cx, buf))? {
                Some(n) => n,
                None => 0,
            },
        ))
    }
}

impl<S> tokio::io::AsyncRead for RecvStream<S>
where
    S: proto::crypto::Session,
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [MaybeUninit<u8>]) -> bool {
        false
    }

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        AsyncRead::poll_read(self, cx, buf)
    }
}

impl<S> Drop for RecvStream<S>
where
    S: proto::crypto::Session,
{
    fn drop(&mut self) {
        let mut conn = self.conn.lock().unwrap();
        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if !self.all_data_read {
            // Ignore UnknownStream errors
            let _ = conn.inner.stop(self.stream, 0u32.into());
            conn.wake();
        }
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream.
    ///
    /// Carries an application-defined error code.
    #[error(display = "stream reset by peer: error {}", 0)]
    Reset(VarInt),
    /// The connection was closed.
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
    /// Attempted an ordered read following an unordered read
    ///
    /// Performing an unordered read allows discontinuities to arise in the receive buffer of a
    /// stream which cannot be recovered, making further ordered reads impossible.
    #[error(display = "ordered read after unordered read")]
    IllegalOrderedRead,
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
            IllegalOrderedRead => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, x)
    }
}

/// Errors that arise from writing to a stream
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream.
    ///
    /// Carries an application-defined error code.
    #[error(display = "sending stopped by peer: error {}", 0)]
    Stopped(VarInt),
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
            Stopped(_) | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            UnknownStream => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, x)
    }
}

/// Future produced by `RecvStream::read`
pub struct Read<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut RecvStream<S>,
    buf: &'a mut [u8],
}

impl<'a, S> Future for Read<'a, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<Option<usize>, ReadError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read(cx, this.buf)
    }
}

/// Future produced by `RecvStream::read_exact`
pub struct ReadExact<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut RecvStream<S>,
    off: usize,
    buf: &'a mut [u8],
}

impl<'a, S> Future for ReadExact<'a, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<(), ReadExactError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        while this.buf.len() != this.off {
            let n: usize = ready!(this
                .stream
                .poll_read(cx, &mut this.buf[this.off..])
                .map_err(ReadExactError::ReadError)?)
            .ok_or(ReadExactError::FinishedEarly)?;
            this.off += n;
        }
        Poll::Ready(Ok(()))
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadExactError {
    /// The stream finished before all bytes were read
    #[error(display = "stream finished early")]
    FinishedEarly,
    /// A read error occurred
    #[error(display = "{}", 0)]
    ReadError(ReadError),
}

/// Future produced by `RecvStream::read_unordered`
pub struct ReadUnordered<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut RecvStream<S>,
}

impl<'a, S> Future for ReadUnordered<'a, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<Option<(Bytes, u64)>, ReadError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.stream.poll_read_unordered(cx)
    }
}

/// Future produced by `SendStream::write`
pub struct Write<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut SendStream<S>,
    buf: &'a [u8],
}

impl<'a, S> Future for Write<'a, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<usize, WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_write(cx, this.buf)
    }
}

/// Future produced by `SendStream::write_all`
pub struct WriteAll<'a, S>
where
    S: proto::crypto::Session,
{
    stream: &'a mut SendStream<S>,
    buf: &'a [u8],
}

impl<'a, S> Future for WriteAll<'a, S>
where
    S: proto::crypto::Session,
{
    type Output = Result<(), WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if this.buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = ready!(this.stream.poll_write(cx, this.buf))?;
            this.buf = &this.buf[n..];
        }
    }
}

#[derive(Debug)]
pub struct UnknownStream {}

impl From<proto::UnknownStream> for UnknownStream {
    fn from(_: proto::UnknownStream) -> Self {
        UnknownStream {}
    }
}
