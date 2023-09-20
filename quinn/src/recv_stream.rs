use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use proto::{Chunk, Chunks, ConnectionError, ReadableError, StreamId};
use thiserror::Error;
use tokio::io::ReadBuf;

use crate::{
    connection::{ConnectionRef, UnknownStream},
    VarInt,
};

/// A stream that can only be used to receive data
///
/// `stop(0)` is implicitly called on drop unless:
/// - A variant of [`ReadError`] has been yielded by a read call
/// - [`stop()`] was called explicitly
///
/// # Closing a stream
///
/// When a stream is expected to be closed gracefully the sender should call
/// [`SendStream::finish`].  However there is no guarantee the connected [`RecvStream`] will
/// receive the "finished" notification in the same QUIC frame as the last frame which
/// carried data.
///
/// Even if the application layer logic already knows it read all the data because it does
/// its own framing, it should still read until it reaches the end of the [`RecvStream`].
/// Otherwise it risks inadvertently calling [`RecvStream::stop`] if it drops the stream.
/// And calling [`RecvStream::stop`] could result in the connected [`SendStream::finish`]
/// call failing with a [`WriteError::Stopped`] error.
///
/// For example if exactly 10 bytes are to be read, you still need to explicitly read the
/// end of the stream:
///
/// ```no_run
/// # use quinn::{SendStream, RecvStream};
/// # async fn func(
/// #     mut send_stream: SendStream,
/// #     mut recv_stream: RecvStream,
/// # ) -> anyhow::Result<()>
/// # {
/// // In the sending task
/// send_stream.write(&b"0123456789"[..]).await?;
/// send_stream.finish().await?;
///
/// // In the receiving task
/// let mut buf = [0u8; 10];
/// let data = recv_stream.read_exact(&mut buf).await?;
/// if recv_stream.read_to_end(0).await.is_err() {
///     // Discard unexpected data and notify the peer to stop sending it
///     let _ = recv_stream.stop(0u8.into());
/// }
/// # Ok(())
/// # }
/// ```
///
/// An alternative approach, used in HTTP/3, is to specify a particular error code used with `stop`
/// that indicates graceful receiver-initiated stream shutdown, rather than a true error condition.
///
/// [`RecvStream::read_chunk`] could be used instead which does not take ownership and
/// allows using an explicit call to [`RecvStream::stop`] with a custom error code.
///
/// [`ReadError`]: crate::ReadError
/// [`stop()`]: RecvStream::stop
/// [`SendStream::finish`]: crate::SendStream::finish
/// [`WriteError::Stopped`]: crate::WriteError::Stopped
#[derive(Debug)]
pub struct RecvStream {
    conn: ConnectionRef,
    stream: StreamId,
    is_0rtt: bool,
    all_data_read: bool,
    reset: Option<VarInt>,
}

impl RecvStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
        Self {
            conn,
            stream,
            is_0rtt,
            all_data_read: false,
            reset: None,
        }
    }

    /// Read data contiguously from the stream.
    ///
    /// Yields the number of bytes read into `buf` on success, or `None` if the stream was finished.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        Read {
            stream: self,
            buf: ReadBuf::new(buf),
        }
        .await
    }

    /// Read an exact number of bytes contiguously from the stream.
    ///
    /// See [`read()`] for details.
    ///
    /// [`read()`]: RecvStream::read
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        ReadExact {
            stream: self,
            buf: ReadBuf::new(buf),
        }
        .await
    }

    fn poll_read(
        &mut self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), ReadError>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        self.poll_read_generic(cx, true, |chunks| {
            let mut read = false;
            loop {
                if buf.remaining() == 0 {
                    // We know `read` is `true` because `buf.remaining()` was not 0 before
                    return ReadStatus::Readable(());
                }

                match chunks.next(buf.remaining()) {
                    Ok(Some(chunk)) => {
                        buf.put_slice(&chunk.bytes);
                        read = true;
                    }
                    res => return (if read { Some(()) } else { None }, res.err()).into(),
                }
            }
        })
        .map(|res| res.map(|_| ()))
    }

    /// Read the next segment of data
    ///
    /// Yields `None` if the stream was finished. Otherwise, yields a segment of data and its
    /// offset in the stream. If `ordered` is `true`, the chunk's offset will be immediately after
    /// the last data yielded by `read()` or `read_chunk()`. If `ordered` is `false`, segments may
    /// be received in any order, and the `Chunk`'s `offset` field can be used to determine
    /// ordering in the caller. Unordered reads are less prone to head-of-line blocking within a
    /// stream, but require the application to manage reassembling the original data.
    ///
    /// Slightly more efficient than `read` due to not copying. Chunk boundaries do not correspond
    /// to peer writes, and hence cannot be used as framing.
    pub async fn read_chunk(
        &mut self,
        max_length: usize,
        ordered: bool,
    ) -> Result<Option<Chunk>, ReadError> {
        ReadChunk {
            stream: self,
            max_length,
            ordered,
        }
        .await
    }

    /// Foundation of [`Self::read_chunk`]
    fn poll_read_chunk(
        &mut self,
        cx: &mut Context,
        max_length: usize,
        ordered: bool,
    ) -> Poll<Result<Option<Chunk>, ReadError>> {
        self.poll_read_generic(cx, ordered, |chunks| match chunks.next(max_length) {
            Ok(Some(chunk)) => ReadStatus::Readable(chunk),
            res => (None, res.err()).into(),
        })
    }

    /// Read the next segments of data
    ///
    /// Fills `bufs` with the segments of data beginning immediately after the
    /// last data yielded by `read` or `read_chunk`, or `None` if the stream was
    /// finished.
    ///
    /// Slightly more efficient than `read` due to not copying. Chunk boundaries
    /// do not correspond to peer writes, and hence cannot be used as framing.
    pub async fn read_chunks(&mut self, bufs: &mut [Bytes]) -> Result<Option<usize>, ReadError> {
        ReadChunks { stream: self, bufs }.await
    }

    /// Foundation of [`Self::read_chunks`]
    fn poll_read_chunks(
        &mut self,
        cx: &mut Context,
        bufs: &mut [Bytes],
    ) -> Poll<Result<Option<usize>, ReadError>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(Some(0)));
        }

        self.poll_read_generic(cx, true, |chunks| {
            let mut read = 0;
            loop {
                if read >= bufs.len() {
                    // We know `read > 0` because `bufs` cannot be empty here
                    return ReadStatus::Readable(read);
                }

                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => {
                        bufs[read] = chunk.bytes;
                        read += 1;
                    }
                    res => return (if read == 0 { None } else { Some(read) }, res.err()).into(),
                }
            }
        })
    }

    /// Convenience method to read all remaining data into a buffer
    ///
    /// Fails with [`ReadToEndError::TooLong`] on reading more than `size_limit` bytes, discarding
    /// all data read. Uses unordered reads to be more efficient than using `AsyncRead` would
    /// allow. `size_limit` should be set to limit worst-case memory use.
    ///
    /// If unordered reads have already been made, the resulting buffer may have gaps containing
    /// arbitrary data.
    ///
    /// [`ReadToEndError::TooLong`]: crate::ReadToEndError::TooLong
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        ReadToEnd {
            stream: self,
            size_limit,
            read: Vec::new(),
            start: u64::max_value(),
            end: 0,
        }
        .await
    }

    /// Stop accepting data
    ///
    /// Discards unread data and notifies the peer to stop transmitting. Once stopped, further
    /// attempts to operate on a stream will yield `UnknownStream` errors.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), UnknownStream> {
        let mut conn = self.conn.state.lock("RecvStream::stop");
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return Ok(());
        }
        conn.inner.recv_stream(self.stream).stop(error_code)?;
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

    /// Get the identity of this stream
    pub fn id(&self) -> StreamId {
        self.stream
    }

    /// Handle common logic related to reading out of a receive stream
    ///
    /// This takes an `FnMut` closure that takes care of the actual reading process, matching
    /// the detailed read semantics for the calling function with a particular return type.
    /// The closure can read from the passed `&mut Chunks` and has to return the status after
    /// reading: the amount of data read, and the status after the final read call.
    fn poll_read_generic<T, U>(
        &mut self,
        cx: &mut Context,
        ordered: bool,
        mut read_fn: T,
    ) -> Poll<Result<Option<U>, ReadError>>
    where
        T: FnMut(&mut Chunks) -> ReadStatus<U>,
    {
        use proto::ReadError::*;
        if self.all_data_read {
            return Poll::Ready(Ok(None));
        }

        let mut conn = self.conn.state.lock("RecvStream::poll_read");
        if self.is_0rtt {
            conn.check_0rtt().map_err(|()| ReadError::ZeroRttRejected)?;
        }

        // If we stored an error during a previous call, return it now. This can happen if a
        // `read_fn` both wants to return data and also returns an error in its final stream status.
        let status = match self.reset.take() {
            Some(code) => ReadStatus::Failed(None, Reset(code)),
            None => {
                let mut recv = conn.inner.recv_stream(self.stream);
                let mut chunks = recv.read(ordered)?;
                let status = read_fn(&mut chunks);
                if chunks.finalize().should_transmit() {
                    conn.wake();
                }
                status
            }
        };

        match status {
            ReadStatus::Readable(read) => Poll::Ready(Ok(Some(read))),
            ReadStatus::Finished(read) => {
                self.all_data_read = true;
                Poll::Ready(Ok(read))
            }
            ReadStatus::Failed(read, Blocked) => match read {
                Some(val) => Poll::Ready(Ok(Some(val))),
                None => {
                    if let Some(ref x) = conn.error {
                        return Poll::Ready(Err(ReadError::ConnectionLost(x.clone())));
                    }
                    conn.blocked_readers.insert(self.stream, cx.waker().clone());
                    Poll::Pending
                }
            },
            ReadStatus::Failed(read, Reset(error_code)) => match read {
                None => {
                    self.all_data_read = true;
                    Poll::Ready(Err(ReadError::Reset(error_code)))
                }
                done => {
                    self.reset = Some(error_code);
                    Poll::Ready(Ok(done))
                }
            },
        }
    }
}

enum ReadStatus<T> {
    Readable(T),
    Finished(Option<T>),
    Failed(Option<T>, proto::ReadError),
}

impl<T> From<(Option<T>, Option<proto::ReadError>)> for ReadStatus<T> {
    fn from(status: (Option<T>, Option<proto::ReadError>)) -> Self {
        match status {
            (read, None) => Self::Finished(read),
            (read, Some(e)) => Self::Failed(read, e),
        }
    }
}

/// Future produced by [`RecvStream::read_to_end()`].
///
/// [`RecvStream::read_to_end()`]: crate::RecvStream::read_to_end
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct ReadToEnd<'a> {
    stream: &'a mut RecvStream,
    read: Vec<(Bytes, u64)>,
    start: u64,
    end: u64,
    size_limit: usize,
}

impl Future for ReadToEnd<'_> {
    type Output = Result<Vec<u8>, ReadToEndError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match ready!(self.stream.poll_read_chunk(cx, usize::MAX, false))? {
                Some(chunk) => {
                    self.start = self.start.min(chunk.offset);
                    let end = chunk.bytes.len() as u64 + chunk.offset;
                    if (end - self.start) > self.size_limit as u64 {
                        return Poll::Ready(Err(ReadToEndError::TooLong));
                    }
                    self.end = self.end.max(end);
                    self.read.push((chunk.bytes, chunk.offset));
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

/// Errors from [`RecvStream::read_to_end`]
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadToEndError {
    /// An error occurred during reading
    #[error("read error: {0}")]
    Read(#[from] ReadError),
    /// The stream is larger than the user-supplied limit
    #[error("stream too long")]
    TooLong,
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(buf);
        ready!(RecvStream::poll_read(self.get_mut(), cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(Self::poll_read(self.get_mut(), cx, buf))?;
        Poll::Ready(Ok(()))
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let mut conn = self.conn.state.lock("RecvStream::drop");

        // clean up any previously registered wakers
        conn.blocked_readers.remove(&self.stream);

        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if !self.all_data_read {
            // Ignore UnknownStream errors
            let _ = conn.inner.recv_stream(self.stream).stop(0u32.into());
            conn.wake();
        }
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream
    ///
    /// Carries an application-defined error code.
    #[error("stream reset by peer: error {0}")]
    Reset(VarInt),
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been stopped, finished, or reset
    #[error("unknown stream")]
    UnknownStream,
    /// Attempted an ordered read following an unordered read
    ///
    /// Performing an unordered read allows discontinuities to arise in the receive buffer of a
    /// stream which cannot be recovered, making further ordered reads impossible.
    #[error("ordered read after unordered read")]
    IllegalOrderedRead,
    /// This was a 0-RTT stream and the server rejected it
    ///
    /// Can only occur on clients for 0-RTT streams, which can be opened using
    /// [`Connecting::into_0rtt()`].
    ///
    /// [`Connecting::into_0rtt()`]: crate::Connecting::into_0rtt()
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

impl From<ReadableError> for ReadError {
    fn from(e: ReadableError) -> Self {
        match e {
            ReadableError::UnknownStream => Self::UnknownStream,
            ReadableError::IllegalOrderedRead => Self::IllegalOrderedRead,
        }
    }
}

impl From<ReadError> for io::Error {
    fn from(x: ReadError) -> Self {
        use self::ReadError::*;
        let kind = match x {
            Reset { .. } | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            ConnectionLost(_) | UnknownStream => io::ErrorKind::NotConnected,
            IllegalOrderedRead => io::ErrorKind::InvalidInput,
        };
        Self::new(kind, x)
    }
}

/// Future produced by [`RecvStream::read()`].
///
/// [`RecvStream::read()`]: crate::RecvStream::read
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct Read<'a> {
    stream: &'a mut RecvStream,
    buf: ReadBuf<'a>,
}

impl<'a> Future for Read<'a> {
    type Output = Result<Option<usize>, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        ready!(this.stream.poll_read(cx, &mut this.buf))?;
        match this.buf.filled().len() {
            0 if this.buf.capacity() != 0 => Poll::Ready(Ok(None)),
            n => Poll::Ready(Ok(Some(n))),
        }
    }
}

/// Future produced by [`RecvStream::read_exact()`].
///
/// [`RecvStream::read_exact()`]: crate::RecvStream::read_exact
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct ReadExact<'a> {
    stream: &'a mut RecvStream,
    buf: ReadBuf<'a>,
}

impl<'a> Future for ReadExact<'a> {
    type Output = Result<(), ReadExactError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let total = this.buf.remaining();
        let mut remaining = total;
        while remaining > 0 {
            ready!(this.stream.poll_read(cx, &mut this.buf))?;
            let new = this.buf.remaining();
            if new == remaining {
                let read = total - remaining;
                return Poll::Ready(Err(ReadExactError::FinishedEarly(read)));
            }
            remaining = new;
        }
        Poll::Ready(Ok(()))
    }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadExactError {
    /// The stream finished before all bytes were read
    #[error("stream finished early ({0} bytes read)")]
    FinishedEarly(usize),
    /// A read error occurred
    #[error(transparent)]
    ReadError(#[from] ReadError),
}

/// Future produced by [`RecvStream::read_chunk()`].
///
/// [`RecvStream::read_chunk()`]: crate::RecvStream::read_chunk
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct ReadChunk<'a> {
    stream: &'a mut RecvStream,
    max_length: usize,
    ordered: bool,
}

impl<'a> Future for ReadChunk<'a> {
    type Output = Result<Option<Chunk>, ReadError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (max_length, ordered) = (self.max_length, self.ordered);
        self.stream.poll_read_chunk(cx, max_length, ordered)
    }
}

/// Future produced by [`RecvStream::read_chunks()`].
///
/// [`RecvStream::read_chunks()`]: crate::RecvStream::read_chunks
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct ReadChunks<'a> {
    stream: &'a mut RecvStream,
    bufs: &'a mut [Bytes],
}

impl<'a> Future for ReadChunks<'a> {
    type Output = Result<Option<usize>, ReadError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read_chunks(cx, this.bufs)
    }
}
