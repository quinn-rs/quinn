use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use proto::{ConnectionError, FinishError, StreamId, Written};
use thiserror::Error;
use tokio::sync::oneshot;

use crate::{
    connection::{ConnectionRef, UnknownStream},
    VarInt,
};

/// A stream that can only be used to send data
///
/// If dropped, streams that haven't been explicitly [`reset()`] will continue to (re)transmit
/// previously written data until it has been fully acknowledged or the connection is closed.
///
/// [`reset()`]: SendStream::reset
#[derive(Debug)]
pub struct SendStream {
    conn: ConnectionRef,
    stream: StreamId,
    is_0rtt: bool,
    finishing: Option<oneshot::Receiver<Option<WriteError>>>,
}

impl SendStream {
    pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
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
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        Write { stream: self, buf }.await
    }

    /// Convenience method to write an entire buffer to the stream
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        WriteAll { stream: self, buf }.await
    }

    /// Write chunks to the stream
    ///
    /// Yields the number of bytes and chunks written on success.
    /// Congestion and flow control may cause this to be shorter than `buf.len()`,
    /// indicating that only a prefix of `bufs` was written
    pub async fn write_chunks(&mut self, bufs: &mut [Bytes]) -> Result<Written, WriteError> {
        WriteChunks { stream: self, bufs }.await
    }

    /// Convenience method to write a single chunk in its entirety to the stream
    pub async fn write_chunk(&mut self, buf: Bytes) -> Result<(), WriteError> {
        WriteChunk {
            stream: self,
            buf: [buf],
        }
        .await
    }

    /// Convenience method to write an entire list of chunks to the stream
    pub async fn write_all_chunks(&mut self, bufs: &mut [Bytes]) -> Result<(), WriteError> {
        WriteAllChunks {
            stream: self,
            bufs,
            offset: 0,
        }
        .await
    }

    fn execute_poll<F, R>(&mut self, cx: &mut Context, write_fn: F) -> Poll<Result<R, WriteError>>
    where
        F: FnOnce(&mut proto::SendStream) -> Result<R, proto::WriteError>,
    {
        use proto::WriteError::*;
        let mut conn = self.conn.state.lock("SendStream::poll_write");
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        if let Some(ref x) = conn.error {
            return Poll::Ready(Err(WriteError::ConnectionLost(x.clone())));
        }

        let result = match write_fn(&mut conn.inner.send_stream(self.stream)) {
            Ok(result) => result,
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
        Poll::Ready(Ok(result))
    }

    /// Shut down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub async fn finish(&mut self) -> Result<(), WriteError> {
        Finish { stream: self }.await
    }

    #[doc(hidden)]
    pub fn poll_finish(&mut self, cx: &mut Context) -> Poll<Result<(), WriteError>> {
        let mut conn = self.conn.state.lock("poll_finish");
        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| WriteError::ZeroRttRejected)?;
        }
        if self.finishing.is_none() {
            conn.inner
                .send_stream(self.stream)
                .finish()
                .map_err(|e| match e {
                    FinishError::UnknownStream => WriteError::UnknownStream,
                    FinishError::Stopped(error_code) => WriteError::Stopped(error_code),
                })?;
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            conn.finishing.insert(self.stream, send);
            conn.wake();
        }
        match Pin::new(self.finishing.as_mut().unwrap())
            .poll(cx)
            .map(|x| x.unwrap())
        {
            Poll::Ready(x) => {
                self.finishing = None;
                Poll::Ready(x.map_or(Ok(()), Err))
            }
            Poll::Pending => {
                // To ensure that finished streams can be detected even after the connection is
                // closed, we must only check for connection errors after determining that the
                // stream has not yet been finished. Note that this relies on holding the connection
                // lock so that it is impossible for the stream to become finished between the above
                // poll call and this check.
                if let Some(ref x) = conn.error {
                    return Poll::Ready(Err(WriteError::ConnectionLost(x.clone())));
                }
                Poll::Pending
            }
        }
    }

    /// Close the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped, and
    /// previously transmitted data will no longer be retransmitted if lost. If an attempt has
    /// already been made to finish the stream, the peer may still receive all written data.
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), UnknownStream> {
        let mut conn = self.conn.state.lock("SendStream::reset");
        if self.is_0rtt && conn.check_0rtt().is_err() {
            return Ok(());
        }
        conn.inner.send_stream(self.stream).reset(error_code)?;
        conn.wake();
        Ok(())
    }

    /// Set the priority of the send stream
    ///
    /// Every send stream has an initial priority of 0. Locally buffered data from streams with
    /// higher priority will be transmitted before data from streams with lower priority. Changing
    /// the priority of a stream with pending data may only take effect after that data has been
    /// transmitted. Using many different priority levels per connection may have a negative
    /// impact on performance.
    pub fn set_priority(&self, priority: i32) -> Result<(), UnknownStream> {
        let mut conn = self.conn.state.lock("SendStream::set_priority");
        conn.inner.send_stream(self.stream).set_priority(priority)?;
        Ok(())
    }

    /// Get the priority of the send stream
    pub fn priority(&self) -> Result<i32, UnknownStream> {
        let mut conn = self.conn.state.lock("SendStream::priority");
        Ok(conn.inner.send_stream(self.stream).priority()?)
    }

    /// Completes if/when the peer stops the stream, yielding the error code
    pub async fn stopped(&mut self) -> Result<VarInt, StoppedError> {
        Stopped { stream: self }.await
    }

    #[doc(hidden)]
    pub fn poll_stopped(&mut self, cx: &mut Context) -> Poll<Result<VarInt, StoppedError>> {
        let mut conn = self.conn.state.lock("SendStream::poll_stopped");

        if self.is_0rtt {
            conn.check_0rtt()
                .map_err(|()| StoppedError::ZeroRttRejected)?;
        }

        match conn.inner.send_stream(self.stream).stopped() {
            Err(_) => Poll::Ready(Err(StoppedError::UnknownStream)),
            Ok(Some(error_code)) => Poll::Ready(Ok(error_code)),
            Ok(None) => {
                conn.stopped.insert(self.stream, cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Get the identity of this stream
    pub fn id(&self) -> StreamId {
        self.stream
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for SendStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        SendStream::execute_poll(self.get_mut(), cx, |stream| stream.write(buf)).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().poll_finish(cx).map_err(Into::into)
    }
}

#[cfg(feature = "runtime-tokio")]
impl tokio::io::AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Self::execute_poll(self.get_mut(), cx, |stream| stream.write(buf)).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().poll_finish(cx).map_err(Into::into)
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        let mut conn = self.conn.state.lock("SendStream::drop");

        // clean up any previously registered wakers
        conn.finishing.remove(&self.stream);
        conn.stopped.remove(&self.stream);
        conn.blocked_writers.remove(&self.stream);

        if conn.error.is_some() || (self.is_0rtt && conn.check_0rtt().is_err()) {
            return;
        }
        if self.finishing.is_none() {
            match conn.inner.send_stream(self.stream).finish() {
                Ok(()) => conn.wake(),
                Err(FinishError::Stopped(reason)) => {
                    if conn.inner.send_stream(self.stream).reset(reason).is_ok() {
                        conn.wake();
                    }
                }
                // Already finished or reset, which is fine.
                Err(FinishError::UnknownStream) => {}
            }
        }
    }
}

/// Future produced by `SendStream::finish`
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct Finish<'a> {
    stream: &'a mut SendStream,
}

impl Future for Finish<'_> {
    type Output = Result<(), WriteError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.get_mut().stream.poll_finish(cx)
    }
}

/// Future produced by `SendStream::stopped`
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct Stopped<'a> {
    stream: &'a mut SendStream,
}

impl Future for Stopped<'_> {
    type Output = Result<VarInt, StoppedError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.get_mut().stream.poll_stopped(cx)
    }
}

/// Future produced by [`SendStream::write()`].
///
/// [`SendStream::write()`]: crate::SendStream::write
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct Write<'a> {
    stream: &'a mut SendStream,
    buf: &'a [u8],
}

impl<'a> Future for Write<'a> {
    type Output = Result<usize, WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let buf = this.buf;
        this.stream.execute_poll(cx, |s| s.write(buf))
    }
}

/// Future produced by [`SendStream::write_all()`].
///
/// [`SendStream::write_all()`]: crate::SendStream::write_all
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct WriteAll<'a> {
    stream: &'a mut SendStream,
    buf: &'a [u8],
}

impl<'a> Future for WriteAll<'a> {
    type Output = Result<(), WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if this.buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let buf = this.buf;
            let n = ready!(this.stream.execute_poll(cx, |s| s.write(buf)))?;
            this.buf = &this.buf[n..];
        }
    }
}

/// Future produced by [`SendStream::write_chunks()`].
///
/// [`SendStream::write_chunks()`]: crate::SendStream::write_chunks
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct WriteChunks<'a> {
    stream: &'a mut SendStream,
    bufs: &'a mut [Bytes],
}

impl<'a> Future for WriteChunks<'a> {
    type Output = Result<Written, WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let bufs = &mut *this.bufs;
        this.stream.execute_poll(cx, |s| s.write_chunks(bufs))
    }
}

/// Future produced by [`SendStream::write_chunk()`].
///
/// [`SendStream::write_chunk()`]: crate::SendStream::write_chunk
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct WriteChunk<'a> {
    stream: &'a mut SendStream,
    buf: [Bytes; 1],
}

impl<'a> Future for WriteChunk<'a> {
    type Output = Result<(), WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if this.buf[0].is_empty() {
                return Poll::Ready(Ok(()));
            }
            let bufs = &mut this.buf[..];
            ready!(this.stream.execute_poll(cx, |s| s.write_chunks(bufs)))?;
        }
    }
}

/// Future produced by [`SendStream::write_all_chunks()`].
///
/// [`SendStream::write_all_chunks()`]: crate::SendStream::write_all_chunks
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
struct WriteAllChunks<'a> {
    stream: &'a mut SendStream,
    bufs: &'a mut [Bytes],
    offset: usize,
}

impl<'a> Future for WriteAllChunks<'a> {
    type Output = Result<(), WriteError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if this.offset == this.bufs.len() {
                return Poll::Ready(Ok(()));
            }
            let bufs = &mut this.bufs[this.offset..];
            let written = ready!(this.stream.execute_poll(cx, |s| s.write_chunks(bufs)))?;
            this.offset += written.chunks;
        }
    }
}

/// Errors that arise from writing to a stream
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream
    ///
    /// Carries an application-defined error code.
    #[error("sending stopped by peer: error {0}")]
    Stopped(VarInt),
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been finished or reset
    #[error("unknown stream")]
    UnknownStream,
    /// This was a 0-RTT stream and the server rejected it
    ///
    /// Can only occur on clients for 0-RTT streams, which can be opened using
    /// [`Connecting::into_0rtt()`].
    ///
    /// [`Connecting::into_0rtt()`]: crate::Connecting::into_0rtt()
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

/// Errors that arise while monitoring for a send stream stop from the peer
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoppedError {
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been finished or reset
    #[error("unknown stream")]
    UnknownStream,
    /// This was a 0-RTT stream and the server rejected it
    ///
    /// Can only occur on clients for 0-RTT streams, which can be opened using
    /// [`Connecting::into_0rtt()`].
    ///
    /// [`Connecting::into_0rtt()`]: crate::Connecting::into_0rtt()
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

impl From<WriteError> for io::Error {
    fn from(x: WriteError) -> Self {
        use self::WriteError::*;
        let kind = match x {
            Stopped(_) | ZeroRttRejected => io::ErrorKind::ConnectionReset,
            ConnectionLost(_) | UnknownStream => io::ErrorKind::NotConnected,
        };
        Self::new(kind, x)
    }
}
