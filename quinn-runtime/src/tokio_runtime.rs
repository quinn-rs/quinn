use super::{AsyncTimer, AsyncWrappedUdpSocket, Runtime};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
#[cfg(not(unix))]
use tokio::io::ReadBuf;
use tokio::time::{sleep_until, Sleep};

#[cfg(unix)]
impl AsyncWrappedUdpSocket for AsyncFd<std::net::UdpSocket> {
    fn new(t: std::net::UdpSocket) -> io::Result<Self> {
        AsyncFd::new(t)
    }
    fn poll_read<T>(
        &self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>> {
        match AsyncFd::poll_read_ready(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(mut guard)) => Poll::Ready(
                guard
                    .try_io(|io| f(io.get_ref()))
                    .unwrap_or_else(|_| Err(io::ErrorKind::WouldBlock.into())),
            ),
        }
    }
    fn poll_write<T>(
        &mut self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>> {
        match AsyncFd::poll_write_ready(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(mut guard)) => Poll::Ready(
                guard
                    .try_io(|io| f(io.get_ref()))
                    .unwrap_or_else(|_| Err(io::ErrorKind::WouldBlock.into())),
            ),
        }
    }
    fn get_ref(&self) -> &std::net::UdpSocket {
        AsyncFd::get_ref(self)
    }
}

#[cfg(not(unix))]
impl AsyncWrappedUdpSocket for tokio::net::UdpSocket {
    fn new(t: std::net::UdpSocket) -> io::Result<Self> {
        tokio::net::UdpSocket::from_std(t)
    }
    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, std::net::SocketAddr)>> {
        let mut buf = ReadBuf::new(buf);
        let addr = match tokio::net::UdpSocket::poll_recv_from(self, cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(addr) => addr,
        }?;
        Poll::Ready(Ok((buf.filled().len(), addr)))
    }
    fn poll_send_to(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        tokio::net::UdpSocket::poll_send_to(self, cx, buf, target)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

impl AsyncTimer for Sleep {
    fn new(t: Instant) -> Self {
        sleep_until(t.into())
    }
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Sleep::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    #[cfg(unix)]
    type AsyncWrappedUdpSocket = AsyncFd<std::net::UdpSocket>;
    #[cfg(not(unix))]
    type AsyncWrappedUdpSocket = tokio::net::UdpSocket;
    type Timer = Sleep;

    fn spawn<T>(future: T)
    where
        T: Future + Send + 'static,
        T::Output: Send + 'static,
    {
        tokio::spawn(future);
    }
}
