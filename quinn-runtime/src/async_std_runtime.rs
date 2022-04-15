use super::{AsyncTimer, AsyncWrappedUdpSocket, Runtime};
use async_io::Async;
use async_io::Timer;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

impl AsyncWrappedUdpSocket for Async<std::net::UdpSocket> {
    fn new(t: std::net::UdpSocket) -> io::Result<Self> {
        Async::new(t)
    }

    #[cfg(unix)]
    fn poll_read<T>(
        &self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>> {
        match Async::poll_readable(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(f(self.get_ref())),
        }
    }
    #[cfg(unix)]
    fn poll_write<T>(
        &mut self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>> {
        match Async::poll_writable(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(f(self.get_ref())),
        }
    }
    #[cfg(unix)]
    fn get_ref(&self) -> &std::net::UdpSocket {
        Async::get_ref(self)
    }

    #[cfg(not(unix))]
    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, std::net::SocketAddr)>> {
        match Async::poll_readable(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(self.get_ref().recv_from(buf)),
        }
    }
    #[cfg(not(unix))]
    fn poll_send_to(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        match Async::poll_writable(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(self.get_ref().send_to(buf, target)),
        }
    }
    #[cfg(not(unix))]
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.get_ref().local_addr()
    }
}

impl AsyncTimer for Timer {
    fn new(t: Instant) -> Self {
        Timer::at(t)
    }
    fn reset(mut self: Pin<&mut Self>, t: Instant) {
        self.set_at(t)
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx).map(|_| ())
    }
}

pub struct AsyncStdRuntime;

impl Runtime for AsyncStdRuntime {
    type AsyncWrappedUdpSocket = Async<std::net::UdpSocket>;
    type Timer = Timer;

    fn spawn<T>(future: T)
    where
        T: Future + Send + 'static,
        T::Output: Send + 'static,
    {
        async_std::task::spawn(future);
    }
}
