use super::{AsyncWrappedUdpSocket, Runtime};
use std::io;
use std::task::{Context, Poll};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

#[cfg(unix)]
impl AsyncWrappedUdpSocket for AsyncFd<std::net::UdpSocket> {
    fn poll_read_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncFd::poll_read_ready(self, cx).map(|x| x.map(|_| ()))
    }

    fn poll_write_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncFd::poll_write_ready(self, cx).map(|x| x.map(|_| ()))
    }

    fn clear_read_ready(&self, cx: &mut Context) {
        match self.poll_read_ready(cx) {
            Poll::Pending => {}
            Poll::Ready(Err(_)) => {}
            Poll::Ready(Ok(mut guard)) => guard.clear_ready(),
        }
    }

    fn clear_write_ready(&self, cx: &mut Context) {
        match self.poll_write_ready(cx) {
            Poll::Pending => {}
            Poll::Ready(Err(_)) => {}
            Poll::Ready(Ok(mut guard)) => guard.clear_ready(),
        }
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        self.get_ref().recv_from(buf)
    }

    fn try_send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> io::Result<usize> {
        self.get_ref().send_to(buf, target)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.get_ref().local_addr()
    }

    fn get_ref(&self) -> &std::net::UdpSocket {
        AsyncFd::get_ref(self)
    }
}

#[cfg(not(unix))]
impl AsyncWrappedUdpSocket for tokio::net::UdpSocket {
    fn poll_read_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        tokio::net::UdpSocket::poll_recv_ready(self, cx)
    }

    fn poll_write_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        tokio::net::UdpSocket::poll_send_ready(self, cx)
    }

    fn clear_read_ready(&self, _cx: &mut Context) {
        // not necessary because tokio::net::UdpSocket::try_recv_from already uses try_io
    }

    fn clear_write_ready(&self, _cx: &mut Context) {
        // not necessary because tokio::net::UdpSocket::try_send_from already uses try_io
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        tokio::net::UdpSocket::try_recv_from(self, buf)
    }

    fn try_send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::try_send_to(self, buf, target)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

#[derive(Debug, Clone)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> io::Result<Box<dyn AsyncWrappedUdpSocket>> {
        t.set_nonblocking(true)?;
        #[cfg(unix)]
        {
            Ok(Box::new(AsyncFd::new(t)?))
        }
        #[cfg(not(unix))]
        {
            Ok(Box::new(tokio::net::UdpSocket::from_std(t)?))
        }
    }
}
