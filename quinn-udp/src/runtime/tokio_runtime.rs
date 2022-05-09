use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::task::{Context, Poll};

use super::{AsyncUdpSocket, Runtime};

#[cfg(unix)]
use tokio::io::unix::AsyncFd;

#[derive(Debug, Clone)]
pub struct TokioRuntime;

#[cfg(unix)]
impl AsyncUdpSocket for AsyncFd<StdUdpSocket> {
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

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.get_ref().recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.get_ref().send_to(buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().local_addr()
    }

    fn get_ref(&self) -> &StdUdpSocket {
        AsyncFd::get_ref(self)
    }
}

#[cfg(not(unix))]
impl AsyncUdpSocket for tokio::net::UdpSocket {
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
        // not necessary because tokio::net::UdpSocket::try_send_to already uses try_io
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::try_recv_from(self, buf)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::try_send_to(self, buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

impl Runtime for TokioRuntime {
    fn wrap_udp_socket(&self, t: StdUdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
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
