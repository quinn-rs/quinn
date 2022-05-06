use super::{AsyncWrappedUdpSocket, Runtime};
use async_io::Async;
use std::io;
use std::task::{Context, Poll};

impl AsyncWrappedUdpSocket for Async<std::net::UdpSocket> {
    fn poll_read_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        Async::poll_readable(self, cx)
    }

    fn poll_write_ready(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        Async::poll_writable(self, cx)
    }

    fn clear_read_ready(&self, _cx: &mut Context) {
        // async-std doesn't need this
    }

    fn clear_write_ready(&self, _cx: &mut Context) {
        // async-std doesn't need this
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

    #[cfg(unix)]
    fn get_ref(&self) -> &std::net::UdpSocket {
        Async::get_ref(self)
    }
}

#[derive(Clone, Debug)]
pub struct AsyncStdRuntime;

impl Runtime for AsyncStdRuntime {
    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> io::Result<Box<dyn AsyncWrappedUdpSocket>> {
        Ok(Box::new(Async::new(t)?))
    }
}
