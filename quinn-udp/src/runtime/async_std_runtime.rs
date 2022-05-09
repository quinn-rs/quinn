use super::{AsyncUdpSocket, Runtime};
use async_io::Async;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::task::{Context, Poll};

#[derive(Clone, Debug)]
pub struct AsyncStdRuntime;

impl AsyncUdpSocket for Async<StdUdpSocket> {
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

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.get_ref().recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.get_ref().send_to(buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().local_addr()
    }

    #[cfg(unix)]
    fn get_ref(&self) -> &StdUdpSocket {
        Async::get_ref(self)
    }
}

impl Runtime for AsyncStdRuntime {
    fn wrap_udp_socket(&self, t: StdUdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        Ok(Box::new(Async::new(t)?))
    }
}
