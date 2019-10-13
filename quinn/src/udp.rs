use std::io;
use std::net::SocketAddr;

use futures::task::Context;
use futures::{ready, Poll};
use mio;

use tokio_net::driver::Handle;
use tokio_net::util::PollEvented;

use proto::EcnCodepoint;

use crate::platform::UdpExt;

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket, handle: &Handle) -> io::Result<UdpSocket> {
        let io = mio::net::UdpSocket::from_socket(socket)?;
        io.init_ext()?;
        let io = PollEvented::new_with_handle(io, handle)?;
        Ok(UdpSocket { io })
    }

    pub fn poll_send(
        &self,
        cx: &mut Context,
        remote: &SocketAddr,
        ecn: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(self.io.poll_write_ready(cx))?;
        match self.io.get_ref().send_ext(remote, ecn, msg) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr, Option<EcnCodepoint>), io::Error>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;
        match self.io.get_ref().recv_ext(buf) {
            Ok(n) => Poll::Ready(Ok(n.into())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
}
