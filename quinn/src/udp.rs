use std::io;
use std::net::SocketAddr;

use futures::Poll;
use mio;

use tokio_reactor::{Handle, PollEvented};

use quinn_proto::EcnCodepoint;

use crate::platform::UdpExt;

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
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
        remote: &SocketAddr,
        ecn: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.io.poll_write_ready() {
            Ok(x) if x.is_not_ready() => {
                return Poll::Pending;
            }
            Ok(_) => {}
            Err(e) => {
                return Poll::Ready(Err(e));
            }
        }
        match self.io.get_ref().send_ext(remote, ecn, msg) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready()?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn poll_recv(
        &self,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, Option<EcnCodepoint>)>> {
        match self.io.poll_read_ready(mio::Ready::readable()) {
            Ok(x) if x.is_not_ready() => {
                return Poll::Pending;
            }
            Ok(_) => {}
            Err(e) => {
                return Poll::Ready(Err(e));
            }
        }
        match self.io.get_ref().recv_ext(buf) {
            Ok(n) => Poll::Ready(Ok(n.into())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(mio::Ready::readable())?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
