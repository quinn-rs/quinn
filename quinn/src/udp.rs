use std::{
    io,
    io::IoSliceMut,
    net::{Ipv6Addr, SocketAddr},
    task::{Context, Poll},
};

use futures::ready;

use tokio::io::PollEvented;

use proto::{EcnCodepoint, Transmit};

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
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        let io = mio::net::UdpSocket::from_socket(socket)?;
        io.init_ext()?;
        let io = PollEvented::new(io)?;
        Ok(UdpSocket { io })
    }

    pub fn poll_send(
        &self,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(self.io.poll_write_ready(cx))?;
        match self.io.get_ref().send_ext(transmits) {
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
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;
        match self.io.get_ref().recv_ext(bufs, meta) {
            Ok(n) => Poll::Ready(Ok(n)),
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

/// Number of UDP packets to send/receive at a time
///
/// Chosen somewhat arbitrarily; might benefit from additional tuning.
pub const BATCH_SIZE: usize = 32;

#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    pub addr: SocketAddr,
    pub len: usize,
    pub ecn: Option<EcnCodepoint>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            ecn: None,
        }
    }
}
