use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    task::{Context, Poll},
};

use futures::ready;
use tokio::io::PollEvented;

use super::RecvMeta;
use proto::Transmit;

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
        Ok(UdpSocket {
            io: PollEvented::new(mio::net::UdpSocket::from_socket(socket)?)?,
        })
    }

    pub fn poll_send(
        &self,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(self.io.poll_write_ready(cx))?;
        match send(self.io.get_ref(), transmits) {
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
        match recv(self.io.get_ref(), bufs, meta) {
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

fn send(io: &mio::net::UdpSocket, transmits: &[Transmit]) -> io::Result<usize> {
    let mut sent = 0;
    for transmit in transmits {
        match io.send_to(&transmit.contents, &transmit.destination) {
            Ok(_) => {
                sent += 1;
            }
            Err(_) if sent != 0 => {
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                return Ok(sent);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(sent)
}

fn recv(
    io: &mio::net::UdpSocket,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    let (len, addr) = io.recv_from(&mut bufs[0])?;
    meta[0] = RecvMeta {
        len,
        addr,
        ecn: None,
        dst_ip: None,
    };
    Ok(1)
}

/// Returns the platforms UDP socket capabilities
pub fn caps() -> super::UdpCapabilities {
    super::UdpCapabilities { gso: false }
}

pub const BATCH_SIZE: usize = 1;
