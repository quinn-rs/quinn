use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    task::{Context, Poll},
};

use futures::ready;
use proto::Transmit;
use tokio::io::ReadBuf;

use super::RecvMeta;

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    io: tokio::net::UdpSocket,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;
        Ok(UdpSocket {
            io: tokio::net::UdpSocket::from_std(socket)?,
        })
    }

    pub fn poll_send(
        &self,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sent = 0;
        for transmit in transmits {
            match self
                .io
                .poll_send_to(cx, &transmit.contents, transmit.destination)
            {
                Poll::Ready(Ok(_)) => {
                    sent += 1;
                }
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                Poll::Ready(Err(_)) | Poll::Pending if sent != 0 => return Poll::Ready(Ok(sent)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(sent))
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        let mut buf = ReadBuf::new(&mut bufs[0]);
        let addr = ready!(self.io.poll_recv_from(cx, &mut buf))?;
        meta[0] = RecvMeta {
            len: buf.filled().len(),
            addr,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

/// Returns the platforms UDP socket capabilities
pub fn caps() -> super::UdpCapabilities {
    super::UdpCapabilities {
        max_gso_segments: 1,
    }
}

pub const BATCH_SIZE: usize = 1;
