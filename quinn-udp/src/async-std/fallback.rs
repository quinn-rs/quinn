use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    task::{Context, Poll},
    time::Instant,
};

use proto::Transmit;

use super::{log_sendmsg_error, RecvMeta, UdpState, IO_ERROR_LOG_INTERVAL};

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    io: async_io::Async<std::net::UdpSocket>,
    last_send_error: Instant,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(UdpSocket {
            io: async_io::Async::new(socket)?,
            last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
        })
    }

    pub fn poll_send(
        &mut self,
        _state: &UdpState,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sent = 0;
        for transmit in transmits {
            let e = match self.io.poll_writable(cx) {
                Poll::Ready(Ok(_)) => {
                    match self
                        .io
                        .get_mut()
                        .send_to(&transmit.contents, transmit.destination)
                    {
                        Ok(_) => {
                            sent += 1;
                            None
                        }
                        Err(e) => Some(e),
                    }
                }
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                Poll::Ready(Err(_)) | Poll::Pending if sent != 0 => return Poll::Ready(Ok(sent)),
                Poll::Ready(Err(e)) => Some(e),
                Poll::Pending => return Poll::Pending,
            };
            if let Some(e) = e {
                // WouldBlock is expected to be returned as `Poll::Pending`
                debug_assert!(e.kind() != io::ErrorKind::WouldBlock);

                // Errors are ignored, since they will ususally be handled
                // by higher level retransmits and timeouts.
                // - PermissionDenied errors have been observed due to iptable rules.
                //   Those are not fatal errors, since the
                //   configuration can be dynamically changed.
                // - Destination unreachable errors have been observed for other
                log_sendmsg_error(&mut self.last_send_error, e, transmit);
                sent += 1;
            }
        }
        Poll::Ready(Ok(sent))
    }

    pub fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        ready!(self.io.poll_readable(cx))?;
        let (len, addr) = self.io.get_mut().recv_from(&mut bufs[0])?;
        meta[0] = RecvMeta {
            len,
            addr,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
}

/// Returns the platforms UDP socket capabilities
pub fn udp_state() -> super::UdpState {
    super::UdpState {
        max_gso_segments: std::sync::atomic::AtomicUsize::new(1),
    }
}

pub const BATCH_SIZE: usize = 1;
