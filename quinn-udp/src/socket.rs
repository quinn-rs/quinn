use proto::{Transmit};
use crate::{RecvMeta, UdpCapabilities};
use async_io::Async;
use futures_lite::future::poll_fn;
use std::io::{IoSliceMut, Result, self};
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::platform as platform;

/// Async-io-compatible UDP socket with some useful specializations.
///
/// Unlike a standard UDP socket, this allows ECN bits to be read
/// and written on some platforms.
#[derive(Debug)]
pub struct UdpSocket {
    inner: Async<std::net::UdpSocket>,
    last_send_error: Instant,
}

impl UdpSocket {
    /// Returns the platforms UDP socket capabilities
    pub fn capabilities() -> Result<UdpCapabilities> {
        Ok(UdpCapabilities {
            max_gso_segments: platform::max_gso_segments()?,
        })
    }

    pub fn from_std(socket: std::net::UdpSocket) -> Result<Self> {
        platform::init(&socket)?;
        let now = Instant::now();
        Ok(Self {
            inner: Async::new(socket)?,
            last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
        })
    }

    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        Self::from_std(socket)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.get_ref().local_addr()
    }

    pub fn ttl(&self) -> Result<u8> {
        let ttl = self.inner.get_ref().ttl()?;
        Ok(ttl as u8)
    }

    pub fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.inner.get_ref().set_ttl(ttl as u32)
    }

    pub fn poll_send(&mut self, cx: &mut Context, transmits: &[Transmit]) -> Poll<Result<usize>> {
        match self.inner.poll_writable(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let socket = self.inner.get_ref();
        match platform::send(socket, transmits) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) => {
                match err.kind() {
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock => {},
                    _ => {
                        log_sendmsg_error(&mut self.last_send_error, &err, &transmits[0]);
                    }
                }
                Poll::Ready(Err(err))
            },
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<Result<usize>> {
        match self.inner.poll_readable(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let socket = self.inner.get_ref();
        Poll::Ready(platform::recv(socket, buffers, meta))
    }

    pub async fn send(&mut self, transmits: &[Transmit]) -> Result<usize> {
        let mut i = 0;
        while i < transmits.len() {
            i += poll_fn(|cx| self.poll_send(cx, &transmits[i..])).await?;
        }
        Ok(i)
    }

    pub async fn recv(
        &self,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Result<usize> {
        poll_fn(|cx| self.poll_recv(cx, buffers, meta)).await
    }
}

/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
fn log_sendmsg_error(
    last_send_error: &mut Instant,
    err: &dyn core::fmt::Debug,
    transmit: &Transmit,
) {
    let now = Instant::now();
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        warn!(
        "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
            err, transmit.destination, transmit.src_ip, transmit.ecn, transmit.contents.len(), transmit.segment_size);
    }
}
