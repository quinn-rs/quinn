use proto::{Transmit};
use crate::{RecvMeta, UdpCapabilities};
use async_io::Async;
use futures_lite::future::poll_fn;
use std::io::{IoSliceMut, Result};
use std::net::SocketAddr;
use std::task::{Context, Poll};

use crate::platform as platform;

/// Async-io-compatible UDP socket with some useful specializations.
///
/// Unlike a standard UDP socket, this allows ECN bits to be read
/// and written on some platforms.
#[derive(Debug)]
pub struct UdpSocket {
    inner: Async<std::net::UdpSocket>,
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
        Ok(Self {
            inner: Async::new(socket)?,
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

    pub fn poll_send(&self, cx: &mut Context, transmits: &[Transmit]) -> Poll<Result<usize>> {
        match self.inner.poll_writable(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let socket = self.inner.get_ref();
        match platform::send(socket, transmits) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) => Poll::Ready(Err(err)),
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

    pub async fn send(&self, transmits: &[Transmit]) -> Result<usize> {
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
