// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper, UdpPoller};
use crate::Instant;

/// Runtime implementation for async-io based runtimes (async-std, smol)
#[derive(Debug)]
pub struct AsyncIoRuntime;

#[cfg(feature = "runtime-async-std")]
/// Runtime for async-std
#[derive(Debug)]
pub struct AsyncStdRuntime;

#[cfg(feature = "runtime-async-std")]
impl Runtime for AsyncStdRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(AsyncIoTimer(async_io::Timer::at(i.into())))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        async_std::task::spawn(future);
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(UdpSocket {
            inner: async_io::Async::new(t)?,
            may_fragment: true, // Default to true for now
        }))
    }
}

#[cfg(feature = "smol")]
/// Runtime for smol
#[derive(Debug)]
pub struct SmolRuntime;

#[cfg(feature = "smol")]
impl Runtime for SmolRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(AsyncIoTimer(async_io::Timer::at(i.into())))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        smol::spawn(future).detach();
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(UdpSocket {
            inner: async_io::Async::new(t)?,
            may_fragment: true, // Default to true for now
        }))
    }
}

/// Timer implementation for async-io
#[derive(Debug)]
struct AsyncIoTimer(async_io::Timer);

impl AsyncTimer for AsyncIoTimer {
    fn reset(mut self: Pin<&mut Self>, i: Instant) {
        self.0.set_at(i.into())
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        match Pin::new(&mut self.get_mut().0).poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// UDP socket implementation for async-io
#[derive(Debug)]
struct UdpSocket {
    inner: async_io::Async<std::net::UdpSocket>,
    may_fragment: bool,
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move {
                loop {
                    socket.inner.writable().await?;
                    return Ok(());
                }
            }
        }))
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        match self
            .inner
            .get_ref()
            .send_to(&transmit.contents, transmit.destination)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            match self.inner.get_ref().recv_from(&mut bufs[0]) {
                Ok((len, addr)) => {
                    meta[0] = quinn_udp::RecvMeta {
                        len,
                        stride: len,
                        addr,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.inner.poll_readable(cx) {
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.get_ref().local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.may_fragment
    }
}
