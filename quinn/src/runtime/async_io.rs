use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use async_io::{Async, Timer};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper};

#[cfg(feature = "smol")]
pub use self::smol::SmolRuntime;

#[cfg(feature = "smol")]
mod smol {
    use super::*;

    /// A Quinn runtime for smol
    #[derive(Debug)]
    pub struct SmolRuntime;

    impl Runtime for SmolRuntime {
        fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
            Box::pin(Timer::at(t))
        }

        fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
            ::smol::spawn(future).detach();
        }

        fn wrap_udp_socket(
            &self,
            sock: std::net::UdpSocket,
        ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
            Ok(Arc::new(UdpSocket::new(sock)?))
        }
    }
}

#[cfg(feature = "async-std")]
pub use self::async_std::AsyncStdRuntime;

#[cfg(feature = "async-std")]
mod async_std {
    use super::*;

    /// A Quinn runtime for async-std
    #[derive(Debug)]
    pub struct AsyncStdRuntime;

    impl Runtime for AsyncStdRuntime {
        fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
            Box::pin(Timer::at(t))
        }

        fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
            ::async_std::task::spawn(future);
        }

        fn wrap_udp_socket(
            &self,
            sock: std::net::UdpSocket,
        ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
            Ok(Arc::new(UdpSocket::new(sock)?))
        }
    }
}

impl AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, t: Instant) {
        self.set_at(t)
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx).map(|_| ())
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: Async<std::net::UdpSocket>,
    inner: udp::UdpSocketState,
}

impl UdpSocket {
    fn new(sock: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            inner: udp::UdpSocketState::new((&sock).into())?,
            io: Async::new(sock)?,
        })
    }
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn super::UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.inner.send((&self.io).into(), transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_readable(cx))?;
            if let Ok(res) = self.inner.recv((&self.io).into(), bufs, meta) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.as_ref().local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}
