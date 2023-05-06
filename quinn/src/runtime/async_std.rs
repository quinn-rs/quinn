use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use async_io::{Async, Timer};

use super::{AsyncTimer, AsyncUdpSocket, Runtime};

/// A Quinn runtime for async-std
#[derive(Debug)]
pub struct AsyncStdRuntime;

impl Runtime for AsyncStdRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(Timer::at(t))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        async_std::task::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        udp::UdpSocketState::configure((&sock).into())?;
        Ok(Box::new(UdpSocket {
            io: Async::new(sock)?,
            inner: udp::UdpSocketState::new(),
        }))
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

impl AsyncUdpSocket for UdpSocket {
    fn poll_send(
        &self,
        state: &udp::UdpState,
        cx: &mut Context,
        transmits: &[udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_writable(cx))?;
            if let Ok(res) = self.inner.send((&self.io).into(), state, transmits) {
                return Poll::Ready(Ok(res));
            }
        }
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
        udp::may_fragment()
    }
}
