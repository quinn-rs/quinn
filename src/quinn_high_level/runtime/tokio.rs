use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::ReadBuf,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper, UdpPoller};
use crate::Instant;

/// Tokio runtime implementation
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(TokioTimer(Box::pin(sleep_until(i.into()))))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        t.set_nonblocking(true)?;
        Ok(Arc::new(UdpSocket {
            inner: tokio::net::UdpSocket::from_std(t)?,
            may_fragment: true, // Default to true for now
        }))
    }

    fn now(&self) -> Instant {
        Instant::from(tokio::time::Instant::now())
    }
}

/// Tokio timer implementation
#[derive(Debug)]
struct TokioTimer(Pin<Box<Sleep>>);

impl AsyncTimer for TokioTimer {
    fn reset(mut self: Pin<&mut Self>, i: Instant) {
        self.0.as_mut().reset(i.into())
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        self.0.as_mut().poll(cx).map(|_| ())
    }
}

/// Tokio UDP socket implementation
#[derive(Debug)]
struct UdpSocket {
    inner: tokio::net::UdpSocket,
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
        self.inner
            .try_send_to(&transmit.contents, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // For now, use a simple single-packet receive
        // In production, should use quinn_udp::recv for GSO/GRO support

        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut buf = ReadBuf::new(&mut bufs[0]);
        let addr = match self.inner.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(addr)) => addr,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let len = buf.filled().len();
        meta[0] = quinn_udp::RecvMeta {
            len,
            stride: len,
            addr,
            ecn: None,
            dst_ip: None,
        };

        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.may_fragment
    }
}

/// Extension trait to convert tokio::Handle to Runtime
pub(super) trait HandleRuntime {
    /// Create a Runtime implementation from this handle
    fn as_runtime(&self) -> TokioRuntime;
}

impl HandleRuntime for tokio::runtime::Handle {
    fn as_runtime(&self) -> TokioRuntime {
        TokioRuntime
    }
}
