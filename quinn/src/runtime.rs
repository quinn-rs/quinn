use std::{
    fmt::Debug,
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use udp::{RecvMeta, Transmit};
use crate::endpoint::GLOBAL_RUNTIME;

/// Abstracts I/O and timer operations for runtime independence
pub trait Runtime: Send + Sync + Debug + 'static {
    /// Construct a timer that will expire at `i`
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>>;
    /// Drive `future` to completion in the background
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
}

/// Abstract implementation of an async timer for runtime independence
pub trait AsyncTimer: Send + Debug + 'static {
    /// Update the timer to expire at `i`
    fn reset(self: Pin<&mut Self>, i: Instant);
    /// Check whether the timer has expired, and register to be woken if not
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()>;
}

/// Abstract implementation of a UDP socket for runtime independence
pub trait AsyncUdpSocket: Send + Sync + Debug + 'static {
    /// Send UDP datagrams from `transmits`, or register to be woken if sending may succeed in the
    /// future
    fn poll_send(&self, cx: &mut Context, transmits: &[Transmit])
        -> Poll<Result<usize, io::Error>>;

    /// Receive UDP datagrams, or register to be woken if receiving may succeed in the future
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>>;

    /// Look up the local IP address and port used by this socket
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Maximum number of datagrams that a [`Transmit`] may encode
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// Maximum number of datagrams that might be described by a single [`RecvMeta`]
    fn max_receive_segments(&self) -> usize {
        1
    }

    /// Whether datagrams might get fragmented into multiple parts
    ///
    /// Sockets should prevent this for best performance. See e.g. the `IPV6_DONTFRAG` socket
    /// option.
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Automatically select an appropriate runtime from those enabled at compile time
///
/// If `runtime-tokio` is enabled and this function is called from within a Tokio runtime context,
/// then `TokioRuntime` is returned. Otherwise, if `runtime-async-std` is enabled, `AsyncStdRuntime`
/// is returned. Otherwise, `None` is returned.
pub fn default_runtime() -> Option<Arc<dyn Runtime>> {
    GLOBAL_RUNTIME.get().map(|rt|rt.clone())
}

#[cfg(feature = "runtime-tokio")]
mod tokio;
#[cfg(feature = "runtime-tokio")]
pub use self::tokio::TokioRuntime;

#[cfg(feature = "runtime-async-std")]
mod async_std;
#[cfg(feature = "runtime-async-std")]
pub use self::async_std::AsyncStdRuntime;
