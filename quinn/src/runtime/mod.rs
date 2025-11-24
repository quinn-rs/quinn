#[cfg(any(feature = "runtime-tokio", feature = "runtime-smol"))]
use std::sync::Arc;
use std::{
    fmt::{self, Debug},
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use udp::{RecvMeta, Transmit};

use crate::Instant;

/// Abstracts I/O and timer operations for runtime independence
pub trait Runtime: Send + Sync + Debug + 'static {
    /// Construct a timer that will expire at `i`
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>>;
    /// Drive `future` to completion in the background
    #[track_caller]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
    /// Convert `t` into the socket type used by this runtime
    #[cfg(not(wasm_browser))]
    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>>;
    /// Look up the current time
    ///
    /// Allows simulating the flow of time for testing.
    fn now(&self) -> Instant {
        Instant::now()
    }
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
    /// Create a [`UdpSender`] that can register a single task for write-readiness notifications
    /// and send a transmit, if ready.
    ///
    /// A `poll_send` method on a single object can usually store only one [`Waker`] at a time,
    /// i.e. allow at most one caller to wait for an event. This method allows any number of
    /// interested tasks to construct their own [`UdpSender`] object. They can all then wait for the
    /// same event and be notified concurrently, because each [`UdpSender`] can store a separate
    /// [`Waker`].
    ///
    /// [`Waker`]: std::task::Waker
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>>;

    /// Receive UDP datagrams, or register to be woken if receiving may succeed in the future
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>>;

    /// Look up the local IP address and port used by this socket
    fn local_addr(&self) -> io::Result<SocketAddr>;

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

/// An object for asynchronously writing to an associated [`AsyncUdpSocket`].
///
/// Any number of [`UdpSender`]s may exist for a single [`AsyncUdpSocket`]. Each [`UdpSender`] is
/// responsible for notifying at most one task for send readiness.
pub trait UdpSender: Send + Sync + Debug + 'static {
    /// Send a UDP datagram, or register to be woken if sending may succeed in the future.
    ///
    /// Usually implementations of this will poll the socket for writability before trying to
    /// write to them, and retry both if writing fails.
    ///
    /// Quinn will create multiple [`UdpSender`]s, one for each task it's using it from. Thus it's
    /// important to poll the underlying socket in a way that doesn't overwrite wakers.
    ///
    /// A single [`UdpSender`] will be re-used, even if `poll_send` returns `Poll::Ready` once,
    /// unlike [`Future::poll`], so calling it again after readiness should not panic.
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>>;

    /// Maximum number of datagrams that a [`Transmit`] may encode.
    fn max_transmit_segments(&self) -> usize {
        1
    }
}

pin_project_lite::pin_project! {
    /// A helper for constructing [`UdpSender`]s from an underlying `Socket` type.
    ///
    /// This struct implements [`UdpSender`] if `MakeWritableFn` produces a `WritableFut`.
    ///
    /// Also serves as a trick, since `WritableFut` doesn't need to be a named future,
    /// it can be an anonymous async block, as long as `MakeWritableFn` produces that
    /// anonymous async block type.
    ///
    /// The `UdpSenderHelper` generic type parameters don't need to named, as it will be
    /// used in its dyn-compatible form as a `Pin<Box<dyn UdpSender>>`.
    struct UdpSenderHelper<Socket, MakeWritableFutFn, WritableFut> {
        socket: Socket,
        make_writable_fut_fn: MakeWritableFutFn,
        #[pin]
        writable_fut: Option<WritableFut>,
    }
}

impl<Socket, MakeWritableFutFn, WritableFut> Debug
    for UdpSenderHelper<Socket, MakeWritableFutFn, WritableFut>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UdpSender")
    }
}

impl<Socket, MakeWritableFutFn, WriteableFut>
    UdpSenderHelper<Socket, MakeWritableFutFn, WriteableFut>
{
    /// Create helper that implements [`UdpSender`] from a socket.
    ///
    /// Additionally you need to provide what is essentially an async function
    /// that resolves once the socket is write-ready.
    ///
    /// See also the bounds on this struct's [`UdpSender`] implementation.
    #[cfg(any(feature = "runtime-smol", feature = "runtime-tokio",))]
    fn new(inner: Socket, make_fut: MakeWritableFutFn) -> Self {
        Self {
            socket: inner,
            make_writable_fut_fn: make_fut,
            writable_fut: None,
        }
    }
}

impl<Socket, MakeWritableFutFn, WritableFut> super::UdpSender
    for UdpSenderHelper<Socket, MakeWritableFutFn, WritableFut>
where
    Socket: UdpSenderHelperSocket,
    MakeWritableFutFn: Fn(&Socket) -> WritableFut + Send + Sync + 'static,
    WritableFut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if this.writable_fut.is_none() {
                this.writable_fut
                    .set(Some((this.make_writable_fut_fn)(this.socket)));
            }
            // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
            // obtain an `&mut WritableFut` after storing it in `self.writable_fut` when `self` is already behind `Pin`,
            // and if we didn't store it then we wouldn't be able to keep it alive between
            // `poll_send` calls.
            let result =
                std::task::ready!(this.writable_fut.as_mut().as_pin_mut().unwrap().poll(cx));

            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.writable_fut.set(None);

            // If .writable() fails, propagate the error
            result?;

            match this.socket.try_send(transmit) {
                // We thought the socket was writable, but it wasn't, then retry so that either another
                // `writable().await` call determines that the socket is indeed not writable and
                // registers us for a wakeup, or the send succeeds if this really was just a
                // transient failure.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // In all other cases, either propagate the error or we're Ok
                result => return Poll::Ready(result),
            }
        }
    }

    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }
}

/// Parts of the [`UdpSender`] trait that aren't asynchronous or require storing wakers.
///
/// This trait is used by [`UdpSenderHelper`] to help construct [`UdpSender`]s.
trait UdpSenderHelperSocket: Send + Sync + 'static {
    /// Try to send a transmit, if the socket happens to be write-ready.
    ///
    /// If not write-ready, this is allowed to return [`std::io::ErrorKind::WouldBlock`].
    ///
    /// The [`UdpSenderHelper`] will use this to implement [`UdpSender::poll_send`].
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()>;

    /// See [`UdpSender::max_transmit_segments`].
    fn max_transmit_segments(&self) -> usize;
}

/// Automatically select an appropriate runtime from those enabled at compile time
///
/// If `runtime-tokio` is enabled and this function is called from within a Tokio runtime context,
/// then `TokioRuntime` is returned. Otherwise, if `runtime-smol` is enabled, `SmolRuntime` is
/// returned. Otherwise, `None` is returned.
#[cfg(any(feature = "runtime-tokio", feature = "runtime-smol"))]
#[allow(clippy::needless_return)] // Be sure we return the right thing
pub fn default_runtime() -> Option<Arc<dyn Runtime>> {
    #[cfg(feature = "runtime-tokio")]
    {
        if ::tokio::runtime::Handle::try_current().is_ok() {
            return Some(Arc::new(TokioRuntime));
        }
    }

    #[cfg(feature = "runtime-smol")]
    {
        return Some(Arc::new(SmolRuntime));
    }

    #[cfg(not(feature = "runtime-smol"))]
    None
}

#[cfg(feature = "runtime-tokio")]
mod tokio;
#[cfg(feature = "runtime-tokio")]
pub use tokio::TokioRuntime;

#[cfg(feature = "runtime-smol")]
mod smol;
#[cfg(feature = "runtime-smol")]
pub use smol::*;
