#[cfg(feature = "runtime-tokio")]
mod tokio_runtime;
#[cfg(feature = "runtime-tokio")]
pub use tokio_runtime::*;

#[cfg(feature = "runtime-async-std")]
mod async_std_runtime;
#[cfg(feature = "runtime-async-std")]
pub use async_std_runtime::*;

use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

pub trait AsyncWrappedUdpSocket: Sized + Send + Debug {
    fn new(t: std::net::UdpSocket) -> io::Result<Self>;

    // On Unix we expect to be able to access the underlying std UdpSocket
    // to be able to implement more advanced features
    #[cfg(unix)]
    fn poll_read<T>(
        &self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>>;
    #[cfg(unix)]
    fn poll_write<T>(
        &mut self,
        f: impl FnOnce(&std::net::UdpSocket) -> io::Result<T>,
        cx: &mut Context,
    ) -> Poll<io::Result<T>>;
    #[cfg(unix)]
    fn get_ref(&self) -> &std::net::UdpSocket;

    // On Non-Unix platforms we only expect to be able to do basic
    // send_to / recv_from operations.
    #[cfg(not(unix))]
    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, std::net::SocketAddr)>>;
    #[cfg(not(unix))]
    fn poll_send_to(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>>;
    #[cfg(not(unix))]
    fn local_addr(&self) -> io::Result<std::net::SocketAddr>;
}

pub trait AsyncTimer: Sized + Send + Debug {
    fn new(i: Instant) -> Self;
    fn reset(self: Pin<&mut Self>, i: Instant);
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()>;
}

pub trait Runtime: Send + 'static {
    type AsyncWrappedUdpSocket: AsyncWrappedUdpSocket;
    type Timer: AsyncTimer;

    fn spawn<T>(future: T)
    where
        T: Future + Send + 'static,
        T::Output: Send + 'static;
}
