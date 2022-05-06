#[cfg(feature = "runtime-tokio")]
mod tokio_runtime;
#[cfg(feature = "runtime-tokio")]
pub use tokio_runtime::*;

#[cfg(feature = "runtime-async-std")]
mod async_std_runtime;
#[cfg(feature = "runtime-async-std")]
pub use async_std_runtime::*;

use std::fmt::Debug;
use std::io;
use std::task::{Context, Poll};

pub trait AsyncWrappedUdpSocket: Send + Debug {
    fn poll_read_ready(&self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn poll_write_ready(&self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn clear_read_ready(&self, cx: &mut Context);

    fn clear_write_ready(&self, cx: &mut Context);

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)>;

    fn try_send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<std::net::SocketAddr>;

    // On Unix we expect to be able to access the underlying std UdpSocket
    // to be able to implement more advanced features
    #[cfg(unix)]
    fn get_ref(&self) -> &std::net::UdpSocket;
}

pub trait Runtime: Send + Sync + Debug + 'static {
    fn wrap_udp_socket(&self, t: std::net::UdpSocket)
        -> io::Result<Box<dyn AsyncWrappedUdpSocket>>;
}
