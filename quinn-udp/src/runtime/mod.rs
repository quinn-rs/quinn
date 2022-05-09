use std::fmt::Debug;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::task::{Context, Poll};

#[cfg(feature = "runtime-tokio")]
mod tokio_runtime;
#[cfg(feature = "runtime-tokio")]
pub use tokio_runtime::*;

#[cfg(feature = "runtime-async-std")]
mod async_std_runtime;
#[cfg(feature = "runtime-async-std")]
pub use async_std_runtime::*;

pub trait AsyncUdpSocket: Send + Debug {
    fn poll_read_ready(&self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn poll_write_ready(&self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn clear_read_ready(&self, cx: &mut Context);

    fn clear_write_ready(&self, cx: &mut Context);

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    // On Unix we expect to be able to access the underlying std UdpSocket
    // to be able to implement more advanced features
    #[cfg(unix)]
    fn get_ref(&self) -> &StdUdpSocket;
}

pub trait Runtime: Send + Sync + Debug + 'static {
    fn wrap_udp_socket(&self, t: StdUdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>>;
}
