//! Uniform interface to send/recv UDP packets with ECN information.
use quinn_proto::EcnCodepoint;
use std::{io, net::SocketAddr};

// The Linux code should work for most unixes, but as of this writing nobody's ported the
// CMSG_... macros to the libc crate for any of the BSDs.
#[cfg(target_os = "linux")]
mod cmsg;
#[cfg(target_os = "linux")]
mod linux;

// No ECN support
#[cfg(not(target_os = "linux"))]
mod fallback;

pub trait UdpExt {
    fn init_ext(&self) -> io::Result<()>;
    fn send_ext(
        &self,
        remote: &SocketAddr,
        ecn: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> io::Result<usize>;
    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)>;
}
