//! Uniform interface to send/recv UDP packets with ECN information.
use proto::{EcnCodepoint, Transmit};
use std::{io, net::SocketAddr};

#[cfg(unix)]
mod cmsg;
#[cfg(unix)]
mod unix;

// No ECN support
#[cfg(not(unix))]
mod fallback;

pub trait UdpExt {
    fn init_ext(&self) -> io::Result<()>;
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize>;
    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)>;
}
