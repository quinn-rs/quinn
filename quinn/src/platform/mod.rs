//! Uniform interface to send/recv UDP packets with ECN information.
use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use proto::{EcnCodepoint, Transmit};

#[cfg(unix)]
mod cmsg;
#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

// No ECN support
#[cfg(not(unix))]
#[path = "fallback.rs"]
mod imp;

pub use imp::UdpSocket;

/// Number of UDP packets to send/receive at a time
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;

pub trait UdpExt {
    fn init_ext(&self) -> io::Result<()>;
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize>;
    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize>;
}

/// The capabilities a (UDP) socket suppports on a certain platform
#[derive(Debug, Clone, Copy)]
pub struct SocketCapabilities {
    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    /// This is 1 if the platform doesn't support GSO.
    pub max_gso_segments: usize,
}

/// Meta information regarding the received buffer
#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    /// The remote address where the buffer came from
    pub addr: SocketAddr,
    /// The length of the buffer
    pub len: usize,
    /// The ECN bit
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address which was encoded in this datagram
    pub dst_ip: Option<IpAddr>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            ecn: None,
            dst_ip: None,
        }
    }
}
