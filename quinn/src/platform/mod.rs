//! Uniform interface to send/recv UDP packets with ECN information.
use proto::Transmit;
use std::{io, io::IoSliceMut};

use crate::udp::RecvMeta;

#[cfg(unix)]
mod cmsg;
#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

// No ECN support
#[cfg(not(unix))]
#[path = "fallback.rs"]
mod imp;

#[allow(dead_code)] // TODO: Remove when used
/// Returns the platforms UDP socket capabilities
pub fn caps() -> UdpCapabilities {
    imp::caps()
}

/// Number of UDP packets to send/receive at a time
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;

pub trait UdpExt {
    fn init_ext(&self) -> io::Result<()>;
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize>;
    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize>;
}

/// The capabilities a UDP socket suppports on a certain platform
#[derive(Debug, Clone, Copy)]
pub struct UdpCapabilities {
    /// Whether the platform supports Generic Send Offload (GSO)
    pub gso: bool,
}
