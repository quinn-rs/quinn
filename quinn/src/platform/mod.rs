//! Uniform interface to send/recv UDP packets with ECN information.
use proto::Transmit;
use std::{io, io::IoSliceMut};

use crate::udp::RecvMeta;

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
    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize>;
}
