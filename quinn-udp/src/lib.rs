//! Uniform interface to send/recv UDP packets with ECN information.
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use proto::{EcnCodepoint, Transmit};
use tracing::warn;

macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

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

/// The capabilities a UDP socket suppports on a certain platform
#[derive(Debug)]
pub struct UdpState {
    max_gso_segments: AtomicUsize,
    gro_segments: usize,
}

impl UdpState {
    pub fn new() -> Self {
        imp::udp_state()
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        self.max_gso_segments.load(Ordering::Relaxed)
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub fn gro_segments(&self) -> usize {
        self.gro_segments
    }
}

impl Default for UdpState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    pub addr: SocketAddr,
    pub len: usize,
    pub stride: usize,
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
            stride: 0,
            ecn: None,
            dst_ip: None,
        }
    }
}

/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
fn log_sendmsg_error(
    last_send_error: &mut Instant,
    err: impl core::fmt::Debug,
    transmit: &Transmit,
) {
    let now = Instant::now();
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        warn!(
        "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
            err, transmit.destination, transmit.src_ip, transmit.ecn, transmit.contents.len(), transmit.segment_size);
    }
}
