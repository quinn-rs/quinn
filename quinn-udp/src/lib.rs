//! Uniform interface to send/recv UDP packets with ECN information.
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use proto::{EcnCodepoint, Transmit};
use tracing::warn;

#[cfg(unix)]
mod cmsg;
#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

// No ECN support
#[cfg(not(any(unix, windows)))]
#[path = "fallback.rs"]
mod imp;

pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;

/// The capabilities a UDP socket suppports on a certain platform
#[derive(Debug)]
pub struct UdpState {
    max_gso_segments: AtomicUsize,
    gro_segments: usize,

    /// True if we have received EINVAL error from `sendmsg` or `sendmmsg` system call at least once.
    ///
    /// If enabled, we assume that old kernel is used and switch to fallback mode.
    /// In particular, we do not use IP_TOS cmsg_type in this case,
    /// which is not supported on Linux <3.13 and results in not sending the UDP packet at all.
    #[cfg(not(windows))]
    sendmsg_einval: AtomicBool,
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

    /// Returns true if we previously got an EINVAL error from `sendmsg` or `sendmmsg` syscall.
    #[inline]
    #[cfg(not(windows))]
    pub fn sendmsg_einval(&self) -> bool {
        self.sendmsg_einval.load(Ordering::Relaxed)
    }

    /// Sets the flag indicating we got EINVAL error from `sendmsg` or `sendmmsg` syscall.
    #[inline]
    #[cfg(not(windows))]
    pub fn set_sendmsg_einval(&self) {
        self.sendmsg_einval.store(true, Ordering::Relaxed)
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
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    transmit: &Transmit,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisend lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        warn!(
        "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
            err, transmit.destination, transmit.src_ip, transmit.ecn, transmit.contents.len(), transmit.segment_size);
    }
}

/// A borrowed UDP socket
///
/// On Unix, constructible via `From<T: AsRawFd>`. On Windows, constructible via `From<T:
/// AsRawSocket>`.
// Wrapper around socket2 to avoid making it a public dependency and incurring stability risk
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsRawFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsRawSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}
