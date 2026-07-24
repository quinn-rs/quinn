//! Uniform interface to send and receive UDP packets with advanced features useful for QUIC
//!
//! This crate exposes kernel UDP stack features available on most modern systems which are required
//! for an efficient and conformant QUIC implementation. As of this writing, these are not available
//! in std or major async runtimes, and their niche character and complexity are a barrier to adding
//! them. Hence, a dedicated crate.
//!
//! Exposed features include:
//!
//! - Segmentation offload for bulk send and receive operations, reducing CPU load.
//! - Reporting the exact destination address of received packets and specifying explicit source
//!   addresses for sent packets, allowing responses to be sent from the address that the peer
//!   expects when there are multiple possibilities. This is common when bound to a wildcard address
//!   in IPv6 due to [RFC 8981] temporary addresses.
//! - [Explicit Congestion Notification], which is required by QUIC to prevent packet loss and reduce
//!   latency on congested links when supported by the network path.
//! - Disabled IP-layer fragmentation, which allows the true physical MTU to be detected and reduces
//!   risk of QUIC packet loss.
//!
//! Some features are unavailable in some environments. This can be due to an outdated operating
//! system or drivers. Some operating systems may not implement desired features at all, or may not
//! yet be supported by the crate. When support is unavailable, functionality will gracefully
//! degrade.
//!
//! [RFC 8981]: https://www.rfc-editor.org/rfc/rfc8981.html
//! [Explicit Congestion Notification]: https://www.rfc-editor.org/rfc/rfc3168.html
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use core::time::Duration;
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
};
#[cfg(not(wasm_browser))]
use std::{sync::Mutex, time::Instant};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock;

#[cfg(apple_fast)]
mod apple_fast;

#[cfg(any(unix, windows))]
mod cmsg;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

// No ECN support
#[cfg(not(any(wasm_browser, unix, windows)))]
#[path = "fallback.rs"]
mod imp;

#[allow(unused_imports, unused_macros)]
mod log {
    #[cfg(all(feature = "log", not(feature = "tracing-log")))]
    pub(crate) use log::{debug, error, info, trace, warn};

    #[cfg(feature = "tracing-log")]
    pub(crate) use tracing::{debug, error, info, trace, warn};

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    mod no_op {
        macro_rules! trace    ( ($($tt:tt)*) => {{}} );
        macro_rules! debug    ( ($($tt:tt)*) => {{}} );
        macro_rules! info     ( ($($tt:tt)*) => {{}} );
        macro_rules! log_warn ( ($($tt:tt)*) => {{}} );
        macro_rules! error    ( ($($tt:tt)*) => {{}} );

        pub(crate) use {debug, error, info, log_warn as warn, trace};
    }

    #[cfg(not(any(feature = "log", feature = "tracing-log")))]
    pub(crate) use no_op::*;
}

#[cfg(not(wasm_browser))]
pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
#[cfg(not(wasm_browser))]
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;
/// Number of UDP packets to send/receive at a time
#[cfg(wasm_browser)]
pub const BATCH_SIZE: usize = 1;

/// Metadata for a single buffer filled with bytes received from the network
///
/// This associated buffer can contain one or more datagrams, see [`stride`].
///
/// [`stride`]: RecvMeta::stride
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct RecvMeta {
    /// The source address of the datagram(s) contained in the buffer
    pub addr: SocketAddr,
    /// The number of bytes the associated buffer has
    pub len: usize,
    /// The size of a single datagram in the associated buffer
    ///
    /// When GRO (Generic Receive Offload) is used this indicates the size of a single
    /// datagram inside the buffer. If the buffer is larger, that is if [`len`] is greater
    /// then this value, then the individual datagrams contained have their boundaries at
    /// `stride` increments from the start. The last datagram could be smaller than
    /// `stride`.
    ///
    /// [`len`]: RecvMeta::len
    pub stride: usize,
    /// The Explicit Congestion Notification bits for the datagram(s) in the buffer
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address which was encoded in this datagram
    ///
    /// Populated on platforms: Windows, Linux, Android (API level > 25),
    /// FreeBSD, OpenBSD, NetBSD, macOS, and iOS.
    pub dst_ip: Option<IpAddr>,
    /// The interface index of the interface on which the datagram was received
    pub interface_index: Option<u32>,
    /// Kernel receive timestamp as Unix epoch
    ///
    /// Populated on platforms: Linux, Android.
    pub timestamp: Option<Duration>,
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
            interface_index: None,
            timestamp: None,
        }
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: &'a [u8],
    /// The segment size if this transmission contains multiple datagrams.
    ///
    /// This is `None` if the transmit only contains a single datagram.
    /// A value of zero is treated like `None`.
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src_ip: Option<IpAddr>,
}

impl<'a> Transmit<'a> {
    /// Returns the number of datagrams encoded by this transmit.
    ///
    /// A transmit without a `segment_size` always represents one datagram, including when its
    /// contents are empty.
    pub fn datagram_count(&self) -> usize {
        match self.segment_size {
            Some(size) if size != 0 && size < self.contents.len() => {
                self.contents.len().div_ceil(size)
            }
            Some(_) | None => 1,
        }
    }

    /// Advances this transmit by `sent` datagrams.
    ///
    /// Returns the unsent remainder, or `None` if the entire transmit was consumed. The returned
    /// transmit borrows a suffix of the same payload; packet data is never copied.
    pub fn advance(mut self, sent: SendCount) -> Option<Self> {
        let sent = sent.get();
        let segment_size = match self.segment_size {
            Some(size) if size != 0 && size < self.contents.len() => size,
            Some(_) | None => {
                debug_assert_eq!(sent, 1, "a single-datagram transmit must consume once");
                return None;
            }
        };

        debug_assert!(sent <= self.contents.len().div_ceil(segment_size));

        let offset = sent.saturating_mul(segment_size);
        if offset >= self.contents.len() {
            return None;
        }

        self.contents = &self.contents[offset..];

        Some(self)
    }

    /// Computes the effective segment-size of the packet.
    ///
    /// Some (older) network drivers don't like being told to do GSO even if
    /// there is effectively only a single segment.
    /// (i.e. `segment_size == contents.len()`)
    /// Additionally, a `segment_size` that is greater than the content also
    /// means there is effectively only a single segment.
    /// This case is actually quite common when splitting up a prepared GSO batch
    /// again after GSO has been disabled because the last datagram in a GSO
    /// batch is allowed to be smaller than the segment size.
    #[cfg_attr(apple_fast, allow(dead_code))] // Used by prepare_msg, which is unused when apple_fast
    fn effective_segment_size(&self) -> Option<usize> {
        match self.segment_size? {
            0 => None,
            size if size >= self.contents.len() => None,
            size => Some(size),
        }
    }

    /// Returns a transmit containing at most `max_datagrams.max(1)` leading datagrams.
    #[cfg(not(wasm_browser))]
    fn limit(&self, max_datagrams: usize) -> Self {
        let max_datagrams = max_datagrams.max(1);

        let segment_size = self.effective_segment_size();

        let contents = match segment_size {
            Some(size) => {
                &self.contents[..self.contents.len().min(size.saturating_mul(max_datagrams))]
            }
            None => self.contents,
        };

        let segment_size = segment_size.filter(|&size| size < contents.len());

        Self {
            destination: self.destination,
            ecn: self.ecn,
            contents,
            segment_size,
            src_ip: self.src_ip,
        }
    }
}

/// Number of leading datagrams consumed by a send operation.
///
/// Pass this to [`Transmit::advance`] on the transmit supplied to the send operation. This consumes
/// the previous transmit and returns its unsent remainder, if any.
#[must_use = "send progress must be used to advance the transmitted packet"]
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SendCount(NonZeroUsize);

impl SendCount {
    /// Constructs a send count, or returns `None` if `value` is zero.
    pub fn new(value: usize) -> Option<Self> {
        Some(Self(NonZeroUsize::new(value)?))
    }

    #[cfg(not(wasm_browser))]
    fn from_datagram_count(value: usize) -> Self {
        Self::new(value).expect("a send operation must consume at least one datagram")
    }

    /// Returns the number of consumed datagrams.
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// Asynchronous transport-layer errors reported by the operating system
///
/// On Linux and Android these are delivered via the socket error queue
/// (`MSG_ERRQUEUE`) and originate from ICMP messages.
///
/// These errors are out-of-band and do not correspond to a received packet.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct TransportError {
    /// Address associated with the error
    ///
    /// This is the remote peer or an intermediate network device that triggered the error.
    /// Returns `None` if the kernel cannot determine the source (e.g. `AF_UNSPEC`).
    pub addr: Option<SocketAddr>,
    /// Transport-layer error details
    pub payload: TransportErrorPayload,
    /// The raw error code from the underlying operating system
    pub raw_errno: i32,
}

impl TransportError {
    /// Returns the recommended MTU for packet-too-big errors
    pub fn mtu(&self) -> Option<u32> {
        match self.payload {
            TransportErrorPayload::TooBig { mtu } => Some(mtu),
            _ => None,
        }
    }
}

/// Transport-layer error details reported by the kernel
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum TransportErrorPayload {
    /// Destination host or port is unreachable
    Unreachable,
    /// Packet exceeds path MTU
    TooBig {
        /// Recommended Maximum Transmission Unit
        mtu: u32,
    },
    /// Other transport-layer or kernel-reported error
    Other,
}

/// Returns true if the given I/O error corresponds to a message size error
///
/// Useful, for example, after invoking [`io::Error::last_os_error()`]
/// to check if the last OS error was a message size error
/// (EMSGSIZE on Unix, WSAEMSGSIZE on Windows).
///
/// Note: EMSGSIZE's value is not standardized across OSes (90 on Linux,
/// 40 on macOS/iOS/BSD; on Windows, `io::Error::raw_os_error()` returns
/// the Winsock error WSAEMSGSIZE (10040) via `GetLastError()`, which is
/// distinct from the MSVCRT `errno.h` EMSGSIZE value of 115, which is
/// never actually populated by socket operations).
pub fn is_msg_size_err(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        err.raw_os_error() == Some(WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Log at most 1 IO error per minute
#[cfg(not(wasm_browser))]
const IO_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
#[cfg(all(not(wasm_browser), any(feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    transmit: &Transmit<'_>,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisend lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        log::warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, ecn: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            transmit.destination,
            transmit.src_ip,
            transmit.ecn,
            transmit.contents.len(),
            transmit.segment_size
        );
    }
}

// No-op
#[cfg(not(any(wasm_browser, feature = "tracing-log", feature = "log")))]
fn log_sendmsg_error(_: &Mutex<Instant>, _: impl core::fmt::Debug, _: &Transmit<'_>) {}

/// A borrowed UDP socket
///
/// On Unix, constructible via `From<T: AsFd>`. On Windows, constructible via `From<T:
/// AsSocket>`.
// Wrapper around socket2 to avoid making it a public dependency and incurring stability risk
#[cfg(not(wasm_browser))]
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn effective_segment_size() {
        assert_eq!(
            make_transmit(&[0u8; 10], Some(15)).effective_segment_size(),
            None,
            "segment_size > content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(10)).effective_segment_size(),
            None,
            "segment_size == content_len should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], None).effective_segment_size(),
            None,
            "no segment_size should yield no effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(5)).effective_segment_size(),
            Some(5),
            "segment_size < content_len should yield effective segment_size"
        );
        assert_eq!(
            make_transmit(&[0u8; 10], Some(0)).effective_segment_size(),
            None,
            "zero is not a valid segment size"
        );
    }

    #[test]
    fn datagram_count() {
        let contents = [0u8; 11];
        let transmit = make_transmit(&contents, Some(5));

        assert!(SendCount::new(0).is_none());

        assert_eq!(transmit.datagram_count(), 3);
        let sent = SendCount::new(1).unwrap();
        assert_eq!(sent.get(), 1);

        assert_eq!(make_transmit(&[], None).datagram_count(), 1);
        assert_eq!(make_transmit(&contents, None).datagram_count(), 1);
        assert_eq!(make_transmit(&contents, Some(0)).datagram_count(), 1);
        assert_eq!(make_transmit(&contents, Some(20)).datagram_count(), 1);
    }

    #[test]
    fn advance_returns_the_unsent_remainder() {
        let contents = [0u8; 11];
        let transmit = make_transmit(&contents, Some(5));

        let transmit = transmit.advance(SendCount::new(1).unwrap()).unwrap();
        assert_eq!(transmit.contents.len(), 6);
        assert_eq!(transmit.datagram_count(), 2);

        let transmit = transmit.advance(SendCount::new(1).unwrap()).unwrap();
        assert_eq!(transmit.contents.len(), 1);
        assert_eq!(transmit.datagram_count(), 1);
        assert!(transmit.advance(SendCount::new(1).unwrap()).is_none());

        assert!(
            make_transmit(&[], None)
                .advance(SendCount::new(1).unwrap())
                .is_none()
        );
        assert!(
            make_transmit(&contents, Some(0))
                .advance(SendCount::new(1).unwrap())
                .is_none()
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn advancing_by_too_large_a_send_count_triggers_debug_assertion() {
        let contents = [0u8; 1];
        let _ = make_transmit(&contents, None).advance(SendCount::new(2).unwrap());
    }

    #[test]
    fn limit_is_infallible_for_degenerate_limits_and_segment_sizes() {
        let contents = [0u8; 11];

        for segment_size in [None, Some(0)] {
            let transmit = make_transmit(&contents, segment_size);
            let transmit = transmit.limit(0);

            assert_eq!(transmit.contents, contents);
            assert_eq!(transmit.datagram_count(), 1);
            assert_eq!(transmit.segment_size, None);
        }
    }

    #[test]
    fn limit_preserves_a_datagram_prefix() {
        let contents = [0u8; 11];
        let transmit = make_transmit(&contents, Some(5));

        let prefix = transmit.limit(2);
        assert_eq!(prefix.contents.len(), 10);
        assert_eq!(prefix.datagram_count(), 2);
        assert_eq!(prefix.segment_size, Some(5));
        assert_eq!(prefix.destination, transmit.destination);
        assert_eq!(prefix.ecn, transmit.ecn);
        assert_eq!(prefix.src_ip, transmit.src_ip);

        let complete = transmit.limit(3);
        assert_eq!(complete.contents.len(), 11);
        assert_eq!(complete.datagram_count(), 3);
        assert_eq!(complete.segment_size, Some(5));

        let single = prefix.limit(1);
        assert_eq!(single.contents.len(), 5);
        assert_eq!(single.datagram_count(), 1);
        assert_eq!(single.segment_size, None);
    }

    fn make_transmit(contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
        Transmit {
            destination: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1)),
            ecn: None,
            contents,
            segment_size,
            src_ip: None,
        }
    }
}
