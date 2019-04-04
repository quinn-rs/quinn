use std::net::SocketAddr;
use std::sync::Arc;
use std::{cmp, fmt};

use bytes::BytesMut;
use err_derive::Error;
use rand::Rng;
use slog::Logger;

use crate::connection::Timer;
use crate::packet::PartialDecode;
use crate::{crypto, varint, MAX_CID_SIZE, MIN_CID_SIZE};

/// Parameters governing the core QUIC state machine
///
/// This should be tuned to suit the application. In particular, window sizes for streams, stream
/// data, and overall connection data should be set differently depending on the expected round trip
/// time, link capacity, memory availability, and rate of stream creation. Tuning for higher
/// bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time, with remote endpoints opening at most 320 new streams per
/// second. Applications which do not require remotely-initiated streams should set the stream
/// windows to zero.
pub struct TransportConfig {
    /// Maximum number of bidirectional streams that may be initiated by the peer but not yet
    /// accepted locally
    ///
    /// Must be nonzero for the peer to open any bidirectional streams.
    ///
    /// Any number of streams may be in flight concurrently. However, to ensure predictable resource
    /// use, the number of streams which the peer has initiated but which the local application has
    /// not yet accepted will be kept below this threshold.
    ///
    /// Because it takes at least one round trip for an endpoint to open a new stream and be
    /// notified of its peer's flow control updates, this imposes a hard upper bound on the number
    /// of streams that may be opened per round-trip. In other words, this should be set to at least
    /// the desired number of streams opened per unit time, multiplied by the round trip time.
    ///
    /// Note that worst-case memory use is directly proportional to `stream_window_bidi *
    /// stream_receive_window`, with an upper bound proportional to `receive_window`.
    pub stream_window_bidi: u64,
    /// Variant of `stream_window_bidi` affecting unidirectional streams
    pub stream_window_uni: u64,
    /// Maximum duration of inactivity to accept before timing out the connection (ms).
    ///
    /// The actual value used is the minimum of this and the peer's own idle timeout. 0 for none.
    pub idle_timeout: u64,
    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub stream_receive_window: u64,
    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub receive_window: u64,
    /// Maximum number of bytes to transmit to a peer without acknowledgment
    ///
    /// Provides an upper bound on memory when communicating with peers that issue large amounts of
    /// flow control credit. Endpoints that wish to handle large numbers of connections robustly
    /// should take care to set this low enough to guarantee memory exhaustion does not occur if
    /// every connection uses the entire window.
    pub send_window: u64,

    /// Maximum number of tail loss probes before an RTO fires.
    pub max_tlps: u32,
    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost.
    pub packet_threshold: u32,
    /// Maximum reordering in time space before time based loss detection considers a packet lost.
    /// 0.16 format, added to 1
    pub time_threshold: u16,
    /// The length of the peer’s delayed ack timer (μs).
    pub delayed_ack_timeout: u64,
    /// The RTT used before an RTT sample is taken (μs)
    pub initial_rtt: u64,

    /// The max packet size that was used for calculating default and minimum congestion windows.
    pub max_datagram_size: u64,
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub initial_window: u64,
    /// Default minimum congestion window.
    ///
    /// Recommended value: `2 * max_datagram_size`.
    pub minimum_window: u64,
    /// Reduction in congestion window when a new loss event is detected. 0.16 format
    pub loss_reduction_factor: u16,
    /// Number of consecutive PTOs after which network is considered to be experiencing persistent congestion.
    pub persistent_congestion_threshold: u32,
    /// Number of milliseconds of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// 0 to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub keep_alive_interval: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u64 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u64 = 12500 * 1000; // bytes/s
                                                        // Window size needed to avoid pipeline
                                                        // stalls
        const STREAM_RWND: u64 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;
        const MAX_DATAGRAM_SIZE: u64 = 1200;

        TransportConfig {
            stream_window_bidi: 32,
            stream_window_uni: 32,
            idle_timeout: 10_000,
            stream_receive_window: STREAM_RWND,
            receive_window: 8 * STREAM_RWND,
            send_window: 8 * STREAM_RWND,

            max_tlps: 2,
            packet_threshold: 3,
            time_threshold: 0x2000, // 1/8
            delayed_ack_timeout: 25 * 1000,
            initial_rtt: EXPECTED_RTT as u64 * 1000,

            max_datagram_size: MAX_DATAGRAM_SIZE,
            initial_window: cmp::min(
                10 * MAX_DATAGRAM_SIZE,
                cmp::max(2 * MAX_DATAGRAM_SIZE, 14720),
            ),
            minimum_window: 2 * MAX_DATAGRAM_SIZE,
            loss_reduction_factor: 0x8000, // 1/2
            persistent_congestion_threshold: 3,
            keep_alive_interval: 0,
        }
    }
}

impl TransportConfig {
    pub(crate) fn validate(&self, log: &Logger) -> Result<(), ConfigError> {
        if let Some((name, _)) = [
            ("stream_window_bidi", self.stream_window_bidi),
            ("stream_window_uni", self.stream_window_uni),
            ("receive_window", self.receive_window),
            ("stream_receive_window", self.stream_receive_window),
            ("idle_timeout", self.idle_timeout),
        ]
        .iter()
        .find(|&&(_, x)| x > varint::MAX_VALUE)
        {
            return Err(ConfigError::VarIntBounds(name));
        }
        if self.idle_timeout != 0 && self.keep_alive_interval as u64 >= self.idle_timeout {
            warn!(
                log,
                "keep-alive interval {} is ineffective due to lower idle timeout {}",
                self.keep_alive_interval,
                self.idle_timeout
            );
        }
        Ok(())
    }
}

/// Errors in the configuration of an endpoint
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The supplied configuration contained an invalid value
    #[error(display = "illegal configuration value: {}", _0)]
    IllegalValue(&'static str),
    /// A configuration field that will be encoded as a variable-length integer exceeds the 0..2^62
    /// range
    #[error(display = "{} must be at most 2^62-1", _0)]
    VarIntBounds(&'static str),
}

/// Events to be sent to the Connection
pub enum ConnectionEvent {
    Datagram {
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        first_decode: PartialDecode,
        remaining: Option<BytesMut>,
    },
    NewIdentifiers(Vec<(u64, ConnectionId)>),
    Timeout(Timer),
}

/// Events to be sent to the Endpoint
#[derive(Clone, Debug)]
pub enum EndpointEvent {
    Drained,
    Migrated(SocketAddr),
    NeedIdentifiers,
    /// Stop routing connection ID for this sequence number to this `Connection`
    RetireConnectionId(u64),
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    pub len: u8,
    pub bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        debug_assert!(
            bytes.is_empty() || (bytes.len() >= MIN_CID_SIZE && bytes.len() <= MAX_CID_SIZE)
        );
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].clone_from_slice(&bytes);
        res
    }

    pub(crate) fn random<R: Rng>(rng: &mut R, len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        let mut rng_bytes = [0; MAX_CID_SIZE];
        rng.fill_bytes(&mut rng_bytes);
        res.bytes[..len].clone_from_slice(&rng_bytes[..len]);
        res
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl slog::Value for ConnectionId {
    fn serialize(
        &self,
        _: &slog::Record<'_>,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments(key, &format_args!("{}", self))
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    ECT0 = 0b10,
    ECT1 = 0b01,
    CE = 0b11,
}

impl EcnCodepoint {
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => ECT0,
            0b01 => ECT1,
            0b11 => CE,
            _ => {
                return None;
            }
        })
    }

    pub fn bits(self) -> u8 {
        self as u8
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub server_name: String,
    pub tls_config: Arc<crypto::ClientConfig>,
}
