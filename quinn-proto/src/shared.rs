use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::{cmp, fmt};

use bytes::BytesMut;
use err_derive::Error;
use rand::{Rng, RngCore};
use slog::Logger;

use crate::packet::PartialDecode;
use crate::{crypto, VarInt, MAX_CID_SIZE, RESET_TOKEN_SIZE};

/// Parameters governing the core QUIC state machine
///
/// Default values should be suitable for most internet applications. Applications protocols which
/// forbid remotely-initiated streams should set `stream_window_bidi` and `stream_window_uni` to
/// zero.
///
/// In some cases, performance or resource requirements can be improved by tuning these values to
/// suit a particular application and/or network connection. In particular, window sizes for
/// streams, stream data, and overall connection data can be tuned for a particular expected round
/// trip time, link capacity, memory availability, and rate of stream creation. Tuning for higher
/// bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time, with remote endpoints opening at most 320 new streams per
/// second.
#[derive(Debug)]
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

    /// The sender’s maximum payload size. Does not include UDP or IP overhead.
    ///
    /// Used for calculating initial and minimum congestion windows.
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
    /// Maximum quantity of out-of-order crypto layer data to buffer
    pub crypto_buffer_size: usize,
    /// Whether the implementation is permitted to set the spin bit on this connection
    ///
    /// This allows passive observers to easily judge the round trip time of a connection, which can
    /// be useful for network administration but sacrifices a small amount of privacy.
    pub allow_spin: bool,
    /// Maximum number of application datagram bytes to buffer, or None to disable datagrams
    ///
    /// The peer is forbidden to send single datagrams larger than this size. If the aggregate size
    /// of all datagrams that have been received from the peer but not consumed by the application
    /// exceeds this value, old datagrams are dropped until it is no longer exceeded.
    pub datagram_window: Option<usize>,
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
            initial_rtt: 500 * 1000, // 500ms per spec, intentionally distinct from EXPECTED_RTT

            max_datagram_size: MAX_DATAGRAM_SIZE,
            initial_window: cmp::min(
                10 * MAX_DATAGRAM_SIZE,
                cmp::max(2 * MAX_DATAGRAM_SIZE, 14720),
            ),
            minimum_window: 2 * MAX_DATAGRAM_SIZE,
            loss_reduction_factor: 0x8000, // 1/2
            persistent_congestion_threshold: 3,
            keep_alive_interval: 0,
            crypto_buffer_size: 16 * 1024,
            allow_spin: true,
            datagram_window: Some(STREAM_RWND as usize),
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
        .find(|&&(_, x)| x > VarInt::MAX.into_inner())
        {
            return Err(ConfigError::VarIntBounds(name));
        }
        if self.crypto_buffer_size < 4096 {
            return Err(ConfigError::IllegalValue(
                "crypto_buffer_size must be at least 4096",
            ));
        }
        if self.idle_timeout != 0 && u64::from(self.keep_alive_interval) >= self.idle_timeout {
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

/// Global configuration for the endpoint, affecting all connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct EndpointConfig {
    /// Length of connection IDs for the endpoint.
    ///
    /// This must be either 0 or between 4 and 18 inclusive. The length of the local connection IDs
    /// constrains the amount of simultaneous connections the endpoint can maintain. The API user is
    /// responsible for making sure that the pool is large enough to cover the intended usage.
    pub local_cid_len: usize,

    /// Private key used to send authenticated connection resets to peers who were
    /// communicating with a previous instance of this endpoint.
    pub reset_key: Vec<u8>,
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EndpointConfig")
            .field("local_cid_len", &self.local_cid_len)
            .field("reset_key", &"[ elided ]")
            .finish()
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        let mut reset_key = vec![0; 64];
        rand::thread_rng().fill_bytes(&mut reset_key);
        Self {
            local_cid_len: 8,
            reset_key,
        }
    }
}

impl EndpointConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.local_cid_len > MAX_CID_SIZE {
            return Err(ConfigError::IllegalValue(
                "local_cid_len must be at most 20",
            ));
        }
        Ok(())
    }
}

/// Parameters governing incoming connections
///
/// Default values should be suitable for most internet applications.
pub struct ServerConfig<S>
where
    S: crypto::Session,
{
    /// Transport configuration to use for incoming connections
    pub transport: Arc<TransportConfig>,

    /// TLS configuration used for incoming connections.
    ///
    /// Must be set to use TLS 1.3 only.
    pub crypto: S::ServerConfig,

    /// Private key used to authenticate data included in handshake tokens.
    pub token_key: Vec<u8>,
    /// Whether to require clients to prove ownership of an address before committing resources.
    ///
    /// Introduces an additional round-trip to the handshake to make denial of service attacks more difficult.
    pub use_stateless_retry: bool,
    /// Microseconds after a stateless retry token was issued for which it's considered valid.
    pub retry_token_lifetime: u64,

    /// Maximum number of incoming connections to buffer.
    ///
    /// Accepting a connection removes it from the buffer, so this does not need to be large.
    pub accept_buffer: u32,

    /// Whether to allow clients to migrate to new addresses
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub migration: bool,
}

impl<S> fmt::Debug for ServerConfig<S>
where
    S: crypto::Session,
    S::ServerConfig: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerConfig<T>")
            .field("transport", &self.transport)
            .field("crypto", &self.crypto)
            .field("token_key", &"[ elided ]")
            .field("use_stateless_retry", &self.use_stateless_retry)
            .field("retry_token_lifetime", &self.retry_token_lifetime)
            .field("accept_buffer", &self.accept_buffer)
            .field("migration", &self.migration)
            .finish()
    }
}

impl<S> Default for ServerConfig<S>
where
    S: crypto::Session,
    S::ServerConfig: Default,
{
    fn default() -> Self {
        let rng = &mut rand::thread_rng();

        let mut token_key = vec![0; 64];
        rng.fill_bytes(&mut token_key);

        Self {
            transport: Arc::new(TransportConfig::default()),
            crypto: S::ServerConfig::default(),

            token_key,
            use_stateless_retry: false,
            retry_token_lifetime: 15_000_000,

            accept_buffer: 1024,

            migration: true,
        }
    }
}

impl<S> Clone for ServerConfig<S>
where
    S: crypto::Session,
    S::ServerConfig: Clone,
{
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            crypto: self.crypto.clone(),
            token_key: self.token_key.clone(),
            use_stateless_retry: self.use_stateless_retry,
            retry_token_lifetime: self.retry_token_lifetime,
            accept_buffer: self.accept_buffer,
            migration: self.migration,
        }
    }
}

/// Configuration for outgoing connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig<C> {
    /// Transport configuration to use
    pub transport: Arc<TransportConfig>,

    /// Cryptographic configuration to use
    pub crypto: C,

    /// Diagnostic logger
    ///
    /// If unset, the endpoint's logger is used.
    pub log: Option<Logger>,
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

/// Events sent from an Endpoint to a Connection
#[derive(Debug)]
pub struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram {
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        first_decode: PartialDecode,
        remaining: Option<BytesMut>,
    },
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>),
}

/// Events sent from a Connection to an Endpoint
#[derive(Debug)]
pub struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// A stateless reset token has been issued for the connection
    ResetToken(ResetToken),
    /// The connection needs connection identifiers
    NeedIdentifiers(u64),
    /// Stop routing connection ID for this sequence number to the connection
    RetireConnectionId(u64),
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
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
    #[doc(hidden)]
    ECT0 = 0b10,
    #[doc(hidden)]
    ECT1 = 0b01,
    #[doc(hidden)]
    CE = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
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
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl std::borrow::Borrow<[u8]> for ResetToken {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IssuedCid {
    pub sequence: u64,
    pub id: ConnectionId,
    pub reset_token: ResetToken,
}
