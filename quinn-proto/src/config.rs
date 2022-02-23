use std::{convert::TryInto, fmt, num::TryFromIntError, sync::Arc, time::Duration};

use rand::RngCore;
use thiserror::Error;

use crate::{
    cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator},
    congestion,
    crypto::{self, HandshakeTokenKey, HmacKey},
    VarInt, VarIntBoundsExceeded, DEFAULT_SUPPORTED_VERSIONS,
};

/// Parameters governing the core QUIC state machine
///
/// Default values should be suitable for most internet applications. Applications protocols which
/// forbid remotely-initiated streams should set `max_concurrent_bidi_streams` and
/// `max_concurrent_uni_streams` to zero.
///
/// In some cases, performance or resource requirements can be improved by tuning these values to
/// suit a particular application and/or network connection. In particular, data window sizes can be
/// tuned for a particular expected round trip time, link capacity, and memory availability. Tuning
/// for higher bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time.
pub struct TransportConfig {
    pub(crate) max_concurrent_bidi_streams: VarInt,
    pub(crate) max_concurrent_uni_streams: VarInt,
    pub(crate) max_idle_timeout: Option<VarInt>,
    pub(crate) stream_receive_window: VarInt,
    pub(crate) receive_window: VarInt,
    pub(crate) send_window: u64,

    pub(crate) max_tlps: u32,
    pub(crate) packet_threshold: u32,
    pub(crate) time_threshold: f32,
    pub(crate) initial_rtt: Duration,

    pub(crate) persistent_congestion_threshold: u32,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) crypto_buffer_size: usize,
    pub(crate) allow_spin: bool,
    pub(crate) datagram_receive_buffer_size: Option<usize>,
    pub(crate) datagram_send_buffer_size: usize,

    pub(crate) congestion_controller_factory: Box<dyn congestion::ControllerFactory + Send + Sync>,
}

impl TransportConfig {
    /// Maximum number of incoming bidirectional streams that may be open concurrently
    ///
    /// Must be nonzero for the peer to open any bidirectional streams.
    ///
    /// Worst-case memory use is directly proportional to `max_concurrent_bidi_streams *
    /// stream_receive_window`, with an upper bound proportional to `receive_window`.
    pub fn max_concurrent_bidi_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_bidi_streams = value;
        self
    }

    /// Variant of `max_concurrent_bidi_streams` affecting unidirectional streams
    pub fn max_concurrent_uni_streams(&mut self, value: VarInt) -> &mut Self {
        self.max_concurrent_uni_streams = value;
        self
    }

    /// Maximum duration of inactivity to accept before timing out the connection.
    ///
    /// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
    /// represents an infinite timeout.
    ///
    /// **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite
    /// idle timeout can result in permanently hung futures!
    ///
    /// ```
    /// # use std::{convert::TryInto, time::Duration};
    /// # use quinn_proto::{TransportConfig, VarInt, VarIntBoundsExceeded};
    /// # fn main() -> Result<(), VarIntBoundsExceeded> {
    /// let mut config = TransportConfig::default();
    ///
    /// // Set the idle timeout as `VarInt`-encoded milliseconds
    /// config.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    ///
    /// // Set the idle timeout as a `Duration`
    /// config.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    /// # Ok(())
    /// # }
    /// ```
    pub fn max_idle_timeout(&mut self, value: Option<IdleTimeout>) -> &mut Self {
        self.max_idle_timeout = value.map(|t| t.0);
        self
    }

    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub fn stream_receive_window(&mut self, value: VarInt) -> &mut Self {
        self.stream_receive_window = value;
        self
    }

    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub fn receive_window(&mut self, value: VarInt) -> &mut Self {
        self.receive_window = value;
        self
    }

    /// Maximum number of bytes to transmit to a peer without acknowledgment
    ///
    /// Provides an upper bound on memory when communicating with peers that issue large amounts of
    /// flow control credit. Endpoints that wish to handle large numbers of connections robustly
    /// should take care to set this low enough to guarantee memory exhaustion does not occur if
    /// every connection uses the entire window.
    pub fn send_window(&mut self, value: u64) -> &mut Self {
        self.send_window = value;
        self
    }

    /// Maximum number of tail loss probes before an RTO fires.
    pub fn max_tlps(&mut self, value: u32) -> &mut Self {
        self.max_tlps = value;
        self
    }

    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost. Should not be less than 3, per RFC5681.
    pub fn packet_threshold(&mut self, value: u32) -> &mut Self {
        self.packet_threshold = value;
        self
    }

    /// Maximum reordering in time space before time based loss detection considers a packet lost,
    /// as a factor of RTT
    pub fn time_threshold(&mut self, value: f32) -> &mut Self {
        self.time_threshold = value;
        self
    }

    /// The RTT used before an RTT sample is taken
    pub fn initial_rtt(&mut self, value: Duration) -> &mut Self {
        self.initial_rtt = value;
        self
    }

    /// Number of consecutive PTOs after which network is considered to be experiencing persistent congestion.
    pub fn persistent_congestion_threshold(&mut self, value: u32) -> &mut Self {
        self.persistent_congestion_threshold = value;
        self
    }

    /// Period of inactivity before sending a keep-alive packet
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// `None` to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub fn keep_alive_interval(&mut self, value: Option<Duration>) -> &mut Self {
        self.keep_alive_interval = value;
        self
    }

    /// Maximum quantity of out-of-order crypto layer data to buffer
    pub fn crypto_buffer_size(&mut self, value: usize) -> &mut Self {
        self.crypto_buffer_size = value;
        self
    }

    /// Whether the implementation is permitted to set the spin bit on this connection
    ///
    /// This allows passive observers to easily judge the round trip time of a connection, which can
    /// be useful for network administration but sacrifices a small amount of privacy.
    pub fn allow_spin(&mut self, value: bool) -> &mut Self {
        self.allow_spin = value;
        self
    }

    /// Maximum number of incoming application datagram bytes to buffer, or None to disable
    /// incoming datagrams
    ///
    /// The peer is forbidden to send single datagrams larger than this size. If the aggregate size
    /// of all datagrams that have been received from the peer but not consumed by the application
    /// exceeds this value, old datagrams are dropped until it is no longer exceeded.
    pub fn datagram_receive_buffer_size(&mut self, value: Option<usize>) -> &mut Self {
        self.datagram_receive_buffer_size = value;
        self
    }

    /// Maximum number of outgoing application datagram bytes to buffer
    ///
    /// While datagrams are sent ASAP, it is possible for an application to generate data faster
    /// than the link, or even the underlying hardware, can transmit them. This limits the amount of
    /// memory that may be consumed in that case. When the send buffer is full and a new datagram is
    /// sent, older datagrams are dropped until sufficient space is available.
    pub fn datagram_send_buffer_size(&mut self, value: usize) -> &mut Self {
        self.datagram_send_buffer_size = value;
        self
    }

    /// How to construct new `congestion::Controller`s
    ///
    /// Typically the refcounted configuration of a `congestion::Controller`,
    /// e.g. a `congestion::NewRenoConfig`.
    ///
    /// # Example
    /// ```
    /// # use quinn_proto::*; use std::sync::Arc;
    /// let mut config = TransportConfig::default();
    /// config.congestion_controller_factory(Arc::new(congestion::NewRenoConfig::default()));
    /// ```
    pub fn congestion_controller_factory(
        &mut self,
        factory: impl congestion::ControllerFactory + Send + Sync + 'static,
    ) -> &mut Self {
        self.congestion_controller_factory = Box::new(factory);
        self
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100; // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s
                                                        // Window size needed to avoid pipeline
                                                        // stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;

        TransportConfig {
            max_concurrent_bidi_streams: 100u32.into(),
            max_concurrent_uni_streams: 100u32.into(),
            max_idle_timeout: Some(VarInt(10_000)),
            stream_receive_window: STREAM_RWND.into(),
            receive_window: VarInt::MAX,
            send_window: (8 * STREAM_RWND).into(),

            max_tlps: 2,
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            initial_rtt: Duration::from_millis(333), // per spec, intentionally distinct from EXPECTED_RTT

            persistent_congestion_threshold: 3,
            keep_alive_interval: None,
            crypto_buffer_size: 16 * 1024,
            allow_spin: true,
            datagram_receive_buffer_size: Some(STREAM_RWND as usize),
            datagram_send_buffer_size: 1024 * 1024,

            congestion_controller_factory: Box::new(Arc::new(congestion::CubicConfig::default())),
        }
    }
}

impl fmt::Debug for TransportConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TranportConfig")
            .field(
                "max_concurrent_bidi_streams",
                &self.max_concurrent_bidi_streams,
            )
            .field(
                "max_concurrent_uni_streams",
                &self.max_concurrent_uni_streams,
            )
            .field("max_idle_timeout", &self.max_idle_timeout)
            .field("stream_receive_window", &self.stream_receive_window)
            .field("receive_window", &self.receive_window)
            .field("send_window", &self.send_window)
            .field("max_tlps", &self.max_tlps)
            .field("packet_threshold", &self.packet_threshold)
            .field("time_threshold", &self.time_threshold)
            .field("initial_rtt", &self.initial_rtt)
            .field(
                "persistent_congestion_threshold",
                &self.persistent_congestion_threshold,
            )
            .field("keep_alive_interval", &self.keep_alive_interval)
            .field("crypto_buffer_size", &self.crypto_buffer_size)
            .field("allow_spin", &self.allow_spin)
            .field(
                "datagram_receive_buffer_size",
                &self.datagram_receive_buffer_size,
            )
            .field("datagram_send_buffer_size", &self.datagram_send_buffer_size)
            .field("congestion_controller_factory", &"[ opaque ]")
            .finish()
    }
}

/// Global configuration for the endpoint, affecting all connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct EndpointConfig {
    pub(crate) reset_key: Arc<dyn HmacKey>,
    pub(crate) max_udp_payload_size: VarInt,
    /// CID generator factory
    ///
    /// Create a cid generator for local cid in Endpoint struct
    pub(crate) connection_id_generator_factory:
        Arc<dyn Fn() -> Box<dyn ConnectionIdGenerator> + Send + Sync>,
    pub(crate) supported_versions: Vec<u32>,
    pub(crate) grease_quic_bit: bool,
}

impl EndpointConfig {
    /// Create a default config with a particular `reset_key`
    pub fn new(reset_key: Arc<dyn HmacKey>) -> Self {
        let cid_factory: fn() -> Box<dyn ConnectionIdGenerator> =
            || Box::new(RandomConnectionIdGenerator::default());
        Self {
            reset_key,
            max_udp_payload_size: 1480u32.into(), // Typical internet MTU minus IPv4 and UDP overhead, rounded up to a multiple of 8
            connection_id_generator_factory: Arc::new(cid_factory),
            supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
            grease_quic_bit: true,
        }
    }

    /// Supply a custom connection ID generator factory
    ///
    /// Called once by each `Endpoint` constructed from this configuration to obtain the CID
    /// generator which will be used to generate the CIDs used for incoming packets on all
    /// connections involving that  `Endpoint`. A custom CID generator allows applications to embed
    /// information in local connection IDs, e.g. to support stateless packet-level load balancers.
    ///
    /// `EndpointConfig::new()` applies a default random CID generator factory. This functions
    /// accepts any customized CID generator to reset CID generator factory that implements
    /// the `ConnectionIdGenerator` trait.
    pub fn cid_generator<F: Fn() -> Box<dyn ConnectionIdGenerator> + Send + Sync + 'static>(
        &mut self,
        factory: F,
    ) -> &mut Self {
        self.connection_id_generator_factory = Arc::new(factory);
        self
    }

    /// Private key used to send authenticated connection resets to peers who were
    /// communicating with a previous instance of this endpoint.
    pub fn reset_key(&mut self, key: Arc<dyn HmacKey>) -> &mut Self {
        self.reset_key = key;
        self
    }

    /// Maximum UDP payload size accepted from peers. Excludes UDP and IP overhead.
    ///
    /// The default is suitable for typical internet applications. Applications which expect to run
    /// on networks supporting Ethernet jumbo frames or similar should set this appropriately.
    pub fn max_udp_payload_size(&mut self, value: u64) -> Result<&mut Self, ConfigError> {
        self.max_udp_payload_size = value.try_into()?;
        Ok(self)
    }

    /// Get the current value of `max_udp_payload_size`
    ///
    /// While most parameters don't need to be readable, this must be exposed to allow higher-level
    /// layers, e.g. the `quinn` crate, to determine how large a receive buffer to allocate to
    /// support an externally-defined `EndpointConfig`.
    ///
    /// While `get_` accessors are typically unidiomatic in Rust, we favor concision for setters,
    /// which will be used far more heavily.
    #[doc(hidden)]
    pub fn get_max_udp_payload_size(&self) -> u64 {
        self.max_udp_payload_size.into()
    }

    /// Override supported QUIC versions
    pub fn supported_versions(&mut self, supported_versions: Vec<u32>) -> &mut Self {
        self.supported_versions = supported_versions;
        self
    }

    /// Whether to accept QUIC packets containing any value for the fixed bit
    ///
    /// Enabled by default. Helps protect against protocol ossification and makes traffic less
    /// identifiable to observers. Disable if helping observers identify this traffic as QUIC is
    /// desired.
    pub fn grease_quic_bit(&mut self, value: bool) -> &mut Self {
        self.grease_quic_bit = value;
        self
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EndpointConfig")
            .field("reset_key", &"[ elided ]")
            .field("max_udp_payload_size", &self.max_udp_payload_size)
            .field("cid_generator_factory", &"[ elided ]")
            .field("supported_versions", &self.supported_versions)
            .field("grease_quic_bit", &self.grease_quic_bit)
            .finish()
    }
}

#[cfg(feature = "ring")]
impl Default for EndpointConfig {
    fn default() -> Self {
        let mut reset_key = [0; 64];
        rand::thread_rng().fill_bytes(&mut reset_key);

        Self::new(Arc::new(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &reset_key,
        )))
    }
}

/// Parameters governing incoming connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct ServerConfig {
    /// Transport configuration to use for incoming connections
    pub transport: Arc<TransportConfig>,

    /// TLS configuration used for incoming connections.
    ///
    /// Must be set to use TLS 1.3 only.
    pub crypto: Arc<dyn crypto::ServerConfig>,

    /// Used to generate one-time AEAD keys to protect handshake tokens
    pub(crate) token_key: Arc<dyn HandshakeTokenKey>,

    /// Whether to require clients to prove ownership of an address before committing resources.
    ///
    /// Introduces an additional round-trip to the handshake to make denial of service attacks more difficult.
    pub(crate) use_retry: bool,
    /// Microseconds after a stateless retry token was issued for which it's considered valid.
    pub(crate) retry_token_lifetime: Duration,

    /// Maximum number of concurrent connections
    pub(crate) concurrent_connections: u32,

    /// Whether to allow clients to migrate to new addresses
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub(crate) migration: bool,
}

impl ServerConfig {
    /// Create a default config with a particular handshake token key
    pub fn new(
        crypto: Arc<dyn crypto::ServerConfig>,
        token_key: Arc<dyn HandshakeTokenKey>,
    ) -> Self {
        Self {
            transport: Arc::new(TransportConfig::default()),
            crypto,

            token_key,
            use_retry: false,
            retry_token_lifetime: Duration::from_secs(15),

            concurrent_connections: 100_000,

            migration: true,
        }
    }

    /// Set a custom [`TransportConfig`]
    pub fn transport_config(&mut self, transport: Arc<TransportConfig>) -> &mut Self {
        self.transport = transport;
        self
    }

    /// Private key used to authenticate data included in handshake tokens.
    pub fn token_key(&mut self, value: Arc<dyn HandshakeTokenKey>) -> &mut Self {
        self.token_key = value;
        self
    }

    /// Whether to require clients to prove ownership of an address before committing resources.
    ///
    /// Introduces an additional round-trip to the handshake to make denial of service attacks more difficult.
    pub fn use_retry(&mut self, value: bool) -> &mut Self {
        self.use_retry = value;
        self
    }

    /// Duration after a stateless retry token was issued for which it's considered valid.
    pub fn retry_token_lifetime(&mut self, value: Duration) -> &mut Self {
        self.retry_token_lifetime = value;
        self
    }

    /// Maximum number of simultaneous connections to accept.
    ///
    /// New incoming connections are only accepted if the total number of incoming or outgoing
    /// connections is less than this. Outgoing connections are unaffected.
    pub fn concurrent_connections(&mut self, value: u32) -> &mut Self {
        self.concurrent_connections = value;
        self
    }

    /// Whether to allow clients to migrate to new addresses
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub fn migration(&mut self, value: bool) -> &mut Self {
        self.migration = value;
        self
    }
}

#[cfg(feature = "rustls")]
impl ServerConfig {
    /// Create a server config with the given certificate chain to be presented to clients
    ///
    /// Uses a randomized handshake token key.
    pub fn with_single_cert(
        cert_chain: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    ) -> Result<Self, rustls::Error> {
        let crypto = crypto::rustls::server_config(cert_chain, key)?;
        Ok(Self::with_crypto(Arc::new(crypto)))
    }
}

#[cfg(feature = "ring")]
impl ServerConfig {
    /// Create a server config with the given [`crypto::ServerConfig`]
    ///
    /// Uses a randomized handshake token key.
    pub fn with_crypto(crypto: Arc<dyn crypto::ServerConfig>) -> Self {
        let rng = &mut rand::thread_rng();
        let mut master_key = [0u8; 64];
        rng.fill_bytes(&mut master_key);
        let master_key = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        Self::new(crypto, Arc::new(master_key))
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerConfig<T>")
            .field("transport", &self.transport)
            .field("crypto", &"ServerConfig { elided }")
            .field("token_key", &"[ elided ]")
            .field("use_retry", &self.use_retry)
            .field("retry_token_lifetime", &self.retry_token_lifetime)
            .field("concurrent_connections", &self.concurrent_connections)
            .field("migration", &self.migration)
            .finish()
    }
}

/// Configuration for outgoing connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Transport configuration to use
    pub(crate) transport: Arc<TransportConfig>,

    /// Cryptographic configuration to use
    pub(crate) crypto: Arc<dyn crypto::ClientConfig>,

    /// QUIC protocol version to use
    pub(crate) version: u32,
}

impl ClientConfig {
    /// Create a default config with a particular cryptographic config
    pub fn new(crypto: Arc<dyn crypto::ClientConfig>) -> Self {
        Self {
            transport: Default::default(),
            crypto,
            version: 1,
        }
    }

    /// Set a custom [`TransportConfig`]
    pub fn transport_config(&mut self, transport: Arc<TransportConfig>) -> &mut Self {
        self.transport = transport;
        self
    }

    /// Set the QUIC version to use
    pub fn version(&mut self, version: u32) -> &mut Self {
        self.version = version;
        self
    }
}

#[cfg(feature = "rustls")]
impl ClientConfig {
    /// Create a client configuration that trusts the platform's native roots
    #[cfg(feature = "native-certs")]
    pub fn with_native_roots() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    if let Err(e) = roots.add(&rustls::Certificate(cert.0)) {
                        tracing::warn!("failed to parse trust anchor: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("couldn't load any default trust roots: {}", e);
            }
        };

        Self::with_root_certificates(roots)
    }

    /// Create a client configuration that trusts specified trust anchors
    pub fn with_root_certificates(roots: rustls::RootCertStore) -> Self {
        Self::new(Arc::new(crypto::rustls::client_config(roots)))
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ClientConfig<T>")
            .field("transport", &self.transport)
            .field("crypto", &"ClientConfig { elided }")
            .field("version", &self.version)
            .finish()
    }
}

/// Errors in the configuration of an endpoint
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// Value exceeds supported bounds
    #[error("value exceeds supported bounds")]
    OutOfBounds,
}

impl From<TryFromIntError> for ConfigError {
    fn from(_: TryFromIntError) -> Self {
        ConfigError::OutOfBounds
    }
}

impl From<VarIntBoundsExceeded> for ConfigError {
    fn from(_: VarIntBoundsExceeded) -> Self {
        ConfigError::OutOfBounds
    }
}

/// Maximum duration of inactivity to accept before timing out the connection.
///
/// This wraps an underlying [`VarInt`], representing the duration in milliseconds. Values can be
/// constructed by converting directly from `VarInt`, or using `TryFrom<Duration>`.
///
/// ```
/// # use std::{convert::TryFrom, time::Duration};
/// # use quinn_proto::{IdleTimeout, VarIntBoundsExceeded, VarInt};
/// # fn main() -> Result<(), VarIntBoundsExceeded> {
/// // A `VarInt`-encoded value in milliseconds
/// let timeout = IdleTimeout::from(VarInt::from_u32(10_000));
///
/// // Try to convert a `Duration` into a `VarInt`-encoded timeout
/// let timeout = IdleTimeout::try_from(Duration::from_secs(10))?;
/// # Ok(())
/// # }
/// ```
#[derive(Default, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdleTimeout(VarInt);

impl From<VarInt> for IdleTimeout {
    fn from(inner: VarInt) -> Self {
        Self(inner)
    }
}

impl std::convert::TryFrom<Duration> for IdleTimeout {
    type Error = VarIntBoundsExceeded;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        let inner = VarInt::try_from(timeout.as_millis())?;
        Ok(Self(inner))
    }
}
