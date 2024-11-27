use std::{
    fmt,
    net::{SocketAddrV4, SocketAddrV6},
    num::TryFromIntError,
    sync::Arc,
};

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use rustls::client::WebPkiServerVerifier;
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use crate::crypto::rustls::{configured_provider, QuicServerConfig};
use crate::{
    cid_generator::{ConnectionIdGenerator, HashedConnectionIdGenerator},
    crypto::{self, HandshakeTokenKey, HmacKey},
    shared::ConnectionId,
    Duration, RandomConnectionIdGenerator, VarInt, VarIntBoundsExceeded,
    DEFAULT_SUPPORTED_VERSIONS, MAX_CID_SIZE,
};

mod transport;
pub use transport::{AckFrequencyConfig, IdleTimeout, MtuDiscoveryConfig, TransportConfig};

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
    /// Minimum interval between outgoing stateless reset packets
    pub(crate) min_reset_interval: Duration,
    /// Optional seed to be used internally for random number generation
    pub(crate) rng_seed: Option<[u8; 32]>,
}

impl EndpointConfig {
    /// Create a default config with a particular `reset_key`
    pub fn new(reset_key: Arc<dyn HmacKey>) -> Self {
        let cid_factory =
            || -> Box<dyn ConnectionIdGenerator> { Box::<HashedConnectionIdGenerator>::default() };
        Self {
            reset_key,
            max_udp_payload_size: (1500u32 - 28).into(), // Ethernet MTU minus IP + UDP headers
            connection_id_generator_factory: Arc::new(cid_factory),
            supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
            grease_quic_bit: true,
            min_reset_interval: Duration::from_millis(20),
            rng_seed: None,
        }
    }

    /// Supply a custom connection ID generator factory
    ///
    /// Called once by each `Endpoint` constructed from this configuration to obtain the CID
    /// generator which will be used to generate the CIDs used for incoming packets on all
    /// connections involving that  `Endpoint`. A custom CID generator allows applications to embed
    /// information in local connection IDs, e.g. to support stateless packet-level load balancers.
    ///
    /// Defaults to [`HashedConnectionIdGenerator`].
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

    /// Maximum UDP payload size accepted from peers (excluding UDP and IP overhead).
    ///
    /// Must be greater or equal than 1200.
    ///
    /// Defaults to 1472, which is the largest UDP payload that can be transmitted in the typical
    /// 1500 byte Ethernet MTU. Deployments on links with larger MTUs (e.g. loopback or Ethernet
    /// with jumbo frames) can raise this to improve performance at the cost of a linear increase in
    /// datagram receive buffer size.
    pub fn max_udp_payload_size(&mut self, value: u16) -> Result<&mut Self, ConfigError> {
        if !(1200..=65_527).contains(&value) {
            return Err(ConfigError::OutOfBounds);
        }

        self.max_udp_payload_size = value.into();
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

    /// Minimum interval between outgoing stateless reset packets
    ///
    /// Defaults to 20ms. Limits the impact of attacks which flood an endpoint with garbage packets,
    /// e.g. [ISAKMP/IKE amplification]. Larger values provide a stronger defense, but may delay
    /// detection of some error conditions by clients. Using a [`ConnectionIdGenerator`] with a low
    /// rate of false positives in [`validate`](ConnectionIdGenerator::validate) reduces the risk
    /// incurred by a small minimum reset interval.
    ///
    /// [ISAKMP/IKE
    /// amplification]: https://bughunters.google.com/blog/5960150648750080/preventing-cross-service-udp-loops-in-quic#isakmp-ike-amplification-vs-quic
    pub fn min_reset_interval(&mut self, value: Duration) -> &mut Self {
        self.min_reset_interval = value;
        self
    }

    /// Optional seed to be used internally for random number generation
    ///
    /// By default, quinn will initialize an endpoint's rng using a platform entropy source.
    /// However, you can seed the rng yourself through this method (e.g. if you need to run quinn
    /// deterministically or if you are using quinn in an environment that doesn't have a source of
    /// entropy available).
    pub fn rng_seed(&mut self, seed: Option<[u8; 32]>) -> &mut Self {
        self.rng_seed = seed;
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
            .field("rng_seed", &self.rng_seed)
            .finish()
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl Default for EndpointConfig {
    fn default() -> Self {
        #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
        use aws_lc_rs::hmac;
        use rand::RngCore;
        #[cfg(feature = "ring")]
        use ring::hmac;

        let mut reset_key = [0; 64];
        rand::thread_rng().fill_bytes(&mut reset_key);

        Self::new(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, &reset_key)))
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

    /// Microseconds after a stateless retry token was issued for which it's considered valid.
    pub(crate) retry_token_lifetime: Duration,

    /// Whether to allow clients to migrate to new addresses
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub(crate) migration: bool,

    pub(crate) preferred_address_v4: Option<SocketAddrV4>,
    pub(crate) preferred_address_v6: Option<SocketAddrV6>,

    pub(crate) max_incoming: usize,
    pub(crate) incoming_buffer_size: u64,
    pub(crate) incoming_buffer_size_total: u64,
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
            retry_token_lifetime: Duration::from_secs(15),

            migration: true,

            preferred_address_v4: None,
            preferred_address_v6: None,

            max_incoming: 1 << 16,
            incoming_buffer_size: 10 << 20,
            incoming_buffer_size_total: 100 << 20,
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

    /// Duration after a stateless retry token was issued for which it's considered valid.
    pub fn retry_token_lifetime(&mut self, value: Duration) -> &mut Self {
        self.retry_token_lifetime = value;
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

    /// The preferred IPv4 address that will be communicated to clients during handshaking.
    /// If the client is able to reach this address, it will switch to it.
    pub fn preferred_address_v4(&mut self, address: Option<SocketAddrV4>) -> &mut Self {
        self.preferred_address_v4 = address;
        self
    }

    /// The preferred IPv6 address that will be communicated to clients during handshaking.
    /// If the client is able to reach this address, it will switch to it.
    pub fn preferred_address_v6(&mut self, address: Option<SocketAddrV6>) -> &mut Self {
        self.preferred_address_v6 = address;
        self
    }

    /// Maximum number of [`Incoming`][crate::Incoming] to allow to exist at a time
    ///
    /// An [`Incoming`][crate::Incoming] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. While this limit is reached, new incoming connection attempts are immediately
    /// refused. Larger values have greater worst-case memory consumption, but accommodate greater
    /// application latency in handling incoming connection attempts.
    ///
    /// The default value is set to 65536. With a typical Ethernet MTU of 1500 bytes, this limits
    /// memory consumption from this to under 100 MiB--a generous amount that still prevents memory
    /// exhaustion in most contexts.
    pub fn max_incoming(&mut self, max_incoming: usize) -> &mut Self {
        self.max_incoming = max_incoming;
        self
    }

    /// Maximum number of received bytes to buffer for each [`Incoming`][crate::Incoming]
    ///
    /// An [`Incoming`][crate::Incoming] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. This limit governs only packets received within that period, and does not include
    /// the first packet. Packets received in excess of this limit are dropped, which may cause
    /// 0-RTT or handshake data to have to be retransmitted.
    ///
    /// The default value is set to 10 MiB--an amount such that in most situations a client would
    /// not transmit that much 0-RTT data faster than the server handles the corresponding
    /// [`Incoming`][crate::Incoming].
    pub fn incoming_buffer_size(&mut self, incoming_buffer_size: u64) -> &mut Self {
        self.incoming_buffer_size = incoming_buffer_size;
        self
    }

    /// Maximum number of received bytes to buffer for all [`Incoming`][crate::Incoming]
    /// collectively
    ///
    /// An [`Incoming`][crate::Incoming] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. This limit governs only packets received within that period, and does not include
    /// the first packet. Packets received in excess of this limit are dropped, which may cause
    /// 0-RTT or handshake data to have to be retransmitted.
    ///
    /// The default value is set to 100 MiB--a generous amount that still prevents memory
    /// exhaustion in most contexts.
    pub fn incoming_buffer_size_total(&mut self, incoming_buffer_size_total: u64) -> &mut Self {
        self.incoming_buffer_size_total = incoming_buffer_size_total;
        self
    }
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl ServerConfig {
    /// Create a server config with the given certificate chain to be presented to clients
    ///
    /// Uses a randomized handshake token key.
    pub fn with_single_cert(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        Ok(Self::with_crypto(Arc::new(QuicServerConfig::new(
            cert_chain, key,
        )?)))
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl ServerConfig {
    /// Create a server config with the given [`crypto::ServerConfig`]
    ///
    /// Uses a randomized handshake token key.
    pub fn with_crypto(crypto: Arc<dyn crypto::ServerConfig>) -> Self {
        #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
        use aws_lc_rs::hkdf;
        use rand::RngCore;
        #[cfg(feature = "ring")]
        use ring::hkdf;

        let rng = &mut rand::thread_rng();
        let mut master_key = [0u8; 64];
        rng.fill_bytes(&mut master_key);
        let master_key = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        Self::new(crypto, Arc::new(master_key))
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerConfig<T>")
            .field("transport", &self.transport)
            .field("crypto", &"ServerConfig { elided }")
            .field("token_key", &"[ elided ]")
            .field("retry_token_lifetime", &self.retry_token_lifetime)
            .field("migration", &self.migration)
            .field("preferred_address_v4", &self.preferred_address_v4)
            .field("preferred_address_v6", &self.preferred_address_v6)
            .field("max_incoming", &self.max_incoming)
            .field("incoming_buffer_size", &self.incoming_buffer_size)
            .field(
                "incoming_buffer_size_total",
                &self.incoming_buffer_size_total,
            )
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

    /// Provider that populates the destination connection ID of Initial Packets
    pub(crate) initial_dst_cid_provider: Arc<dyn Fn() -> ConnectionId + Send + Sync>,

    /// QUIC protocol version to use
    pub(crate) version: u32,
}

impl ClientConfig {
    /// Create a default config with a particular cryptographic config
    pub fn new(crypto: Arc<dyn crypto::ClientConfig>) -> Self {
        Self {
            transport: Default::default(),
            crypto,
            initial_dst_cid_provider: Arc::new(|| {
                RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid()
            }),
            version: 1,
        }
    }

    /// Configure how to populate the destination CID of the initial packet when attempting to
    /// establish a new connection.
    ///
    /// By default, it's populated with random bytes with reasonable length, so unless you have
    /// a good reason, you do not need to change it.
    ///
    /// When prefer to override the default, please note that the generated connection ID MUST be
    /// at least 8 bytes long and unpredictable, as per section 7.2 of RFC 9000.
    pub fn initial_dst_cid_provider(
        &mut self,
        initial_dst_cid_provider: Arc<dyn Fn() -> ConnectionId + Send + Sync>,
    ) -> &mut Self {
        self.initial_dst_cid_provider = initial_dst_cid_provider;
        self
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

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl ClientConfig {
    /// Create a client configuration that trusts the platform's native roots
    #[cfg(feature = "platform-verifier")]
    pub fn with_platform_verifier() -> Self {
        Self::new(Arc::new(crypto::rustls::QuicClientConfig::new(Arc::new(
            rustls_platform_verifier::Verifier::new(),
        ))))
    }

    /// Create a client configuration that trusts specified trust anchors
    pub fn with_root_certificates(
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self, rustls::client::VerifierBuilderError> {
        Ok(Self::new(Arc::new(crypto::rustls::QuicClientConfig::new(
            WebPkiServerVerifier::builder_with_provider(roots, configured_provider()).build()?,
        ))))
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ClientConfig<T>")
            .field("transport", &self.transport)
            .field("crypto", &"ClientConfig { elided }")
            .field("version", &self.version)
            .finish_non_exhaustive()
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
        Self::OutOfBounds
    }
}

impl From<VarIntBoundsExceeded> for ConfigError {
    fn from(_: VarIntBoundsExceeded) -> Self {
        Self::OutOfBounds
    }
}
