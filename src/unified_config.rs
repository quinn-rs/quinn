// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configuration for ant-quic P2P endpoints
//!
//! This module provides `P2pConfig` with builder pattern support for
//! configuring endpoints, NAT traversal, MTU, PQC, and other settings.
//!
//! # v0.13.0 Symmetric P2P API
//!
//! ```rust,ignore
//! use ant_quic::P2pConfig;
//!
//! // All nodes are symmetric - no client/server roles
//! let config = P2pConfig::builder()
//!     .bind_addr("0.0.0.0:9000".parse()?)
//!     .known_peer("peer1.example.com:9000".parse()?)
//!     .known_peer("peer2.example.com:9000".parse()?)
//!     .build()?;
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// v0.2: AuthConfig removed - TLS handles peer authentication via ML-DSA-65
use crate::bootstrap_cache::BootstrapCacheConfig;
use crate::config::nat_timeouts::TimeoutConfig;
use crate::crypto::pqc::PqcConfig;
use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey};
use crate::host_identity::HostIdentity;
use crate::transport::{TransportProvider, TransportRegistry};

/// Configuration for ant-quic P2P endpoints
///
/// This struct provides all configuration options for P2P networking including
/// NAT traversal, authentication, MTU settings, and post-quantum cryptography.
///
/// Named `P2pConfig` to avoid collision with the low-level `config::EndpointConfig`
/// which is used for QUIC protocol settings.
///
/// # Pure P2P Design (v0.13.0+)
/// All nodes are symmetric - they can connect, accept connections, and coordinate
/// NAT traversal for peers. There is no role distinction.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Local address to bind to. If `None`, an ephemeral port is auto-assigned
    /// with enhanced security through port randomization.
    pub bind_addr: Option<SocketAddr>,

    /// Known peers for initial discovery and NAT traversal coordination
    /// These can be any nodes in the network - all nodes are symmetric.
    pub known_peers: Vec<SocketAddr>,

    /// Maximum number of concurrent connections
    pub max_connections: usize,

    // v0.2: auth field removed - TLS handles peer authentication via ML-DSA-65
    /// NAT traversal configuration
    pub nat: NatConfig,

    /// Timeout configuration for all operations
    pub timeouts: TimeoutConfig,

    /// Post-quantum cryptography configuration
    pub pqc: PqcConfig,

    /// MTU configuration for network packet sizing
    pub mtu: MtuConfig,

    /// Interval for collecting and reporting statistics
    pub stats_interval: Duration,

    /// Identity keypair for persistent peer identity (ML-DSA-65).
    /// If `None`, a fresh keypair is generated on startup.
    /// Provide this for persistent identity across restarts.
    pub keypair: Option<(MlDsaPublicKey, MlDsaSecretKey)>,

    /// Bootstrap cache configuration
    pub bootstrap_cache: BootstrapCacheConfig,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity. If empty, a default UDP transport
    /// is created automatically.
    pub transport_registry: TransportRegistry,
}
// v0.13.0: enable_coordinator removed - all nodes are coordinators

/// NAT traversal specific configuration
///
/// These options control how the endpoint discovers external addresses,
/// coordinates hole punching, and handles NAT traversal failures.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Maximum number of address candidates to track
    pub max_candidates: usize,

    /// Enable symmetric NAT prediction algorithms
    pub enable_symmetric_nat: bool,

    /// Enable automatic relay fallback when direct connection fails
    pub enable_relay_fallback: bool,

    /// Enable relay service for other peers (symmetric P2P)
    /// When true, this node will accept and forward CONNECT-UDP Bind requests from peers.
    /// Per ADR-004: All nodes are equal and participate in relaying with resource budgets.
    pub enable_relay_service: bool,

    /// Known relay nodes for MASQUE CONNECT-UDP Bind fallback
    pub relay_nodes: Vec<std::net::SocketAddr>,

    /// Maximum concurrent NAT traversal attempts
    pub max_concurrent_attempts: usize,

    /// Prefer RFC-compliant NAT traversal frame format
    pub prefer_rfc_nat_traversal: bool,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            max_candidates: 10,
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            enable_relay_service: true, // Symmetric P2P: every node provides relay services
            relay_nodes: Vec::new(),
            max_concurrent_attempts: 3,
            prefer_rfc_nat_traversal: true,
        }
    }
}

/// MTU (Maximum Transmission Unit) configuration
///
/// Controls packet sizing for optimal network performance. Post-quantum
/// cryptography requires larger packets due to bigger key sizes:
/// - ML-KEM-768: 1,184 byte public key + 1,088 byte ciphertext
/// - ML-DSA-65: 1,952 byte public key + 3,309 byte signature
///
/// The default configuration enables MTU discovery which automatically
/// finds the optimal packet size for the network path.
#[derive(Debug, Clone)]
pub struct MtuConfig {
    /// Initial MTU to use before discovery (default: 1200)
    ///
    /// Must be at least 1200 bytes per QUIC specification.
    /// For PQC-enabled connections, consider using 1500+ if network allows.
    pub initial_mtu: u16,

    /// Minimum MTU that must always work (default: 1200)
    ///
    /// The connection will fall back to this if larger packets are lost.
    /// Must not exceed `initial_mtu`.
    pub min_mtu: u16,

    /// Enable path MTU discovery (default: true)
    ///
    /// When enabled, the connection probes for larger packet sizes
    /// to optimize throughput. Disable for constrained networks.
    pub discovery_enabled: bool,

    /// Upper bound for MTU discovery probing (default: 1452)
    ///
    /// For PQC connections, consider higher values (up to 4096) if the
    /// network path supports jumbo frames.
    pub max_mtu: u16,

    /// Automatically adjust MTU for PQC handshakes (default: true)
    ///
    /// When enabled, the connection will use larger MTU settings
    /// during PQC handshakes to accommodate large key exchanges.
    pub auto_pqc_adjustment: bool,
}

impl Default for MtuConfig {
    fn default() -> Self {
        Self {
            initial_mtu: 1200,
            min_mtu: 1200,
            discovery_enabled: true,
            max_mtu: 1452, // Ethernet MTU minus IP/UDP headers
            auto_pqc_adjustment: true,
        }
    }
}

impl MtuConfig {
    /// Configuration optimized for PQC (larger MTUs)
    pub fn pqc_optimized() -> Self {
        Self {
            initial_mtu: 1500,
            min_mtu: 1200,
            discovery_enabled: true,
            max_mtu: 4096, // Higher bound for PQC key exchange
            auto_pqc_adjustment: true,
        }
    }

    /// Configuration for constrained networks (no discovery)
    pub fn constrained() -> Self {
        Self {
            initial_mtu: 1200,
            min_mtu: 1200,
            discovery_enabled: false,
            max_mtu: 1200,
            auto_pqc_adjustment: false,
        }
    }

    /// Configuration for high-bandwidth networks with jumbo frames
    pub fn jumbo_frames() -> Self {
        Self {
            initial_mtu: 1500,
            min_mtu: 1200,
            discovery_enabled: true,
            max_mtu: 9000, // Jumbo frame MTU
            auto_pqc_adjustment: true,
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            known_peers: Vec::new(),
            max_connections: 256,
            // v0.2: auth removed
            nat: NatConfig::default(),
            timeouts: TimeoutConfig::default(),
            pqc: PqcConfig::default(),
            mtu: MtuConfig::default(),
            stats_interval: Duration::from_secs(30),
            keypair: None,
            bootstrap_cache: BootstrapCacheConfig::default(),
            transport_registry: TransportRegistry::new(),
        }
    }
}

impl P2pConfig {
    /// Create a new configuration builder
    pub fn builder() -> P2pConfigBuilder {
        P2pConfigBuilder::default()
    }

    /// Convert to `NatTraversalConfig` for internal use
    pub fn to_nat_config(&self) -> crate::nat_traversal_api::NatTraversalConfig {
        crate::nat_traversal_api::NatTraversalConfig {
            known_peers: self.known_peers.clone(),
            max_candidates: self.nat.max_candidates,
            coordination_timeout: self.timeouts.nat_traversal.coordination_timeout,
            enable_symmetric_nat: self.nat.enable_symmetric_nat,
            enable_relay_fallback: self.nat.enable_relay_fallback,
            enable_relay_service: self.nat.enable_relay_service,
            relay_nodes: self.nat.relay_nodes.clone(),
            max_concurrent_attempts: self.nat.max_concurrent_attempts,
            bind_addr: self.bind_addr,
            prefer_rfc_nat_traversal: self.nat.prefer_rfc_nat_traversal,
            pqc: Some(self.pqc.clone()),
            timeouts: self.timeouts.clone(),
            identity_key: None,
            allow_ipv4_mapped: true, // Required for dual-stack socket support
            transport_registry: Some(Arc::new(self.transport_registry.clone())),
        }
    }

    /// Convert to `NatTraversalConfig` with a specific identity key
    ///
    /// This ensures the same ML-DSA-65 keypair is used for both P2pEndpoint
    /// authentication and TLS/RPK identity in NatTraversalEndpoint.
    pub fn to_nat_config_with_key(
        &self,
        public_key: MlDsaPublicKey,
        secret_key: MlDsaSecretKey,
    ) -> crate::nat_traversal_api::NatTraversalConfig {
        let mut config = self.to_nat_config();
        config.identity_key = Some((public_key, secret_key));
        config
    }
}

/// Builder for `P2pConfig`
#[derive(Debug, Clone, Default)]
pub struct P2pConfigBuilder {
    bind_addr: Option<SocketAddr>,
    known_peers: Vec<SocketAddr>,
    max_connections: Option<usize>,
    // v0.2: auth removed
    nat: Option<NatConfig>,
    timeouts: Option<TimeoutConfig>,
    pqc: Option<PqcConfig>,
    mtu: Option<MtuConfig>,
    stats_interval: Option<Duration>,
    keypair: Option<(MlDsaPublicKey, MlDsaSecretKey)>,
    bootstrap_cache: Option<BootstrapCacheConfig>,
    transport_registry: Option<TransportRegistry>,
}

/// Error type for configuration validation
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    /// Invalid max connections value
    #[error("max_connections must be at least 1")]
    InvalidMaxConnections,

    /// Invalid timeout value
    #[error("Invalid timeout: {0}")]
    InvalidTimeout(String),

    /// PQC configuration error
    #[error("PQC configuration error: {0}")]
    PqcError(String),

    /// Invalid MTU configuration
    #[error("Invalid MTU configuration: {0}")]
    InvalidMtu(String),
}

impl P2pConfigBuilder {
    /// Set the bind address
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Add a known peer for initial discovery
    /// In v0.13.0+ all nodes are symmetric - these are just starting points
    pub fn known_peer(mut self, addr: SocketAddr) -> Self {
        self.known_peers.push(addr);
        self
    }

    /// Add multiple known peers
    pub fn known_peers(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.known_peers.extend(addrs);
        self
    }

    /// Add a bootstrap node (alias for known_peer for backwards compatibility)
    #[doc(hidden)]
    pub fn bootstrap(mut self, addr: SocketAddr) -> Self {
        self.known_peers.push(addr);
        self
    }

    /// Set maximum connections
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    // v0.2: auth() method removed - TLS handles peer authentication via ML-DSA-65

    /// Set NAT traversal configuration
    pub fn nat(mut self, nat: NatConfig) -> Self {
        self.nat = Some(nat);
        self
    }

    /// Set timeout configuration
    pub fn timeouts(mut self, timeouts: TimeoutConfig) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Use fast timeouts (for local networks)
    pub fn fast_timeouts(mut self) -> Self {
        self.timeouts = Some(TimeoutConfig::fast());
        self
    }

    /// Use conservative timeouts (for unreliable networks)
    pub fn conservative_timeouts(mut self) -> Self {
        self.timeouts = Some(TimeoutConfig::conservative());
        self
    }

    /// Set PQC configuration
    pub fn pqc(mut self, pqc: PqcConfig) -> Self {
        self.pqc = Some(pqc);
        self
    }

    /// Set MTU configuration
    pub fn mtu(mut self, mtu: MtuConfig) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Use PQC-optimized MTU settings
    ///
    /// Enables larger MTU bounds (up to 4096) for efficient PQC handshakes.
    pub fn pqc_optimized_mtu(mut self) -> Self {
        self.mtu = Some(MtuConfig::pqc_optimized());
        self
    }

    /// Use constrained network MTU settings
    ///
    /// Disables MTU discovery and uses minimum MTU (1200).
    pub fn constrained_mtu(mut self) -> Self {
        self.mtu = Some(MtuConfig::constrained());
        self
    }

    /// Use jumbo frame MTU settings
    ///
    /// For high-bandwidth networks supporting larger frames (up to 9000).
    pub fn jumbo_mtu(mut self) -> Self {
        self.mtu = Some(MtuConfig::jumbo_frames());
        self
    }

    /// Set statistics collection interval
    pub fn stats_interval(mut self, interval: Duration) -> Self {
        self.stats_interval = Some(interval);
        self
    }

    /// Set identity keypair for persistent peer ID (ML-DSA-65)
    ///
    /// If not set, a fresh keypair is generated on startup.
    /// Provide this for stable identity across restarts.
    pub fn keypair(mut self, public_key: MlDsaPublicKey, secret_key: MlDsaSecretKey) -> Self {
        self.keypair = Some((public_key, secret_key));
        self
    }

    /// Configure with a HostIdentity for persistent, encrypted endpoint keypair storage
    ///
    /// This method:
    /// 1. Derives an endpoint encryption key from the HostIdentity for this network
    /// 2. Loads the existing keypair from encrypted storage if available
    /// 3. Generates and stores a new keypair if none exists
    ///
    /// The keypair is stored encrypted on disk, ensuring persistent identity across
    /// restarts while protecting the secret key at rest.
    ///
    /// # Arguments
    /// * `host` - The HostIdentity for deriving encryption keys
    /// * `network_id` - Network identifier for per-network key isolation
    /// * `storage_dir` - Directory for encrypted keypair storage
    ///
    /// # Example
    /// ```rust,ignore
    /// use ant_quic::{P2pConfig, HostIdentity};
    ///
    /// let host = HostIdentity::generate();
    /// let config = P2pConfig::builder()
    ///     .bind_addr("0.0.0.0:9000".parse()?)
    ///     .with_host_identity(&host, b"my-network", "/var/lib/ant-quic")?
    ///     .build()?;
    /// ```
    pub fn with_host_identity(
        mut self,
        host: &HostIdentity,
        network_id: &[u8],
        storage_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, ConfigError> {
        let keypair = load_or_generate_endpoint_keypair(host, network_id, storage_dir.as_ref())
            .map_err(|e| ConfigError::PqcError(format!("Failed to load/generate keypair: {e}")))?;
        self.keypair = Some(keypair);
        Ok(self)
    }

    /// Set bootstrap cache configuration
    pub fn bootstrap_cache(mut self, config: BootstrapCacheConfig) -> Self {
        self.bootstrap_cache = Some(config);
        self
    }

    /// Add a single transport provider to the registry
    ///
    /// This method can be called multiple times to add multiple providers.
    /// Providers are stored in the transport registry and used for multi-transport
    /// connectivity (UDP, BLE, etc.).
    ///
    /// # Example
    /// ```rust,ignore
    /// use ant_quic::{P2pConfig, transport::UdpTransport};
    /// use std::sync::Arc;
    ///
    /// let udp = UdpTransport::bind("0.0.0.0:0".parse()?).await?;
    /// let config = P2pConfig::builder()
    ///     .transport_provider(Arc::new(udp))
    ///     .build()?;
    /// ```
    pub fn transport_provider(mut self, provider: Arc<dyn TransportProvider>) -> Self {
        let registry = self
            .transport_registry
            .get_or_insert_with(TransportRegistry::new);
        registry.register(provider);
        self
    }

    /// Set the entire transport registry
    ///
    /// This replaces any previously registered providers. Use this when you have
    /// a pre-configured registry with multiple providers.
    ///
    /// # Example
    /// ```rust,ignore
    /// use ant_quic::{P2pConfig, transport::{TransportRegistry, UdpTransport}};
    /// use std::sync::Arc;
    ///
    /// let mut registry = TransportRegistry::new();
    /// registry.register(Arc::new(UdpTransport::bind("0.0.0.0:0".parse()?).await?));
    /// let config = P2pConfig::builder()
    ///     .transport_registry(registry)
    ///     .build()?;
    /// ```
    pub fn transport_registry(mut self, registry: TransportRegistry) -> Self {
        self.transport_registry = Some(registry);
        self
    }

    /// Build the configuration with validation
    pub fn build(self) -> Result<P2pConfig, ConfigError> {
        // Validate max_connections
        let max_connections = self.max_connections.unwrap_or(256);
        if max_connections == 0 {
            return Err(ConfigError::InvalidMaxConnections);
        }

        // v0.13.0+: No role validation - all nodes are symmetric
        // Nodes can operate without known peers (they can be connected to by others)

        Ok(P2pConfig {
            bind_addr: self.bind_addr,
            known_peers: self.known_peers,
            max_connections,
            // v0.2: auth removed
            nat: self.nat.unwrap_or_default(),
            timeouts: self.timeouts.unwrap_or_default(),
            pqc: self.pqc.unwrap_or_default(),
            mtu: self.mtu.unwrap_or_default(),
            stats_interval: self.stats_interval.unwrap_or(Duration::from_secs(30)),
            keypair: self.keypair,
            bootstrap_cache: self.bootstrap_cache.unwrap_or_default(),
            transport_registry: self.transport_registry.unwrap_or_default(),
        })
    }
}

// =============================================================================
// Endpoint Keypair Storage (ADR-007)
// =============================================================================

/// Load or generate an endpoint keypair with encrypted storage
///
/// This function:
/// 1. Derives an encryption key from the HostIdentity for the given network
/// 2. Attempts to load an existing keypair from encrypted storage
/// 3. If not found, generates a new ML-DSA-65 keypair and stores it encrypted
///
/// The keypair file is stored as `{network_id_hex}_keypair.enc` in the storage directory.
pub fn load_or_generate_endpoint_keypair(
    host: &HostIdentity,
    network_id: &[u8],
    storage_dir: &std::path::Path,
) -> Result<(MlDsaPublicKey, MlDsaSecretKey), std::io::Error> {
    // Derive encryption key for this network's keypair
    let encryption_key = host.derive_endpoint_encryption_key(network_id);

    // Compute filename based on network_id
    let network_id_hex = hex::encode(network_id);
    let keypair_file = storage_dir.join(format!("{network_id_hex}_keypair.enc"));

    // Ensure storage directory exists
    std::fs::create_dir_all(storage_dir)?;

    // Try to load existing keypair
    if keypair_file.exists() {
        let ciphertext = std::fs::read(&keypair_file)?;
        let plaintext = decrypt_keypair_data(&ciphertext, &encryption_key)?;
        return deserialize_keypair(&plaintext);
    }

    // Generate new keypair
    let (public_key, secret_key) =
        crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Serialize and encrypt
    let plaintext = serialize_keypair(&public_key, &secret_key)?;
    let ciphertext = encrypt_keypair_data(&plaintext, &encryption_key)?;

    // Write to file atomically
    let temp_file = keypair_file.with_extension("tmp");
    std::fs::write(&temp_file, &ciphertext)?;
    std::fs::rename(&temp_file, &keypair_file)?;

    Ok((public_key, secret_key))
}

/// Encrypt keypair data using ChaCha20-Poly1305
fn encrypt_keypair_data(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, std::io::Error> {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    aws_lc_rs::rand::fill(&mut nonce_bytes).map_err(|e| std::io::Error::other(e.to_string()))?;

    // Create cipher
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    // Encrypt
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(in_out);
    Ok(result)
}

/// Decrypt keypair data using ChaCha20-Poly1305
fn decrypt_keypair_data(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, std::io::Error> {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

    if ciphertext.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Ciphertext too short",
        ));
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_bytes);

    // Create cipher
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    // Decrypt
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = encrypted.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed"))?;

    Ok(plaintext.to_vec())
}

/// Serialize keypair to bytes (public key || secret key)
fn serialize_keypair(
    public_key: &MlDsaPublicKey,
    secret_key: &MlDsaSecretKey,
) -> Result<Vec<u8>, std::io::Error> {
    let pub_bytes = public_key.as_bytes();
    let sec_bytes = secret_key.as_bytes();

    // Format: [4-byte public key length][public key bytes][secret key bytes]
    let pub_len = pub_bytes.len() as u32;
    let mut result = Vec::with_capacity(4 + pub_bytes.len() + sec_bytes.len());
    result.extend_from_slice(&pub_len.to_le_bytes());
    result.extend_from_slice(pub_bytes);
    result.extend_from_slice(sec_bytes);
    Ok(result)
}

/// Deserialize keypair from bytes
fn deserialize_keypair(data: &[u8]) -> Result<(MlDsaPublicKey, MlDsaSecretKey), std::io::Error> {
    if data.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Keypair data too short",
        ));
    }

    let pub_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + pub_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Keypair data truncated",
        ));
    }

    let pub_bytes = &data[4..4 + pub_len];
    let sec_bytes = &data[4 + pub_len..];

    let public_key = MlDsaPublicKey::from_bytes(pub_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let secret_key = MlDsaSecretKey::from_bytes(sec_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    Ok((public_key, secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = P2pConfig::default();
        // v0.13.0+: No role field - all nodes are symmetric
        assert!(config.bind_addr.is_none());
        assert!(config.known_peers.is_empty());
        assert_eq!(config.max_connections, 256);
    }

    #[test]
    fn test_builder_basic() {
        let config = P2pConfig::builder()
            .max_connections(100)
            .build()
            .expect("Failed to build config");

        // v0.13.0+: No role field - all nodes are symmetric
        assert_eq!(config.max_connections, 100);
    }

    #[test]
    fn test_builder_with_known_peers() {
        let addr1: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let addr2: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");

        let config = P2pConfig::builder()
            .known_peer(addr1)
            .known_peer(addr2)
            .build()
            .expect("Failed to build config");

        assert_eq!(config.known_peers.len(), 2);
    }

    #[test]
    fn test_invalid_max_connections() {
        let result = P2pConfig::builder().max_connections(0).build();

        assert!(matches!(result, Err(ConfigError::InvalidMaxConnections)));
    }

    #[test]
    fn test_to_nat_config() {
        let config = P2pConfig::builder()
            .known_peer("127.0.0.1:9000".parse().expect("valid addr"))
            .nat(NatConfig {
                max_candidates: 20,
                enable_symmetric_nat: false,
                ..Default::default()
            })
            .build()
            .expect("Failed to build config");

        let nat_config = config.to_nat_config();
        assert_eq!(nat_config.max_candidates, 20);
        assert!(!nat_config.enable_symmetric_nat);
    }

    #[test]
    fn test_nat_config_default() {
        let nat = NatConfig::default();
        assert_eq!(nat.max_candidates, 10);
        assert!(nat.enable_symmetric_nat);
        assert!(nat.enable_relay_fallback);
        assert_eq!(nat.max_concurrent_attempts, 3);
        assert!(nat.prefer_rfc_nat_traversal);
    }

    #[test]
    fn test_mtu_config_default() {
        let mtu = MtuConfig::default();
        assert_eq!(mtu.initial_mtu, 1200);
        assert_eq!(mtu.min_mtu, 1200);
        assert!(mtu.discovery_enabled);
        assert_eq!(mtu.max_mtu, 1452);
        assert!(mtu.auto_pqc_adjustment);
    }

    #[test]
    fn test_mtu_config_pqc_optimized() {
        let mtu = MtuConfig::pqc_optimized();
        assert_eq!(mtu.initial_mtu, 1500);
        assert_eq!(mtu.min_mtu, 1200);
        assert!(mtu.discovery_enabled);
        assert_eq!(mtu.max_mtu, 4096);
        assert!(mtu.auto_pqc_adjustment);
    }

    #[test]
    fn test_mtu_config_constrained() {
        let mtu = MtuConfig::constrained();
        assert_eq!(mtu.initial_mtu, 1200);
        assert_eq!(mtu.min_mtu, 1200);
        assert!(!mtu.discovery_enabled);
        assert_eq!(mtu.max_mtu, 1200);
        assert!(!mtu.auto_pqc_adjustment);
    }

    #[test]
    fn test_mtu_config_jumbo_frames() {
        let mtu = MtuConfig::jumbo_frames();
        assert_eq!(mtu.initial_mtu, 1500);
        assert_eq!(mtu.min_mtu, 1200);
        assert!(mtu.discovery_enabled);
        assert_eq!(mtu.max_mtu, 9000);
        assert!(mtu.auto_pqc_adjustment);
    }

    #[test]
    fn test_builder_with_mtu_config() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder()
            .mtu(MtuConfig::pqc_optimized())
            .build()
            .expect("Failed to build config");

        assert_eq!(config.mtu.initial_mtu, 1500);
        assert_eq!(config.mtu.max_mtu, 4096);
    }

    #[test]
    fn test_builder_pqc_optimized_mtu() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder()
            .pqc_optimized_mtu()
            .build()
            .expect("Failed to build config");

        assert_eq!(config.mtu.initial_mtu, 1500);
        assert_eq!(config.mtu.max_mtu, 4096);
    }

    #[test]
    fn test_builder_constrained_mtu() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder()
            .constrained_mtu()
            .build()
            .expect("Failed to build config");

        assert!(!config.mtu.discovery_enabled);
        assert_eq!(config.mtu.max_mtu, 1200);
    }

    #[test]
    fn test_builder_jumbo_mtu() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder()
            .jumbo_mtu()
            .build()
            .expect("Failed to build config");

        assert_eq!(config.mtu.max_mtu, 9000);
    }

    #[test]
    fn test_default_config_has_mtu() {
        let config = P2pConfig::default();
        assert_eq!(config.mtu.initial_mtu, 1200);
        assert!(config.mtu.discovery_enabled);
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 3)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_config_builder_transport_provider() {
        use crate::transport::{TransportType, UdpTransport};
        use std::sync::Arc;

        // Create a real UdpTransport provider
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let transport = UdpTransport::bind(addr)
            .await
            .expect("Failed to bind UdpTransport");
        let provider: Arc<dyn crate::transport::TransportProvider> = Arc::new(transport);

        // Build config with single transport_provider() call
        let config = P2pConfig::builder()
            .transport_provider(provider)
            .build()
            .expect("Failed to build config");

        // Verify registry has exactly 1 provider
        assert_eq!(config.transport_registry.len(), 1);
        assert!(!config.transport_registry.is_empty());

        // Verify it's a UDP provider
        let udp_providers = config
            .transport_registry
            .providers_by_type(TransportType::Udp);
        assert_eq!(udp_providers.len(), 1);
    }

    #[tokio::test]
    async fn test_p2p_config_builder_multiple_providers() {
        use crate::transport::{TransportType, UdpTransport};
        use std::sync::Arc;

        // Create two UDP transports on different ports
        let addr1: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let addr2: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        let transport1 = UdpTransport::bind(addr1)
            .await
            .expect("Failed to bind transport 1");
        let transport2 = UdpTransport::bind(addr2)
            .await
            .expect("Failed to bind transport 2");

        let provider1: Arc<dyn crate::transport::TransportProvider> = Arc::new(transport1);
        let provider2: Arc<dyn crate::transport::TransportProvider> = Arc::new(transport2);

        // Build config with multiple transport_provider() calls
        let config = P2pConfig::builder()
            .transport_provider(provider1)
            .transport_provider(provider2)
            .build()
            .expect("Failed to build config");

        // Verify registry has both providers
        assert_eq!(config.transport_registry.len(), 2);
        assert_eq!(
            config
                .transport_registry
                .providers_by_type(TransportType::Udp)
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_p2p_config_builder_transport_registry() {
        use crate::transport::{TransportRegistry, TransportType, UdpTransport};
        use std::sync::Arc;

        // Create a registry and add multiple providers
        let mut registry = TransportRegistry::new();

        let addr1: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let addr2: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid addr");

        let transport1 = UdpTransport::bind(addr1)
            .await
            .expect("Failed to bind transport 1");
        let transport2 = UdpTransport::bind(addr2)
            .await
            .expect("Failed to bind transport 2");

        registry.register(Arc::new(transport1));
        registry.register(Arc::new(transport2));

        // Build config with transport_registry() method
        let config = P2pConfig::builder()
            .transport_registry(registry)
            .build()
            .expect("Failed to build config");

        // Verify all providers present
        assert_eq!(config.transport_registry.len(), 2);
        assert_eq!(
            config
                .transport_registry
                .providers_by_type(TransportType::Udp)
                .len(),
            2
        );
    }

    #[test]
    fn test_p2p_config_default_has_empty_registry() {
        let config = P2pConfig::default();
        assert!(config.transport_registry.is_empty());
        assert_eq!(config.transport_registry.len(), 0);
    }

    #[test]
    fn test_p2p_config_builder_default_has_empty_registry() {
        let config = P2pConfig::builder()
            .build()
            .expect("Failed to build config");
        assert!(config.transport_registry.is_empty());
        assert_eq!(config.transport_registry.len(), 0);
    }
}
