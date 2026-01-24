// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Minimal configuration for zero-config P2P nodes
//!
//! This module provides [`NodeConfig`] - a simple configuration struct
//! with only 3 optional fields. Most applications need zero configuration.
//!
//! # Zero Configuration
//!
//! ```rust,ignore
//! use ant_quic::Node;
//!
//! // No configuration needed - just create a node
//! let node = Node::new().await?;
//! ```
//!
//! # Optional Configuration
//!
//! ```rust,ignore
//! use ant_quic::{Node, NodeConfig};
//!
//! // Only configure what you need
//! let config = NodeConfig::builder()
//!     .known_peer("quic.saorsalabs.com:9000".parse()?)
//!     .build();
//!
//! let node = Node::with_config(config).await?;
//! ```

use std::path::Path;
use std::sync::Arc;

use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey};
use crate::host_identity::HostIdentity;
use crate::transport::{TransportAddr, TransportProvider, TransportRegistry};
use crate::unified_config::load_or_generate_endpoint_keypair;

/// Minimal configuration for P2P nodes
///
/// All fields are optional - the node will auto-configure everything.
/// - `bind_addr`: Defaults to `0.0.0.0:0` (random port)
/// - `known_peers`: Defaults to empty (node can still accept connections)
/// - `keypair`: Defaults to fresh generated keypair
/// - `transport_providers`: Defaults to UDP transport only
///
/// # Example
///
/// ```rust,ignore
/// // Zero configuration
/// let config = NodeConfig::default();
///
/// // Or with known peers
/// let config = NodeConfig::builder()
///     .known_peer("peer1.example.com:9000".parse()?)
///     .build();
///
/// // Or with additional transport providers
/// #[cfg(feature = "ble")]
/// let config = NodeConfig::builder()
///     .transport_provider(Arc::new(BleTransport::new().await?))
///     .build();
/// ```
#[derive(Clone, Default)]
pub struct NodeConfig {
    /// Bind address. Default: 0.0.0.0:0 (random port)
    pub bind_addr: Option<TransportAddr>,

    /// Known peers for initial discovery. Default: empty
    /// When empty, node can still accept incoming connections.
    pub known_peers: Vec<TransportAddr>,

    /// Identity keypair (ML-DSA-65). Default: fresh generated
    /// Provide for persistent identity across restarts.
    pub keypair: Option<(MlDsaPublicKey, MlDsaSecretKey)>,

    /// Additional transport providers beyond the default UDP transport.
    ///
    /// The UDP transport is always included by default. Use this to add
    /// additional transports like BLE, LoRa, serial, etc.
    ///
    /// Transport capabilities are propagated to peer advertisements and
    /// used for routing decisions.
    pub transport_providers: Vec<Arc<dyn TransportProvider>>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind_addr", &self.bind_addr)
            .field("known_peers", &self.known_peers)
            .field("keypair", &self.keypair.as_ref().map(|_| "[REDACTED]"))
            .field("transport_providers", &self.transport_providers.len())
            .finish()
    }
}

impl NodeConfig {
    /// Create a new config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for fluent construction
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::default()
    }

    /// Create config with a specific bind address
    pub fn with_bind_addr(addr: impl Into<TransportAddr>) -> Self {
        Self {
            bind_addr: Some(addr.into()),
            ..Default::default()
        }
    }

    /// Create config with known peers
    pub fn with_known_peers(peers: impl IntoIterator<Item = impl Into<TransportAddr>>) -> Self {
        Self {
            known_peers: peers.into_iter().map(|p| p.into()).collect(),
            ..Default::default()
        }
    }

    /// Create config with a specific ML-DSA-65 keypair
    pub fn with_keypair(public_key: MlDsaPublicKey, secret_key: MlDsaSecretKey) -> Self {
        Self {
            keypair: Some((public_key, secret_key)),
            ..Default::default()
        }
    }
}

/// Builder for [`NodeConfig`]
#[derive(Default)]
pub struct NodeConfigBuilder {
    bind_addr: Option<TransportAddr>,
    known_peers: Vec<TransportAddr>,
    keypair: Option<(MlDsaPublicKey, MlDsaSecretKey)>,
    transport_providers: Vec<Arc<dyn TransportProvider>>,
}

impl NodeConfigBuilder {
    /// Set the local address to bind to
    ///
    /// Accepts any type implementing `Into<TransportAddr>`:
    /// - `SocketAddr` - Auto-converts to `TransportAddr::Udp` (backward compatible)
    /// - `TransportAddr` - Enables multi-transport support (BLE, LoRa, etc.)
    ///
    /// If not specified, defaults to `0.0.0.0:0` (random ephemeral port).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use ant_quic::NodeConfig;
    /// use std::net::SocketAddr;
    ///
    /// // Backward compatible: SocketAddr
    /// let config = NodeConfig::builder()
    ///     .bind_addr("0.0.0.0:9000".parse::<SocketAddr>().unwrap())
    ///     .build();
    ///
    /// // Multi-transport: Explicit TransportAddr
    /// use ant_quic::transport::TransportAddr;
    /// let config = NodeConfig::builder()
    ///     .bind_addr(TransportAddr::Udp("0.0.0.0:0".parse().unwrap()))
    ///     .build();
    /// ```
    pub fn bind_addr(mut self, addr: impl Into<TransportAddr>) -> Self {
        self.bind_addr = Some(addr.into());
        self
    }

    /// Add a known peer for initial network connectivity
    ///
    /// Known peers are used for initial discovery and connection establishment.
    /// The node will learn about additional peers through the network.
    ///
    /// Accepts any type implementing `Into<TransportAddr>`:
    /// - `SocketAddr` - Auto-converts to `TransportAddr::Udp`
    /// - `TransportAddr` - Supports multiple transport types
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use ant_quic::NodeConfig;
    /// use std::net::SocketAddr;
    ///
    /// // Backward compatible: SocketAddr
    /// let config = NodeConfig::builder()
    ///     .known_peer("peer.example.com:9000".parse::<SocketAddr>().unwrap())
    ///     .build();
    ///
    /// // Multi-transport: Mix different transport types
    /// use ant_quic::transport::TransportAddr;
    /// let config = NodeConfig::builder()
    ///     .known_peer(TransportAddr::Udp("192.168.1.1:9000".parse().unwrap()))
    ///     .known_peer(TransportAddr::ble([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], None))
    ///     .build();
    /// ```
    pub fn known_peer(mut self, addr: impl Into<TransportAddr>) -> Self {
        self.known_peers.push(addr.into());
        self
    }

    /// Add multiple known peers at once
    ///
    /// Convenient method to add a collection of peers. Each item is automatically
    /// converted via `Into<TransportAddr>`, supporting both `SocketAddr` and
    /// `TransportAddr` for backward compatibility and multi-transport scenarios.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use ant_quic::NodeConfig;
    /// use std::net::SocketAddr;
    ///
    /// // Backward compatible: Vec<SocketAddr>
    /// let peers: Vec<SocketAddr> = vec![
    ///     "peer1.example.com:9000".parse().unwrap(),
    ///     "peer2.example.com:9000".parse().unwrap(),
    /// ];
    /// let config = NodeConfig::builder()
    ///     .known_peers(peers)
    ///     .build();
    ///
    /// // Multi-transport: Heterogeneous transport list
    /// use ant_quic::transport::TransportAddr;
    /// let mixed = vec![
    ///     TransportAddr::Udp("192.168.1.1:9000".parse().unwrap()),
    ///     TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None),
    ///     TransportAddr::serial("/dev/ttyUSB0"),
    /// ];
    /// let config = NodeConfig::builder()
    ///     .known_peers(mixed)
    ///     .build();
    /// ```
    pub fn known_peers(
        mut self,
        addrs: impl IntoIterator<Item = impl Into<TransportAddr>>,
    ) -> Self {
        self.known_peers.extend(addrs.into_iter().map(|a| a.into()));
        self
    }

    /// Set the identity keypair (ML-DSA-65)
    pub fn keypair(mut self, public_key: MlDsaPublicKey, secret_key: MlDsaSecretKey) -> Self {
        self.keypair = Some((public_key, secret_key));
        self
    }

    /// Set the identity from a HostIdentity with encrypted storage
    ///
    /// This loads or generates a keypair using the HostIdentity for encryption.
    /// The keypair is stored encrypted at rest in the specified directory.
    ///
    /// # Arguments
    ///
    /// * `host` - The HostIdentity for key derivation
    /// * `network_id` - Network identifier for per-network keypair isolation
    /// * `storage_dir` - Directory to store the encrypted keypair
    ///
    /// # Errors
    ///
    /// Returns an error if the keypair cannot be loaded or generated.
    pub fn with_host_identity(
        mut self,
        host: &HostIdentity,
        network_id: &[u8],
        storage_dir: &Path,
    ) -> Result<Self, String> {
        let (public_key, secret_key) =
            load_or_generate_endpoint_keypair(host, network_id, storage_dir)
                .map_err(|e| format!("Failed to load/generate keypair: {e}"))?;
        self.keypair = Some((public_key, secret_key));
        Ok(self)
    }

    /// Add a transport provider
    ///
    /// Transport providers are used for multi-transport P2P networking.
    /// The UDP transport is always included by default.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// #[cfg(feature = "ble")]
    /// let config = NodeConfig::builder()
    ///     .transport_provider(Arc::new(BleTransport::new().await?))
    ///     .build();
    /// ```
    pub fn transport_provider(mut self, provider: Arc<dyn TransportProvider>) -> Self {
        self.transport_providers.push(provider);
        self
    }

    /// Add multiple transport providers
    pub fn transport_providers(
        mut self,
        providers: impl IntoIterator<Item = Arc<dyn TransportProvider>>,
    ) -> Self {
        self.transport_providers.extend(providers);
        self
    }

    /// Build the configuration
    pub fn build(self) -> NodeConfig {
        NodeConfig {
            bind_addr: self.bind_addr,
            known_peers: self.known_peers,
            keypair: self.keypair,
            transport_providers: self.transport_providers,
        }
    }
}

impl NodeConfig {
    /// Build a transport registry from this configuration
    ///
    /// Creates a registry containing all configured transport providers.
    /// If no providers are configured, returns an empty registry (UDP
    /// should be added by the caller based on bind_addr).
    pub fn build_transport_registry(&self) -> TransportRegistry {
        let mut registry = TransportRegistry::new();
        for provider in &self.transport_providers {
            registry.register(provider.clone());
        }
        registry
    }

    /// Check if this configuration has any non-UDP transport providers
    pub fn has_constrained_transports(&self) -> bool {
        use crate::transport::TransportType;
        self.transport_providers
            .iter()
            .any(|p| p.transport_type() != TransportType::Udp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert!(config.bind_addr.is_none());
        assert!(config.known_peers.is_empty());
        assert!(config.keypair.is_none());
        assert!(config.transport_providers.is_empty());
    }

    #[test]
    fn test_builder_with_bind_addr() {
        let addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let config = NodeConfig::builder().bind_addr(addr).build();
        assert_eq!(config.bind_addr, Some(TransportAddr::from(addr)));
    }

    #[test]
    fn test_builder_with_known_peers() {
        let peer1: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let peer2: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let config = NodeConfig::builder()
            .known_peer(peer1)
            .known_peer(peer2)
            .build();

        assert_eq!(config.known_peers.len(), 2);
        assert!(config.known_peers.contains(&TransportAddr::from(peer1)));
        assert!(config.known_peers.contains(&TransportAddr::from(peer2)));
    }

    #[test]
    fn test_builder_with_multiple_peers() {
        let peers: Vec<SocketAddr> = vec![
            "127.0.0.1:9000".parse().unwrap(),
            "127.0.0.1:9001".parse().unwrap(),
        ];

        let config = NodeConfig::builder().known_peers(peers.clone()).build();

        assert_eq!(config.known_peers.len(), 2);
        assert_eq!(
            config.known_peers,
            peers
                .into_iter()
                .map(TransportAddr::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_with_bind_addr() {
        let addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let config = NodeConfig::with_bind_addr(addr);
        assert_eq!(config.bind_addr, Some(TransportAddr::from(addr)));
        assert!(config.known_peers.is_empty());
        assert!(config.keypair.is_none());
    }

    #[test]
    fn test_with_known_peers() {
        let peers: Vec<SocketAddr> = vec![
            "127.0.0.1:9000".parse().unwrap(),
            "127.0.0.1:9001".parse().unwrap(),
        ];

        let config = NodeConfig::with_known_peers(peers.clone());
        assert!(config.bind_addr.is_none());
        assert_eq!(
            config.known_peers,
            peers
                .into_iter()
                .map(TransportAddr::from)
                .collect::<Vec<_>>()
        );
        assert!(config.keypair.is_none());
    }

    #[test]
    fn test_debug_redacts_keypair() {
        use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;
        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let config = NodeConfig::with_keypair(public_key, secret_key);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&format!("{:?}", config.keypair)));
    }

    #[test]
    fn test_config_is_clone() {
        let addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let config = NodeConfig::builder()
            .bind_addr(addr)
            .known_peer(peer)
            .build();

        let cloned = config.clone();
        assert_eq!(config.bind_addr, cloned.bind_addr);
        assert_eq!(config.known_peers, cloned.known_peers);
    }

    #[test]
    fn test_build_transport_registry() {
        let config = NodeConfig::default();
        let registry = config.build_transport_registry();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_has_constrained_transports_default() {
        let config = NodeConfig::default();
        assert!(!config.has_constrained_transports());
    }

    #[test]
    fn test_debug_shows_transport_count() {
        let config = NodeConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("transport_providers: 0"));
    }

    #[test]
    fn test_node_config_with_transport_addr() {
        // Create NodeConfig with TransportAddr bind and peers
        let bind_addr = TransportAddr::from("0.0.0.0:9000".parse::<SocketAddr>().unwrap());
        let peer1 = TransportAddr::from("127.0.0.1:9001".parse::<SocketAddr>().unwrap());
        let peer2 = TransportAddr::from("127.0.0.1:9002".parse::<SocketAddr>().unwrap());

        let config = NodeConfig::builder()
            .bind_addr(bind_addr.clone())
            .known_peer(peer1.clone())
            .known_peer(peer2.clone())
            .build();

        // Verify fields set correctly
        assert_eq!(config.bind_addr, Some(bind_addr));
        assert_eq!(config.known_peers.len(), 2);
        assert!(config.known_peers.contains(&peer1));
        assert!(config.known_peers.contains(&peer2));
    }

    #[test]
    fn test_node_config_builder_backward_compat() {
        // Use builder with SocketAddr (should auto-convert via Into trait)
        let bind_socket: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let peer_socket: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let config = NodeConfig::builder()
            .bind_addr(bind_socket)
            .known_peer(peer_socket)
            .build();

        // Verify Into trait conversion works
        assert_eq!(config.bind_addr, Some(TransportAddr::from(bind_socket)));
        assert_eq!(config.known_peers.len(), 1);
        assert_eq!(config.known_peers[0], TransportAddr::from(peer_socket));

        // Verify it's the same as explicit TransportAddr usage
        let explicit_config = NodeConfig::builder()
            .bind_addr(TransportAddr::from(bind_socket))
            .known_peer(TransportAddr::from(peer_socket))
            .build();

        assert_eq!(config.bind_addr, explicit_config.bind_addr);
        assert_eq!(config.known_peers, explicit_config.known_peers);
    }

    #[test]
    fn test_node_config_transport_addr_preservation() {
        // Create NodeConfig with various TransportAddr types
        let udp_bind = TransportAddr::from("0.0.0.0:0".parse::<SocketAddr>().unwrap());
        let udp_peer = TransportAddr::from("127.0.0.1:9000".parse::<SocketAddr>().unwrap());
        let ipv6_peer = TransportAddr::from("[::1]:9001".parse::<SocketAddr>().unwrap());

        let config = NodeConfig::builder()
            .bind_addr(udp_bind.clone())
            .known_peer(udp_peer.clone())
            .known_peer(ipv6_peer.clone())
            .build();

        // Verify address types preserved
        assert_eq!(config.bind_addr, Some(udp_bind));
        assert_eq!(config.known_peers.len(), 2);

        // Check that TransportAddr types are maintained
        assert!(matches!(config.known_peers[0], TransportAddr::Udp(_)));
        assert!(matches!(config.known_peers[1], TransportAddr::Udp(_)));

        // Verify actual addresses match
        assert_eq!(config.known_peers[0], udp_peer);
        assert_eq!(config.known_peers[1], ipv6_peer);
    }
}
