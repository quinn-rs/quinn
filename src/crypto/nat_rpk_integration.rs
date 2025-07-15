//! Integration of NAT Traversal with Raw Public Keys
//!
//! This module provides high-level APIs that combine NAT traversal capabilities
//! with Raw Public Key authentication, enabling P2P connections through NATs
//! without the overhead of X.509 certificates.

use std::sync::Arc;
use std::net::SocketAddr;

use rustls::{ClientConfig, ServerConfig};
use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};

use super::{
    raw_public_keys::{RawPublicKeyConfigBuilder, utils::*},
    tls_extensions::CertificateTypePreferences,
    tls_extension_simulation::{Rfc7250ClientConfig, Rfc7250ServerConfig},
    rpk_integration::RpkNatConfig,
};

use crate::nat_traversal_api::{NatTraversalRole, PeerId};

/// Configuration for a P2P node with NAT traversal and Raw Public Keys
#[derive(Debug, Clone)]
pub struct P2PNodeConfig {
    /// The node's Ed25519 private key
    pub private_key: Ed25519SecretKey,
    /// The node's public key (derived from private key)
    pub public_key: Ed25519PublicKey,
    /// The node's peer ID (derived from public key)
    pub peer_id: PeerId,
    /// NAT traversal role
    pub nat_role: NatTraversalRole,
    /// List of trusted peer public keys
    pub trusted_peers: Vec<[u8; 32]>,
    /// Whether to allow connections from any peer (development mode)
    pub allow_any_peer: bool,
    /// Certificate type preferences
    pub cert_preferences: CertificateTypePreferences,
}

impl P2PNodeConfig {
    /// Create a new P2P node configuration
    pub fn new(private_key: Ed25519SecretKey, nat_role: NatTraversalRole) -> Self {
        let public_key = private_key.verifying_key();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        Self {
            private_key,
            public_key,
            peer_id,
            nat_role,
            trusted_peers: Vec::new(),
            allow_any_peer: false,
            cert_preferences: CertificateTypePreferences::prefer_raw_public_key(),
        }
    }

    /// Create a development configuration that accepts any peer
    pub fn new_dev(private_key: Ed25519SecretKey, nat_role: NatTraversalRole) -> Self {
        let mut config = Self::new(private_key, nat_role);
        config.allow_any_peer = true;
        config
    }

    /// Add a trusted peer by their public key
    pub fn add_trusted_peer(&mut self, public_key: [u8; 32]) {
        self.trusted_peers.push(public_key);
    }

    /// Add a trusted peer by their peer ID (requires public key verification during handshake)
    pub fn add_trusted_peer_id(&mut self, peer_id: &PeerId) {
        // In a real implementation, we'd maintain a mapping of peer IDs to public keys
        // For now, we'll require direct public key trust
        tracing::warn!("add_trusted_peer_id requires public key mapping - use add_trusted_peer instead");
    }

    /// Set certificate type preferences to Raw Public Key only
    pub fn require_raw_public_keys(&mut self) {
        self.cert_preferences = CertificateTypePreferences::raw_public_key_only();
    }

    /// Build the complete client configuration with NAT traversal and RPK
    pub fn build_client_config(self) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
        let mut builder = RawPublicKeyConfigBuilder::new();

        if self.allow_any_peer {
            builder = builder.allow_any_key();
        } else {
            for key in self.trusted_peers {
                builder = builder.add_trusted_key(key);
            }
        }

        builder = builder.with_certificate_type_extensions(self.cert_preferences);

        let config = builder.build_client_config()?;
        Ok(Arc::new(config))
    }

    /// Build the complete server configuration with NAT traversal and RPK
    pub fn build_server_config(self) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(self.private_key)
            .with_certificate_type_extensions(self.cert_preferences);

        let config = builder.build_server_config()?;
        Ok(Arc::new(config))
    }

    /// Build RFC 7250 aware client configuration
    pub fn build_rfc7250_client_config(self) -> Result<Rfc7250ClientConfig, Box<dyn std::error::Error>> {
        let mut builder = RawPublicKeyConfigBuilder::new();

        if self.allow_any_peer {
            builder = builder.allow_any_key();
        } else {
            for key in self.trusted_peers {
                builder = builder.add_trusted_key(key);
            }
        }

        builder = builder.with_certificate_type_extensions(self.cert_preferences);

        Ok(builder.build_rfc7250_client_config()?)
    }

    /// Build RFC 7250 aware server configuration
    pub fn build_rfc7250_server_config(self) -> Result<Rfc7250ServerConfig, Box<dyn std::error::Error>> {
        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(self.private_key)
            .with_certificate_type_extensions(self.cert_preferences);

        Ok(builder.build_rfc7250_server_config()?)
    }

    /// Get the RpkNatConfig for integration with ant-quic endpoints
    pub fn get_rpk_nat_config(&self) -> RpkNatConfig {
        RpkNatConfig {
            private_key: self.private_key.clone(),
            public_key: self.public_key,
            peer_id: self.peer_id,
            nat_role: self.nat_role.clone(),
            trusted_peers: self.trusted_peers.clone(),
        }
    }
}

/// Builder pattern for creating P2P bootstrap nodes
pub struct BootstrapNodeBuilder {
    private_key: Option<Ed25519SecretKey>,
    bind_addr: Option<SocketAddr>,
    trusted_peers: Vec<[u8; 32]>,
}

impl BootstrapNodeBuilder {
    /// Create a new bootstrap node builder
    pub fn new() -> Self {
        Self {
            private_key: None,
            bind_addr: None,
            trusted_peers: Vec::new(),
        }
    }

    /// Set the node's private key
    pub fn with_private_key(mut self, private_key: Ed25519SecretKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Generate a new random private key
    pub fn with_generated_key(mut self) -> Self {
        let (private_key, _) = generate_ed25519_keypair();
        self.private_key = Some(private_key);
        self
    }

    /// Set the bind address for the bootstrap node
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Add trusted peers that can connect to this bootstrap node
    pub fn add_trusted_peer(mut self, public_key: [u8; 32]) -> Self {
        self.trusted_peers.push(public_key);
        self
    }

    /// Build the bootstrap node configuration
    pub fn build(self) -> Result<P2PNodeConfig, Box<dyn std::error::Error>> {
        let private_key = self.private_key
            .ok_or("Private key required for bootstrap node")?;

        let mut config = P2PNodeConfig::new(
            private_key,
            NatTraversalRole::Server { can_relay: true },
        );

        for peer in self.trusted_peers {
            config.add_trusted_peer(peer);
        }

        // Bootstrap nodes should prefer Raw Public Keys but allow X.509 for compatibility
        config.cert_preferences = CertificateTypePreferences::prefer_raw_public_key();

        Ok(config)
    }
}

/// Helper functions for common P2P scenarios
pub mod helpers {
    use super::*;

    /// Create a pair of P2P node configurations that trust each other
    pub fn create_trusted_pair() -> (P2PNodeConfig, P2PNodeConfig) {
        let (private_key1, public_key1) = generate_ed25519_keypair();
        let (private_key2, public_key2) = generate_ed25519_keypair();

        let key1_bytes = public_key_to_bytes(&public_key1);
        let key2_bytes = public_key_to_bytes(&public_key2);

        let mut node1 = P2PNodeConfig::new(private_key1, NatTraversalRole::Client);
        node1.add_trusted_peer(key2_bytes);

        let mut node2 = P2PNodeConfig::new(private_key2, NatTraversalRole::Server { can_relay: false });
        node2.add_trusted_peer(key1_bytes);

        (node1, node2)
    }

    /// Create a bootstrap node configuration for testing
    pub fn create_test_bootstrap_node() -> P2PNodeConfig {
        let (private_key, _) = generate_ed25519_keypair();
        P2PNodeConfig::new_dev(private_key, NatTraversalRole::Server { can_relay: true })
    }

    /// Verify that a peer's claimed ID matches their public key
    pub fn verify_peer_identity(peer_id: &PeerId, public_key: &Ed25519PublicKey) -> bool {
        verify_peer_id(peer_id, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::helpers::*;

    #[test]
    fn test_p2p_node_config_creation() {
        let (private_key, public_key) = generate_ed25519_keypair();
        let config = P2PNodeConfig::new(private_key, NatTraversalRole::Client);

        assert_eq!(config.public_key, public_key);
        assert_eq!(config.peer_id, derive_peer_id_from_public_key(&public_key));
        assert!(!config.allow_any_peer);
        assert!(config.trusted_peers.is_empty());
    }

    #[test]
    fn test_trusted_pair_creation() {
        let (node1, node2) = create_trusted_pair();

        // Each node should trust the other
        assert_eq!(node1.trusted_peers.len(), 1);
        assert_eq!(node2.trusted_peers.len(), 1);

        // Verify they trust each other's public keys
        let node1_key_bytes = public_key_to_bytes(&node1.public_key);
        let node2_key_bytes = public_key_to_bytes(&node2.public_key);

        assert_eq!(node1.trusted_peers[0], node2_key_bytes);
        assert_eq!(node2.trusted_peers[0], node1_key_bytes);
    }

    #[test]
    fn test_bootstrap_node_builder() {
        let bootstrap = BootstrapNodeBuilder::new()
            .with_generated_key()
            .bind("0.0.0.0:9000".parse().unwrap())
            .build()
            .unwrap();

        match bootstrap.nat_role {
            NatTraversalRole::Server { can_relay } => assert!(can_relay),
            _ => panic!("Bootstrap node should be a server with relay capability"),
        }
    }

    #[test]
    fn test_config_building() {
        let (private_key, _) = generate_ed25519_keypair();
        let config = P2PNodeConfig::new(private_key, NatTraversalRole::Client);

        // Test client config building
        let client_config = config.clone().build_client_config().unwrap();
        assert!(Arc::strong_count(&client_config) == 1);

        // Test server config building
        let server_config = config.build_server_config().unwrap();
        assert!(Arc::strong_count(&server_config) == 1);
    }

    #[test]
    fn test_rfc7250_config_building() {
        let (node1, node2) = create_trusted_pair();

        // Build RFC 7250 configs
        let client_config = node1.build_rfc7250_client_config().unwrap();
        let server_config = node2.build_rfc7250_server_config().unwrap();

        // Test that extension contexts are available
        assert!(client_config.extension_context().is_some());
        assert!(server_config.extension_context().is_some());
    }
}