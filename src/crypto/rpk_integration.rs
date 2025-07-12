//! Integration of Raw Public Keys with ant-quic's existing QUIC infrastructure
//!
//! This module provides high-level integration between the Raw Public Keys implementation
//! and ant-quic's existing QUIC configuration and endpoint management.

use std::sync::Arc;

use ed25519_dalek::{VerifyingKey as Ed25519PublicKey, SigningKey as Ed25519SecretKey};

use crate::{
    crypto::{
        raw_public_keys::{RawPublicKeyConfigBuilder, utils},
        rustls::{QuicClientConfig, QuicServerConfig},
    },
    nat_traversal_api::{NatTraversalConfig, EndpointRole, PeerId},
    config::EndpointConfig,
};

/// Configuration for Raw Public Keys in NAT traversal
#[derive(Debug, Clone)]
pub struct RpkNatConfig {
    /// The local keypair for this node
    pub local_keypair: (Ed25519SecretKey, Ed25519PublicKey),
    /// Set of trusted public keys for peer verification
    pub trusted_peers: Vec<[u8; 32]>,
    /// Whether to allow any valid key (development mode)
    pub allow_any_peer: bool,
    /// Role of this endpoint in NAT traversal
    pub role: EndpointRole,
}

impl RpkNatConfig {
    /// Create a new RPK NAT configuration with a generated keypair
    pub fn new(role: EndpointRole) -> Self {
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        Self {
            local_keypair: (private_key, public_key),
            trusted_peers: Vec::new(),
            allow_any_peer: false,
            role,
        }
    }

    /// Create configuration with a specific keypair
    pub fn with_keypair(
        private_key: Ed25519SecretKey,
        public_key: Ed25519PublicKey,
        role: EndpointRole,
    ) -> Self {
        Self {
            local_keypair: (private_key, public_key),
            trusted_peers: Vec::new(),
            allow_any_peer: false,
            role,
        }
    }

    /// Add a trusted peer's public key
    pub fn add_trusted_peer(mut self, public_key: [u8; 32]) -> Self {
        self.trusted_peers.push(public_key);
        self
    }

    /// Allow any valid Ed25519 public key (development only)
    pub fn allow_any_peer(mut self) -> Self {
        self.allow_any_peer = true;
        self
    }

    /// Get this node's public key as bytes
    pub fn local_public_key_bytes(&self) -> [u8; 32] {
        utils::public_key_to_bytes(&self.local_keypair.1)
    }

    /// Get this node's PeerId based on the public key
    pub fn peer_id(&self) -> PeerId {
        // Use the first 16 bytes of the public key as PeerId
        let key_bytes = self.local_public_key_bytes();
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&key_bytes);
        PeerId(peer_id)
    }

    /// Create a QuicClientConfig with Raw Public Keys
    pub fn create_client_config(&self) -> Result<QuicClientConfig, Box<dyn std::error::Error>> {
        let mut builder = RawPublicKeyConfigBuilder::new();

        // Add trusted peers
        for peer_key in &self.trusted_peers {
            builder = builder.add_trusted_key(*peer_key);
        }

        // Allow any peer if configured
        if self.allow_any_peer {
            builder = builder.allow_any_key();
        }

        // Build rustls client config
        let rustls_config = builder.build_client_config()?;

        // Wrap in QuicClientConfig
        QuicClientConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("Failed to create QuicClientConfig: {}", e).into())
    }

    /// Create a QuicServerConfig with Raw Public Keys
    pub fn create_server_config(&self) -> Result<QuicServerConfig, Box<dyn std::error::Error>> {
        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(self.local_keypair.0.clone());

        // Build rustls server config
        let rustls_config = builder.build_server_config()?;

        // Wrap in QuicServerConfig
        QuicServerConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("Failed to create QuicServerConfig: {}", e).into())
    }

    /// Create both client and server configs for a bidirectional endpoint
    pub fn create_endpoint_configs(&self) -> Result<(QuicClientConfig, QuicServerConfig), Box<dyn std::error::Error>> {
        let client_config = self.create_client_config()?;
        let server_config = self.create_server_config()?;
        Ok((client_config, server_config))
    }
}

/// Extension trait for EndpointConfig to support Raw Public Keys
pub trait EndpointConfigExt {
    /// Configure endpoint with Raw Public Keys
    fn with_raw_public_keys(self, rpk_config: &RpkNatConfig) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

impl EndpointConfigExt for EndpointConfig {
    fn with_raw_public_keys(self, rpk_config: &RpkNatConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Create QUIC configs with Raw Public Keys
        let (_client_config, _server_config) = rpk_config.create_endpoint_configs()?;

        // Set the configs (this would need to be implemented in EndpointConfig)
        // For now, this is a placeholder showing the integration pattern
        
        Ok(self)
    }
}

/// Utility functions for Raw Public Keys in NAT traversal
pub mod rpk_utils {
    use super::*;
    use crate::nat_traversal_api::CandidateAddress;

    /// Create a bootstrap node configuration with Raw Public Keys
    pub fn create_bootstrap_config() -> RpkNatConfig {
        RpkNatConfig::new(EndpointRole::Bootstrap)
            .allow_any_peer() // Bootstrap nodes accept connections from any peer
    }

    /// Create a client configuration for NAT traversal
    pub fn create_client_config(bootstrap_keys: Vec<[u8; 32]>) -> RpkNatConfig {
        let mut config = RpkNatConfig::new(EndpointRole::Client);
        for key in bootstrap_keys {
            config = config.add_trusted_peer(key);
        }
        config
    }

    /// Create a server configuration for NAT traversal
    pub fn create_server_config(bootstrap_keys: Vec<[u8; 32]>) -> RpkNatConfig {
        let mut config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true });
        for key in bootstrap_keys {
            config = config.add_trusted_peer(key);
        }
        config
    }

    /// Extract peer public key from a QUIC connection (placeholder)
    /// This would need integration with the QUIC connection to extract the peer's public key
    pub fn extract_peer_public_key(_connection: &quinn::Connection) -> Option<[u8; 32]> {
        // Placeholder - would need to extract from the TLS session
        None
    }

    /// Verify that a candidate address matches the expected peer
    pub fn verify_candidate_peer(
        _candidate: &CandidateAddress,
        _expected_peer_key: &[u8; 32],
    ) -> bool {
        // Placeholder - would verify that the candidate's public key matches expected
        true
    }

    /// Create test configurations for integration testing
    #[cfg(test)]
    pub fn create_test_configs() -> (RpkNatConfig, RpkNatConfig) {
        let (client_private, client_public) = utils::generate_ed25519_keypair();
        let (server_private, server_public) = utils::generate_ed25519_keypair();

        let client_config = RpkNatConfig::with_keypair(
            client_private,
            client_public,
            EndpointRole::Client,
        ).add_trusted_peer(utils::public_key_to_bytes(&server_public));

        let server_config = RpkNatConfig::with_keypair(
            server_private,
            server_public,
            EndpointRole::Server { can_coordinate: true },
        ).add_trusted_peer(utils::public_key_to_bytes(&client_public));

        (client_config, server_config)
    }
}

/// Example usage and integration patterns
pub mod examples {
    use super::*;
    use crate::nat_traversal_api::NatTraversalEndpoint;

    /// Example: Create a P2P endpoint with Raw Public Keys
    pub async fn create_p2p_endpoint_with_rpk() -> Result<NatTraversalEndpoint, Box<dyn std::error::Error>> {
        // Generate local keypair
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        
        // Create RPK configuration
        let rpk_config = RpkNatConfig::with_keypair(private_key, public_key, EndpointRole::Client)
            .allow_any_peer(); // For demo - in production, add specific trusted peers

        // Create QUIC configurations
        let (_client_config, _server_config) = rpk_config.create_endpoint_configs()?;

        // Create NAT traversal configuration
        let _nat_config = NatTraversalConfig {
            role: rpk_config.role,
            // ... other NAT traversal settings
            ..Default::default()
        };

        // Create endpoint with RPK support
        // This would need integration with the actual endpoint creation
        // NatTraversalEndpoint::new_with_rpk(nat_config, rpk_config).await

        // Placeholder return
        todo!("Integration with NatTraversalEndpoint needed")
    }

    /// Example: Bootstrap node with Raw Public Keys
    pub async fn create_bootstrap_node() -> Result<(), Box<dyn std::error::Error>> {
        let rpk_config = rpk_utils::create_bootstrap_config();
        
        println!("Bootstrap node public key: {}", 
                 hex::encode(rpk_config.local_public_key_bytes()));
        
        // Create server config for accepting connections
        let _server_config = rpk_config.create_server_config()?;
        
        // Start bootstrap node
        // This would integrate with the actual bootstrap node implementation
        
        Ok(())
    }

    /// Example: Client connecting to bootstrap node
    pub async fn connect_to_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
        // Bootstrap node's public key (would be known/distributed)
        let bootstrap_key = [42u8; 32]; // Example key
        
        let rpk_config = rpk_utils::create_client_config(vec![bootstrap_key]);
        let _client_config = rpk_config.create_client_config()?;
        
        // Connect to bootstrap node with RPK authentication
        // This would integrate with the connection establishment code
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::rpk_utils::*;

    #[test]
    fn test_rpk_nat_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client);
        assert_eq!(config.role, EndpointRole::Client);
        assert!(!config.allow_any_peer);
        assert!(config.trusted_peers.is_empty());
    }

    #[test]
    fn test_rpk_config_with_trusted_peers() {
        let peer_key = [1u8; 32];
        let config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true })
            .add_trusted_peer(peer_key);
        
        assert_eq!(config.trusted_peers.len(), 1);
        assert_eq!(config.trusted_peers[0], peer_key);
    }

    #[test]
    fn test_peer_id_generation() {
        let config = RpkNatConfig::new(EndpointRole::Client);
        let peer_id = config.peer_id();
        
        // PeerId should be derived from public key
        let key_bytes = config.local_public_key_bytes();
        let expected_peer_id = PeerId(key_bytes);
        
        assert_eq!(peer_id, expected_peer_id);
    }

    #[test]
    fn test_create_test_configs() {
        let (client_config, server_config) = create_test_configs();
        
        assert_eq!(client_config.role, EndpointRole::Client);
        assert_eq!(server_config.role, EndpointRole::Server { can_coordinate: true });
        assert_eq!(client_config.trusted_peers.len(), 1);
        assert_eq!(server_config.trusted_peers.len(), 1);
    }

    #[tokio::test]
    async fn test_client_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client).allow_any_peer();
        let client_config = config.create_client_config();
        assert!(client_config.is_ok());
    }

    #[tokio::test]
    async fn test_server_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true });
        let server_config = config.create_server_config();
        assert!(server_config.is_ok());
    }

    #[tokio::test]
    async fn test_endpoint_configs_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client).allow_any_peer();
        let result = config.create_endpoint_configs();
        assert!(result.is_ok());
        
        let (client_config, server_config) = result.unwrap();
        // Verify both configs were created
        // Additional validation would go here
    }
}