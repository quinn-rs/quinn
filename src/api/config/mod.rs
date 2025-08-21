// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Configuration module for ant-quic
//!
//! This module provides a clean, builder-based configuration API for the ant-quic library.
//! It includes validation for configuration options and sensible defaults.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

use crate::nat_traversal::{BootstrapNode, NatTraversalConfig};
use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};

mod validation;

/// Configuration errors with detailed context
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid bootstrap node configuration: {0}")]
    InvalidBootstrapNode(String),

    #[error("Invalid network configuration: {0}")]
    InvalidNetwork(String),

    #[error("Invalid timeout configuration: {0}")]
    InvalidTimeout(String),

    #[error("Invalid role configuration: {0}")]
    InvalidRole(String),

    #[error("Missing required configuration: {0}")]
    MissingRequiredConfig(String),

    #[error("Configuration value out of range: {0}")]
    ValueOutOfRange(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Platform-specific configuration error: {0}")]
    PlatformSpecific(String),
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;

/// P2P configuration
///
/// This struct contains all configuration options for a P2P node.
/// Use the builder pattern via `P2PConfig::builder()` to create a configuration.
///
/// # Example
///
/// ```
/// use ant_quic::api::config::P2PConfig;
/// use ant_quic::crypto::raw_public_keys::key_utils;
/// use ant_quic::nat_traversal::BootstrapNode;
/// use std::net::SocketAddr;
///
/// let bootstrap_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
/// let config = P2PConfig::builder()
///     .with_bootstrap_nodes(vec![BootstrapNode::new(bootstrap_addr)])
///     .with_keypair(key_utils::generate_ed25519_keypair())
///     .with_nat_traversal(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct P2PConfig {
    /// Bootstrap nodes for NAT traversal
    pub(crate) bootstrap_nodes: Vec<BootstrapNode>,

    /// Keypair for authentication
    pub(crate) keypair: (Ed25519SecretKey, Ed25519PublicKey),

    /// Enable NAT traversal
    pub(crate) nat_traversal_enabled: bool,

    /// Listen address
    pub(crate) listen_address: SocketAddr,

    /// Connection timeout
    pub(crate) connection_timeout: Duration,

    /// Maximum number of connection attempts
    pub(crate) max_connection_attempts: u32,

    /// Maximum number of concurrent connections
    pub(crate) max_concurrent_connections: u32,

    /// Advanced NAT traversal configuration
    pub(crate) nat_traversal_config: Option<NatTraversalConfig>,
}

impl P2PConfig {
    /// Create a new configuration builder
    ///
    /// # Example
    ///
    /// ```
    /// use ant_quic::api::config::P2PConfig;
    ///
    /// let builder = P2PConfig::builder();
    /// ```
    pub fn builder() -> P2PConfigBuilder {
        P2PConfigBuilder::new()
    }

    /// Get the bootstrap nodes
    pub fn bootstrap_nodes(&self) -> &[BootstrapNode] {
        &self.bootstrap_nodes
    }

    /// Get the keypair
    pub fn keypair(&self) -> &(Ed25519SecretKey, Ed25519PublicKey) {
        &self.keypair
    }

    /// Check if NAT traversal is enabled
    pub fn nat_traversal_enabled(&self) -> bool {
        self.nat_traversal_enabled
    }

    /// Get the listen address
    pub fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    /// Get the connection timeout
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Get the maximum number of connection attempts
    pub fn max_connection_attempts(&self) -> u32 {
        self.max_connection_attempts
    }

    /// Get the maximum number of concurrent connections
    pub fn max_concurrent_connections(&self) -> u32 {
        self.max_concurrent_connections
    }

    /// Get the advanced NAT traversal configuration
    pub fn nat_traversal_config(&self) -> Option<&NatTraversalConfig> {
        self.nat_traversal_config.as_ref()
    }
}

/// Builder for P2PConfig
///
/// This builder provides a fluent API for creating a P2PConfig.
///
/// # Example
///
/// ```
/// use ant_quic::api::config::P2PConfigBuilder;
/// use ant_quic::crypto::raw_public_keys::key_utils;
/// use ant_quic::nat_traversal::BootstrapNode;
/// use std::net::SocketAddr;
///
/// let bootstrap_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
/// let config = P2PConfigBuilder::new()
///     .with_bootstrap_nodes(vec![BootstrapNode::new(bootstrap_addr)])
///     .with_keypair(key_utils::generate_ed25519_keypair())
///     .with_nat_traversal(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct P2PConfigBuilder {
    bootstrap_nodes: Vec<BootstrapNode>,
    keypair: Option<(Ed25519SecretKey, Ed25519PublicKey)>,
    nat_traversal_enabled: bool,
    listen_address: Option<SocketAddr>,
    connection_timeout: Duration,
    max_connection_attempts: u32,
    max_concurrent_connections: u32,
    nat_traversal_config: Option<NatTraversalConfig>,
}

impl P2PConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            keypair: None,
            nat_traversal_enabled: true,
            listen_address: None,
            connection_timeout: Duration::from_secs(30),
            max_connection_attempts: 3,
            max_concurrent_connections: 100,
            nat_traversal_config: None,
        }
    }

    /// Set the bootstrap nodes
    ///
    /// Bootstrap nodes are used for NAT traversal coordination.
    /// At least one bootstrap node is required if NAT traversal is enabled.
    pub fn with_bootstrap_nodes<T: Into<Vec<BootstrapNode>>>(&mut self, nodes: T) -> &mut Self {
        self.bootstrap_nodes = nodes.into();
        self
    }

    /// Add a bootstrap node
    pub fn add_bootstrap_node(&mut self, node: BootstrapNode) -> &mut Self {
        self.bootstrap_nodes.push(node);
        self
    }

    /// Set the keypair for authentication
    pub fn with_keypair(&mut self, keypair: (Ed25519SecretKey, Ed25519PublicKey)) -> &mut Self {
        self.keypair = Some(keypair);
        self
    }

    /// Enable or disable NAT traversal
    pub fn with_nat_traversal(&mut self, enabled: bool) -> &mut Self {
        self.nat_traversal_enabled = enabled;
        self
    }

    /// Set the listen address
    pub fn with_listen_address(&mut self, address: SocketAddr) -> &mut Self {
        self.listen_address = Some(address);
        self
    }

    /// Set the connection timeout
    pub fn with_connection_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.connection_timeout = timeout;
        self
    }

    /// Set the maximum number of connection attempts
    pub fn with_max_connection_attempts(&mut self, attempts: u32) -> &mut Self {
        self.max_connection_attempts = attempts;
        self
    }

    /// Set the maximum number of concurrent connections
    pub fn with_max_concurrent_connections(&mut self, connections: u32) -> &mut Self {
        self.max_concurrent_connections = connections;
        self
    }

    /// Set advanced NAT traversal configuration
    pub fn with_nat_traversal_config(&mut self, config: NatTraversalConfig) -> &mut Self {
        self.nat_traversal_config = Some(config);
        self
    }

    /// Build the configuration
    ///
    /// This method validates the configuration and returns a `P2PConfig` if valid.
    /// If the configuration is invalid, it returns a `ConfigError`.
    pub fn build(&self) -> ConfigResult<P2PConfig> {
        // Validate bootstrap nodes if NAT traversal is enabled
        if self.nat_traversal_enabled && self.bootstrap_nodes.is_empty() {
            return Err(ConfigError::MissingRequiredConfig(
                "At least one bootstrap node is required when NAT traversal is enabled".to_string(),
            ));
        }

        // Check for duplicate bootstrap nodes
        let mut seen = HashSet::new();
        for (i, node) in self.bootstrap_nodes.iter().enumerate() {
            if !seen.insert(node.address) {
                return Err(ConfigError::InvalidBootstrapNode(format!(
                    "Duplicate bootstrap node at index {}: {}",
                    i, node.address
                )));
            }
        }

        // Validate keypair
        let keypair = self
            .keypair
            .clone()
            .ok_or_else(|| ConfigError::MissingRequiredConfig("Keypair is required".to_string()))?;

        // Validate listen address
        let listen_address = self.listen_address.unwrap_or_else(|| {
            // Default to a random port on all interfaces
            "0.0.0.0:0".parse().unwrap()
        });

        // Validate connection timeout
        if self.connection_timeout < Duration::from_secs(1)
            || self.connection_timeout > Duration::from_secs(300)
        {
            return Err(ConfigError::ValueOutOfRange(format!(
                "Connection timeout must be between 1 and 300 seconds, got {:?}",
                self.connection_timeout
            )));
        }

        // Validate max connection attempts
        if self.max_connection_attempts == 0 || self.max_connection_attempts > 10 {
            return Err(ConfigError::ValueOutOfRange(format!(
                "Maximum connection attempts must be between 1 and 10, got {}",
                self.max_connection_attempts
            )));
        }

        // Validate max concurrent connections
        if self.max_concurrent_connections == 0 || self.max_concurrent_connections > 1000 {
            return Err(ConfigError::ValueOutOfRange(format!(
                "Maximum concurrent connections must be between 1 and 1000, got {}",
                self.max_concurrent_connections
            )));
        }

        // Create the configuration
        Ok(P2PConfig {
            bootstrap_nodes: self.bootstrap_nodes.clone(),
            keypair,
            nat_traversal_enabled: self.nat_traversal_enabled,
            listen_address,
            connection_timeout: self.connection_timeout,
            max_connection_attempts: self.max_connection_attempts,
            max_concurrent_connections: self.max_concurrent_connections,
            nat_traversal_config: self.nat_traversal_config.clone(),
        })
    }
}

impl Default for P2PConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::raw_public_keys::key_utils;
    use crate::nat_traversal::BootstrapNode;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_builder_with_valid_config() {
        let keypair = key_utils::generate_ed25519_keypair();
        let bootstrap_node = BootstrapNode::new("127.0.0.1:9000".parse().unwrap());

        let config = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .add_bootstrap_node(bootstrap_node)
            .with_nat_traversal(true)
            .with_listen_address(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8000,
            ))
            .with_connection_timeout(Duration::from_secs(60))
            .build()
            .unwrap();

        assert_eq!(config.bootstrap_nodes.len(), 1);
        assert_eq!(
            config.bootstrap_nodes[0].address.to_string(),
            "127.0.0.1:9000"
        );
        assert!(config.nat_traversal_enabled);
        assert_eq!(config.listen_address.to_string(), "127.0.0.1:8000");
        assert_eq!(config.connection_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_builder_missing_keypair() {
        let bootstrap_node = BootstrapNode::new("127.0.0.1:9000".parse().unwrap());

        let result = P2PConfigBuilder::new()
            .add_bootstrap_node(bootstrap_node)
            .with_nat_traversal(true)
            .build();

        assert!(result.is_err());
        match result {
            Err(ConfigError::MissingRequiredConfig(msg)) => {
                assert!(msg.contains("Keypair is required"));
            }
            _ => panic!("Expected MissingRequiredConfig error"),
        }
    }

    #[test]
    fn test_builder_missing_bootstrap_nodes() {
        let keypair = key_utils::generate_ed25519_keypair();

        let result = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .with_nat_traversal(true)
            .build();

        assert!(result.is_err());
        match result {
            Err(ConfigError::MissingRequiredConfig(msg)) => {
                assert!(msg.contains("bootstrap node"));
            }
            _ => panic!("Expected MissingRequiredConfig error"),
        }
    }

    #[test]
    fn test_builder_duplicate_bootstrap_nodes() {
        let keypair = key_utils::generate_ed25519_keypair();
        let addr = "127.0.0.1:9000".parse().unwrap();
        let bootstrap_node1 = BootstrapNode::new(addr);
        let bootstrap_node2 = BootstrapNode::new(addr);

        let result = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .add_bootstrap_node(bootstrap_node1)
            .add_bootstrap_node(bootstrap_node2)
            .build();

        assert!(result.is_err());
        match result {
            Err(ConfigError::InvalidBootstrapNode(msg)) => {
                assert!(msg.contains("Duplicate bootstrap node"));
            }
            _ => panic!("Expected InvalidBootstrapNode error"),
        }
    }

    #[test]
    fn test_builder_invalid_connection_timeout() {
        let keypair = key_utils::generate_ed25519_keypair();
        let bootstrap_node = BootstrapNode::new("127.0.0.1:9000".parse().unwrap());

        let result = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .add_bootstrap_node(bootstrap_node)
            .with_connection_timeout(Duration::from_millis(500))
            .build();

        assert!(result.is_err());
        match result {
            Err(ConfigError::ValueOutOfRange(msg)) => {
                assert!(msg.contains("Connection timeout"));
            }
            _ => panic!("Expected ValueOutOfRange error"),
        }
    }

    #[test]
    fn test_builder_nat_traversal_disabled() {
        let keypair = key_utils::generate_ed25519_keypair();

        let config = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .with_nat_traversal(false)
            .build()
            .unwrap();

        assert!(!config.nat_traversal_enabled);
        assert_eq!(config.bootstrap_nodes.len(), 0);
    }

    #[test]
    fn test_config_getters() {
        let keypair = key_utils::generate_ed25519_keypair();
        let bootstrap_node = BootstrapNode::new("127.0.0.1:9000".parse().unwrap());
        let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        let timeout = Duration::from_secs(60);

        let config = P2PConfigBuilder::new()
            .with_keypair(keypair)
            .add_bootstrap_node(bootstrap_node)
            .with_listen_address(listen_address)
            .with_connection_timeout(timeout)
            .with_max_connection_attempts(5)
            .with_max_concurrent_connections(200)
            .build()
            .unwrap();

        assert_eq!(config.bootstrap_nodes().len(), 1);
        assert_eq!(config.listen_address(), listen_address);
        assert_eq!(config.connection_timeout(), timeout);
        assert_eq!(config.max_connection_attempts(), 5);
        assert_eq!(config.max_concurrent_connections(), 200);
    }
}
