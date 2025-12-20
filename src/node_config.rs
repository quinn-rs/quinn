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

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;

/// Minimal configuration for P2P nodes
///
/// All fields are optional - the node will auto-configure everything.
/// - `bind_addr`: Defaults to `0.0.0.0:0` (random port)
/// - `known_peers`: Defaults to empty (node can still accept connections)
/// - `keypair`: Defaults to fresh generated keypair
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
/// ```
#[derive(Clone)]
pub struct NodeConfig {
    /// Bind address. Default: 0.0.0.0:0 (random port)
    pub bind_addr: Option<SocketAddr>,

    /// Known peers for initial discovery. Default: empty
    /// When empty, node can still accept incoming connections.
    pub known_peers: Vec<SocketAddr>,

    /// Identity keypair. Default: fresh generated
    /// Provide for persistent identity across restarts.
    pub keypair: Option<SigningKey>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            known_peers: Vec::new(),
            keypair: None,
        }
    }
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind_addr", &self.bind_addr)
            .field("known_peers", &self.known_peers)
            .field("keypair", &self.keypair.as_ref().map(|_| "[REDACTED]"))
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
    pub fn with_bind_addr(addr: SocketAddr) -> Self {
        Self {
            bind_addr: Some(addr),
            ..Default::default()
        }
    }

    /// Create config with known peers
    pub fn with_known_peers(peers: Vec<SocketAddr>) -> Self {
        Self {
            known_peers: peers,
            ..Default::default()
        }
    }

    /// Create config with a specific keypair
    pub fn with_keypair(keypair: SigningKey) -> Self {
        Self {
            keypair: Some(keypair),
            ..Default::default()
        }
    }
}

/// Builder for [`NodeConfig`]
#[derive(Default)]
pub struct NodeConfigBuilder {
    bind_addr: Option<SocketAddr>,
    known_peers: Vec<SocketAddr>,
    keypair: Option<SigningKey>,
}

impl NodeConfigBuilder {
    /// Set the bind address
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Add a known peer
    pub fn known_peer(mut self, addr: SocketAddr) -> Self {
        self.known_peers.push(addr);
        self
    }

    /// Add multiple known peers
    pub fn known_peers(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.known_peers.extend(addrs);
        self
    }

    /// Set the identity keypair
    pub fn keypair(mut self, keypair: SigningKey) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Build the configuration
    pub fn build(self) -> NodeConfig {
        NodeConfig {
            bind_addr: self.bind_addr,
            known_peers: self.known_peers,
            keypair: self.keypair,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert!(config.bind_addr.is_none());
        assert!(config.known_peers.is_empty());
        assert!(config.keypair.is_none());
    }

    #[test]
    fn test_builder_with_bind_addr() {
        let addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let config = NodeConfig::builder().bind_addr(addr).build();
        assert_eq!(config.bind_addr, Some(addr));
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
        assert!(config.known_peers.contains(&peer1));
        assert!(config.known_peers.contains(&peer2));
    }

    #[test]
    fn test_builder_with_multiple_peers() {
        let peers: Vec<SocketAddr> = vec![
            "127.0.0.1:9000".parse().unwrap(),
            "127.0.0.1:9001".parse().unwrap(),
        ];

        let config = NodeConfig::builder().known_peers(peers.clone()).build();

        assert_eq!(config.known_peers, peers);
    }

    #[test]
    fn test_with_bind_addr() {
        let addr: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let config = NodeConfig::with_bind_addr(addr);
        assert_eq!(config.bind_addr, Some(addr));
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
        assert_eq!(config.known_peers, peers);
        assert!(config.keypair.is_none());
    }

    #[test]
    fn test_debug_redacts_keypair() {
        use rand::rngs::OsRng;
        let keypair = SigningKey::generate(&mut OsRng);
        let config = NodeConfig::with_keypair(keypair);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&format!("{:?}", config.keypair)));
    }

    #[test]
    fn test_config_is_clone() {
        let config = NodeConfig::builder()
            .bind_addr("0.0.0.0:9000".parse().unwrap())
            .known_peer("127.0.0.1:9001".parse().unwrap())
            .build();

        let cloned = config.clone();
        assert_eq!(config.bind_addr, cloned.bind_addr);
        assert_eq!(config.known_peers, cloned.known_peers);
    }
}
