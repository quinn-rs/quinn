// Copyright 2024 Saorsa Labs Limited
//
// Adapter for ant-quic integration

//\! Native ant-quic integration
//\! 
//\! This module provides a direct wrapper around ant-quic functionality,
//\! embracing its peer-oriented architecture for advanced NAT traversal 
//\! and post-quantum cryptography.
//\!
//\! ## Architecture
//\! 
//\! Instead of trying to fit ant-quic into our Transport/Connection abstraction,
//\! we use ant-quic's native peer-oriented model:
//\! - Single `QuicP2PNode` per P2P instance handles all peer connections
//\! - All communication uses `PeerId` instead of socket addresses
//\! - Centralized send/receive through the node
//\! - Built-in NAT traversal, peer discovery, and post-quantum crypto
//\!
//\! This is much simpler and more efficient than trying to bridge between
//\! different architectural paradigms.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// Import ant-quic types
use ant_quic::{QuicP2PNode, QuicNodeConfig};
use ant_quic::nat_traversal_api::{EndpointRole, PeerId};
use ant_quic::auth::AuthConfig;

/// Native ant-quic network node
/// 
/// This provides a clean interface to ant-quic's peer-to-peer networking
/// with advanced NAT traversal and post-quantum cryptography.
pub struct P2PNetworkNode {
    /// The underlying ant-quic node
    pub node: Arc<QuicP2PNode>,
    /// Our local binding address
    pub local_addr: SocketAddr,
    /// Peer registry for tracking connected peers
    pub peers: Arc<RwLock<Vec<(PeerId, SocketAddr)>>>,
}

impl P2PNetworkNode {
    /// Create a new P2P network node
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let config = QuicNodeConfig {
            role: EndpointRole::Client, // Regular P2P node
            bootstrap_nodes: vec\![],    // Bootstrap nodes can be added later
            enable_coordinator: false,  // We don't need a coordinator
            max_connections: 100,       // Reasonable default
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig::default(), // Use ant-quic's default auth
            bind_addr: Some(bind_addr),
        };
        
        Self::new_with_config(bind_addr, config).await
    }

    /// Create a new P2P network node with custom configuration
    pub async fn new_with_config(bind_addr: SocketAddr, mut config: QuicNodeConfig) -> Result<Self> {
        // Ensure bind address is set
        if config.bind_addr.is_none() {
            config.bind_addr = Some(bind_addr);
        }
        
        // Create the ant-quic node
        let node = QuicP2PNode::new(config)
            .await
            .map_err(|e| anyhow::anyhow\!("Failed to create ant-quic node: {}", e))?;
        
        Ok(Self {
            node: Arc::new(node),
            local_addr: bind_addr,
            peers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<PeerId> {
        log::info\!("Connecting to peer at {}", peer_addr);
        
        // Use ant-quic's connect_to_bootstrap for direct socket address connection
        let peer_id = self.node.connect_to_bootstrap(peer_addr)
            .await
            .map_err(|e| anyhow::anyhow\!("Failed to connect to peer: {}", e))?;
        
        // Register the peer
        self.add_peer(peer_id.clone(), peer_addr).await;
        
        log::info\!("Connected to peer {} at {}", peer_id, peer_addr);
        Ok(peer_id)
    }

    /// Accept incoming connections (non-blocking)
    pub async fn accept_connection(&self) -> Result<(PeerId, SocketAddr)> {
        let (addr, peer_id) = self.node.accept()
            .await
            .map_err(|e| anyhow::anyhow\!("Failed to accept connection: {}", e))?;
        
        // Register the peer
        self.add_peer(peer_id.clone(), addr).await;
        
        log::info\!("Accepted connection from peer {} at {}", peer_id, addr);
        Ok((peer_id, addr))
    }

    /// Send data to a specific peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, data: &[u8]) -> Result<()> {
        self.node.send_to_peer(peer_id, data)
            .await
            .map_err(|e| anyhow::anyhow\!("Failed to send to peer {}: {}", peer_id, e))?;
        Ok(())
    }

    /// Receive data from any peer (non-blocking)
    pub async fn receive_from_any_peer(&self) -> Result<(PeerId, Vec<u8>)> {
        self.node.receive()
            .await
            .map_err(|e| anyhow::anyhow\!("Failed to receive data: {}", e))
    }

    /// Get our local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get our peer ID
    pub fn our_peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    /// Get all connected peers
    pub async fn get_connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        self.peers.read().await.clone()
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        self.node.is_peer_authenticated(peer_id).await
    }

    /// Connect to bootstrap nodes to join the network
    pub async fn bootstrap_from_nodes(&self, bootstrap_addrs: &[SocketAddr]) -> Result<Vec<PeerId>> {
        let mut connected_peers = Vec::new();
        
        for &addr in bootstrap_addrs {
            match self.connect_to_peer(addr).await {
                Ok(peer_id) => {
                    connected_peers.push(peer_id);
                    log::info\!("Successfully bootstrapped from {}", addr);
                }
                Err(e) => {
                    log::warn\!("Failed to bootstrap from {}: {}", addr, e);
                }
            }
        }
        
        if connected_peers.is_empty() {
            return Err(anyhow::anyhow\!("Failed to connect to any bootstrap nodes"));
        }
        
        Ok(connected_peers)
    }
    
    /// Internal helper to register a peer
    async fn add_peer(&self, peer_id: PeerId, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        // Avoid duplicates
        if \!peers.iter().any(|(p, _)| *p == peer_id) {
            peers.push((peer_id, addr));
        }
    }
}

/// Convert from our PeerId (String) to ant_quic PeerId
pub fn string_to_ant_peer_id(peer_id: &str) -> ant_quic::nat_traversal_api::PeerId {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(peer_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    ant_quic::nat_traversal_api::PeerId(bytes)
}

/// Convert from ant_quic PeerId to our PeerId (String)
pub fn ant_peer_id_to_string(peer_id: &ant_quic::nat_traversal_api::PeerId) -> String {
    hex::encode(peer_id.0)
}

impl P2PNetworkNode {
    /// Send data to a peer using String PeerId (for compatibility with our P2P core)
    pub async fn send_to_peer_string(&self, peer_id_str: &str, data: &[u8]) -> anyhow::Result<()> {
        let ant_peer_id = string_to_ant_peer_id(peer_id_str);
        self.send_to_peer(&ant_peer_id, data).await
            .map_err(|e| anyhow::anyhow\!("Transport error: {}", e))
    }

    /// Connect to a peer and return String PeerId
    pub async fn connect_to_peer_string(&self, peer_addr: SocketAddr) -> anyhow::Result<String> {
        let ant_peer_id = self.connect_to_peer(peer_addr).await?;
        Ok(ant_peer_id_to_string(&ant_peer_id))
    }
}
EOF < /dev/null