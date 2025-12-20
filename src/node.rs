// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Zero-configuration P2P node
//!
//! This module provides [`Node`] - the simple API for creating P2P nodes
//! that work out of the box with zero configuration. Every node automatically:
//!
//! - Uses 100% post-quantum cryptography (ML-KEM-768)
//! - Works behind any NAT via native QUIC hole punching
//! - Can act as coordinator/relay if environment allows
//! - Exposes complete observability via [`NodeStatus`]
//!
//! # Zero Configuration
//!
//! ```rust,ignore
//! use ant_quic::Node;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create a node - that's it!
//!     let node = Node::new().await?;
//!
//!     println!("I am: {:?}", node.peer_id());
//!     println!("Listening on: {:?}", node.local_addr());
//!
//!     // Check status
//!     let status = node.status().await;
//!     println!("NAT type: {}", status.nat_type);
//!     println!("Can receive direct: {}", status.can_receive_direct);
//!     println!("Acting as relay: {}", status.is_relaying);
//!
//!     // Connect to a peer
//!     let conn = node.connect_addr("quic.saorsalabs.com:9000".parse()?).await?;
//!
//!     // Accept connections
//!     let incoming = node.accept().await;
//!
//!     Ok(())
//! }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tokio::sync::broadcast;
use tracing::info;

use crate::crypto::raw_public_keys::key_utils::derive_peer_id_from_public_key;
use crate::nat_traversal_api::PeerId;
use crate::node_config::NodeConfig;
use crate::node_event::{DisconnectReason as NodeDisconnectReason, NodeEvent};
use crate::node_status::{NatType, NodeStatus};
use crate::p2p_endpoint::{P2pEndpoint, EndpointError, PeerConnection, P2pEvent, DisconnectReason as P2pDisconnectReason};
use crate::unified_config::P2pConfig;

/// Error type for Node operations
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Failed to create node
    #[error("Failed to create node: {0}")]
    Creation(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Endpoint error
    #[error("Endpoint error: {0}")]
    Endpoint(#[from] EndpointError),

    /// Shutting down
    #[error("Node is shutting down")]
    ShuttingDown,
}

/// Zero-configuration P2P node
///
/// This is the primary API for ant-quic. Create a node with zero configuration
/// and it will automatically handle NAT traversal, post-quantum cryptography,
/// and peer discovery.
///
/// # Symmetric P2P
///
/// All nodes are equal - every node can:
/// - Connect to other nodes
/// - Accept incoming connections
/// - Act as coordinator for NAT traversal
/// - Act as relay for peers behind restrictive NATs
///
/// # Post-Quantum Security
///
/// Every connection uses ML-KEM-768 key exchange with Ed25519 authentication.
/// There is no classical crypto fallback - security is quantum-resistant by default.
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::Node;
///
/// // Zero configuration
/// let node = Node::new().await?;
///
/// // Or with known peers
/// let node = Node::with_peers(vec!["quic.saorsalabs.com:9000".parse()?]).await?;
///
/// // Or with persistent identity
/// let keypair = load_keypair()?;
/// let node = Node::with_keypair(keypair).await?;
/// ```
pub struct Node {
    /// Inner P2pEndpoint
    inner: Arc<P2pEndpoint>,

    /// Start time for uptime calculation
    start_time: Instant,

    /// Event broadcaster for unified events
    event_tx: broadcast::Sender<NodeEvent>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("peer_id", &self.peer_id())
            .field("local_addr", &self.local_addr())
            .finish_non_exhaustive()
    }
}

impl Node {
    // === Creation ===

    /// Create a node with automatic configuration
    ///
    /// This is the recommended way to create a node. It will:
    /// - Bind to a random port on all interfaces (0.0.0.0:0)
    /// - Generate a fresh Ed25519 keypair
    /// - Enable all NAT traversal capabilities
    /// - Use 100% post-quantum cryptography
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::new().await?;
    /// ```
    pub async fn new() -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::default()).await
    }

    /// Create a node with a specific bind address
    ///
    /// Use this when you need a specific port for firewall rules or port forwarding.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::bind("0.0.0.0:9000".parse()?).await?;
    /// ```
    pub async fn bind(addr: SocketAddr) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_bind_addr(addr)).await
    }

    /// Create a node with known peers
    ///
    /// Use this when you have a list of known peers to connect to initially.
    /// These can be any nodes in the network - they'll help with NAT traversal.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::with_peers(vec![
    ///     "quic.saorsalabs.com:9000".parse()?,
    ///     "peer2.example.com:9000".parse()?,
    /// ]).await?;
    /// ```
    pub async fn with_peers(peers: Vec<SocketAddr>) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_known_peers(peers)).await
    }

    /// Create a node with an existing keypair
    ///
    /// Use this for persistent identity across restarts. The peer ID
    /// is derived from the public key, so using the same keypair
    /// gives you the same peer ID.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let keypair = load_keypair_from_file("~/.ant-quic/identity.key")?;
    /// let node = Node::with_keypair(keypair).await?;
    /// ```
    pub async fn with_keypair(keypair: SigningKey) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_keypair(keypair)).await
    }

    /// Create a node with full configuration
    ///
    /// For power users who need specific settings. Most applications
    /// should use `Node::new()` or one of the convenience methods.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::builder()
    ///     .bind_addr("0.0.0.0:9000".parse()?)
    ///     .known_peer("quic.saorsalabs.com:9000".parse()?)
    ///     .keypair(load_keypair()?)
    ///     .build();
    ///
    /// let node = Node::with_config(config).await?;
    /// ```
    pub async fn with_config(config: NodeConfig) -> Result<Self, NodeError> {
        // Convert NodeConfig to P2pConfig
        let mut p2p_config = P2pConfig::default();

        if let Some(bind_addr) = config.bind_addr {
            p2p_config.bind_addr = Some(bind_addr);
        }

        p2p_config.known_peers = config.known_peers;
        p2p_config.keypair = config.keypair;

        // Create event channel
        let (event_tx, _) = broadcast::channel(256);

        // Create P2pEndpoint
        let endpoint = P2pEndpoint::new(p2p_config)
            .await
            .map_err(NodeError::Endpoint)?;

        info!("Node created with peer ID: {:?}", endpoint.peer_id());

        let inner = Arc::new(endpoint);

        // Spawn event bridge task to forward P2pEvent -> NodeEvent
        Self::spawn_event_bridge(Arc::clone(&inner), event_tx.clone());

        Ok(Self {
            inner,
            start_time: Instant::now(),
            event_tx,
        })
    }

    /// Spawn a background task to bridge P2pEvents to NodeEvents
    fn spawn_event_bridge(
        endpoint: Arc<P2pEndpoint>,
        event_tx: broadcast::Sender<NodeEvent>,
    ) {
        let mut p2p_events = endpoint.subscribe();

        tokio::spawn(async move {
            loop {
                match p2p_events.recv().await {
                    Ok(p2p_event) => {
                        if let Some(node_event) = Self::convert_event(p2p_event) {
                            // Ignore send errors - means no subscribers
                            let _ = event_tx.send(node_event);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed, endpoint shutting down
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Subscriber lagged behind, log and continue
                        tracing::warn!("Event bridge lagged by {} events", n);
                    }
                }
            }
        });
    }

    /// Convert a P2pEvent to a NodeEvent
    fn convert_event(p2p_event: P2pEvent) -> Option<NodeEvent> {
        match p2p_event {
            P2pEvent::PeerConnected { peer_id, addr } => {
                Some(NodeEvent::PeerConnected {
                    peer_id,
                    addr,
                    direct: true, // P2pEvent doesn't distinguish, assume direct
                })
            }
            P2pEvent::PeerDisconnected { peer_id, reason } => {
                Some(NodeEvent::PeerDisconnected {
                    peer_id,
                    reason: Self::convert_disconnect_reason(reason),
                })
            }
            P2pEvent::ExternalAddressDiscovered { addr } => {
                Some(NodeEvent::ExternalAddressDiscovered { addr })
            }
            P2pEvent::DataReceived { peer_id, bytes } => {
                Some(NodeEvent::DataReceived {
                    peer_id,
                    stream_id: 0, // P2pEvent doesn't track stream IDs
                    bytes,
                })
            }
            // Events without direct NodeEvent equivalents are ignored
            P2pEvent::NatTraversalProgress { .. } => None,
            P2pEvent::BootstrapStatus { .. } => None,
            P2pEvent::PeerAuthenticated { .. } => None,
        }
    }

    /// Convert P2pDisconnectReason to NodeDisconnectReason
    fn convert_disconnect_reason(p2p_reason: P2pDisconnectReason) -> NodeDisconnectReason {
        match p2p_reason {
            P2pDisconnectReason::Normal => NodeDisconnectReason::Graceful,
            P2pDisconnectReason::Timeout => NodeDisconnectReason::Timeout,
            P2pDisconnectReason::ProtocolError(e) => NodeDisconnectReason::TransportError(e),
            P2pDisconnectReason::AuthenticationFailed => {
                NodeDisconnectReason::TransportError("authentication failed".to_string())
            }
            P2pDisconnectReason::ConnectionLost => NodeDisconnectReason::Reset,
            P2pDisconnectReason::RemoteClosed => NodeDisconnectReason::ApplicationClose,
        }
    }

    // === Identity ===

    /// Get this node's peer ID
    ///
    /// The peer ID is derived from the Ed25519 public key and is
    /// the unique identifier for this node on the network.
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id()
    }

    /// Get the local bind address
    ///
    /// Returns `None` if the endpoint hasn't bound yet.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    /// Get the observed external address
    ///
    /// This is the address as seen by other peers on the network.
    /// Returns `None` if no external address has been discovered yet.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.external_addr()
    }

    /// Get the public key bytes
    ///
    /// Returns the 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.public_key_bytes()
    }

    // === Connections ===

    /// Connect to a peer by address
    ///
    /// This creates a direct connection to the specified address.
    /// NAT traversal is handled automatically if needed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let conn = node.connect_addr("quic.saorsalabs.com:9000".parse()?).await?;
    /// println!("Connected to: {:?}", conn.peer_id);
    /// ```
    pub async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        self.inner
            .connect(addr)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Connect to a peer by ID
    ///
    /// This uses NAT traversal to find and connect to the peer.
    /// A coordinator (known peer) is used to help with hole punching.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let conn = node.connect(peer_id).await?;
    /// ```
    pub async fn connect(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        self.inner
            .connect_to_peer(peer_id, None)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Accept an incoming connection
    ///
    /// Waits for and accepts the next incoming connection.
    /// Returns `None` if the node is shutting down.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// while let Some(conn) = node.accept().await {
    ///     println!("Accepted connection from: {:?}", conn.peer_id);
    ///     // Handle connection...
    /// }
    /// ```
    pub async fn accept(&self) -> Option<PeerConnection> {
        self.inner.accept().await
    }

    /// Add a known peer dynamically
    ///
    /// Known peers help with NAT traversal and peer discovery.
    /// You can add more peers at runtime.
    pub async fn add_peer(&self, addr: SocketAddr) {
        self.inner.add_bootstrap(addr).await;
    }

    /// Connect to all known peers
    ///
    /// Returns the number of successful connections.
    pub async fn connect_known_peers(&self) -> Result<usize, NodeError> {
        self.inner
            .connect_known_peers()
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), NodeError> {
        self.inner
            .disconnect(peer_id)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.inner.connected_peers().await
    }

    /// Check if connected to a peer
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.inner.is_connected(peer_id).await
    }

    // === Messaging ===

    /// Send data to a peer
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.inner
            .send(peer_id, data)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Receive data from any peer
    pub async fn recv(&self, timeout: Duration) -> Result<(PeerId, Vec<u8>), NodeError> {
        self.inner
            .recv(timeout)
            .await
            .map_err(NodeError::Endpoint)
    }

    // === Observability ===

    /// Get a snapshot of the node's current status
    ///
    /// This provides complete visibility into the node's state,
    /// including NAT type, connectivity, relay status, and performance.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = node.status().await;
    /// println!("NAT type: {}", status.nat_type);
    /// println!("Connected peers: {}", status.connected_peers);
    /// println!("Acting as relay: {}", status.is_relaying);
    /// ```
    pub async fn status(&self) -> NodeStatus {
        let stats = self.inner.stats().await;
        let nat_stats = self.inner.nat_stats().ok();
        let connected_peers = self.inner.connected_peers().await;

        // Determine NAT type from stats
        let nat_type = self.detect_nat_type(&stats, nat_stats.as_ref());

        // Check if we have public IP
        let local_addr = self.local_addr();
        let external_addr = self.external_addr();
        let has_public_ip = match (local_addr, external_addr) {
            (Some(local), Some(external)) => {
                // Public if external matches local (ignoring port differences)
                local.ip() == external.ip()
            }
            _ => false,
        };

        // Collect external addresses
        let mut external_addrs = Vec::new();
        if let Some(addr) = external_addr {
            external_addrs.push(addr);
        }

        // Calculate hole punch success rate
        let hole_punch_success_rate = if stats.nat_traversal_attempts > 0 {
            stats.nat_traversal_successes as f64 / stats.nat_traversal_attempts as f64
        } else {
            0.0
        };

        // Determine if we can help with traversal
        let can_receive_direct = has_public_ip
            || nat_type == NatType::FullCone
            || nat_type == NatType::None;

        // Check relay status from NAT stats
        // Currently, relay status is indicated by having relayed_connections > 0
        // and active sessions that may be acting as relays
        let (is_relaying, relay_sessions, relay_bytes_forwarded) =
            if let Some(ref nat) = nat_stats {
                // If we have any active sessions and are accepting connections,
                // we're potentially relaying
                let relaying = nat.relayed_connections > 0 && can_receive_direct;
                (
                    relaying,
                    if relaying { nat.active_sessions } else { 0 },
                    0u64, // Not tracked yet - future enhancement
                )
            } else {
                (false, 0, 0)
            };

        // Check coordination status
        // Any node with active sessions is acting as a coordinator
        let (is_coordinating, coordination_sessions) = if let Some(ref nat) = nat_stats {
            (nat.active_sessions > 0, nat.active_sessions)
        } else {
            (false, 0)
        };

        // Calculate average RTT from connected peers
        let avg_rtt = Duration::ZERO; // TODO: Calculate from connection metrics

        NodeStatus {
            peer_id: self.peer_id(),
            local_addr: local_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            })),
            external_addrs,
            nat_type,
            can_receive_direct,
            has_public_ip,
            connected_peers: connected_peers.len(),
            active_connections: stats.active_connections,
            pending_connections: 0, // Not tracked yet
            direct_connections: stats.direct_connections,
            relayed_connections: stats.relayed_connections,
            hole_punch_success_rate,
            is_relaying,
            relay_sessions,
            relay_bytes_forwarded,
            is_coordinating,
            coordination_sessions,
            avg_rtt,
            uptime: self.start_time.elapsed(),
        }
    }

    /// Subscribe to node events
    ///
    /// Returns a receiver for all significant node events including
    /// connections, disconnections, NAT detection, and relay activity.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut events = node.subscribe();
    /// tokio::spawn(async move {
    ///     while let Ok(event) = events.recv().await {
    ///         match event {
    ///             NodeEvent::PeerConnected { peer_id, .. } => {
    ///                 println!("Connected: {:?}", peer_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    /// });
    /// ```
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to raw P2pEvents (for advanced use)
    ///
    /// This provides access to the underlying P2pEndpoint events.
    /// Most applications should use `subscribe()` for NodeEvents.
    pub fn subscribe_raw(&self) -> broadcast::Receiver<P2pEvent> {
        self.inner.subscribe()
    }

    // === Shutdown ===

    /// Gracefully shut down the node
    ///
    /// This closes all connections and releases resources.
    pub async fn shutdown(self) {
        self.inner.shutdown().await;
    }

    /// Check if the node is still running
    pub fn is_running(&self) -> bool {
        self.inner.is_running()
    }

    // === Private Helpers ===

    /// Detect NAT type from statistics
    fn detect_nat_type(
        &self,
        stats: &crate::p2p_endpoint::EndpointStats,
        nat_stats: Option<&crate::nat_traversal_api::NatTraversalStatistics>,
    ) -> NatType {
        // If we have lots of direct connections and no relayed, likely no/easy NAT
        if stats.direct_connections > 0 && stats.relayed_connections == 0 {
            if let Some(nat) = nat_stats {
                // Calculate direct connection rate
                let total = nat.direct_connections + nat.relayed_connections;
                if total > 0 {
                    let direct_rate = nat.direct_connections as f64 / total as f64;
                    if direct_rate > 0.9 {
                        return NatType::FullCone;
                    }
                }
            }
            return NatType::FullCone; // Assume easy NAT if all direct
        }

        // If we have mixed connections, harder NAT
        if stats.direct_connections > 0 && stats.relayed_connections > 0 {
            if let Some(nat) = nat_stats {
                // Calculate success rate from total attempts vs successful connections
                let success_rate = if nat.total_attempts > 0 {
                    nat.successful_connections as f64 / nat.total_attempts as f64
                } else {
                    0.0
                };

                if success_rate > 0.7 {
                    return NatType::PortRestricted;
                } else if success_rate > 0.3 {
                    return NatType::AddressRestricted;
                }
            }
            return NatType::PortRestricted;
        }

        // If mostly relayed, likely symmetric NAT
        if stats.relayed_connections > stats.direct_connections {
            return NatType::Symmetric;
        }

        // Not enough data yet
        NatType::Unknown
    }
}

// Enable cloning through Arc
impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            start_time: self.start_time,
            event_tx: self.event_tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_new_default() {
        let node = Node::new().await;
        assert!(node.is_ok(), "Node::new() should succeed");

        let node = node.unwrap();
        assert!(node.is_running());

        // Peer ID should be valid (non-zero)
        let peer_id = node.peer_id();
        assert_ne!(peer_id.0, [0u8; 32]);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_bind() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = Node::bind(addr).await;
        assert!(node.is_ok(), "Node::bind() should succeed");

        let node = node.unwrap();
        assert!(node.local_addr().is_some());

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_peers() {
        let peers = vec!["127.0.0.1:9000".parse().unwrap()];
        let node = Node::with_peers(peers).await;
        assert!(node.is_ok(), "Node::with_peers() should succeed");

        node.unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_config() {
        let config = NodeConfig::builder()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .build();

        let node = Node::with_config(config).await;
        assert!(node.is_ok(), "Node::with_config() should succeed");

        node.unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status() {
        let node = Node::new().await.unwrap();
        let status = node.status().await;

        // Check status fields are populated
        assert_ne!(status.peer_id.0, [0u8; 32]);
        assert_eq!(status.connected_peers, 0); // No connections yet

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_subscribe() {
        let node = Node::new().await.unwrap();
        let _events = node.subscribe();

        // Just verify subscription works
        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_is_clone() {
        let node1 = Node::new().await.unwrap();
        let node2 = node1.clone();

        // Both should have same peer ID
        assert_eq!(node1.peer_id(), node2.peer_id());

        node1.shutdown().await;
        // node2 still references the same Arc, so shutdown already happened
    }

    #[tokio::test]
    async fn test_node_debug() {
        let node = Node::new().await.unwrap();
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("Node"));
        assert!(debug_str.contains("peer_id"));

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_identity() {
        let node = Node::new().await.unwrap();

        // Verify identity methods
        let peer_id = node.peer_id();
        let public_key = node.public_key_bytes();

        // Peer ID should be derived from public key
        let derived = derive_peer_id_from_public_key(&ed25519_dalek::VerifyingKey::from_bytes(
            &public_key,
        ).unwrap());
        assert_eq!(peer_id, derived);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_connected_peers_empty() {
        let node = Node::new().await.unwrap();
        let peers = node.connected_peers().await;
        assert!(peers.is_empty());

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_error_types() {
        // Test error conversions
        let err = NodeError::Creation("test".to_string());
        assert!(err.to_string().contains("test"));

        let err = NodeError::Connection("connection failed".to_string());
        assert!(err.to_string().contains("connection"));

        let err = NodeError::ShuttingDown;
        assert!(err.to_string().contains("shutting down"));
    }

    #[tokio::test]
    async fn test_node_with_keypair_persistence() {
        // Generate a keypair
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);
        let expected_public_key = keypair.verifying_key();
        let expected_peer_id = derive_peer_id_from_public_key(&expected_public_key);

        // Create node with the keypair
        let node = Node::with_keypair(keypair).await.unwrap();

        // Verify the node uses the same identity
        assert_eq!(node.peer_id(), expected_peer_id);
        assert_eq!(node.public_key_bytes(), expected_public_key.to_bytes());

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_keypair_via_config() {
        // Generate a keypair
        let keypair = SigningKey::generate(&mut rand::rngs::OsRng);
        let expected_public_key = keypair.verifying_key();
        let expected_peer_id = derive_peer_id_from_public_key(&expected_public_key);

        // Create node via config with keypair
        let config = NodeConfig::with_keypair(keypair);
        let node = Node::with_config(config).await.unwrap();

        // Verify the node uses the same identity
        assert_eq!(node.peer_id(), expected_peer_id);
        assert_eq!(node.public_key_bytes(), expected_public_key.to_bytes());

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_event_bridge_exists() {
        let node = Node::new().await.unwrap();

        // Subscribe to events - this should work
        let mut events = node.subscribe();

        // The event channel should be connected (won't receive anything yet,
        // but the bridge task should be running)
        // We can't easily test event reception without connections,
        // but we verify the infrastructure is in place
        assert!(events.try_recv().is_err()); // No events yet

        node.shutdown().await;
    }
}
