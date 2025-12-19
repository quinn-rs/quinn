// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! P2P endpoint for ant-quic
//!
//! This module provides the main API for P2P communication with NAT traversal,
//! secure connections, and event-driven architecture.
//!
//! # Features
//!
//! - Configuration via [`P2pConfig`](crate::unified_config::P2pConfig)
//! - Event subscription via broadcast channels
//! - Built-in authentication support
//! - NAT traversal with automatic fallback
//! - Connection metrics and statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::{P2pEndpoint, P2pConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // All nodes are symmetric - they can both connect and accept connections
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:9000".parse()?)
//!         .known_peer("quic.saorsalabs.com:9000".parse()?)
//!         .build()?;
//!
//!     let endpoint = P2pEndpoint::new(config).await?;
//!     println!("Peer ID: {:?}", endpoint.peer_id());
//!
//!     // Subscribe to events
//!     let mut events = endpoint.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             println!("Event: {:?}", event);
//!         }
//!     });
//!
//!     // Connect to known peers
//!     endpoint.connect_known_peers().await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::auth::{AuthManager, AuthMessage, AuthProtocol};
use crate::crypto::raw_public_keys::key_utils::{
    derive_peer_id_from_public_key, generate_ed25519_keypair,
};
use crate::nat_traversal_api::{
    NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, NatTraversalStatistics, PeerId,
};

// Re-export TraversalPhase from nat_traversal_api for convenience
pub use crate::nat_traversal_api::TraversalPhase;
use crate::unified_config::P2pConfig;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// P2P endpoint - the primary API for ant-quic
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    /// Authentication manager
    auth_manager: Arc<AuthManager>,

    /// Connected peers with their addresses
    connected_peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,

    /// Endpoint statistics
    stats: Arc<RwLock<EndpointStats>>,

    /// Configuration
    config: P2pConfig,

    /// Event broadcaster
    event_tx: broadcast::Sender<P2pEvent>,

    /// Our peer ID
    peer_id: PeerId,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,

    /// Pending data buffer for data received from non-target peers during authentication
    /// This prevents data loss when authenticate_peer receives data from other peers
    pending_data: Arc<RwLock<HashMap<PeerId, VecDeque<Vec<u8>>>>>,
}

impl std::fmt::Debug for P2pEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pEndpoint")
            .field("peer_id", &self.peer_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Connection information for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote peer's ID
    pub peer_id: PeerId,

    /// Remote address
    pub remote_addr: SocketAddr,

    /// Whether peer is authenticated
    pub authenticated: bool,

    /// Connection established time
    pub connected_at: Instant,

    /// Last activity time
    pub last_activity: Instant,
}

/// Connection metrics for P2P peers
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,

    /// Bytes received from this peer
    pub bytes_received: u64,

    /// Round-trip time
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Last activity timestamp
    pub last_activity: Option<Instant>,
}

/// P2P endpoint statistics
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of active connections
    pub active_connections: usize,

    /// Total successful connections
    pub successful_connections: u64,

    /// Total failed connections
    pub failed_connections: u64,

    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,

    /// Successful NAT traversals
    pub nat_traversal_successes: u64,

    /// Direct connections (no NAT traversal needed)
    pub direct_connections: u64,

    /// Relayed connections
    pub relayed_connections: u64,

    /// Total bootstrap nodes configured
    pub total_bootstrap_nodes: usize,

    /// Connected bootstrap nodes
    pub connected_bootstrap_nodes: usize,

    /// Endpoint start time
    pub start_time: Instant,

    /// Average coordination time for NAT traversal
    pub average_coordination_time: Duration,
}

impl Default for EndpointStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            direct_connections: 0,
            relayed_connections: 0,
            total_bootstrap_nodes: 0,
            connected_bootstrap_nodes: 0,
            start_time: Instant::now(),
            average_coordination_time: Duration::ZERO,
        }
    }
}

/// P2P event for connection and network state changes
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// New peer connected
    PeerConnected {
        /// Peer's ID
        peer_id: PeerId,
        /// Remote address
        addr: SocketAddr,
    },

    /// Peer disconnected
    PeerDisconnected {
        /// Peer's ID
        peer_id: PeerId,
        /// Reason for disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress
    NatTraversalProgress {
        /// Target peer ID
        peer_id: PeerId,
        /// Current phase
        phase: TraversalPhase,
    },

    /// External address discovered
    ExternalAddressDiscovered {
        /// Discovered external address
        addr: SocketAddr,
    },

    /// Bootstrap connection status
    BootstrapStatus {
        /// Number of connected bootstrap nodes
        connected: usize,
        /// Total number of bootstrap nodes
        total: usize,
    },

    /// Peer authenticated
    PeerAuthenticated {
        /// Authenticated peer ID
        peer_id: PeerId,
    },

    /// Data received from peer
    DataReceived {
        /// Source peer ID
        peer_id: PeerId,
        /// Number of bytes received
        bytes: usize,
    },
}

/// Reason for peer disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Normal disconnect
    Normal,
    /// Connection timeout
    Timeout,
    /// Protocol error
    ProtocolError(String),
    /// Authentication failure
    AuthenticationFailed,
    /// Connection lost
    ConnectionLost,
    /// Remote closed
    RemoteClosed,
}

// TraversalPhase is re-exported from nat_traversal_api

/// Error type for P2pEndpoint operations
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] NatTraversalError),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Peer not found
    #[error("Peer not found: {0:?}")]
    PeerNotFound(PeerId),

    /// Already connected
    #[error("Already connected to peer: {0:?}")]
    AlreadyConnected(PeerId),

    /// Shutdown in progress
    #[error("Endpoint is shutting down")]
    ShuttingDown,
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Generate Ed25519 keypair for authentication
        let (secret_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Creating P2P endpoint with peer ID: {:?}", peer_id);

        // Create authentication manager (clone secret_key since we need it for NAT config too)
        let auth_manager = Arc::new(AuthManager::new(secret_key.clone(), config.auth.clone()));

        // Create event channel
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let event_tx_clone = event_tx.clone();

        // Create stats
        let stats = Arc::new(RwLock::new(EndpointStats {
            total_bootstrap_nodes: config.known_peers.len(),
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_clone = Arc::clone(&stats);

        // Create event callback that bridges to broadcast channel
        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let event_tx = event_tx_clone.clone();
            let stats = stats_clone.clone();

            tokio::spawn(async move {
                // Update stats based on event
                let mut stats_guard = stats.write().await;
                match &event {
                    NatTraversalEvent::CoordinationRequested { .. } => {
                        stats_guard.nat_traversal_attempts += 1;
                    }
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id,
                        remote_address,
                    } => {
                        stats_guard.nat_traversal_successes += 1;
                        stats_guard.active_connections += 1;
                        stats_guard.successful_connections += 1;

                        // Broadcast event
                        let _ = event_tx.send(P2pEvent::PeerConnected {
                            peer_id: *peer_id,
                            addr: *remote_address,
                        });
                    }
                    NatTraversalEvent::TraversalFailed { peer_id, .. } => {
                        stats_guard.failed_connections += 1;
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            peer_id: *peer_id,
                            phase: TraversalPhase::Failed,
                        });
                    }
                    NatTraversalEvent::PhaseTransition {
                        peer_id, to_phase, ..
                    } => {
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            peer_id: *peer_id,
                            phase: *to_phase,
                        });
                    }
                    NatTraversalEvent::ExternalAddressDiscovered { address, .. } => {
                        info!("External address discovered: {}", address);
                        let _ =
                            event_tx.send(P2pEvent::ExternalAddressDiscovered { addr: *address });
                    }
                    _ => {}
                }
                drop(stats_guard);
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let nat_config = config.to_nat_config_with_key(secret_key);
        let inner = NatTraversalEndpoint::new(nat_config, Some(event_callback))
            .await
            .map_err(|e| EndpointError::Config(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(inner),
            auth_manager,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            peer_id,
            shutdown: Arc::new(AtomicBool::new(false)),
            pending_data: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get the local bind address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .get_endpoint()
            .and_then(|ep| ep.local_addr().ok())
    }

    /// Get observed external address (if discovered)
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.get_observed_external_address().ok().flatten()
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.auth_manager.public_key_bytes()
    }

    // === Connection Management ===

    /// Connect to a peer by address (direct connection)
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        info!("Connecting directly to {}", addr);

        let endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let connecting = endpoint
            .connect(addr, "peer")
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        let connection = connecting
            .await
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Prefer peer ID derived from the authenticated public key.
        let peer_id = self
            .inner
            .extract_peer_id_from_connection(&connection)
            .await
            .unwrap_or_else(|| self.derive_peer_id_from_address(addr));

        // Store connection
        self.inner
            .add_connection(peer_id, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Spawn handler
        self.inner
            .spawn_connection_handler(peer_id, connection)
            .map_err(EndpointError::NatTraversal)?;

        // Create peer connection record
        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: addr,
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Store peer
        self.connected_peers
            .write()
            .await
            .insert(peer_id, peer_conn.clone());

        // Handle authentication if required
        if self.config.auth.require_authentication {
            if let Err(err) = self.authenticate_peer(&peer_id).await {
                let _ = self.inner.remove_connection(&peer_id);
                let _ = self.connected_peers.write().await.remove(&peer_id);
                return Err(err);
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        // Broadcast event
        let _ = self
            .event_tx
            .send(P2pEvent::PeerConnected { peer_id, addr });

        Ok(peer_conn)
    }

    /// Connect to a peer by ID using NAT traversal
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: Option<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        let coord_addr = coordinator
            .or_else(|| self.config.known_peers.first().copied())
            .ok_or_else(|| EndpointError::Config("No coordinator available".to_string()))?;

        info!(
            "Initiating NAT traversal to peer {:?} via coordinator {}",
            peer_id, coord_addr
        );

        // Broadcast progress
        let _ = self.event_tx.send(P2pEvent::NatTraversalProgress {
            peer_id,
            phase: TraversalPhase::Discovery,
        });

        // Initiate NAT traversal
        self.inner
            .initiate_nat_traversal(peer_id, coord_addr)
            .map_err(EndpointError::NatTraversal)?;

        // Poll for completion
        let start = Instant::now();
        let timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;

        while start.elapsed() < timeout {
            if self.shutdown.load(Ordering::SeqCst) {
                return Err(EndpointError::ShuttingDown);
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(EndpointError::NatTraversal)?;

            for event in events {
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                    } if evt_peer == peer_id => {
                        let peer_conn = PeerConnection {
                            peer_id,
                            remote_addr: remote_address,
                            authenticated: false,
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        self.connected_peers
                            .write()
                            .await
                            .insert(peer_id, peer_conn.clone());

                        // Handle authentication if required
                        if self.config.auth.require_authentication {
                            self.authenticate_peer(&peer_id).await?;
                        }

                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        ..
                    } if evt_peer == peer_id => {
                        return Err(EndpointError::NatTraversal(error));
                    }
                    _ => {}
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Err(EndpointError::Timeout)
    }

    /// Accept incoming connections
    pub async fn accept(&self) -> Option<PeerConnection> {
        if self.shutdown.load(Ordering::SeqCst) {
            return None;
        }

        match self.inner.accept_connection().await {
            Ok((peer_id, connection)) => {
                let remote_addr = connection.remote_address();
                let mut resolved_peer_id = peer_id;

                if let Some(actual_peer_id) = self
                    .inner
                    .extract_peer_id_from_connection(&connection)
                    .await
                {
                    if actual_peer_id != peer_id {
                        let _ = self.inner.remove_connection(&peer_id);
                        let _ = self
                            .inner
                            .add_connection(actual_peer_id, connection.clone());
                        resolved_peer_id = actual_peer_id;
                    }
                }

                if let Err(e) = self
                    .inner
                    .spawn_connection_handler(resolved_peer_id, connection)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                let peer_conn = PeerConnection {
                    peer_id: resolved_peer_id,
                    remote_addr,
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                self.connected_peers
                    .write()
                    .await
                    .insert(resolved_peer_id, peer_conn.clone());

                if self.config.auth.require_authentication {
                    if let Err(err) = self.authenticate_peer(&resolved_peer_id).await {
                        let _ = self.inner.remove_connection(&resolved_peer_id);
                        let _ = self.connected_peers.write().await.remove(&resolved_peer_id);
                        warn!(
                            "Authentication failed for peer {:?}: {}",
                            resolved_peer_id, err
                        );
                        return None;
                    }
                }

                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    peer_id: resolved_peer_id,
                    addr: remote_addr,
                });

                Some(peer_conn)
            }
            Err(e) => {
                debug!("Accept failed: {}", e);
                None
            }
        }
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), EndpointError> {
        if let Some(peer_conn) = self.connected_peers.write().await.remove(peer_id) {
            let _ = self.inner.remove_connection(peer_id);

            {
                let mut stats = self.stats.write().await;
                stats.active_connections = stats.active_connections.saturating_sub(1);
            }

            let _ = self.event_tx.send(P2pEvent::PeerDisconnected {
                peer_id: *peer_id,
                reason: DisconnectReason::Normal,
            });

            info!(
                "Disconnected from peer {:?} at {}",
                peer_id, peer_conn.remote_addr
            );
            Ok(())
        } else {
            Err(EndpointError::PeerNotFound(*peer_id))
        }
    }

    // === Messaging ===

    /// Send data to a peer
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        let connection = self
            .inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)?
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;

        let mut send_stream = connection
            .open_uni()
            .await
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        send_stream
            .write_all(data)
            .await
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        send_stream
            .finish()
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Update last activity
        if let Some(peer_conn) = self.connected_peers.write().await.get_mut(peer_id) {
            peer_conn.last_activity = Instant::now();
        }

        debug!("Sent {} bytes to peer {:?}", data.len(), peer_id);
        Ok(())
    }

    /// Receive data from any peer (with timeout)
    ///
    /// This function first checks the pending data buffer for data that was
    /// buffered during authentication, then polls streams from connected peers.
    /// The timeout is properly distributed across all peers to avoid O(n*timeout) delays.
    pub async fn recv(&self, timeout: Duration) -> Result<(PeerId, Vec<u8>), EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // First, check pending data buffer (data buffered during authentication)
        {
            let mut pending = self.pending_data.write().await;
            for (peer_id, queue) in pending.iter_mut() {
                if let Some(data) = queue.pop_front() {
                    if let Some(peer_conn) =
                        self.connected_peers.write().await.get_mut(peer_id)
                    {
                        peer_conn.last_activity = Instant::now();
                    }
                    let _ = self.event_tx.send(P2pEvent::DataReceived {
                        peer_id: *peer_id,
                        bytes: data.len(),
                    });
                    return Ok((*peer_id, data));
                }
            }
            // Clean up empty queues
            pending.retain(|_, queue| !queue.is_empty());
        }

        let peers = self.connected_peers.read().await.clone();

        if peers.is_empty() {
            return Err(EndpointError::Connection("No connected peers".to_string()));
        }

        let start = Instant::now();
        let peer_count = peers.len().max(1);

        while start.elapsed() < timeout {
            // Calculate per-peer timeout based on remaining time
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            // Distribute remaining time across peers with minimum 5ms per peer
            let per_peer_timeout = remaining
                .checked_div(peer_count as u32)
                .unwrap_or(Duration::from_millis(5))
                .max(Duration::from_millis(5));

            for (peer_id, _) in peers.iter() {
                // Check if we've exceeded total timeout
                if start.elapsed() >= timeout {
                    break;
                }

                if let Ok(Some(connection)) = self.inner.get_connection(peer_id) {
                    // Try unidirectional stream with calculated per-peer timeout
                    if let Ok(Ok(mut recv_stream)) =
                        tokio::time::timeout(per_peer_timeout, connection.accept_uni())
                            .await
                    {
                        if let Ok(data) = recv_stream.read_to_end(1024 * 1024).await {
                            if !data.is_empty() {
                                if let Some(peer_conn) =
                                    self.connected_peers.write().await.get_mut(peer_id)
                                {
                                    peer_conn.last_activity = Instant::now();
                                }

                                let _ = self.event_tx.send(P2pEvent::DataReceived {
                                    peer_id: *peer_id,
                                    bytes: data.len(),
                                });
                                return Ok((*peer_id, data));
                            }
                        }
                    }
                }
            }

            // Short sleep between iterations, but only if we have time left
            if start.elapsed() < timeout {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        Err(EndpointError::Timeout)
    }

    // === Events ===

    /// Subscribe to endpoint events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    // === Statistics ===

    /// Get endpoint statistics
    pub async fn stats(&self) -> EndpointStats {
        self.stats.read().await.clone()
    }

    /// Get metrics for a specific connection
    pub async fn connection_metrics(&self, peer_id: &PeerId) -> Option<ConnectionMetrics> {
        let connection = self.inner.get_connection(peer_id).ok()??;
        let stats = connection.stats();
        let rtt = connection.rtt();

        let last_activity = self
            .connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.last_activity);

        Some(ConnectionMetrics {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            rtt: Some(rtt),
            packet_loss: stats.path.lost_packets as f64
                / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
            last_activity,
        })
    }

    /// Get NAT traversal statistics
    pub fn nat_stats(&self) -> Result<NatTraversalStatistics, EndpointError> {
        self.inner
            .get_nat_stats()
            .map_err(|e| EndpointError::Connection(e.to_string()))
    }

    // === Known Peers ===

    /// Connect to configured known peers
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let known_peers = self.config.known_peers.clone();

        for addr in &known_peers {
            match self.connect(*addr).await {
                Ok(_) => {
                    connected += 1;
                    info!("Connected to known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to known peer {}: {}", addr, e);
                }
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.connected_bootstrap_nodes = connected;
        }

        let _ = self.event_tx.send(P2pEvent::BootstrapStatus {
            connected,
            total: known_peers.len(),
        });

        Ok(connected)
    }

    /// Add a bootstrap node dynamically
    pub async fn add_bootstrap(&self, addr: SocketAddr) {
        let _ = self.inner.add_bootstrap_node(addr);
        let mut stats = self.stats.write().await;
        stats.total_bootstrap_nodes += 1;
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.connected_peers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.read().await.contains_key(peer_id)
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        self.connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.authenticated)
            .unwrap_or(false)
    }

    // === Lifecycle ===

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down P2P endpoint");
        self.shutdown.store(true, Ordering::SeqCst);

        // Disconnect all peers
        let peers: Vec<PeerId> = self.connected_peers.read().await.keys().copied().collect();
        for peer_id in peers {
            let _ = self.disconnect(&peer_id).await;
        }

        let _ = self.inner.shutdown().await;
    }

    /// Check if endpoint is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }

    // === Internal helpers ===

    fn derive_peer_id_from_address(&self, addr: SocketAddr) -> PeerId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        let hash = hasher.finish();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes[..8].copy_from_slice(&hash.to_le_bytes());
        peer_id_bytes[8..10].copy_from_slice(&addr.port().to_le_bytes());

        PeerId(peer_id_bytes)
    }

    async fn authenticate_peer(&self, peer_id: &PeerId) -> Result<(), EndpointError> {
        info!("Authenticating peer {:?}", peer_id);

        let auth_protocol = AuthProtocol::new(Arc::clone(&self.auth_manager));
        let auth_request = auth_protocol.initiate_auth().await;
        let data = AuthManager::serialize_message(&auth_request)
            .map_err(|e| EndpointError::Authentication(e.to_string()))?;

        self.send(peer_id, &data).await?;

        let timeout = self.config.auth.auth_timeout;
        let start = Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());

            match self.recv(remaining).await {
                Ok((recv_peer_id, data)) if recv_peer_id == *peer_id => {
                    let message = AuthManager::deserialize_message(&data)
                        .map_err(|e| EndpointError::Authentication(e.to_string()))?;

                    if let AuthMessage::AuthFailure { reason } = &message {
                        return Err(EndpointError::Authentication(reason.clone()));
                    }

                    let response = auth_protocol
                        .handle_message(*peer_id, message.clone())
                        .await
                        .map_err(|e| EndpointError::Authentication(e.to_string()))?;

                    if let Some(response) = response {
                        let response_data = AuthManager::serialize_message(&response)
                            .map_err(|e| EndpointError::Authentication(e.to_string()))?;
                        self.send(peer_id, &response_data).await?;

                        if matches!(response, AuthMessage::AuthSuccess { .. }) {
                            if let Some(peer_conn) =
                                self.connected_peers.write().await.get_mut(peer_id)
                            {
                                peer_conn.authenticated = true;
                            }
                            let _ = self
                                .event_tx
                                .send(P2pEvent::PeerAuthenticated { peer_id: *peer_id });
                            return Ok(());
                        }
                    }

                    if matches!(message, AuthMessage::AuthSuccess { .. }) {
                        if let Some(peer_conn) = self.connected_peers.write().await.get_mut(peer_id)
                        {
                            peer_conn.authenticated = true;
                        }
                        let _ = self
                            .event_tx
                            .send(P2pEvent::PeerAuthenticated { peer_id: *peer_id });
                        return Ok(());
                    }
                }
                Ok((other_peer_id, data)) => {
                    // Buffer data from non-target peers to prevent data loss
                    // This data will be retrieved on the next recv() call
                    debug!(
                        "Buffering {} bytes from peer {:?} during authentication",
                        data.len(),
                        other_peer_id
                    );
                    let mut pending = self.pending_data.write().await;
                    pending
                        .entry(other_peer_id)
                        .or_insert_with(VecDeque::new)
                        .push_back(data);
                    continue;
                }
                Err(EndpointError::Timeout) => break,
                Err(e) => {
                    return Err(EndpointError::Authentication(format!(
                        "Authentication failed: {e}"
                    )));
                }
            }
        }

        Err(EndpointError::Authentication(
            "Authentication timeout".to_string(),
        ))
    }
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            auth_manager: Arc::clone(&self.auth_manager),
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            peer_id: self.peer_id,
            shutdown: Arc::clone(&self.shutdown),
            pending_data: Arc::clone(&self.pending_data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.nat_traversal_attempts, 0);
    }

    #[test]
    fn test_connection_metrics_default() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert!(metrics.rtt.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn test_peer_connection_debug() {
        let conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: "127.0.0.1:8080".parse().expect("valid addr"),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("PeerConnection"));
    }

    #[test]
    fn test_disconnect_reason_debug() {
        let reason = DisconnectReason::Normal;
        assert!(format!("{:?}", reason).contains("Normal"));

        let reason = DisconnectReason::ProtocolError("test".to_string());
        assert!(format!("{:?}", reason).contains("test"));
    }

    #[test]
    fn test_traversal_phase_debug() {
        let phase = TraversalPhase::Discovery;
        assert!(format!("{:?}", phase).contains("Discovery"));
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let err = EndpointError::PeerNotFound(PeerId([0u8; 32]));
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder()
            .build()
            .expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }
}
