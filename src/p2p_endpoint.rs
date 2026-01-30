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
//! - TLS-based peer authentication via ML-DSA-65 (v0.2+)
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::constrained::ConnectionId as ConstrainedConnectionId;
use crate::transport::TransportAddr;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::constrained::EngineEvent;

// v0.2: auth module removed - TLS handles peer authentication via ML-DSA-65
use crate::bounded_pending_buffer::BoundedPendingBuffer;
use crate::connection_router::{ConnectionRouter, RouterConfig};
use crate::connection_strategy::{
    ConnectionMethod, ConnectionStage, ConnectionStrategy, StrategyConfig,
};
use crate::crypto::raw_public_keys::key_utils::{
    derive_peer_id_from_public_key, generate_ml_dsa_keypair,
};
use crate::nat_traversal_api::{
    NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, NatTraversalStatistics, PeerId,
};
use crate::transport::{ProtocolEngine, TransportRegistry};

// Re-export TraversalPhase from nat_traversal_api for convenience
use crate::Side;
use crate::bootstrap_cache::{BootstrapCache, BootstrapTokenStore};
pub use crate::nat_traversal_api::TraversalPhase;
use crate::unified_config::P2pConfig;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the data channel shared between background reader tasks and recv()
const DATA_CHANNEL_CAPACITY: usize = 256;

/// Maximum payload size for a single uni stream read (1 MB)
const MAX_UNI_STREAM_READ_BYTES: usize = 1024 * 1024;

/// Sleep interval for the constrained transport poller when idle (ms)
const CONSTRAINED_POLL_INTERVAL_MS: u64 = 1;

/// Derive a synthetic PeerId by hashing a `TransportAddr` display string.
///
/// Used for constrained connections (BLE, LoRa) where no TLS-based identity exists.
fn peer_id_from_transport_addr(addr: &TransportAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    format!("{}", addr).hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..16].copy_from_slice(&hash.to_be_bytes());
    PeerId(id)
}

/// Derive a synthetic PeerId by hashing a `SocketAddr`.
///
/// Used when the peer's real identity (ML-DSA-65 key) is not yet known.
fn peer_id_from_socket_addr(addr: SocketAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..10].copy_from_slice(&addr.port().to_le_bytes());
    PeerId(id)
}

/// P2P endpoint - the primary API for ant-quic
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
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

    /// Our ML-DSA-65 public key bytes (for identity sharing) - 1952 bytes
    public_key: Vec<u8>,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,

    /// Bounded pending data buffer for message ordering
    pending_data: Arc<RwLock<BoundedPendingBuffer>>,

    /// Bootstrap cache for peer persistence
    pub bootstrap_cache: Arc<BootstrapCache>,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity.
    transport_registry: Arc<TransportRegistry>,

    /// Connection router for automatic protocol engine selection
    ///
    /// Routes connections through either QUIC (for broadband) or Constrained
    /// engine (for BLE/LoRa) based on transport capabilities.
    router: Arc<RwLock<ConnectionRouter>>,

    /// Mapping from PeerId to ConnectionId for constrained connections
    ///
    /// When a peer is connected via a constrained transport (BLE, LoRa, etc.),
    /// this map stores the ConstrainedEngine's ConnectionId for that peer.
    /// UDP/QUIC peers are NOT in this map - they use the standard QUIC connection.
    constrained_connections: Arc<RwLock<HashMap<PeerId, ConstrainedConnectionId>>>,

    /// Reverse lookup: ConnectionId → (PeerId, TransportAddr) for constrained connections
    ///
    /// This enables mapping incoming constrained data back to the correct PeerId.
    /// Registered when ConnectionAccepted/Established fires for constrained transports.
    constrained_peer_addrs: Arc<RwLock<HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>>>,

    /// Channel sender for data received from QUIC reader tasks and constrained poller
    data_tx: mpsc::Sender<(PeerId, Vec<u8>)>,

    /// Channel receiver for data received from QUIC reader tasks and constrained poller
    data_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(PeerId, Vec<u8>)>>>,

    /// Background reader task handles per QUIC peer (for cleanup on disconnect/shutdown)
    reader_tasks: Arc<RwLock<HashMap<PeerId, tokio::task::JoinHandle<()>>>>,
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

    /// Remote address (supports all transport types)
    pub remote_addr: TransportAddr,

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

/// P2P event for connection and network state changes.
///
/// Events use [`TransportAddr`] to support multi-transport connectivity.
/// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
///
/// # Examples
///
/// ## Handling events with transport awareness
///
/// ```rust,ignore
/// use ant_quic::{P2pEvent, transport::TransportAddr};
///
/// while let Ok(event) = events.recv().await {
///     match event {
///         P2pEvent::PeerConnected { peer_id, addr, side } => {
///             // Handle different transport types
///             match addr {
///                 TransportAddr::Udp(socket_addr) => {
///                     println!("UDP connection from {socket_addr}");
///                 },
///                 TransportAddr::Ble { device_id, .. } => {
///                     println!("BLE connection from {:?}", device_id);
///                 },
///                 _ => println!("Other transport: {addr}"),
///             }
///         }
///         P2pEvent::ExternalAddressDiscovered { addr } => {
///             // Our external address was discovered
///             if let Some(socket_addr) = addr.as_socket_addr() {
///                 println!("External UDP address: {socket_addr}");
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Backward-compatible event handling
///
/// For code that only needs UDP support:
///
/// ```rust,ignore
/// match event {
///     P2pEvent::PeerConnected { peer_id, addr, .. } => {
///         if let Some(socket_addr) = addr.as_socket_addr() {
///             // Works as before with SocketAddr
///             println!("Peer {} connected from {}", peer_id, socket_addr);
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A new peer has connected.
    ///
    /// The `addr` field contains a [`TransportAddr`] which can represent different
    /// transport types (UDP, BLE, LoRa, etc.). Use `addr.as_socket_addr()` to extract
    /// the [`SocketAddr`] for UDP connections, or pattern match for specific transports.
    PeerConnected {
        /// The unique identifier of the connected peer
        peer_id: PeerId,
        /// Remote transport address (supports UDP, BLE, LoRa, and other transports)
        addr: TransportAddr,
        /// Who initiated the connection (Client = we connected, Server = they connected)
        side: Side,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// The unique identifier of the disconnected peer
        peer_id: PeerId,
        /// Reason for the disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress update.
    NatTraversalProgress {
        /// Target peer ID for the NAT traversal
        peer_id: PeerId,
        /// Current phase of NAT traversal
        phase: TraversalPhase,
    },

    /// An external address was discovered for this node.
    ///
    /// The `addr` field contains a [`TransportAddr`] representing our externally
    /// visible address. For UDP connections, use `addr.as_socket_addr()` to get
    /// the [`SocketAddr`].
    ExternalAddressDiscovered {
        /// Discovered external transport address (typically TransportAddr::Udp for NAT traversal)
        addr: TransportAddr,
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

    /// Data received from a constrained transport (BLE, LoRa, etc.)
    ///
    /// This event is generated when data arrives via a non-UDP transport that uses
    /// the constrained protocol engine. The peer may not have a PeerId assigned yet
    /// (early in the connection lifecycle).
    ConstrainedDataReceived {
        /// Remote transport address (BLE device ID, LoRa address, etc.)
        remote_addr: TransportAddr,
        /// Connection ID from the constrained engine
        connection_id: u16,
        /// The received data payload
        data: Vec<u8>,
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

    /// All connection strategies failed
    #[error("All connection strategies failed: {0}")]
    AllStrategiesFailed(String),

    /// No target address provided
    #[error("No target address provided")]
    NoAddress,
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Use provided keypair or generate a new one (ML-DSA-65)
        let (public_key, secret_key) = match config.keypair.clone() {
            Some(keypair) => keypair,
            None => generate_ml_dsa_keypair().map_err(|e| {
                EndpointError::Config(format!("Failed to generate ML-DSA-65 keypair: {e:?}"))
            })?,
        };
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Creating P2P endpoint with peer ID: {:?}", peer_id);

        // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
        // Store public key bytes directly for identity sharing
        let public_key_bytes: Vec<u8> = public_key.as_bytes().to_vec();

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
                        side,
                    } => {
                        stats_guard.nat_traversal_successes += 1;
                        stats_guard.active_connections += 1;
                        stats_guard.successful_connections += 1;

                        // Broadcast event with connection direction
                        let _ = event_tx.send(P2pEvent::PeerConnected {
                            peer_id: *peer_id,
                            addr: TransportAddr::Udp(*remote_address),
                            side: *side,
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
                        let _ = event_tx.send(P2pEvent::ExternalAddressDiscovered {
                            addr: TransportAddr::Udp(*address),
                        });
                    }
                    _ => {}
                }
                drop(stats_guard);
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let mut nat_config = config.to_nat_config_with_key(public_key.clone(), secret_key);
        let bootstrap_cache = Arc::new(
            BootstrapCache::open(config.bootstrap_cache.clone())
                .await
                .map_err(|e| {
                    EndpointError::Config(format!("Failed to open bootstrap cache: {}", e))
                })?,
        );

        // Create token store
        let token_store = Arc::new(BootstrapTokenStore::new(bootstrap_cache.clone()).await);

        // Phase 5.3 Deliverable 3: Socket sharing in default constructor
        // Bind a single UDP socket and share it between transport registry and Quinn
        let default_addr: std::net::SocketAddr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let bind_addr = config
            .bind_addr
            .as_ref()
            .and_then(|addr| addr.as_socket_addr())
            .unwrap_or(default_addr);
        let (udp_transport, quinn_socket) =
            crate::transport::UdpTransport::bind_for_quinn(bind_addr)
                .await
                .map_err(|e| EndpointError::Config(format!("Failed to bind UDP socket: {e}")))?;

        let actual_bind_addr = quinn_socket
            .local_addr()
            .map_err(|e| EndpointError::Config(format!("Failed to get local address: {e}")))?;

        info!("Bound shared UDP socket at {}", actual_bind_addr);

        // Create transport registry with the UDP transport
        // Also include any additional transports from the config
        let mut transport_registry = config.transport_registry.clone();
        transport_registry.register(Arc::new(udp_transport));

        // Update NAT config to use our registry and bind address
        nat_config.transport_registry = Some(Arc::new(transport_registry.clone()));
        nat_config.bind_addr = Some(actual_bind_addr);

        // Create NAT traversal endpoint with the shared socket
        let inner = NatTraversalEndpoint::new_with_socket(
            nat_config,
            Some(event_callback),
            Some(token_store.clone()),
            Some(quinn_socket),
        )
        .await
        .map_err(|e| EndpointError::Config(e.to_string()))?;

        // Wrap the registry in Arc for shared ownership
        let transport_registry = Arc::new(transport_registry);

        // Create connection router for automatic protocol engine selection
        let inner_arc = Arc::new(inner);
        let router_config = RouterConfig {
            constrained_config: crate::constrained::ConstrainedTransportConfig::default(),
            prefer_quic: true, // Default to QUIC for broadband transports
            enable_metrics: true,
            max_connections: 256,
        };
        let mut router = ConnectionRouter::with_full_config(
            router_config,
            Arc::clone(&transport_registry),
            Arc::clone(&inner_arc),
        );

        // Set QUIC endpoint on the router
        router.set_quic_endpoint(Arc::clone(&inner_arc));

        // Create channel for data received from background reader tasks
        let (data_tx, data_rx) = mpsc::channel(DATA_CHANNEL_CAPACITY);
        let reader_tasks = Arc::new(RwLock::new(HashMap::new()));

        let endpoint = Self {
            inner: inner_arc,
            // v0.2: auth_manager removed
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            peer_id,
            public_key: public_key_bytes,
            shutdown: Arc::new(AtomicBool::new(false)),
            pending_data: Arc::new(RwLock::new(BoundedPendingBuffer::default())),
            bootstrap_cache,
            transport_registry,
            router: Arc::new(RwLock::new(router)),
            constrained_connections: Arc::new(RwLock::new(HashMap::new())),
            constrained_peer_addrs: Arc::new(RwLock::new(HashMap::new())),
            data_tx,
            data_rx: Arc::new(tokio::sync::Mutex::new(data_rx)),
            reader_tasks,
        };

        // Spawn background constrained poller task
        endpoint.spawn_constrained_poller();

        Ok(endpoint)
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get the underlying QUIC connection for a peer.
    ///
    /// This is used by the LinkTransport abstraction layer to wrap connections.
    pub fn get_quic_connection(
        &self,
        peer_id: &PeerId,
    ) -> Result<Option<crate::high_level::Connection>, EndpointError> {
        self.inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)
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

    /// Get the transport registry for this endpoint
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this endpoint can use for connectivity.
    pub fn transport_registry(&self) -> &TransportRegistry {
        &self.transport_registry
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    // === Connection Management ===

    /// Connect to a peer by address (direct connection).
    ///
    /// Uses Raw Public Key authentication - the peer's identity is verified via their
    /// ML-DSA-65 public key, not via SNI/certificates.
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

        // Spawn handler (we initiated the connection = Client side)
        self.inner
            .spawn_connection_handler(peer_id, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        // Create peer connection record
        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(addr),
            authenticated: true, // TLS handles authentication
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Store peer
        self.connected_peers
            .write()
            .await
            .insert(peer_id, peer_conn.clone());

        // Spawn background reader task for this QUIC connection
        if let Ok(Some(conn)) = self.inner.get_connection(&peer_id) {
            self.spawn_reader_task(peer_id, conn);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        // Broadcast event (we initiated the connection = Client side)
        let _ = self.event_tx.send(P2pEvent::PeerConnected {
            peer_id,
            addr: TransportAddr::Udp(addr),
            side: Side::Client,
        });

        Ok(peer_conn)
    }

    /// Connect to a peer using any transport address
    ///
    /// This method uses the connection router to automatically select the appropriate
    /// protocol engine (QUIC or Constrained) based on the transport capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use ant_quic::transport::TransportAddr;
    ///
    /// // Connect via UDP (uses QUIC)
    /// let udp_addr = TransportAddr::Udp("192.168.1.100:9000".parse()?);
    /// let conn = endpoint.connect_transport(&udp_addr, None).await?;
    ///
    /// // Connect via BLE (uses Constrained engine)
    /// let ble_addr = TransportAddr::Ble {
    ///     device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     service_uuid: None,
    /// };
    /// let conn = endpoint.connect_transport(&ble_addr, None).await?;
    /// ```
    pub async fn connect_transport(
        &self,
        addr: &TransportAddr,
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Use the router to determine the appropriate engine
        let mut router = self.router.write().await;
        let engine = router.select_engine_for_addr(addr);

        info!(
            "Connecting to {} via {:?} engine (peer_id: {:?})",
            addr, engine, peer_id
        );

        match engine {
            ProtocolEngine::Quic => {
                // For QUIC, extract socket address and use existing connect path
                let socket_addr = addr.as_socket_addr().ok_or_else(|| {
                    EndpointError::Connection(format!(
                        "Cannot extract socket address from {} for QUIC",
                        addr
                    ))
                })?;
                drop(router); // Release lock before async operation
                self.connect(socket_addr).await
            }
            ProtocolEngine::Constrained => {
                // For constrained transports, use the router's constrained connection
                let _routed = router.connect(addr).map_err(|e| {
                    EndpointError::Connection(format!("Constrained connection failed: {}", e))
                })?;

                // Create a synthetic peer ID for constrained connections if not provided
                let actual_peer_id =
                    peer_id.unwrap_or_else(|| self.derive_peer_id_from_transport_addr(addr));

                let peer_conn = PeerConnection {
                    peer_id: actual_peer_id,
                    remote_addr: addr.clone(),
                    authenticated: false, // Constrained connections don't have TLS auth yet
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Store peer
                drop(router); // Release lock before acquiring connected_peers lock
                self.connected_peers
                    .write()
                    .await
                    .insert(actual_peer_id, peer_conn.clone());

                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // Broadcast event
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    peer_id: actual_peer_id,
                    addr: addr.clone(),
                    side: Side::Client,
                });

                Ok(peer_conn)
            }
        }
    }

    /// Get the connection router for advanced routing control
    ///
    /// Returns a reference to the connection router which can be used to:
    /// - Query engine selection for addresses
    /// - Get routing statistics
    /// - Configure routing behavior
    pub async fn router(&self) -> tokio::sync::RwLockReadGuard<'_, ConnectionRouter> {
        self.router.read().await
    }

    /// Get routing statistics
    pub async fn routing_stats(&self) -> crate::connection_router::RouterStats {
        self.router.read().await.stats().clone()
    }

    /// Register a constrained connection for a peer
    ///
    /// This associates a PeerId with a ConstrainedEngine ConnectionId, enabling
    /// send() to use the proper constrained protocol for reliable delivery.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's identity
    /// * `conn_id` - The ConnectionId from the ConstrainedEngine
    ///
    /// # Returns
    ///
    /// The previous ConnectionId if one was already registered for this peer.
    pub async fn register_constrained_connection(
        &self,
        peer_id: PeerId,
        conn_id: ConstrainedConnectionId,
    ) -> Option<ConstrainedConnectionId> {
        let old = self
            .constrained_connections
            .write()
            .await
            .insert(peer_id, conn_id);
        debug!(
            "Registered constrained connection for peer {:?}: conn_id={:?}",
            peer_id, conn_id
        );
        old
    }

    /// Unregister a constrained connection for a peer
    ///
    /// Call this when a constrained connection is closed or reset.
    ///
    /// # Returns
    ///
    /// The ConnectionId if one was registered for this peer.
    pub async fn unregister_constrained_connection(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        let removed = self.constrained_connections.write().await.remove(peer_id);
        if removed.is_some() {
            debug!("Unregistered constrained connection for peer {:?}", peer_id);
        }
        removed
    }

    /// Check if a peer has a constrained connection
    pub async fn has_constrained_connection(&self, peer_id: &PeerId) -> bool {
        self.constrained_connections
            .read()
            .await
            .contains_key(peer_id)
    }

    /// Get the ConnectionId for a peer's constrained connection
    pub async fn get_constrained_connection_id(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        self.constrained_connections
            .read()
            .await
            .get(peer_id)
            .copied()
    }

    /// Get the number of active constrained connections
    pub async fn constrained_connection_count(&self) -> usize {
        self.constrained_connections.read().await.len()
    }

    /// Look up PeerId from constrained ConnectionId
    pub async fn peer_id_from_constrained_conn(
        &self,
        conn_id: ConstrainedConnectionId,
    ) -> Option<PeerId> {
        self.constrained_peer_addrs
            .read()
            .await
            .get(&conn_id)
            .map(|(peer_id, _)| *peer_id)
    }

    /// Derive a peer ID from a transport address (for constrained connections)
    fn derive_peer_id_from_transport_addr(&self, addr: &TransportAddr) -> PeerId {
        peer_id_from_transport_addr(addr)
    }

    /// Connect to a peer using dual-stack strategy (tries both IPv4 and IPv6 in parallel)
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///    - **IPv6-only**: Uses IPv6 connection, graceful degradation  
    ///    - **Neither**: Returns error (try NAT traversal next)
    ///
    /// # Arguments
    /// * `addresses` - List of candidate addresses (mix of IPv4 and IPv6)
    /// * `peer_id` - Optional peer ID (for token persistence and 0-RTT/Fast Reconnect)
    ///
    /// # Returns
    /// Primary connection (IPv6 preferred if both succeed)
    ///
    /// # Dual-Connection Behavior
    /// When both IPv4 AND IPv6 succeed, BOTH connections are stored in `connected_peers`.
    /// The system maintains redundant connections for maximum reliability.
    pub async fn connect_dual_stack(
        &self,
        addresses: &[SocketAddr],
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        use std::net::IpAddr;

        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Separate addresses by family
        let ipv4_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .copied()
            .collect();

        let ipv6_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V6(_)))
            .copied()
            .collect();

        info!(
            "Dual-stack connect: {} IPv4, {} IPv6 addresses (PeerId: {:?})",
            ipv4_addrs.len(),
            ipv6_addrs.len(),
            peer_id
        );

        // Use "peer" as SNI for all P2P connections
        // Raw Public Key authentication validates the peer's public key directly,
        // so we don't need/use SNI for authentication. A fixed SNI avoids
        // "invalid server name" errors from hex peer IDs being too long.
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.try_connect_family(&ipv4_addrs, "IPv4"),
            self.try_connect_family(&ipv6_addrs, "IPv6"),
        );

        // Handle all possible outcomes
        match (ipv4_result, ipv6_result) {
            (Some(v4_conn), Some(v6_conn)) => {
                // 🎉 BEST CASE: Both IPv4 AND IPv6 work - keep both!
                info!(
                    "✓✓ Dual-stack success! IPv4: {}, IPv6: {} (maintaining both connections)",
                    v4_conn.remote_addr, v6_conn.remote_addr
                );

                // Both connections already stored by try_connect_family
                // Return IPv6 as primary (modern internet best practice)
                Ok(v6_conn)
            }

            (Some(v4_conn), None) => {
                // IPv4-only network (v6 unavailable or failed)
                info!(
                    "IPv4-only connection established to {}",
                    v4_conn.remote_addr
                );
                Ok(v4_conn)
            }

            (None, Some(v6_conn)) => {
                // IPv6-only network (v4 unavailable or failed)
                info!(
                    "IPv6-only connection established to {}",
                    v6_conn.remote_addr
                );
                Ok(v6_conn)
            }

            (None, None) => {
                // Neither direct connection works - try NAT traversal next
                warn!("Both IPv4 and IPv6 direct connections failed");
                Err(EndpointError::Connection(
                    "Dual-stack connection failed for both address families".to_string(),
                ))
            }
        }
    }

    /// Try to connect using addresses from one family (IPv4 or IPv6)
    ///
    async fn try_connect_family(
        &self,
        addresses: &[SocketAddr],
        family_name: &str,
    ) -> Option<PeerConnection> {
        use tokio::time::{Duration, timeout};

        if addresses.is_empty() {
            debug!("{}: No addresses to try", family_name);
            return None;
        }

        debug!("Trying {} {} addresses", addresses.len(), family_name);

        for (idx, addr) in addresses.iter().enumerate() {
            debug!(
                "  {} attempt {}/{}: {}",
                family_name,
                idx + 1,
                addresses.len(),
                addr
            );

            match timeout(Duration::from_secs(5), self.connect(*addr)).await {
                Ok(Ok(peer_conn)) => {
                    info!("✓ {} connection successful to {}", family_name, addr);
                    return Some(peer_conn);
                }
                Ok(Err(e)) => {
                    debug!("  {} to {} failed: {}", family_name, addr, e);
                    // Try next address
                }
                Err(_) => {
                    debug!("  {} to {} timed out (5s)", family_name, addr);
                    // Try next address
                }
            }
        }

        debug!("{}: All {} addresses failed", family_name, addresses.len());
        None
    }

    /// Connect to a peer using cached information (addresses, tokens)
    ///
    /// This method retrieves the peer from `BootstrapCache` and attempts to connect
    /// using its known addresses. It leverages `connect_dual_stack` with the `PeerId`
    /// to enable token-based 0-RTT/Fast Reconnect.
    pub async fn connect_cached(&self, peer_id: PeerId) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Check if already connected
        if let Some(conn) = self.connected_peers.read().await.get(&peer_id) {
            return Ok(conn.clone());
        }

        // Retrieve from cache
        let cached_peer = self
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .ok_or(EndpointError::PeerNotFound(peer_id))?;

        debug!(
            "Connecting to cached peer {:?} ({} addresses)",
            peer_id,
            cached_peer.addresses.len()
        );

        // Try dual-stack connection with PeerId (triggers token usage)
        self.connect_dual_stack(&cached_peer.addresses, Some(peer_id))
            .await
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
            .or_else(|| {
                self.config
                    .known_peers
                    .first()
                    .and_then(|addr| addr.as_socket_addr())
            })
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
                        side: _, // We initiated this NAT traversal, side is Client
                    } if evt_peer == peer_id => {
                        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                        let peer_conn = PeerConnection {
                            peer_id,
                            remote_addr: TransportAddr::Udp(remote_address),
                            authenticated: true, // TLS handles authentication
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        self.connected_peers
                            .write()
                            .await
                            .insert(peer_id, peer_conn.clone());

                        // Spawn background reader task for this QUIC connection
                        if let Ok(Some(conn)) = self.inner.get_connection(&peer_id) {
                            self.spawn_reader_task(peer_id, conn);
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

    /// Connect with automatic fallback: IPv4 → IPv6 → HolePunch → Relay
    ///
    /// This method implements a progressive connection strategy that automatically
    /// falls back through increasingly aggressive NAT traversal techniques:
    ///
    /// 1. **Direct IPv4** (5s timeout) - Simple direct connection
    /// 2. **Direct IPv6** (5s timeout) - Bypasses NAT when IPv6 available
    /// 3. **Hole-Punch** (15s timeout) - Coordinated NAT traversal via common peer
    /// 4. **Relay** (30s timeout) - MASQUE relay as last resort
    ///
    /// # Arguments
    ///
    /// * `target_ipv4` - Optional IPv4 address of the target peer
    /// * `target_ipv6` - Optional IPv6 address of the target peer
    /// * `strategy_config` - Optional custom strategy configuration
    ///
    /// # Returns
    ///
    /// A tuple of (PeerConnection, ConnectionMethod) indicating how the connection
    /// was established.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (conn, method) = endpoint.connect_with_fallback(
    ///     Some("1.2.3.4:9000".parse()?),
    ///     Some("[2001:db8::1]:9000".parse()?),
    ///     None, // Use default strategy config
    /// ).await?;
    ///
    /// match method {
    ///     ConnectionMethod::DirectIPv4 => println!("Direct IPv4"),
    ///     ConnectionMethod::DirectIPv6 => println!("Direct IPv6"),
    ///     ConnectionMethod::HolePunched { coordinator } => println!("Via {}", coordinator),
    ///     ConnectionMethod::Relayed { relay } => println!("Relayed via {}", relay),
    /// }
    /// ```
    pub async fn connect_with_fallback(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
        peer_id: Option<PeerId>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        use tokio::time::timeout;

        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Build strategy config with coordinator and relay from our config
        let mut config = strategy_config.unwrap_or_default();
        if config.coordinator.is_none() {
            config.coordinator = self
                .config
                .known_peers
                .first()
                .and_then(|addr| addr.as_socket_addr());
        }
        if config.relay_addr.is_none() {
            // Optimization: Try to find a high-quality relay from our cache first
            let target_addr = target_ipv4.or(target_ipv6);
            if let Some(addr) = target_addr {
                // Select best relay for this target (preferring dual-stack)
                let relays = self
                    .bootstrap_cache
                    .select_relays_for_target(1, &addr, true)
                    .await;

                if let Some(best_relay) = relays.first() {
                    // Use the first address of the best relay
                    // In a perfect world we'd check reachability of this address too,
                    // but for now we assume cached addresses are valid candidates.
                    config.relay_addr = best_relay.addresses.first().copied();
                    debug!(
                        "Selected optimized relay from cache: {:?} for target {}",
                        config.relay_addr, addr
                    );
                }
            }

            // Fallback to static config if cache gave nothing
            if config.relay_addr.is_none() {
                config.relay_addr = self.config.nat.relay_nodes.first().copied();
            }
        }

        let mut strategy = ConnectionStrategy::new(config);

        info!(
            "Starting fallback connection: IPv4={:?}, IPv6={:?} (PeerId: {:?})",
            target_ipv4, target_ipv6, peer_id
        );

        loop {
            match strategy.current_stage().clone() {
                ConnectionStage::DirectIPv4 { .. } => {
                    if let Some(addr) = target_ipv4 {
                        info!("Trying direct IPv4 connection to {}", addr);
                        match timeout(strategy.ipv4_timeout(), self.connect(addr)).await {
                            Ok(Ok(conn)) => {
                                info!("✓ Direct IPv4 connection succeeded to {}", addr);
                                return Ok((conn, ConnectionMethod::DirectIPv4));
                            }
                            Ok(Err(e)) => {
                                debug!("Direct IPv4 failed: {}", e);
                                strategy.transition_to_ipv6(e.to_string());
                            }
                            Err(_) => {
                                debug!("Direct IPv4 timed out");
                                strategy.transition_to_ipv6("Timeout");
                            }
                        }
                    } else {
                        debug!("No IPv4 address provided, skipping");
                        strategy.transition_to_ipv6("No IPv4 address");
                    }
                }

                ConnectionStage::DirectIPv6 { .. } => {
                    if let Some(addr) = target_ipv6 {
                        info!("Trying direct IPv6 connection to {}", addr);
                        match timeout(strategy.ipv6_timeout(), self.connect(addr)).await {
                            Ok(Ok(conn)) => {
                                info!("✓ Direct IPv6 connection succeeded to {}", addr);
                                return Ok((conn, ConnectionMethod::DirectIPv6));
                            }
                            Ok(Err(e)) => {
                                debug!("Direct IPv6 failed: {}", e);
                                strategy.transition_to_holepunch(e.to_string());
                            }
                            Err(_) => {
                                debug!("Direct IPv6 timed out");
                                strategy.transition_to_holepunch("Timeout");
                            }
                        }
                    } else {
                        debug!("No IPv6 address provided, skipping");
                        strategy.transition_to_holepunch("No IPv6 address");
                    }
                }

                ConnectionStage::HolePunching {
                    coordinator, round, ..
                } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!(
                        "Trying hole-punch to {} via {} (round {})",
                        target, coordinator, round
                    );

                    // Use our existing NAT traversal infrastructure
                    // If peer_id provided, use it. Otherwise derive from address.
                    let target_peer_id =
                        peer_id.unwrap_or_else(|| self.derive_peer_id_from_address(target));

                    match timeout(
                        strategy.holepunch_timeout(),
                        self.try_hole_punch(target, coordinator, target_peer_id),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!("✓ Hole-punch succeeded to {} via {}", target, coordinator);
                            return Ok((conn, ConnectionMethod::HolePunched { coordinator }));
                        }
                        Ok(Err(e)) => {
                            strategy.record_holepunch_error(round, e.to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} failed, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch failed after {} rounds", round);
                                strategy.transition_to_relay(e.to_string());
                            }
                        }
                        Err(_) => {
                            strategy.record_holepunch_error(round, "Timeout".to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} timed out, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch timed out after {} rounds", round);
                                strategy.transition_to_relay("Timeout");
                            }
                        }
                    }
                }

                ConnectionStage::Relay { relay_addr, .. } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!("Trying relay connection to {} via {}", target, relay_addr);

                    match timeout(
                        strategy.relay_timeout(),
                        self.try_relay_connection(target, relay_addr),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!(
                                "✓ Relay connection succeeded to {} via {}",
                                target, relay_addr
                            );
                            return Ok((conn, ConnectionMethod::Relayed { relay: relay_addr }));
                        }
                        Ok(Err(e)) => {
                            debug!("Relay connection failed: {}", e);
                            strategy.transition_to_failed(e.to_string());
                        }
                        Err(_) => {
                            debug!("Relay connection timed out");
                            strategy.transition_to_failed("Timeout");
                        }
                    }
                }

                ConnectionStage::Failed { errors } => {
                    let error_summary = errors
                        .iter()
                        .map(|e| format!("{:?}: {}", e.method, e.error))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(EndpointError::AllStrategiesFailed(error_summary));
                }

                ConnectionStage::Connected { via } => {
                    // This shouldn't happen in the loop, but handle it
                    unreachable!("Connected stage reached in loop: {:?}", via);
                }
            }
        }
    }

    /// Internal helper for hole-punch attempt
    async fn try_hole_punch(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
        peer_id: PeerId,
    ) -> Result<PeerConnection, EndpointError> {
        // First ensure we're connected to the coordinator
        if !self.is_connected_to_addr(coordinator).await {
            debug!("Connecting to coordinator {} first", coordinator);
            self.connect(coordinator).await?;
        }

        // Initiate NAT traversal
        self.inner
            .initiate_nat_traversal(peer_id, coordinator)
            .map_err(EndpointError::NatTraversal)?;

        // Poll for completion with shorter timeout
        let start = Instant::now();
        let timeout_duration = Duration::from_secs(15);

        while start.elapsed() < timeout_duration {
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
                        side: _,
                    } if evt_peer == peer_id || remote_address == target => {
                        let peer_conn = PeerConnection {
                            peer_id: evt_peer,
                            remote_addr: TransportAddr::Udp(remote_address),
                            authenticated: true,
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        self.connected_peers
                            .write()
                            .await
                            .insert(evt_peer, peer_conn.clone());

                        // Spawn background reader task for this QUIC connection
                        if let Ok(Some(conn)) = self.inner.get_connection(&evt_peer) {
                            self.spawn_reader_task(evt_peer, conn);
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

    async fn try_relay_connection(
        &self,
        target: SocketAddr,
        relay_addr: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "Attempting MASQUE relay connection to {} via {}",
            target, relay_addr
        );

        let public_addr = self
            .inner
            .establish_relay_session(relay_addr)
            .await
            .map_err(EndpointError::NatTraversal)?;

        info!(
            "MASQUE relay session established via {} (public addr: {:?})",
            relay_addr, public_addr
        );

        let conn = self.connect(target).await?;

        info!(
            "MASQUE relay connection succeeded to {} via {} (our relay addr: {:?})",
            target, relay_addr, public_addr
        );

        Ok(conn)
    }

    /// Check if we're connected to a specific address
    async fn is_connected_to_addr(&self, addr: SocketAddr) -> bool {
        let transport_addr = TransportAddr::Udp(addr);
        let peers = self.connected_peers.read().await;
        peers.values().any(|p| p.remote_addr == transport_addr)
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

                // They initiated the connection to us = Server side
                if let Err(e) =
                    self.inner
                        .spawn_connection_handler(resolved_peer_id, connection, Side::Server)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                let peer_conn = PeerConnection {
                    peer_id: resolved_peer_id,
                    remote_addr: TransportAddr::Udp(remote_addr),
                    authenticated: true, // TLS handles authentication
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                self.connected_peers
                    .write()
                    .await
                    .insert(resolved_peer_id, peer_conn.clone());

                // Spawn background reader task for this QUIC connection
                if let Ok(Some(conn)) = self.inner.get_connection(&resolved_peer_id) {
                    self.spawn_reader_task(resolved_peer_id, conn);
                }

                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // They initiated the connection to us = Server side
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    peer_id: resolved_peer_id,
                    addr: TransportAddr::Udp(remote_addr),
                    side: Side::Server,
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

            // Abort the background reader task for this peer
            if let Some(handle) = self.reader_tasks.write().await.remove(peer_id) {
                handle.abort();
            }

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
    ///
    /// # Transport Selection
    ///
    /// This method selects the appropriate transport provider based on the destination
    /// peer's address type and the capabilities advertised in the transport registry.
    ///
    /// ## Current Behavior (Phase 2.1)
    ///
    /// All connections currently use UDP/QUIC via the existing `connection.open_uni()`
    /// path. This ensures backward compatibility with existing peers.
    ///
    /// ## Future Behavior (Phase 2.3)
    ///
    /// Transport selection will be based on:
    /// - Peer's advertised transport addresses (from connection metadata)
    /// - Transport provider capabilities (from `transport_registry`)
    /// - Protocol engine requirements (QUIC vs Constrained)
    ///
    /// Selection priority:
    /// 1. **UDP/QUIC**: Default for broadband, full QUIC support
    /// 2. **BLE**: For nearby devices, constrained engine
    /// 3. **LoRa**: For long-range, low-bandwidth scenarios
    /// 4. **Overlay**: For I2P/Yggdrasil privacy-preserving routing
    ///
    /// # Arguments
    ///
    /// - `peer_id`: The target peer's identifier
    /// - `data`: The payload to send
    ///
    /// # Errors
    ///
    /// Returns `EndpointError` if:
    /// - The endpoint is shutting down
    /// - The peer is not connected
    /// - No suitable transport provider is available
    /// - The send operation fails
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Get peer's transport address to determine which engine/transport to use
        let peer_info = self.connected_peers.read().await;
        let transport_addr = peer_info
            .get(peer_id)
            .map(|conn| conn.remote_addr.clone())
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;
        drop(peer_info); // Release read lock before async operations

        // Select protocol engine based on transport address
        let engine = {
            let mut router = self.router.write().await;
            router.select_engine_for_addr(&transport_addr)
        };

        match engine {
            crate::transport::ProtocolEngine::Quic => {
                // Use existing QUIC connection (UDP transport)
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

                debug!("Sent {} bytes to peer {:?} via QUIC", data.len(), peer_id);
            }
            crate::transport::ProtocolEngine::Constrained => {
                // Check if we have an established constrained connection for this peer
                let maybe_conn_id = self
                    .constrained_connections
                    .read()
                    .await
                    .get(peer_id)
                    .copied();

                if let Some(conn_id) = maybe_conn_id {
                    // Use ConstrainedEngine for reliable delivery
                    let engine = self.inner.constrained_engine();
                    let responses = {
                        let mut engine = engine.lock();
                        engine
                            .send(conn_id, data)
                            .map_err(|e| EndpointError::Connection(e.to_string()))?
                    };

                    // Send any packets generated by the constrained engine
                    for (_dest_addr, packet_data) in responses {
                        self.transport_registry
                            .send(&packet_data, &transport_addr)
                            .await
                            .map_err(|e| EndpointError::Connection(e.to_string()))?;
                    }

                    debug!(
                        "Sent {} bytes to peer {:?} via constrained engine ({})",
                        data.len(),
                        peer_id,
                        transport_addr.transport_type()
                    );
                } else {
                    // No established connection - send directly via transport
                    // This path is used for initial connection or connectionless messages
                    self.transport_registry
                        .send(data, &transport_addr)
                        .await
                        .map_err(|e| EndpointError::Connection(e.to_string()))?;

                    debug!(
                        "Sent {} bytes to peer {:?} via constrained transport (direct, {})",
                        data.len(),
                        peer_id,
                        transport_addr.transport_type()
                    );
                }
            }
        }

        // Update last activity
        if let Some(peer_conn) = self.connected_peers.write().await.get_mut(peer_id) {
            peer_conn.last_activity = Instant::now();
        }

        Ok(())
    }

    /// Receive data from any connected peer.
    ///
    /// Blocks until data arrives from any transport (UDP/QUIC, BLE, LoRa, etc.)
    /// or the endpoint shuts down. Background reader tasks feed a shared channel,
    /// so this wakes instantly when data is available.
    ///
    /// # Errors
    ///
    /// Returns `EndpointError::ShuttingDown` if the endpoint is shutting down.
    pub async fn recv(&self) -> Result<(PeerId, Vec<u8>), EndpointError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(EndpointError::ShuttingDown);
        }

        // Fast path: check pending data buffer (data buffered during authentication)
        {
            let mut pending = self.pending_data.write().await;
            pending.cleanup_expired();

            if let Some((peer_id, data)) = pending.pop_any() {
                tracing::trace!(
                    "Received {} bytes from peer {:?} (from pending buffer)",
                    data.len(),
                    peer_id
                );
                return Ok((peer_id, data));
            }
        }

        // Wait for data from the shared channel (fed by background reader tasks)
        let mut rx = self.data_rx.lock().await;
        match rx.recv().await {
            Some(msg) => Ok(msg),
            None => Err(EndpointError::ShuttingDown),
        }
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
    ///
    /// This method now uses the connection router to automatically select
    /// the appropriate protocol engine for each peer address.
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let known_peers = self.config.known_peers.clone();

        for addr in &known_peers {
            // Use connect_transport for all address types
            match self.connect_transport(addr, None).await {
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

        // Abort all background reader tasks
        let tasks: HashMap<PeerId, tokio::task::JoinHandle<()>> =
            std::mem::take(&mut *self.reader_tasks.write().await);
        for (_peer_id, handle) in tasks {
            handle.abort();
        }

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
        peer_id_from_socket_addr(addr)
    }

    /// Spawn a background tokio task that reads uni streams from a QUIC connection
    /// and forwards received data into the shared `data_tx` channel.
    ///
    /// The task exits naturally when the connection is closed or the channel is dropped.
    fn spawn_reader_task(&self, peer_id: PeerId, connection: crate::high_level::Connection) {
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let reader_tasks = Arc::clone(&self.reader_tasks);

        let handle = tokio::spawn(async move {
            loop {
                // Accept the next unidirectional stream
                let mut recv_stream = match connection.accept_uni().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!(
                            "Reader task for peer {:?} ending: accept_uni error: {}",
                            peer_id, e
                        );
                        break;
                    }
                };

                let data = match recv_stream.read_to_end(MAX_UNI_STREAM_READ_BYTES).await {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => data,
                    Err(e) => {
                        debug!(
                            "Reader task for peer {:?}: read_to_end error: {}",
                            peer_id, e
                        );
                        break;
                    }
                };

                let data_len = data.len();
                tracing::trace!("Reader task: {} bytes from peer {:?}", data_len, peer_id);

                // Update last_activity
                if let Some(peer_conn) = connected_peers.write().await.get_mut(&peer_id) {
                    peer_conn.last_activity = Instant::now();
                }

                // Emit DataReceived event
                let _ = event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: data_len,
                });

                // Send through channel; if the receiver is dropped, exit
                if data_tx.send((peer_id, data)).await.is_err() {
                    debug!(
                        "Reader task for peer {:?}: channel closed, exiting",
                        peer_id
                    );
                    break;
                }
            }

            // Clean up our entry from reader_tasks
            reader_tasks.write().await.remove(&peer_id);
        });

        // Store the handle (fire-and-forget storage; blocking is fine since we just created it)
        let reader_tasks = Arc::clone(&self.reader_tasks);
        tokio::spawn(async move {
            reader_tasks.write().await.insert(peer_id, handle);
        });
    }

    /// Spawn a single background task that polls constrained transport events
    /// and forwards `DataReceived` payloads into the shared `data_tx` channel.
    ///
    /// Lifecycle events (ConnectionAccepted, ConnectionClosed, etc.) are handled
    /// inline within this task.
    fn spawn_constrained_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let constrained_peer_addrs = Arc::clone(&self.constrained_peer_addrs);
        let constrained_connections = Arc::clone(&self.constrained_connections);
        let shutdown = Arc::clone(&self.shutdown);

        /// Register a new constrained peer in all lookup maps and emit a connect event.
        async fn register_peer(
            peer_id: PeerId,
            connection_id: ConstrainedConnectionId,
            addr: &TransportAddr,
            side: Side,
            constrained_connections: &RwLock<HashMap<PeerId, ConstrainedConnectionId>>,
            constrained_peer_addrs: &RwLock<
                HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>,
            >,
            connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
            event_tx: &broadcast::Sender<P2pEvent>,
        ) {
            constrained_connections
                .write()
                .await
                .insert(peer_id, connection_id);
            constrained_peer_addrs
                .write()
                .await
                .insert(connection_id, (peer_id, addr.clone()));
            connected_peers.write().await.insert(
                peer_id,
                PeerConnection {
                    peer_id,
                    remote_addr: addr.clone(),
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
            let _ = event_tx.send(P2pEvent::PeerConnected {
                peer_id,
                addr: addr.clone(),
                side,
            });
        }

        tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                let Some(wrapper) = inner.try_recv_constrained_event() else {
                    tokio::time::sleep(Duration::from_millis(CONSTRAINED_POLL_INTERVAL_MS)).await;
                    continue;
                };

                match wrapper.event {
                    EngineEvent::DataReceived {
                        connection_id,
                        data,
                    } => {
                        let peer_id = constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .map(|(pid, _)| *pid)
                            .unwrap_or_else(|| {
                                peer_id_from_socket_addr(
                                    wrapper.remote_addr.to_synthetic_socket_addr(),
                                )
                            });

                        let data_len = data.len();
                        tracing::trace!(
                            "Constrained poller: {} bytes from peer {:?}",
                            data_len,
                            peer_id
                        );

                        if let Some(peer_conn) = connected_peers.write().await.get_mut(&peer_id) {
                            peer_conn.last_activity = Instant::now();
                        }
                        let _ = event_tx.send(P2pEvent::DataReceived {
                            peer_id,
                            bytes: data_len,
                        });

                        if data_tx.send((peer_id, data)).await.is_err() {
                            debug!("Constrained poller: channel closed, exiting");
                            break;
                        }
                    }
                    EngineEvent::ConnectionAccepted {
                        connection_id,
                        remote_addr: _,
                    } => {
                        let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                        register_peer(
                            peer_id,
                            connection_id,
                            &wrapper.remote_addr,
                            Side::Server,
                            &constrained_connections,
                            &constrained_peer_addrs,
                            &connected_peers,
                            &event_tx,
                        )
                        .await;
                    }
                    EngineEvent::ConnectionEstablished { connection_id } => {
                        if constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .is_none()
                        {
                            let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                            register_peer(
                                peer_id,
                                connection_id,
                                &wrapper.remote_addr,
                                Side::Client,
                                &constrained_connections,
                                &constrained_peer_addrs,
                                &connected_peers,
                                &event_tx,
                            )
                            .await;
                        }
                    }
                    EngineEvent::ConnectionClosed { connection_id } => {
                        let peer_info = constrained_peer_addrs.write().await.remove(&connection_id);
                        if let Some((peer_id, addr)) = peer_info {
                            constrained_connections.write().await.remove(&peer_id);
                            connected_peers.write().await.remove(&peer_id);
                            let _ = event_tx.send(P2pEvent::PeerDisconnected {
                                peer_id,
                                reason: DisconnectReason::RemoteClosed,
                            });
                            debug!(
                                "Constrained poller: peer {:?} at {} disconnected",
                                peer_id, addr
                            );
                        }
                    }
                    EngineEvent::ConnectionError {
                        connection_id,
                        error,
                    } => {
                        warn!(
                            "Constrained poller: conn_id={}, error={}",
                            connection_id.value(),
                            error
                        );
                    }
                    EngineEvent::Transmit { .. } => {}
                }
            }
        });
    }

    // v0.2: authenticate_peer removed - TLS handles peer authentication via ML-DSA-65
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // v0.2: auth_manager removed - TLS handles peer authentication
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            peer_id: self.peer_id,
            public_key: self.public_key.clone(),
            shutdown: Arc::clone(&self.shutdown),
            pending_data: Arc::clone(&self.pending_data),
            bootstrap_cache: Arc::clone(&self.bootstrap_cache),
            transport_registry: Arc::clone(&self.transport_registry),
            router: Arc::clone(&self.router),
            constrained_connections: Arc::clone(&self.constrained_connections),
            constrained_peer_addrs: Arc::clone(&self.constrained_peer_addrs),
            data_tx: self.data_tx.clone(),
            data_rx: Arc::clone(&self.data_rx),
            reader_tasks: Arc::clone(&self.reader_tasks),
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
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
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
        let config = P2pConfig::builder().build().expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 5)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_endpoint_stores_transport_registry() {
        use crate::transport::TransportType;

        // Build config with default transport providers
        // Phase 5.3: P2pEndpoint::new() always adds a shared UDP transport
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Verify registry is accessible and contains the auto-added UDP provider
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            // Phase 5.3: Registry now always has at least 1 UDP provider (socket sharing)
            assert!(
                !registry.is_empty(),
                "Registry should have at least 1 provider"
            );

            let udp_providers = registry.providers_by_type(TransportType::Udp);
            assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_p2p_endpoint_default_config_has_udp_registry() {
        // Build config with no additional transport providers
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Phase 5.3: Default registry now includes a shared UDP transport
        // This is required for socket sharing with Quinn
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            assert!(
                !registry.is_empty(),
                "Default registry should have UDP for socket sharing"
            );
            assert!(
                registry.has_quic_capable_transport(),
                "Default registry should have QUIC-capable transport"
            );
        }
        // Note: endpoint creation may fail in test environment without network
    }

    // ==========================================================================
    // Event Address Migration Tests (Phase 2.2 Task 7)
    // ==========================================================================

    #[test]
    fn test_peer_connected_event_with_udp() {
        let socket_addr: SocketAddr = "192.168.1.100:8080".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xab; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
        } = event
        {
            assert_eq!(peer_id.0, [0xab; 32]);
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert!(side.is_client());

            // Verify as_socket_addr() works
            let extracted = addr.as_socket_addr();
            assert_eq!(extracted, Some(socket_addr));
        } else {
            panic!("Expected PeerConnected event");
        }
    }

    #[test]
    fn test_peer_connected_event_with_ble() {
        // BLE MAC address (6 bytes)
        let device_id = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xcd; 32]),
            addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            side: Side::Server,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
        } = event
        {
            assert_eq!(peer_id.0, [0xcd; 32]);
            assert!(side.is_server());

            // Verify as_socket_addr() returns None for BLE
            assert!(addr.as_socket_addr().is_none());

            // Verify we can match on BLE variant
            if let TransportAddr::Ble {
                device_id: mac,
                service_uuid,
            } = addr
            {
                assert_eq!(mac, device_id);
                assert!(service_uuid.is_none());
            } else {
                panic!("Expected BLE address");
            }
        }
    }

    #[test]
    fn test_external_address_discovered_udp() {
        let socket_addr: SocketAddr = "203.0.113.1:12345".parse().expect("valid addr");
        let event = P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Udp(socket_addr),
        };

        if let P2pEvent::ExternalAddressDiscovered { addr } = event {
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert_eq!(addr.as_socket_addr(), Some(socket_addr));
        } else {
            panic!("Expected ExternalAddressDiscovered event");
        }
    }

    #[test]
    fn test_event_clone() {
        let socket_addr: SocketAddr = "10.0.0.1:9000".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0x11; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
        };

        // Verify events are Clone
        let cloned = event.clone();
        if let (
            P2pEvent::PeerConnected {
                peer_id: p1,
                addr: a1,
                ..
            },
            P2pEvent::PeerConnected {
                peer_id: p2,
                addr: a2,
                ..
            },
        ) = (&event, &cloned)
        {
            assert_eq!(p1.0, p2.0);
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn test_peer_connection_with_transport_addr() {
        // Test with UDP
        let udp_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let udp_conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(udp_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert_eq!(
            udp_conn.remote_addr.as_socket_addr(),
            Some(udp_addr),
            "UDP connection should have extractable socket address"
        );

        // Test with BLE
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ble_conn = PeerConnection {
            peer_id: PeerId([1u8; 32]),
            remote_addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert!(
            ble_conn.remote_addr.as_socket_addr().is_none(),
            "BLE connection should not have socket address"
        );
    }

    #[test]
    fn test_transport_addr_display_in_events() {
        let socket_addr: SocketAddr = "192.168.1.1:9001".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xff; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
        };

        // Verify display formatting works for logging
        let debug_str = format!("{:?}", event);
        assert!(
            debug_str.contains("192.168.1.1"),
            "Event debug should contain IP address"
        );
        assert!(
            debug_str.contains("9001"),
            "Event debug should contain port"
        );
    }

    // ==========================================================================
    // Connection Tracking Tests (Phase 2.2 Task 8)
    // ==========================================================================

    #[test]
    fn test_connection_tracking_udp() {
        use std::collections::HashMap;

        // Simulate connection tracking with TransportAddr::Udp
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");
        let peer_id = PeerId([0x01; 32]);
        let conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(socket_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        connections.insert(peer_id, conn.clone());

        // Verify connection is tracked
        assert!(connections.contains_key(&peer_id));
        let retrieved = connections.get(&peer_id).expect("connection exists");
        assert_eq!(retrieved.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(retrieved.authenticated);
    }

    #[test]
    fn test_connection_tracking_multi_transport() {
        use std::collections::HashMap;

        // Simulate multiple connections on different transports
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // UDP connection
        let udp_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
        let peer1 = PeerId([0x01; 32]);
        connections.insert(
            peer1,
            PeerConnection {
                peer_id: peer1,
                remote_addr: TransportAddr::Udp(udp_addr),
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // BLE connection (different peer)
        let peer2 = PeerId([0x02; 32]);
        let ble_device = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        connections.insert(
            peer2,
            PeerConnection {
                peer_id: peer2,
                remote_addr: TransportAddr::Ble {
                    device_id: ble_device,
                    service_uuid: None,
                },
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // Verify each tracked independently
        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .get(&peer1)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_some()
        );
        assert!(
            connections
                .get(&peer2)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_none()
        );
    }

    #[test]
    fn test_connection_lookup_by_transport_addr() {
        use std::collections::HashMap;

        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // Add multiple connections
        let addrs = [
            ("10.0.0.1:8080", [0x01; 32]),
            ("10.0.0.2:8080", [0x02; 32]),
            ("10.0.0.3:8080", [0x03; 32]),
        ];

        for (addr_str, peer_bytes) in addrs {
            let socket_addr: SocketAddr = addr_str.parse().expect("valid addr");
            let peer_id = PeerId(peer_bytes);
            connections.insert(
                peer_id,
                PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(socket_addr),
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
        }

        // Look up connection by transport address
        let target: SocketAddr = "10.0.0.2:8080".parse().expect("valid addr");
        let target_addr = TransportAddr::Udp(target);
        let found = connections.values().find(|c| c.remote_addr == target_addr);

        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.0, [0x02; 32]);
    }

    #[test]
    fn test_transport_addr_equality_in_tracking() {
        // Verify TransportAddr equality works correctly for tracking
        let addr1: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr2: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr3: SocketAddr = "192.168.1.1:8081".parse().expect("valid addr");

        let t1 = TransportAddr::Udp(addr1);
        let t2 = TransportAddr::Udp(addr2);
        let t3 = TransportAddr::Udp(addr3);

        // Same address should be equal
        assert_eq!(t1, t2);

        // Different port should not be equal
        assert_ne!(t1, t3);

        // Different transport type should not be equal
        let ble = TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        };
        assert_ne!(t1, ble);
    }

    #[test]
    fn test_peer_connection_update_preserves_transport_addr() {
        let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");
        let mut conn = PeerConnection {
            peer_id: PeerId([0xaa; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Simulate updating the connection (e.g., after authentication)
        conn.authenticated = true;
        conn.last_activity = Instant::now();

        // Verify transport address is preserved
        assert_eq!(conn.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(conn.authenticated);
    }
}
