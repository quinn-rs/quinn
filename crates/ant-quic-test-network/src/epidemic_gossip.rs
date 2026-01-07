//! True Epidemic Gossip Integration using saorsa-gossip
//!
//! This module replaces the passive gossip implementation with full
//! saorsa-gossip integration using HyParView + SWIM + Plumtree.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    EpidemicGossip                                │
//! ├──────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
//! │  │ AntQuicTransport│  │ HyParView       │  │ PlumtreePubSub  │  │
//! │  │ (networking)    │  │ (membership)    │  │ (broadcast)     │  │
//! │  │                 │  │                 │  │                 │  │
//! │  │ - dial()        │  │ - active_view   │  │ - publish()     │  │
//! │  │ - listen()      │  │ - passive_view  │  │ - subscribe()   │  │
//! │  │ - send_to_peer  │  │ - SWIM detector │  │ - eager push    │  │
//! │  └────────┬────────┘  └────────┬────────┘  │ - lazy IHAVE    │  │
//! │           │                    │           └────────┬────────┘  │
//! │           └────────────────────┴────────────────────┘           │
//! │                              │                                   │
//! │                              ▼                                   │
//! │                    ┌─────────────────┐                          │
//! │                    │  Event Channel  │ ──► Registry Heartbeats  │
//! │                    └─────────────────┘                          │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Events
//!
//! Events are pushed to the registry via heartbeats:
//! - `peer_joined`: New peer discovered via HyParView
//! - `peer_left`: Peer marked dead by SWIM
//! - `message_received`: Gossip message via Plumtree

pub use ::bytes::Bytes; // Re-export for use by client.rs
use saorsa_gossip_identity::MlDsaKeyPair;
use saorsa_gossip_membership::{HyParViewMembership, Membership, PeerState};
use saorsa_gossip_pubsub::{PlumtreePubSub, PubSub};
use saorsa_gossip_transport::{
    AntQuicTransport, AntQuicTransportConfig, GossipTransport, StreamType,
};
use saorsa_gossip_types::{PeerId, TopicId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

/// The network topic for ant-quic-test-network gossip.
pub const NETWORK_TOPIC: &str = "ant-quic-test-network";

/// Events emitted by the epidemic gossip layer.
#[derive(Debug, Clone)]
pub enum EpidemicEvent {
    /// A new peer joined the network (added to active or passive view).
    PeerJoined {
        peer_id: PeerId,
        addresses: Vec<SocketAddr>,
    },
    /// A peer left the network (SWIM marked as dead).
    PeerLeft { peer_id: PeerId },
    /// A peer is suspected (SWIM marked as suspect).
    PeerSuspect { peer_id: PeerId },
    /// A peer's SWIM status changed back to alive.
    PeerAlive { peer_id: PeerId },
    /// A gossip message was received.
    MessageReceived {
        from: PeerId,
        topic: TopicId,
        payload: Vec<u8>,
    },
    /// Connection type determined for a peer.
    ConnectionType {
        peer_id: PeerId,
        connection_type: ConnectionType,
    },
    /// A peer's address was discovered or updated.
    ///
    /// This event is emitted when we learn a peer's address, either from
    /// a new connection or from gossip messages. Applications can subscribe
    /// to this event to get addresses for direct P2P connections.
    AddressDiscovered {
        peer_id: PeerId,
        address: SocketAddr,
    },
}

/// Connection type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Direct IPv4 connection.
    DirectIpv4,
    /// Direct IPv6 connection.
    DirectIpv6,
    /// Connection established via hole-punching.
    HolePunched,
    /// Connection via relay.
    Relayed,
    /// Unknown or not yet determined.
    Unknown,
}

/// Statistics for HyParView membership.
#[derive(Debug, Clone, Default)]
pub struct HyParViewStats {
    /// Number of peers in active view.
    pub active_view_size: usize,
    /// Number of peers in passive view.
    pub passive_view_size: usize,
    /// Total shuffles performed.
    pub shuffles: u64,
    /// Total joins processed.
    pub joins: u64,
}

/// Statistics for SWIM failure detection.
#[derive(Debug, Clone, Default)]
pub struct SwimStats {
    /// Peers currently alive.
    pub alive_count: usize,
    /// Peers currently suspected.
    pub suspect_count: usize,
    /// Peers declared dead.
    pub dead_count: usize,
    /// Total pings sent.
    pub pings_sent: u64,
    /// Total acks received.
    pub acks_received: u64,
}

/// Statistics for Plumtree broadcast.
#[derive(Debug, Clone, Default)]
pub struct PlumtreeStats {
    /// Peers receiving eager pushes.
    pub eager_peers: usize,
    /// Peers receiving lazy IHAVEs.
    pub lazy_peers: usize,
    /// Messages sent.
    pub messages_sent: u64,
    /// Messages received.
    pub messages_received: u64,
    /// Duplicate messages (already seen).
    pub duplicates: u64,
    /// Grafts performed (promoted lazy to eager).
    pub grafts: u64,
    /// Prunes performed (demoted eager to lazy).
    pub prunes: u64,
}

/// Combined gossip statistics for registry reporting.
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    /// HyParView membership stats.
    pub hyparview: HyParViewStats,
    /// SWIM failure detection stats.
    pub swim: SwimStats,
    /// Plumtree broadcast stats.
    pub plumtree: PlumtreeStats,
    /// Connection type breakdown.
    pub connection_types: ConnectionBreakdown,
}

/// Breakdown of connection types.
#[derive(Debug, Clone, Default)]
pub struct ConnectionBreakdown {
    /// Direct IPv4 connections.
    pub direct_ipv4: usize,
    /// Direct IPv6 connections.
    pub direct_ipv6: usize,
    /// Hole-punched connections.
    pub hole_punched: usize,
    /// Relayed connections.
    pub relayed: usize,
}

/// Configuration for the epidemic gossip layer.
#[derive(Debug, Clone)]
pub struct EpidemicConfig {
    /// Listen address for gossip connections.
    pub listen_addr: SocketAddr,
    /// Bootstrap peers to connect to initially.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Maximum active view size (HyParView).
    pub max_active: usize,
    /// Maximum passive view size (HyParView).
    pub max_passive: usize,
    /// SWIM probe interval.
    pub swim_interval: Duration,
    /// SWIM suspect timeout.
    pub suspect_timeout: Duration,
    /// Registry URL for heartbeat reporting.
    pub registry_url: Option<String>,
    /// Optional ML-DSA keypair bytes (public_key, secret_key) for identity persistence.
    /// If provided, the transport will use this keypair to ensure the gossip layer's
    /// peer ID matches the application's identity peer ID.
    pub keypair: Option<(Vec<u8>, Vec<u8>)>,
}

impl Default for EpidemicConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid default addr"),
            bootstrap_peers: Vec::new(),
            max_active: 8,
            max_passive: 64,
            swim_interval: Duration::from_secs(1),
            suspect_timeout: Duration::from_secs(5),
            registry_url: None,
            keypair: None,
        }
    }
}

/// Internal state holding the gossip stack components.
struct GossipStack {
    /// The ant-quic transport layer.
    #[allow(dead_code)] // Kept for future use (e.g., direct peer connections)
    transport: Arc<AntQuicTransport>,
    /// HyParView membership management.
    membership: Arc<HyParViewMembership<AntQuicTransport>>,
    /// Plumtree pub/sub for message broadcast.
    pubsub: Arc<PlumtreePubSub<AntQuicTransport>>,
}

/// True epidemic gossip layer using saorsa-gossip.
///
/// This replaces the passive `GossipDiscovery` with active epidemic broadcast.
pub struct EpidemicGossip {
    /// Our peer ID.
    peer_id: PeerId,
    /// Configuration.
    config: EpidemicConfig,
    /// Event channel sender.
    event_tx: mpsc::Sender<EpidemicEvent>,
    /// Statistics (updated periodically).
    stats: Arc<RwLock<GossipStats>>,
    /// Connection types per peer.
    connection_types: Arc<RwLock<HashMap<PeerId, ConnectionType>>>,
    /// Whether the gossip layer is running.
    running: Arc<std::sync::atomic::AtomicBool>,
    /// The gossip stack (initialized on start).
    stack: Arc<RwLock<Option<GossipStack>>>,
}

impl EpidemicGossip {
    /// Create a new epidemic gossip layer.
    ///
    /// # Arguments
    /// * `peer_id` - Our peer ID (32-byte BLAKE3 hash)
    /// * `config` - Gossip configuration
    /// * `event_tx` - Channel to send gossip events
    pub fn new(
        peer_id: PeerId,
        config: EpidemicConfig,
        event_tx: mpsc::Sender<EpidemicEvent>,
    ) -> Self {
        Self {
            peer_id,
            config,
            event_tx,
            stats: Arc::new(RwLock::new(GossipStats::default())),
            connection_types: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stack: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the gossip layer.
    ///
    /// This initializes:
    /// 1. AntQuicTransport for networking
    /// 2. HyParViewMembership for peer management
    /// 3. SwimDetector for failure detection (part of HyParView)
    /// 4. PlumtreePubSub for message broadcast
    pub async fn start(&self) -> Result<(), GossipError> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(GossipError::AlreadyRunning);
        }

        info!(
            "Starting epidemic gossip on {} with {} bootstrap peers",
            self.config.listen_addr,
            self.config.bootstrap_peers.len()
        );

        // Create transport configuration
        let mut transport_config = AntQuicTransportConfig::new(
            self.config.listen_addr,
            self.config.bootstrap_peers.clone(),
        );

        if let Some((pub_key, sec_key)) = &self.config.keypair {
            transport_config = transport_config.with_keypair(pub_key.clone(), sec_key.clone());
            info!("Using provided keypair for gossip transport identity");
        }

        // Create the AntQuicTransport
        let transport = AntQuicTransport::with_config(transport_config, None)
            .await
            .map_err(|e| GossipError::Transport(e.to_string()))?;

        // CRITICAL: Start listening for incoming connections
        // Without this, other nodes cannot connect to us!
        transport
            .listen(self.config.listen_addr)
            .await
            .map_err(|e| GossipError::Transport(format!("Failed to listen: {e}")))?;
        info!(
            "Transport listening on {} for incoming gossip connections",
            self.config.listen_addr
        );

        let transport = Arc::new(transport);
        info!("Transport initialized, peer ID: {:?}", self.peer_id);

        // Create HyParView membership with SWIM failure detection
        let membership = Arc::new(HyParViewMembership::new(
            self.config.max_active,
            self.config.max_passive,
            transport.clone(),
        ));
        info!(
            "HyParView initialized: max_active={}, max_passive={}",
            self.config.max_active, self.config.max_passive
        );

        // Generate signing key for Plumtree message authentication
        let signing_key = MlDsaKeyPair::generate()
            .map_err(|e| GossipError::Transport(format!("Failed to generate signing key: {e}")))?;
        info!("Generated ML-DSA-65 signing key for message authentication");

        // Create Plumtree pub/sub
        // PlumtreePubSub requires: peer_id, Arc<GossipTransport>, MlDsaKeyPair
        let pubsub = Arc::new(PlumtreePubSub::new(
            self.peer_id,
            transport.clone(),
            signing_key,
        ));
        info!("Plumtree pub/sub initialized");

        // Subscribe to the network topic
        let topic = TopicId::from_entity(NETWORK_TOPIC)
            .map_err(|e| GossipError::Transport(format!("Invalid topic: {e}")))?;
        let message_receiver = pubsub.subscribe(topic);
        info!("Subscribed to topic: {}", NETWORK_TOPIC);

        // Store the stack
        {
            let mut stack_guard = self.stack.write().await;
            *stack_guard = Some(GossipStack {
                transport,
                membership,
                pubsub,
            });
        }

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Spawn background tasks
        self.spawn_stats_updater();
        self.spawn_event_monitor();
        self.spawn_message_receiver(message_receiver);

        info!("Epidemic gossip started successfully");
        Ok(())
    }

    /// Stop the gossip layer.
    pub async fn stop(&self) {
        info!("Stopping epidemic gossip");
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Clear the stack
        let mut stack_guard = self.stack.write().await;
        *stack_guard = None;
    }

    /// Check if the gossip layer is running.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get current gossip statistics.
    pub async fn stats(&self) -> GossipStats {
        self.stats.read().await.clone()
    }

    /// Get our peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Publish a message to the network topic.
    pub async fn publish(&self, payload: Vec<u8>) -> Result<(), GossipError> {
        if !self.is_running() {
            return Err(GossipError::NotRunning);
        }

        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        let topic = TopicId::from_entity(NETWORK_TOPIC)
            .map_err(|e| GossipError::Publish(format!("Invalid topic: {e}")))?;
        stack
            .pubsub
            .publish(topic, payload.into())
            .await
            .map_err(|e| GossipError::Publish(e.to_string()))?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.plumtree.messages_sent += 1;
        }

        Ok(())
    }

    /// Get the active view (directly connected peers).
    pub async fn active_view(&self) -> Vec<PeerId> {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            stack.membership.active_view()
        } else {
            Vec::new()
        }
    }

    /// Get the passive view (known but not connected peers).
    pub async fn passive_view(&self) -> Vec<PeerId> {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            stack.membership.passive_view()
        } else {
            Vec::new()
        }
    }

    /// Get SWIM state for a peer.
    pub async fn peer_state(&self, peer_id: &PeerId) -> Option<PeerState> {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            stack.membership.swim().get_state(peer_id).await
        } else {
            None
        }
    }

    /// Get connection type for a peer.
    pub async fn connection_type(&self, peer_id: &PeerId) -> ConnectionType {
        self.connection_types
            .read()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or(ConnectionType::Unknown)
    }

    /// Set connection type for a peer.
    pub async fn set_connection_type(&self, peer_id: PeerId, conn_type: ConnectionType) {
        self.connection_types
            .write()
            .await
            .insert(peer_id, conn_type);

        // Emit event
        let _ = self
            .event_tx
            .send(EpidemicEvent::ConnectionType {
                peer_id,
                connection_type: conn_type,
            })
            .await;
    }

    /// Get the address for a specific connected peer.
    ///
    /// This queries the gossip transport for the peer's current address.
    /// Returns `None` if the peer is not currently connected.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(addr) = gossip.get_peer_address(&peer_id).await {
    ///     // Connect directly via P2pEndpoint or MASQUE
    ///     p2p_endpoint.connect(addr).await?;
    /// }
    /// ```
    pub async fn get_peer_address(&self, peer_id: &PeerId) -> Option<SocketAddr> {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            let peers = stack.transport.connected_peers().await;
            peers
                .into_iter()
                .find(|(id, _)| id == peer_id)
                .map(|(_, addr)| addr)
        } else {
            None
        }
    }

    /// Get all connected peers with their addresses.
    ///
    /// This returns the current gossip transport connections, which can be used
    /// to establish direct P2P connections for applications like video conferencing.
    ///
    /// # Returns
    ///
    /// A vector of `(PeerId, SocketAddr)` pairs for all peers currently connected
    /// via the gossip transport (HyParView active view).
    pub async fn connected_peers_with_addresses(&self) -> Vec<(PeerId, SocketAddr)> {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            stack.transport.connected_peers().await
        } else {
            Vec::new()
        }
    }

    /// Get SWIM liveness status for all known peers.
    ///
    /// Returns a snapshot of which peers are alive, suspect, or dead
    /// according to SWIM failure detection.
    pub async fn peer_liveness(&self) -> (Vec<PeerId>, Vec<PeerId>, Vec<PeerId>) {
        let stack_guard = self.stack.read().await;
        if let Some(stack) = stack_guard.as_ref() {
            let active = stack.membership.active_view();
            let passive = stack.membership.passive_view();
            let all_peers: Vec<_> = active.iter().chain(passive.iter()).cloned().collect();

            let mut alive = Vec::new();
            let mut suspect = Vec::new();
            let mut dead = Vec::new();

            for peer in all_peers {
                if let Some(state) = stack.membership.swim().get_state(&peer).await {
                    match state {
                        PeerState::Alive => alive.push(peer),
                        PeerState::Suspect => suspect.push(peer),
                        PeerState::Dead => dead.push(peer),
                    }
                }
            }

            (alive, suspect, dead)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        }
    }

    /// Bootstrap from known peers.
    ///
    /// NOTE: We use `transport.dial_bootstrap()` directly instead of `membership.join()`
    /// because saorsa-gossip-membership v0.1.12's join() is incomplete (has TODO: transport).
    pub async fn bootstrap(&self) -> Result<usize, GossipError> {
        if !self.is_running() {
            return Err(GossipError::NotRunning);
        }

        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        if self.config.bootstrap_peers.is_empty() {
            debug!("No bootstrap peers configured");
            return Ok(0);
        }

        info!(
            "Bootstrapping from {} peers: {:?}",
            self.config.bootstrap_peers.len(),
            self.config.bootstrap_peers
        );

        // WORKAROUND: saorsa-gossip-membership v0.1.12's join() method is incomplete.
        // It logs "(TODO: transport)" and doesn't actually dial the seeds.
        // Instead, we use transport.dial_bootstrap() directly to connect to each peer,
        // then add them to the active view.
        let mut connected = 0;
        for addr in &self.config.bootstrap_peers {
            info!("Dialing bootstrap peer at {}", addr);
            match stack.transport.dial_bootstrap(*addr).await {
                Ok(peer_id) => {
                    info!("Connected to bootstrap peer {} ({})", peer_id, addr);
                    // Add to active view
                    if let Err(e) = stack.membership.add_active(peer_id).await {
                        warn!("Failed to add peer {} to active view: {}", peer_id, e);
                    } else {
                        info!("Added peer {} to HyParView active view", peer_id);
                        connected += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to dial bootstrap peer {}: {}", addr, e);
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.hyparview.joins += 1;
        }

        if connected > 0 {
            info!(
                "Bootstrap complete: connected to {}/{} peers",
                connected,
                self.config.bootstrap_peers.len()
            );
        } else {
            warn!(
                "Bootstrap failed: could not connect to any of {} peers",
                self.config.bootstrap_peers.len()
            );
        }

        Ok(connected)
    }

    /// Add bootstrap peers dynamically (e.g., from registry) and trigger join.
    ///
    /// This is called after registration when we have peer addresses from the registry.
    /// The peers are joined to the HyParView overlay network.
    ///
    /// NOTE: We use `transport.dial_bootstrap()` directly instead of `membership.join()`
    /// because saorsa-gossip-membership v0.1.12's join() is incomplete (has TODO: transport).
    pub async fn add_bootstrap_peers(&self, peers: Vec<SocketAddr>) -> Result<usize, GossipError> {
        if !self.is_running() {
            return Err(GossipError::NotRunning);
        }

        if peers.is_empty() {
            debug!("No peers to add");
            return Ok(0);
        }

        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        info!(
            "Adding {} bootstrap peers from registry: {:?}",
            peers.len(),
            peers
        );

        // WORKAROUND: saorsa-gossip-membership v0.1.12's join() method is incomplete.
        // It logs "(TODO: transport)" and doesn't actually dial the seeds.
        // Instead, we use transport.dial_bootstrap() directly to connect to each peer,
        // then add them to the active view.
        let mut connected = 0;
        for addr in &peers {
            info!("Dialing bootstrap peer at {}", addr);
            match stack.transport.dial_bootstrap(*addr).await {
                Ok(peer_id) => {
                    info!("Connected to bootstrap peer {} ({})", peer_id, addr);
                    // Add to active view
                    if let Err(e) = stack.membership.add_active(peer_id).await {
                        warn!("Failed to add peer {} to active view: {}", peer_id, e);
                    } else {
                        info!("Added peer {} to HyParView active view", peer_id);
                        connected += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to dial bootstrap peer {}: {}", addr, e);
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.hyparview.joins += 1;
        }

        if connected > 0 {
            info!(
                "Successfully connected to {}/{} bootstrap peers, added to HyParView active view",
                connected,
                peers.len()
            );
        } else {
            warn!(
                "Failed to connect to any of {} bootstrap peers",
                peers.len()
            );
        }
        Ok(connected)
    }

    /// Add a peer to the active view.
    pub async fn add_peer(&self, peer_id: PeerId) -> Result<(), GossipError> {
        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        stack
            .membership
            .add_active(peer_id)
            .await
            .map_err(|e| GossipError::Membership(e.to_string()))?;

        // Emit event
        let _ = self
            .event_tx
            .send(EpidemicEvent::PeerJoined {
                peer_id,
                addresses: vec![], // Will be filled by transport
            })
            .await;

        Ok(())
    }

    /// Remove a peer from the active view.
    pub async fn remove_peer(&self, peer_id: PeerId) -> Result<(), GossipError> {
        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        stack
            .membership
            .remove_active(peer_id)
            .await
            .map_err(|e| GossipError::Membership(e.to_string()))?;

        // Emit event
        let _ = self
            .event_tx
            .send(EpidemicEvent::PeerLeft { peer_id })
            .await;

        Ok(())
    }

    /// Send data to a peer using the gossip transport.
    /// This bypasses the P2pEndpoint and uses the gossip connections directly,
    /// which uses the port configured via --bind-port (or random if 0).
    pub async fn send_to_peer(&self, peer_id: PeerId, data: Vec<u8>) -> Result<(), GossipError> {
        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;

        stack
            .transport
            .send_to_peer(peer_id, StreamType::Bulk, Bytes::from(data))
            .await
            .map_err(|e| GossipError::Transport(e.to_string()))?;

        Ok(())
    }

    /// Send data to a peer with relay fallback.
    ///
    /// Tries direct send first. If that fails (peer not in active view),
    /// attempts to relay through peers in our active view.
    ///
    /// The relay message includes the target peer ID so intermediate nodes
    /// can forward it to the final destination.
    pub async fn send_to_peer_with_relay(
        &self,
        target_peer_id: PeerId,
        data: Vec<u8>,
    ) -> Result<(), GossipError> {
        // Try direct send first
        match self.send_to_peer(target_peer_id, data.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(
                    "Direct send failed to {}: {}, trying relay",
                    hex::encode(&target_peer_id.as_bytes()[..4]),
                    e
                );
            }
        }

        // Get active view for potential relay peers
        let active_peers = self.active_view().await;
        if active_peers.is_empty() {
            return Err(GossipError::Transport(
                "No peers in active view for relay".to_string(),
            ));
        }

        // Create a relay message with target peer ID prefix
        // Format: [RELAY_MAGIC:4][TARGET_PEER_ID:32][DATA:...]
        const RELAY_MAGIC: &[u8] = b"RELY";
        let mut relay_message = Vec::with_capacity(4 + 32 + data.len());
        relay_message.extend_from_slice(RELAY_MAGIC);
        relay_message.extend_from_slice(target_peer_id.as_bytes());
        relay_message.extend_from_slice(&data);

        // Try each active peer as a potential relay
        for relay_peer in &active_peers {
            // Skip if relay peer is the target
            if relay_peer == &target_peer_id {
                continue;
            }

            match self.send_to_peer(*relay_peer, relay_message.clone()).await {
                Ok(()) => {
                    info!(
                        "Relayed message to {} through {}",
                        hex::encode(&target_peer_id.as_bytes()[..4]),
                        hex::encode(&relay_peer.as_bytes()[..4])
                    );
                    return Ok(());
                }
                Err(e) => {
                    debug!(
                        "Relay through {} failed: {}",
                        hex::encode(&relay_peer.as_bytes()[..4]),
                        e
                    );
                }
            }
        }

        Err(GossipError::Transport(format!(
            "Failed to reach {} via direct or relay (tried {} peers)",
            hex::encode(&target_peer_id.as_bytes()[..4]),
            active_peers.len()
        )))
    }

    /// Check if a message is a relay message and extract the target peer ID.
    ///
    /// Returns Some((target_peer_id, payload)) if this is a relay message,
    /// or None if it's a direct message.
    pub fn parse_relay_message(data: &[u8]) -> Option<(PeerId, &[u8])> {
        const RELAY_MAGIC: &[u8] = b"RELY";

        if data.len() < 4 + 32 {
            return None;
        }

        if &data[..4] != RELAY_MAGIC {
            return None;
        }

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(&data[4..36]);

        Some((PeerId::new(peer_id_bytes), &data[36..]))
    }

    /// Handle a received relay message by forwarding to the target peer.
    ///
    /// Call this when receiving data that might be a relay message.
    /// Returns Ok(true) if it was a relay message and was forwarded,
    /// Ok(false) if it wasn't a relay message.
    pub async fn handle_relay_message(&self, data: &[u8]) -> Result<bool, GossipError> {
        let (target_peer_id, payload) = match Self::parse_relay_message(data) {
            Some(parsed) => parsed,
            None => return Ok(false), // Not a relay message
        };

        info!(
            "Forwarding relay message to {}",
            hex::encode(&target_peer_id.as_bytes()[..4])
        );

        // Try to forward to the target
        self.send_to_peer(target_peer_id, payload.to_vec()).await?;

        Ok(true)
    }

    /// Get the transport for direct access to QUIC connections.
    pub async fn transport(&self) -> Result<Arc<AntQuicTransport>, GossipError> {
        let stack_guard = self.stack.read().await;
        let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
        Ok(stack.transport.clone())
    }

    /// Get the transport's peer ID (the actual identity used for gossip connections).
    ///
    /// IMPORTANT: This returns the gossip transport's peer ID which is DIFFERENT from
    /// the peer ID passed to EpidemicGossip::new(). The transport generates its own
    /// identity. Use this peer ID for registry registration to ensure consistency
    /// with HyParView's active/passive views.
    pub async fn transport_peer_id(&self) -> Result<PeerId, GossipError> {
        let transport = self.transport().await?;
        Ok(transport.peer_id())
    }

    /// Spawn background task to update statistics periodically.
    fn spawn_stats_updater(&self) {
        let stats = self.stats.clone();
        let stack = self.stack.clone();
        let running = self.running.clone();
        let connection_types = self.connection_types.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }

                // Extract Arc refs from stack - clone Arcs to release lock quickly
                let stack_refs = {
                    let stack_guard = stack.read().await;
                    stack_guard
                        .as_ref()
                        .map(|s| (Arc::clone(&s.membership), Arc::clone(&s.transport)))
                };

                if let Some((membership, transport)) = stack_refs {
                    let active = membership.active_view();
                    let passive = membership.passive_view();
                    let mut alive_count = 0;
                    let mut suspect_count = 0;
                    let mut dead_count = 0;

                    for peer in &active {
                        if let Some(state) = membership.swim().get_state(peer).await {
                            match state {
                                PeerState::Alive => alive_count += 1,
                                PeerState::Suspect => suspect_count += 1,
                                PeerState::Dead => dead_count += 1,
                            }
                        }
                    }

                    let connected_peers = transport.connected_peers().await;
                    let mut breakdown = ConnectionBreakdown::default();

                    {
                        let mut conn_types = connection_types.write().await;
                        for (peer_id, addr) in &connected_peers {
                            let inferred_type = if addr.is_ipv4() {
                                ConnectionType::DirectIpv4
                            } else {
                                ConnectionType::DirectIpv6
                            };
                            conn_types.insert(*peer_id, inferred_type);

                            match inferred_type {
                                ConnectionType::DirectIpv4 => breakdown.direct_ipv4 += 1,
                                ConnectionType::DirectIpv6 => breakdown.direct_ipv6 += 1,
                                ConnectionType::HolePunched => breakdown.hole_punched += 1,
                                ConnectionType::Relayed => breakdown.relayed += 1,
                                ConnectionType::Unknown => {}
                            }
                        }
                    }

                    let mut stats_guard = stats.write().await;
                    stats_guard.hyparview.active_view_size = active.len();
                    stats_guard.hyparview.passive_view_size = passive.len();
                    stats_guard.swim.alive_count = alive_count;
                    stats_guard.swim.suspect_count = suspect_count;
                    stats_guard.swim.dead_count = dead_count;
                    stats_guard.connection_types = breakdown;

                    debug!(
                        "Stats updated: active={}, passive={}, alive={}, suspect={}, dead={}",
                        active.len(),
                        passive.len(),
                        alive_count,
                        suspect_count,
                        dead_count
                    );
                }
            }
        });
    }

    /// Spawn background task to monitor for events.
    fn spawn_event_monitor(&self) {
        let event_tx = self.event_tx.clone();
        let stack = self.stack.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;

                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }

                // Clone Arc to release lock quickly - prevents deadlock
                let membership = {
                    let stack_guard = stack.read().await;
                    stack_guard.as_ref().map(|s| Arc::clone(&s.membership))
                };

                if let Some(membership) = membership {
                    let dead_peers = membership.swim().get_peers_in_state(PeerState::Dead).await;
                    for peer_id in dead_peers {
                        if let Err(e) = event_tx.try_send(EpidemicEvent::PeerLeft { peer_id }) {
                            debug!("Channel full, dropping PeerLeft event: {}", e);
                        }
                    }

                    let suspect_peers = membership
                        .swim()
                        .get_peers_in_state(PeerState::Suspect)
                        .await;
                    for peer_id in suspect_peers {
                        if let Err(e) = event_tx.try_send(EpidemicEvent::PeerSuspect { peer_id }) {
                            debug!("Channel full, dropping PeerSuspect event: {}", e);
                        }
                    }
                }
            }
        });
    }

    fn spawn_message_receiver(
        &self,
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<(PeerId, bytes::Bytes)>,
    ) {
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let stats = self.stats.clone();

        let topic = match TopicId::from_entity(NETWORK_TOPIC) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to create topic for message receiver: {}", e);
                return;
            }
        };

        tokio::spawn(async move {
            info!("Gossip message receiver started");
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::select! {
                    Some((from_peer, data)) = receiver.recv() => {
                        debug!(
                            "Received gossip message from {:?} ({} bytes)",
                            from_peer,
                            data.len()
                        );

                        {
                            let mut stats_guard = stats.write().await;
                            stats_guard.plumtree.messages_received += 1;
                        }

                        if let Err(e) = event_tx
                            .send(EpidemicEvent::MessageReceived {
                                from: from_peer,
                                topic,
                                payload: data.to_vec(),
                            })
                            .await
                        {
                            debug!("Failed to forward gossip message to event channel: {}", e);
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        continue;
                    }
                }
            }
            info!("Message receiver task stopped");
        });
    }
}

/// Errors from the epidemic gossip layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipError {
    /// The gossip layer is already running.
    AlreadyRunning,
    /// The gossip layer is not running.
    NotRunning,
    /// Transport error.
    Transport(String),
    /// Membership error.
    Membership(String),
    /// Publish error.
    Publish(String),
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipError::AlreadyRunning => write!(f, "gossip layer already running"),
            GossipError::NotRunning => write!(f, "gossip layer not running"),
            GossipError::Transport(e) => write!(f, "transport error: {}", e),
            GossipError::Membership(e) => write!(f, "membership error: {}", e),
            GossipError::Publish(e) => write!(f, "publish error: {}", e),
        }
    }
}

impl std::error::Error for GossipError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id() -> PeerId {
        PeerId::new([0u8; 32])
    }

    fn test_config() -> EpidemicConfig {
        EpidemicConfig::default()
    }

    // ============================================================
    // PROOF POINT 1: Initialization Tests
    // ============================================================

    #[tokio::test]
    async fn test_epidemic_gossip_creation() {
        let (tx, _rx) = mpsc::channel(100);
        let peer_id = test_peer_id();
        let config = test_config();

        let gossip = EpidemicGossip::new(peer_id, config, tx);

        assert!(!gossip.is_running());
        assert_eq!(gossip.peer_id(), &test_peer_id());
    }

    #[tokio::test]
    async fn test_epidemic_gossip_initial_stats() {
        let (tx, _rx) = mpsc::channel(100);
        let gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx);

        let stats = gossip.stats().await;

        assert_eq!(stats.hyparview.active_view_size, 0);
        assert_eq!(stats.hyparview.passive_view_size, 0);
        assert_eq!(stats.swim.alive_count, 0);
        assert_eq!(stats.plumtree.messages_sent, 0);
    }

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_epidemic_gossip_start_and_stop() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        // Start should succeed
        let result = gossip.start().await;
        assert!(result.is_ok(), "Start failed: {:?}", result.err());
        assert!(gossip.is_running());

        // Starting again should fail
        let result2 = gossip.start().await;
        assert_eq!(result2, Err(GossipError::AlreadyRunning));

        // Stop
        gossip.stop().await;
        assert!(!gossip.is_running());
    }

    // ============================================================
    // PROOF POINT 2: HyParView Membership Tests
    // ============================================================

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_active_view_empty_initially() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.start().await.unwrap();
        let active = gossip.active_view().await;
        assert!(active.is_empty());

        gossip.stop().await;
    }

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_passive_view_empty_initially() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.start().await.unwrap();
        let passive = gossip.passive_view().await;
        assert!(passive.is_empty());

        gossip.stop().await;
    }

    // ============================================================
    // PROOF POINT 3: SWIM Failure Detection Tests
    // ============================================================

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_peer_state_unknown_peer() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.start().await.unwrap();

        let unknown_peer = PeerId::new([1u8; 32]);
        let state = gossip.peer_state(&unknown_peer).await;
        assert!(state.is_none());

        gossip.stop().await;
    }

    // ============================================================
    // PROOF POINT 4: Plumtree Broadcast Tests
    // ============================================================

    #[tokio::test]
    async fn test_publish_when_not_running() {
        let (tx, _rx) = mpsc::channel(100);
        let gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx);

        let result = gossip.publish(vec![1, 2, 3]).await;

        assert_eq!(result, Err(GossipError::NotRunning));
    }

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_publish_when_running() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.start().await.unwrap();

        // Publish should succeed (even without peers)
        let result = gossip.publish(vec![1, 2, 3]).await;
        assert!(result.is_ok());

        // Check stats updated
        let stats = gossip.stats().await;
        assert_eq!(stats.plumtree.messages_sent, 1);

        gossip.stop().await;
    }

    // ============================================================
    // PROOF POINT 5: Connection Type Tracking Tests
    // ============================================================

    #[tokio::test]
    async fn test_connection_type_unknown_initially() {
        let (tx, _rx) = mpsc::channel(100);
        let gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx);

        let peer = PeerId::new([2u8; 32]);
        let conn_type = gossip.connection_type(&peer).await;

        assert_eq!(conn_type, ConnectionType::Unknown);
    }

    #[tokio::test]
    async fn test_set_connection_type() {
        let (tx, mut rx) = mpsc::channel(100);
        let gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx);

        let peer = PeerId::new([2u8; 32]);
        gossip
            .set_connection_type(peer, ConnectionType::DirectIpv4)
            .await;

        // Check it was set
        let conn_type = gossip.connection_type(&peer).await;
        assert_eq!(conn_type, ConnectionType::DirectIpv4);

        // Check event was emitted
        let event = rx.recv().await.unwrap();
        match event {
            EpidemicEvent::ConnectionType {
                peer_id,
                connection_type,
            } => {
                assert_eq!(peer_id, peer);
                assert_eq!(connection_type, ConnectionType::DirectIpv4);
            }
            _ => panic!("unexpected event type"),
        }
    }

    // ============================================================
    // PROOF POINT 6: Event Emission Tests
    // ============================================================

    #[tokio::test]
    async fn test_event_channel_creation() {
        let (tx, mut rx) = mpsc::channel(100);
        let _gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx.clone());

        // Send a test event
        tx.send(EpidemicEvent::PeerJoined {
            peer_id: PeerId::new([3u8; 32]),
            addresses: vec!["192.168.1.1:9000".parse().unwrap()],
        })
        .await
        .unwrap();

        // Verify event is received
        let event = rx.recv().await.unwrap();
        match event {
            EpidemicEvent::PeerJoined { peer_id, addresses } => {
                assert_eq!(peer_id, PeerId::new([3u8; 32]));
                assert_eq!(addresses.len(), 1);
            }
            _ => panic!("unexpected event type"),
        }
    }

    // ============================================================
    // PROOF POINT 7: Bootstrap Tests
    // ============================================================

    #[tokio::test]
    async fn test_bootstrap_when_not_running() {
        let (tx, _rx) = mpsc::channel(100);
        let gossip = EpidemicGossip::new(test_peer_id(), test_config(), tx);

        let result = gossip.bootstrap().await;

        assert_eq!(result, Err(GossipError::NotRunning));
    }

    #[tokio::test]
    #[ignore = "requires network access - run with --ignored"]
    async fn test_bootstrap_with_no_peers() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bootstrap_peers: vec![],
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.start().await.unwrap();
        let result = gossip.bootstrap().await;
        assert_eq!(result, Ok(0));

        gossip.stop().await;
    }

    // ============================================================
    // PROOF POINT 8: Config Tests
    // ============================================================

    #[test]
    fn test_epidemic_config_defaults() {
        let config = EpidemicConfig::default();

        assert_eq!(config.max_active, 8);
        assert_eq!(config.max_passive, 64);
        assert_eq!(config.swim_interval, Duration::from_secs(1));
        assert_eq!(config.suspect_timeout, Duration::from_secs(5));
        assert!(config.bootstrap_peers.is_empty());
        assert!(config.registry_url.is_none());
    }

    #[test]
    fn test_epidemic_config_custom() {
        let config = EpidemicConfig {
            listen_addr: "0.0.0.0:9000".parse().unwrap(),
            bootstrap_peers: vec!["192.168.1.1:9000".parse().unwrap()],
            max_active: 12,
            max_passive: 128,
            swim_interval: Duration::from_millis(500),
            suspect_timeout: Duration::from_secs(10),
            registry_url: Some("https://registry.example.com".to_string()),
            keypair: None,
        };

        assert_eq!(config.max_active, 12);
        assert_eq!(config.max_passive, 128);
        assert_eq!(config.bootstrap_peers.len(), 1);
    }

    // ============================================================
    // PROOF POINT 9: Error Type Tests
    // ============================================================

    #[test]
    fn test_gossip_error_display() {
        assert_eq!(
            GossipError::AlreadyRunning.to_string(),
            "gossip layer already running"
        );
        assert_eq!(
            GossipError::NotRunning.to_string(),
            "gossip layer not running"
        );
        assert_eq!(
            GossipError::Transport("connection refused".to_string()).to_string(),
            "transport error: connection refused"
        );
    }

    // ============================================================
    // PROOF POINT 10: Stats Structure Tests
    // ============================================================

    #[test]
    fn test_gossip_stats_default() {
        let stats = GossipStats::default();

        assert_eq!(stats.hyparview.active_view_size, 0);
        assert_eq!(stats.swim.alive_count, 0);
        assert_eq!(stats.plumtree.eager_peers, 0);
        assert_eq!(stats.connection_types.direct_ipv4, 0);
    }

    #[test]
    fn test_connection_breakdown_default() {
        let breakdown = ConnectionBreakdown::default();

        assert_eq!(breakdown.direct_ipv4, 0);
        assert_eq!(breakdown.direct_ipv6, 0);
        assert_eq!(breakdown.hole_punched, 0);
        assert_eq!(breakdown.relayed, 0);
    }
}
