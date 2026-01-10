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
use saorsa_gossip_coordinator::{AddrHint, CoordinatorAdvert, CoordinatorRoles, NatClass};
use saorsa_gossip_crdt_sync::{OrSet, VectorClock};
use saorsa_gossip_groups::GroupContext;
use saorsa_gossip_identity::MlDsaKeyPair;
use saorsa_gossip_membership::{HyParViewMembership, Membership, PeerState};
use saorsa_gossip_pubsub::{PlumtreePubSub, PubSub};
use saorsa_gossip_rendezvous::{Capability, ProviderSummary};
use saorsa_gossip_transport::{
    AntQuicTransport, AntQuicTransportConfig, GossipTransport, StreamType,
};
use saorsa_gossip_types::{PeerId, TopicId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Statistics for CRDT synchronization (saorsa-gossip-crdt-sync).
#[derive(Debug, Clone, Default)]
pub struct CrdtStats {
    /// Number of entries in the CRDT state.
    pub entries: usize,
    /// Number of merge operations performed.
    pub merges: u64,
    /// Length of the vector clock.
    pub vector_clock_len: usize,
    /// Seconds since last sync.
    pub last_sync_age_secs: u64,
}

/// Statistics for NAT coordination (saorsa-gossip-coordinator).
#[derive(Debug, Clone, Default)]
pub struct CoordinatorStats {
    /// Whether this node is acting as a coordinator.
    pub is_coordinator: bool,
    /// Number of active coordinators discovered.
    pub active_coordinators: usize,
    /// Successful coordination operations.
    pub coordination_success: u64,
    /// Failed coordination operations.
    pub coordination_failed: u64,
}

/// Statistics for group membership (saorsa-gossip-groups).
#[derive(Debug, Clone, Default)]
pub struct GroupStats {
    /// Number of groups this node is a member of.
    pub groups_count: usize,
    /// Total members across all groups.
    pub total_members: usize,
}

/// Statistics for rendezvous discovery (saorsa-gossip-rendezvous).
#[derive(Debug, Clone, Default)]
pub struct RendezvousStats {
    /// Number of provider registrations.
    pub registrations: u64,
    /// Number of provider discoveries.
    pub discoveries: u64,
    /// Number of currently active providers.
    pub active_providers: usize,
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
    /// CRDT synchronization stats (saorsa-gossip-crdt-sync).
    pub crdt: CrdtStats,
    /// NAT coordinator stats (saorsa-gossip-coordinator).
    pub coordinator: CoordinatorStats,
    /// Group membership stats (saorsa-gossip-groups).
    pub groups: GroupStats,
    /// Rendezvous discovery stats (saorsa-gossip-rendezvous).
    pub rendezvous: RendezvousStats,
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
    /// Whether this node acts as a coordinator for NAT traversal.
    /// VPS nodes with public IPs should set this to true.
    pub is_coordinator: bool,
    /// Public addresses to advertise (for coordinator nodes).
    pub public_addresses: Vec<SocketAddr>,
}

impl Default for EpidemicConfig {
    fn default() -> Self {
        Self {
            // Use dual-stack [::]:0 to accept both IPv4 and IPv6 connections
            listen_addr: "[::]:0".parse().expect("valid default addr"),
            bootstrap_peers: Vec::new(),
            max_active: 8,
            max_passive: 64,
            swim_interval: Duration::from_secs(1),
            suspect_timeout: Duration::from_secs(5),
            registry_url: None,
            keypair: None,
            is_coordinator: false,
            public_addresses: Vec::new(),
        }
    }
}

/// Entry stored in the peer cache CRDT.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerCacheEntry {
    /// The peer's ID.
    pub peer_id: [u8; 32],
    /// Known addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// Last heartbeat timestamp (Unix epoch millis).
    pub last_seen: u64,
    /// Location string (e.g., "NYC" or "LON").
    pub location: Option<String>,
}

/// CRDT synchronization state for distributed network state.
pub struct CrdtSyncState {
    /// OR-Set for peer cache (sync across all nodes).
    pub peer_cache: OrSet<PeerCacheEntry>,
    /// Vector clock for causal ordering.
    pub vector_clock: VectorClock,
    /// Our peer ID for generating unique tags.
    pub our_peer_id: PeerId,
    /// Sequence number for unique tags.
    pub sequence: u64,
    /// Last sync timestamp.
    pub last_sync: Instant,
    /// Count of merge operations.
    pub merges: u64,
    /// Number of peers tracked in vector clock.
    pub peers_tracked: usize,
}

impl CrdtSyncState {
    /// Create a new CRDT sync state.
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_cache: OrSet::new(),
            vector_clock: VectorClock::new(),
            our_peer_id: peer_id,
            sequence: 0,
            last_sync: Instant::now(),
            merges: 0,
            peers_tracked: 1, // Start with ourselves
        }
    }

    /// Generate the next unique tag for this peer.
    pub fn next_tag(&mut self) -> (PeerId, u64) {
        self.sequence += 1;
        (self.our_peer_id, self.sequence)
    }

    /// Get statistics for reporting.
    pub fn stats(&self) -> CrdtStats {
        CrdtStats {
            entries: self.peer_cache.len(),
            merges: self.merges,
            vector_clock_len: self.peers_tracked,
            last_sync_age_secs: self.last_sync.elapsed().as_secs(),
        }
    }
}

/// Coordinator state for NAT traversal coordination (saorsa-gossip-coordinator).
pub struct CoordinatorState {
    /// Whether this node is acting as a coordinator.
    pub is_coordinator: bool,
    /// Our advertisement (for coordinator nodes).
    pub our_advert: Option<CoordinatorAdvert>,
    /// Known coordinators discovered via gossip.
    pub known_coordinators: Vec<(PeerId, CoordinatorAdvert)>,
    /// Successful coordination operations.
    pub coordination_success: u64,
    /// Failed coordination operations.
    pub coordination_failed: u64,
    /// Last advertisement time.
    pub last_advert_time: Option<Instant>,
}

impl CoordinatorState {
    /// Create a new coordinator state.
    pub fn new(is_coordinator: bool) -> Self {
        Self {
            is_coordinator,
            our_advert: None,
            known_coordinators: Vec::new(),
            coordination_success: 0,
            coordination_failed: 0,
            last_advert_time: None,
        }
    }

    /// Get statistics for reporting.
    pub fn stats(&self) -> CoordinatorStats {
        CoordinatorStats {
            is_coordinator: self.is_coordinator,
            active_coordinators: self.known_coordinators.len(),
            coordination_success: self.coordination_success,
            coordination_failed: self.coordination_failed,
        }
    }

    /// Add a discovered coordinator.
    pub fn add_coordinator(&mut self, peer_id: PeerId, advert: CoordinatorAdvert) {
        // Update existing or add new
        if let Some(entry) = self
            .known_coordinators
            .iter_mut()
            .find(|(id, _)| *id == peer_id)
        {
            entry.1 = advert;
        } else {
            self.known_coordinators.push((peer_id, advert));
        }
    }

    /// Remove expired coordinators.
    pub fn cleanup_expired(&mut self) {
        self.known_coordinators
            .retain(|(_, advert)| advert.is_valid());
    }
}

/// Default groups for topic subscriptions.
pub const DEFAULT_GROUPS: &[&str] = &["connectivity-updates", "nat-events", "gossip-health"];

/// Group state for topic subscriptions (saorsa-gossip-groups).
pub struct GroupState {
    /// Groups this node is a member of.
    pub groups: HashMap<TopicId, GroupContext>,
    /// Number of members per group (tracked separately since GroupContext doesn't expose this).
    pub members_per_group: HashMap<TopicId, usize>,
    /// Total messages published to groups.
    pub messages_published: u64,
}

impl GroupState {
    /// Create a new group state.
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            members_per_group: HashMap::new(),
            messages_published: 0,
        }
    }

    /// Join a group by entity name.
    pub fn join_group(&mut self, entity_name: &str) -> Result<TopicId, String> {
        let group_context = GroupContext::from_entity(entity_name)
            .map_err(|e| format!("Failed to create group context: {e}"))?;
        let topic_id = group_context.topic_id;

        self.groups.insert(topic_id, group_context);
        // Start with 1 member (ourselves)
        self.members_per_group.insert(topic_id, 1);

        Ok(topic_id)
    }

    /// Leave a group.
    pub fn leave_group(&mut self, topic_id: &TopicId) -> bool {
        let removed = self.groups.remove(topic_id).is_some();
        if removed {
            self.members_per_group.remove(topic_id);
        }
        removed
    }

    /// Check if we're a member of a group.
    pub fn is_member(&self, topic_id: &TopicId) -> bool {
        self.groups.contains_key(topic_id)
    }

    /// Get statistics for reporting.
    pub fn stats(&self) -> GroupStats {
        let total_members: usize = self.members_per_group.values().sum();
        GroupStats {
            groups_count: self.groups.len(),
            total_members,
        }
    }

    /// Add a member to a group's member count.
    pub fn add_member(&mut self, topic_id: &TopicId) {
        if let Some(count) = self.members_per_group.get_mut(topic_id) {
            *count += 1;
        }
    }

    /// Remove a member from a group's member count.
    pub fn remove_member(&mut self, topic_id: &TopicId) {
        if let Some(count) = self.members_per_group.get_mut(topic_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Advance a group's epoch (for presence updates).
    pub fn advance_epoch(&mut self, topic_id: &TopicId) {
        if let Some(group) = self.groups.get_mut(topic_id) {
            group.next_epoch();
        }
    }
}

impl Default for GroupState {
    fn default() -> Self {
        Self::new()
    }
}

/// Rendezvous state for peer discovery (saorsa-gossip-rendezvous).
pub struct RendezvousState {
    /// Provider summaries we've registered.
    pub our_summaries: Vec<ProviderSummary>,
    /// Discovered providers by target.
    pub discovered_providers: HashMap<[u8; 32], Vec<ProviderSummary>>,
    /// Number of successful registrations.
    pub registrations: u64,
    /// Number of successful discoveries.
    pub discoveries: u64,
}

impl RendezvousState {
    /// Create a new rendezvous state.
    pub fn new() -> Self {
        Self {
            our_summaries: Vec::new(),
            discovered_providers: HashMap::new(),
            registrations: 0,
            discoveries: 0,
        }
    }

    /// Register as a provider for a target.
    pub fn register_provider(
        &mut self,
        target: [u8; 32],
        provider_peer_id: PeerId,
        capabilities: Vec<Capability>,
        validity_ms: u64,
    ) -> ProviderSummary {
        let summary = ProviderSummary::new(target, provider_peer_id, capabilities, validity_ms);

        // Update or add the summary
        if let Some(existing) = self
            .our_summaries
            .iter_mut()
            .find(|s| s.target == target && s.provider == provider_peer_id)
        {
            *existing = summary.clone();
        } else {
            self.our_summaries.push(summary.clone());
        }

        self.registrations += 1;
        summary
    }

    /// Add a discovered provider.
    pub fn add_discovered(&mut self, summary: ProviderSummary) {
        if !summary.is_valid() {
            return;
        }

        let providers = self.discovered_providers.entry(summary.target).or_default();

        // Update existing or add new
        if let Some(existing) = providers
            .iter_mut()
            .find(|s| s.provider == summary.provider)
        {
            *existing = summary;
        } else {
            providers.push(summary);
            self.discoveries += 1;
        }
    }

    /// Get providers for a target.
    pub fn get_providers(&self, target: &[u8; 32]) -> Vec<&ProviderSummary> {
        self.discovered_providers
            .get(target)
            .map(|v| v.iter().filter(|s| s.is_valid()).collect())
            .unwrap_or_default()
    }

    /// Get statistics for reporting.
    pub fn stats(&self) -> RendezvousStats {
        let active_providers: usize = self
            .discovered_providers
            .values()
            .flat_map(|v| v.iter())
            .filter(|s| s.is_valid())
            .count();

        RendezvousStats {
            registrations: self.registrations,
            discoveries: self.discoveries,
            active_providers,
        }
    }

    /// Remove expired summaries.
    pub fn cleanup_expired(&mut self) {
        // Clean our summaries
        self.our_summaries.retain(|s| s.is_valid());

        // Clean discovered providers
        for providers in self.discovered_providers.values_mut() {
            providers.retain(|s| s.is_valid());
        }

        // Remove empty target entries
        self.discovered_providers.retain(|_, v| !v.is_empty());
    }
}

impl Default for RendezvousState {
    fn default() -> Self {
        Self::new()
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
    /// CRDT synchronization state (saorsa-gossip-crdt-sync).
    crdt_state: Arc<RwLock<CrdtSyncState>>,
    /// Coordinator state for NAT traversal (saorsa-gossip-coordinator).
    coordinator_state: Arc<RwLock<CoordinatorState>>,
    /// Group state for topic subscriptions (saorsa-gossip-groups).
    groups_state: Arc<RwLock<GroupState>>,
    /// Rendezvous state for peer discovery (saorsa-gossip-rendezvous).
    rendezvous_state: Arc<RwLock<RendezvousState>>,
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
        let is_coordinator = config.is_coordinator;
        Self {
            peer_id,
            config,
            event_tx,
            stats: Arc::new(RwLock::new(GossipStats::default())),
            connection_types: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stack: Arc::new(RwLock::new(None)),
            crdt_state: Arc::new(RwLock::new(CrdtSyncState::new(peer_id))),
            coordinator_state: Arc::new(RwLock::new(CoordinatorState::new(is_coordinator))),
            groups_state: Arc::new(RwLock::new(GroupState::new())),
            rendezvous_state: Arc::new(RwLock::new(RendezvousState::new())),
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

        // Initialize default groups for topic subscriptions
        {
            let mut groups_guard = self.groups_state.write().await;
            for group_name in DEFAULT_GROUPS {
                match groups_guard.join_group(group_name) {
                    Ok(topic_id) => {
                        info!(
                            "Joined default group '{}' (topic: {:?})",
                            group_name, topic_id
                        );
                    }
                    Err(e) => {
                        warn!("Failed to join default group '{}': {}", group_name, e);
                    }
                }
            }
            // Debug: verify groups were added
            let stats = groups_guard.stats();
            info!(
                "Groups initialized: count={}, members={}",
                stats.groups_count, stats.total_members
            );
        }

        // Register as a provider for the network topic (rendezvous)
        {
            // Create target ID from network topic name
            let mut target = [0u8; 32];
            let topic_bytes = NETWORK_TOPIC.as_bytes();
            let len = topic_bytes.len().min(32);
            target[..len].copy_from_slice(&topic_bytes[..len]);

            let mut rendezvous_guard = self.rendezvous_state.write().await;
            let summary = rendezvous_guard.register_provider(
                target,
                self.peer_id,
                vec![Capability::Site], // We provide network connectivity
                300_000,                // Valid for 5 minutes
            );
            info!(
                "Registered as provider for network topic (shard: {})",
                summary.shard()
            );
        }

        // Initialize stats immediately with groups and rendezvous data
        // (stats updater waits 5 seconds before first update, which would miss first heartbeats)
        {
            let groups_stats = self.groups_state.read().await.stats();
            let rendezvous_stats = self.rendezvous_state.read().await.stats();
            let mut stats_guard = self.stats.write().await;
            stats_guard.groups = groups_stats;
            stats_guard.rendezvous = rendezvous_stats;
            info!(
                "Initial stats populated: groups={}, rendezvous={}",
                stats_guard.groups.groups_count, stats_guard.rendezvous.registrations
            );
        }

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

        let pubsub = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            Arc::clone(&stack.pubsub)
        };

        let topic = TopicId::from_entity(NETWORK_TOPIC)
            .map_err(|e| GossipError::Publish(format!("Invalid topic: {e}")))?;
        pubsub
            .publish(topic, payload.into())
            .await
            .map_err(|e| GossipError::Publish(e.to_string()))?;

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
        let membership = {
            let stack_guard = self.stack.read().await;
            stack_guard.as_ref().map(|s| Arc::clone(&s.membership))
        };
        if let Some(membership) = membership {
            membership.swim().get_state(peer_id).await
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
        let transport = {
            let stack_guard = self.stack.read().await;
            stack_guard.as_ref().map(|s| Arc::clone(&s.transport))
        };
        if let Some(transport) = transport {
            let peers = transport.connected_peers().await;
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
        let transport = {
            let stack_guard = self.stack.read().await;
            stack_guard.as_ref().map(|s| Arc::clone(&s.transport))
        };
        if let Some(transport) = transport {
            transport.connected_peers().await
        } else {
            Vec::new()
        }
    }

    /// Get SWIM liveness status for all known peers.
    ///
    /// Returns a snapshot of which peers are alive, suspect, or dead
    /// according to SWIM failure detection.
    pub async fn peer_liveness(&self) -> (Vec<PeerId>, Vec<PeerId>, Vec<PeerId>) {
        let membership = {
            let stack_guard = self.stack.read().await;
            stack_guard.as_ref().map(|s| Arc::clone(&s.membership))
        };
        if let Some(membership) = membership {
            let active = membership.active_view();
            let passive = membership.passive_view();
            let all_peers: Vec<_> = active.iter().chain(passive.iter()).cloned().collect();

            let mut alive = Vec::new();
            let mut suspect = Vec::new();
            let mut dead = Vec::new();

            for peer in all_peers {
                if let Some(state) = membership.swim().get_state(&peer).await {
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

        if self.config.bootstrap_peers.is_empty() {
            debug!("No bootstrap peers configured");
            return Ok(0);
        }

        let (transport, membership) = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            (Arc::clone(&stack.transport), Arc::clone(&stack.membership))
        };

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
            match transport.dial_bootstrap(*addr).await {
                Ok(peer_id) => {
                    info!("Connected to bootstrap peer {} ({})", peer_id, addr);
                    if let Err(e) = membership.add_active(peer_id).await {
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

        let (transport, membership) = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            (Arc::clone(&stack.transport), Arc::clone(&stack.membership))
        };

        info!(
            "Adding {} bootstrap peers from registry: {:?}",
            peers.len(),
            peers
        );

        // WORKAROUND: saorsa-gossip-membership v0.1.12's join() method is incomplete.
        // It logs "(TODO: transport)" and doesn't actually dial the seeds.
        // Instead, we use transport.dial_bootstrap() directly to connect to each peer,
        // then add them to the active view.
        //
        // OPTIMIZATION: Dial all bootstrap peers CONCURRENTLY with a per-dial timeout.
        // This prevents blocking the main run() loop for minutes when many peers time out.
        const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
        const MAX_CONCURRENT_DIALS: usize = 8;

        info!(
            "Dialing {} bootstrap peers concurrently (timeout={}s, max_concurrent={})",
            peers.len(),
            DIAL_TIMEOUT.as_secs(),
            MAX_CONCURRENT_DIALS
        );

        // Dial all peers concurrently in batches
        let mut connected = 0;
        for chunk in peers.chunks(MAX_CONCURRENT_DIALS) {
            let dial_futures: Vec<_> = chunk
                .iter()
                .map(|addr| {
                    let transport = Arc::clone(&transport);
                    let addr = *addr;
                    async move {
                        let result =
                            tokio::time::timeout(DIAL_TIMEOUT, transport.dial_bootstrap(addr))
                                .await;
                        (addr, result)
                    }
                })
                .collect();

            // Wait for all dials in this batch to complete
            let results = futures::future::join_all(dial_futures).await;

            // Process results and add successful connections to membership
            for (addr, result) in results {
                match result {
                    Ok(Ok(peer_id)) => {
                        info!("Connected to bootstrap peer {} ({})", peer_id, addr);
                        if let Err(e) = membership.add_active(peer_id).await {
                            warn!("Failed to add peer {} to active view: {}", peer_id, e);
                        } else {
                            debug!("Added peer {} to HyParView active view", peer_id);
                            connected += 1;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("Failed to dial bootstrap peer {}: {}", addr, e);
                    }
                    Err(_) => {
                        debug!(
                            "Timeout dialing bootstrap peer {} ({}s)",
                            addr,
                            DIAL_TIMEOUT.as_secs()
                        );
                    }
                }
            }
        }

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
        let membership = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            Arc::clone(&stack.membership)
        };

        membership
            .add_active(peer_id)
            .await
            .map_err(|e| GossipError::Membership(e.to_string()))?;

        let _ = self
            .event_tx
            .send(EpidemicEvent::PeerJoined {
                peer_id,
                addresses: vec![],
            })
            .await;

        Ok(())
    }

    /// Remove a peer from the active view.
    pub async fn remove_peer(&self, peer_id: PeerId) -> Result<(), GossipError> {
        let membership = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            Arc::clone(&stack.membership)
        };

        membership
            .remove_active(peer_id)
            .await
            .map_err(|e| GossipError::Membership(e.to_string()))?;

        let _ = self
            .event_tx
            .send(EpidemicEvent::PeerLeft { peer_id })
            .await;

        Ok(())
    }

    // ============================================================
    // CRDT Sync Methods (saorsa-gossip-crdt-sync)
    // ============================================================

    /// Add a peer entry to the CRDT peer cache.
    ///
    /// This entry will be synchronized across all nodes via delta CRDT.
    pub async fn add_to_peer_cache(&self, entry: PeerCacheEntry) {
        let mut crdt_guard = self.crdt_state.write().await;
        let tag = crdt_guard.next_tag();
        if let Err(e) = crdt_guard.peer_cache.add(entry, tag) {
            warn!("Failed to add entry to CRDT peer cache: {}", e);
            return;
        }
        crdt_guard.vector_clock.increment(self.peer_id);
        debug!(
            "Added entry to CRDT peer cache, total entries: {}",
            crdt_guard.peer_cache.len()
        );
    }

    /// Remove a peer entry from the CRDT peer cache.
    pub async fn remove_from_peer_cache(&self, entry: &PeerCacheEntry) {
        let mut crdt_guard = self.crdt_state.write().await;
        if let Err(e) = crdt_guard.peer_cache.remove(entry) {
            debug!("Failed to remove entry from CRDT peer cache: {}", e);
            return;
        }
        crdt_guard.vector_clock.increment(self.peer_id);
    }

    /// Get all entries from the CRDT peer cache.
    pub async fn get_peer_cache_entries(&self) -> Vec<PeerCacheEntry> {
        let crdt_guard = self.crdt_state.read().await;
        crdt_guard
            .peer_cache
            .elements()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get the number of entries in the CRDT peer cache.
    pub async fn peer_cache_len(&self) -> usize {
        let crdt_guard = self.crdt_state.read().await;
        crdt_guard.peer_cache.len()
    }

    /// Get CRDT statistics.
    pub async fn crdt_stats(&self) -> CrdtStats {
        let crdt_guard = self.crdt_state.read().await;
        crdt_guard.stats()
    }

    /// Merge a delta from another node into our CRDT state.
    ///
    /// Returns the number of new entries added.
    pub async fn merge_peer_cache_delta(
        &self,
        entries: Vec<PeerCacheEntry>,
        source_peer_id: PeerId,
        source_sequence: u64,
    ) -> usize {
        let mut crdt_guard = self.crdt_state.write().await;
        let initial_len = crdt_guard.peer_cache.len();

        for (idx, entry) in entries.into_iter().enumerate() {
            // Use source peer's tag to maintain proper CRDT semantics
            let tag = (source_peer_id, source_sequence + idx as u64);
            if let Err(e) = crdt_guard.peer_cache.add(entry, tag) {
                debug!("Failed to add delta entry: {}", e);
            }
        }

        crdt_guard.merges += 1;
        crdt_guard.last_sync = Instant::now();
        crdt_guard.peers_tracked = crdt_guard.peers_tracked.max(2); // At least us + source

        let new_entries = crdt_guard.peer_cache.len().saturating_sub(initial_len);
        debug!(
            "Merged CRDT delta: {} new entries, total merges: {}",
            new_entries, crdt_guard.merges
        );
        new_entries
    }

    /// Merge another node's full CRDT state into ours.
    pub async fn merge_peer_cache_state(&self, other: &OrSet<PeerCacheEntry>) {
        let mut crdt_guard = self.crdt_state.write().await;
        if let Err(e) = crdt_guard.peer_cache.merge_state(other) {
            warn!("Failed to merge CRDT state: {}", e);
            return;
        }
        crdt_guard.merges += 1;
        crdt_guard.last_sync = Instant::now();
        debug!(
            "Merged CRDT state, total entries: {}, merges: {}",
            crdt_guard.peer_cache.len(),
            crdt_guard.merges
        );
    }

    // ============================================================
    // Coordinator Methods (saorsa-gossip-coordinator)
    // ============================================================

    /// Check if this node is acting as a coordinator.
    pub async fn is_coordinator(&self) -> bool {
        self.coordinator_state.read().await.is_coordinator
    }

    /// Get coordinator statistics.
    pub async fn coordinator_stats(&self) -> CoordinatorStats {
        self.coordinator_state.read().await.stats()
    }

    /// Create a coordinator advertisement for this node.
    ///
    /// Only call this for VPS nodes with public IP addresses.
    pub fn create_coordinator_advert(&self, addresses: Vec<SocketAddr>) -> CoordinatorAdvert {
        let roles = CoordinatorRoles {
            coordinator: true,
            reflector: true,
            rendezvous: true,
            relay: true,
        };

        // Convert SocketAddr to AddrHint
        let addr_hints: Vec<AddrHint> = addresses.into_iter().map(AddrHint::new).collect();

        CoordinatorAdvert::new(
            self.peer_id,
            roles,
            addr_hints,
            NatClass::Eim, // Public VPS nodes have open NAT
            60_000,        // Valid for 60 seconds
        )
    }

    /// Set this node's coordinator advertisement.
    pub async fn set_coordinator_advert(&self, advert: CoordinatorAdvert) {
        let mut coord_guard = self.coordinator_state.write().await;
        coord_guard.our_advert = Some(advert);
        coord_guard.last_advert_time = Some(Instant::now());
        info!("Coordinator advertisement set for peer {}", self.peer_id);
    }

    /// Get this node's coordinator advertisement.
    pub async fn get_coordinator_advert(&self) -> Option<CoordinatorAdvert> {
        self.coordinator_state.read().await.our_advert.clone()
    }

    /// Add a discovered coordinator.
    pub async fn add_discovered_coordinator(&self, peer_id: PeerId, advert: CoordinatorAdvert) {
        let mut coord_guard = self.coordinator_state.write().await;
        coord_guard.add_coordinator(peer_id, advert);
        debug!(
            "Added coordinator {}, total known: {}",
            peer_id,
            coord_guard.known_coordinators.len()
        );
    }

    /// Get all known coordinators.
    pub async fn get_known_coordinators(&self) -> Vec<(PeerId, CoordinatorAdvert)> {
        self.coordinator_state
            .read()
            .await
            .known_coordinators
            .clone()
    }

    /// Get the number of known coordinators.
    pub async fn known_coordinators_count(&self) -> usize {
        self.coordinator_state.read().await.known_coordinators.len()
    }

    /// Record a successful coordination operation.
    pub async fn record_coordination_success(&self) {
        let mut coord_guard = self.coordinator_state.write().await;
        coord_guard.coordination_success += 1;
    }

    /// Record a failed coordination operation.
    pub async fn record_coordination_failure(&self) {
        let mut coord_guard = self.coordinator_state.write().await;
        coord_guard.coordination_failed += 1;
    }

    // ============================================================
    // Group Methods (saorsa-gossip-groups)
    // ============================================================

    /// Join a group by entity name.
    ///
    /// This creates a GroupContext for the group and subscribes to the topic.
    /// Default groups ("connectivity-updates", "nat-events", "gossip-health")
    /// are automatically joined on start.
    pub async fn join_group(&self, entity_name: &str) -> Result<TopicId, GossipError> {
        let mut groups_guard = self.groups_state.write().await;
        groups_guard
            .join_group(entity_name)
            .map_err(GossipError::Membership)
    }

    /// Leave a group.
    ///
    /// Returns true if we were a member and left, false if we weren't a member.
    pub async fn leave_group(&self, topic_id: &TopicId) -> bool {
        let mut groups_guard = self.groups_state.write().await;
        groups_guard.leave_group(topic_id)
    }

    /// Check if we're a member of a group.
    pub async fn is_group_member(&self, topic_id: &TopicId) -> bool {
        let groups_guard = self.groups_state.read().await;
        groups_guard.is_member(topic_id)
    }

    /// Get statistics for all groups.
    pub async fn groups_stats(&self) -> GroupStats {
        let groups_guard = self.groups_state.read().await;
        groups_guard.stats()
    }

    /// Get the number of groups we're a member of.
    pub async fn groups_count(&self) -> usize {
        let groups_guard = self.groups_state.read().await;
        groups_guard.groups.len()
    }

    /// Get all groups we're a member of.
    pub async fn get_groups(&self) -> Vec<TopicId> {
        let groups_guard = self.groups_state.read().await;
        groups_guard.groups.keys().copied().collect()
    }

    /// Publish a message to a specific group (topic).
    ///
    /// This publishes through the Plumtree pubsub layer to the specified topic.
    /// Only members of the group will receive the message.
    pub async fn group_publish(
        &self,
        topic_id: TopicId,
        payload: Vec<u8>,
    ) -> Result<(), GossipError> {
        if !self.is_running() {
            return Err(GossipError::NotRunning);
        }

        // Verify we're a member of the group
        {
            let groups_guard = self.groups_state.read().await;
            if !groups_guard.is_member(&topic_id) {
                return Err(GossipError::Membership(format!(
                    "Not a member of group {:?}",
                    topic_id
                )));
            }
        }

        let pubsub = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            Arc::clone(&stack.pubsub)
        };

        pubsub
            .publish(topic_id, payload.into())
            .await
            .map_err(|e| GossipError::Publish(e.to_string()))?;

        // Update message count
        {
            let mut groups_guard = self.groups_state.write().await;
            groups_guard.messages_published += 1;
        }

        {
            let mut stats = self.stats.write().await;
            stats.plumtree.messages_sent += 1;
        }

        Ok(())
    }

    /// Get a group's epoch (for presence tracking).
    pub async fn group_epoch(&self, topic_id: &TopicId) -> Option<u64> {
        let groups_guard = self.groups_state.read().await;
        groups_guard.groups.get(topic_id).map(|g| g.epoch)
    }

    /// Advance a group's epoch.
    pub async fn advance_group_epoch(&self, topic_id: &TopicId) {
        let mut groups_guard = self.groups_state.write().await;
        groups_guard.advance_epoch(topic_id);
    }

    // ========== Rendezvous Methods ==========

    /// Register this node as a provider for a capability.
    /// Returns the shard this provider is assigned to.
    pub async fn register_provider(
        &self,
        target: [u8; 32],
        capabilities: Vec<Capability>,
        validity_ms: u64,
    ) -> u16 {
        let mut rendezvous_guard = self.rendezvous_state.write().await;
        let summary =
            rendezvous_guard.register_provider(target, self.peer_id, capabilities, validity_ms);
        summary.shard()
    }

    /// Add a discovered provider to our cache.
    pub async fn add_discovered_provider(&self, summary: ProviderSummary) {
        let mut rendezvous_guard = self.rendezvous_state.write().await;
        rendezvous_guard.add_discovered(summary);
    }

    /// Get providers for a target.
    pub async fn get_providers(&self, target: &[u8; 32]) -> Vec<ProviderSummary> {
        let rendezvous_guard = self.rendezvous_state.read().await;
        rendezvous_guard
            .get_providers(target)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get rendezvous statistics.
    pub async fn rendezvous_stats(&self) -> RendezvousStats {
        let rendezvous_guard = self.rendezvous_state.read().await;
        rendezvous_guard.stats()
    }

    /// Get the number of registrations made by this node.
    pub async fn registrations_count(&self) -> u64 {
        let rendezvous_guard = self.rendezvous_state.read().await;
        rendezvous_guard.registrations
    }

    /// Get the number of provider discoveries.
    pub async fn discoveries_count(&self) -> u64 {
        let rendezvous_guard = self.rendezvous_state.read().await;
        rendezvous_guard.discoveries
    }

    /// Get the total number of active providers across all targets.
    pub async fn active_providers_count(&self) -> usize {
        let rendezvous_guard = self.rendezvous_state.read().await;
        rendezvous_guard
            .discovered_providers
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Cleanup expired provider summaries.
    pub async fn cleanup_expired_providers(&self) {
        let mut rendezvous_guard = self.rendezvous_state.write().await;
        rendezvous_guard.cleanup_expired();
    }

    /// Send data to a peer using the gossip transport.
    /// This bypasses the P2pEndpoint and uses the gossip connections directly,
    /// which uses the port configured via --bind-port (or random if 0).
    pub async fn send_to_peer(&self, peer_id: PeerId, data: Vec<u8>) -> Result<(), GossipError> {
        let transport = {
            let stack_guard = self.stack.read().await;
            let stack = stack_guard.as_ref().ok_or(GossipError::NotRunning)?;
            Arc::clone(&stack.transport)
        };

        transport
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
        let crdt_state = self.crdt_state.clone();
        let coordinator_state = self.coordinator_state.clone();
        let groups_state = self.groups_state.clone();
        let rendezvous_state = self.rendezvous_state.clone();

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

                    // First, get transport connected peers - these are the actually connected peers
                    let connected_peers = transport.connected_peers().await;

                    // Check SWIM state for peers in active view
                    for peer in &active {
                        if let Some(state) = membership.swim().get_state(peer).await {
                            match state {
                                PeerState::Alive => alive_count += 1,
                                PeerState::Suspect => suspect_count += 1,
                                PeerState::Dead => dead_count += 1,
                            }
                        }
                    }

                    // WORKAROUND: If HyParView active_view is empty but transport has connections,
                    // count transport connected peers as "alive" since they are actually connected.
                    // This handles the case where peers connect but aren't added to HyParView.
                    if alive_count == 0 && !connected_peers.is_empty() {
                        for (peer_id, _) in &connected_peers {
                            // Only count if not already in active view (avoid double counting)
                            if !active.contains(peer_id) {
                                alive_count += 1;
                            }
                        }
                        debug!(
                            "Using transport connected peers for alive count: {} peers",
                            connected_peers.len()
                        );
                    }
                    let mut breakdown = ConnectionBreakdown::default();

                    {
                        let mut conn_types = connection_types.write().await;

                        // First, update connection_types from transport's connected_peers
                        // (in case transport tracked some peers we don't know about)
                        for (peer_id, addr) in &connected_peers {
                            let inferred_type = if addr.is_ipv4() {
                                ConnectionType::DirectIpv4
                            } else {
                                ConnectionType::DirectIpv6
                            };
                            conn_types.insert(*peer_id, inferred_type);
                        }

                        // Now build breakdown from ALL known connection types
                        // This includes peers set via set_connection_type() from client.rs
                        // (inbound connections that the transport didn't see due to race)
                        for conn_type in conn_types.values() {
                            match conn_type {
                                ConnectionType::DirectIpv4 => breakdown.direct_ipv4 += 1,
                                ConnectionType::DirectIpv6 => breakdown.direct_ipv6 += 1,
                                ConnectionType::HolePunched => breakdown.hole_punched += 1,
                                ConnectionType::Relayed => breakdown.relayed += 1,
                                ConnectionType::Unknown => {}
                            }
                        }
                    }

                    // Get CRDT stats
                    let crdt_stats = {
                        let crdt_guard = crdt_state.read().await;
                        crdt_guard.stats()
                    };

                    // Get coordinator stats and cleanup expired coordinators
                    let coordinator_stats = {
                        let mut coord_guard = coordinator_state.write().await;
                        coord_guard.cleanup_expired();
                        coord_guard.stats()
                    };

                    // Get groups stats
                    let groups_stats = {
                        let groups_guard = groups_state.read().await;
                        groups_guard.stats()
                    };

                    // Get rendezvous stats and cleanup expired providers
                    let rendezvous_stats = {
                        let mut rendezvous_guard = rendezvous_state.write().await;
                        rendezvous_guard.cleanup_expired();
                        rendezvous_guard.stats()
                    };

                    let mut stats_guard = stats.write().await;
                    stats_guard.hyparview.active_view_size = active.len();
                    stats_guard.hyparview.passive_view_size = passive.len();
                    stats_guard.swim.alive_count = alive_count;
                    stats_guard.swim.suspect_count = suspect_count;
                    stats_guard.swim.dead_count = dead_count;
                    stats_guard.connection_types = breakdown;
                    stats_guard.crdt = crdt_stats;
                    stats_guard.coordinator = coordinator_stats;
                    stats_guard.groups = groups_stats;
                    stats_guard.rendezvous = rendezvous_stats;

                    debug!(
                        "Stats updated: active={}, passive={}, alive={}, suspect={}, dead={}, crdt_entries={}, coordinators={}, groups={}, rdv={}",
                        active.len(),
                        passive.len(),
                        alive_count,
                        suspect_count,
                        dead_count,
                        stats_guard.crdt.entries,
                        stats_guard.coordinator.active_coordinators,
                        stats_guard.groups.groups_count,
                        stats_guard.rendezvous.registrations
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
        assert!(!config.is_coordinator);
        assert!(config.public_addresses.is_empty());
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
            is_coordinator: true,
            public_addresses: vec!["1.2.3.4:9000".parse().unwrap()],
        };

        assert_eq!(config.max_active, 12);
        assert_eq!(config.max_passive, 128);
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert!(config.is_coordinator);
        assert_eq!(config.public_addresses.len(), 1);
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
        // New stats fields
        assert_eq!(stats.crdt.entries, 0);
        assert_eq!(stats.coordinator.active_coordinators, 0);
        assert_eq!(stats.groups.groups_count, 0);
        assert_eq!(stats.rendezvous.registrations, 0);
    }

    #[test]
    fn test_connection_breakdown_default() {
        let breakdown = ConnectionBreakdown::default();

        assert_eq!(breakdown.direct_ipv4, 0);
        assert_eq!(breakdown.direct_ipv6, 0);
        assert_eq!(breakdown.hole_punched, 0);
        assert_eq!(breakdown.relayed, 0);
    }

    // ============================================================
    // PROOF POINT 11: New Stats Structure Tests (Task 1)
    // ============================================================

    #[test]
    fn test_crdt_stats_default() {
        let stats = CrdtStats::default();

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.merges, 0);
        assert_eq!(stats.vector_clock_len, 0);
        assert_eq!(stats.last_sync_age_secs, 0);
    }

    #[test]
    fn test_crdt_stats_custom() {
        let stats = CrdtStats {
            entries: 100,
            merges: 50,
            vector_clock_len: 10,
            last_sync_age_secs: 5,
        };

        assert_eq!(stats.entries, 100);
        assert_eq!(stats.merges, 50);
        assert_eq!(stats.vector_clock_len, 10);
        assert_eq!(stats.last_sync_age_secs, 5);
    }

    #[test]
    fn test_coordinator_stats_default() {
        let stats = CoordinatorStats::default();

        assert!(!stats.is_coordinator);
        assert_eq!(stats.active_coordinators, 0);
        assert_eq!(stats.coordination_success, 0);
        assert_eq!(stats.coordination_failed, 0);
    }

    #[test]
    fn test_coordinator_stats_custom() {
        let stats = CoordinatorStats {
            is_coordinator: true,
            active_coordinators: 3,
            coordination_success: 100,
            coordination_failed: 2,
        };

        assert!(stats.is_coordinator);
        assert_eq!(stats.active_coordinators, 3);
        assert_eq!(stats.coordination_success, 100);
        assert_eq!(stats.coordination_failed, 2);
    }

    #[test]
    fn test_group_stats_default() {
        let stats = GroupStats::default();

        assert_eq!(stats.groups_count, 0);
        assert_eq!(stats.total_members, 0);
    }

    #[test]
    fn test_group_stats_custom() {
        let stats = GroupStats {
            groups_count: 5,
            total_members: 25,
        };

        assert_eq!(stats.groups_count, 5);
        assert_eq!(stats.total_members, 25);
    }

    #[test]
    fn test_rendezvous_stats_default() {
        let stats = RendezvousStats::default();

        assert_eq!(stats.registrations, 0);
        assert_eq!(stats.discoveries, 0);
        assert_eq!(stats.active_providers, 0);
    }

    #[test]
    fn test_rendezvous_stats_custom() {
        let stats = RendezvousStats {
            registrations: 10,
            discoveries: 50,
            active_providers: 8,
        };

        assert_eq!(stats.registrations, 10);
        assert_eq!(stats.discoveries, 50);
        assert_eq!(stats.active_providers, 8);
    }

    #[test]
    fn test_gossip_stats_with_all_components() {
        let mut stats = GossipStats::default();

        // Set values for all components
        stats.hyparview.active_view_size = 5;
        stats.swim.alive_count = 10;
        stats.plumtree.messages_sent = 100;
        stats.connection_types.direct_ipv4 = 3;
        stats.crdt.entries = 50;
        stats.coordinator.is_coordinator = true;
        stats.groups.groups_count = 3;
        stats.rendezvous.discoveries = 20;

        // Verify all components have values
        assert_eq!(stats.hyparview.active_view_size, 5);
        assert_eq!(stats.swim.alive_count, 10);
        assert_eq!(stats.plumtree.messages_sent, 100);
        assert_eq!(stats.connection_types.direct_ipv4, 3);
        assert_eq!(stats.crdt.entries, 50);
        assert!(stats.coordinator.is_coordinator);
        assert_eq!(stats.groups.groups_count, 3);
        assert_eq!(stats.rendezvous.discoveries, 20);
    }

    // ============================================================
    // PROOF POINT 12: Coordinator State Tests (Task 3)
    // ============================================================

    #[test]
    fn test_coordinator_state_new_non_coordinator() {
        let state = CoordinatorState::new(false);

        assert!(!state.is_coordinator);
        assert!(state.our_advert.is_none());
        assert!(state.known_coordinators.is_empty());
        assert_eq!(state.coordination_success, 0);
        assert_eq!(state.coordination_failed, 0);
        assert!(state.last_advert_time.is_none());
    }

    #[test]
    fn test_coordinator_state_new_coordinator() {
        let state = CoordinatorState::new(true);

        assert!(state.is_coordinator);
        assert!(state.our_advert.is_none());
        assert!(state.known_coordinators.is_empty());
    }

    #[test]
    fn test_coordinator_state_stats() {
        let mut state = CoordinatorState::new(true);
        state.coordination_success = 10;
        state.coordination_failed = 2;

        let stats = state.stats();
        assert!(stats.is_coordinator);
        assert_eq!(stats.active_coordinators, 0);
        assert_eq!(stats.coordination_success, 10);
        assert_eq!(stats.coordination_failed, 2);
    }

    #[test]
    fn test_coordinator_state_add_coordinator() {
        let mut state = CoordinatorState::new(false);
        let peer_id = PeerId::new([1u8; 32]);
        let advert = CoordinatorAdvert::new(
            peer_id,
            CoordinatorRoles {
                coordinator: true,
                reflector: true,
                rendezvous: true,
                relay: true,
            },
            vec![AddrHint::new("1.2.3.4:9000".parse().unwrap())],
            NatClass::Eim,
            60_000,
        );

        state.add_coordinator(peer_id, advert);
        assert_eq!(state.known_coordinators.len(), 1);

        let stats = state.stats();
        assert_eq!(stats.active_coordinators, 1);
    }

    #[test]
    fn test_coordinator_state_update_existing() {
        let mut state = CoordinatorState::new(false);
        let peer_id = PeerId::new([1u8; 32]);
        let advert1 = CoordinatorAdvert::new(
            peer_id,
            CoordinatorRoles {
                coordinator: true,
                reflector: false,
                rendezvous: false,
                relay: false,
            },
            vec![AddrHint::new("1.2.3.4:9000".parse().unwrap())],
            NatClass::Eim,
            60_000,
        );
        let advert2 = CoordinatorAdvert::new(
            peer_id,
            CoordinatorRoles {
                coordinator: true,
                reflector: true,
                rendezvous: true,
                relay: true,
            },
            vec![AddrHint::new("1.2.3.4:9000".parse().unwrap())],
            NatClass::Eim,
            60_000,
        );

        state.add_coordinator(peer_id, advert1);
        assert_eq!(state.known_coordinators.len(), 1);

        // Adding the same peer_id should update, not add
        state.add_coordinator(peer_id, advert2);
        assert_eq!(state.known_coordinators.len(), 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_coordinator_stats_default() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let stats = gossip.coordinator_stats().await;
        assert!(!stats.is_coordinator);
        assert_eq!(stats.active_coordinators, 0);
        assert_eq!(stats.coordination_success, 0);
        assert_eq!(stats.coordination_failed, 0);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_is_coordinator() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        assert!(!gossip.is_coordinator().await);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_coordinator_with_config() {
        let (tx, _rx) = mpsc::channel(100);
        let config = EpidemicConfig {
            is_coordinator: true,
            public_addresses: vec!["1.2.3.4:9000".parse().unwrap()],
            ..Default::default()
        };
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        assert!(gossip.is_coordinator().await);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_create_advert() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let addresses = vec!["1.2.3.4:9000".parse().unwrap()];
        let advert = gossip.create_coordinator_advert(addresses);

        assert!(advert.is_valid());
    }

    #[tokio::test]
    async fn test_epidemic_gossip_add_discovered_coordinator() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let peer_id = PeerId::new([1u8; 32]);
        let advert = CoordinatorAdvert::new(
            peer_id,
            CoordinatorRoles {
                coordinator: true,
                reflector: true,
                rendezvous: true,
                relay: true,
            },
            vec![AddrHint::new("1.2.3.4:9000".parse().unwrap())],
            NatClass::Eim,
            60_000,
        );

        gossip.add_discovered_coordinator(peer_id, advert).await;

        assert_eq!(gossip.known_coordinators_count().await, 1);

        let known = gossip.get_known_coordinators().await;
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].0, peer_id);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_record_coordination() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        gossip.record_coordination_success().await;
        gossip.record_coordination_success().await;
        gossip.record_coordination_failure().await;

        let stats = gossip.coordinator_stats().await;
        assert_eq!(stats.coordination_success, 2);
        assert_eq!(stats.coordination_failed, 1);
    }

    // ============================================================
    // PROOF POINT 13: Group State Tests (Task 4)
    // ============================================================

    #[test]
    fn test_group_state_new() {
        let state = GroupState::new();

        assert!(state.groups.is_empty());
        assert!(state.members_per_group.is_empty());
        assert_eq!(state.messages_published, 0);
    }

    #[test]
    fn test_group_state_default() {
        let state = GroupState::default();

        assert!(state.groups.is_empty());
        assert_eq!(state.messages_published, 0);
    }

    #[test]
    fn test_group_state_join_group() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        assert!(state.is_member(&topic_id));
        assert_eq!(state.groups.len(), 1);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&1));
    }

    #[test]
    fn test_group_state_leave_group() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        assert!(state.is_member(&topic_id));

        let removed = state.leave_group(&topic_id);
        assert!(removed);
        assert!(!state.is_member(&topic_id));
        assert!(state.groups.is_empty());
    }

    #[test]
    fn test_group_state_leave_nonexistent_group() {
        let mut state = GroupState::new();
        let fake_topic = TopicId::from_entity("fake").unwrap();

        let removed = state.leave_group(&fake_topic);
        assert!(!removed);
    }

    #[test]
    fn test_group_state_stats() {
        let mut state = GroupState::new();

        state.join_group("group1").unwrap();
        state.join_group("group2").unwrap();

        let stats = state.stats();
        assert_eq!(stats.groups_count, 2);
        assert_eq!(stats.total_members, 2); // 1 member each (ourselves)
    }

    #[test]
    fn test_group_state_add_member() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        assert_eq!(state.members_per_group.get(&topic_id), Some(&1));

        state.add_member(&topic_id);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&2));
    }

    #[test]
    fn test_group_state_remove_member() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        state.add_member(&topic_id);
        state.add_member(&topic_id);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&3));

        state.remove_member(&topic_id);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&2));
    }

    #[test]
    fn test_group_state_remove_member_saturates() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        state.remove_member(&topic_id);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&0));

        // Should not go negative
        state.remove_member(&topic_id);
        assert_eq!(state.members_per_group.get(&topic_id), Some(&0));
    }

    #[test]
    fn test_group_state_advance_epoch() {
        let mut state = GroupState::new();

        let topic_id = state.join_group("test-group").unwrap();
        let initial_epoch = state.groups.get(&topic_id).unwrap().epoch;

        state.advance_epoch(&topic_id);
        let new_epoch = state.groups.get(&topic_id).unwrap().epoch;

        assert_eq!(new_epoch, initial_epoch + 1);
    }

    #[test]
    fn test_default_groups_constant() {
        assert_eq!(DEFAULT_GROUPS.len(), 3);
        assert!(DEFAULT_GROUPS.contains(&"connectivity-updates"));
        assert!(DEFAULT_GROUPS.contains(&"nat-events"));
        assert!(DEFAULT_GROUPS.contains(&"gossip-health"));
    }

    #[tokio::test]
    async fn test_epidemic_gossip_groups_stats_default() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let stats = gossip.groups_stats().await;
        assert_eq!(stats.groups_count, 0);
        assert_eq!(stats.total_members, 0);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_groups_count() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        assert_eq!(gossip.groups_count().await, 0);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_join_group() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let topic_id = gossip.join_group("custom-group").await.unwrap();
        assert!(gossip.is_group_member(&topic_id).await);
        assert_eq!(gossip.groups_count().await, 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_leave_group() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let topic_id = gossip.join_group("custom-group").await.unwrap();
        assert!(gossip.is_group_member(&topic_id).await);

        let left = gossip.leave_group(&topic_id).await;
        assert!(left);
        assert!(!gossip.is_group_member(&topic_id).await);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_get_groups() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let topic1 = gossip.join_group("group-a").await.unwrap();
        let topic2 = gossip.join_group("group-b").await.unwrap();

        let groups = gossip.get_groups().await;
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&topic1));
        assert!(groups.contains(&topic2));
    }

    #[tokio::test]
    async fn test_epidemic_gossip_group_epoch() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let topic_id = gossip.join_group("test-group").await.unwrap();
        let epoch1 = gossip.group_epoch(&topic_id).await.unwrap();

        gossip.advance_group_epoch(&topic_id).await;
        let epoch2 = gossip.group_epoch(&topic_id).await.unwrap();

        assert_eq!(epoch2, epoch1 + 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_group_publish_not_running() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let topic_id = gossip.join_group("test-group").await.unwrap();
        let result = gossip.group_publish(topic_id, vec![1, 2, 3]).await;

        assert_eq!(result, Err(GossipError::NotRunning));
    }

    #[tokio::test]
    async fn test_epidemic_gossip_group_publish_not_member() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        // Create a topic but don't join it
        let fake_topic = TopicId::from_entity("not-joined").unwrap();

        // Mark as running artificially to test membership check
        gossip
            .running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let result = gossip.group_publish(fake_topic, vec![1, 2, 3]).await;

        match result {
            Err(GossipError::Membership(msg)) => {
                assert!(msg.contains("Not a member"));
            }
            _ => panic!("Expected Membership error"),
        }
    }

    // ========== Rendezvous Tests ==========

    #[tokio::test]
    async fn test_rendezvous_state_new() {
        let state = RendezvousState::new();
        assert!(state.our_summaries.is_empty());
        assert!(state.discovered_providers.is_empty());
        assert_eq!(state.registrations, 0);
        assert_eq!(state.discoveries, 0);
    }

    #[tokio::test]
    async fn test_rendezvous_register_provider() {
        let mut state = RendezvousState::new();
        let target = [1u8; 32];
        let peer_id = test_peer_id();
        let caps = vec![Capability::Site];

        let summary = state.register_provider(target, peer_id, caps, 60_000);

        assert_eq!(state.our_summaries.len(), 1);
        assert_eq!(state.registrations, 1);
        // Shard is a u16, valid in range [0, 65535]
        let shard = summary.shard();
        // Verify shard is deterministic
        assert_eq!(shard, summary.shard());
    }

    #[tokio::test]
    async fn test_rendezvous_add_discovered() {
        let mut state = RendezvousState::new();
        let target = [2u8; 32];
        let peer_id = test_peer_id();

        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Identity], 60_000);
        state.add_discovered(summary);

        assert_eq!(state.discoveries, 1);
        assert_eq!(
            state.discovered_providers.get(&target).map(|v| v.len()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_rendezvous_get_providers() {
        let mut state = RendezvousState::new();
        let target = [3u8; 32];
        let peer_id = test_peer_id();

        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Site], 60_000);
        state.add_discovered(summary);

        let providers = state.get_providers(&target);
        assert_eq!(providers.len(), 1);

        // Unknown target returns empty
        let unknown = [99u8; 32];
        let providers_empty = state.get_providers(&unknown);
        assert!(providers_empty.is_empty());
    }

    #[tokio::test]
    async fn test_rendezvous_stats() {
        let mut state = RendezvousState::new();
        let target = [4u8; 32];
        let peer_id = test_peer_id();

        state.register_provider(target, peer_id, vec![Capability::Site], 60_000);
        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Identity], 60_000);
        state.add_discovered(summary);

        let stats = state.stats();
        assert_eq!(stats.registrations, 1);
        assert_eq!(stats.discoveries, 1);
        assert_eq!(stats.active_providers, 1);
    }

    #[tokio::test]
    async fn test_rendezvous_cleanup_expired() {
        let mut state = RendezvousState::new();
        let target = [5u8; 32];
        let peer_id = test_peer_id();

        // Create with 0ms validity (immediately expired)
        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Site], 0);
        state.add_discovered(summary.clone());

        // Wait a tiny bit to ensure expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        state.cleanup_expired();

        // Discovered providers should be cleaned up (empty for this target)
        let providers = state.get_providers(&target);
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn test_epidemic_gossip_register_provider() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [6u8; 32];
        let shard = gossip
            .register_provider(target, vec![Capability::Site], 60_000)
            .await;

        // Shard is a u16, valid in range [0, 65535]
        // Just verify we got a shard back by using it
        let _shard_value: u16 = shard;
        assert_eq!(gossip.registrations_count().await, 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_add_discovered_provider() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [7u8; 32];
        let peer_id = test_peer_id();
        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Identity], 60_000);

        gossip.add_discovered_provider(summary).await;

        assert_eq!(gossip.discoveries_count().await, 1);
        assert_eq!(gossip.active_providers_count().await, 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_get_providers() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [8u8; 32];
        let peer_id = test_peer_id();
        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Site], 60_000);

        gossip.add_discovered_provider(summary).await;

        let providers = gossip.get_providers(&target).await;
        assert_eq!(providers.len(), 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_rendezvous_stats() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [9u8; 32];
        gossip
            .register_provider(target, vec![Capability::Site], 60_000)
            .await;

        let stats = gossip.rendezvous_stats().await;
        assert_eq!(stats.registrations, 1);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_cleanup_expired_providers() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [10u8; 32];
        let peer_id = test_peer_id();
        // Create with 0ms validity (immediately expired)
        let summary = ProviderSummary::new(target, peer_id, vec![Capability::Site], 0);
        gossip.add_discovered_provider(summary).await;

        // Wait a tiny bit to ensure expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        gossip.cleanup_expired_providers().await;

        // Should be cleaned up
        let providers = gossip.get_providers(&target).await;
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn test_epidemic_gossip_multiple_providers_same_target() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        let target = [11u8; 32];

        // Add multiple providers for the same target
        for i in 0..3 {
            let mut peer_bytes = [0u8; 32];
            peer_bytes[0] = i;
            let peer_id = PeerId::new(peer_bytes);
            let summary = ProviderSummary::new(target, peer_id, vec![Capability::Site], 60_000);
            gossip.add_discovered_provider(summary).await;
        }

        let providers = gossip.get_providers(&target).await;
        assert_eq!(providers.len(), 3);
        assert_eq!(gossip.active_providers_count().await, 3);
    }

    #[tokio::test]
    async fn test_epidemic_gossip_multiple_targets() {
        let (tx, _rx) = mpsc::channel(100);
        let config = test_config();
        let gossip = EpidemicGossip::new(test_peer_id(), config, tx);

        // Register providers for different targets
        let target1 = [12u8; 32];
        let target2 = [13u8; 32];

        let peer_id = test_peer_id();
        let summary1 = ProviderSummary::new(target1, peer_id, vec![Capability::Site], 60_000);
        let summary2 = ProviderSummary::new(target2, peer_id, vec![Capability::Identity], 60_000);

        gossip.add_discovered_provider(summary1).await;
        gossip.add_discovered_provider(summary2).await;

        assert_eq!(gossip.get_providers(&target1).await.len(), 1);
        assert_eq!(gossip.get_providers(&target2).await.len(), 1);
        assert_eq!(gossip.active_providers_count().await, 2);
    }
}
