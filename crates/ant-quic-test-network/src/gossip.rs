//! Gossip-based decentralized peer and relay discovery.
//!
//! This module provides a gossip layer on top of ant-quic for:
//! - Peer announcements: Broadcast known peers across the network
//! - Relay discovery: Share relay/coordinator info via gossip
//! - Coordinator election: Public nodes self-announce as coordinators
//! - Peer connection queries: Find peers connected to a specific node
//! - Bootstrap cache: Persistent cache of known good peers (via saorsa-gossip)
//!
//! Uses saorsa-gossip's Plumtree epidemic broadcast for O(log n) message propagation.

use saorsa_gossip_coordinator::{NatClass, PeerCache, PeerCacheEntry, PeerRoles};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn};

/// Topic names for gossip channels.
pub const TOPIC_PEERS: &str = "ant-quic/peers/v1";
pub const TOPIC_RELAYS: &str = "ant-quic/relays/v1";
pub const TOPIC_COORDINATORS: &str = "ant-quic/coordinators/v1";
/// New topics for peer connection queries (NAT coordination)
pub const TOPIC_PEER_QUERY: &str = "ant-quic/peer-query/v1";
pub const TOPIC_PEER_RESPONSE: &str = "ant-quic/peer-response/v1";

/// A peer announcement broadcast via gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// Hex-encoded peer ID (first 16 chars of SHA-256(ML-DSA-65 pubkey)).
    pub peer_id: String,
    /// All known addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// Whether this peer is publicly reachable (not behind NAT on any IP family).
    /// This is `is_public_ipv4 || is_public_ipv6` for backward compatibility.
    pub is_public: bool,
    /// Whether this peer is public on IPv4 (external IPv4 matches local IPv4).
    #[serde(default)]
    pub is_public_ipv4: bool,
    /// Whether this peer is public on IPv6 (external IPv6 matches local IPv6).
    #[serde(default)]
    pub is_public_ipv6: bool,
    /// Timestamp when this announcement was created.
    pub timestamp_ms: u64,
    /// Optional country code for geo-proximity routing.
    pub country_code: Option<String>,
    /// Supported NAT traversal capabilities.
    pub capabilities: PeerCapabilities,
    /// Monotonic epoch for delta-based gossip (0 = legacy, >0 = versioned).
    #[serde(default)]
    pub epoch: u64,
}

/// Capabilities advertised by a peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Supports direct connections (public IP on any family).
    pub direct: bool,
    /// Supports direct IPv4 connections (public IPv4).
    #[serde(default)]
    pub direct_ipv4: bool,
    /// Supports direct IPv6 connections (public IPv6).
    #[serde(default)]
    pub direct_ipv6: bool,
    /// Supports hole-punching (can coordinate).
    pub hole_punch: bool,
    /// Can act as a relay for other peers.
    pub relay: bool,
    /// Can act as a coordinator for NAT traversal.
    pub coordinator: bool,
    /// Supports dual-stack bridging (can relay between IPv4 and IPv6).
    /// This is true when a relay has both IPv4 and IPv6 addresses and
    /// can translate traffic between the two IP versions.
    #[serde(default)]
    pub supports_dual_stack: bool,
}

impl PeerCapabilities {
    /// Check if this peer can bridge to a specific IP version target.
    ///
    /// Returns true if either:
    /// - The peer has direct connectivity to that IP version
    /// - The peer supports dual-stack bridging (can relay between versions)
    pub fn can_reach_ip_version(&self, is_ipv4: bool) -> bool {
        if is_ipv4 {
            self.direct_ipv4 || self.supports_dual_stack
        } else {
            self.direct_ipv6 || self.supports_dual_stack
        }
    }

    /// Check if this peer can act as a bridging relay between IP versions.
    pub fn can_bridge(&self) -> bool {
        self.relay && self.supports_dual_stack
    }
}

/// A relay announcement for NAT traversal fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAnnouncement {
    /// Hex-encoded peer ID of the relay.
    pub peer_id: String,
    /// Addresses where the relay can be reached.
    pub addresses: Vec<SocketAddr>,
    /// Number of active relay connections (load indicator).
    pub active_connections: u32,
    /// Maximum relay connections this node supports.
    pub max_connections: u32,
    /// Timestamp when this announcement was created.
    pub timestamp_ms: u64,
    /// Geographic region for proximity-based selection.
    pub region: Option<String>,
    /// Whether this relay supports dual-stack bridging (IPv4 ↔ IPv6).
    #[serde(default)]
    pub supports_dual_stack: bool,
}

impl RelayAnnouncement {
    /// Check if this relay can reach the target address.
    ///
    /// Returns true if:
    /// - Relay has an address in the same IP version as target
    /// - Relay supports dual-stack bridging
    pub fn can_reach(&self, target: &SocketAddr) -> bool {
        if self.supports_dual_stack {
            return true;
        }
        // Check if any address matches the target's IP version
        self.addresses
            .iter()
            .any(|a| a.is_ipv4() == target.is_ipv4())
    }

    /// Get IPv4 addresses from this relay.
    pub fn ipv4_addresses(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .filter(|a| a.is_ipv4())
            .copied()
            .collect()
    }

    /// Get IPv6 addresses from this relay.
    pub fn ipv6_addresses(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .filter(|a| a.is_ipv6())
            .copied()
            .collect()
    }

    /// Check if this relay has addresses in both IP versions.
    pub fn has_both_ip_versions(&self) -> bool {
        let has_v4 = self.addresses.iter().any(|a| a.is_ipv4());
        let has_v6 = self.addresses.iter().any(|a| a.is_ipv6());
        has_v4 && has_v6
    }
}

/// A coordinator announcement for NAT traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorAnnouncement {
    /// Hex-encoded peer ID of the coordinator.
    pub peer_id: String,
    /// Addresses where the coordinator can be reached.
    pub addresses: Vec<SocketAddr>,
    /// Number of active coordination sessions.
    pub active_sessions: u32,
    /// Timestamp when this announcement was created.
    pub timestamp_ms: u64,
    /// Success rate for hole-punching (0.0-1.0).
    pub success_rate: f32,
}

/// Query: "Who is connected to peer X?" for NAT coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnectionQuery {
    /// Unique query ID for matching responses.
    pub query_id: [u8; 16],
    /// Hex-encoded peer ID of the querier.
    pub querier_id: String,
    /// ML-DSA-65 public key (hex) of the target peer we want to find.
    pub target_public_key: String,
    /// Timestamp when this query was created.
    pub timestamp_ms: u64,
}

/// Response: "I'm connected to peer X" for NAT coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnectionResponse {
    /// Query ID this response is for.
    pub query_id: [u8; 16],
    /// Hex-encoded peer ID of the responder.
    pub responder_id: String,
    /// Addresses where the responder can be reached.
    pub responder_addresses: Vec<SocketAddr>,
    /// Timestamp when this connection was established.
    pub connected_since_ms: u64,
    /// Connection quality metric (0.0-1.0).
    pub connection_quality: f64,
}

/// Events from the gossip layer.
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// New peer discovered via gossip.
    PeerDiscovered(PeerAnnouncement),
    /// New relay discovered via gossip.
    RelayDiscovered(RelayAnnouncement),
    /// New coordinator discovered via gossip.
    CoordinatorDiscovered(CoordinatorAnnouncement),
    /// A peer went offline (no recent announcements).
    PeerOffline(String),
    /// Peer connection query received.
    PeerQueryReceived(PeerConnectionQuery),
    /// Peer connection response received.
    PeerResponseReceived(PeerConnectionResponse),
}

/// Configuration for the gossip layer.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// How often to re-announce ourselves.
    pub announce_interval: Duration,
    /// How long before a peer is considered stale.
    pub peer_ttl: Duration,
    /// Maximum peers to track.
    pub max_peers: usize,
    /// Maximum relays to track.
    pub max_relays: usize,
    /// Maximum coordinators to track.
    pub max_coordinators: usize,
    /// Path to persistent peer cache (optional).
    pub cache_path: Option<PathBuf>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(30),
            peer_ttl: Duration::from_secs(120),
            max_peers: 1000,
            max_relays: 50,
            max_coordinators: 50,
            cache_path: None,
        }
    }
}

/// Metrics for gossip layer (Prometheus-compatible).
#[derive(Debug, Default)]
pub struct GossipMetrics {
    /// Total peer announcements sent.
    pub announcements_sent: AtomicU64,
    /// Total peer announcements received.
    pub announcements_received: AtomicU64,
    /// Total peer queries sent.
    pub peer_queries_sent: AtomicU64,
    /// Total peer queries received.
    pub peer_queries_received: AtomicU64,
    /// Total peer query responses sent.
    pub peer_responses_sent: AtomicU64,
    /// Total peer query responses received.
    pub peer_responses_received: AtomicU64,
    /// Bootstrap cache updates.
    pub cache_updates: AtomicU64,
    /// Bootstrap cache hits (found peer in cache).
    pub cache_hits: AtomicU64,
    /// Bootstrap cache misses.
    pub cache_misses: AtomicU64,
}

impl GossipMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get metrics as Prometheus-format text.
    pub fn to_prometheus(&self) -> String {
        format!(
            r#"# HELP ant_quic_gossip_announcements_sent Total peer announcements sent
# TYPE ant_quic_gossip_announcements_sent counter
ant_quic_gossip_announcements_sent {}

# HELP ant_quic_gossip_announcements_received Total peer announcements received
# TYPE ant_quic_gossip_announcements_received counter
ant_quic_gossip_announcements_received {}

# HELP ant_quic_gossip_peer_queries_sent Total peer queries sent
# TYPE ant_quic_gossip_peer_queries_sent counter
ant_quic_gossip_peer_queries_sent {}

# HELP ant_quic_gossip_peer_queries_received Total peer queries received
# TYPE ant_quic_gossip_peer_queries_received counter
ant_quic_gossip_peer_queries_received {}

# HELP ant_quic_gossip_peer_responses_sent Total peer query responses sent
# TYPE ant_quic_gossip_peer_responses_sent counter
ant_quic_gossip_peer_responses_sent {}

# HELP ant_quic_gossip_peer_responses_received Total peer query responses received
# TYPE ant_quic_gossip_peer_responses_received counter
ant_quic_gossip_peer_responses_received {}

# HELP ant_quic_gossip_cache_updates Bootstrap cache updates
# TYPE ant_quic_gossip_cache_updates counter
ant_quic_gossip_cache_updates {}

# HELP ant_quic_gossip_cache_hits Bootstrap cache hits
# TYPE ant_quic_gossip_cache_hits counter
ant_quic_gossip_cache_hits {}

# HELP ant_quic_gossip_cache_misses Bootstrap cache misses
# TYPE ant_quic_gossip_cache_misses counter
ant_quic_gossip_cache_misses {}
"#,
            self.announcements_sent.load(Ordering::Relaxed),
            self.announcements_received.load(Ordering::Relaxed),
            self.peer_queries_sent.load(Ordering::Relaxed),
            self.peer_queries_received.load(Ordering::Relaxed),
            self.peer_responses_sent.load(Ordering::Relaxed),
            self.peer_responses_received.load(Ordering::Relaxed),
            self.cache_updates.load(Ordering::Relaxed),
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
        )
    }
}

/// Gossip layer for decentralized discovery.
///
/// Provides local announcement handling and integrates with saorsa-gossip's
/// PeerCache for persistent bootstrap cache.
pub struct GossipDiscovery {
    /// Our peer ID.
    peer_id: String,
    /// Our addresses.
    addresses: Vec<SocketAddr>,
    /// Whether we're a public node (on any IP family).
    is_public: bool,
    /// Whether we're public on IPv4.
    is_public_ipv4: bool,
    /// Whether we're public on IPv6.
    is_public_ipv6: bool,
    /// Configuration.
    config: GossipConfig,
    /// Known peers from gossip.
    known_peers: Arc<RwLock<HashMap<String, (PeerAnnouncement, Instant)>>>,
    /// Known relays from gossip.
    known_relays: Arc<RwLock<HashMap<String, (RelayAnnouncement, Instant)>>>,
    /// Known coordinators from gossip.
    known_coordinators: Arc<RwLock<HashMap<String, (CoordinatorAnnouncement, Instant)>>>,
    /// Event sender for discovery events.
    event_tx: mpsc::Sender<GossipEvent>,
    /// Shutdown flag.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Gossip metrics.
    metrics: Arc<GossipMetrics>,
}

impl GossipDiscovery {
    /// Create a new gossip discovery layer.
    ///
    /// # Arguments
    /// * `peer_id` - Our peer ID as hex string
    /// * `addresses` - Our addresses (both IPv4 and IPv6)
    /// * `is_public` - Combined public status (backward compat, true if public on either family)
    /// * `is_public_ipv4` - Whether we're public on IPv4
    /// * `is_public_ipv6` - Whether we're public on IPv6
    /// * `config` - Gossip configuration
    /// * `event_tx` - Channel to send discovery events
    pub fn new(
        peer_id: String,
        addresses: Vec<SocketAddr>,
        is_public: bool,
        is_public_ipv4: bool,
        is_public_ipv6: bool,
        config: GossipConfig,
        event_tx: mpsc::Sender<GossipEvent>,
    ) -> Self {
        Self {
            peer_id,
            addresses,
            is_public,
            is_public_ipv4,
            is_public_ipv6,
            config,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            known_relays: Arc::new(RwLock::new(HashMap::new())),
            known_coordinators: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics: Arc::new(GossipMetrics::new()),
        }
    }

    /// Get current timestamp in milliseconds.
    fn timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &Arc<GossipMetrics> {
        &self.metrics
    }

    pub fn create_announcement(&self, capabilities: PeerCapabilities) -> PeerAnnouncement {
        PeerAnnouncement {
            peer_id: self.peer_id.clone(),
            addresses: self.addresses.clone(),
            is_public: self.is_public,
            is_public_ipv4: self.is_public_ipv4,
            is_public_ipv6: self.is_public_ipv6,
            timestamp_ms: Self::timestamp_ms(),
            country_code: None,
            capabilities,
            epoch: Self::timestamp_ms(),
        }
    }

    /// Handle an incoming peer announcement.
    pub async fn handle_peer_announcement(&self, announcement: PeerAnnouncement) {
        if announcement.peer_id == self.peer_id {
            return;
        }

        self.metrics
            .announcements_received
            .fetch_add(1, Ordering::Relaxed);

        let peer_id = announcement.peer_id.clone();
        let mut peers = self.known_peers.write().await;

        let (is_new, should_update) = if let Some((existing, _)) = peers.get(&peer_id) {
            (
                false,
                announcement.epoch > existing.epoch || announcement.epoch == 0,
            )
        } else {
            (true, true)
        };

        if !should_update {
            return;
        }

        peers.insert(peer_id.clone(), (announcement.clone(), Instant::now()));

        if peers.len() > self.config.max_peers {
            let mut entries: Vec<_> = peers.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
            entries.sort_by_key(|(_, t)| *t);
            for (k, _) in entries.iter().take(peers.len() - self.config.max_peers) {
                peers.remove(k);
            }
        }

        drop(peers);

        if is_new {
            debug!(
                "Gossip: discovered new peer {} (epoch {})",
                &peer_id[..16.min(peer_id.len())],
                announcement.epoch
            );
            let _ = self
                .event_tx
                .send(GossipEvent::PeerDiscovered(announcement))
                .await;
        }
    }

    /// Handle an incoming relay announcement.
    pub async fn handle_relay_announcement(&self, announcement: RelayAnnouncement) {
        let peer_id = announcement.peer_id.clone();
        let mut relays = self.known_relays.write().await;

        let is_new = !relays.contains_key(&peer_id);
        relays.insert(peer_id.clone(), (announcement.clone(), Instant::now()));

        // Enforce max relays limit
        if relays.len() > self.config.max_relays {
            let mut entries: Vec<_> = relays.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
            entries.sort_by_key(|(_, t)| *t);
            for (k, _) in entries.iter().take(relays.len() - self.config.max_relays) {
                relays.remove(k);
            }
        }

        drop(relays);

        if is_new {
            info!(
                "Gossip: discovered new relay {} at {:?}",
                &peer_id[..16.min(peer_id.len())],
                announcement.addresses
            );
            let _ = self
                .event_tx
                .send(GossipEvent::RelayDiscovered(announcement))
                .await;
        }
    }

    /// Handle an incoming coordinator announcement.
    pub async fn handle_coordinator_announcement(&self, announcement: CoordinatorAnnouncement) {
        let peer_id = announcement.peer_id.clone();
        let mut coordinators = self.known_coordinators.write().await;

        let is_new = !coordinators.contains_key(&peer_id);
        coordinators.insert(peer_id.clone(), (announcement.clone(), Instant::now()));

        // Enforce max coordinators limit
        if coordinators.len() > self.config.max_coordinators {
            let mut entries: Vec<_> = coordinators
                .iter()
                .map(|(k, (_, t))| (k.clone(), *t))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            for (k, _) in entries
                .iter()
                .take(coordinators.len() - self.config.max_coordinators)
            {
                coordinators.remove(k);
            }
        }

        drop(coordinators);

        if is_new {
            info!(
                "Gossip: discovered new coordinator {} (success rate: {:.1}%)",
                &peer_id[..16.min(peer_id.len())],
                announcement.success_rate * 100.0
            );
            let _ = self
                .event_tx
                .send(GossipEvent::CoordinatorDiscovered(announcement))
                .await;
        }
    }

    /// Handle an incoming peer connection query.
    pub async fn handle_peer_query(&self, query: PeerConnectionQuery) {
        self.metrics
            .peer_queries_received
            .fetch_add(1, Ordering::Relaxed);

        debug!(
            "Gossip: received peer query from {} for target {}",
            &query.querier_id[..8.min(query.querier_id.len())],
            &query.target_public_key[..16.min(query.target_public_key.len())]
        );

        let _ = self
            .event_tx
            .send(GossipEvent::PeerQueryReceived(query))
            .await;
    }

    /// Handle an incoming peer connection response.
    pub async fn handle_peer_response(&self, response: PeerConnectionResponse) {
        self.metrics
            .peer_responses_received
            .fetch_add(1, Ordering::Relaxed);

        debug!(
            "Gossip: received peer response from {} for query {:?}",
            &response.responder_id[..8.min(response.responder_id.len())],
            &response.query_id[..4]
        );

        let _ = self
            .event_tx
            .send(GossipEvent::PeerResponseReceived(response))
            .await;
    }

    /// Get all known peers.
    pub async fn get_peers(&self) -> Vec<PeerAnnouncement> {
        let peers = self.known_peers.read().await;
        peers.values().map(|(a, _)| a.clone()).collect()
    }

    /// Get all known relays.
    pub async fn get_relays(&self) -> Vec<RelayAnnouncement> {
        let relays = self.known_relays.read().await;
        relays.values().map(|(a, _)| a.clone()).collect()
    }

    /// Get all known coordinators.
    pub async fn get_coordinators(&self) -> Vec<CoordinatorAnnouncement> {
        let coordinators = self.known_coordinators.read().await;
        coordinators.values().map(|(a, _)| a.clone()).collect()
    }

    /// Get best relay for a target peer (based on load and geography).
    pub async fn get_best_relay(&self, _target_region: Option<&str>) -> Option<RelayAnnouncement> {
        let relays = self.known_relays.read().await;
        relays
            .values()
            .filter(|(r, _)| r.active_connections < r.max_connections)
            .min_by_key(|(r, _)| r.active_connections)
            .map(|(r, _)| r.clone())
    }

    /// Get best relay that can reach a specific target address.
    ///
    /// Prioritizes:
    /// 1. Relays with matching IP version and low load
    /// 2. Dual-stack relays that can bridge between IP versions
    ///
    /// # Arguments
    /// * `target` - The target address to reach through relay
    /// * `prefer_dual_stack` - If true, prefer dual-stack relays for bridging scenarios
    pub async fn get_best_relay_for_target(
        &self,
        target: &SocketAddr,
        prefer_dual_stack: bool,
    ) -> Option<RelayAnnouncement> {
        let relays = self.known_relays.read().await;

        // Filter to relays that can reach the target
        let mut candidates: Vec<_> = relays
            .values()
            .filter(|(r, _)| r.active_connections < r.max_connections && r.can_reach(target))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Sort by preference:
        // 1. If prefer_dual_stack: dual-stack relays first
        // 2. Lower load (active_connections) is better
        candidates.sort_by(|(a, _), (b, _)| {
            if prefer_dual_stack {
                // Dual-stack relays first
                match (a.supports_dual_stack, b.supports_dual_stack) {
                    (true, false) => return std::cmp::Ordering::Less,
                    (false, true) => return std::cmp::Ordering::Greater,
                    _ => {}
                }
            }
            // Then by load
            a.active_connections.cmp(&b.active_connections)
        });

        candidates.first().map(|(r, _)| (*r).clone())
    }

    /// Get all dual-stack relays (can bridge IPv4 ↔ IPv6).
    pub async fn get_dual_stack_relays(&self) -> Vec<RelayAnnouncement> {
        let relays = self.known_relays.read().await;
        relays
            .values()
            .filter(|(r, _)| r.supports_dual_stack)
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Get relays that can reach IPv4 targets.
    pub async fn get_ipv4_relays(&self) -> Vec<RelayAnnouncement> {
        let relays = self.known_relays.read().await;
        relays
            .values()
            .filter(|(r, _)| r.supports_dual_stack || r.addresses.iter().any(|a| a.is_ipv4()))
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Get relays that can reach IPv6 targets.
    pub async fn get_ipv6_relays(&self) -> Vec<RelayAnnouncement> {
        let relays = self.known_relays.read().await;
        relays
            .values()
            .filter(|(r, _)| r.supports_dual_stack || r.addresses.iter().any(|a| a.is_ipv6()))
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Get best coordinator for NAT traversal.
    pub async fn get_best_coordinator(&self) -> Option<CoordinatorAnnouncement> {
        let coordinators = self.known_coordinators.read().await;
        coordinators
            .values()
            .max_by(|(a, _), (b, _)| {
                a.success_rate
                    .partial_cmp(&b.success_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(c, _)| c.clone())
    }

    /// Cleanup stale entries.
    pub async fn cleanup_stale(&self) {
        let now = Instant::now();
        let ttl = self.config.peer_ttl;

        // Cleanup peers
        {
            let mut peers = self.known_peers.write().await;
            let stale: Vec<_> = peers
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) > ttl)
                .map(|(k, _)| k.clone())
                .collect();

            for peer_id in stale {
                peers.remove(&peer_id);
                // Non-blocking send to avoid deadlock if receiver is slow
                let _ = self.event_tx.try_send(GossipEvent::PeerOffline(peer_id));
            }
        }

        // Cleanup relays
        {
            let mut relays = self.known_relays.write().await;
            relays.retain(|_, (_, t)| now.duration_since(*t) <= ttl);
        }

        // Cleanup coordinators
        {
            let mut coordinators = self.known_coordinators.write().await;
            coordinators.retain(|_, (_, t)| now.duration_since(*t) <= ttl);
        }
    }

    /// Shutdown the gossip layer.
    pub fn shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Integrated gossip layer with saorsa-gossip PeerCache.
///
/// Combines GossipDiscovery with saorsa-gossip's PeerCache for:
/// - Persistent bootstrap cache (CBOR format)
/// - Quality-based peer selection
/// - NAT class tracking
pub struct GossipIntegration {
    /// Local gossip discovery.
    discovery: GossipDiscovery,
    /// saorsa-gossip's PeerCache for bootstrap persistence.
    peer_cache: PeerCache,
    /// Path to cache file.
    cache_path: Option<PathBuf>,
}

impl GossipIntegration {
    /// Create a new gossip integration layer.
    ///
    /// # Arguments
    /// * `peer_id` - Our peer ID as hex string
    /// * `addresses` - Our addresses (both IPv4 and IPv6)
    /// * `is_public` - Combined public status (backward compat)
    /// * `is_public_ipv4` - Whether we're public on IPv4
    /// * `is_public_ipv6` - Whether we're public on IPv6
    /// * `config` - Gossip configuration
    /// * `event_tx` - Channel to send discovery events
    pub fn new(
        peer_id: String,
        addresses: Vec<SocketAddr>,
        is_public: bool,
        is_public_ipv4: bool,
        is_public_ipv6: bool,
        config: GossipConfig,
        event_tx: mpsc::Sender<GossipEvent>,
    ) -> Self {
        let cache_path = config.cache_path.clone();

        // Try to load existing peer cache, or create new
        let peer_cache = cache_path
            .as_ref()
            .and_then(|path| match PeerCache::load(path) {
                Ok(cache) => {
                    info!(
                        "Loaded peer cache with {} entries from {:?}",
                        cache.len(),
                        path
                    );
                    Some(cache)
                }
                Err(e) => {
                    debug!("Could not load peer cache from {:?}: {}", path, e);
                    None
                }
            })
            .unwrap_or_default();

        let discovery = GossipDiscovery::new(
            peer_id,
            addresses,
            is_public,
            is_public_ipv4,
            is_public_ipv6,
            config,
            event_tx,
        );

        Self {
            discovery,
            peer_cache,
            cache_path,
        }
    }

    /// Get a reference to the underlying discovery layer.
    pub fn discovery(&self) -> &GossipDiscovery {
        &self.discovery
    }

    /// Get a mutable reference to the underlying discovery layer.
    pub fn discovery_mut(&mut self) -> &mut GossipDiscovery {
        &mut self.discovery
    }

    /// Get a reference to the gossip metrics.
    pub fn metrics(&self) -> &Arc<GossipMetrics> {
        self.discovery.metrics()
    }

    /// Get bootstrap cache size.
    pub fn cache_size(&self) -> usize {
        self.peer_cache.len()
    }

    /// Get best N peers from the bootstrap cache (quality-sorted).
    pub fn get_best_cached_peers(&self, count: usize) -> Vec<PeerCacheEntry> {
        // Get all coordinators (sorted by recency) as best peers
        let mut entries = self.peer_cache.get_coordinators();
        // If not enough coordinators, add relays
        if entries.len() < count {
            let relays = self.peer_cache.get_by_role(|e| e.roles.relay);
            entries.extend(relays);
        }
        entries.truncate(count);
        self.discovery
            .metrics
            .cache_hits
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        entries
    }

    /// Get all cached coordinators.
    pub fn get_cached_coordinators(&self) -> Vec<PeerCacheEntry> {
        self.peer_cache.get_coordinators()
    }

    /// Add a peer to the bootstrap cache.
    pub fn add_to_cache(&self, entry: PeerCacheEntry) {
        self.discovery
            .metrics
            .cache_updates
            .fetch_add(1, Ordering::Relaxed);
        self.peer_cache.insert(entry);
    }

    /// Add a peer by ID and addresses (simple interface for gossip).
    pub fn add_peer(&self, peer_id_hex: &str, addresses: &[std::net::SocketAddr], is_public: bool) {
        let peer_id = match parse_peer_id(peer_id_hex) {
            Some(id) => id,
            None => {
                debug!(
                    "Could not parse peer ID for cache: {}",
                    &peer_id_hex[..16.min(peer_id_hex.len())]
                );
                return;
            }
        };

        let nat_class = if is_public {
            NatClass::Eim // Endpoint-independent mapping (public)
        } else {
            NatClass::Unknown
        };

        let roles = PeerRoles {
            coordinator: false,
            relay: false,
            reflector: false,
            rendezvous: false,
        };
        let entry = PeerCacheEntry::new(peer_id, addresses.to_vec(), nat_class, roles);
        self.add_to_cache(entry);
        debug!(
            "Added peer {} with {} addresses to gossip cache",
            &peer_id_hex[..8.min(peer_id_hex.len())],
            addresses.len()
        );
    }

    /// Add a peer announcement to the bootstrap cache.
    pub fn cache_peer_announcement(&self, announcement: &PeerAnnouncement) {
        // Convert announcement to PeerCacheEntry
        let peer_id = match parse_peer_id(&announcement.peer_id) {
            Some(id) => id,
            None => {
                warn!(
                    "Could not parse peer ID for cache: {}",
                    &announcement.peer_id[..16.min(announcement.peer_id.len())]
                );
                return;
            }
        };

        let nat_class = if announcement.is_public {
            NatClass::Eim // Endpoint-independent mapping (public)
        } else if announcement.capabilities.hole_punch {
            NatClass::Edm // Endpoint-dependent mapping (can hole-punch)
        } else {
            NatClass::Unknown
        };

        let roles = PeerRoles {
            coordinator: announcement.capabilities.coordinator,
            relay: announcement.capabilities.relay,
            reflector: false,  // Not tracked in announcements
            rendezvous: false, // Not tracked in announcements
        };

        let entry = PeerCacheEntry::new(peer_id, announcement.addresses.clone(), nat_class, roles);

        self.add_to_cache(entry);
    }

    /// Lookup a peer in the cache.
    pub fn lookup_peer(&self, peer_id_hex: &str) -> Option<PeerCacheEntry> {
        let peer_id = parse_peer_id(peer_id_hex)?;
        let result = self.peer_cache.get(&peer_id);
        if result.is_some() {
            self.discovery
                .metrics
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.discovery
                .metrics
                .cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Record a successful connection to a peer.
    pub fn record_success(&self, peer_id_hex: &str) {
        if let Some(peer_id) = parse_peer_id(peer_id_hex) {
            if let Some(mut entry) = self.peer_cache.get(&peer_id) {
                entry.mark_success();
                self.peer_cache.insert(entry);
            }
        }
    }

    /// Prune old entries from the cache.
    pub fn prune_cache(&self) -> usize {
        self.peer_cache.prune_old()
    }

    /// Save the peer cache to disk (prunes stale entries first).
    pub fn save_cache(&self) -> Result<(), String> {
        let pruned = self.prune_cache();
        if pruned > 0 {
            tracing::info!("Pruned {} stale peers before saving cache", pruned);
        }

        if let Some(path) = &self.cache_path {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create cache directory: {}", e))?;
                }
            }
            self.peer_cache
                .save(path)
                .map_err(|e| format!("Failed to save peer cache: {}", e))
        } else {
            Ok(())
        }
    }

    /// Get cache status for API reporting.
    pub fn cache_status(&self) -> CacheStatus {
        // Get counts from available methods
        let total = self.peer_cache.len();
        let coordinators = self.peer_cache.get_coordinators();
        let relays = self.peer_cache.get_by_role(|e| e.roles.relay);

        CacheStatus {
            total_entries: total,
            public_peers: coordinators.len(), // Coordinators are usually public
            nat_peers: total.saturating_sub(coordinators.len()),
            with_reflexive_addr: 0, // Not easily queryable without iteration
            with_relay: relays.len(),
            coordinators: coordinators.len(),
            cache_path: self.cache_path.as_ref().map(|p| p.display().to_string()),
        }
    }
}

/// Status of the bootstrap cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatus {
    /// Total entries in cache.
    pub total_entries: usize,
    /// Peers with public addresses.
    pub public_peers: usize,
    /// Peers behind NAT.
    pub nat_peers: usize,
    /// Peers with known reflexive (external) addresses.
    pub with_reflexive_addr: usize,
    /// Peers using relay.
    pub with_relay: usize,
    /// Coordinator nodes.
    pub coordinators: usize,
    /// Path to cache file (if configured).
    pub cache_path: Option<String>,
}

/// Parse a hex-encoded peer ID string into PeerId.
fn parse_peer_id(hex_str: &str) -> Option<PeerId> {
    // PeerId is 32 bytes (BLAKE3 hash of ML-DSA pubkey)
    // We may have truncated versions, so pad or truncate as needed
    let bytes = hex::decode(hex_str).ok()?;

    if bytes.len() >= 32 {
        // Use first 32 bytes
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Some(PeerId::new(arr))
    } else {
        // Pad with zeros (for truncated peer IDs)
        let mut arr = [0u8; 32];
        arr[..bytes.len()].copy_from_slice(&bytes);
        Some(PeerId::new(arr))
    }
}

/// Serialize a peer announcement to bytes for gossip.
pub fn serialize_peer_announcement(announcement: &PeerAnnouncement) -> Vec<u8> {
    serde_json::to_vec(announcement).unwrap_or_default()
}

/// Deserialize a peer announcement from bytes.
pub fn deserialize_peer_announcement(data: &[u8]) -> Option<PeerAnnouncement> {
    serde_json::from_slice(data).ok()
}

/// Serialize a relay announcement to bytes for gossip.
pub fn serialize_relay_announcement(announcement: &RelayAnnouncement) -> Vec<u8> {
    serde_json::to_vec(announcement).unwrap_or_default()
}

/// Deserialize a relay announcement from bytes.
pub fn deserialize_relay_announcement(data: &[u8]) -> Option<RelayAnnouncement> {
    serde_json::from_slice(data).ok()
}

/// Serialize a coordinator announcement to bytes for gossip.
pub fn serialize_coordinator_announcement(announcement: &CoordinatorAnnouncement) -> Vec<u8> {
    serde_json::to_vec(announcement).unwrap_or_default()
}

/// Deserialize a coordinator announcement from bytes.
pub fn deserialize_coordinator_announcement(data: &[u8]) -> Option<CoordinatorAnnouncement> {
    serde_json::from_slice(data).ok()
}

/// Serialize a peer query to bytes for gossip.
pub fn serialize_peer_query(query: &PeerConnectionQuery) -> Vec<u8> {
    serde_json::to_vec(query).unwrap_or_default()
}

/// Deserialize a peer query from bytes.
pub fn deserialize_peer_query(data: &[u8]) -> Option<PeerConnectionQuery> {
    serde_json::from_slice(data).ok()
}

/// Serialize a peer response to bytes for gossip.
pub fn serialize_peer_response(response: &PeerConnectionResponse) -> Vec<u8> {
    serde_json::to_vec(response).unwrap_or_default()
}

/// Deserialize a peer response from bytes.
pub fn deserialize_peer_response(data: &[u8]) -> Option<PeerConnectionResponse> {
    serde_json::from_slice(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_announcement_serialization() {
        let announcement = PeerAnnouncement {
            peer_id: "abc123".to_string(),
            addresses: vec!["192.168.1.1:9000".parse().expect("valid addr")],
            is_public: true,
            is_public_ipv4: true,
            is_public_ipv6: false,
            timestamp_ms: 1234567890,
            country_code: Some("US".to_string()),
            capabilities: PeerCapabilities {
                direct: true,
                direct_ipv4: true,
                direct_ipv6: false,
                hole_punch: true,
                relay: false,
                coordinator: true,
                supports_dual_stack: false,
            },
            epoch: 1234567890,
        };

        let bytes = serialize_peer_announcement(&announcement);
        let decoded = deserialize_peer_announcement(&bytes).expect("decode failed");

        assert_eq!(decoded.peer_id, announcement.peer_id);
        assert_eq!(decoded.addresses, announcement.addresses);
        assert_eq!(decoded.is_public, announcement.is_public);
        assert_eq!(decoded.is_public_ipv4, announcement.is_public_ipv4);
        assert_eq!(decoded.is_public_ipv6, announcement.is_public_ipv6);
        assert_eq!(
            decoded.capabilities.direct_ipv4,
            announcement.capabilities.direct_ipv4
        );
        assert_eq!(
            decoded.capabilities.direct_ipv6,
            announcement.capabilities.direct_ipv6
        );
        assert_eq!(
            decoded.capabilities.supports_dual_stack,
            announcement.capabilities.supports_dual_stack
        );
    }

    #[test]
    fn test_peer_query_serialization() {
        let query = PeerConnectionQuery {
            query_id: [1u8; 16],
            querier_id: "abc123".to_string(),
            target_public_key: "def456".to_string(),
            timestamp_ms: 1234567890,
        };

        let bytes = serialize_peer_query(&query);
        let decoded = deserialize_peer_query(&bytes).expect("decode failed");

        assert_eq!(decoded.query_id, query.query_id);
        assert_eq!(decoded.querier_id, query.querier_id);
        assert_eq!(decoded.target_public_key, query.target_public_key);
    }

    #[test]
    fn test_peer_response_serialization() {
        let response = PeerConnectionResponse {
            query_id: [1u8; 16],
            responder_id: "xyz789".to_string(),
            responder_addresses: vec!["10.0.0.1:9000".parse().expect("valid addr")],
            connected_since_ms: 1234567890,
            connection_quality: 0.95,
        };

        let bytes = serialize_peer_response(&response);
        let decoded = deserialize_peer_response(&bytes).expect("decode failed");

        assert_eq!(decoded.query_id, response.query_id);
        assert_eq!(decoded.responder_id, response.responder_id);
        assert!((decoded.connection_quality - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gossip_metrics_prometheus_format() {
        let metrics = GossipMetrics::new();
        metrics.announcements_sent.store(10, Ordering::Relaxed);
        metrics.cache_hits.store(5, Ordering::Relaxed);

        let prometheus = metrics.to_prometheus();
        assert!(prometheus.contains("ant_quic_gossip_announcements_sent 10"));
        assert!(prometheus.contains("ant_quic_gossip_cache_hits 5"));
    }

    #[test]
    fn test_parse_peer_id() {
        // Full 32-byte hex (64 chars)
        let full_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let peer_id = parse_peer_id(full_hex);
        assert!(peer_id.is_some());

        // Truncated hex (should still work with padding)
        let truncated = "abc123";
        let peer_id = parse_peer_id(truncated);
        assert!(peer_id.is_some());

        // Invalid hex
        let invalid = "not-hex!";
        let peer_id = parse_peer_id(invalid);
        assert!(peer_id.is_none());
    }

    #[test]
    fn test_cache_status() {
        // Create a GossipIntegration without persistence
        let (tx, _rx) = mpsc::channel(10);
        let config = GossipConfig::default();
        let integration = GossipIntegration::new(
            "test_peer".to_string(),
            vec![],
            true,  // is_public
            true,  // is_public_ipv4
            false, // is_public_ipv6 (no IPv6 in test)
            config,
            tx,
        );

        let status = integration.cache_status();
        assert_eq!(status.total_entries, 0);
        assert!(status.cache_path.is_none());
    }

    // ========== Dual-Stack Capability Tests ==========

    #[test]
    fn test_peer_capabilities_can_reach_ipv4() {
        // IPv4-only peer
        let caps = PeerCapabilities {
            direct_ipv4: true,
            direct_ipv6: false,
            supports_dual_stack: false,
            ..Default::default()
        };
        assert!(caps.can_reach_ip_version(true)); // Can reach IPv4
        assert!(!caps.can_reach_ip_version(false)); // Cannot reach IPv6
    }

    #[test]
    fn test_peer_capabilities_can_reach_ipv6() {
        // IPv6-only peer
        let caps = PeerCapabilities {
            direct_ipv4: false,
            direct_ipv6: true,
            supports_dual_stack: false,
            ..Default::default()
        };
        assert!(!caps.can_reach_ip_version(true)); // Cannot reach IPv4
        assert!(caps.can_reach_ip_version(false)); // Can reach IPv6
    }

    #[test]
    fn test_peer_capabilities_dual_stack_can_reach_both() {
        // Dual-stack peer
        let caps = PeerCapabilities {
            direct_ipv4: false, // Even without direct, dual-stack can bridge
            direct_ipv6: false,
            supports_dual_stack: true,
            ..Default::default()
        };
        assert!(caps.can_reach_ip_version(true)); // Can reach IPv4 via bridging
        assert!(caps.can_reach_ip_version(false)); // Can reach IPv6 via bridging
    }

    #[test]
    fn test_peer_capabilities_can_bridge() {
        // Relay with dual-stack
        let caps = PeerCapabilities {
            relay: true,
            supports_dual_stack: true,
            ..Default::default()
        };
        assert!(caps.can_bridge());

        // Relay without dual-stack cannot bridge
        let caps_no_ds = PeerCapabilities {
            relay: true,
            supports_dual_stack: false,
            ..Default::default()
        };
        assert!(!caps_no_ds.can_bridge());

        // Dual-stack without relay cannot bridge
        let caps_no_relay = PeerCapabilities {
            relay: false,
            supports_dual_stack: true,
            ..Default::default()
        };
        assert!(!caps_no_relay.can_bridge());
    }

    #[test]
    fn test_relay_announcement_can_reach() {
        let ipv4_addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let ipv6_addr: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();

        // IPv4-only relay
        let ipv4_relay = RelayAnnouncement {
            peer_id: "relay1".to_string(),
            addresses: vec![ipv4_addr],
            active_connections: 0,
            max_connections: 100,
            timestamp_ms: 0,
            region: None,
            supports_dual_stack: false,
        };
        assert!(ipv4_relay.can_reach(&"10.0.0.1:8080".parse().unwrap())); // IPv4 target
        assert!(!ipv4_relay.can_reach(&"[2001:db8::2]:8080".parse().unwrap())); // IPv6 target

        // IPv6-only relay
        let ipv6_relay = RelayAnnouncement {
            peer_id: "relay2".to_string(),
            addresses: vec![ipv6_addr],
            active_connections: 0,
            max_connections: 100,
            timestamp_ms: 0,
            region: None,
            supports_dual_stack: false,
        };
        assert!(!ipv6_relay.can_reach(&"10.0.0.1:8080".parse().unwrap())); // IPv4 target
        assert!(ipv6_relay.can_reach(&"[2001:db8::2]:8080".parse().unwrap())); // IPv6 target

        // Dual-stack relay
        let dual_relay = RelayAnnouncement {
            peer_id: "relay3".to_string(),
            addresses: vec![ipv4_addr, ipv6_addr],
            active_connections: 0,
            max_connections: 100,
            timestamp_ms: 0,
            region: None,
            supports_dual_stack: true,
        };
        assert!(dual_relay.can_reach(&"10.0.0.1:8080".parse().unwrap())); // IPv4 target
        assert!(dual_relay.can_reach(&"[2001:db8::2]:8080".parse().unwrap())); // IPv6 target
    }

    #[test]
    fn test_relay_announcement_ip_version_helpers() {
        let ipv4_addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let ipv6_addr: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();

        let relay = RelayAnnouncement {
            peer_id: "relay1".to_string(),
            addresses: vec![ipv4_addr, ipv6_addr],
            active_connections: 0,
            max_connections: 100,
            timestamp_ms: 0,
            region: None,
            supports_dual_stack: true,
        };

        assert_eq!(relay.ipv4_addresses(), vec![ipv4_addr]);
        assert_eq!(relay.ipv6_addresses(), vec![ipv6_addr]);
        assert!(relay.has_both_ip_versions());

        // Single IP version relay
        let ipv4_only = RelayAnnouncement {
            peer_id: "relay2".to_string(),
            addresses: vec![ipv4_addr],
            active_connections: 0,
            max_connections: 100,
            timestamp_ms: 0,
            region: None,
            supports_dual_stack: false,
        };
        assert!(!ipv4_only.has_both_ip_versions());
    }

    #[test]
    fn test_relay_announcement_serialization_with_dual_stack() {
        let relay = RelayAnnouncement {
            peer_id: "relay1".to_string(),
            addresses: vec!["192.168.1.1:9000".parse().unwrap()],
            active_connections: 5,
            max_connections: 100,
            timestamp_ms: 1234567890,
            region: Some("us-east".to_string()),
            supports_dual_stack: true,
        };

        let bytes = serialize_relay_announcement(&relay);
        let decoded = deserialize_relay_announcement(&bytes).expect("decode failed");

        assert_eq!(decoded.peer_id, relay.peer_id);
        assert!(decoded.supports_dual_stack);
    }

    #[test]
    fn test_relay_announcement_backward_compat_no_dual_stack() {
        // Test that old announcements without supports_dual_stack field default to false
        let json = r#"{
            "peer_id": "relay1",
            "addresses": ["192.168.1.1:9000"],
            "active_connections": 5,
            "max_connections": 100,
            "timestamp_ms": 1234567890,
            "region": null
        }"#;

        let decoded: RelayAnnouncement = serde_json::from_str(json).expect("decode failed");
        assert!(!decoded.supports_dual_stack); // Should default to false
    }

    #[test]
    fn test_peer_capabilities_backward_compat() {
        // Test that old announcements without supports_dual_stack field default to false
        let json = r#"{
            "direct": true,
            "hole_punch": true,
            "relay": false,
            "coordinator": false
        }"#;

        let decoded: PeerCapabilities = serde_json::from_str(json).expect("decode failed");
        assert!(!decoded.supports_dual_stack); // Should default to false
        assert!(!decoded.direct_ipv4); // Should default to false
        assert!(!decoded.direct_ipv6); // Should default to false
    }
}
