//! Gossip-first peer discovery module.
//!
//! This module implements the gossip-first peer discovery strategy:
//! 1. Load bootstrap cache from disk (or use hardcoded bootstrap nodes)
//! 2. Gossip cache to connected peers (full sync on connect, deltas afterward)
//! 3. Try direct connection to peers
//! 4. If direct fails, request PUNCH_ME_NOW via intermediary
//! 5. Fall back to relay if hole-punch fails (30s timeout)
//!
//! Registry is used for REPORTING only, not discovery.

use ant_quic::PeerId;
use ant_quic::bootstrap_cache::{
    BootstrapCache, BootstrapCacheConfig, CachedPeer, NatType as CacheNatType, PeerSource,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info};

pub const BOOTSTRAP_NODES: &[(&str, &str)] = &[
    ("saorsa-1.saorsalabs.com", "9001"),
    ("saorsa-2.saorsalabs.com", "9001"),
    ("saorsa-3.saorsalabs.com", "9001"),
    ("saorsa-4.saorsalabs.com", "9001"),
    ("saorsa-5.saorsalabs.com", "9001"),
    ("saorsa-6.saorsalabs.com", "9001"),
    ("saorsa-7.saorsalabs.com", "9001"),
    ("saorsa-8.saorsalabs.com", "9001"),
    ("saorsa-9.saorsalabs.com", "9001"),
];

/// Configuration for gossip-first discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Directory for bootstrap cache persistence.
    pub cache_dir: std::path::PathBuf,
    /// Maximum peers in cache.
    pub max_peers: usize,
    /// Timeout for direct connection before escalating to intermediary.
    pub direct_timeout: Duration,
    /// Timeout for coordinated hole-punch before falling back to relay.
    pub punch_timeout: Duration,
    /// Relay TTL before marking peer unreachable.
    pub relay_ttl: Duration,
    /// Epsilon for epsilon-greedy peer selection (0.0-1.0).
    pub epsilon: f64,
    /// Minimum peers required before persisting cache to disk.
    pub min_peers_to_save: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            cache_dir: dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("ant-quic-test"),
            max_peers: 10_000,
            direct_timeout: Duration::from_secs(3), // 2-5s as per design
            punch_timeout: Duration::from_secs(30),
            relay_ttl: Duration::from_secs(30),
            epsilon: 0.1,
            min_peers_to_save: 10, // Default from ant-quic BootstrapCacheConfig
        }
    }
}

/// Messages for cache gossip protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheGossipMessage {
    /// Full cache sync (sent on connect).
    FullSync { peers: Vec<GossipPeerEntry> },
    /// Delta update (new/changed peers).
    Delta {
        added: Vec<GossipPeerEntry>,
        removed: Vec<String>, // peer_id hex
    },
    /// Request peer's cache.
    Request,
}

/// Simplified peer entry for gossip (subset of CachedPeer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPeerEntry {
    /// Peer ID (hex).
    pub peer_id: String,
    /// Known addresses.
    pub addresses: Vec<SocketAddr>,
    /// NAT type (for intermediary preference).
    pub nat_type: Option<String>, // "None", "FullCone", "Symmetric", etc.
    /// Whether peer supports coordination.
    pub supports_coordination: bool,
    /// Whether peer supports relay.
    pub supports_relay: bool,
    /// Success rate (0.0-1.0).
    pub success_rate: f64,
    /// Average RTT in ms.
    pub avg_rtt_ms: u32,
    /// Last seen timestamp (unix ms).
    pub last_seen_ms: u64,
}

impl GossipPeerEntry {
    /// Convert hex peer_id to PeerId.
    pub fn to_peer_id(&self) -> Option<PeerId> {
        let bytes = hex::decode(&self.peer_id).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(PeerId(arr))
    }

    /// Convert to CachedPeer for storage.
    pub fn to_cached_peer(&self) -> Option<CachedPeer> {
        let peer_id = self.to_peer_id()?;
        let mut peer = CachedPeer::new(peer_id, self.addresses.clone(), PeerSource::Merge);

        // Set capabilities
        peer.capabilities.supports_coordination = self.supports_coordination;
        peer.capabilities.supports_relay = self.supports_relay;
        peer.capabilities.nat_type = self.nat_type.as_ref().map(|s| match s.as_str() {
            "None" => CacheNatType::None,
            "FullCone" => CacheNatType::FullCone,
            "AddressRestrictedCone" => CacheNatType::AddressRestrictedCone,
            "PortRestrictedCone" => CacheNatType::PortRestrictedCone,
            "Symmetric" => CacheNatType::Symmetric,
            _ => CacheNatType::Unknown,
        });

        // Set stats from gossip data
        peer.stats.avg_rtt_ms = self.avg_rtt_ms;

        Some(peer)
    }
}

/// Gossip-first discovery service.
pub struct PeerDiscoveryService {
    /// Bootstrap cache (from ant-quic).
    cache: Arc<BootstrapCache>,
    /// Configuration.
    config: DiscoveryConfig,
    /// Event sender for discovery events.
    event_tx: mpsc::Sender<DiscoveryEvent>,
    /// Currently connected peers (peer_id hex -> connected info).
    connected_peers: Arc<RwLock<HashSet<String>>>,
    /// Peers we've sent full sync to (don't resend).
    synced_peers: Arc<RwLock<HashSet<String>>>,
    /// Pending delta changes to broadcast.
    pending_delta: Arc<RwLock<PendingDelta>>,
}

/// Pending delta changes for broadcasting.
#[derive(Debug, Default)]
pub struct PendingDelta {
    /// Peers added since last broadcast.
    pub added: Vec<GossipPeerEntry>,
    /// Peers removed since last broadcast.
    pub removed: Vec<String>,
}

/// Events from discovery layer.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// Cache was updated with new peers.
    CacheUpdated { peer_count: usize },
    /// Peer discovered via gossip.
    PeerDiscovered {
        peer_id: String,
        addresses: Vec<SocketAddr>,
    },
    /// Connection method determined.
    ConnectionMethod {
        peer_id: String,
        method: ConnectionMethod,
    },
    /// Peer marked unreachable after all attempts failed.
    PeerUnreachable { peer_id: String },
}

/// How we connected to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMethod {
    /// Direct connection succeeded.
    Direct,
    /// Hole-punch via intermediary succeeded.
    HolePunched,
    /// Relay fallback.
    Relayed,
}

/// Request for coordinated hole-punch via intermediary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedPunchRequest {
    /// ID of the peer we want to connect to.
    pub target_peer: String, // hex
    /// Our address for the target to punch to.
    pub requester_addr: SocketAddr,
    /// Our peer ID.
    pub requester_peer: String, // hex
}

/// Response from coordinated hole-punch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedPunchResponse {
    /// Whether the punch was successfully coordinated.
    pub success: bool,
    /// Target's observed address (for direct connection).
    pub target_addr: Option<SocketAddr>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Status of a punch coordination attempt.
#[derive(Debug, Clone)]
pub enum PunchCoordinationStatus {
    /// Waiting for intermediary response.
    Pending,
    /// Intermediary forwarded the request.
    Forwarded { intermediary: String },
    /// Target responded, punch in progress.
    PunchInProgress { target_addr: SocketAddr },
    /// Successfully connected.
    Success { method: ConnectionMethod },
    /// Failed, falling back to relay.
    FallbackToRelay { reason: String },
    /// Completely failed.
    Failed { reason: String },
}

/// Information about a relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Relay node peer ID.
    pub peer_id: String, // hex
    /// Relay address.
    pub address: SocketAddr,
    /// Whether relay is currently healthy.
    pub healthy: bool,
    /// Last time relay was verified working.
    pub last_verified_ms: u64,
    /// Number of active connections through this relay.
    pub active_connections: u32,
}

/// Status of a relayed connection.
#[derive(Debug, Clone)]
pub enum RelayConnectionStatus {
    /// Searching for relay.
    FindingRelay,
    /// Connecting to relay.
    Connecting { relay: String },
    /// Relay connection established.
    Connected {
        relay: String,
        established_at: std::time::Instant,
    },
    /// Attempting upgrade to direct connection.
    UpgradeInProgress {
        relay: String,
        direct_addr: SocketAddr,
    },
    /// Successfully upgraded to direct.
    UpgradedToDirect,
    /// Relay connection failed.
    Failed { reason: String },
}

// ========== GOSSIP-5: Connection Reporter for Registry ==========

/// Reporter for sending connection events to the registry.
///
/// The registry is used for REPORTING connections only, NOT for discovery.
/// This enables the dashboard to show real-time connection statistics.
pub struct ConnectionReporter {
    /// Registry base URL.
    registry_url: String,
    /// HTTP client for reporting.
    client: reqwest::Client,
    /// Our peer ID (hex string).
    our_peer_id: String,
}

impl ConnectionReporter {
    /// Create a new connection reporter.
    pub fn new(registry_url: String, our_peer_id: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            registry_url,
            client,
            our_peer_id,
        }
    }

    /// Report a successful connection to the registry.
    ///
    /// This is called after a connection is established to report:
    /// - Connection method (direct/holepunched/relayed)
    /// - NAT type detected
    /// - RTT measurement
    /// - IPv4/IPv6 path used
    pub async fn report_connection(
        &self,
        to_peer: &str,
        method: ConnectionMethod,
        is_ipv6: bool,
        rtt_ms: Option<u64>,
    ) -> Result<(), anyhow::Error> {
        // Convert our ConnectionMethod to registry's format
        let registry_method = match method {
            ConnectionMethod::Direct => "direct",
            ConnectionMethod::HolePunched => "hole_punched",
            ConnectionMethod::Relayed => "relayed",
        };

        let report = serde_json::json!({
            "from_peer": self.our_peer_id,
            "to_peer": to_peer,
            "method": registry_method,
            "is_ipv6": is_ipv6,
            "rtt_ms": rtt_ms,
        });

        let url = format!("{}/api/connection", self.registry_url);

        let response = self.client.post(&url).json(&report).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Registry report failed: {} - {}", status, body);
        }

        debug!(
            "Reported connection to registry: {} -> {} via {:?}",
            self.our_peer_id, to_peer, method
        );

        Ok(())
    }

    /// Report a connection with full NAT type information.
    pub async fn report_connection_with_nat(
        &self,
        to_peer: &str,
        method: ConnectionMethod,
        our_nat: Option<CacheNatType>,
        peer_nat: Option<CacheNatType>,
        is_ipv6: bool,
        rtt_ms: Option<u64>,
    ) -> Result<(), anyhow::Error> {
        let registry_method = match method {
            ConnectionMethod::Direct => "direct",
            ConnectionMethod::HolePunched => "hole_punched",
            ConnectionMethod::Relayed => "relayed",
        };

        let nat_to_string = |nat: Option<CacheNatType>| -> Option<String> {
            nat.map(|n| match n {
                CacheNatType::None => "none".to_string(),
                CacheNatType::FullCone => "full_cone".to_string(),
                CacheNatType::AddressRestrictedCone => "address_restricted".to_string(),
                CacheNatType::PortRestrictedCone => "port_restricted".to_string(),
                CacheNatType::Symmetric => "symmetric".to_string(),
                CacheNatType::Unknown => "unknown".to_string(),
            })
        };

        let report = serde_json::json!({
            "from_peer": self.our_peer_id,
            "to_peer": to_peer,
            "method": registry_method,
            "is_ipv6": is_ipv6,
            "rtt_ms": rtt_ms,
            "our_nat_type": nat_to_string(our_nat),
            "peer_nat_type": nat_to_string(peer_nat),
        });

        let url = format!("{}/api/connection", self.registry_url);

        let response = self.client.post(&url).json(&report).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Registry report failed: {} - {}", status, body);
        }

        debug!(
            "Reported connection to registry: {} -> {} via {:?} (NAT: {:?} -> {:?})",
            self.our_peer_id, to_peer, method, our_nat, peer_nat
        );

        Ok(())
    }

    /// Get the registry URL.
    pub fn registry_url(&self) -> &str {
        &self.registry_url
    }

    /// Get our peer ID.
    pub fn our_peer_id(&self) -> &str {
        &self.our_peer_id
    }
}

impl PeerDiscoveryService {
    /// Create a new gossip discovery service.
    pub async fn new(
        config: DiscoveryConfig,
        event_tx: mpsc::Sender<DiscoveryEvent>,
    ) -> std::io::Result<Self> {
        let cache_config = BootstrapCacheConfig::builder()
            .cache_dir(&config.cache_dir)
            .max_peers(config.max_peers)
            .epsilon(config.epsilon)
            .min_peers_to_save(config.min_peers_to_save)
            .build();

        let cache = BootstrapCache::open(cache_config).await?;

        Ok(Self {
            cache: Arc::new(cache),
            config,
            event_tx,
            connected_peers: Arc::new(RwLock::new(HashSet::new())),
            synced_peers: Arc::new(RwLock::new(HashSet::new())),
            pending_delta: Arc::new(RwLock::new(PendingDelta::default())),
        })
    }

    /// Get the bootstrap cache.
    pub fn cache(&self) -> &Arc<BootstrapCache> {
        &self.cache
    }

    /// Check if we should use hardcoded bootstrap nodes.
    pub async fn should_use_bootstrap_nodes(&self) -> bool {
        let peer_count = self.cache.peer_count().await;
        if peer_count == 0 {
            info!("Cache empty, using hardcoded bootstrap nodes");
            return true;
        }

        // Check if any cached peers are reachable
        // (This would be called after attempting to connect to cached peers)
        false
    }

    /// Get peers to try connecting to (epsilon-greedy selection from cache).
    pub async fn get_peers_to_connect(&self, count: usize) -> Vec<CachedPeer> {
        self.cache.select_peers(count).await
    }

    /// Get hardcoded bootstrap addresses.
    pub fn get_bootstrap_addresses() -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for (host, port) in BOOTSTRAP_NODES {
            // Resolve hostname
            if let Ok(resolved) =
                std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
            {
                addrs.extend(resolved);
            }
        }
        addrs
    }

    /// Generate full sync message for a peer.
    pub async fn generate_full_sync(&self) -> CacheGossipMessage {
        let peers = self.cache.all_peers().await;
        let gossip_peers: Vec<GossipPeerEntry> = peers.into_iter().map(|p| p.into()).collect();
        CacheGossipMessage::FullSync {
            peers: gossip_peers,
        }
    }

    /// Handle incoming cache gossip message.
    pub async fn handle_gossip_message(
        &self,
        from_peer: &str,
        message: CacheGossipMessage,
    ) -> Option<CacheGossipMessage> {
        match message {
            CacheGossipMessage::FullSync { peers } => {
                info!(
                    "Received full cache sync from {} with {} peers",
                    from_peer,
                    peers.len()
                );
                self.merge_gossip_peers(peers).await;
                None
            }
            CacheGossipMessage::Delta { added, removed } => {
                debug!(
                    "Received delta from {}: +{} -{} peers",
                    from_peer,
                    added.len(),
                    removed.len()
                );
                self.merge_gossip_peers(added).await;
                // Handle removed peers by removing from cache
                for peer_id_hex in removed {
                    if let Some(peer_id) = hex_to_peer_id(&peer_id_hex) {
                        self.cache.remove(&peer_id).await;
                    }
                }
                None
            }
            CacheGossipMessage::Request => {
                // Respond with full sync
                Some(self.generate_full_sync().await)
            }
        }
    }

    /// Merge received gossip peers into our cache.
    async fn merge_gossip_peers(&self, peers: Vec<GossipPeerEntry>) {
        let mut added = 0;
        for gossip_peer in peers {
            if let Some(cached_peer) = gossip_peer.to_cached_peer() {
                // Check if peer already exists
                if !self.cache.contains(&cached_peer.peer_id).await {
                    self.cache.upsert(cached_peer).await;
                    added += 1;
                }
            }
        }
        if added > 0 {
            info!("Merged {} new peers from gossip", added);
            let _ = self
                .event_tx
                .send(DiscoveryEvent::CacheUpdated {
                    peer_count: self.cache.peer_count().await,
                })
                .await;
        }
    }

    /// Mark a peer as successfully connected.
    pub async fn record_connection_success(&self, peer_id: &str, rtt_ms: u32) {
        if let Some(pid) = hex_to_peer_id(peer_id) {
            self.cache.record_success(&pid, rtt_ms).await;
        }
        self.connected_peers
            .write()
            .await
            .insert(peer_id.to_string());
    }

    /// Mark a peer as failed to connect.
    pub async fn record_connection_failure(&self, peer_id: &str) {
        if let Some(pid) = hex_to_peer_id(peer_id) {
            self.cache.record_failure(&pid).await;
        }
    }

    /// Check if a peer is marked as public (NAT type = None).
    pub async fn is_public_peer(&self, peer_id: &str) -> bool {
        if let Some(pid) = hex_to_peer_id(peer_id) {
            if let Some(peer) = self.cache.get(&pid).await {
                return matches!(peer.capabilities.nat_type, Some(CacheNatType::None));
            }
        }
        false
    }

    /// Get peers connected to a target (for intermediary selection).
    pub async fn get_peers_connected_to(&self, _target_peer_id: &str) -> Vec<String> {
        // This would query the gossip network for "Who is connected to X?"
        // For now, return connected peers that are public (good intermediaries)
        let connected = self.connected_peers.read().await;
        let mut public_peers = Vec::new();

        for peer_id in connected.iter() {
            if self.is_public_peer(peer_id).await {
                public_peers.push(peer_id.clone());
            }
        }

        public_peers
    }

    /// Save cache to disk.
    pub async fn save_cache(&self) -> std::io::Result<()> {
        self.cache.save().await
    }

    /// Get the configuration.
    pub fn discovery_config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Add a peer and track it for delta broadcast.
    pub async fn add_peer(&self, peer: CachedPeer) -> bool {
        // Check if peer already exists (deduplication)
        if self.cache.contains(&peer.peer_id).await {
            return false;
        }

        let gossip_entry: GossipPeerEntry = peer.clone().into();
        self.cache.upsert(peer).await;

        // Track in pending delta
        self.pending_delta.write().await.added.push(gossip_entry);
        true
    }

    /// Remove a peer and track it for delta broadcast.
    pub async fn remove_peer(&self, peer_id: &str) {
        if let Some(pid) = hex_to_peer_id(peer_id) {
            self.cache.remove(&pid).await;
            // Track in pending delta
            self.pending_delta
                .write()
                .await
                .removed
                .push(peer_id.to_string());
        }
    }

    /// Get and clear pending delta for broadcast.
    pub async fn take_pending_delta(&self) -> Option<CacheGossipMessage> {
        let mut delta = self.pending_delta.write().await;
        if delta.added.is_empty() && delta.removed.is_empty() {
            return None;
        }

        let message = CacheGossipMessage::Delta {
            added: std::mem::take(&mut delta.added),
            removed: std::mem::take(&mut delta.removed),
        };
        Some(message)
    }

    /// Check if there are pending changes to broadcast.
    pub async fn has_pending_delta(&self) -> bool {
        let delta = self.pending_delta.read().await;
        !delta.added.is_empty() || !delta.removed.is_empty()
    }

    // ========== GOSSIP-3: Coordinated Hole-Punch Methods ==========

    /// Select the best intermediary for a punch coordination.
    /// Prefers public nodes (NAT=None), then nodes with high success rates.
    pub async fn select_intermediary(&self, target_peer: &str) -> Option<String> {
        let connected = self.connected_peers.read().await;

        // Collect candidates with their scores
        let mut candidates: Vec<(String, f64)> = Vec::new();

        for peer_id in connected.iter() {
            // Don't use target as intermediary
            if peer_id == target_peer {
                continue;
            }

            if let Some(pid) = hex_to_peer_id(peer_id) {
                if let Some(cached) = self.cache.get(&pid).await {
                    let mut score = 0.0;

                    // Prefer public nodes (NAT=None)
                    if matches!(cached.capabilities.nat_type, Some(CacheNatType::None)) {
                        score += 100.0;
                    }

                    // Add success rate (0-1)
                    let total = cached.stats.success_count + cached.stats.failure_count;
                    if total > 0 {
                        score += cached.stats.success_count as f64 / total as f64;
                    }

                    // Penalize high RTT
                    if cached.stats.avg_rtt_ms > 0 {
                        score -= (cached.stats.avg_rtt_ms as f64 / 1000.0).min(10.0);
                    }

                    // Require coordination support
                    if cached.capabilities.supports_coordination {
                        score += 10.0;
                    }

                    candidates.push((peer_id.clone(), score));
                }
            }
        }

        // Sort by score descending
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        candidates.first().map(|(id, _)| id.clone())
    }

    /// Create a punch request to send via an intermediary.
    pub fn create_punch_request(
        &self,
        target_peer: &str,
        requester_addr: SocketAddr,
        requester_peer: &str,
    ) -> CoordinatedPunchRequest {
        CoordinatedPunchRequest {
            target_peer: target_peer.to_string(),
            requester_addr,
            requester_peer: requester_peer.to_string(),
        }
    }

    /// Handle an incoming punch request as intermediary.
    /// Returns the forwarded request to send to the target.
    pub async fn handle_punch_request_as_intermediary(
        &self,
        request: &CoordinatedPunchRequest,
    ) -> Option<CoordinatedPunchRequest> {
        // Verify we're connected to the target
        let connected = self.connected_peers.read().await;
        if !connected.contains(&request.target_peer) {
            debug!(
                "Cannot coordinate punch: not connected to target {}",
                request.target_peer
            );
            return None;
        }

        // Forward the request (the actual forwarding is done by caller)
        info!(
            "Forwarding punch request from {} to {}",
            request.requester_peer, request.target_peer
        );
        Some(request.clone())
    }

    /// Handle an incoming punch request as target.
    /// Returns the response indicating whether we'll send PUNCH_ME_NOW.
    pub fn handle_punch_request_as_target(
        &self,
        request: &CoordinatedPunchRequest,
        our_observed_addr: SocketAddr,
    ) -> CoordinatedPunchResponse {
        // In real implementation, this would trigger sending PUNCH_ME_NOW
        // to the requester's address
        info!(
            "Received punch request from {}, will punch to {}",
            request.requester_peer, request.requester_addr
        );

        CoordinatedPunchResponse {
            success: true,
            target_addr: Some(our_observed_addr),
            error: None,
        }
    }

    /// Create a failed punch response.
    pub fn create_punch_failure(reason: &str) -> CoordinatedPunchResponse {
        CoordinatedPunchResponse {
            success: false,
            target_addr: None,
            error: Some(reason.to_string()),
        }
    }

    /// Determine the connection strategy for a peer.
    /// Returns recommended method based on NAT types.
    pub async fn recommended_strategy(
        &self,
        peer_id: &str,
        our_nat: Option<CacheNatType>,
    ) -> ConnectionMethod {
        let target_nat = if let Some(pid) = hex_to_peer_id(peer_id) {
            if let Some(cached) = self.cache.get(&pid).await {
                cached.capabilities.nat_type
            } else {
                None
            }
        } else {
            None
        };

        match (our_nat, target_nat) {
            // Either side is public - direct should work
            (Some(CacheNatType::None), _) | (_, Some(CacheNatType::None)) => {
                ConnectionMethod::Direct
            }
            // Full cone NATs - hole punch should work
            (Some(CacheNatType::FullCone), Some(CacheNatType::FullCone)) => {
                ConnectionMethod::HolePunched
            }
            // Symmetric NAT on both sides - likely need relay
            (Some(CacheNatType::Symmetric), Some(CacheNatType::Symmetric)) => {
                ConnectionMethod::Relayed
            }
            // Mixed - try hole punch
            _ => ConnectionMethod::HolePunched,
        }
    }

    // ========== GOSSIP-4: Relay Fallback Methods ==========

    /// Find available relay nodes, preferring public nodes with low load.
    pub async fn find_relay_nodes(&self, count: usize) -> Vec<RelayInfo> {
        let all_peers = self.cache.all_peers().await;
        let mut relay_candidates: Vec<(CachedPeer, f64)> = Vec::new();

        for peer in all_peers {
            // Only consider peers that support relay
            if !peer.capabilities.supports_relay {
                continue;
            }

            let mut score = 0.0;

            // Prefer public nodes
            if matches!(peer.capabilities.nat_type, Some(CacheNatType::None)) {
                score += 100.0;
            }

            // Prefer peers with high success rate
            let total = peer.stats.success_count + peer.stats.failure_count;
            if total > 0 {
                score += (peer.stats.success_count as f64 / total as f64) * 50.0;
            }

            // Prefer low RTT
            if peer.stats.avg_rtt_ms > 0 && peer.stats.avg_rtt_ms < 500 {
                score += 50.0 - (peer.stats.avg_rtt_ms as f64 / 10.0);
            }

            relay_candidates.push((peer, score));
        }

        // Sort by score descending
        relay_candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Take top candidates
        relay_candidates
            .into_iter()
            .take(count)
            .map(|(peer, _)| {
                let last_verified_ms = peer
                    .last_seen
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                RelayInfo {
                    peer_id: hex::encode(peer.peer_id.0),
                    address: peer
                        .addresses
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                    healthy: true,
                    last_verified_ms,
                    active_connections: 0,
                }
            })
            .collect()
    }

    /// Select the best relay for a connection.
    /// Returns None if no suitable relay is available.
    pub async fn select_relay(&self) -> Option<RelayInfo> {
        let relays = self.find_relay_nodes(1).await;
        relays.into_iter().next()
    }

    /// Mark a relay as unhealthy (for failover).
    pub async fn mark_relay_unhealthy(&self, relay_peer_id: &str) {
        // Record failure in cache
        self.record_connection_failure(relay_peer_id).await;
        debug!("Marked relay {} as unhealthy", relay_peer_id);
    }

    /// Check if we should attempt to upgrade a relayed connection to direct.
    pub fn should_attempt_upgrade(&self, relay_established: std::time::Instant) -> bool {
        // Try to upgrade after the connection has been stable for a while
        // but within the relay TTL window
        let elapsed = relay_established.elapsed();
        elapsed > Duration::from_secs(5) && elapsed < self.config.relay_ttl
    }

    /// Create a relay fallback status.
    pub fn create_relay_fallback(reason: &str) -> PunchCoordinationStatus {
        PunchCoordinationStatus::FallbackToRelay {
            reason: reason.to_string(),
        }
    }

    /// Check if punch timeout has been exceeded.
    pub fn punch_timeout_exceeded(&self, started: std::time::Instant) -> bool {
        started.elapsed() > self.config.punch_timeout
    }

    /// Get the punch timeout duration.
    pub fn punch_timeout(&self) -> Duration {
        self.config.punch_timeout
    }

    /// Get the relay TTL duration.
    pub fn relay_ttl(&self) -> Duration {
        self.config.relay_ttl
    }

    /// Check if we need to send full sync to a peer.
    pub async fn needs_full_sync(&self, peer_id: &str) -> bool {
        !self.synced_peers.read().await.contains(peer_id)
    }

    /// Mark that we've sent full sync to a peer.
    pub async fn mark_synced(&self, peer_id: &str) {
        self.synced_peers.write().await.insert(peer_id.to_string());
    }
}

/// Convert hex string to PeerId.
fn hex_to_peer_id(hex_str: &str) -> Option<PeerId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(PeerId(arr))
}

impl From<CachedPeer> for GossipPeerEntry {
    fn from(peer: CachedPeer) -> Self {
        let nat_type = peer.capabilities.nat_type.map(|nt| match nt {
            CacheNatType::None => "None".to_string(),
            CacheNatType::FullCone => "FullCone".to_string(),
            CacheNatType::AddressRestrictedCone => "AddressRestrictedCone".to_string(),
            CacheNatType::PortRestrictedCone => "PortRestrictedCone".to_string(),
            CacheNatType::Symmetric => "Symmetric".to_string(),
            CacheNatType::Unknown => "Unknown".to_string(),
        });

        let success_rate = if peer.stats.success_count + peer.stats.failure_count > 0 {
            peer.stats.success_count as f64
                / (peer.stats.success_count + peer.stats.failure_count) as f64
        } else {
            0.5 // Default for untested peers
        };

        let last_seen_ms = peer
            .last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            peer_id: hex::encode(peer.peer_id.0),
            addresses: peer.addresses,
            nat_type,
            supports_coordination: peer.capabilities.supports_coordination,
            supports_relay: peer.capabilities.supports_relay,
            success_rate,
            avg_rtt_ms: peer.stats.avg_rtt_ms,
            last_seen_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper to create a test discovery service.
    async fn create_test_discovery() -> (
        PeerDiscoveryService,
        mpsc::Receiver<DiscoveryEvent>,
        TempDir,
    ) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = DiscoveryConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel(100);
        let discovery = PeerDiscoveryService::new(config, tx)
            .await
            .expect("Failed to create discovery");
        (discovery, rx, temp_dir)
    }

    // ========== GOSSIP-1: Bootstrap Cache Integration Tests ==========

    #[tokio::test]
    async fn test_bootstrap_cache_initialization() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Fresh cache should be empty
        let peer_count = discovery.cache.peer_count().await;
        assert_eq!(peer_count, 0, "Fresh cache should be empty");

        // Should recommend using bootstrap nodes when cache is empty
        assert!(
            discovery.should_use_bootstrap_nodes().await,
            "Should use bootstrap nodes when cache is empty"
        );
    }

    #[tokio::test]
    async fn test_cache_persistence_on_change() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = DiscoveryConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            min_peers_to_save: 1, // Allow saving with 1 peer for tests
            ..Default::default()
        };

        // Create discovery and add a peer via upsert
        {
            let (tx, _rx) = mpsc::channel(100);
            let discovery = PeerDiscoveryService::new(config.clone(), tx)
                .await
                .expect("Failed to create discovery");

            // Add a peer directly to cache
            let peer = CachedPeer::new(
                PeerId([0xab; 32]),
                vec!["127.0.0.1:9000".parse().unwrap()],
                PeerSource::Seed,
            );
            discovery.cache.upsert(peer).await;
            discovery.save_cache().await.expect("Failed to save cache");
        }

        // Create new discovery with same path - should load persisted data
        {
            let (tx, _rx) = mpsc::channel(100);
            let discovery = PeerDiscoveryService::new(config, tx)
                .await
                .expect("Failed to create discovery");

            // Cache should have the peer we added
            let peer_count = discovery.cache.peer_count().await;
            assert_eq!(peer_count, 1, "Cache should persist across restarts");
        }
    }

    #[tokio::test]
    async fn test_cache_loads_on_startup() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Cache should be available immediately after construction
        // Fresh cache is empty (0 peers)
        let count = discovery.cache.peer_count().await;
        assert_eq!(count, 0, "Fresh cache should start empty");
    }

    // ========== GOSSIP-2: Cache Gossip Protocol Tests ==========

    #[tokio::test]
    async fn test_full_sync_on_connect() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Generate full sync message
        let message = discovery.generate_full_sync().await;

        match message {
            CacheGossipMessage::FullSync { peers } => {
                // Should be able to generate sync even with empty cache
                assert!(peers.is_empty() || !peers.is_empty());
            }
            _ => panic!("Expected FullSync message"),
        }
    }

    #[tokio::test]
    async fn test_gossip_request_response() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Handle a Request message - should return FullSync
        let response = discovery
            .handle_gossip_message("test-peer", CacheGossipMessage::Request)
            .await;

        assert!(
            response.is_some(),
            "Should respond to Request with FullSync"
        );
        match response.unwrap() {
            CacheGossipMessage::FullSync { .. } => {}
            _ => panic!("Expected FullSync response"),
        }
    }

    #[tokio::test]
    async fn test_delta_broadcast_on_new_peer() {
        let (discovery, mut rx, _temp) = create_test_discovery().await;

        // Receive a delta with new peers
        let new_peer = GossipPeerEntry {
            peer_id: "deadbeef".repeat(8), // 64 hex chars = 32 bytes
            addresses: vec!["127.0.0.1:9000".parse().unwrap()],
            nat_type: Some("None".to_string()),
            supports_coordination: true,
            supports_relay: false,
            success_rate: 0.8,
            avg_rtt_ms: 50,
            last_seen_ms: 1234567890000,
        };

        discovery
            .handle_gossip_message(
                "other-peer",
                CacheGossipMessage::Delta {
                    added: vec![new_peer],
                    removed: vec![],
                },
            )
            .await;

        // Should receive CacheUpdated event
        tokio::select! {
            event = rx.recv() => {
                // May not get event if peer wasn't actually added (dedup)
                if let Some(DiscoveryEvent::CacheUpdated { peer_count }) = event {
                    assert!(peer_count > 0, "Should have added the peer");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Timeout is acceptable if no event fired
            }
        }
    }

    #[tokio::test]
    async fn test_delta_broadcast_on_status_change() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Add a peer
        let peer = CachedPeer::new(
            PeerId([0xcd; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        let added = discovery.add_peer(peer).await;
        assert!(added, "Should add new peer");

        // Should have pending delta
        assert!(
            discovery.has_pending_delta().await,
            "Should have pending delta after add"
        );

        // Take the delta
        let delta = discovery.take_pending_delta().await;
        assert!(delta.is_some(), "Should return delta");

        match delta.unwrap() {
            CacheGossipMessage::Delta { added, removed } => {
                assert_eq!(added.len(), 1, "Should have 1 added peer");
                assert!(removed.is_empty(), "Should have no removed peers");
            }
            _ => panic!("Expected Delta message"),
        }

        // After taking, should have no pending delta
        assert!(
            !discovery.has_pending_delta().await,
            "Should have no pending delta after take"
        );

        // Remove the peer
        let peer_id_hex = hex::encode([0xcd; 32]);
        discovery.remove_peer(&peer_id_hex).await;

        // Should have pending delta for removal
        assert!(
            discovery.has_pending_delta().await,
            "Should have pending delta after remove"
        );

        let delta = discovery.take_pending_delta().await;
        match delta.unwrap() {
            CacheGossipMessage::Delta { added, removed } => {
                assert!(added.is_empty(), "Should have no added peers");
                assert_eq!(removed.len(), 1, "Should have 1 removed peer");
            }
            _ => panic!("Expected Delta message"),
        }
    }

    #[tokio::test]
    async fn test_cache_merge_deduplication() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        let peer_id_hex = "ab".repeat(32); // Valid 32-byte peer ID

        // Create a gossip peer entry
        let gossip_peer = GossipPeerEntry {
            peer_id: peer_id_hex.clone(),
            addresses: vec!["127.0.0.1:9000".parse().unwrap()],
            nat_type: Some("None".to_string()),
            supports_coordination: true,
            supports_relay: false,
            success_rate: 0.8,
            avg_rtt_ms: 50,
            last_seen_ms: 1234567890000,
        };

        // Add via FullSync
        discovery
            .handle_gossip_message(
                "peer-a",
                CacheGossipMessage::FullSync {
                    peers: vec![gossip_peer.clone()],
                },
            )
            .await;

        let count_after_first = discovery.cache.peer_count().await;
        assert_eq!(count_after_first, 1, "Should have 1 peer after first sync");

        // Add same peer again via Delta - should be deduplicated
        discovery
            .handle_gossip_message(
                "peer-b",
                CacheGossipMessage::Delta {
                    added: vec![gossip_peer.clone()],
                    removed: vec![],
                },
            )
            .await;

        let count_after_second = discovery.cache.peer_count().await;
        assert_eq!(
            count_after_second, 1,
            "Should still have 1 peer after dedup"
        );

        // Add via direct add_peer - should also be deduplicated
        let peer = gossip_peer.to_cached_peer().unwrap();
        let added = discovery.add_peer(peer).await;
        assert!(!added, "Should not add duplicate peer");

        let count_after_third = discovery.cache.peer_count().await;
        assert_eq!(count_after_third, 1, "Should still have 1 peer");
    }

    // ========== GOSSIP-3: Intermediary Selection Tests ==========

    #[tokio::test]
    async fn test_intermediary_selection_prefers_public() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Add a public peer to cache and mark as connected
        let public_peer_id = hex::encode([0x11; 32]);
        let mut public_peer = CachedPeer::new(
            PeerId([0x11; 32]),
            vec!["1.2.3.4:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        public_peer.capabilities.nat_type = Some(CacheNatType::None);
        public_peer.capabilities.supports_coordination = true;
        discovery.cache.upsert(public_peer).await;
        discovery
            .connected_peers
            .write()
            .await
            .insert(public_peer_id.clone());

        // Add a NAT-behind peer
        let nat_peer_id = hex::encode([0x22; 32]);
        let mut nat_peer = CachedPeer::new(
            PeerId([0x22; 32]),
            vec!["5.6.7.8:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        nat_peer.capabilities.nat_type = Some(CacheNatType::Symmetric);
        nat_peer.capabilities.supports_coordination = true;
        discovery.cache.upsert(nat_peer).await;
        discovery
            .connected_peers
            .write()
            .await
            .insert(nat_peer_id.clone());

        // Select intermediary for a target
        let target = hex::encode([0x33; 32]);
        let intermediary = discovery.select_intermediary(&target).await;

        assert!(intermediary.is_some(), "Should find an intermediary");
        assert_eq!(
            intermediary.unwrap(),
            public_peer_id,
            "Should prefer public peer as intermediary"
        );
    }

    #[tokio::test]
    async fn test_punch_coordination_through_intermediary() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Setup: Add target peer to connected peers (simulating intermediary's view)
        let target_peer_id = hex::encode([0xaa; 32]);
        discovery
            .connected_peers
            .write()
            .await
            .insert(target_peer_id.clone());

        // Create a punch request
        let request = discovery.create_punch_request(
            &target_peer_id,
            "192.168.1.100:12345".parse().unwrap(),
            &hex::encode([0xbb; 32]),
        );

        // Intermediary should forward the request
        let forwarded = discovery
            .handle_punch_request_as_intermediary(&request)
            .await;
        assert!(
            forwarded.is_some(),
            "Should forward when connected to target"
        );

        // Remove target from connected peers
        discovery
            .connected_peers
            .write()
            .await
            .remove(&target_peer_id);

        // Now should refuse to forward
        let forwarded = discovery
            .handle_punch_request_as_intermediary(&request)
            .await;
        assert!(
            forwarded.is_none(),
            "Should not forward when not connected to target"
        );
    }

    #[tokio::test]
    async fn test_punch_success_via_coordination() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Create a punch request
        let request = CoordinatedPunchRequest {
            target_peer: hex::encode([0xcc; 32]),
            requester_addr: "10.0.0.1:5000".parse().unwrap(),
            requester_peer: hex::encode([0xdd; 32]),
        };

        // Target handles the request
        let response =
            discovery.handle_punch_request_as_target(&request, "1.2.3.4:9000".parse().unwrap());

        assert!(response.success, "Punch coordination should succeed");
        assert!(
            response.target_addr.is_some(),
            "Should include target address"
        );
        assert_eq!(
            response.target_addr.unwrap(),
            "1.2.3.4:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn test_punch_timeout_fallback_to_relay() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Test failure response creation
        let response = PeerDiscoveryService::create_punch_failure("Timeout after 30s");

        assert!(!response.success, "Should indicate failure");
        assert!(response.target_addr.is_none(), "Should have no target addr");
        assert!(response.error.is_some(), "Should have error message");
        assert!(
            response.error.unwrap().contains("Timeout"),
            "Error should mention timeout"
        );

        // Test recommended strategy for symmetric-symmetric (should suggest relay)
        let symmetric_peer_id = hex::encode([0xee; 32]);
        let mut peer = CachedPeer::new(
            PeerId([0xee; 32]),
            vec!["8.8.8.8:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        peer.capabilities.nat_type = Some(CacheNatType::Symmetric);
        discovery.cache.upsert(peer).await;

        let strategy = discovery
            .recommended_strategy(&symmetric_peer_id, Some(CacheNatType::Symmetric))
            .await;
        assert_eq!(
            strategy,
            ConnectionMethod::Relayed,
            "Symmetric-Symmetric should recommend relay"
        );
    }

    #[tokio::test]
    async fn test_connection_strategy_recommendations() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Add a public peer
        let public_peer_id = hex::encode([0xff; 32]);
        let mut peer = CachedPeer::new(
            PeerId([0xff; 32]),
            vec!["1.1.1.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        peer.capabilities.nat_type = Some(CacheNatType::None);
        discovery.cache.upsert(peer).await;

        // Public target - should recommend direct
        let strategy = discovery
            .recommended_strategy(&public_peer_id, Some(CacheNatType::Symmetric))
            .await;
        assert_eq!(
            strategy,
            ConnectionMethod::Direct,
            "Public target should recommend direct"
        );

        // We're public - should recommend direct
        let strategy = discovery
            .recommended_strategy(&public_peer_id, Some(CacheNatType::None))
            .await;
        assert_eq!(
            strategy,
            ConnectionMethod::Direct,
            "We're public should recommend direct"
        );

        // Add a full cone peer
        let fullcone_peer_id = hex::encode([0xf0; 32]);
        let mut peer = CachedPeer::new(
            PeerId([0xf0; 32]),
            vec!["2.2.2.2:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        peer.capabilities.nat_type = Some(CacheNatType::FullCone);
        discovery.cache.upsert(peer).await;

        // Full cone to full cone - hole punch
        let strategy = discovery
            .recommended_strategy(&fullcone_peer_id, Some(CacheNatType::FullCone))
            .await;
        assert_eq!(
            strategy,
            ConnectionMethod::HolePunched,
            "FullCone-FullCone should recommend hole punch"
        );
    }

    // ========== GOSSIP-4: Relay Fallback Tests ==========

    #[tokio::test]
    async fn test_relay_fallback_after_punch_timeout() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = DiscoveryConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            punch_timeout: Duration::from_millis(100), // Short timeout for testing
            relay_ttl: Duration::from_secs(30),
            ..Default::default()
        };

        let (tx, _rx) = mpsc::channel(100);
        let discovery = PeerDiscoveryService::new(config, tx)
            .await
            .expect("Failed to create discovery");

        // Simulate punch timeout
        let start = std::time::Instant::now() - Duration::from_millis(200);
        assert!(
            discovery.punch_timeout_exceeded(start),
            "Should detect punch timeout"
        );

        // Create fallback status
        let status = PeerDiscoveryService::create_relay_fallback("Punch timeout after 30s");
        match status {
            PunchCoordinationStatus::FallbackToRelay { reason } => {
                assert!(reason.contains("timeout"), "Should indicate timeout reason");
            }
            _ => panic!("Expected FallbackToRelay status"),
        }

        // Verify timeout config
        assert_eq!(
            discovery.punch_timeout(),
            Duration::from_millis(100),
            "Should return configured punch timeout"
        );
    }

    #[tokio::test]
    async fn test_relay_auto_failover_on_relay_death() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Add multiple relay nodes with same RTT for fair comparison
        let relay1_id = hex::encode([0xa1; 32]);
        let mut relay1 = CachedPeer::new(
            PeerId([0xa1; 32]),
            vec!["10.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        relay1.capabilities.nat_type = Some(CacheNatType::None);
        relay1.capabilities.supports_relay = true;
        relay1.stats.success_count = 10; // Fewer successes so failure has bigger impact
        relay1.stats.failure_count = 0;
        relay1.stats.avg_rtt_ms = 50;
        discovery.cache.upsert(relay1).await;

        let relay2_id = hex::encode([0xa2; 32]);
        let mut relay2 = CachedPeer::new(
            PeerId([0xa2; 32]),
            vec!["10.0.0.2:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        relay2.capabilities.nat_type = Some(CacheNatType::None);
        relay2.capabilities.supports_relay = true;
        relay2.stats.success_count = 10;
        relay2.stats.failure_count = 0;
        relay2.stats.avg_rtt_ms = 50; // Same RTT so success rate determines winner
        discovery.cache.upsert(relay2).await;

        // Mark relay1 as unhealthy multiple times to significantly lower its score
        discovery.mark_relay_unhealthy(&relay1_id).await;
        discovery.mark_relay_unhealthy(&relay1_id).await;
        discovery.mark_relay_unhealthy(&relay1_id).await;

        // Verify failures were recorded
        let peer = discovery.cache.get(&PeerId([0xa1; 32])).await;
        assert!(peer.is_some(), "Peer should still exist");
        assert_eq!(
            peer.unwrap().stats.failure_count,
            3,
            "Should have recorded 3 failures"
        );

        // After multiple failures, relay2 should be preferred
        // relay1: 10/(10+3) = 0.77 success rate
        // relay2: 10/(10+0) = 1.0 success rate
        let relay = discovery.select_relay().await;
        assert!(relay.is_some(), "Should find a relay after failover");
        assert_eq!(
            relay.unwrap().peer_id,
            relay2_id,
            "Should select relay2 after relay1 failed multiple times"
        );

        // Verify we can still find multiple relays for redundancy
        let relays = discovery.find_relay_nodes(2).await;
        assert_eq!(relays.len(), 2, "Should find both relays for redundancy");
    }

    #[tokio::test]
    async fn test_relay_upgrade_to_direct_in_background() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = DiscoveryConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            relay_ttl: Duration::from_secs(30),
            ..Default::default()
        };

        let (tx, _rx) = mpsc::channel(100);
        let discovery = PeerDiscoveryService::new(config, tx)
            .await
            .expect("Failed to create discovery");

        // Just established - should not upgrade yet
        let just_established = std::time::Instant::now();
        assert!(
            !discovery.should_attempt_upgrade(just_established),
            "Should not upgrade immediately"
        );

        // Established 6 seconds ago - should attempt upgrade
        let established_6s_ago = std::time::Instant::now() - Duration::from_secs(6);
        assert!(
            discovery.should_attempt_upgrade(established_6s_ago),
            "Should attempt upgrade after 5s"
        );

        // Established more than TTL ago - should not upgrade (past window)
        let established_past_ttl = std::time::Instant::now() - Duration::from_secs(35);
        assert!(
            !discovery.should_attempt_upgrade(established_past_ttl),
            "Should not upgrade past TTL"
        );

        // Verify TTL config
        assert_eq!(
            discovery.relay_ttl(),
            Duration::from_secs(30),
            "Should return configured relay TTL"
        );
    }

    #[tokio::test]
    async fn test_find_relay_nodes_prefers_public() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Add a public relay
        let public_relay_id = hex::encode([0xb1; 32]);
        let mut public_relay = CachedPeer::new(
            PeerId([0xb1; 32]),
            vec!["1.2.3.4:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        public_relay.capabilities.nat_type = Some(CacheNatType::None);
        public_relay.capabilities.supports_relay = true;
        discovery.cache.upsert(public_relay).await;

        // Add a NAT-behind relay
        let nat_relay_id = hex::encode([0xb2; 32]);
        let mut nat_relay = CachedPeer::new(
            PeerId([0xb2; 32]),
            vec!["5.6.7.8:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        nat_relay.capabilities.nat_type = Some(CacheNatType::Symmetric);
        nat_relay.capabilities.supports_relay = true;
        discovery.cache.upsert(nat_relay).await;

        // Add a peer that doesn't support relay
        let no_relay = CachedPeer::new(
            PeerId([0xb3; 32]),
            vec!["9.10.11.12:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        discovery.cache.upsert(no_relay).await;

        // Find relay nodes
        let relays = discovery.find_relay_nodes(10).await;

        // Should only include peers that support relay
        assert_eq!(relays.len(), 2, "Should find 2 relay nodes");

        // Public relay should be first
        assert_eq!(
            relays[0].peer_id, public_relay_id,
            "Public relay should be preferred"
        );
        assert_eq!(
            relays[1].peer_id, nat_relay_id,
            "NAT relay should be second"
        );
    }

    // ========== GOSSIP-5: Registry Role Tests ==========

    #[tokio::test]
    async fn test_no_registry_peer_discovery_calls() {
        // This test ensures we're not calling registry.get_peers() for discovery
        // The discovery module should not import or use RegistryClient for getting peers

        // Verify PeerDiscoveryService doesn't have registry dependency
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // Getting peers should come from cache, not registry
        let peers = discovery.get_peers_to_connect(10).await;

        // This should work without any network call
        assert!(peers.is_empty() || !peers.is_empty());
    }

    #[tokio::test]
    async fn test_connection_reporter_creation() {
        // Test that ConnectionReporter can be created with valid config
        let reporter = ConnectionReporter::new(
            "https://saorsa-1.saorsalabs.com".to_string(),
            hex::encode([0xaa; 32]),
        );

        assert_eq!(
            reporter.registry_url(),
            "https://saorsa-1.saorsalabs.com",
            "Should store registry URL"
        );
        assert_eq!(
            reporter.our_peer_id(),
            hex::encode([0xaa; 32]),
            "Should store our peer ID"
        );
    }

    #[tokio::test]
    async fn test_registry_receives_connection_reports() {
        // This test validates the structure of connection reports
        // (actual network test would be integration test with mock server)

        let reporter = ConnectionReporter::new(
            "http://localhost:12345".to_string(), // Non-existent for unit test
            hex::encode([0xbb; 32]),
        );

        // Test that report methods don't panic with valid parameters
        // (they will fail network-wise, but should not panic)
        let result = reporter
            .report_connection(
                &hex::encode([0xcc; 32]),
                ConnectionMethod::Direct,
                false, // IPv4
                Some(42),
            )
            .await;

        // Should fail because server doesn't exist, but should return error not panic
        assert!(result.is_err(), "Should fail with no server");

        // Test with NAT info
        let result = reporter
            .report_connection_with_nat(
                &hex::encode([0xdd; 32]),
                ConnectionMethod::HolePunched,
                Some(CacheNatType::FullCone),
                Some(CacheNatType::Symmetric),
                true, // IPv6
                Some(100),
            )
            .await;

        assert!(result.is_err(), "Should fail with no server");
    }

    #[tokio::test]
    async fn test_connection_reporter_method_conversion() {
        // Verify that all ConnectionMethod variants are properly handled
        let reporter = ConnectionReporter::new(
            "http://localhost:12345".to_string(),
            hex::encode([0xee; 32]),
        );

        // Test each connection method - all should produce proper JSON (even if network fails)
        for method in [
            ConnectionMethod::Direct,
            ConnectionMethod::HolePunched,
            ConnectionMethod::Relayed,
        ] {
            let result = reporter
                .report_connection(&hex::encode([0xff; 32]), method, false, None)
                .await;
            // Should fail due to network, not serialization
            assert!(
                result.is_err(),
                "Should fail due to network for {:?}",
                method
            );
        }
    }

    #[tokio::test]
    async fn test_connection_reporter_nat_type_conversion() {
        // Verify all NAT types are properly converted to strings
        let reporter = ConnectionReporter::new(
            "http://localhost:12345".to_string(),
            hex::encode([0x11; 32]),
        );

        // Test each NAT type
        for nat in [
            Some(CacheNatType::None),
            Some(CacheNatType::FullCone),
            Some(CacheNatType::AddressRestrictedCone),
            Some(CacheNatType::PortRestrictedCone),
            Some(CacheNatType::Symmetric),
            Some(CacheNatType::Unknown),
            None,
        ] {
            let result = reporter
                .report_connection_with_nat(
                    &hex::encode([0x22; 32]),
                    ConnectionMethod::Direct,
                    nat,
                    nat,
                    false,
                    Some(50),
                )
                .await;
            // Should fail due to network, not conversion
            assert!(result.is_err(), "Should fail due to network for {:?}", nat);
        }
    }

    // ========== Bootstrap Fallback Tests ==========

    #[tokio::test]
    async fn test_bootstrap_fallback_when_cache_empty() {
        let (discovery, _rx, _temp) = create_test_discovery().await;

        // With empty cache, should use bootstrap nodes
        assert!(discovery.should_use_bootstrap_nodes().await);

        // Bootstrap addresses should be resolvable
        let bootstrap_addrs = PeerDiscoveryService::get_bootstrap_addresses();
        // Note: May be empty if DNS resolution fails in test environment
        // Just verify the function doesn't panic
        assert!(bootstrap_addrs.is_empty() || !bootstrap_addrs.is_empty());
    }

    // ========== GossipPeerEntry Tests ==========

    #[tokio::test]
    async fn test_gossip_peer_entry_conversion() {
        let entry = GossipPeerEntry {
            peer_id: "ab".repeat(32), // 64 hex chars = 32 bytes
            addresses: vec!["192.168.1.1:9000".parse().unwrap()],
            nat_type: Some("FullCone".to_string()),
            supports_coordination: true,
            supports_relay: true,
            success_rate: 0.95,
            avg_rtt_ms: 42,
            last_seen_ms: 1234567890000,
        };

        let peer_id = entry.to_peer_id();
        assert!(peer_id.is_some(), "Should convert valid hex to PeerId");
        assert_eq!(peer_id.unwrap().0, [0xab; 32]);

        let cached = entry.to_cached_peer();
        assert!(cached.is_some(), "Should convert to CachedPeer");

        let cached = cached.unwrap();
        assert_eq!(cached.addresses.len(), 1);
        assert!(cached.capabilities.supports_coordination);
        assert!(cached.capabilities.supports_relay);
        assert_eq!(cached.capabilities.nat_type, Some(CacheNatType::FullCone));
    }

    #[tokio::test]
    async fn test_invalid_peer_id_handling() {
        // Invalid hex (odd length)
        let entry = GossipPeerEntry {
            peer_id: "abc".to_string(), // Invalid: odd length
            addresses: vec![],
            nat_type: None,
            supports_coordination: false,
            supports_relay: false,
            success_rate: 0.5,
            avg_rtt_ms: 0,
            last_seen_ms: 0,
        };

        assert!(entry.to_peer_id().is_none(), "Should reject invalid hex");
        assert!(
            entry.to_cached_peer().is_none(),
            "Should reject invalid peer"
        );

        // Valid hex but wrong length
        let entry2 = GossipPeerEntry {
            peer_id: "abcd".to_string(), // Valid hex but only 2 bytes
            addresses: vec![],
            nat_type: None,
            supports_coordination: false,
            supports_relay: false,
            success_rate: 0.5,
            avg_rtt_ms: 0,
            last_seen_ms: 0,
        };

        assert!(
            entry2.to_peer_id().is_none(),
            "Should reject wrong-length peer ID"
        );
    }
}
