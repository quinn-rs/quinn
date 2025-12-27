//! Gossip-based decentralized peer and relay discovery.
//!
//! This module provides a gossip layer on top of ant-quic for:
//! - Peer announcements: Broadcast known peers across the network
//! - Relay discovery: Share relay/coordinator info via gossip
//! - Coordinator election: Public nodes self-announce as coordinators
//!
//! Uses saorsa-gossip's Plumtree epidemic broadcast for O(log n) message propagation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

/// Topic names for gossip channels.
pub const TOPIC_PEERS: &str = "ant-quic/peers/v1";
pub const TOPIC_RELAYS: &str = "ant-quic/relays/v1";
pub const TOPIC_COORDINATORS: &str = "ant-quic/coordinators/v1";

/// A peer announcement broadcast via gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// Hex-encoded peer ID (first 16 chars of SHA-256(ML-DSA-65 pubkey)).
    pub peer_id: String,
    /// All known addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// Whether this peer is publicly reachable (not behind NAT).
    pub is_public: bool,
    /// Timestamp when this announcement was created.
    pub timestamp_ms: u64,
    /// Optional country code for geo-proximity routing.
    pub country_code: Option<String>,
    /// Supported NAT traversal capabilities.
    pub capabilities: PeerCapabilities,
}

/// Capabilities advertised by a peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Supports direct connections (public IP).
    pub direct: bool,
    /// Supports hole-punching (can coordinate).
    pub hole_punch: bool,
    /// Can act as a relay for other peers.
    pub relay: bool,
    /// Can act as a coordinator for NAT traversal.
    pub coordinator: bool,
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
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(30),
            peer_ttl: Duration::from_secs(120),
            max_peers: 1000,
            max_relays: 50,
            max_coordinators: 50,
        }
    }
}

/// Gossip layer for decentralized discovery.
pub struct GossipDiscovery {
    /// Our peer ID.
    peer_id: String,
    /// Our addresses.
    addresses: Vec<SocketAddr>,
    /// Whether we're a public node.
    is_public: bool,
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
}

impl GossipDiscovery {
    /// Create a new gossip discovery layer.
    pub fn new(
        peer_id: String,
        addresses: Vec<SocketAddr>,
        is_public: bool,
        config: GossipConfig,
        event_tx: mpsc::Sender<GossipEvent>,
    ) -> Self {
        Self {
            peer_id,
            addresses,
            is_public,
            config,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            known_relays: Arc::new(RwLock::new(HashMap::new())),
            known_coordinators: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get current timestamp in milliseconds.
    fn timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Create our peer announcement.
    pub fn create_announcement(&self, capabilities: PeerCapabilities) -> PeerAnnouncement {
        PeerAnnouncement {
            peer_id: self.peer_id.clone(),
            addresses: self.addresses.clone(),
            is_public: self.is_public,
            timestamp_ms: Self::timestamp_ms(),
            country_code: None, // TODO: Could be set from config
            capabilities,
        }
    }

    /// Handle an incoming peer announcement.
    pub async fn handle_peer_announcement(&self, announcement: PeerAnnouncement) {
        // Don't process our own announcements
        if announcement.peer_id == self.peer_id {
            return;
        }

        let peer_id = announcement.peer_id.clone();
        let mut peers = self.known_peers.write().await;

        // Check if this is a new peer or an update
        let is_new = !peers.contains_key(&peer_id);

        // Update or insert
        peers.insert(peer_id.clone(), (announcement.clone(), Instant::now()));

        // Enforce max peers limit
        if peers.len() > self.config.max_peers {
            // Remove oldest entries
            let mut entries: Vec<_> = peers.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
            entries.sort_by_key(|(_, t)| *t);
            for (k, _) in entries.iter().take(peers.len() - self.config.max_peers) {
                peers.remove(k);
            }
        }

        drop(peers);

        // Notify if new peer
        if is_new {
            debug!(
                "Gossip: discovered new peer {} with {} addresses",
                &peer_id[..16.min(peer_id.len())],
                announcement.addresses.len()
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
                let _ = self.event_tx.send(GossipEvent::PeerOffline(peer_id)).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_announcement_serialization() {
        let announcement = PeerAnnouncement {
            peer_id: "abc123".to_string(),
            addresses: vec!["192.168.1.1:9000".parse().expect("valid addr")],
            is_public: true,
            timestamp_ms: 1234567890,
            country_code: Some("US".to_string()),
            capabilities: PeerCapabilities {
                direct: true,
                hole_punch: true,
                relay: false,
                coordinator: true,
            },
        };

        let bytes = serialize_peer_announcement(&announcement);
        let decoded = deserialize_peer_announcement(&bytes).expect("decode failed");

        assert_eq!(decoded.peer_id, announcement.peer_id);
        assert_eq!(decoded.addresses, announcement.addresses);
        assert_eq!(decoded.is_public, announcement.is_public);
    }
}
