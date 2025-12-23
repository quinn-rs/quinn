//! In-memory peer store with TTL-based expiration.
//!
//! This module provides thread-safe storage for registered nodes
//! with automatic expiration of stale entries.

use crate::registry::types::{
    ConnectionBreakdown, NatStats, NetworkEvent, NetworkStats, NodeHeartbeat, NodeRegistration,
    PeerInfo,
};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Default time-to-live for registrations (2 minutes).
const DEFAULT_TTL_SECS: u64 = 120;

/// Heartbeat interval expected from nodes (30 seconds).
#[allow(dead_code)]
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Active threshold - nodes with heartbeat within this time are considered active.
const ACTIVE_THRESHOLD_SECS: u64 = 60;

/// Internal storage entry for a registered node.
#[derive(Debug, Clone)]
struct NodeEntry {
    /// Registration data
    registration: NodeRegistration,
    /// When this entry was created
    registered_at: Instant,
    /// Last heartbeat received
    last_heartbeat: Instant,
    /// Geographic coordinates (resolved from IP)
    latitude: f64,
    longitude: f64,
    /// Country code (resolved from IP)
    country_code: Option<String>,
    /// Cumulative NAT stats
    nat_stats: NatStats,
    /// Connected peers count (from last heartbeat)
    connected_peers: usize,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
}

/// Thread-safe peer registry store.
#[derive(Debug)]
pub struct PeerStore {
    /// Peer storage (peer_id -> NodeEntry)
    peers: DashMap<String, NodeEntry>,
    /// Event broadcaster for real-time updates
    event_tx: broadcast::Sender<NetworkEvent>,
    /// Store creation time (for uptime calculation)
    created_at: Instant,
    /// Total connections established (aggregate from heartbeats)
    /// Reserved for future use when tracking total connections over time.
    #[allow(dead_code)]
    total_connections: AtomicU64,
    /// Total bytes transferred
    total_bytes: AtomicU64,
    /// Configuration
    ttl_secs: u64,
}

impl PeerStore {
    /// Create a new peer store with default configuration.
    pub fn new() -> Arc<Self> {
        Self::with_ttl(DEFAULT_TTL_SECS)
    }

    /// Create a new peer store with custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1000);
        Arc::new(Self {
            peers: DashMap::new(),
            event_tx,
            created_at: Instant::now(),
            total_connections: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            ttl_secs,
        })
    }

    /// Subscribe to real-time network events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Register a new node or update existing registration.
    pub fn register(&self, registration: NodeRegistration) -> Result<Vec<PeerInfo>, String> {
        let peer_id = registration.peer_id.clone();
        let now = Instant::now();

        // Resolve geographic coordinates from IP
        // For now, use (0, 0) - will be enhanced with GeoIP module
        let (latitude, longitude, country_code) =
            self.resolve_geo(&registration.external_addresses);

        let entry = NodeEntry {
            registration: registration.clone(),
            registered_at: now,
            last_heartbeat: now,
            latitude,
            longitude,
            country_code: country_code.clone(),
            nat_stats: NatStats {
                attempts: 0,
                direct_success: 0,
                hole_punch_success: 0,
                relay_success: 0,
                failures: 0,
            },
            connected_peers: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };

        let is_new = !self.peers.contains_key(&peer_id);
        self.peers.insert(peer_id.clone(), entry);

        // Broadcast registration event
        if is_new {
            let _ = self.event_tx.send(NetworkEvent::NodeRegistered {
                peer_id: peer_id.clone(),
                country_code,
                latitude,
                longitude,
            });
        }

        // Return current peer list (excluding the registering node)
        Ok(self.get_peers_except(&peer_id))
    }

    /// Process a heartbeat from a node.
    pub fn heartbeat(&self, heartbeat: NodeHeartbeat) -> Result<(), String> {
        let peer_id = &heartbeat.peer_id;

        let mut entry = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Unknown peer: {}", peer_id))?;

        entry.last_heartbeat = Instant::now();
        entry.connected_peers = heartbeat.connected_peers;
        entry.bytes_sent = heartbeat.bytes_sent;
        entry.bytes_received = heartbeat.bytes_received;

        // Update external addresses if provided
        if let Some(addrs) = heartbeat.external_addresses {
            entry.registration.external_addresses = addrs;
        }

        // Update NAT stats if provided
        if let Some(stats) = heartbeat.nat_stats {
            entry.nat_stats = stats;
        }

        // Update global counters
        self.total_bytes
            .fetch_add(heartbeat.bytes_sent + heartbeat.bytes_received, Ordering::Relaxed);

        Ok(())
    }

    /// Get all registered peers.
    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.get_peers_except("")
    }

    /// Get all peers except the specified one.
    fn get_peers_except(&self, exclude_peer_id: &str) -> Vec<PeerInfo> {
        let now = Instant::now();
        let active_threshold = Duration::from_secs(ACTIVE_THRESHOLD_SECS);

        self.peers
            .iter()
            .filter(|entry| entry.key() != exclude_peer_id)
            .filter(|entry| {
                // Filter out expired entries
                now.duration_since(entry.registered_at).as_secs() < self.ttl_secs
            })
            .map(|entry| self.entry_to_peer_info(&entry, now, active_threshold))
            .collect()
    }

    /// Convert internal entry to public PeerInfo.
    fn entry_to_peer_info(
        &self,
        entry: &NodeEntry,
        now: Instant,
        active_threshold: Duration,
    ) -> PeerInfo {
        let is_active = now.duration_since(entry.last_heartbeat) < active_threshold;

        // Combine listen and external addresses
        let mut addresses = entry.registration.external_addresses.clone();
        addresses.extend(entry.registration.listen_addresses.clone());
        addresses.sort();
        addresses.dedup();

        // Calculate success rate
        let total_attempts = entry.nat_stats.attempts.max(1);
        let total_success = entry.nat_stats.direct_success
            + entry.nat_stats.hole_punch_success
            + entry.nat_stats.relay_success;
        let success_rate = total_success as f64 / total_attempts as f64;

        // Get unix timestamp for last_seen
        let last_seen_secs = now.duration_since(entry.last_heartbeat).as_secs();
        let last_seen = crate::registry::types::unix_timestamp().saturating_sub(last_seen_secs);

        PeerInfo {
            peer_id: entry.registration.peer_id.clone(),
            addresses,
            nat_type: entry.registration.nat_type,
            country_code: entry.country_code.clone(),
            latitude: entry.latitude,
            longitude: entry.longitude,
            last_seen,
            connection_success_rate: success_rate,
            capabilities: entry.registration.capabilities.clone(),
            version: entry.registration.version.clone(),
            is_active,
        }
    }

    /// Get network-wide statistics.
    pub fn get_stats(&self) -> NetworkStats {
        let now = Instant::now();
        let active_threshold = Duration::from_secs(ACTIVE_THRESHOLD_SECS);

        let mut total_nodes = 0;
        let mut active_nodes = 0;
        let mut total_connections: u64 = 0;
        let mut geographic_distribution: HashMap<String, usize> = HashMap::new();
        let mut breakdown = ConnectionBreakdown::default();
        let mut total_attempts: u64 = 0;
        let mut total_success: u64 = 0;

        for entry in self.peers.iter() {
            // Skip expired entries
            if now.duration_since(entry.registered_at).as_secs() >= self.ttl_secs {
                continue;
            }

            total_nodes += 1;

            if now.duration_since(entry.last_heartbeat) < active_threshold {
                active_nodes += 1;
            }

            total_connections += entry.connected_peers as u64;

            // Geographic distribution
            if let Some(ref cc) = entry.country_code {
                *geographic_distribution.entry(cc.clone()).or_insert(0) += 1;
            }

            // Connection breakdown
            breakdown.direct += entry.nat_stats.direct_success;
            breakdown.hole_punched += entry.nat_stats.hole_punch_success;
            breakdown.relayed += entry.nat_stats.relay_success;

            total_attempts += entry.nat_stats.attempts;
            total_success += entry.nat_stats.direct_success
                + entry.nat_stats.hole_punch_success
                + entry.nat_stats.relay_success;
        }

        let success_rate = if total_attempts > 0 {
            total_success as f64 / total_attempts as f64
        } else {
            1.0
        };

        NetworkStats {
            total_nodes,
            active_nodes,
            total_connections,
            total_bytes_transferred: self.total_bytes.load(Ordering::Relaxed),
            connection_success_rate: success_rate,
            connection_breakdown: breakdown,
            geographic_distribution,
            uptime_secs: self.created_at.elapsed().as_secs(),
        }
    }

    /// Remove expired entries (called periodically).
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut removed = Vec::new();

        for entry in self.peers.iter() {
            if now.duration_since(entry.registered_at).as_secs() >= self.ttl_secs {
                removed.push(entry.key().clone());
            }
        }

        let count = removed.len();
        for peer_id in removed {
            self.peers.remove(&peer_id);
            let _ = self.event_tx.send(NetworkEvent::NodeOffline {
                peer_id: peer_id.clone(),
            });
        }

        count
    }

    /// Get the number of registered peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Resolve geographic coordinates from IP addresses.
    /// TODO: Integrate with GeoIP module when available.
    fn resolve_geo(&self, addresses: &[SocketAddr]) -> (f64, f64, Option<String>) {
        // Placeholder - returns default coordinates
        // Will be replaced with actual GeoIP lookup in Phase 4
        let _addr = addresses.first();

        // Default to center of map with unknown country
        (0.0, 0.0, None)
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        // Note: This creates an Arc-less instance for testing
        let (event_tx, _) = broadcast::channel(1000);
        Self {
            peers: DashMap::new(),
            event_tx,
            created_at: Instant::now(),
            total_connections: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::types::{NatType, NodeCapabilities};

    fn make_registration(peer_id: &str) -> NodeRegistration {
        NodeRegistration {
            peer_id: peer_id.to_string(),
            public_key: "test_key".to_string(),
            listen_addresses: vec!["127.0.0.1:9000".parse().unwrap()],
            external_addresses: vec!["203.0.113.1:9000".parse().unwrap()],
            nat_type: NatType::FullCone,
            version: "0.14.1".to_string(),
            capabilities: NodeCapabilities::default(),
            location_label: None,
        }
    }

    #[test]
    fn test_register_and_get_peers() {
        let store = PeerStore::new();

        // Register first node
        let peers = store.register(make_registration("peer1")).unwrap();
        assert!(peers.is_empty()); // No other peers yet

        // Register second node
        let peers = store.register(make_registration("peer2")).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, "peer1");

        // Get all peers
        let all_peers = store.get_all_peers();
        assert_eq!(all_peers.len(), 2);
    }

    #[test]
    fn test_heartbeat() {
        let store = PeerStore::new();
        store.register(make_registration("peer1")).unwrap();

        let heartbeat = NodeHeartbeat {
            peer_id: "peer1".to_string(),
            connected_peers: 5,
            bytes_sent: 1000,
            bytes_received: 2000,
            external_addresses: None,
            nat_stats: Some(NatStats {
                attempts: 10,
                direct_success: 8,
                hole_punch_success: 1,
                relay_success: 0,
                failures: 1,
            }),
        };

        assert!(store.heartbeat(heartbeat).is_ok());

        // Verify stats updated
        let stats = store.get_stats();
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.connection_breakdown.direct, 8);
    }

    #[test]
    fn test_unknown_peer_heartbeat() {
        let store = PeerStore::new();

        let heartbeat = NodeHeartbeat {
            peer_id: "unknown".to_string(),
            connected_peers: 0,
            bytes_sent: 0,
            bytes_received: 0,
            external_addresses: None,
            nat_stats: None,
        };

        assert!(store.heartbeat(heartbeat).is_err());
    }
}
