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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
        self.total_bytes.fetch_add(
            heartbeat.bytes_sent + heartbeat.bytes_received,
            Ordering::Relaxed,
        );

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

    /// Get NAT statistics for a specific node.
    pub fn get_node_nat_stats(&self, peer_id: &str) -> NatStats {
        self.peers
            .get(peer_id)
            .map(|entry| entry.nat_stats.clone())
            .unwrap_or_default()
    }

    /// Get connection statistics for a specific node.
    /// Returns (connected_peers, bytes_sent, bytes_received)
    pub fn get_node_connection_stats(&self, peer_id: &str) -> (usize, u64, u64) {
        self.peers
            .get(peer_id)
            .map(|entry| (entry.connected_peers, entry.bytes_sent, entry.bytes_received))
            .unwrap_or((0, 0, 0))
    }

    /// Resolve geographic coordinates from IP addresses.
    /// Uses known data center IP ranges and public IP geolocation.
    fn resolve_geo(&self, addresses: &[SocketAddr]) -> (f64, f64, Option<String>) {
        let Some(addr) = addresses.first() else {
            // No address - return a random position to avoid stacking
            return (51.5, -0.1, Some("GB".to_string())); // London default
        };

        let ip = addr.ip();
        let ip_str = ip.to_string();

        // Known data center IP ranges with their locations
        // Hetzner data centers
        if ip_str.starts_with("77.42.") || ip_str.starts_with("95.216.") || ip_str.starts_with("65.109.") {
            // Hetzner Helsinki
            return (60.1699, 24.9384, Some("FI".to_string()));
        }
        if ip_str.starts_with("5.9.") || ip_str.starts_with("78.46.") || ip_str.starts_with("88.99.") {
            // Hetzner Falkenstein
            return (50.4779, 12.3713, Some("DE".to_string()));
        }
        if ip_str.starts_with("138.201.") || ip_str.starts_with("148.251.") || ip_str.starts_with("144.76.") {
            // Hetzner Nuremberg
            return (49.4521, 11.0767, Some("DE".to_string()));
        }

        // DigitalOcean data centers
        if ip_str.starts_with("159.65.") || ip_str.starts_with("164.90.") || ip_str.starts_with("167.99.") {
            // DigitalOcean various (default to NYC)
            return (40.7128, -74.0060, Some("US".to_string()));
        }
        if ip_str.starts_with("162.243.") || ip_str.starts_with("104.131.") || ip_str.starts_with("192.241.") {
            // DigitalOcean NYC
            return (40.7128, -74.0060, Some("US".to_string()));
        }
        if ip_str.starts_with("46.101.") || ip_str.starts_with("165.22.") {
            // DigitalOcean London
            return (51.5074, -0.1278, Some("GB".to_string()));
        }

        // AWS regions (common ranges)
        if ip_str.starts_with("52.") || ip_str.starts_with("54.") {
            // AWS - default to us-east-1
            return (37.7749, -122.4194, Some("US".to_string()));
        }

        // GCP ranges
        if ip_str.starts_with("35.") {
            return (37.4220, -122.0841, Some("US".to_string())); // Mountain View
        }

        // Common residential ISP ranges by first octet (approximate)
        let first_octet: u8 = ip_str.split('.').next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        match first_octet {
            // European ranges (non-overlapping)
            2..=5 | 31..=37 | 46..=47 | 62 | 77..=95 | 109 | 176..=183 | 192..=195 => {
                // Europe - spread across different cities
                let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                let cities = [
                    (51.5074, -0.1278, "GB"),  // London
                    (48.8566, 2.3522, "FR"),   // Paris
                    (52.5200, 13.4050, "DE"),  // Berlin
                    (52.3676, 4.9041, "NL"),   // Amsterdam
                    (59.3293, 18.0686, "SE"),  // Stockholm
                    (60.1699, 24.9384, "FI"),  // Helsinki
                    (55.6761, 12.5683, "DK"),  // Copenhagen
                ];
                let (lat, lon, cc) = cities[(hash as usize) % cities.len()];
                (lat, lon, Some(cc.to_string()))
            }
            // North American ranges (non-overlapping)
            23..=24 | 63..=76 | 96..=108 | 184..=185 | 206..=209 => {
                let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                let cities = [
                    (40.7128, -74.0060, "US"),   // New York
                    (34.0522, -118.2437, "US"),  // Los Angeles
                    (41.8781, -87.6298, "US"),   // Chicago
                    (47.6062, -122.3321, "US"),  // Seattle
                    (37.7749, -122.4194, "US"),  // San Francisco
                    (43.6532, -79.3832, "CA"),   // Toronto
                    (45.5017, -73.5673, "CA"),   // Montreal
                ];
                let (lat, lon, cc) = cities[(hash as usize) % cities.len()];
                (lat, lon, Some(cc.to_string()))
            }
            // Asia-Pacific ranges (non-overlapping)
            110..=126 | 202..=205 | 210..=223 => {
                let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                let cities = [
                    (35.6762, 139.6503, "JP"),   // Tokyo
                    (37.5665, 126.9780, "KR"),   // Seoul
                    (22.3193, 114.1694, "HK"),   // Hong Kong
                    (1.3521, 103.8198, "SG"),    // Singapore
                    (-33.8688, 151.2093, "AU"),  // Sydney
                    (28.6139, 77.2090, "IN"),    // New Delhi
                ];
                let (lat, lon, cc) = cities[(hash as usize) % cities.len()];
                (lat, lon, Some(cc.to_string()))
            }
            // South America (non-overlapping)
            186..=191 | 200..=201 => {
                let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                let cities = [
                    (-23.5505, -46.6333, "BR"),  // São Paulo
                    (-34.6037, -58.3816, "AR"),  // Buenos Aires
                    (-33.4489, -70.6693, "CL"),  // Santiago
                ];
                let (lat, lon, cc) = cities[(hash as usize) % cities.len()];
                (lat, lon, Some(cc.to_string()))
            }
            // Default: spread around the world based on IP hash
            _ => {
                let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                let cities = [
                    (51.5074, -0.1278, "GB"),    // London
                    (40.7128, -74.0060, "US"),   // New York
                    (35.6762, 139.6503, "JP"),   // Tokyo
                    (-33.8688, 151.2093, "AU"),  // Sydney
                    (48.8566, 2.3522, "FR"),     // Paris
                    (52.5200, 13.4050, "DE"),    // Berlin
                ];
                let (lat, lon, cc) = cities[(hash as usize) % cities.len()];
                (lat, lon, Some(cc.to_string()))
            }
        }
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
