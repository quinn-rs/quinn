//! In-memory peer store with TTL-based expiration and historical tracking.
//!
//! This module provides thread-safe storage for registered nodes
//! with automatic expiration of stale entries and persistent
//! historical tracking for experiment results.

use crate::registry::geo::BgpGeoProvider;
use crate::registry::types::{
    ConnectionBreakdown, ConnectionMethod, ConnectionRecord, ExperimentResults, NatStats,
    NetworkEvent, NetworkStats, NodeHeartbeat, NodeRegistration, PeerInfo, PeerStatus,
};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::sync::broadcast;

/// Default time-to-live for registrations (2 minutes).
const DEFAULT_TTL_SECS: u64 = 120;

/// Heartbeat interval expected from nodes (30 seconds).
#[allow(dead_code)]
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Active threshold - nodes with heartbeat within this time are considered active.
const ACTIVE_THRESHOLD_SECS: u64 = 60;

/// Inactive threshold - nodes between active and historical (5 minutes).
const INACTIVE_THRESHOLD_SECS: u64 = 300;

/// Internal storage entry for a registered node.
#[derive(Debug, Clone)]
struct NodeEntry {
    /// Registration data
    registration: NodeRegistration,
    /// When this entry was created (kept for metadata, expiration uses last_heartbeat)
    #[allow(dead_code)]
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

/// Thread-safe peer registry store with historical tracking.
pub struct PeerStore {
    /// Active peer storage (peer_id -> NodeEntry)
    peers: DashMap<String, NodeEntry>,
    /// Historical nodes (offline but preserved for results)
    historical_peers: DashMap<String, NodeEntry>,
    /// Connection records for experiment results
    connections: RwLock<Vec<ConnectionRecord>>,
    /// Event broadcaster for real-time updates
    event_tx: broadcast::Sender<NetworkEvent>,
    /// Store creation time (for uptime calculation)
    created_at: Instant,
    /// Total connections established
    total_connections: AtomicU64,
    /// Total bytes transferred
    total_bytes: AtomicU64,
    /// IPv4 connection count
    ipv4_connections: AtomicU64,
    /// IPv6 connection count
    ipv6_connections: AtomicU64,
    /// Peak concurrent nodes
    peak_nodes: AtomicU64,
    /// Total unique nodes ever seen
    total_unique_nodes: AtomicU64,
    /// Configuration
    ttl_secs: u64,
    /// Next connection ID
    next_connection_id: AtomicU64,
    /// BGP-based geo provider for IP-to-country lookup
    geo_provider: BgpGeoProvider,
}

impl std::fmt::Debug for PeerStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerStore")
            .field("peers", &self.peers.len())
            .field("historical_peers", &self.historical_peers.len())
            .field("total_connections", &self.total_connections)
            .field("ttl_secs", &self.ttl_secs)
            .finish()
    }
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
            historical_peers: DashMap::new(),
            connections: RwLock::new(Vec::new()),
            event_tx,
            created_at: Instant::now(),
            total_connections: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            ipv4_connections: AtomicU64::new(0),
            ipv6_connections: AtomicU64::new(0),
            peak_nodes: AtomicU64::new(0),
            total_unique_nodes: AtomicU64::new(0),
            ttl_secs,
            next_connection_id: AtomicU64::new(1),
            geo_provider: BgpGeoProvider::new(),
        })
    }

    /// Subscribe to real-time network events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Register a new node or update existing registration.
    pub fn register(&self, registration: NodeRegistration) -> Result<Vec<PeerInfo>, String> {
        self.register_with_client_ip(registration, None)
    }

    /// Register a new node with optional client IP for geo-location fallback.
    ///
    /// When external_addresses is empty, uses the client_ip from the HTTP request
    /// for geographic location lookup.
    pub fn register_with_client_ip(
        &self,
        registration: NodeRegistration,
        client_ip: Option<IpAddr>,
    ) -> Result<Vec<PeerInfo>, String> {
        let peer_id = registration.peer_id.clone();
        let now = Instant::now();

        // Check if this node was previously historical (coming back online)
        let was_historical = self.historical_peers.remove(&peer_id).is_some();

        // Resolve geographic coordinates from IP
        // Use client_ip as fallback when external_addresses is empty
        let (latitude, longitude, country_code) =
            self.resolve_geo_with_fallback(&registration.external_addresses, client_ip);

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

        // Track unique nodes and peak
        if is_new && !was_historical {
            self.total_unique_nodes.fetch_add(1, Ordering::Relaxed);
        }

        // Update peak nodes
        let current_count = self.peers.len() as u64;
        let mut peak = self.peak_nodes.load(Ordering::Relaxed);
        while current_count > peak {
            match self.peak_nodes.compare_exchange_weak(
                peak,
                current_count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }

        // Broadcast registration event
        if is_new || was_historical {
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
                // Filter out expired entries (based on last heartbeat, not registration time)
                now.duration_since(entry.last_heartbeat).as_secs() < self.ttl_secs
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
        let since_heartbeat = now.duration_since(entry.last_heartbeat).as_secs();
        let is_active = since_heartbeat < active_threshold.as_secs();

        // Determine peer status
        let status = if since_heartbeat < ACTIVE_THRESHOLD_SECS {
            PeerStatus::Active
        } else if since_heartbeat < INACTIVE_THRESHOLD_SECS {
            PeerStatus::Inactive
        } else {
            PeerStatus::Historical
        };

        // Combine listen and external addresses, prioritizing external (public) addresses
        let mut addresses = entry.registration.external_addresses.clone();
        addresses.extend(entry.registration.listen_addresses.clone());
        addresses.sort();
        addresses.dedup();

        // Filter out non-routable addresses (RFC1918, loopback, link-local)
        // These private addresses are not reachable by remote peers
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|addr| {
                let ip = addr.ip();
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        !v4.is_private()
                            && !v4.is_loopback()
                            && !v4.is_link_local()
                            && !v4.is_unspecified()
                    }
                    std::net::IpAddr::V6(v6) => {
                        !v6.is_loopback()
                            && !v6.is_unspecified()
                            // Filter out link-local IPv6 (fe80::/10)
                            && (v6.segments()[0] & 0xffc0) != 0xfe80
                    }
                }
            })
            .collect();

        // Calculate success rate
        let total_attempts = entry.nat_stats.attempts.max(1);
        let total_success = entry.nat_stats.direct_success
            + entry.nat_stats.hole_punch_success
            + entry.nat_stats.relay_success;
        let success_rate = total_success as f64 / total_attempts as f64;

        // Get unix timestamp for last_seen
        let last_seen = crate::registry::types::unix_timestamp().saturating_sub(since_heartbeat);

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
            status,
            bytes_sent: entry.bytes_sent,
            bytes_received: entry.bytes_received,
            connected_peers: entry.connected_peers,
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
            // Skip expired entries (based on last heartbeat, not registration time)
            if now.duration_since(entry.last_heartbeat).as_secs() >= self.ttl_secs {
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
            historical_nodes: self.historical_peers.len(),
            total_connections,
            total_bytes_transferred: self.total_bytes.load(Ordering::Relaxed),
            connection_success_rate: success_rate,
            connection_breakdown: breakdown,
            geographic_distribution,
            uptime_secs: self.created_at.elapsed().as_secs(),
            ipv4_connections: self.ipv4_connections.load(Ordering::Relaxed),
            ipv6_connections: self.ipv6_connections.load(Ordering::Relaxed),
        }
    }

    /// Move expired entries to historical (called periodically).
    /// Returns the number of nodes moved to historical.
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut moved_to_historical = Vec::new();

        for entry in self.peers.iter() {
            // Expire based on last heartbeat, not registration time
            if now.duration_since(entry.last_heartbeat).as_secs() >= self.ttl_secs {
                moved_to_historical.push((entry.key().clone(), entry.value().clone()));
            }
        }

        let count = moved_to_historical.len();
        for (peer_id, entry) in moved_to_historical {
            // Move to historical storage instead of deleting
            self.peers.remove(&peer_id);
            self.historical_peers.insert(peer_id.clone(), entry);

            let _ = self.event_tx.send(NetworkEvent::NodeOffline {
                peer_id: peer_id.clone(),
            });
        }

        count
    }

    /// Record a connection for experiment results.
    pub async fn record_connection(
        &self,
        from_peer: String,
        to_peer: String,
        method: ConnectionMethod,
        is_ipv6: bool,
        rtt_ms: Option<u64>,
    ) {
        let id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);

        // Get country codes from peer entries
        let from_country = self
            .peers
            .get(&from_peer)
            .and_then(|e| e.country_code.clone());
        let to_country = self
            .peers
            .get(&to_peer)
            .and_then(|e| e.country_code.clone());

        let record = ConnectionRecord {
            id,
            from_peer: from_peer.clone(),
            to_peer: to_peer.clone(),
            method,
            is_ipv6,
            rtt_ms,
            timestamp: crate::registry::types::unix_timestamp(),
            from_country,
            to_country,
            is_active: true,
        };

        // Update IP version counters
        if is_ipv6 {
            self.ipv6_connections.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ipv4_connections.fetch_add(1, Ordering::Relaxed);
        }

        self.total_connections.fetch_add(1, Ordering::Relaxed);

        let mut connections = self.connections.write().await;
        connections.push(record);

        // Also broadcast the connection event
        let _ = self.event_tx.send(NetworkEvent::ConnectionEstablished {
            from_peer,
            to_peer,
            method,
            rtt_ms,
        });
    }

    /// Get all registered peers including historical.
    pub fn get_all_peers_with_historical(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        let active_threshold = Duration::from_secs(ACTIVE_THRESHOLD_SECS);

        let mut peers: Vec<PeerInfo> = self
            .peers
            .iter()
            .map(|entry| self.entry_to_peer_info(&entry, now, active_threshold))
            .collect();

        // Add historical peers with Historical status
        for entry in self.historical_peers.iter() {
            let mut info = self.entry_to_peer_info(&entry, now, active_threshold);
            info.status = PeerStatus::Historical;
            info.is_active = false;
            peers.push(info);
        }

        peers
    }

    /// Get experiment results summary.
    pub async fn get_experiment_results(&self) -> ExperimentResults {
        let now = Instant::now();
        let active_threshold = Duration::from_secs(ACTIVE_THRESHOLD_SECS);

        let connections = self.connections.read().await;

        // Aggregate NAT stats from all nodes
        let mut nat_stats = NatStats::default();
        let mut breakdown = ConnectionBreakdown::default();
        let mut geographic_distribution: HashMap<String, usize> = HashMap::new();

        // Active peers
        for entry in self.peers.iter() {
            nat_stats.attempts += entry.nat_stats.attempts;
            nat_stats.direct_success += entry.nat_stats.direct_success;
            nat_stats.hole_punch_success += entry.nat_stats.hole_punch_success;
            nat_stats.relay_success += entry.nat_stats.relay_success;
            nat_stats.failures += entry.nat_stats.failures;

            if let Some(ref cc) = entry.country_code {
                *geographic_distribution.entry(cc.clone()).or_insert(0) += 1;
            }
        }

        // Historical peers (count them too)
        for entry in self.historical_peers.iter() {
            if let Some(ref cc) = entry.country_code {
                *geographic_distribution.entry(cc.clone()).or_insert(0) += 1;
            }
        }

        // Count connections by method
        for conn in connections.iter() {
            match conn.method {
                ConnectionMethod::Direct => breakdown.direct += 1,
                ConnectionMethod::HolePunched => breakdown.hole_punched += 1,
                ConnectionMethod::Relayed => breakdown.relayed += 1,
            }
        }

        // Historical nodes as PeerInfo
        let historical_nodes: Vec<PeerInfo> = self
            .historical_peers
            .iter()
            .map(|entry| {
                let mut info = self.entry_to_peer_info(&entry, now, active_threshold);
                info.status = PeerStatus::Historical;
                info.is_active = false;
                info
            })
            .collect();

        ExperimentResults {
            start_time: crate::registry::types::unix_timestamp()
                .saturating_sub(self.created_at.elapsed().as_secs()),
            duration_secs: self.created_at.elapsed().as_secs(),
            total_nodes_seen: self.total_unique_nodes.load(Ordering::Relaxed) as usize,
            peak_concurrent_nodes: self.peak_nodes.load(Ordering::Relaxed) as usize,
            connections: connections.clone(),
            nat_stats,
            connection_breakdown: breakdown,
            ipv4_connections: self.ipv4_connections.load(Ordering::Relaxed),
            ipv6_connections: self.ipv6_connections.load(Ordering::Relaxed),
            geographic_distribution,
            historical_nodes,
        }
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
            .map(|entry| {
                (
                    entry.connected_peers,
                    entry.bytes_sent,
                    entry.bytes_received,
                )
            })
            .unwrap_or((0, 0, 0))
    }

    /// Resolve geographic coordinates from IP addresses.
    /// Uses BGP-based IP-to-ASN-to-country lookup with jitter.
    #[allow(dead_code)]
    fn resolve_geo(&self, addresses: &[SocketAddr]) -> (f64, f64, Option<String>) {
        self.resolve_geo_with_fallback(addresses, None)
    }

    /// Resolve geographic coordinates with optional client IP fallback.
    ///
    /// Priority:
    /// 1. First address in external_addresses list
    /// 2. Client IP from HTTP request (if external_addresses is empty)
    /// 3. Default London coordinates
    fn resolve_geo_with_fallback(
        &self,
        addresses: &[SocketAddr],
        client_ip: Option<IpAddr>,
    ) -> (f64, f64, Option<String>) {
        // Try to get IP from external addresses first
        let ip = if let Some(addr) = addresses.first() {
            match addr.ip() {
                IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
                IpAddr::V6(v6) => {
                    // Handle IPv4-mapped IPv6 addresses
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        Some(IpAddr::V4(v4))
                    } else {
                        Some(IpAddr::V6(v6))
                    }
                }
            }
        } else {
            // No external addresses - use client IP from HTTP request
            client_ip
        };

        match ip {
            Some(ip) => self.geo_provider.lookup(ip),
            None => {
                // No IP available - return London as default
                (51.5, -0.1, Some("GB".to_string()))
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
            historical_peers: DashMap::new(),
            connections: RwLock::new(Vec::new()),
            event_tx,
            created_at: Instant::now(),
            total_connections: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            ipv4_connections: AtomicU64::new(0),
            ipv6_connections: AtomicU64::new(0),
            peak_nodes: AtomicU64::new(0),
            total_unique_nodes: AtomicU64::new(0),
            ttl_secs: DEFAULT_TTL_SECS,
            next_connection_id: AtomicU64::new(1),
            geo_provider: BgpGeoProvider::new(),
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
