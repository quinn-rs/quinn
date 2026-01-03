//! TUI type definitions for the network test interface.
//!
//! This module defines the data structures used by the terminal UI
//! to display network state and peer connections.

use crate::registry::{ConnectionDirection, ConnectionMethod, ConnectivityMatrix, NatType};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Connection quality indicator (5 levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionQuality {
    /// Excellent connection (< 50ms RTT)
    Excellent,
    /// Good connection (50-100ms RTT)
    Good,
    /// Fair connection (100-200ms RTT)
    Fair,
    /// Poor connection (200-500ms RTT)
    Poor,
    /// Very poor connection (> 500ms RTT)
    VeryPoor,
}

impl ConnectionQuality {
    /// Create quality indicator from RTT measurement.
    pub fn from_rtt(rtt: Duration) -> Self {
        let ms = rtt.as_millis();
        if ms < 50 {
            Self::Excellent
        } else if ms < 100 {
            Self::Good
        } else if ms < 200 {
            Self::Fair
        } else if ms < 500 {
            Self::Poor
        } else {
            Self::VeryPoor
        }
    }

    /// Get the quality bar representation (5 dots).
    pub fn as_bar(&self) -> &'static str {
        match self {
            Self::Excellent => "●●●●●",
            Self::Good => "●●●●○",
            Self::Fair => "●●●○○",
            Self::Poor => "●●○○○",
            Self::VeryPoor => "●○○○○",
        }
    }
}

/// Traffic direction indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    /// Sending data
    Sending,
    /// Receiving data
    Receiving,
    /// Idle
    Idle,
}

/// Information about a connected peer for display.
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    /// Short peer ID (first 8 chars)
    pub short_id: String,
    /// Full peer ID (QUIC PeerId hex - canonical identifier)
    pub full_id: String,
    /// Gossip peer ID (BLAKE3 hash) - for gossip transport correlation
    pub gossip_peer_id: Option<String>,
    /// Country code with flag emoji
    pub location: String,
    /// Connection method used
    pub method: ConnectionMethod,
    /// Connection direction (who initiated the current/most recent connection)
    pub direction: ConnectionDirection,
    /// Current RTT measurement
    pub rtt: Option<Duration>,
    /// Connection quality
    pub quality: ConnectionQuality,
    /// TX traffic indicator
    pub tx_active: bool,
    /// RX traffic indicator
    pub rx_active: bool,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Connection established time
    pub connected_at: Instant,
    /// Remote addresses
    pub addresses: Vec<SocketAddr>,
    /// Connectivity matrix showing all tested paths
    pub connectivity: ConnectivityMatrix,
    /// Outbound connection verified (we successfully connected to them)
    pub outbound_verified: bool,
    /// Inbound connection verified (they successfully connected to us - proves NAT traversal!)
    pub inbound_verified: bool,
    /// When we last tested NAT traversal with this peer
    pub last_nat_test_time: Option<Instant>,
    /// Last time we had a connection to/from this peer (for 30-second rule)
    pub last_connection_time: Instant,
    /// Current NAT traversal phase
    pub nat_phase: NatTraversalPhase,
    /// Peer ID coordinating NAT traversal (if applicable)
    pub coordinator_id: Option<String>,
    /// Protocol traffic (TX)
    pub protocol_tx: bool,
    /// Protocol traffic (RX)
    pub protocol_rx: bool,
    /// Test data traffic (TX)
    pub data_tx: bool,
    /// Test data traffic (RX)
    pub data_rx: bool,
}

impl ConnectedPeer {
    /// Create a new connected peer.
    pub fn new(peer_id: &str, method: ConnectionMethod) -> Self {
        Self::with_direction(peer_id, method, ConnectionDirection::Outbound)
    }

    /// Create a new connected peer with explicit direction.
    pub fn with_direction(
        peer_id: &str,
        method: ConnectionMethod,
        direction: ConnectionDirection,
    ) -> Self {
        let short_id = if peer_id.len() > 8 {
            peer_id[..8].to_string()
        } else {
            peer_id.to_string()
        };

        let now = Instant::now();
        let (outbound_verified, inbound_verified) = match direction {
            ConnectionDirection::Outbound => (true, false),
            ConnectionDirection::Inbound => (false, true),
        };

        Self {
            short_id,
            full_id: peer_id.to_string(),
            gossip_peer_id: None,
            location: "??".to_string(),
            method,
            direction,
            rtt: None,
            quality: ConnectionQuality::Fair,
            tx_active: false,
            rx_active: false,
            packets_sent: 0,
            packets_received: 0,
            connected_at: now,
            addresses: Vec::new(),
            connectivity: ConnectivityMatrix::default(),
            outbound_verified,
            inbound_verified,
            last_nat_test_time: None,
            last_connection_time: now,
            nat_phase: NatTraversalPhase::Discovering,
            coordinator_id: None,
            protocol_tx: false,
            protocol_rx: false,
            data_tx: false,
            data_rx: false,
        }
    }

    /// Set the gossip peer ID for correlation.
    pub fn set_gossip_peer_id(&mut self, gossip_id: &str) {
        self.gossip_peer_id = Some(gossip_id.to_string());
    }

    /// Mark that outbound connection was verified (we connected to them).
    pub fn mark_outbound_verified(&mut self) {
        self.outbound_verified = true;
        self.last_connection_time = Instant::now();
    }

    /// Mark that inbound connection was verified (they connected to us).
    pub fn mark_inbound_verified(&mut self) {
        self.inbound_verified = true;
        self.last_connection_time = Instant::now();
    }

    /// Check if NAT traversal is fully verified (both directions tested).
    pub fn is_nat_verified(&self) -> bool {
        self.outbound_verified && self.inbound_verified
    }

    /// Check if this peer is eligible for a NAT callback test (30-second rule).
    /// Returns true if we haven't had a connection for 30+ seconds.
    pub fn needs_nat_callback_test(&self) -> bool {
        self.last_connection_time.elapsed() > Duration::from_secs(30)
    }

    /// Update RTT measurement.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
        self.quality = ConnectionQuality::from_rtt(rtt);
    }

    /// Get formatted RTT string.
    pub fn rtt_string(&self) -> String {
        match self.rtt {
            Some(rtt) => format!("{}ms", rtt.as_millis()),
            None => "---".to_string(),
        }
    }

    /// Get TX/RX indicator string.
    pub fn traffic_indicator(&self) -> String {
        let tx = if self.tx_active { ">>" } else { "  " };
        let rx = if self.rx_active { "<<" } else { "  " };
        format!("[{}] [{}]", tx, rx)
    }

    /// Get connectivity summary string.
    pub fn connectivity_summary(&self) -> String {
        self.connectivity.summary()
    }

    /// Update connectivity matrix from test results.
    pub fn update_connectivity(&mut self, matrix: ConnectivityMatrix) {
        self.connectivity = matrix;
    }
}

/// Local node information for display.
#[derive(Debug, Clone)]
pub struct LocalNodeInfo {
    /// Peer ID (full)
    pub peer_id: String,
    /// Short peer ID (first 8 chars)
    pub short_id: String,
    /// Detected NAT type
    pub nat_type: NatType,
    /// Local IPv4 address
    pub local_ipv4: Option<SocketAddr>,
    /// External IPv4 address (discovered)
    pub external_ipv4: Option<SocketAddr>,
    /// Local IPv6 address
    pub local_ipv6: Option<SocketAddr>,
    /// External IPv6 address (discovered)
    pub external_ipv6: Option<SocketAddr>,
    /// Whether registered with central registry
    pub registered: bool,
    /// Time until registration expires
    pub registration_expires_in: Option<Duration>,
    /// Last heartbeat sent
    pub last_heartbeat: Option<Instant>,
}

impl Default for LocalNodeInfo {
    fn default() -> Self {
        Self {
            peer_id: String::new(),
            short_id: String::new(),
            nat_type: NatType::Unknown,
            local_ipv4: None,
            external_ipv4: None,
            local_ipv6: None,
            external_ipv6: None,
            registered: false,
            registration_expires_in: None,
            last_heartbeat: None,
        }
    }
}

impl LocalNodeInfo {
    /// Set the peer ID.
    pub fn set_peer_id(&mut self, peer_id: &str) {
        self.peer_id = peer_id.to_string();
        self.short_id = if peer_id.len() > 8 {
            peer_id[..8].to_string()
        } else {
            peer_id.to_string()
        };
    }

    /// Get registration status string.
    pub fn registration_status(&self) -> &'static str {
        if self.registered {
            "✓"
        } else {
            "✗"
        }
    }

    /// Get last heartbeat string.
    pub fn heartbeat_status(&self) -> String {
        match self.last_heartbeat {
            Some(instant) => {
                let elapsed = instant.elapsed().as_secs();
                format!("{}s ago", elapsed)
            }
            None => "Never".to_string(),
        }
    }
}

/// Network-wide statistics for display.
#[derive(Debug, Clone, Default)]
pub struct NetworkStatistics {
    /// Total connection attempts
    pub connection_attempts: u64,
    /// Successful connections
    pub connection_successes: u64,
    /// Failed connections
    pub connection_failures: u64,
    /// Direct connections
    pub direct_connections: u64,
    /// Hole-punched connections
    pub hole_punched_connections: u64,
    /// Relayed connections
    pub relayed_connections: u64,
    /// Inbound connections (they connected to us - proves NAT traversal works!)
    pub inbound_connections: u64,
    /// Outbound connections (we connected to them)
    pub outbound_connections: u64,
    /// Test packets sent
    pub packets_sent: u64,
    /// Test packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Node start time
    pub started_at: Option<Instant>,
    /// Total registered nodes in network
    pub total_registered_nodes: usize,
    /// Peers discovered via gossip network
    pub gossip_peers_discovered: u64,
    /// Relays discovered via gossip network
    pub gossip_relays_discovered: u64,
    /// SWIM liveness: peers marked alive
    pub swim_alive: usize,
    /// SWIM liveness: peers marked suspect
    pub swim_suspect: usize,
    /// SWIM liveness: peers marked dead
    pub swim_dead: usize,
    /// HyParView: active view size
    pub hyparview_active: usize,
    /// HyParView: passive view size
    pub hyparview_passive: usize,
}

impl NetworkStatistics {
    /// Get connection success rate as percentage.
    pub fn success_rate(&self) -> f64 {
        if self.connection_attempts == 0 {
            0.0
        } else {
            (self.connection_successes as f64 / self.connection_attempts as f64) * 100.0
        }
    }

    /// Get uptime string.
    pub fn uptime(&self) -> String {
        match self.started_at {
            Some(started) => {
                let elapsed = started.elapsed();
                let hours = elapsed.as_secs() / 3600;
                let minutes = (elapsed.as_secs() % 3600) / 60;
                let seconds = elapsed.as_secs() % 60;
                format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
            }
            None => "00:00:00".to_string(),
        }
    }

    /// Get formatted bytes sent.
    pub fn bytes_sent_formatted(&self) -> String {
        format_bytes(self.bytes_sent)
    }

    /// Get formatted bytes received.
    pub fn bytes_received_formatted(&self) -> String {
        format_bytes(self.bytes_received)
    }
}

/// Format bytes into human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Country code to flag emoji mapping.
pub fn country_flag(country_code: &str) -> &'static str {
    match country_code.to_uppercase().as_str() {
        "US" => "🇺🇸",
        "GB" | "UK" => "🇬🇧",
        "DE" => "🇩🇪",
        "FR" => "🇫🇷",
        "JP" => "🇯🇵",
        "CN" => "🇨🇳",
        "KR" => "🇰🇷",
        "AU" => "🇦🇺",
        "CA" => "🇨🇦",
        "BR" => "🇧🇷",
        "IN" => "🇮🇳",
        "RU" => "🇷🇺",
        "IT" => "🇮🇹",
        "ES" => "🇪🇸",
        "NL" => "🇳🇱",
        "SE" => "🇸🇪",
        "NO" => "🇳🇴",
        "FI" => "🇫🇮",
        "DK" => "🇩🇰",
        "PL" => "🇵🇱",
        "CH" => "🇨🇭",
        "AT" => "🇦🇹",
        "BE" => "🇧🇪",
        "IE" => "🇮🇪",
        "SG" => "🇸🇬",
        "HK" => "🇭🇰",
        "NZ" => "🇳🇿",
        "ZA" => "🇿🇦",
        "MX" => "🇲🇽",
        "AR" => "🇦🇷",
        _ => "🌍",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_quality_from_rtt() {
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(10)),
            ConnectionQuality::Excellent
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(75)),
            ConnectionQuality::Good
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(150)),
            ConnectionQuality::Fair
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(300)),
            ConnectionQuality::Poor
        );
        assert_eq!(
            ConnectionQuality::from_rtt(Duration::from_millis(1000)),
            ConnectionQuality::VeryPoor
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_country_flag() {
        assert_eq!(country_flag("US"), "🇺🇸");
        assert_eq!(country_flag("GB"), "🇬🇧");
        assert_eq!(country_flag("XX"), "🌍");
    }

    #[test]
    fn test_nat_type_stats() {
        let mut stats = NatTypeStats::default();

        // Test empty stats
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.attempts, 0);

        // Test recording attempts
        stats.record_attempt();
        stats.record_success();
        stats.record_failure();
        assert_eq!(stats.attempts, 3);
        assert_eq!(stats.successes, 1);
        assert_eq!(stats.failures, 1);

        // Test success rate calculation
        let expected_rate = (1.0 / 3.0) * 100.0;
        assert!((stats.success_rate() - expected_rate).abs() < 0.001);
    }

    #[test]
    fn test_nat_type_analytics() {
        let mut analytics = NatTypeAnalytics::default();

        // Test recording different NAT types
        use crate::registry::NatType;
        analytics.record_success(NatType::FullCone);
        analytics.record_failure(NatType::Symmetric);
        analytics.record_attempt(NatType::Cgnat);

        assert_eq!(analytics.full_cone.successes, 1);
        assert_eq!(analytics.full_cone.attempts, 1);
        assert_eq!(analytics.symmetric.failures, 1);
        assert_eq!(analytics.symmetric.attempts, 1);
        assert_eq!(analytics.cgnat.attempts, 1);

        // Test overall success rate
        assert_eq!(analytics.total_attempts(), 3);
        assert_eq!(analytics.total_successes(), 1);
        assert!((analytics.overall_success_rate() - (1.0 / 3.0 * 100.0)).abs() < 0.001);
    }

    #[test]
    fn test_geographic_distribution() {
        let mut geo = GeographicDistribution::new();

        // Test adding peers from different regions
        geo.add_peer("US".to_string());
        geo.add_peer("GB".to_string());
        geo.add_peer("JP".to_string());
        geo.add_peer("US".to_string()); // Duplicate

        assert_eq!(geo.total_peers, 4);
        assert_eq!(geo.regions.get("US"), Some(&2));
        assert_eq!(geo.regions.get("GB"), Some(&1));
        assert_eq!(geo.regions.get("JP"), Some(&1));

        // Test percentages
        assert!((geo.region_percentage("US") - 50.0).abs() < 0.001);
        assert!((geo.region_percentage("GB") - 25.0).abs() < 0.001);
        assert!((geo.region_percentage("JP") - 25.0).abs() < 0.001);

        // Test diversity
        assert!(geo.is_diverse());
        assert!(geo.diversity_score() > 0.5);

        // Test top regions
        let top = geo.top_regions(3);
        assert_eq!(top.len(), 3);
        assert!(top.iter().any(|(region, _)| *region == "US"));
    }

    #[test]
    fn test_cache_health() {
        use std::time::Duration;

        let health = CacheHealth {
            total_peers: 100,
            valid_peers: 80,
            public_peers: 25,
            average_quality: 0.75,
            cache_age: Duration::from_secs(3600),
            last_updated: None,
            cache_hits: 150,
            cache_misses: 50,
            fresh_peers: 60,
            stale_peers: 10,
            private_peers: 75,
            public_quality: 0.8,
            private_quality: 0.7,
        };

        assert_eq!(health.validity_percentage(), 80.0);
        assert_eq!(health.public_percentage(), 25.0);

        // Test with zero peers
        let empty_health = CacheHealth {
            total_peers: 0,
            valid_peers: 0,
            public_peers: 0,
            average_quality: 0.0,
            cache_age: Duration::from_secs(0),
            last_updated: None,
            cache_hits: 0,
            cache_misses: 0,
            fresh_peers: 0,
            stale_peers: 0,
            private_peers: 0,
            public_quality: 0.0,
            private_quality: 0.0,
        };

        assert_eq!(empty_health.validity_percentage(), 0.0);
        assert_eq!(empty_health.public_percentage(), 0.0);
    }
}

/// NAT Traversal phase for detailed connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalPhase {
    /// Discovering external addresses via OBSERVED_ADDRESS frames
    Discovering,
    /// Coordinating with a peer to schedule hole punching
    Coordinating,
    /// Active hole punching in progress
    Punching,
    /// Direct connection established
    Connected,
    /// Fallback to relay connection
    Relayed,
}

impl NatTraversalPhase {
    /// Get emoji representation for UI
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Discovering => "🔍",
            Self::Coordinating => "🤝",
            Self::Punching => "💥",
            Self::Connected => "✅",
            Self::Relayed => "🌐",
        }
    }

    /// Get color name for UI display
    pub fn color_name(&self) -> &'static str {
        match self {
            Self::Discovering => "blue",
            Self::Coordinating => "yellow",
            Self::Punching => "orange",
            Self::Connected => "green",
            Self::Relayed => "red",
        }
    }
}

/// Protocol frame information for real-time tracking
#[derive(Debug, Clone)]
pub struct ProtocolFrame {
    /// Peer ID this frame is associated with
    pub peer_id: String,
    /// Frame type (ADD_ADDRESS, PUNCH_ME_NOW, etc.)
    pub frame_type: String,
    /// Direction: SENT or RECEIVED
    pub direction: FrameDirection,
    /// Timestamp when frame was processed
    pub timestamp: Instant,
    /// Additional context (optional)
    pub context: Option<String>,
}

/// Direction of protocol frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    Sent,
    Received,
}

impl FrameDirection {
    /// Get arrow representation
    pub fn arrow(&self) -> &'static str {
        match self {
            Self::Sent => "→",
            Self::Received => "←",
        }
    }

    /// Get color name for UI
    pub fn color_name(&self) -> &'static str {
        match self {
            Self::Sent => "cyan",      // Outgoing frames
            Self::Received => "green", // Incoming frames
        }
    }
}

/// Enhanced traffic type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficType {
    /// Protocol overhead (gossip, heartbeats, NAT frames)
    Protocol,
    /// Test data packets (5KB test packets)
    TestData,
    /// Relay traffic (MASQUE protocol)
    Relay,
}

impl TrafficType {
    /// Get emoji for UI display
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Protocol => "🔄",
            Self::TestData => "📦",
            Self::Relay => "🌐",
        }
    }

    /// Get color name for UI display
    pub fn color_name(&self) -> &'static str {
        match self {
            Self::Protocol => "blue",
            Self::TestData => "green",
            Self::Relay => "magenta",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheHealth {
    pub total_peers: usize,
    pub valid_peers: usize,
    pub public_peers: usize,
    pub average_quality: f32,
    pub cache_age: std::time::Duration,
    pub last_updated: Option<Instant>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub fresh_peers: usize,
    pub stale_peers: usize,
    pub private_peers: usize,
    pub public_quality: f32,
    pub private_quality: f32,
}

impl CacheHealth {
    pub fn validity_percentage(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.valid_peers as f32 / self.total_peers as f32) * 100.0
        }
    }

    pub fn public_percentage(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.public_peers as f32 / self.total_peers as f32) * 100.0
        }
    }

    pub fn cache_hit_rate(&self) -> f32 {
        let total_requests = self.cache_hits + self.cache_misses;
        if total_requests == 0 {
            0.0
        } else {
            (self.cache_hits as f32 / total_requests as f32) * 100.0
        }
    }

    pub fn freshness_percentage(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.fresh_peers as f32 / self.total_peers as f32) * 100.0
        }
    }

    pub fn staleness_percentage(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.stale_peers as f32 / self.total_peers as f32) * 100.0
        }
    }

    pub fn private_percentage(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.private_peers as f32 / self.total_peers as f32) * 100.0
        }
    }

    pub fn health_score(&self) -> f32 {
        let validity_weight = 0.3;
        let freshness_weight = 0.25;
        let quality_weight = 0.25;
        let hit_rate_weight = 0.2;

        (self.validity_percentage() / 100.0 * validity_weight)
            + (self.freshness_percentage() / 100.0 * freshness_weight)
            + (self.average_quality * quality_weight)
            + (self.cache_hit_rate() / 100.0 * hit_rate_weight)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NatTypeAnalytics {
    pub full_cone: NatTypeStats,
    pub restricted_cone: NatTypeStats,
    pub port_restricted: NatTypeStats,
    pub symmetric: NatTypeStats,
    pub cgnat: NatTypeStats,
    pub rtt_by_nat_type: std::collections::HashMap<String, f64>,
    pub connection_methods_by_nat_type: std::collections::HashMap<String, ConnectionMethodStats>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionMethodStats {
    pub direct: u64,
    pub hole_punched: u64,
    pub relayed: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NatTypeStats {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub direct_connections: u64,
    pub hole_punched_connections: u64,
    pub relayed_connections: u64,
    pub total_rtt: f64,
    pub rtt_samples: u64,
}

impl NatTypeStats {
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            (self.successes as f64 / self.attempts as f64) * 100.0
        }
    }

    pub fn average_rtt(&self) -> f64 {
        if self.rtt_samples == 0 {
            0.0
        } else {
            self.total_rtt / self.rtt_samples as f64
        }
    }

    pub fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    pub fn record_success(&mut self) {
        self.successes += 1;
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn record_direct_connection(&mut self) {
        self.direct_connections += 1;
    }

    pub fn record_hole_punched_connection(&mut self) {
        self.hole_punched_connections += 1;
    }

    pub fn record_relayed_connection(&mut self) {
        self.relayed_connections += 1;
    }

    pub fn record_rtt(&mut self, rtt: f64) {
        self.total_rtt += rtt;
        self.rtt_samples += 1;
    }
}

impl NatTypeAnalytics {
    pub fn get_stats(&self, nat_type: NatType) -> &NatTypeStats {
        match nat_type {
            NatType::FullCone => &self.full_cone,
            NatType::AddressRestricted => &self.restricted_cone,
            NatType::PortRestricted => &self.port_restricted,
            NatType::Symmetric => &self.symmetric,
            NatType::Cgnat => &self.cgnat,
            NatType::Unknown => &self.restricted_cone,
            _ => &self.restricted_cone,
        }
    }

    pub fn get_stats_mut(&mut self, nat_type: NatType) -> &mut NatTypeStats {
        match nat_type {
            NatType::FullCone => &mut self.full_cone,
            NatType::AddressRestricted => &mut self.restricted_cone,
            NatType::PortRestricted => &mut self.port_restricted,
            NatType::Symmetric => &mut self.symmetric,
            NatType::Cgnat => &mut self.cgnat,
            NatType::Unknown => &mut self.restricted_cone,
            _ => &mut self.restricted_cone,
        }
    }

    pub fn record_attempt(&mut self, nat_type: NatType) {
        self.get_stats_mut(nat_type).record_attempt();
    }

    pub fn record_success(&mut self, nat_type: NatType) {
        self.get_stats_mut(nat_type).record_success();
    }

    pub fn record_failure(&mut self, nat_type: NatType) {
        self.get_stats_mut(nat_type).record_failure();
    }

    pub fn record_connection_method(&mut self, nat_type: NatType, method: ConnectionMethod) {
        let key = format!("{:?}", nat_type);
        let stats = self
            .connection_methods_by_nat_type
            .entry(key)
            .or_default();

        match method {
            ConnectionMethod::Direct => stats.direct += 1,
            ConnectionMethod::HolePunched => stats.hole_punched += 1,
            ConnectionMethod::Relayed => stats.relayed += 1,
        }

        let nat_stats = self.get_stats_mut(nat_type);
        match method {
            ConnectionMethod::Direct => nat_stats.record_direct_connection(),
            ConnectionMethod::HolePunched => nat_stats.record_hole_punched_connection(),
            ConnectionMethod::Relayed => nat_stats.record_relayed_connection(),
        }
    }

    pub fn record_rtt(&mut self, nat_type: NatType, rtt: f64) {
        let key = format!("{:?}", nat_type);
        self.rtt_by_nat_type.insert(key, rtt);
        self.get_stats_mut(nat_type).record_rtt(rtt);
    }

    pub fn total_attempts(&self) -> u64 {
        self.full_cone.attempts
            + self.restricted_cone.attempts
            + self.port_restricted.attempts
            + self.symmetric.attempts
            + self.cgnat.attempts
    }

    pub fn total_successes(&self) -> u64 {
        self.full_cone.successes
            + self.restricted_cone.successes
            + self.port_restricted.successes
            + self.symmetric.successes
            + self.cgnat.successes
    }

    pub fn overall_success_rate(&self) -> f64 {
        let total = self.total_attempts();
        if total == 0 {
            0.0
        } else {
            (self.total_successes() as f64 / total as f64) * 100.0
        }
    }

    pub fn success_rate_color(success_rate: f64) -> &'static str {
        if success_rate >= 90.0 {
            "green"
        } else if success_rate >= 70.0 {
            "yellow"
        } else if success_rate >= 50.0 {
            "orange"
        } else {
            "red"
        }
    }

    pub fn get_average_rtt(&self, nat_type: NatType) -> f64 {
        self.get_stats(nat_type).average_rtt()
    }

    pub fn get_connection_method_breakdown(
        &self,
        nat_type: NatType,
    ) -> Option<&ConnectionMethodStats> {
        let key = format!("{:?}", nat_type);
        self.connection_methods_by_nat_type.get(&key)
    }
}

/// Geographic distribution statistics for network diversity
#[derive(Debug, Clone, Default)]
pub struct GeographicDistribution {
    /// Peers by region/country code
    pub regions: std::collections::HashMap<String, usize>,
    /// Total peers across all regions
    pub total_peers: usize,
}

impl GeographicDistribution {
    /// Create new geographic distribution
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer from a region
    pub fn add_peer(&mut self, region: String) {
        *self.regions.entry(region).or_insert(0) += 1;
        self.total_peers += 1;
    }

    /// Get percentage for a region
    pub fn region_percentage(&self, region: &str) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            (self.regions.get(region).copied().unwrap_or(0) as f32 / self.total_peers as f32)
                * 100.0
        }
    }

    /// Get top N regions by peer count
    pub fn top_regions(&self, n: usize) -> Vec<(&String, &usize)> {
        let mut regions: Vec<_> = self.regions.iter().collect();
        regions.sort_by(|a, b| b.1.cmp(a.1));
        regions.into_iter().take(n).collect()
    }

    /// Check if network is geographically diverse (peers in 3+ regions)
    pub fn is_diverse(&self) -> bool {
        self.regions.len() >= 3
    }

    /// Get diversity score (0.0 - 1.0)
    pub fn diversity_score(&self) -> f32 {
        if self.total_peers == 0 {
            0.0
        } else {
            // Use Shannon entropy for diversity
            let mut entropy = 0.0;
            for count in self.regions.values() {
                let p = *count as f32 / self.total_peers as f32;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            // Normalize by maximum possible entropy
            let max_entropy = (self.regions.len() as f32).log2();
            if max_entropy > 0.0 {
                entropy / max_entropy
            } else {
                0.0
            }
        }
    }
}
