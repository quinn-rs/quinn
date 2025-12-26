//! Registry types for node registration and peer discovery.
//!
//! This module defines the data structures used by the central registry
//! to track nodes in the network and facilitate peer discovery.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NAT type classification for connectivity assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// No NAT - publicly routable address
    None,
    /// Full cone NAT - most permissive
    FullCone,
    /// Address-restricted cone NAT
    AddressRestricted,
    /// Port-restricted cone NAT
    PortRestricted,
    /// Symmetric NAT - most restrictive
    Symmetric,
    /// Unknown NAT type (not yet determined)
    Unknown,
}

impl Default for NatType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::FullCone => write!(f, "Full Cone"),
            Self::AddressRestricted => write!(f, "Address Restricted"),
            Self::PortRestricted => write!(f, "Port Restricted"),
            Self::Symmetric => write!(f, "Symmetric"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Connection method used for NAT traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMethod {
    /// Direct connection (no NAT traversal needed)
    Direct,
    /// Connection via hole-punching
    HolePunched,
    /// Connection via relay
    Relayed,
}

impl std::fmt::Display for ConnectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::HolePunched => write!(f, "HolePunched"),
            Self::Relayed => write!(f, "Relayed"),
        }
    }
}

/// Connection direction - who initiated the connection.
///
/// This is more reliable for NAT testing than trying to detect the traversal method.
/// If a node behind NAT successfully receives inbound connections, that proves
/// NAT traversal is working regardless of which code path was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDirection {
    /// We initiated the connection to the remote peer (outbound)
    Outbound,
    /// Remote peer initiated the connection to us (inbound)
    Inbound,
}

impl std::fmt::Display for ConnectionDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Outbound => write!(f, "Outbound"),
            Self::Inbound => write!(f, "Inbound"),
        }
    }
}

/// Node capabilities advertised during registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Supports post-quantum cryptography
    pub pqc: bool,
    /// Supports IPv4
    pub ipv4: bool,
    /// Supports IPv6
    pub ipv6: bool,
    /// Supports NAT traversal
    pub nat_traversal: bool,
    /// Can act as a relay for other nodes
    pub relay: bool,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            pqc: true, // Always true for ant-quic
            ipv4: true,
            ipv6: false,
            nat_traversal: true,
            relay: false,
        }
    }
}

/// Registration request sent by nodes to the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// Unique peer identifier (SHA-256 hash of ML-DSA-65 public key)
    pub peer_id: String,
    /// Full ML-DSA-65 public key (hex-encoded)
    pub public_key: String,
    /// Local listening addresses
    pub listen_addresses: Vec<SocketAddr>,
    /// Discovered external addresses (via STUN-like discovery)
    pub external_addresses: Vec<SocketAddr>,
    /// Detected NAT type
    pub nat_type: NatType,
    /// ant-quic version string
    pub version: String,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Optional user-provided location label
    pub location_label: Option<String>,
}

/// Heartbeat sent by nodes to maintain registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    /// Unique peer identifier
    pub peer_id: String,
    /// Number of currently connected peers
    pub connected_peers: usize,
    /// Total bytes sent since startup
    pub bytes_sent: u64,
    /// Total bytes received since startup
    pub bytes_received: u64,
    /// Updated external addresses (if changed)
    pub external_addresses: Option<Vec<SocketAddr>>,
    /// NAT traversal statistics
    pub nat_stats: Option<NatStats>,
}

/// Connection report sent by nodes to record individual connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionReport {
    /// Source peer ID (the reporting node)
    pub from_peer: String,
    /// Destination peer ID
    pub to_peer: String,
    /// Connection method used
    pub method: ConnectionMethod,
    /// Whether connection used IPv6
    pub is_ipv6: bool,
    /// Round-trip time in milliseconds (optional)
    pub rtt_ms: Option<u64>,
}

/// NAT traversal statistics included in heartbeats.
///
/// Tracks both outbound (we initiated) and inbound (they initiated) connections.
/// Inbound success is the key metric for NAT traversal - if a node behind NAT
/// receives inbound connections, that proves hole-punching works.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatStats {
    /// Total outbound connection attempts (we initiated)
    pub attempts: u64,
    /// Successful direct connections (outbound)
    pub direct_success: u64,
    /// Successful hole-punched connections (outbound)
    pub hole_punch_success: u64,
    /// Successful relayed connections (outbound)
    pub relay_success: u64,
    /// Failed connection attempts (outbound)
    pub failures: u64,
    /// Total inbound connections received (they initiated to us)
    /// This is the key metric for nodes behind NAT
    #[serde(default)]
    pub inbound_connections: u64,
    /// Whether this node is behind NAT (external != local address)
    #[serde(default)]
    pub is_behind_nat: bool,
}

/// Information about a registered peer (returned by registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub peer_id: String,
    /// All known addresses for this peer
    pub addresses: Vec<SocketAddr>,
    /// Detected NAT type
    pub nat_type: NatType,
    /// ISO 3166-1 alpha-2 country code (if known)
    pub country_code: Option<String>,
    /// Geographic latitude (for globe visualization)
    pub latitude: f64,
    /// Geographic longitude (for globe visualization)
    pub longitude: f64,
    /// Unix timestamp of last successful heartbeat
    pub last_seen: u64,
    /// Historical connection success rate (0.0 - 1.0)
    pub connection_success_rate: f64,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Node version
    pub version: String,
    /// Whether this node is currently active (heartbeat within threshold)
    pub is_active: bool,
    /// Peer status (active, inactive, or historical)
    #[serde(default)]
    pub status: PeerStatus,
    /// Total bytes sent by this node
    #[serde(default)]
    pub bytes_sent: u64,
    /// Total bytes received by this node
    #[serde(default)]
    pub bytes_received: u64,
    /// Number of connected peers
    #[serde(default)]
    pub connected_peers: usize,
}

/// Network-wide statistics (returned by /api/stats).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Total number of registered nodes
    pub total_nodes: usize,
    /// Number of currently active nodes
    pub active_nodes: usize,
    /// Number of historical (offline) nodes
    pub historical_nodes: usize,
    /// Total connections established network-wide
    pub total_connections: u64,
    /// Total bytes transferred network-wide
    pub total_bytes_transferred: u64,
    /// Overall connection success rate
    pub connection_success_rate: f64,
    /// Breakdown by connection method
    pub connection_breakdown: ConnectionBreakdown,
    /// Geographic distribution (country code -> count)
    pub geographic_distribution: std::collections::HashMap<String, usize>,
    /// Registry uptime in seconds
    pub uptime_secs: u64,
    /// IPv4 connections count
    pub ipv4_connections: u64,
    /// IPv6 connections count
    pub ipv6_connections: u64,
}

/// Breakdown of connections by method.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionBreakdown {
    /// Direct connections
    pub direct: u64,
    /// Hole-punched connections
    pub hole_punched: u64,
    /// Relayed connections
    pub relayed: u64,
}

/// Real-time event for WebSocket streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum NetworkEvent {
    /// New node registered
    NodeRegistered {
        /// Unique peer identifier
        peer_id: String,
        /// Country code (ISO 3166-1 alpha-2)
        country_code: Option<String>,
        /// Geographic latitude
        latitude: f64,
        /// Geographic longitude
        longitude: f64,
    },
    /// Node went offline (missed heartbeats)
    NodeOffline {
        /// Unique peer identifier
        peer_id: String,
    },
    /// Connection established between two nodes
    ConnectionEstablished {
        /// Source peer ID
        from_peer: String,
        /// Destination peer ID
        to_peer: String,
        /// NAT traversal method used
        method: ConnectionMethod,
        /// Round-trip time in milliseconds
        rtt_ms: Option<u64>,
    },
    /// Network statistics update
    StatsUpdate(NetworkStats),
}

/// Response to registration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Whether registration was successful
    pub success: bool,
    /// Error message if registration failed
    pub error: Option<String>,
    /// Current peer list
    pub peers: Vec<PeerInfo>,
    /// Registration expiry time (heartbeat deadline)
    pub expires_in_secs: u64,
}

/// Individual connection record for experiment results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Unique connection ID
    pub id: u64,
    /// Source peer ID
    pub from_peer: String,
    /// Destination peer ID
    pub to_peer: String,
    /// Connection method used
    pub method: ConnectionMethod,
    /// Whether connection used IPv6
    pub is_ipv6: bool,
    /// Round-trip time in milliseconds
    pub rtt_ms: Option<u64>,
    /// Unix timestamp when connection was established
    pub timestamp: u64,
    /// Source country code
    pub from_country: Option<String>,
    /// Destination country code
    pub to_country: Option<String>,
    /// Whether connection is still active
    pub is_active: bool,
}

/// Experiment results summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentResults {
    /// Experiment start time (unix timestamp)
    pub start_time: u64,
    /// Total duration in seconds
    pub duration_secs: u64,
    /// Total unique nodes seen
    pub total_nodes_seen: usize,
    /// Peak concurrent nodes
    pub peak_concurrent_nodes: usize,
    /// All connection records
    pub connections: Vec<ConnectionRecord>,
    /// NAT traversal statistics
    pub nat_stats: NatStats,
    /// Breakdown by connection method
    pub connection_breakdown: ConnectionBreakdown,
    /// IPv4 vs IPv6 statistics
    pub ipv4_connections: u64,
    pub ipv6_connections: u64,
    /// Geographic distribution
    pub geographic_distribution: std::collections::HashMap<String, usize>,
    /// Historical nodes (nodes that have gone offline)
    pub historical_nodes: Vec<PeerInfo>,
}

/// Status of a peer (active or historical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Currently active (heartbeat within threshold)
    Active,
    /// Recently inactive (within 5 minutes)
    Inactive,
    /// Historical (offline for more than 5 minutes)
    Historical,
}

impl Default for PeerStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Connectivity matrix for comprehensive path testing.
///
/// Tracks which connection paths have been tested and their results for each peer.
/// This enables comprehensive network testing by trying ALL paths, not just the first
/// successful one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectivityMatrix {
    /// IPv4 direct connection tested
    pub ipv4_direct_tested: bool,
    /// IPv4 direct connection succeeded
    pub ipv4_direct_success: bool,
    /// IPv4 direct connection RTT in ms
    pub ipv4_direct_rtt_ms: Option<u64>,

    /// IPv6 direct connection tested
    pub ipv6_direct_tested: bool,
    /// IPv6 direct connection succeeded
    pub ipv6_direct_success: bool,
    /// IPv6 direct connection RTT in ms
    pub ipv6_direct_rtt_ms: Option<u64>,

    /// NAT traversal (hole-punch) tested
    pub nat_traversal_tested: bool,
    /// NAT traversal succeeded
    pub nat_traversal_success: bool,
    /// NAT traversal RTT in ms
    pub nat_traversal_rtt_ms: Option<u64>,

    /// Relay tested
    pub relay_tested: bool,
    /// Relay succeeded
    pub relay_success: bool,
    /// Relay RTT in ms
    pub relay_rtt_ms: Option<u64>,

    /// Active connection method (which path we're using for data)
    pub active_method: Option<ConnectionMethod>,
    /// Active connection is IPv6
    pub active_is_ipv6: bool,
}

impl ConnectivityMatrix {
    /// Create a new empty connectivity matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a summary string of tested paths.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if self.ipv4_direct_tested {
            let status = if self.ipv4_direct_success { "✓" } else { "✗" };
            parts.push(format!("IPv4:{}", status));
        }

        if self.ipv6_direct_tested {
            let status = if self.ipv6_direct_success { "✓" } else { "✗" };
            parts.push(format!("IPv6:{}", status));
        }

        if self.nat_traversal_tested {
            let status = if self.nat_traversal_success { "✓" } else { "✗" };
            parts.push(format!("NAT:{}", status));
        }

        if self.relay_tested {
            let status = if self.relay_success { "✓" } else { "✗" };
            parts.push(format!("Relay:{}", status));
        }

        if parts.is_empty() {
            "Not tested".to_string()
        } else {
            parts.join(" ")
        }
    }

    /// Count successful paths.
    pub fn successful_paths(&self) -> usize {
        let mut count = 0;
        if self.ipv4_direct_success {
            count += 1;
        }
        if self.ipv6_direct_success {
            count += 1;
        }
        if self.nat_traversal_success {
            count += 1;
        }
        if self.relay_success {
            count += 1;
        }
        count
    }

    /// Count tested paths.
    pub fn tested_paths(&self) -> usize {
        let mut count = 0;
        if self.ipv4_direct_tested {
            count += 1;
        }
        if self.ipv6_direct_tested {
            count += 1;
        }
        if self.nat_traversal_tested {
            count += 1;
        }
        if self.relay_tested {
            count += 1;
        }
        count
    }
}

/// Helper function to get current unix timestamp.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(NatType::FullCone.to_string(), "Full Cone");
        assert_eq!(NatType::Symmetric.to_string(), "Symmetric");
    }

    #[test]
    fn test_registration_serialization() {
        let reg = NodeRegistration {
            peer_id: "a3b7c9d2".to_string(),
            public_key: "0x1234".to_string(),
            listen_addresses: vec!["192.168.1.1:9000".parse().unwrap()],
            external_addresses: vec!["203.0.113.1:9000".parse().unwrap()],
            nat_type: NatType::PortRestricted,
            version: "0.14.1".to_string(),
            capabilities: NodeCapabilities::default(),
            location_label: Some("NYC".to_string()),
        };

        let json = serde_json::to_string(&reg).expect("serialization should work");
        assert!(json.contains("a3b7c9d2"));
        assert!(json.contains("port_restricted"));
    }
}
