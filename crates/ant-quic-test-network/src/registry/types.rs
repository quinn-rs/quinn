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

/// NAT traversal statistics included in heartbeats.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatStats {
    /// Total connection attempts
    pub attempts: u64,
    /// Successful direct connections
    pub direct_success: u64,
    /// Successful hole-punched connections
    pub hole_punch_success: u64,
    /// Successful relayed connections
    pub relay_success: u64,
    /// Failed connection attempts
    pub failures: u64,
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
}

/// Network-wide statistics (returned by /api/stats).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Total number of registered nodes
    pub total_nodes: usize,
    /// Number of currently active nodes
    pub active_nodes: usize,
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
