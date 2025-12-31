//! Registry types for node registration and peer discovery.
//!
//! This module defines the data structures used by the central registry
//! to track nodes in the network and facilitate peer discovery.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NAT type classification for connectivity assessment.
///
/// Based on RFC 4787 NAT behavioral requirements and RFC 3489 classic NAT types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// No NAT - publicly routable address
    None,
    /// Full cone NAT - most permissive (EIM/EIF)
    FullCone,
    /// Address-restricted cone NAT (EIM/ADF)
    AddressRestricted,
    /// Port-restricted cone NAT (EIM/APDF)
    PortRestricted,
    /// Symmetric NAT - most restrictive (APDM/APDF)
    Symmetric,
    /// Unknown NAT type (not yet determined)
    Unknown,
    // =========================================================================
    // Extended NAT types for comprehensive home/ISP emulation
    // =========================================================================
    /// Carrier-Grade NAT (shared IP, limited port range)
    /// Common in: ISPs with IPv4 shortage, mobile carriers
    Cgnat,
    /// Double NAT (two layers of NAT - router behind router)
    /// Common in: apartments, dorms, office networks
    DoubleNat,
    /// Hairpin NAT - can reach own external IP from inside
    /// Common in: better home routers
    HairpinNat,
    /// Mobile carrier NAT (often symmetric + CGNAT characteristics)
    /// Common in: 4G/5G cellular networks
    MobileCarrier,
    /// UPnP-enabled NAT (port mapping available)
    /// Indicates automatic port mapping is possible
    Upnp,
    /// NAT-PMP enabled NAT (Apple's port mapping protocol)
    /// Similar to UPnP but simpler protocol
    NatPmp,
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
            Self::Cgnat => write!(f, "CGNAT"),
            Self::DoubleNat => write!(f, "Double NAT"),
            Self::HairpinNat => write!(f, "Hairpin NAT"),
            Self::MobileCarrier => write!(f, "Mobile Carrier"),
            Self::Upnp => write!(f, "UPnP"),
            Self::NatPmp => write!(f, "NAT-PMP"),
        }
    }
}

impl NatType {
    /// Returns the expected hole-punching difficulty for this NAT type.
    ///
    /// Lower values are easier, higher values are harder:
    /// - 1: Very easy (direct or full cone)
    /// - 2: Easy (cone NATs with filtering)
    /// - 3: Medium (port-restricted)
    /// - 4: Hard (symmetric, CGNAT)
    /// - 5: Very hard (double NAT, mobile carrier)
    #[must_use]
    pub fn hole_punch_difficulty(&self) -> u8 {
        match self {
            Self::None => 1,
            Self::FullCone | Self::Upnp | Self::NatPmp => 1,
            Self::AddressRestricted | Self::HairpinNat => 2,
            Self::PortRestricted => 3,
            Self::Symmetric | Self::Cgnat => 4,
            Self::DoubleNat | Self::MobileCarrier => 5,
            Self::Unknown => 3, // Assume medium difficulty
        }
    }

    /// Returns whether this NAT type typically requires relay for connectivity.
    #[must_use]
    pub fn typically_requires_relay(&self) -> bool {
        matches!(
            self,
            Self::Symmetric | Self::DoubleNat | Self::MobileCarrier
        )
    }

    /// Returns whether port mapping (UPnP/NAT-PMP) is likely available.
    #[must_use]
    pub fn has_port_mapping(&self) -> bool {
        matches!(self, Self::Upnp | Self::NatPmp)
    }

    /// Returns the RFC 4787 mapping behavior for this NAT type.
    #[must_use]
    pub fn mapping_behavior(&self) -> MappingBehavior {
        match self {
            Self::None => MappingBehavior::EndpointIndependent,
            Self::FullCone
            | Self::AddressRestricted
            | Self::PortRestricted
            | Self::HairpinNat
            | Self::Upnp
            | Self::NatPmp => MappingBehavior::EndpointIndependent,
            Self::Symmetric | Self::Cgnat | Self::MobileCarrier => {
                MappingBehavior::AddressPortDependent
            }
            Self::DoubleNat => MappingBehavior::AddressPortDependent, // Outer NAT dominates
            Self::Unknown => MappingBehavior::AddressPortDependent,   // Assume worst case
        }
    }

    /// Returns the RFC 4787 filtering behavior for this NAT type.
    #[must_use]
    pub fn filtering_behavior(&self) -> FilteringBehavior {
        match self {
            Self::None => FilteringBehavior::EndpointIndependent,
            Self::FullCone => FilteringBehavior::EndpointIndependent,
            Self::AddressRestricted | Self::HairpinNat => FilteringBehavior::AddressDependent,
            Self::PortRestricted
            | Self::Symmetric
            | Self::Cgnat
            | Self::DoubleNat
            | Self::MobileCarrier
            | Self::Upnp
            | Self::NatPmp => FilteringBehavior::AddressPortDependent,
            Self::Unknown => FilteringBehavior::AddressPortDependent, // Assume worst case
        }
    }

    /// Returns all standard NAT types (excluding extended types).
    #[must_use]
    pub fn standard_types() -> Vec<Self> {
        vec![
            Self::None,
            Self::FullCone,
            Self::AddressRestricted,
            Self::PortRestricted,
            Self::Symmetric,
        ]
    }

    /// Returns all extended NAT types (home/ISP-specific).
    #[must_use]
    pub fn extended_types() -> Vec<Self> {
        vec![
            Self::Cgnat,
            Self::DoubleNat,
            Self::HairpinNat,
            Self::MobileCarrier,
            Self::Upnp,
            Self::NatPmp,
        ]
    }

    /// Returns all NAT types for comprehensive testing.
    #[must_use]
    pub fn all_types() -> Vec<Self> {
        vec![
            Self::None,
            Self::FullCone,
            Self::AddressRestricted,
            Self::PortRestricted,
            Self::Symmetric,
            Self::Cgnat,
            Self::DoubleNat,
            Self::HairpinNat,
            Self::MobileCarrier,
            Self::Upnp,
            Self::NatPmp,
        ]
    }
}

/// RFC 4787 NAT mapping behavior classification.
///
/// Describes how the NAT maps internal addresses to external addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingBehavior {
    /// Endpoint Independent Mapping (EIM)
    /// Same external port for all destinations (cone NATs)
    EndpointIndependent,
    /// Address Dependent Mapping (ADM)
    /// Different external port per destination IP
    AddressDependent,
    /// Address and Port Dependent Mapping (APDM)
    /// Different external port per destination IP:port (symmetric)
    AddressPortDependent,
}

impl std::fmt::Display for MappingBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointIndependent => write!(f, "Endpoint Independent"),
            Self::AddressDependent => write!(f, "Address Dependent"),
            Self::AddressPortDependent => write!(f, "Address+Port Dependent"),
        }
    }
}

/// RFC 4787 NAT filtering behavior classification.
///
/// Describes what external traffic the NAT allows through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilteringBehavior {
    /// Endpoint Independent Filtering (EIF)
    /// Accept from any external host on mapped port (full cone)
    EndpointIndependent,
    /// Address Dependent Filtering (ADF)
    /// Only accept from IPs we've sent to (address-restricted)
    AddressDependent,
    /// Address and Port Dependent Filtering (APDF)
    /// Only accept from exact IP:port we've sent to (port-restricted, symmetric)
    AddressPortDependent,
}

impl std::fmt::Display for FilteringBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointIndependent => write!(f, "Endpoint Independent"),
            Self::AddressDependent => write!(f, "Address Dependent"),
            Self::AddressPortDependent => write!(f, "Address+Port Dependent"),
        }
    }
}

/// Comprehensive NAT behavior description based on RFC 4787.
///
/// Provides detailed information about NAT characteristics beyond simple type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatBehavior {
    /// How internal addresses are mapped to external
    pub mapping: MappingBehavior,
    /// What external traffic is allowed through
    pub filtering: FilteringBehavior,
    /// Whether hairpin NAT (NAT loopback) is supported
    pub hairpin: bool,
    /// Whether UPnP port mapping is available
    pub upnp_available: bool,
    /// Whether NAT-PMP port mapping is available
    pub nat_pmp_available: bool,
    /// CGNAT port range limits (None if unlimited)
    pub port_range: Option<(u16, u16)>,
    /// Whether this is behind multiple NAT layers
    pub is_double_nat: bool,
    /// Estimated hole-punch success rate (0.0 - 1.0)
    pub estimated_success_rate: f64,
}

impl Default for NatBehavior {
    fn default() -> Self {
        Self {
            mapping: MappingBehavior::EndpointIndependent,
            filtering: FilteringBehavior::AddressPortDependent,
            hairpin: false,
            upnp_available: false,
            nat_pmp_available: false,
            port_range: None,
            is_double_nat: false,
            estimated_success_rate: 0.5,
        }
    }
}

impl NatBehavior {
    /// Create behavior from a NAT type.
    #[must_use]
    pub fn from_nat_type(nat_type: NatType) -> Self {
        match nat_type {
            NatType::None => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::EndpointIndependent,
                hairpin: true,
                estimated_success_rate: 1.0,
                ..Default::default()
            },
            NatType::FullCone => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::EndpointIndependent,
                hairpin: false,
                estimated_success_rate: 0.95,
                ..Default::default()
            },
            NatType::AddressRestricted => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressDependent,
                estimated_success_rate: 0.85,
                ..Default::default()
            },
            NatType::PortRestricted => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                estimated_success_rate: 0.80,
                ..Default::default()
            },
            NatType::Symmetric => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                estimated_success_rate: 0.40,
                ..Default::default()
            },
            NatType::Cgnat => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                port_range: Some((32768, 33023)), // 256 ports typical
                estimated_success_rate: 0.35,
                ..Default::default()
            },
            NatType::DoubleNat => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                is_double_nat: true,
                estimated_success_rate: 0.25,
                ..Default::default()
            },
            NatType::HairpinNat => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressDependent,
                hairpin: true,
                estimated_success_rate: 0.85,
                ..Default::default()
            },
            NatType::MobileCarrier => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                port_range: Some((32768, 40959)), // Larger CGNAT range
                estimated_success_rate: 0.30,
                ..Default::default()
            },
            NatType::Upnp => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                upnp_available: true,
                estimated_success_rate: 0.90,
                ..Default::default()
            },
            NatType::NatPmp => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                nat_pmp_available: true,
                estimated_success_rate: 0.90,
                ..Default::default()
            },
            NatType::Unknown => Self::default(),
        }
    }

    /// Estimate success rate for connection between two NAT behaviors.
    #[must_use]
    pub fn estimate_pair_success_rate(source: &Self, dest: &Self) -> f64 {
        // If either has port mapping, success is likely
        if source.upnp_available || source.nat_pmp_available {
            return 0.95;
        }
        if dest.upnp_available || dest.nat_pmp_available {
            return 0.95;
        }

        // Double NAT is very hard
        if source.is_double_nat || dest.is_double_nat {
            return 0.30;
        }

        // Both symmetric/CGNAT = relay required
        if source.mapping == MappingBehavior::AddressPortDependent
            && dest.mapping == MappingBehavior::AddressPortDependent
        {
            return 0.40; // Relay success rate
        }

        // One endpoint independent = easier
        if source.filtering == FilteringBehavior::EndpointIndependent
            || dest.filtering == FilteringBehavior::EndpointIndependent
        {
            return 0.95;
        }

        // Default: average of individual rates
        (source.estimated_success_rate + dest.estimated_success_rate) / 2.0
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

/// Detailed connection technique for comprehensive tracking.
///
/// This provides finer granularity than `ConnectionMethod` to track
/// exactly which NAT traversal techniques were attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTechnique {
    /// Direct IPv4 connection
    DirectIpv4,
    /// Direct IPv6 connection
    DirectIpv6,
    /// Basic hole-punching (simultaneous open)
    HolePunch,
    /// Coordinated hole-punching via relay/coordinator
    HolePunchCoordinated,
    /// Connection via relay node
    Relay,
    /// UPnP port mapping
    UPnP,
    /// NAT-PMP port mapping
    NatPmp,
}

impl std::fmt::Display for ConnectionTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectIpv4 => write!(f, "Direct IPv4"),
            Self::DirectIpv6 => write!(f, "Direct IPv6"),
            Self::HolePunch => write!(f, "Hole Punch"),
            Self::HolePunchCoordinated => write!(f, "Coordinated Hole Punch"),
            Self::Relay => write!(f, "Relay"),
            Self::UPnP => write!(f, "UPnP"),
            Self::NatPmp => write!(f, "NAT-PMP"),
        }
    }
}

/// Record of a single technique attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueAttempt {
    /// The technique that was tried
    pub technique: ConnectionTechnique,
    /// Whether it succeeded
    pub success: bool,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp of attempt (unix ms)
    pub timestamp_ms: u64,
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
    /// Gossip protocol statistics
    #[serde(default)]
    pub gossip_stats: Option<NodeGossipStats>,
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
    /// Comprehensive connectivity matrix (all paths tested)
    #[serde(default)]
    pub connectivity: ConnectivityMatrix,
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
    /// Gossip protocol statistics (if available)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_stats: Option<NodeGossipStats>,
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

/// Per-node gossip statistics (reported in heartbeat).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeGossipStats {
    /// Announcements sent by this node
    pub announcements_sent: u64,
    /// Announcements received by this node
    pub announcements_received: u64,
    /// Peer queries sent
    pub peer_queries_sent: u64,
    /// Peer queries received
    pub peer_queries_received: u64,
    /// Peer responses sent
    pub peer_responses_sent: u64,
    /// Peer responses received
    pub peer_responses_received: u64,
    /// Bootstrap cache updates
    pub cache_updates: u64,
    /// Bootstrap cache hits
    pub cache_hits: u64,
    /// Bootstrap cache misses
    pub cache_misses: u64,
    /// Current cache size
    pub cache_size: u64,

    // === Epidemic Gossip Stats (saorsa-gossip integration) ===
    /// HyParView active view size (directly connected peers)
    #[serde(default)]
    pub hyparview_active: usize,
    /// HyParView passive view size (known but not connected)
    #[serde(default)]
    pub hyparview_passive: usize,

    /// SWIM peers in Alive state
    #[serde(default)]
    pub swim_alive: usize,
    /// SWIM peers in Suspect state
    #[serde(default)]
    pub swim_suspect: usize,
    /// SWIM peers in Dead state
    #[serde(default)]
    pub swim_dead: usize,

    /// Plumtree messages sent
    #[serde(default)]
    pub plumtree_sent: u64,
    /// Plumtree messages received
    #[serde(default)]
    pub plumtree_received: u64,
    /// Plumtree eager peers count
    #[serde(default)]
    pub plumtree_eager: usize,
    /// Plumtree lazy peers count
    #[serde(default)]
    pub plumtree_lazy: usize,

    /// Connection type breakdown - Direct IPv4
    #[serde(default)]
    pub conn_direct_ipv4: usize,
    /// Connection type breakdown - Direct IPv6
    #[serde(default)]
    pub conn_direct_ipv6: usize,
    /// Connection type breakdown - Hole punched
    #[serde(default)]
    pub conn_hole_punched: usize,
    /// Connection type breakdown - Relayed
    #[serde(default)]
    pub conn_relayed: usize,
}

/// Gossip network statistics (aggregated from all nodes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GossipStats {
    /// Total gossip announcements received across all nodes
    pub total_announcements: u64,
    /// Total peer queries sent across all nodes
    pub total_peer_queries: u64,
    /// Total peer query responses received
    pub total_peer_responses: u64,
    /// Total bootstrap cache updates
    pub total_cache_updates: u64,
    /// Total bootstrap cache hits
    pub total_cache_hits: u64,
    /// Total entries in bootstrap caches (sum across nodes)
    pub total_cache_size: u64,
    /// Number of nodes with public IP (no NAT)
    pub nat_type_public: u64,
    /// Number of nodes with full cone NAT
    pub nat_type_full_cone: u64,
    /// Number of nodes with symmetric NAT
    pub nat_type_symmetric: u64,
    /// Number of nodes with restricted NAT
    pub nat_type_restricted: u64,
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
    /// Comprehensive connectivity matrix (all paths tested)
    #[serde(default)]
    pub connectivity: ConnectivityMatrix,
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

    // Enhanced per-peer stats tracking (v0.14.68+)
    /// Ordered list of all technique attempts for this peer
    #[serde(default)]
    pub technique_attempts: Vec<TechniqueAttempt>,

    /// Total time to establish connection in milliseconds
    #[serde(default)]
    pub connection_time_ms: Option<u64>,

    /// Peer ID of relay used (if connection is relayed)
    #[serde(default)]
    pub relay_peer_id: Option<String>,

    /// Number of connection retries before success
    #[serde(default)]
    pub retry_count: u32,

    /// Whether connection was initiated by us or them
    #[serde(default)]
    pub initiated_by_us: bool,

    /// Unix timestamp when connection was first established
    #[serde(default)]
    pub connected_at_ms: Option<u64>,
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
            let status = if self.ipv4_direct_success {
                "✓"
            } else {
                "✗"
            };
            parts.push(format!("IPv4:{}", status));
        }

        if self.ipv6_direct_tested {
            let status = if self.ipv6_direct_success {
                "✓"
            } else {
                "✗"
            };
            parts.push(format!("IPv6:{}", status));
        }

        if self.nat_traversal_tested {
            let status = if self.nat_traversal_success {
                "✓"
            } else {
                "✗"
            };
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

    /// Record a technique attempt.
    pub fn record_attempt(
        &mut self,
        technique: ConnectionTechnique,
        success: bool,
        duration_ms: u64,
        error: Option<String>,
    ) {
        let attempt = TechniqueAttempt {
            technique,
            success,
            duration_ms,
            error,
            timestamp_ms: unix_timestamp_ms(),
        };
        self.technique_attempts.push(attempt);

        // Also update the legacy fields for backward compatibility
        match technique {
            ConnectionTechnique::DirectIpv4 => {
                self.ipv4_direct_tested = true;
                if success {
                    self.ipv4_direct_success = true;
                    self.ipv4_direct_rtt_ms = Some(duration_ms);
                }
            }
            ConnectionTechnique::DirectIpv6 => {
                self.ipv6_direct_tested = true;
                if success {
                    self.ipv6_direct_success = true;
                    self.ipv6_direct_rtt_ms = Some(duration_ms);
                }
            }
            ConnectionTechnique::HolePunch | ConnectionTechnique::HolePunchCoordinated => {
                self.nat_traversal_tested = true;
                if success {
                    self.nat_traversal_success = true;
                    self.nat_traversal_rtt_ms = Some(duration_ms);
                }
            }
            ConnectionTechnique::Relay => {
                self.relay_tested = true;
                if success {
                    self.relay_success = true;
                    self.relay_rtt_ms = Some(duration_ms);
                }
            }
            ConnectionTechnique::UPnP | ConnectionTechnique::NatPmp => {
                // These map to direct connection once port is mapped
                self.ipv4_direct_tested = true;
                if success {
                    self.ipv4_direct_success = true;
                    self.ipv4_direct_rtt_ms = Some(duration_ms);
                }
            }
        }
    }

    /// Get detailed technique breakdown string.
    ///
    /// Returns a string like: "Direct ✗ → HolePunch ✗ → Relay ✓ (42ms)"
    pub fn technique_breakdown(&self) -> String {
        if self.technique_attempts.is_empty() {
            return self.summary();
        }

        let parts: Vec<String> = self
            .technique_attempts
            .iter()
            .map(|attempt| {
                let status = if attempt.success { "✓" } else { "✗" };
                let time = if attempt.success {
                    format!(" ({}ms)", attempt.duration_ms)
                } else {
                    String::new()
                };
                format!("{} {}{}", attempt.technique, status, time)
            })
            .collect();

        parts.join(" → ")
    }

    /// Get count of successful technique attempts.
    pub fn successful_attempts(&self) -> usize {
        self.technique_attempts.iter().filter(|a| a.success).count()
    }

    /// Get count of total technique attempts.
    pub fn total_attempts(&self) -> usize {
        self.technique_attempts.len()
    }

    /// Get the first successful technique (if any).
    pub fn first_successful_technique(&self) -> Option<ConnectionTechnique> {
        self.technique_attempts
            .iter()
            .find(|a| a.success)
            .map(|a| a.technique)
    }

    /// Get total time spent on all attempts.
    pub fn total_attempt_time_ms(&self) -> u64 {
        self.technique_attempts.iter().map(|a| a.duration_ms).sum()
    }
}

/// Helper function to get current unix timestamp in seconds.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Helper function to get current unix timestamp in milliseconds.
pub fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Connection test result for a single path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTestResult {
    /// Whether the path was tested
    pub tested: bool,
    /// Whether the test succeeded
    pub success: bool,
    /// Round-trip time in milliseconds (if successful)
    pub rtt_ms: Option<u64>,
}

/// Peer-to-peer connection matrix entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnectionMatrix {
    /// Source peer ID (truncated for display)
    pub from_peer: String,
    /// Destination peer ID (truncated for display)
    pub to_peer: String,
    /// IPv4 direct connection result
    pub ipv4: PathTestResult,
    /// IPv6 direct connection result
    pub ipv6: PathTestResult,
    /// NAT traversal (hole-punch) result
    pub nat: PathTestResult,
    /// Relay connection result
    pub relay: PathTestResult,
    /// Currently active method (if any)
    pub active_method: Option<ConnectionMethod>,
}

/// Response for /api/results/matrix endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMatrixResponse {
    /// List of peer IDs (truncated)
    pub peers: Vec<String>,
    /// Connection matrix entries
    pub matrix: Vec<PeerConnectionMatrix>,
    /// Total connections tested
    pub total_tested: usize,
    /// Successful connections
    pub total_success: usize,
}

/// Response for /api/results/breakdown endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakdownResponse {
    /// Breakdown by connection method
    pub by_method: ConnectionBreakdown,
    /// Breakdown by IP version
    pub by_ip_version: IpVersionBreakdown,
    /// Breakdown by NAT type
    pub by_nat_type: std::collections::HashMap<String, u64>,
}

/// Breakdown by IP version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpVersionBreakdown {
    /// IPv4 connections
    pub ipv4: u64,
    /// IPv6 connections
    pub ipv6: u64,
}

/// Response for /api/gossip/health endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipHealthResponse {
    /// Number of peers discovered via gossip
    pub peers_discovered: u64,
    /// Total announcements received
    pub announcements_received: u64,
    /// Known relay nodes
    pub relays_known: usize,
    /// Known coordinators
    pub coordinators_known: usize,
    /// Stale peers cleaned up
    pub stale_peers_cleaned: u64,
    /// Health status (healthy, degraded, unhealthy)
    pub status: String,
}

/// Response for /api/cache/status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatusResponse {
    /// Total peers in bootstrap cache
    pub total_peers: usize,
    /// Active peers (recently seen)
    pub active_peers: usize,
    /// Stale peers (not seen recently)
    pub stale_peers: usize,
    /// Quality distribution (high, medium, low)
    pub quality_distribution: QualityDistribution,
}

/// Quality distribution for bootstrap cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QualityDistribution {
    /// High quality peers (public IP, good latency)
    pub high: usize,
    /// Medium quality peers
    pub medium: usize,
    /// Low quality peers (behind NAT, high latency)
    pub low: usize,
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

    #[test]
    fn test_connection_technique_display() {
        assert_eq!(ConnectionTechnique::DirectIpv4.to_string(), "Direct IPv4");
        assert_eq!(ConnectionTechnique::HolePunch.to_string(), "Hole Punch");
        assert_eq!(
            ConnectionTechnique::HolePunchCoordinated.to_string(),
            "Coordinated Hole Punch"
        );
        assert_eq!(ConnectionTechnique::Relay.to_string(), "Relay");
    }

    #[test]
    fn test_connectivity_matrix_record_attempt() {
        let mut matrix = ConnectivityMatrix::new();

        // Record a failed direct attempt
        matrix.record_attempt(
            ConnectionTechnique::DirectIpv4,
            false,
            100,
            Some("timeout".into()),
        );

        // Record a failed hole punch attempt
        matrix.record_attempt(
            ConnectionTechnique::HolePunch,
            false,
            200,
            Some("no response".into()),
        );

        // Record a successful relay attempt
        matrix.record_attempt(ConnectionTechnique::Relay, true, 50, None);

        // Verify the attempts were recorded
        assert_eq!(matrix.total_attempts(), 3);
        assert_eq!(matrix.successful_attempts(), 1);

        // Verify legacy fields were updated
        assert!(matrix.ipv4_direct_tested);
        assert!(!matrix.ipv4_direct_success);
        assert!(matrix.nat_traversal_tested);
        assert!(!matrix.nat_traversal_success);
        assert!(matrix.relay_tested);
        assert!(matrix.relay_success);
        assert_eq!(matrix.relay_rtt_ms, Some(50));

        // Verify first successful technique
        assert_eq!(
            matrix.first_successful_technique(),
            Some(ConnectionTechnique::Relay)
        );
    }

    #[test]
    fn test_connectivity_matrix_technique_breakdown() {
        let mut matrix = ConnectivityMatrix::new();

        matrix.record_attempt(ConnectionTechnique::DirectIpv4, false, 100, None);
        matrix.record_attempt(ConnectionTechnique::HolePunch, false, 150, None);
        matrix.record_attempt(ConnectionTechnique::Relay, true, 42, None);

        let breakdown = matrix.technique_breakdown();
        assert!(breakdown.contains("Direct IPv4 ✗"));
        assert!(breakdown.contains("Hole Punch ✗"));
        assert!(breakdown.contains("Relay ✓ (42ms)"));
        assert!(breakdown.contains("→"));
    }

    #[test]
    fn test_technique_attempt_serialization() {
        let attempt = TechniqueAttempt {
            technique: ConnectionTechnique::HolePunchCoordinated,
            success: true,
            duration_ms: 123,
            error: None,
            timestamp_ms: 1234567890123,
        };

        let json = serde_json::to_string(&attempt).expect("serialization should work");
        assert!(json.contains("hole_punch_coordinated"));
        assert!(json.contains("123"));
    }

    #[test]
    fn test_nat_behavior_from_nat_type() {
        // Test Full Cone NAT behavior
        let full_cone = NatBehavior::from_nat_type(NatType::FullCone);
        assert_eq!(full_cone.mapping, MappingBehavior::EndpointIndependent);
        assert_eq!(full_cone.filtering, FilteringBehavior::EndpointIndependent);
        assert!(full_cone.estimated_success_rate > 0.9);

        // Test Symmetric NAT behavior
        let symmetric = NatBehavior::from_nat_type(NatType::Symmetric);
        assert_eq!(symmetric.mapping, MappingBehavior::AddressPortDependent);
        assert_eq!(symmetric.filtering, FilteringBehavior::AddressPortDependent);
        assert!(symmetric.estimated_success_rate < full_cone.estimated_success_rate);

        // Test CGNAT behavior
        let cgnat = NatBehavior::from_nat_type(NatType::Cgnat);
        assert!(cgnat.port_range.is_some());
        assert!(cgnat.estimated_success_rate < symmetric.estimated_success_rate);

        // Test Double NAT behavior
        let double_nat = NatBehavior::from_nat_type(NatType::DoubleNat);
        assert!(double_nat.estimated_success_rate < cgnat.estimated_success_rate);
    }

    #[test]
    fn test_nat_behavior_pair_success_rate() {
        // Easy pair: Full Cone to Full Cone
        let full_cone = NatBehavior::from_nat_type(NatType::FullCone);
        let easy_rate = NatBehavior::estimate_pair_success_rate(&full_cone, &full_cone);
        assert!(easy_rate > 0.9);

        // Hard pair: Symmetric to Symmetric
        let symmetric = NatBehavior::from_nat_type(NatType::Symmetric);
        let hard_rate = NatBehavior::estimate_pair_success_rate(&symmetric, &symmetric);
        assert!(hard_rate < easy_rate);

        // Very hard pair: Double NAT to Double NAT
        let double_nat = NatBehavior::from_nat_type(NatType::DoubleNat);
        let very_hard_rate = NatBehavior::estimate_pair_success_rate(&double_nat, &double_nat);
        assert!(very_hard_rate < hard_rate);
    }

    #[test]
    fn test_nat_type_extended_variants() {
        // Test new NAT type display names
        assert_eq!(NatType::Cgnat.to_string(), "CGNAT");
        assert_eq!(NatType::DoubleNat.to_string(), "Double NAT");
        assert_eq!(NatType::HairpinNat.to_string(), "Hairpin NAT");
        assert_eq!(NatType::MobileCarrier.to_string(), "Mobile Carrier");
        assert_eq!(NatType::Upnp.to_string(), "UPnP");
        assert_eq!(NatType::NatPmp.to_string(), "NAT-PMP");
    }
}
