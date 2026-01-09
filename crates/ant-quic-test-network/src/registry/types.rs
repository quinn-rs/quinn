//! Registry types for node registration and peer discovery.
//!
//! This module defines the data structures used by the central registry
//! to track nodes in the network and facilitate peer discovery.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NAT type classification for connectivity assessment.
///
/// Based on RFC 4787 NAT behavioral requirements and RFC 3489 classic NAT types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
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
    #[default]
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

/// RFC 4787 REQ-1: Port preservation behavior.
///
/// Describes whether a NAT attempts to preserve the internal port number
/// when allocating an external mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortPreservation {
    /// NAT always tries to use the same external port as internal.
    /// Falls back to random if port is in use.
    Preferred,
    /// NAT does not preserve port - always allocates from its pool.
    #[default]
    NotPreserved,
    /// NAT uses a fixed overloaded port (rare, breaks most things).
    Overloaded,
}

impl std::fmt::Display for PortPreservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preferred => write!(f, "Port Preservation Preferred"),
            Self::NotPreserved => write!(f, "No Port Preservation"),
            Self::Overloaded => write!(f, "Overloaded Port"),
        }
    }
}

/// Comprehensive NAT behavior description based on RFC 4787.
///
/// Provides detailed information about NAT characteristics beyond simple type.
/// Includes all RFC 4787 behavioral requirements for accurate NAT simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatBehavior {
    /// How internal addresses are mapped to external (REQ-1 mapping behavior)
    pub mapping: MappingBehavior,
    /// What external traffic is allowed through (REQ-8 filtering behavior)
    pub filtering: FilteringBehavior,
    /// Whether hairpin NAT (NAT loopback) is supported (REQ-6)
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
    /// RFC 4787 REQ-1: Port preservation behavior
    pub port_preservation: PortPreservation,
    /// RFC 4787 REQ-5: UDP mapping timeout in seconds (minimum recommended: 120)
    pub mapping_timeout_secs: u32,
    /// RFC 4787 REQ-7: Whether NAT preserves port parity (odd/even)
    pub port_parity: bool,
    /// RFC 4787 REQ-8: Whether NAT allocates contiguous port blocks
    pub port_contiguity: bool,
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
            port_preservation: PortPreservation::Preferred,
            mapping_timeout_secs: 120, // RFC 4787 REQ-5 minimum
            port_parity: false,
            port_contiguity: false,
        }
    }
}

impl NatBehavior {
    /// Create behavior from a NAT type.
    ///
    /// Sets appropriate RFC 4787 behavioral requirements based on NAT type:
    /// - Port preservation: Whether NAT tries to use same external port (REQ-1)
    /// - Mapping timeout: How long NAT mappings remain active (REQ-5)
    /// - Port parity/contiguity: Advanced allocation properties (REQ-7, REQ-8)
    #[must_use]
    pub fn from_nat_type(nat_type: NatType) -> Self {
        match nat_type {
            NatType::None => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::EndpointIndependent,
                hairpin: true,
                estimated_success_rate: 1.0,
                port_preservation: PortPreservation::Preferred, // No NAT, ports pass through
                mapping_timeout_secs: u32::MAX,                 // No timeout without NAT
                port_parity: true,
                port_contiguity: true,
                ..Default::default()
            },
            NatType::FullCone => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::EndpointIndependent,
                hairpin: false,
                estimated_success_rate: 0.95,
                port_preservation: PortPreservation::Preferred, // Good routers preserve
                mapping_timeout_secs: 300,                      // 5 minutes typical
                port_parity: true,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::AddressRestricted => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressDependent,
                estimated_success_rate: 0.85,
                port_preservation: PortPreservation::Preferred,
                mapping_timeout_secs: 180, // 3 minutes
                port_parity: true,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::PortRestricted => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                estimated_success_rate: 0.80,
                port_preservation: PortPreservation::Preferred,
                mapping_timeout_secs: 120, // RFC 4787 minimum
                port_parity: false,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::Symmetric => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                estimated_success_rate: 0.40,
                port_preservation: PortPreservation::NotPreserved, // Different port per dest
                mapping_timeout_secs: 120,
                port_parity: false,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::Cgnat => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                port_range: Some((32768, 33023)), // 256 ports typical
                estimated_success_rate: 0.35,
                port_preservation: PortPreservation::NotPreserved, // Randomized from pool
                mapping_timeout_secs: 60, // CGNAT often has shorter timeouts
                port_parity: false,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::DoubleNat => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                is_double_nat: true,
                estimated_success_rate: 0.25,
                port_preservation: PortPreservation::NotPreserved, // Outer NAT dominates
                mapping_timeout_secs: 60,                          // Use minimum of both layers
                port_parity: false,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::HairpinNat => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressDependent,
                hairpin: true,
                estimated_success_rate: 0.85,
                port_preservation: PortPreservation::Preferred, // Quality router
                mapping_timeout_secs: 300,                      // 5 minutes
                port_parity: true,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::MobileCarrier => Self {
                mapping: MappingBehavior::AddressPortDependent,
                filtering: FilteringBehavior::AddressPortDependent,
                port_range: Some((32768, 40959)), // Larger CGNAT range
                estimated_success_rate: 0.30,
                port_preservation: PortPreservation::NotPreserved,
                mapping_timeout_secs: 30, // Mobile carriers often aggressive
                port_parity: false,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::Upnp => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                upnp_available: true,
                estimated_success_rate: 0.90,
                port_preservation: PortPreservation::Preferred,
                mapping_timeout_secs: 3600, // UPnP mappings are long-lived
                port_parity: true,
                port_contiguity: false,
                ..Default::default()
            },
            NatType::NatPmp => Self {
                mapping: MappingBehavior::EndpointIndependent,
                filtering: FilteringBehavior::AddressPortDependent,
                nat_pmp_available: true,
                estimated_success_rate: 0.90,
                port_preservation: PortPreservation::Preferred,
                mapping_timeout_secs: 7200, // NAT-PMP default lease is 2 hours
                port_parity: true,
                port_contiguity: false,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// MASQUE CONNECT-UDP relay (RFC 9298)
    MasqueRelay,
    /// MASQUE CONNECT-UDP relay over IPv4
    MasqueRelayIpv4,
    /// MASQUE CONNECT-UDP relay over IPv6
    MasqueRelayIpv6,
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
            Self::MasqueRelay => write!(f, "MASQUE Relay"),
            Self::MasqueRelayIpv4 => write!(f, "MASQUE IPv4"),
            Self::MasqueRelayIpv6 => write!(f, "MASQUE IPv6"),
            Self::UPnP => write!(f, "UPnP"),
            Self::NatPmp => write!(f, "NAT-PMP"),
        }
    }
}

/// Record of a single technique attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueAttempt {
    pub technique: ConnectionTechnique,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub data_proof: Option<DataProof>,
    #[serde(default)]
    pub method_proof: Option<MethodProof>,
}

/// Proof of bidirectional data transfer.
///
/// A connection is not considered "working" unless we can prove
/// data flows in BOTH directions. This struct captures that evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof {
    /// Bytes sent from local to remote
    pub bytes_sent: u64,
    /// Bytes received from remote to local
    pub bytes_received: u64,
    /// SHA-256 checksum of sent payload
    pub sent_checksum: String,
    /// SHA-256 checksum of received payload (should match what remote sent)
    pub received_checksum: String,
    /// Whether the received data was verified correct
    pub verified: bool,
    /// Round-trip time for echo test (send + receive + verify)
    pub echo_rtt_ms: Option<u64>,
    /// Whether stream-based transfer was tested
    pub stream_tested: bool,
    /// Whether datagram-based transfer was tested  
    pub datagram_tested: bool,
    /// Timestamp when data proof was captured
    pub timestamp_ms: u64,
}

impl DataProof {
    /// Create a new data proof with the given measurements.
    pub fn new(
        bytes_sent: u64,
        bytes_received: u64,
        sent_checksum: String,
        received_checksum: String,
        verified: bool,
    ) -> Self {
        Self {
            bytes_sent,
            bytes_received,
            sent_checksum,
            received_checksum,
            verified,
            echo_rtt_ms: None,
            stream_tested: true,
            datagram_tested: false,
            timestamp_ms: unix_timestamp_ms(),
        }
    }

    /// Check if this data proof demonstrates bidirectional communication.
    pub fn is_bidirectional(&self) -> bool {
        self.bytes_sent > 0 && self.bytes_received > 0 && self.verified
    }

    /// Create a failed/empty data proof.
    pub fn failed() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            sent_checksum: String::new(),
            received_checksum: String::new(),
            verified: false,
            echo_rtt_ms: None,
            stream_tested: false,
            datagram_tested: false,
            timestamp_ms: unix_timestamp_ms(),
        }
    }
}

impl Default for DataProof {
    fn default() -> Self {
        Self::failed()
    }
}

/// Success level for connectivity verification.
///
/// These levels define escalating proof requirements for "connectivity works".
/// Tests MUST achieve at least Level 2 (Usable) + Level 4 (CorrectMethod) to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SuccessLevel {
    /// Level 0: Connection failed entirely
    #[default]
    Failed = 0,
    /// Level 1: Established - QUIC handshake completed, peer authenticated
    /// Necessary but NOT sufficient for "connectivity works"
    Established = 1,
    /// Level 2: Usable - Bidirectional application data verified
    /// MINIMUM requirement for pass
    Usable = 2,
    /// Level 3: Sustained - Transfer maintained under impairment
    /// No spurious disconnects or stalled streams
    Sustained = 3,
    /// Level 4: CorrectMethod - Proved the right technique was used
    /// (direct vs hole-punched vs relayed with evidence)
    CorrectMethod = 4,
    /// Level 5: Temporal - Survives time and change
    /// Idle/expiry resilience, reconnect within SLO
    Temporal = 5,
}

impl SuccessLevel {
    /// Check if this level meets the minimum requirement for a passing test.
    /// Requires at least Level 2 (Usable).
    pub fn is_passing(&self) -> bool {
        *self >= SuccessLevel::Usable
    }

    /// Human-readable description of this success level.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Failed => "Connection failed",
            Self::Established => "QUIC handshake completed (no data proof)",
            Self::Usable => "Bidirectional data transfer verified",
            Self::Sustained => "Sustained transfer under impairment",
            Self::CorrectMethod => "Correct technique attribution verified",
            Self::Temporal => "Temporal resilience verified",
        }
    }
}

impl std::fmt::Display for SuccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "L{}: {}", *self as u8, self.description())
    }
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

/// Proof of connection method attribution.
///
/// Captures NAT frame exchange evidence to prove HOW a connection succeeded.
/// Without this evidence, we cannot distinguish between:
/// - "Direct succeeded because peer was reachable"
/// - "NAT traversal succeeded but we recorded it wrong"
/// - "Relay was used but we think it was direct"
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MethodProof {
    /// Claimed connection method
    pub claimed_method: Option<ConnectionMethod>,

    /// ADD_ADDRESS frames sent during connection establishment
    pub add_address_sent: u32,
    /// ADD_ADDRESS frames received during connection establishment
    pub add_address_received: u32,

    /// PUNCH_ME_NOW frames sent during connection establishment
    pub punch_me_now_sent: u32,
    /// PUNCH_ME_NOW frames received during connection establishment
    pub punch_me_now_received: u32,

    /// OBSERVED_ADDRESS frames sent during connection establishment
    pub observed_address_sent: u32,
    /// OBSERVED_ADDRESS frames received during connection establishment
    pub observed_address_received: u32,

    /// Local address used for connection (our side of the 5-tuple)
    pub local_addr: Option<String>,
    /// Remote address used for connection (peer side of the 5-tuple)
    pub remote_addr: Option<String>,

    /// External address as reported by peer (from OBSERVED_ADDRESS)
    pub observed_external_addr: Option<String>,

    /// Relay peer ID if connection is relayed
    pub relay_peer_id: Option<String>,
    /// Relay address if connection is relayed
    pub relay_addr: Option<String>,

    /// Coordinator peer ID if hole-punch was coordinated
    pub coordinator_peer_id: Option<String>,

    /// Timestamp when first NAT frame was exchanged (ms since epoch)
    pub first_nat_frame_ms: Option<u64>,
    /// Timestamp when connection was established (ms since epoch)
    pub connection_established_ms: Option<u64>,

    /// Whether the path changed during connection (migration detected)
    pub path_changed: bool,

    /// Confidence score for the method attribution (0.0 - 1.0)
    pub confidence: f64,
}

impl MethodProof {
    /// Create a new empty method proof.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a proof for a direct connection (no NAT frames exchanged).
    pub fn direct(local: &str, remote: &str) -> Self {
        Self {
            claimed_method: Some(ConnectionMethod::Direct),
            local_addr: Some(local.to_string()),
            remote_addr: Some(remote.to_string()),
            confidence: 1.0,
            connection_established_ms: Some(unix_timestamp_ms()),
            ..Default::default()
        }
    }

    /// Create a proof for a hole-punched connection.
    pub fn hole_punched(
        local: &str,
        remote: &str,
        coordinator: Option<&str>,
        nat_frames_exchanged: u32,
    ) -> Self {
        let confidence = if nat_frames_exchanged > 0 { 0.9 } else { 0.5 };
        Self {
            claimed_method: Some(ConnectionMethod::HolePunched),
            local_addr: Some(local.to_string()),
            remote_addr: Some(remote.to_string()),
            coordinator_peer_id: coordinator.map(String::from),
            add_address_sent: nat_frames_exchanged / 2,
            punch_me_now_sent: nat_frames_exchanged / 2,
            confidence,
            connection_established_ms: Some(unix_timestamp_ms()),
            ..Default::default()
        }
    }

    /// Create a proof for a relayed connection.
    pub fn relayed(relay_peer: &str, relay_addr: &str) -> Self {
        Self {
            claimed_method: Some(ConnectionMethod::Relayed),
            relay_peer_id: Some(relay_peer.to_string()),
            relay_addr: Some(relay_addr.to_string()),
            confidence: 1.0,
            connection_established_ms: Some(unix_timestamp_ms()),
            ..Default::default()
        }
    }

    /// Check if this proof has sufficient evidence for the claimed method.
    pub fn has_sufficient_evidence(&self) -> bool {
        match self.claimed_method {
            Some(ConnectionMethod::Direct) => {
                self.add_address_sent == 0
                    && self.punch_me_now_sent == 0
                    && self.relay_peer_id.is_none()
            }
            Some(ConnectionMethod::HolePunched) => {
                (self.add_address_sent > 0 || self.punch_me_now_sent > 0)
                    && self.relay_peer_id.is_none()
            }
            Some(ConnectionMethod::Relayed) => self.relay_peer_id.is_some(),
            None => false,
        }
    }

    /// Calculate confidence score based on evidence.
    pub fn calculate_confidence(&self) -> f64 {
        match self.claimed_method {
            Some(ConnectionMethod::Direct) => {
                if self.add_address_sent == 0
                    && self.punch_me_now_sent == 0
                    && self.relay_peer_id.is_none()
                {
                    1.0
                } else if self.relay_peer_id.is_some() {
                    0.0
                } else {
                    0.3
                }
            }
            Some(ConnectionMethod::HolePunched) => {
                let nat_frames = self.add_address_sent + self.punch_me_now_sent;
                if nat_frames == 0 {
                    0.3
                } else if nat_frames >= 2 && self.coordinator_peer_id.is_some() {
                    0.95
                } else if nat_frames >= 2 {
                    0.8
                } else {
                    0.6
                }
            }
            Some(ConnectionMethod::Relayed) => {
                if self.relay_peer_id.is_some() && self.relay_addr.is_some() {
                    1.0
                } else if self.relay_peer_id.is_some() {
                    0.8
                } else {
                    0.2
                }
            }
            None => 0.0,
        }
    }

    /// Update confidence score based on current evidence.
    pub fn update_confidence(&mut self) {
        self.confidence = self.calculate_confidence();
    }

    /// Record that an ADD_ADDRESS frame was sent.
    pub fn record_add_address_sent(&mut self) {
        self.add_address_sent += 1;
        if self.first_nat_frame_ms.is_none() {
            self.first_nat_frame_ms = Some(unix_timestamp_ms());
        }
    }

    /// Record that an ADD_ADDRESS frame was received.
    pub fn record_add_address_received(&mut self) {
        self.add_address_received += 1;
        if self.first_nat_frame_ms.is_none() {
            self.first_nat_frame_ms = Some(unix_timestamp_ms());
        }
    }

    /// Record that a PUNCH_ME_NOW frame was sent.
    pub fn record_punch_me_now_sent(&mut self) {
        self.punch_me_now_sent += 1;
        if self.first_nat_frame_ms.is_none() {
            self.first_nat_frame_ms = Some(unix_timestamp_ms());
        }
    }

    /// Record that a PUNCH_ME_NOW frame was received.
    pub fn record_punch_me_now_received(&mut self) {
        self.punch_me_now_received += 1;
        if self.first_nat_frame_ms.is_none() {
            self.first_nat_frame_ms = Some(unix_timestamp_ms());
        }
    }

    /// Record that an OBSERVED_ADDRESS frame was received with our external address.
    pub fn record_observed_address(&mut self, external_addr: &str) {
        self.observed_address_received += 1;
        self.observed_external_addr = Some(external_addr.to_string());
        if self.first_nat_frame_ms.is_none() {
            self.first_nat_frame_ms = Some(unix_timestamp_ms());
        }
    }

    /// Total NAT frames exchanged (sent + received).
    pub fn total_nat_frames(&self) -> u32 {
        self.add_address_sent
            + self.add_address_received
            + self.punch_me_now_sent
            + self.punch_me_now_received
            + self.observed_address_sent
            + self.observed_address_received
    }

    /// Check if any NAT traversal frames were exchanged.
    pub fn has_nat_frame_evidence(&self) -> bool {
        self.total_nat_frames() > 0
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TestPattern {
    #[default]
    Outbound,
    Inbound,
    Simultaneous,
    InboundUnderLoad,
}

impl std::fmt::Display for TestPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Outbound => write!(f, "A→B"),
            Self::Inbound => write!(f, "B→A"),
            Self::Simultaneous => write!(f, "A↔B"),
            Self::InboundUnderLoad => write!(f, "B→A (load)"),
        }
    }
}

impl TestPattern {
    pub fn requires_coordination(&self) -> bool {
        matches!(self, Self::Simultaneous)
    }

    pub fn is_bidirectional_test(&self) -> bool {
        matches!(self, Self::Simultaneous)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub name: String,
    pub mtu: u16,
    pub latency_ms: u32,
    pub loss_percent: f32,
    pub jitter_ms: u32,
    pub bandwidth_kbps: Option<u32>,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self::ideal()
    }
}

impl NetworkProfile {
    pub fn ideal() -> Self {
        Self {
            name: "ideal".to_string(),
            mtu: 1500,
            latency_ms: 0,
            loss_percent: 0.0,
            jitter_ms: 0,
            bandwidth_kbps: None,
        }
    }

    pub fn low_mtu() -> Self {
        Self {
            name: "low_mtu".to_string(),
            mtu: 1200,
            latency_ms: 10,
            loss_percent: 0.0,
            jitter_ms: 5,
            bandwidth_kbps: None,
        }
    }

    pub fn high_latency() -> Self {
        Self {
            name: "high_latency".to_string(),
            mtu: 1500,
            latency_ms: 200,
            loss_percent: 0.0,
            jitter_ms: 50,
            bandwidth_kbps: None,
        }
    }

    pub fn lossy() -> Self {
        Self {
            name: "lossy".to_string(),
            mtu: 1500,
            latency_ms: 50,
            loss_percent: 3.0,
            jitter_ms: 20,
            bandwidth_kbps: None,
        }
    }

    pub fn mobile() -> Self {
        Self {
            name: "mobile".to_string(),
            mtu: 1400,
            latency_ms: 100,
            loss_percent: 1.0,
            jitter_ms: 30,
            bandwidth_kbps: Some(5000),
        }
    }

    pub fn stressed() -> Self {
        Self {
            name: "stressed".to_string(),
            mtu: 1200,
            latency_ms: 300,
            loss_percent: 5.0,
            jitter_ms: 100,
            bandwidth_kbps: Some(1000),
        }
    }

    pub fn is_impaired(&self) -> bool {
        self.mtu < 1400 || self.latency_ms > 50 || self.loss_percent > 0.5
    }

    pub fn severity_score(&self) -> f32 {
        let mtu_penalty = if self.mtu < 1400 {
            (1400 - self.mtu) as f32 / 200.0
        } else {
            0.0
        };
        let latency_penalty = self.latency_ms as f32 / 500.0;
        let loss_penalty = self.loss_percent / 5.0;
        (mtu_penalty + latency_penalty + loss_penalty).min(1.0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpairmentMetrics {
    pub handshake_bytes: u64,
    pub handshake_messages: u32,
    pub pmtu_probes_sent: u32,
    pub pmtu_blackholes_detected: u32,
    pub retransmissions: u64,
    pub pto_events: u32,
    pub handshake_duration_ms: u64,
    pub crypto_cpu_us: Option<u64>,
    pub fragmentation_events: u32,
    pub connection_migrations: u32,
}

impl ImpairmentMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_handshake(&mut self, bytes: u64, messages: u32, duration_ms: u64) {
        self.handshake_bytes = bytes;
        self.handshake_messages = messages;
        self.handshake_duration_ms = duration_ms;
    }

    pub fn record_pmtu_probe(&mut self) {
        self.pmtu_probes_sent += 1;
    }

    pub fn record_blackhole(&mut self) {
        self.pmtu_blackholes_detected += 1;
    }

    pub fn record_retransmission(&mut self) {
        self.retransmissions += 1;
    }

    pub fn record_pto(&mut self) {
        self.pto_events += 1;
    }

    pub fn has_issues(&self) -> bool {
        self.pmtu_blackholes_detected > 0 || self.pto_events > 3 || self.retransmissions > 10
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TemporalScenario {
    #[default]
    ColdStart,
    WarmReconnect,
    NatBindingExpiry,
    RepeatedChurn,
}

impl std::fmt::Display for TemporalScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ColdStart => write!(f, "Cold Start"),
            Self::WarmReconnect => write!(f, "Warm Reconnect"),
            Self::NatBindingExpiry => write!(f, "NAT Binding Expiry"),
            Self::RepeatedChurn => write!(f, "Repeated Churn"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemporalMetrics {
    pub scenario: TemporalScenario,
    pub idle_duration_ms: u64,
    pub keepalive_sent: u32,
    pub keepalive_received: u32,
    pub binding_expired: bool,
    pub reconnect_required: bool,
    pub reconnect_time_ms: Option<u64>,
    pub re_hole_punch_required: bool,
    pub churn_cycles_completed: u32,
    pub churn_cycles_failed: u32,
    pub connection_survived: bool,
}

impl TemporalMetrics {
    pub fn new(scenario: TemporalScenario) -> Self {
        Self {
            scenario,
            ..Default::default()
        }
    }

    pub fn record_idle(&mut self, duration_ms: u64) {
        self.idle_duration_ms = duration_ms;
    }

    pub fn record_keepalive_sent(&mut self) {
        self.keepalive_sent += 1;
    }

    pub fn record_keepalive_received(&mut self) {
        self.keepalive_received += 1;
    }

    pub fn record_binding_expired(&mut self) {
        self.binding_expired = true;
    }

    pub fn record_reconnect(&mut self, time_ms: u64, re_hole_punch: bool) {
        self.reconnect_required = true;
        self.reconnect_time_ms = Some(time_ms);
        self.re_hole_punch_required = re_hole_punch;
    }

    pub fn record_churn_cycle(&mut self, success: bool) {
        if success {
            self.churn_cycles_completed += 1;
        } else {
            self.churn_cycles_failed += 1;
        }
    }

    pub fn mark_survived(&mut self) {
        self.connection_survived = true;
    }

    pub fn is_level5_passing(&self) -> bool {
        self.connection_survived
            || (self.reconnect_required && self.reconnect_time_ms.is_some_and(|t| t < 5000))
    }

    pub fn keepalive_effective(&self) -> bool {
        self.keepalive_sent > 0 && !self.binding_expired
    }

    pub fn churn_success_rate(&self) -> f64 {
        let total = self.churn_cycles_completed + self.churn_cycles_failed;
        if total == 0 {
            1.0
        } else {
            self.churn_cycles_completed as f64 / total as f64
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationMetrics {
    pub migrations_attempted: u32,
    pub migrations_succeeded: u32,
    pub path_challenges_sent: u32,
    pub path_responses_received: u32,
    pub data_continued_after_migration: bool,
    pub path_history: Vec<PathTuple>,
    pub source_changes: u32,
    pub nat_rebindings: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTuple {
    pub local_addr: String,
    pub remote_addr: String,
    pub timestamp_ms: u64,
}

impl MigrationMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_migration_attempt(&mut self) {
        self.migrations_attempted += 1;
    }

    pub fn record_migration_success(&mut self) {
        self.migrations_succeeded += 1;
    }

    pub fn record_path_challenge(&mut self) {
        self.path_challenges_sent += 1;
    }

    pub fn record_path_response(&mut self) {
        self.path_responses_received += 1;
    }

    pub fn record_path_change(&mut self, local: &str, remote: &str) {
        self.path_history.push(PathTuple {
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            timestamp_ms: unix_timestamp_ms(),
        });
    }

    pub fn mark_data_continued(&mut self) {
        self.data_continued_after_migration = true;
    }

    pub fn migration_success_rate(&self) -> f64 {
        if self.migrations_attempted == 0 {
            1.0
        } else {
            self.migrations_succeeded as f64 / self.migrations_attempted as f64
        }
    }

    pub fn path_validation_rate(&self) -> f64 {
        if self.path_challenges_sent == 0 {
            1.0
        } else {
            self.path_responses_received as f64 / self.path_challenges_sent as f64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailureReasonCode {
    Success,
    Timeout,
    ConnectionRefused,
    HandshakeFailed,
    CryptoError,
    PmtuBlackhole,
    NatBindingExpired,
    AddressUnreachable,
    NoRouteToHost,
    PortUnreachable,
    TlsError,
    PqcNegotiationFailed,
    StreamReset,
    DataVerificationFailed,
    KeepaliveTimeout,
    MigrationFailed,
    RelayUnavailable,
    CoordinatorUnreachable,
    RateLimited,
    ResourceExhausted,
    ProtocolViolation,
    InternalError,
    #[default]
    Unknown,
}

impl std::fmt::Display for FailureReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Timeout => write!(f, "Connection timeout"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::HandshakeFailed => write!(f, "Handshake failed"),
            Self::CryptoError => write!(f, "Cryptographic error"),
            Self::PmtuBlackhole => write!(f, "PMTU blackhole detected"),
            Self::NatBindingExpired => write!(f, "NAT binding expired"),
            Self::AddressUnreachable => write!(f, "Address unreachable"),
            Self::NoRouteToHost => write!(f, "No route to host"),
            Self::PortUnreachable => write!(f, "Port unreachable"),
            Self::TlsError => write!(f, "TLS error"),
            Self::PqcNegotiationFailed => write!(f, "PQC negotiation failed"),
            Self::StreamReset => write!(f, "Stream reset"),
            Self::DataVerificationFailed => write!(f, "Data verification failed"),
            Self::KeepaliveTimeout => write!(f, "Keepalive timeout"),
            Self::MigrationFailed => write!(f, "Migration failed"),
            Self::RelayUnavailable => write!(f, "Relay unavailable"),
            Self::CoordinatorUnreachable => write!(f, "Coordinator unreachable"),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::ProtocolViolation => write!(f, "Protocol violation"),
            Self::InternalError => write!(f, "Internal error"),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl FailureReasonCode {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::NatBindingExpired
                | Self::KeepaliveTimeout
                | Self::RateLimited
                | Self::RelayUnavailable
        )
    }

    pub fn is_configuration_issue(&self) -> bool {
        matches!(
            self,
            Self::AddressUnreachable | Self::NoRouteToHost | Self::PortUnreachable
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestReport {
    pub run_id: String,
    pub git_sha: Option<String>,
    pub timestamp_ms: u64,
    pub duration_ms: u64,
    pub topology: String,
    pub network_profile: Option<NetworkProfile>,
    pub total_pairs: u32,
    pub pairs_passed: u32,
    pub pairs_failed: u32,
    pub pass_rate: f64,
    pub techniques_tested: Vec<ConnectionTechnique>,
    pub failure_breakdown: HashMap<FailureReasonCode, u32>,
    pub latency_p50_ms: Option<u64>,
    pub latency_p95_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
}

impl TestReport {
    pub fn new(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_string(),
            timestamp_ms: unix_timestamp_ms(),
            ..Default::default()
        }
    }

    pub fn set_git_sha(&mut self, sha: &str) {
        self.git_sha = Some(sha.to_string());
    }

    pub fn set_topology(&mut self, topology: &str) {
        self.topology = topology.to_string();
    }

    pub fn record_pair_result(&mut self, passed: bool, failure_code: Option<FailureReasonCode>) {
        self.total_pairs += 1;
        if passed {
            self.pairs_passed += 1;
        } else {
            self.pairs_failed += 1;
            if let Some(code) = failure_code {
                *self.failure_breakdown.entry(code).or_insert(0) += 1;
            }
        }
        self.update_pass_rate();
    }

    pub fn update_pass_rate(&mut self) {
        if self.total_pairs > 0 {
            self.pass_rate = self.pairs_passed as f64 / self.total_pairs as f64;
        }
    }

    pub fn set_latencies(&mut self, p50: u64, p95: u64, p99: u64) {
        self.latency_p50_ms = Some(p50);
        self.latency_p95_ms = Some(p95);
        self.latency_p99_ms = Some(p99);
    }

    pub fn finalize(&mut self, duration_ms: u64) {
        self.duration_ms = duration_ms;
        self.update_pass_rate();
    }

    pub fn top_failures(&self, n: usize) -> Vec<(FailureReasonCode, u32)> {
        let mut failures: Vec<_> = self
            .failure_breakdown
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        failures.sort_by(|a, b| b.1.cmp(&a.1));
        failures.truncate(n);
        failures
    }

    pub fn human_summary(&self) -> String {
        let status = if self.pass_rate >= 0.95 {
            "PASS"
        } else if self.pass_rate >= 0.80 {
            "DEGRADED"
        } else {
            "FAIL"
        };
        let top_fails = self
            .top_failures(3)
            .iter()
            .map(|(code, count)| format!("{}: {}", code, count))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "[{}] {}/{} pairs passed ({:.1}%) | p50={}ms p95={}ms | top failures: {}",
            status,
            self.pairs_passed,
            self.total_pairs,
            self.pass_rate * 100.0,
            self.latency_p50_ms.unwrap_or(0),
            self.latency_p95_ms.unwrap_or(0),
            if top_fails.is_empty() {
                "none".to_string()
            } else {
                top_fails
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatScenario {
    BothPublic,
    SingleNatOnePublic,
    SingleNatBoth,
    Cgnat,
    DoubleNat,
    Hairpin,
    NatRebinding,
    MobileCarrier,
    Ipv6OnlyNat64,
    SymmetricBoth,
}

impl std::fmt::Display for NatScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BothPublic => write!(f, "Both Public"),
            Self::SingleNatOnePublic => write!(f, "Single NAT + Public"),
            Self::SingleNatBoth => write!(f, "Single NAT Both"),
            Self::Cgnat => write!(f, "CGNAT"),
            Self::DoubleNat => write!(f, "Double NAT"),
            Self::Hairpin => write!(f, "Hairpin NAT"),
            Self::NatRebinding => write!(f, "NAT Rebinding"),
            Self::MobileCarrier => write!(f, "Mobile Carrier"),
            Self::Ipv6OnlyNat64 => write!(f, "IPv6-only + NAT64"),
            Self::SymmetricBoth => write!(f, "Symmetric Both"),
        }
    }
}

impl NatScenario {
    pub fn is_ci_fast(&self) -> bool {
        matches!(
            self,
            Self::BothPublic | Self::SingleNatOnePublic | Self::SingleNatBoth | Self::Cgnat
        )
    }

    pub fn requires_relay(&self) -> bool {
        matches!(self, Self::SymmetricBoth | Self::DoubleNat)
    }

    pub fn expected_difficulty(&self) -> u8 {
        match self {
            Self::BothPublic => 1,
            Self::SingleNatOnePublic => 2,
            Self::SingleNatBoth => 3,
            Self::Cgnat => 4,
            Self::Hairpin => 3,
            Self::NatRebinding => 4,
            Self::MobileCarrier => 5,
            Self::DoubleNat => 5,
            Self::Ipv6OnlyNat64 => 4,
            Self::SymmetricBoth => 5,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayMetrics {
    pub relay_peer_id: Option<String>,
    pub relay_addr: Option<String>,
    pub relay_hop_count: u32,
    pub relay_latency_overhead_ms: Option<u64>,
    pub relay_throughput_kbps: Option<u32>,
    pub fallback_sequence: Vec<ConnectionTechnique>,
    pub direct_failed: bool,
    pub hole_punch_failed: bool,
    pub relay_required: bool,
    pub relay_success: bool,
}

impl RelayMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_direct_failed(&mut self) {
        self.direct_failed = true;
        self.fallback_sequence.push(ConnectionTechnique::DirectIpv4);
    }

    pub fn record_hole_punch_failed(&mut self) {
        self.hole_punch_failed = true;
        self.fallback_sequence.push(ConnectionTechnique::HolePunch);
    }

    pub fn record_relay_attempt(&mut self, peer_id: &str, addr: &str) {
        self.relay_required = true;
        self.relay_peer_id = Some(peer_id.to_string());
        self.relay_addr = Some(addr.to_string());
        self.fallback_sequence.push(ConnectionTechnique::Relay);
    }

    pub fn record_relay_success(&mut self, hop_count: u32, latency_overhead_ms: u64) {
        self.relay_success = true;
        self.relay_hop_count = hop_count;
        self.relay_latency_overhead_ms = Some(latency_overhead_ms);
    }

    pub fn is_relay_proven(&self) -> bool {
        self.relay_success && self.relay_peer_id.is_some() && self.relay_hop_count > 0
    }

    pub fn fallback_depth(&self) -> usize {
        self.fallback_sequence.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TestSuite {
    #[default]
    CiFast,
    NightlyDeep,
    Full,
}

impl std::fmt::Display for TestSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CiFast => write!(f, "CI-Fast (~5min)"),
            Self::NightlyDeep => write!(f, "Nightly-Deep (~30min)"),
            Self::Full => write!(f, "Full (~60min)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuiteConfig {
    pub suite: TestSuite,
    pub nat_scenarios: Vec<NatScenario>,
    pub test_patterns: Vec<TestPattern>,
    pub network_profiles: Vec<NetworkProfile>,
    pub temporal_scenarios: Vec<TemporalScenario>,
    pub enable_migration_tests: bool,
    pub enable_relay_tests: bool,
    pub churn_cycles: u32,
    pub timeout_secs: u32,
}

impl Default for TestSuiteConfig {
    fn default() -> Self {
        Self::ci_fast()
    }
}

impl TestSuiteConfig {
    pub fn ci_fast() -> Self {
        Self {
            suite: TestSuite::CiFast,
            nat_scenarios: vec![
                NatScenario::BothPublic,
                NatScenario::SingleNatOnePublic,
                NatScenario::SingleNatBoth,
            ],
            test_patterns: vec![TestPattern::Outbound, TestPattern::Inbound],
            network_profiles: vec![NetworkProfile::ideal(), NetworkProfile::low_mtu()],
            temporal_scenarios: vec![TemporalScenario::ColdStart],
            enable_migration_tests: false,
            enable_relay_tests: false,
            churn_cycles: 0,
            timeout_secs: 300,
        }
    }

    pub fn nightly_deep() -> Self {
        Self {
            suite: TestSuite::NightlyDeep,
            nat_scenarios: vec![
                NatScenario::BothPublic,
                NatScenario::SingleNatOnePublic,
                NatScenario::SingleNatBoth,
                NatScenario::Cgnat,
                NatScenario::DoubleNat,
                NatScenario::Hairpin,
                NatScenario::MobileCarrier,
            ],
            test_patterns: vec![
                TestPattern::Outbound,
                TestPattern::Inbound,
                TestPattern::Simultaneous,
                TestPattern::InboundUnderLoad,
            ],
            network_profiles: vec![
                NetworkProfile::ideal(),
                NetworkProfile::low_mtu(),
                NetworkProfile::high_latency(),
                NetworkProfile::lossy(),
                NetworkProfile::mobile(),
            ],
            temporal_scenarios: vec![
                TemporalScenario::ColdStart,
                TemporalScenario::WarmReconnect,
                TemporalScenario::NatBindingExpiry,
                TemporalScenario::RepeatedChurn,
            ],
            enable_migration_tests: true,
            enable_relay_tests: true,
            churn_cycles: 10,
            timeout_secs: 1800,
        }
    }

    pub fn full() -> Self {
        Self {
            suite: TestSuite::Full,
            nat_scenarios: vec![
                NatScenario::BothPublic,
                NatScenario::SingleNatOnePublic,
                NatScenario::SingleNatBoth,
                NatScenario::Cgnat,
                NatScenario::DoubleNat,
                NatScenario::Hairpin,
                NatScenario::NatRebinding,
                NatScenario::MobileCarrier,
                NatScenario::Ipv6OnlyNat64,
                NatScenario::SymmetricBoth,
            ],
            test_patterns: vec![
                TestPattern::Outbound,
                TestPattern::Inbound,
                TestPattern::Simultaneous,
                TestPattern::InboundUnderLoad,
            ],
            network_profiles: vec![
                NetworkProfile::ideal(),
                NetworkProfile::low_mtu(),
                NetworkProfile::high_latency(),
                NetworkProfile::lossy(),
                NetworkProfile::mobile(),
                NetworkProfile::stressed(),
            ],
            temporal_scenarios: vec![
                TemporalScenario::ColdStart,
                TemporalScenario::WarmReconnect,
                TemporalScenario::NatBindingExpiry,
                TemporalScenario::RepeatedChurn,
            ],
            enable_migration_tests: true,
            enable_relay_tests: true,
            churn_cycles: 20,
            timeout_secs: 3600,
        }
    }

    pub fn estimated_pairs(&self) -> usize {
        self.nat_scenarios.len() * self.test_patterns.len()
    }

    pub fn estimated_duration_secs(&self) -> u32 {
        match self.suite {
            TestSuite::CiFast => 300,
            TestSuite::NightlyDeep => 1800,
            TestSuite::Full => 3600,
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
    /// Detected NAT type (updated after external address discovery)
    #[serde(default)]
    pub nat_type: Option<NatType>,
    /// NAT traversal statistics
    pub nat_stats: Option<NatStats>,
    /// Gossip protocol statistics
    #[serde(default)]
    pub gossip_stats: Option<NodeGossipStats>,
    /// Full-mesh connectivity probe results.
    /// Maps peer_id -> probe result for all peers this node attempted to probe.
    #[serde(default)]
    pub full_mesh_probes: Option<HashMap<String, FullMeshProbeResult>>,
}

/// Result of a full-mesh connectivity probe to a single peer.
///
/// Unlike HyParView (which maintains only 8 active peers), the full-mesh probe
/// tests reachability to ALL peers in the network via the gossip transport.
/// This enables comprehensive network health monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FullMeshProbeResult {
    /// Peer was successfully probed (we could send/receive via gossip transport).
    pub reachable: bool,
    /// Round-trip time in milliseconds (if successful).
    pub rtt_ms: Option<u64>,
    /// Unix timestamp (millis) of the last probe attempt.
    pub last_probe_ms: u64,
    /// Number of successful probes in this interval.
    pub success_count: u32,
    /// Number of failed probes in this interval.
    pub failure_count: u32,
    /// Whether the peer is in our HyParView active view.
    pub in_active_view: bool,
    /// Whether the peer is in our HyParView passive view.
    pub in_passive_view: bool,
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
    /// Full-mesh connectivity probe results (peer_id -> result)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_mesh_probes: Option<HashMap<String, FullMeshProbeResult>>,
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

    // === Extended saorsa-gossip crate stats ===

    // HyParView extended stats
    /// Number of view shuffles performed
    #[serde(default)]
    pub hyparview_shuffles: u64,
    /// Join messages sent
    #[serde(default)]
    pub hyparview_joins: u64,
    /// ForwardJoin messages processed
    #[serde(default)]
    pub hyparview_forward_joins: u64,

    // SWIM extended stats
    /// SWIM pings sent
    #[serde(default)]
    pub swim_pings_sent: u64,
    /// SWIM pings received
    #[serde(default)]
    pub swim_pings_received: u64,
    /// SWIM ping-req sent (indirect pings)
    #[serde(default)]
    pub swim_ping_req_sent: u64,
    /// SWIM acks received
    #[serde(default)]
    pub swim_acks_received: u64,

    // Plumtree extended stats
    /// IHAVE messages sent (lazy push)
    #[serde(default)]
    pub plumtree_ihaves_sent: u64,
    /// IHAVE messages received
    #[serde(default)]
    pub plumtree_ihaves_received: u64,
    /// GRAFT messages sent (request missing data)
    #[serde(default)]
    pub plumtree_grafts_sent: u64,
    /// PRUNE messages sent (demote eager to lazy)
    #[serde(default)]
    pub plumtree_prunes_sent: u64,
    /// Total messages broadcast
    #[serde(default)]
    pub plumtree_broadcasts: u64,

    // CRDT-sync stats (saorsa-gossip-crdt-sync)
    /// Number of CRDT entries currently stored
    #[serde(default)]
    pub crdt_entries: usize,
    /// Total CRDT merges performed
    #[serde(default)]
    pub crdt_merges: u64,
    /// Current vector clock length
    #[serde(default)]
    pub crdt_vector_clock_len: usize,
    /// CRDT sync rounds completed
    #[serde(default)]
    pub crdt_sync_rounds: u64,
    /// CRDT delta messages sent
    #[serde(default)]
    pub crdt_deltas_sent: u64,
    /// CRDT delta messages received
    #[serde(default)]
    pub crdt_deltas_received: u64,

    // Coordinator stats (saorsa-gossip-coordinator)
    /// Active NAT traversal coordinations
    #[serde(default)]
    pub coordinator_active: usize,
    /// Successful coordinations
    #[serde(default)]
    pub coordinator_success: u64,
    /// Failed coordinations
    #[serde(default)]
    pub coordinator_failed: u64,
    /// Coordination requests sent
    #[serde(default)]
    pub coordinator_requests: u64,

    // Groups stats (saorsa-gossip-groups)
    /// Number of groups this node is a member of
    #[serde(default)]
    pub groups_count: usize,
    /// Total members across all groups
    #[serde(default)]
    pub groups_total_members: usize,
    /// Group join messages sent
    #[serde(default)]
    pub groups_joins: u64,
    /// Group leave messages sent
    #[serde(default)]
    pub groups_leaves: u64,

    // Rendezvous stats (saorsa-gossip-rendezvous)
    /// Rendezvous registrations
    #[serde(default)]
    pub rendezvous_registrations: u64,
    /// Rendezvous discoveries
    #[serde(default)]
    pub rendezvous_discoveries: u64,
    /// Active rendezvous points
    #[serde(default)]
    pub rendezvous_points: usize,
    /// Rendezvous queries sent
    #[serde(default)]
    pub rendezvous_queries: u64,

    // Identity stats (saorsa-gossip-identity)
    /// Known peer identities
    #[serde(default)]
    pub identity_known_peers: usize,
    /// Identity verifications performed
    #[serde(default)]
    pub identity_verifications: u64,

    // Transport stats (saorsa-gossip-transport)
    /// UDP packets sent via gossip transport
    #[serde(default)]
    pub transport_packets_sent: u64,
    /// UDP packets received via gossip transport
    #[serde(default)]
    pub transport_packets_received: u64,
    /// Transport bytes sent
    #[serde(default)]
    pub transport_bytes_sent: u64,
    /// Transport bytes received
    #[serde(default)]
    pub transport_bytes_received: u64,
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

    // === Aggregated Epidemic Gossip Stats ===
    /// Total SWIM alive peers across all nodes
    pub total_swim_alive: u64,
    /// Total SWIM suspect peers across all nodes
    pub total_swim_suspect: u64,
    /// Total SWIM dead peers across all nodes
    pub total_swim_dead: u64,
    /// Total HyParView active peers across all nodes
    pub total_hyparview_active: u64,
    /// Total HyParView passive peers across all nodes
    pub total_hyparview_passive: u64,

    // === Connection Type Breakdown ===
    /// Total direct IPv4 connections across all nodes
    pub total_conn_direct_ipv4: u64,
    /// Total direct IPv6 connections across all nodes
    pub total_conn_direct_ipv6: u64,
    /// Total hole-punched connections across all nodes
    pub total_conn_hole_punched: u64,
    /// Total relayed connections across all nodes
    pub total_conn_relayed: u64,
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
    /// Request for all nodes to test connectivity to a new peer.
    /// This is broadcast when a new peer registers and wants connectivity testing.
    /// All receiving nodes should attempt to connect to the peer using:
    /// IPv4 direct → IPv6 direct → NAT traversal → Relay
    ConnectivityTestRequest {
        /// Peer ID to test connectivity to
        peer_id: String,
        /// Addresses where the peer can be reached
        addresses: Vec<SocketAddr>,
        /// Relay address to use if direct connection fails
        relay_addr: Option<SocketAddr>,
        /// Request timestamp (unix ms)
        timestamp_ms: u64,
    },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Currently active (heartbeat within threshold)
    #[default]
    Active,
    /// Recently inactive (within 5 minutes)
    Inactive,
    /// Historical (offline for more than 5 minutes)
    Historical,
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

    /// MASQUE CONNECT-UDP relay tested
    #[serde(default)]
    pub masque_tested: bool,
    /// MASQUE CONNECT-UDP relay succeeded
    #[serde(default)]
    pub masque_success: bool,
    /// MASQUE CONNECT-UDP relay RTT in ms
    #[serde(default)]
    pub masque_rtt_ms: Option<u64>,

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

    #[serde(default)]
    pub success_level: SuccessLevel,

    #[serde(default)]
    pub data_proof: Option<DataProof>,

    #[serde(default)]
    pub method_proof: Option<MethodProof>,

    #[serde(default)]
    pub test_pattern: TestPattern,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_profile: Option<NetworkProfile>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impairment_metrics: Option<ImpairmentMetrics>,
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

        if self.masque_tested {
            let status = if self.masque_success { "✓" } else { "✗" };
            parts.push(format!("MASQUE:{}", status));
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
        if self.masque_success {
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
        if self.masque_tested {
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
            data_proof: None,
            method_proof: None,
        };
        self.technique_attempts.push(attempt);

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
            ConnectionTechnique::MasqueRelay
            | ConnectionTechnique::MasqueRelayIpv4
            | ConnectionTechnique::MasqueRelayIpv6 => {
                self.masque_tested = true;
                if success {
                    self.masque_success = true;
                    self.masque_rtt_ms = Some(duration_ms);
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

    /// Record a technique attempt with bidirectional data proof.
    pub fn record_attempt_with_proof(
        &mut self,
        technique: ConnectionTechnique,
        success: bool,
        duration_ms: u64,
        error: Option<String>,
        data_proof: Option<DataProof>,
    ) {
        let attempt = TechniqueAttempt {
            technique,
            success,
            duration_ms,
            error,
            timestamp_ms: unix_timestamp_ms(),
            data_proof: data_proof.clone(),
            method_proof: None,
        };
        self.technique_attempts.push(attempt);

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
            ConnectionTechnique::MasqueRelay
            | ConnectionTechnique::MasqueRelayIpv4
            | ConnectionTechnique::MasqueRelayIpv6 => {
                self.masque_tested = true;
                if success {
                    self.masque_success = true;
                    self.masque_rtt_ms = Some(duration_ms);
                }
            }
            ConnectionTechnique::UPnP | ConnectionTechnique::NatPmp => {
                self.ipv4_direct_tested = true;
                if success {
                    self.ipv4_direct_success = true;
                    self.ipv4_direct_rtt_ms = Some(duration_ms);
                }
            }
        }

        if data_proof.is_some() {
            self.data_proof = data_proof;
        }

        self.success_level = self.calculate_success_level();
    }

    /// Calculate the success level based on current state.
    pub fn calculate_success_level(&self) -> SuccessLevel {
        let any_success = self.ipv4_direct_success
            || self.ipv6_direct_success
            || self.nat_traversal_success
            || self.relay_success
            || self.masque_success;

        if !any_success {
            return SuccessLevel::Failed;
        }

        let has_bidirectional_proof = self
            .data_proof
            .as_ref()
            .is_some_and(|p| p.is_bidirectional());

        if !has_bidirectional_proof {
            return SuccessLevel::Established;
        }

        let has_method_proof = self
            .method_proof
            .as_ref()
            .is_some_and(|p| p.has_sufficient_evidence());

        if has_method_proof {
            return SuccessLevel::CorrectMethod;
        }

        SuccessLevel::Usable
    }

    pub fn is_passing(&self) -> bool {
        self.success_level.is_passing()
    }

    pub fn has_data_proof(&self) -> bool {
        self.data_proof
            .as_ref()
            .is_some_and(|p| p.is_bidirectional())
    }

    pub fn has_method_proof(&self) -> bool {
        self.method_proof
            .as_ref()
            .is_some_and(|p| p.has_sufficient_evidence())
    }

    pub fn is_fully_passing(&self) -> bool {
        self.success_level >= SuccessLevel::Usable && self.has_method_proof()
    }

    pub fn passes_for_pattern(&self, pattern: TestPattern) -> bool {
        if !self.is_passing() {
            return false;
        }
        self.test_pattern == pattern
    }

    pub fn passes_under_impairment(&self) -> bool {
        self.is_passing()
            && self
                .network_profile
                .as_ref()
                .is_some_and(|p| p.is_impaired())
    }

    pub fn set_test_pattern(&mut self, pattern: TestPattern) {
        self.test_pattern = pattern;
    }

    pub fn set_network_profile(&mut self, profile: NetworkProfile) {
        self.network_profile = Some(profile);
    }

    pub fn record_impairment_metrics(&mut self, metrics: ImpairmentMetrics) {
        self.impairment_metrics = Some(metrics);
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
    /// Aggregated epidemic gossip stats (the working gossip layer)
    #[serde(default)]
    pub gossip: Option<AggregatedGossipStats>,
}

/// Aggregated gossip statistics across all nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregatedGossipStats {
    /// Total Plumtree messages sent across network
    pub plumtree_messages_sent: u64,
    /// Total Plumtree messages received across network
    pub plumtree_messages_received: u64,
    /// Total HyParView active view connections
    pub hyparview_active_total: u64,
    /// Total SWIM alive peers
    pub swim_alive_total: u64,
    /// Average active view size per node
    pub avg_active_view_size: f64,

    // Additional fields for dashboard gossip panel
    /// Average HyParView active view size per node
    #[serde(default)]
    pub avg_hyparview_active: usize,
    /// Average HyParView passive view size per node
    #[serde(default)]
    pub avg_hyparview_passive: usize,
    /// Total SWIM alive peers across network
    #[serde(default)]
    pub total_swim_alive: usize,
    /// Total SWIM suspect peers across network
    #[serde(default)]
    pub total_swim_suspect: usize,
    /// Total SWIM dead peers across network
    #[serde(default)]
    pub total_swim_dead: usize,
    /// Average Plumtree eager peers per node
    #[serde(default)]
    pub avg_plumtree_eager: usize,
    /// Average Plumtree lazy peers per node
    #[serde(default)]
    pub avg_plumtree_lazy: usize,
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
            data_proof: None,
            method_proof: None,
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

    #[test]
    fn test_connectivity_test_request_deserialization() {
        let json = r#"{"type":"connectivity_test_request","peer_id":"abc123def456","addresses":["127.0.0.1:9000","[::1]:9001"],"relay_addr":null,"timestamp_ms":1234567890}"#;
        let event: NetworkEvent = serde_json::from_str(json).expect("should deserialize");
        match event {
            NetworkEvent::ConnectivityTestRequest {
                peer_id,
                addresses,
                relay_addr,
                timestamp_ms,
            } => {
                assert_eq!(peer_id, "abc123def456");
                assert_eq!(addresses.len(), 2);
                assert_eq!(addresses[0].to_string(), "127.0.0.1:9000");
                assert_eq!(addresses[1].to_string(), "[::1]:9001");
                assert!(relay_addr.is_none());
                assert_eq!(timestamp_ms, 1234567890);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ===== DataProof Tests =====

    #[test]
    fn test_data_proof_new() {
        let proof = DataProof::new(1024, 1024, "abc123".to_string(), "def456".to_string(), true);

        assert_eq!(proof.bytes_sent, 1024);
        assert_eq!(proof.bytes_received, 1024);
        assert_eq!(proof.sent_checksum, "abc123");
        assert_eq!(proof.received_checksum, "def456");
        assert!(proof.verified);
        assert!(proof.stream_tested);
        assert!(!proof.datagram_tested);
        assert!(proof.timestamp_ms > 0);
    }

    #[test]
    fn test_data_proof_is_bidirectional() {
        // Valid bidirectional proof
        let proof = DataProof::new(1024, 1024, "a".into(), "b".into(), true);
        assert!(proof.is_bidirectional());

        // Missing send data
        let no_send = DataProof::new(0, 1024, "".into(), "b".into(), true);
        assert!(!no_send.is_bidirectional());

        // Missing receive data
        let no_recv = DataProof::new(1024, 0, "a".into(), "".into(), true);
        assert!(!no_recv.is_bidirectional());

        // Not verified
        let unverified = DataProof::new(1024, 1024, "a".into(), "b".into(), false);
        assert!(!unverified.is_bidirectional());
    }

    #[test]
    fn test_data_proof_failed() {
        let proof = DataProof::failed();
        assert_eq!(proof.bytes_sent, 0);
        assert_eq!(proof.bytes_received, 0);
        assert!(!proof.verified);
        assert!(!proof.is_bidirectional());
    }

    #[test]
    fn test_data_proof_default() {
        let proof = DataProof::default();
        assert!(!proof.is_bidirectional());
        assert!(!proof.verified);
    }

    #[test]
    fn test_data_proof_serialization() {
        let proof = DataProof::new(512, 512, "checksum1".into(), "checksum2".into(), true);
        let json = serde_json::to_string(&proof).expect("serialization should work");
        assert!(json.contains("512"));
        assert!(json.contains("checksum1"));
        assert!(json.contains("checksum2"));
        assert!(json.contains("true"));

        // Round-trip
        let decoded: DataProof = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.bytes_sent, 512);
        assert_eq!(decoded.bytes_received, 512);
        assert!(decoded.verified);
    }

    // ===== SuccessLevel Tests =====

    #[test]
    fn test_success_level_ordering() {
        assert!(SuccessLevel::Failed < SuccessLevel::Established);
        assert!(SuccessLevel::Established < SuccessLevel::Usable);
        assert!(SuccessLevel::Usable < SuccessLevel::Sustained);
        assert!(SuccessLevel::Sustained < SuccessLevel::CorrectMethod);
        assert!(SuccessLevel::CorrectMethod < SuccessLevel::Temporal);
    }

    #[test]
    fn test_success_level_is_passing() {
        assert!(!SuccessLevel::Failed.is_passing());
        assert!(!SuccessLevel::Established.is_passing());
        assert!(SuccessLevel::Usable.is_passing());
        assert!(SuccessLevel::Sustained.is_passing());
        assert!(SuccessLevel::CorrectMethod.is_passing());
        assert!(SuccessLevel::Temporal.is_passing());
    }

    #[test]
    fn test_success_level_display() {
        assert!(SuccessLevel::Failed.to_string().contains("L0"));
        assert!(SuccessLevel::Established.to_string().contains("L1"));
        assert!(SuccessLevel::Usable.to_string().contains("L2"));
        assert!(SuccessLevel::Sustained.to_string().contains("L3"));
        assert!(SuccessLevel::CorrectMethod.to_string().contains("L4"));
        assert!(SuccessLevel::Temporal.to_string().contains("L5"));
    }

    #[test]
    fn test_success_level_description() {
        assert!(SuccessLevel::Failed.description().contains("failed"));
        assert!(
            SuccessLevel::Established
                .description()
                .contains("handshake")
        );
        assert!(SuccessLevel::Usable.description().contains("Bidirectional"));
        assert!(SuccessLevel::Sustained.description().contains("Sustained"));
        assert!(
            SuccessLevel::CorrectMethod
                .description()
                .contains("technique")
        );
        assert!(SuccessLevel::Temporal.description().contains("Temporal"));
    }

    #[test]
    fn test_success_level_serialization() {
        let level = SuccessLevel::Usable;
        let json = serde_json::to_string(&level).expect("serialization should work");
        assert!(json.contains("usable"));

        let decoded: SuccessLevel =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded, SuccessLevel::Usable);
    }

    // ===== ConnectivityMatrix with DataProof Tests =====

    #[test]
    fn test_connectivity_matrix_record_attempt_with_proof() {
        let mut matrix = ConnectivityMatrix::new();

        // Record successful connection with data proof
        let proof = DataProof::new(1024, 1024, "sent".into(), "recv".into(), true);
        matrix.record_attempt_with_proof(
            ConnectionTechnique::DirectIpv4,
            true,
            50,
            None,
            Some(proof),
        );

        assert!(matrix.ipv4_direct_success);
        assert!(matrix.has_data_proof());
        assert_eq!(matrix.success_level, SuccessLevel::Usable);
        assert!(matrix.is_passing());
    }

    #[test]
    fn test_connectivity_matrix_without_data_proof() {
        let mut matrix = ConnectivityMatrix::new();

        // Record successful connection WITHOUT data proof
        matrix.record_attempt_with_proof(ConnectionTechnique::DirectIpv4, true, 50, None, None);

        assert!(matrix.ipv4_direct_success);
        assert!(!matrix.has_data_proof());
        assert_eq!(matrix.success_level, SuccessLevel::Established);
        assert!(!matrix.is_passing()); // Must have data proof to pass
    }

    #[test]
    fn test_connectivity_matrix_calculate_success_level() {
        let mut matrix = ConnectivityMatrix::new();

        // No success = Failed
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Failed);

        // Connection success but no data proof = Established
        matrix.ipv4_direct_success = true;
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Established);

        // With bidirectional data proof = Usable
        matrix.data_proof = Some(DataProof::new(1024, 1024, "a".into(), "b".into(), true));
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Usable);

        // With invalid data proof (not verified) = Established
        matrix.data_proof = Some(DataProof::new(1024, 1024, "a".into(), "b".into(), false));
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Established);
    }

    #[test]
    fn test_technique_attempt_with_data_proof() {
        let proof = DataProof::new(512, 512, "x".into(), "y".into(), true);
        let attempt = TechniqueAttempt {
            technique: ConnectionTechnique::DirectIpv4,
            success: true,
            duration_ms: 25,
            error: None,
            timestamp_ms: 1234567890,
            data_proof: Some(proof),
            method_proof: None,
        };

        assert!(attempt.data_proof.is_some());
        assert!(attempt.data_proof.as_ref().unwrap().is_bidirectional());

        let json = serde_json::to_string(&attempt).expect("serialization should work");
        assert!(json.contains("data_proof"));
        let decoded: TechniqueAttempt =
            serde_json::from_str(&json).expect("deserialization should work");
        assert!(decoded.data_proof.is_some());
    }

    #[test]
    fn test_method_proof_direct() {
        let proof = MethodProof::direct("127.0.0.1:9000", "192.168.1.1:9000");
        assert_eq!(proof.claimed_method, Some(ConnectionMethod::Direct));
        assert!(proof.has_sufficient_evidence());
        assert_eq!(proof.confidence, 1.0);
        assert_eq!(proof.total_nat_frames(), 0);
    }

    #[test]
    fn test_method_proof_hole_punched() {
        let proof = MethodProof::hole_punched(
            "127.0.0.1:9000",
            "192.168.1.1:9000",
            Some("coordinator-peer-id"),
            4,
        );
        assert_eq!(proof.claimed_method, Some(ConnectionMethod::HolePunched));
        assert!(proof.coordinator_peer_id.is_some());
        assert!(proof.add_address_sent > 0 || proof.punch_me_now_sent > 0);
    }

    #[test]
    fn test_method_proof_relayed() {
        let proof = MethodProof::relayed("relay-peer-id", "10.0.0.1:9000");
        assert_eq!(proof.claimed_method, Some(ConnectionMethod::Relayed));
        assert!(proof.has_sufficient_evidence());
        assert_eq!(proof.relay_peer_id, Some("relay-peer-id".to_string()));
        assert_eq!(proof.confidence, 1.0);
    }

    #[test]
    fn test_method_proof_has_sufficient_evidence() {
        let mut proof = MethodProof::new();
        proof.claimed_method = Some(ConnectionMethod::Direct);
        assert!(proof.has_sufficient_evidence());

        proof.claimed_method = Some(ConnectionMethod::HolePunched);
        assert!(!proof.has_sufficient_evidence());

        proof.add_address_sent = 2;
        assert!(proof.has_sufficient_evidence());

        proof.claimed_method = Some(ConnectionMethod::Relayed);
        assert!(!proof.has_sufficient_evidence());

        proof.relay_peer_id = Some("relay".to_string());
        assert!(proof.has_sufficient_evidence());
    }

    #[test]
    fn test_method_proof_calculate_confidence() {
        let mut proof = MethodProof::new();

        proof.claimed_method = Some(ConnectionMethod::Direct);
        assert_eq!(proof.calculate_confidence(), 1.0);

        proof.add_address_sent = 1;
        assert!(proof.calculate_confidence() < 1.0);

        proof.claimed_method = Some(ConnectionMethod::HolePunched);
        proof.add_address_sent = 2;
        proof.coordinator_peer_id = Some("coord".to_string());
        assert!(proof.calculate_confidence() >= 0.95);

        proof.claimed_method = Some(ConnectionMethod::Relayed);
        proof.relay_peer_id = Some("relay".to_string());
        proof.relay_addr = Some("10.0.0.1:9000".to_string());
        assert_eq!(proof.calculate_confidence(), 1.0);
    }

    #[test]
    fn test_method_proof_record_nat_frames() {
        let mut proof = MethodProof::new();
        assert_eq!(proof.total_nat_frames(), 0);
        assert!(!proof.has_nat_frame_evidence());

        proof.record_add_address_sent();
        assert_eq!(proof.total_nat_frames(), 1);
        assert!(proof.has_nat_frame_evidence());
        assert!(proof.first_nat_frame_ms.is_some());

        proof.record_punch_me_now_received();
        assert_eq!(proof.total_nat_frames(), 2);

        proof.record_observed_address("203.0.113.1:9000");
        assert_eq!(proof.total_nat_frames(), 3);
        assert_eq!(
            proof.observed_external_addr,
            Some("203.0.113.1:9000".to_string())
        );
    }

    #[test]
    fn test_method_proof_serialization() {
        let proof = MethodProof::direct("127.0.0.1:9000", "192.168.1.1:9000");
        let json = serde_json::to_string(&proof).expect("serialization should work");
        assert!(json.contains("direct"));
        assert!(json.contains("127.0.0.1:9000"));

        let decoded: MethodProof =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.claimed_method, Some(ConnectionMethod::Direct));
    }

    #[test]
    fn test_connectivity_matrix_with_method_proof() {
        let mut matrix = ConnectivityMatrix::new();
        matrix.ipv4_direct_success = true;
        matrix.data_proof = Some(DataProof::new(1024, 1024, "a".into(), "b".into(), true));

        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Usable);
        assert!(!matrix.has_method_proof());

        matrix.method_proof = Some(MethodProof::direct("127.0.0.1:9000", "192.168.1.1:9000"));

        assert!(matrix.has_method_proof());
        assert_eq!(
            matrix.calculate_success_level(),
            SuccessLevel::CorrectMethod
        );
    }

    #[test]
    fn test_connectivity_matrix_success_level_with_method_proof() {
        let mut matrix = ConnectivityMatrix::new();

        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Failed);

        matrix.nat_traversal_success = true;
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Established);

        matrix.data_proof = Some(DataProof::new(1024, 1024, "a".into(), "b".into(), true));
        assert_eq!(matrix.calculate_success_level(), SuccessLevel::Usable);

        let mut method_proof = MethodProof::new();
        method_proof.claimed_method = Some(ConnectionMethod::HolePunched);
        method_proof.add_address_sent = 2;
        method_proof.punch_me_now_sent = 1;
        matrix.method_proof = Some(method_proof);

        assert_eq!(
            matrix.calculate_success_level(),
            SuccessLevel::CorrectMethod
        );
    }

    #[test]
    fn test_test_pattern_display() {
        assert_eq!(TestPattern::Outbound.to_string(), "A→B");
        assert_eq!(TestPattern::Inbound.to_string(), "B→A");
        assert_eq!(TestPattern::Simultaneous.to_string(), "A↔B");
        assert_eq!(TestPattern::InboundUnderLoad.to_string(), "B→A (load)");
    }

    #[test]
    fn test_test_pattern_requires_coordination() {
        assert!(!TestPattern::Outbound.requires_coordination());
        assert!(!TestPattern::Inbound.requires_coordination());
        assert!(TestPattern::Simultaneous.requires_coordination());
        assert!(!TestPattern::InboundUnderLoad.requires_coordination());
    }

    #[test]
    fn test_test_pattern_serialization() {
        let pattern = TestPattern::Simultaneous;
        let json = serde_json::to_string(&pattern).expect("serialization should work");
        assert!(json.contains("simultaneous"));

        let decoded: TestPattern =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded, TestPattern::Simultaneous);
    }

    #[test]
    fn test_network_profile_ideal() {
        let profile = NetworkProfile::ideal();
        assert_eq!(profile.mtu, 1500);
        assert_eq!(profile.latency_ms, 0);
        assert_eq!(profile.loss_percent, 0.0);
        assert!(!profile.is_impaired());
        assert_eq!(profile.severity_score(), 0.0);
    }

    #[test]
    fn test_network_profile_low_mtu() {
        let profile = NetworkProfile::low_mtu();
        assert_eq!(profile.mtu, 1200);
        assert!(profile.is_impaired());
        assert!(profile.severity_score() > 0.0);
    }

    #[test]
    fn test_network_profile_high_latency() {
        let profile = NetworkProfile::high_latency();
        assert_eq!(profile.latency_ms, 200);
        assert!(profile.is_impaired());
    }

    #[test]
    fn test_network_profile_lossy() {
        let profile = NetworkProfile::lossy();
        assert_eq!(profile.loss_percent, 3.0);
        assert!(profile.is_impaired());
    }

    #[test]
    fn test_network_profile_mobile() {
        let profile = NetworkProfile::mobile();
        assert!(profile.bandwidth_kbps.is_some());
        assert!(profile.is_impaired());
    }

    #[test]
    fn test_network_profile_stressed() {
        let profile = NetworkProfile::stressed();
        assert!(profile.is_impaired());
        assert!(profile.severity_score() > 0.5);
    }

    #[test]
    fn test_network_profile_serialization() {
        let profile = NetworkProfile::mobile();
        let json = serde_json::to_string(&profile).expect("serialization should work");
        assert!(json.contains("mobile"));
        assert!(json.contains("bandwidth_kbps"));

        let decoded: NetworkProfile =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.name, "mobile");
    }

    #[test]
    fn test_impairment_metrics_new() {
        let metrics = ImpairmentMetrics::new();
        assert_eq!(metrics.handshake_bytes, 0);
        assert_eq!(metrics.retransmissions, 0);
        assert!(!metrics.has_issues());
    }

    #[test]
    fn test_impairment_metrics_record() {
        let mut metrics = ImpairmentMetrics::new();
        metrics.record_handshake(5000, 4, 150);
        assert_eq!(metrics.handshake_bytes, 5000);
        assert_eq!(metrics.handshake_messages, 4);
        assert_eq!(metrics.handshake_duration_ms, 150);

        metrics.record_pmtu_probe();
        assert_eq!(metrics.pmtu_probes_sent, 1);

        metrics.record_blackhole();
        assert!(metrics.has_issues());
    }

    #[test]
    fn test_impairment_metrics_has_issues() {
        let mut metrics = ImpairmentMetrics::new();
        assert!(!metrics.has_issues());

        metrics.pto_events = 4;
        assert!(metrics.has_issues());

        metrics.pto_events = 0;
        metrics.retransmissions = 15;
        assert!(metrics.has_issues());
    }

    #[test]
    fn test_impairment_metrics_serialization() {
        let mut metrics = ImpairmentMetrics::new();
        metrics.record_handshake(3000, 3, 100);
        let json = serde_json::to_string(&metrics).expect("serialization should work");
        assert!(json.contains("3000"));

        let decoded: ImpairmentMetrics =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.handshake_bytes, 3000);
    }

    #[test]
    fn test_connectivity_matrix_is_fully_passing() {
        let mut matrix = ConnectivityMatrix::new();
        assert!(!matrix.is_fully_passing());

        matrix.ipv4_direct_success = true;
        matrix.success_level = SuccessLevel::Usable;
        assert!(!matrix.is_fully_passing());

        matrix.method_proof = Some(MethodProof::direct("127.0.0.1:9000", "192.168.1.1:9000"));
        assert!(matrix.is_fully_passing());
    }

    #[test]
    fn test_connectivity_matrix_passes_for_pattern() {
        let mut matrix = ConnectivityMatrix::new();
        matrix.ipv4_direct_success = true;
        matrix.success_level = SuccessLevel::Usable;
        matrix.test_pattern = TestPattern::Outbound;

        assert!(matrix.passes_for_pattern(TestPattern::Outbound));
        assert!(!matrix.passes_for_pattern(TestPattern::Inbound));
    }

    #[test]
    fn test_connectivity_matrix_passes_under_impairment() {
        let mut matrix = ConnectivityMatrix::new();
        matrix.ipv4_direct_success = true;
        matrix.success_level = SuccessLevel::Usable;

        assert!(!matrix.passes_under_impairment());

        matrix.network_profile = Some(NetworkProfile::stressed());
        assert!(matrix.passes_under_impairment());
    }

    #[test]
    fn test_connectivity_matrix_set_test_pattern() {
        let mut matrix = ConnectivityMatrix::new();
        assert_eq!(matrix.test_pattern, TestPattern::Outbound);

        matrix.set_test_pattern(TestPattern::Simultaneous);
        assert_eq!(matrix.test_pattern, TestPattern::Simultaneous);
    }

    #[test]
    fn test_connectivity_matrix_set_network_profile() {
        let mut matrix = ConnectivityMatrix::new();
        assert!(matrix.network_profile.is_none());

        matrix.set_network_profile(NetworkProfile::mobile());
        assert!(matrix.network_profile.is_some());
        assert_eq!(matrix.network_profile.as_ref().unwrap().name, "mobile");
    }

    #[test]
    fn test_connectivity_matrix_record_impairment_metrics() {
        let mut matrix = ConnectivityMatrix::new();
        assert!(matrix.impairment_metrics.is_none());

        let mut metrics = ImpairmentMetrics::new();
        metrics.record_handshake(4000, 4, 200);
        matrix.record_impairment_metrics(metrics);

        assert!(matrix.impairment_metrics.is_some());
        assert_eq!(
            matrix.impairment_metrics.as_ref().unwrap().handshake_bytes,
            4000
        );
    }

    #[test]
    fn test_temporal_scenario_display() {
        assert_eq!(TemporalScenario::ColdStart.to_string(), "Cold Start");
        assert_eq!(
            TemporalScenario::WarmReconnect.to_string(),
            "Warm Reconnect"
        );
        assert_eq!(
            TemporalScenario::NatBindingExpiry.to_string(),
            "NAT Binding Expiry"
        );
        assert_eq!(
            TemporalScenario::RepeatedChurn.to_string(),
            "Repeated Churn"
        );
    }

    #[test]
    fn test_temporal_metrics_new() {
        let metrics = TemporalMetrics::new(TemporalScenario::ColdStart);
        assert_eq!(metrics.scenario, TemporalScenario::ColdStart);
        assert_eq!(metrics.idle_duration_ms, 0);
        assert!(!metrics.binding_expired);
    }

    #[test]
    fn test_temporal_metrics_record_idle() {
        let mut metrics = TemporalMetrics::new(TemporalScenario::NatBindingExpiry);
        metrics.record_idle(60000);
        assert_eq!(metrics.idle_duration_ms, 60000);
    }

    #[test]
    fn test_temporal_metrics_keepalive() {
        let mut metrics = TemporalMetrics::new(TemporalScenario::NatBindingExpiry);
        metrics.record_keepalive_sent();
        metrics.record_keepalive_sent();
        metrics.record_keepalive_received();

        assert_eq!(metrics.keepalive_sent, 2);
        assert_eq!(metrics.keepalive_received, 1);
        assert!(metrics.keepalive_effective());

        metrics.record_binding_expired();
        assert!(!metrics.keepalive_effective());
    }

    #[test]
    fn test_temporal_metrics_reconnect() {
        let mut metrics = TemporalMetrics::new(TemporalScenario::NatBindingExpiry);
        metrics.record_reconnect(3000, true);

        assert!(metrics.reconnect_required);
        assert_eq!(metrics.reconnect_time_ms, Some(3000));
        assert!(metrics.re_hole_punch_required);
        assert!(metrics.is_level5_passing());
    }

    #[test]
    fn test_temporal_metrics_churn() {
        let mut metrics = TemporalMetrics::new(TemporalScenario::RepeatedChurn);
        metrics.record_churn_cycle(true);
        metrics.record_churn_cycle(true);
        metrics.record_churn_cycle(false);

        assert_eq!(metrics.churn_cycles_completed, 2);
        assert_eq!(metrics.churn_cycles_failed, 1);
        assert!((metrics.churn_success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_temporal_metrics_is_level5_passing() {
        let mut metrics = TemporalMetrics::new(TemporalScenario::ColdStart);
        assert!(!metrics.is_level5_passing());

        metrics.mark_survived();
        assert!(metrics.is_level5_passing());
    }

    #[test]
    fn test_temporal_metrics_serialization() {
        let metrics = TemporalMetrics::new(TemporalScenario::WarmReconnect);
        let json = serde_json::to_string(&metrics).expect("serialization should work");
        assert!(json.contains("warm_reconnect"));

        let decoded: TemporalMetrics =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.scenario, TemporalScenario::WarmReconnect);
    }

    #[test]
    fn test_migration_metrics_new() {
        let metrics = MigrationMetrics::new();
        assert_eq!(metrics.migrations_attempted, 0);
        assert_eq!(metrics.migrations_succeeded, 0);
        assert!(metrics.path_history.is_empty());
    }

    #[test]
    fn test_migration_metrics_record() {
        let mut metrics = MigrationMetrics::new();
        metrics.record_migration_attempt();
        metrics.record_migration_success();
        metrics.record_path_challenge();
        metrics.record_path_response();

        assert_eq!(metrics.migrations_attempted, 1);
        assert_eq!(metrics.migrations_succeeded, 1);
        assert_eq!(metrics.migration_success_rate(), 1.0);
        assert_eq!(metrics.path_validation_rate(), 1.0);
    }

    #[test]
    fn test_migration_metrics_path_change() {
        let mut metrics = MigrationMetrics::new();
        metrics.record_path_change("192.168.1.1:9000", "10.0.0.1:9000");
        metrics.record_path_change("192.168.1.1:9001", "10.0.0.1:9000");

        assert_eq!(metrics.path_history.len(), 2);
        assert_eq!(metrics.path_history[0].local_addr, "192.168.1.1:9000");
    }

    #[test]
    fn test_migration_metrics_success_rate() {
        let mut metrics = MigrationMetrics::new();
        metrics.record_migration_attempt();
        metrics.record_migration_attempt();
        metrics.record_migration_success();

        assert_eq!(metrics.migration_success_rate(), 0.5);
    }

    #[test]
    fn test_migration_metrics_serialization() {
        let mut metrics = MigrationMetrics::new();
        metrics.record_migration_attempt();
        metrics.mark_data_continued();
        let json = serde_json::to_string(&metrics).expect("serialization should work");
        assert!(json.contains("data_continued_after_migration"));

        let decoded: MigrationMetrics =
            serde_json::from_str(&json).expect("deserialization should work");
        assert!(decoded.data_continued_after_migration);
    }

    #[test]
    fn test_failure_reason_code_display() {
        assert_eq!(FailureReasonCode::Success.to_string(), "Success");
        assert_eq!(FailureReasonCode::Timeout.to_string(), "Connection timeout");
        assert_eq!(
            FailureReasonCode::PmtuBlackhole.to_string(),
            "PMTU blackhole detected"
        );
    }

    #[test]
    fn test_failure_reason_code_is_success() {
        assert!(FailureReasonCode::Success.is_success());
        assert!(!FailureReasonCode::Timeout.is_success());
    }

    #[test]
    fn test_failure_reason_code_is_recoverable() {
        assert!(FailureReasonCode::Timeout.is_recoverable());
        assert!(FailureReasonCode::NatBindingExpired.is_recoverable());
        assert!(!FailureReasonCode::HandshakeFailed.is_recoverable());
        assert!(!FailureReasonCode::CryptoError.is_recoverable());
    }

    #[test]
    fn test_failure_reason_code_is_configuration_issue() {
        assert!(FailureReasonCode::AddressUnreachable.is_configuration_issue());
        assert!(FailureReasonCode::NoRouteToHost.is_configuration_issue());
        assert!(!FailureReasonCode::Timeout.is_configuration_issue());
    }

    #[test]
    fn test_failure_reason_code_serialization() {
        let code = FailureReasonCode::PqcNegotiationFailed;
        let json = serde_json::to_string(&code).expect("serialization should work");
        assert!(json.contains("pqc_negotiation_failed"));

        let decoded: FailureReasonCode =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded, FailureReasonCode::PqcNegotiationFailed);
    }

    #[test]
    fn test_test_report_new() {
        let report = TestReport::new("run-123");
        assert_eq!(report.run_id, "run-123");
        assert_eq!(report.total_pairs, 0);
        assert!(report.timestamp_ms > 0);
    }

    #[test]
    fn test_test_report_record_pair_result() {
        let mut report = TestReport::new("test-run");
        report.record_pair_result(true, None);
        report.record_pair_result(true, None);
        report.record_pair_result(false, Some(FailureReasonCode::Timeout));

        assert_eq!(report.total_pairs, 3);
        assert_eq!(report.pairs_passed, 2);
        assert_eq!(report.pairs_failed, 1);
        assert!((report.pass_rate - 0.666).abs() < 0.01);
        assert_eq!(
            report.failure_breakdown.get(&FailureReasonCode::Timeout),
            Some(&1)
        );
    }

    #[test]
    fn test_test_report_top_failures() {
        let mut report = TestReport::new("test-run");
        report.record_pair_result(false, Some(FailureReasonCode::Timeout));
        report.record_pair_result(false, Some(FailureReasonCode::Timeout));
        report.record_pair_result(false, Some(FailureReasonCode::HandshakeFailed));

        let top = report.top_failures(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, FailureReasonCode::Timeout);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_test_report_human_summary() {
        let mut report = TestReport::new("test-run");
        report.record_pair_result(true, None);
        report.record_pair_result(true, None);
        report.set_latencies(50, 150, 300);
        report.finalize(5000);

        let summary = report.human_summary();
        assert!(summary.contains("PASS"));
        assert!(summary.contains("2/2"));
        assert!(summary.contains("100.0%"));
        assert!(summary.contains("p50=50ms"));
    }

    #[test]
    fn test_test_report_serialization() {
        let mut report = TestReport::new("test-run");
        report.set_git_sha("abc123");
        report.set_topology("2-node");
        let json = serde_json::to_string(&report).expect("serialization should work");
        assert!(json.contains("test-run"));
        assert!(json.contains("abc123"));

        let decoded: TestReport = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.run_id, "test-run");
        assert_eq!(decoded.git_sha, Some("abc123".to_string()));
    }

    #[test]
    fn test_nat_scenario_display() {
        assert_eq!(NatScenario::BothPublic.to_string(), "Both Public");
        assert_eq!(NatScenario::DoubleNat.to_string(), "Double NAT");
        assert_eq!(NatScenario::Cgnat.to_string(), "CGNAT");
    }

    #[test]
    fn test_nat_scenario_is_ci_fast() {
        assert!(NatScenario::BothPublic.is_ci_fast());
        assert!(NatScenario::SingleNatBoth.is_ci_fast());
        assert!(!NatScenario::DoubleNat.is_ci_fast());
        assert!(!NatScenario::Hairpin.is_ci_fast());
    }

    #[test]
    fn test_nat_scenario_requires_relay() {
        assert!(!NatScenario::BothPublic.requires_relay());
        assert!(NatScenario::SymmetricBoth.requires_relay());
        assert!(NatScenario::DoubleNat.requires_relay());
    }

    #[test]
    fn test_nat_scenario_difficulty() {
        assert!(
            NatScenario::BothPublic.expected_difficulty()
                < NatScenario::Cgnat.expected_difficulty()
        );
        assert!(
            NatScenario::Cgnat.expected_difficulty()
                < NatScenario::SymmetricBoth.expected_difficulty()
        );
    }

    #[test]
    fn test_nat_scenario_serialization() {
        let scenario = NatScenario::MobileCarrier;
        let json = serde_json::to_string(&scenario).expect("serialization should work");
        assert!(json.contains("mobile_carrier"));

        let decoded: NatScenario =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded, NatScenario::MobileCarrier);
    }

    #[test]
    fn test_relay_metrics_new() {
        let metrics = RelayMetrics::new();
        assert!(!metrics.relay_required);
        assert!(!metrics.relay_success);
        assert!(metrics.fallback_sequence.is_empty());
    }

    #[test]
    fn test_relay_metrics_fallback_sequence() {
        let mut metrics = RelayMetrics::new();
        metrics.record_direct_failed();
        metrics.record_hole_punch_failed();
        metrics.record_relay_attempt("relay-peer", "10.0.0.1:9000");

        assert!(metrics.direct_failed);
        assert!(metrics.hole_punch_failed);
        assert!(metrics.relay_required);
        assert_eq!(metrics.fallback_depth(), 3);
    }

    #[test]
    fn test_relay_metrics_is_relay_proven() {
        let mut metrics = RelayMetrics::new();
        assert!(!metrics.is_relay_proven());

        metrics.record_relay_attempt("relay-peer", "10.0.0.1:9000");
        metrics.record_relay_success(1, 50);

        assert!(metrics.is_relay_proven());
    }

    #[test]
    fn test_relay_metrics_serialization() {
        let mut metrics = RelayMetrics::new();
        metrics.record_relay_attempt("relay-peer", "10.0.0.1:9000");
        let json = serde_json::to_string(&metrics).expect("serialization should work");
        assert!(json.contains("relay-peer"));

        let decoded: RelayMetrics =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.relay_peer_id, Some("relay-peer".to_string()));
    }

    #[test]
    fn test_test_suite_display() {
        assert_eq!(TestSuite::CiFast.to_string(), "CI-Fast (~5min)");
        assert_eq!(TestSuite::NightlyDeep.to_string(), "Nightly-Deep (~30min)");
        assert_eq!(TestSuite::Full.to_string(), "Full (~60min)");
    }

    #[test]
    fn test_test_suite_config_ci_fast() {
        let config = TestSuiteConfig::ci_fast();
        assert_eq!(config.suite, TestSuite::CiFast);
        assert!(!config.enable_relay_tests);
        assert!(!config.enable_migration_tests);
        assert_eq!(config.churn_cycles, 0);
        assert!(config.nat_scenarios.contains(&NatScenario::BothPublic));
    }

    #[test]
    fn test_test_suite_config_nightly_deep() {
        let config = TestSuiteConfig::nightly_deep();
        assert_eq!(config.suite, TestSuite::NightlyDeep);
        assert!(config.enable_relay_tests);
        assert!(config.enable_migration_tests);
        assert!(config.churn_cycles > 0);
        assert!(config.nat_scenarios.contains(&NatScenario::DoubleNat));
    }

    #[test]
    fn test_test_suite_config_full() {
        let config = TestSuiteConfig::full();
        assert_eq!(config.suite, TestSuite::Full);
        assert!(config.nat_scenarios.len() >= 10);
        assert!(config.network_profiles.len() >= 6);
    }

    #[test]
    fn test_test_suite_config_estimated_pairs() {
        let config = TestSuiteConfig::ci_fast();
        assert!(config.estimated_pairs() > 0);
        assert_eq!(
            config.estimated_pairs(),
            config.nat_scenarios.len() * config.test_patterns.len()
        );
    }

    #[test]
    fn test_test_suite_config_serialization() {
        let config = TestSuiteConfig::ci_fast();
        let json = serde_json::to_string(&config).expect("serialization should work");
        assert!(json.contains("ci_fast"));

        let decoded: TestSuiteConfig =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(decoded.suite, TestSuite::CiFast);
    }
}
