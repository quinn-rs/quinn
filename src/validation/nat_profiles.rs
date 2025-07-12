//! Real-World NAT Profiles
//!
//! This module contains profiles of real NAT devices and their behaviors
//! based on empirical testing and field observations.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// NAT device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfiguration {
    /// NAT type classification
    pub nat_type: NatType,
    /// Detailed NAT behavior
    pub behavior: NatBehavior,
    /// Mapping timeout in milliseconds
    pub mapping_timeout_ms: u32,
    /// Whether port is preserved in mappings
    pub port_preservation: bool,
    /// Whether hairpinning is supported
    pub hairpinning_support: bool,
    /// Real device quirks and issues
    pub quirks: Vec<NatQuirk>,
    /// Known workarounds
    pub workarounds: Vec<Workaround>,
}

/// NAT type classifications
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// Full Cone NAT (1:1 NAT)
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestrictedCone,
    /// Symmetric NAT
    Symmetric,
    /// Carrier Grade NAT (CGN/LSN)
    CarrierGrade,
    /// Double NAT scenario
    DoubleNat,
    /// No NAT (direct connection)
    None,
}

/// Detailed NAT behavior characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatBehavior {
    /// Mapping behavior
    pub mapping: MappingBehavior,
    /// Filtering behavior
    pub filtering: FilteringBehavior,
    /// Port allocation strategy
    pub port_allocation: PortAllocationStrategy,
    /// Timeout behavior
    pub timeout_behavior: TimeoutBehavior,
    /// Protocol-specific behaviors
    pub protocol_behaviors: HashMap<String, ProtocolBehavior>,
}

/// Mapping behavior types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingBehavior {
    /// Endpoint-Independent Mapping
    EndpointIndependent,
    /// Address-Dependent Mapping
    AddressDependent,
    /// Address and Port-Dependent Mapping
    AddressPortDependent,
}

/// Filtering behavior types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilteringBehavior {
    /// Endpoint-Independent Filtering
    EndpointIndependent,
    /// Address-Dependent Filtering
    AddressDependent,
    /// Address and Port-Dependent Filtering
    AddressPortDependent,
}

/// Port allocation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortAllocationStrategy {
    /// Sequential port allocation
    Sequential { start_port: u16, increment: u16 },
    /// Random port allocation
    Random { min_port: u16, max_port: u16 },
    /// Port preservation (try to use same port)
    Preservation { fallback: Box<PortAllocationStrategy> },
    /// Port range based on time
    TimeBasedRange { ranges: Vec<(Duration, (u16, u16))> },
}

/// Timeout behavior characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutBehavior {
    /// UDP mapping timeout
    pub udp_timeout: Duration,
    /// TCP established timeout
    pub tcp_established_timeout: Duration,
    /// TCP transitory timeout
    pub tcp_transitory_timeout: Duration,
    /// ICMP timeout
    pub icmp_timeout: Duration,
    /// Timeout refresh on activity
    pub refresh_on_activity: bool,
    /// Aggressive timeout under load
    pub aggressive_timeout_threshold: Option<u32>,
}

/// Protocol-specific NAT behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolBehavior {
    /// Whether protocol is allowed
    pub allowed: bool,
    /// Special handling rules
    pub special_rules: Vec<SpecialRule>,
    /// ALG (Application Layer Gateway) behavior
    pub alg_behavior: Option<AlgBehavior>,
}

/// Special protocol handling rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpecialRule {
    /// Port range restrictions
    PortRestriction { blocked_ports: Vec<u16> },
    /// Rate limiting
    RateLimit { max_connections_per_second: u32 },
    /// Packet size restrictions
    PacketSizeLimit { max_size_bytes: u32 },
    /// Deep packet inspection
    DeepPacketInspection { patterns: Vec<String> },
}

/// Application Layer Gateway behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgBehavior {
    /// ALG type (SIP, FTP, etc.)
    pub alg_type: String,
    /// Whether ALG can be disabled
    pub can_disable: bool,
    /// Known issues with ALG
    pub known_issues: Vec<String>,
}

/// Known NAT quirks and issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatQuirk {
    /// Drops packets with certain characteristics
    PacketDrop {
        condition: String,
        probability: f32,
    },
    /// Incorrect checksum calculation
    ChecksumError {
        affects_protocols: Vec<String>,
    },
    /// Fragment handling issues
    FragmentationIssue {
        description: String,
    },
    /// Timing-related quirks
    TimingQuirk {
        description: String,
        impact: String,
    },
    /// State table limitations
    StateTableLimit {
        max_entries: u32,
        behavior_at_limit: String,
    },
    /// Asymmetric behavior
    AsymmetricBehavior {
        inbound_different: bool,
        description: String,
    },
}

/// Known workarounds for NAT issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workaround {
    /// Quirk this addresses
    pub addresses_quirk: String,
    /// Workaround description
    pub description: String,
    /// Implementation steps
    pub implementation: Vec<String>,
    /// Success rate (0.0-1.0)
    pub success_rate: f32,
}

/// Collection of real-world NAT profiles
pub struct RealWorldNatProfiles;

impl RealWorldNatProfiles {
    /// Get common home router profiles
    pub fn home_routers() -> Vec<RouterProfile> {
        vec![
            RouterProfile {
                manufacturer: "Netgear".to_string(),
                model: "Nighthawk R7000".to_string(),
                firmware_version: "V1.0.11.123".to_string(),
                nat_config: NatConfiguration {
                    nat_type: NatType::PortRestrictedCone,
                    behavior: NatBehavior {
                        mapping: MappingBehavior::EndpointIndependent,
                        filtering: FilteringBehavior::AddressPortDependent,
                        port_allocation: PortAllocationStrategy::Preservation {
                            fallback: Box::new(PortAllocationStrategy::Random {
                                min_port: 1024,
                                max_port: 65535,
                            }),
                        },
                        timeout_behavior: TimeoutBehavior {
                            udp_timeout: Duration::from_secs(180),
                            tcp_established_timeout: Duration::from_secs(7440),
                            tcp_transitory_timeout: Duration::from_secs(300),
                            icmp_timeout: Duration::from_secs(60),
                            refresh_on_activity: true,
                            aggressive_timeout_threshold: Some(1000),
                        },
                        protocol_behaviors: HashMap::new(),
                    },
                    mapping_timeout_ms: 180000,
                    port_preservation: true,
                    hairpinning_support: true,
                    quirks: vec![],
                    workarounds: vec![],
                },
                known_issues: vec![],
            },
            RouterProfile {
                manufacturer: "TP-Link".to_string(),
                model: "Archer AX50".to_string(),
                firmware_version: "1.0.11".to_string(),
                nat_config: NatConfiguration {
                    nat_type: NatType::RestrictedCone,
                    behavior: NatBehavior {
                        mapping: MappingBehavior::EndpointIndependent,
                        filtering: FilteringBehavior::AddressDependent,
                        port_allocation: PortAllocationStrategy::Sequential {
                            start_port: 1024,
                            increment: 1,
                        },
                        timeout_behavior: TimeoutBehavior {
                            udp_timeout: Duration::from_secs(300),
                            tcp_established_timeout: Duration::from_secs(7440),
                            tcp_transitory_timeout: Duration::from_secs(240),
                            icmp_timeout: Duration::from_secs(30),
                            refresh_on_activity: true,
                            aggressive_timeout_threshold: None,
                        },
                        protocol_behaviors: HashMap::new(),
                    },
                    mapping_timeout_ms: 300000,
                    port_preservation: false,
                    hairpinning_support: false,
                    quirks: vec![
                        NatQuirk::StateTableLimit {
                            max_entries: 2048,
                            behavior_at_limit: "Drops new connections".to_string(),
                        },
                    ],
                    workarounds: vec![
                        Workaround {
                            addresses_quirk: "No hairpinning support".to_string(),
                            description: "Use external STUN server for local connections".to_string(),
                            implementation: vec![
                                "Detect local network".to_string(),
                                "Use STUN for address discovery".to_string(),
                                "Route through external relay if needed".to_string(),
                            ],
                            success_rate: 0.95,
                        },
                    ],
                },
                known_issues: vec![
                    KnownIssue {
                        description: "No hairpinning support".to_string(),
                        severity: Severity::Medium,
                        affects_versions: vec!["1.0.11".to_string()],
                        workaround_available: true,
                    },
                ],
            },
        ]
    }

    /// Get enterprise firewall profiles
    pub fn enterprise_firewalls() -> Vec<FirewallProfile> {
        vec![
            FirewallProfile {
                vendor: "Cisco".to_string(),
                model: "ASA 5506-X".to_string(),
                software_version: "9.14(3)".to_string(),
                nat_config: NatConfiguration {
                    nat_type: NatType::Symmetric,
                    behavior: NatBehavior {
                        mapping: MappingBehavior::AddressPortDependent,
                        filtering: FilteringBehavior::AddressPortDependent,
                        port_allocation: PortAllocationStrategy::Random {
                            min_port: 1024,
                            max_port: 65535,
                        },
                        timeout_behavior: TimeoutBehavior {
                            udp_timeout: Duration::from_secs(120),
                            tcp_established_timeout: Duration::from_secs(3600),
                            tcp_transitory_timeout: Duration::from_secs(120),
                            icmp_timeout: Duration::from_secs(2),
                            refresh_on_activity: false,
                            aggressive_timeout_threshold: Some(500),
                        },
                        protocol_behaviors: HashMap::new(),
                    },
                    mapping_timeout_ms: 120000,
                    port_preservation: false,
                    hairpinning_support: false,
                    quirks: vec![
                        NatQuirk::AsymmetricBehavior {
                            inbound_different: true,
                            description: "Different NAT behavior for inbound vs outbound".to_string(),
                        },
                    ],
                    workarounds: vec![],
                },
                security_features: SecurityFeatures {
                    deep_packet_inspection: true,
                    intrusion_prevention: true,
                    application_control: true,
                    ssl_inspection: false,
                },
                policy_restrictions: vec![
                    PolicyRestriction {
                        name: "Block P2P".to_string(),
                        blocked_ports: vec![6881, 6889],
                        blocked_protocols: vec!["BitTorrent".to_string()],
                    },
                ],
            },
        ]
    }

    /// Get mobile carrier NAT profiles
    pub fn carrier_grade_nats() -> Vec<CgNatProfile> {
        vec![
            CgNatProfile {
                carrier: "Verizon".to_string(),
                region: "US".to_string(),
                technology: "4G LTE".to_string(),
                nat_config: NatConfiguration {
                    nat_type: NatType::CarrierGrade,
                    behavior: NatBehavior {
                        mapping: MappingBehavior::AddressPortDependent,
                        filtering: FilteringBehavior::AddressPortDependent,
                        port_allocation: PortAllocationStrategy::Random {
                            min_port: 1024,
                            max_port: 65535,
                        },
                        timeout_behavior: TimeoutBehavior {
                            udp_timeout: Duration::from_secs(30),
                            tcp_established_timeout: Duration::from_secs(600),
                            tcp_transitory_timeout: Duration::from_secs(60),
                            icmp_timeout: Duration::from_secs(2),
                            refresh_on_activity: false,
                            aggressive_timeout_threshold: Some(100),
                        },
                        protocol_behaviors: HashMap::new(),
                    },
                    mapping_timeout_ms: 30000,
                    port_preservation: false,
                    hairpinning_support: false,
                    quirks: vec![
                        NatQuirk::StateTableLimit {
                            max_entries: 100,
                            behavior_at_limit: "Evicts oldest entries".to_string(),
                        },
                        NatQuirk::TimingQuirk {
                            description: "Very short UDP timeout".to_string(),
                            impact: "Requires frequent keepalives".to_string(),
                        },
                    ],
                    workarounds: vec![
                        Workaround {
                            addresses_quirk: "Short UDP timeout".to_string(),
                            description: "Send keepalives every 20 seconds".to_string(),
                            implementation: vec![
                                "Set keepalive interval to 20s".to_string(),
                                "Use small keepalive packets".to_string(),
                                "Monitor for timeout changes".to_string(),
                            ],
                            success_rate: 0.98,
                        },
                    ],
                },
                multi_layer_nat: true,
                ipv6_support: true,
                typical_latency_ms: 40,
            },
        ]
    }

    /// Get public WiFi NAT profiles
    pub fn public_wifi_profiles() -> Vec<PublicWiFiProfile> {
        vec![
            PublicWiFiProfile {
                venue_type: "Coffee Shop".to_string(),
                typical_equipment: "Consumer Router".to_string(),
                nat_config: NatConfiguration {
                    nat_type: NatType::PortRestrictedCone,
                    behavior: NatBehavior {
                        mapping: MappingBehavior::EndpointIndependent,
                        filtering: FilteringBehavior::AddressPortDependent,
                        port_allocation: PortAllocationStrategy::Sequential {
                            start_port: 1024,
                            increment: 1,
                        },
                        timeout_behavior: TimeoutBehavior {
                            udp_timeout: Duration::from_secs(60),
                            tcp_established_timeout: Duration::from_secs(3600),
                            tcp_transitory_timeout: Duration::from_secs(180),
                            icmp_timeout: Duration::from_secs(30),
                            refresh_on_activity: true,
                            aggressive_timeout_threshold: Some(50),
                        },
                        protocol_behaviors: HashMap::new(),
                    },
                    mapping_timeout_ms: 60000,
                    port_preservation: false,
                    hairpinning_support: true,
                    quirks: vec![
                        NatQuirk::StateTableLimit {
                            max_entries: 512,
                            behavior_at_limit: "Rejects new connections".to_string(),
                        },
                    ],
                    workarounds: vec![],
                },
                captive_portal: true,
                session_timeout: Some(Duration::from_secs(3600)),
                bandwidth_per_client_mbps: Some(5),
            },
        ]
    }
}

/// Router profile with manufacturer details
#[derive(Debug, Clone)]
pub struct RouterProfile {
    /// Manufacturer name
    pub manufacturer: String,
    /// Model number
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
    /// NAT configuration
    pub nat_config: NatConfiguration,
    /// Known issues
    pub known_issues: Vec<KnownIssue>,
}

/// Known issue with severity
#[derive(Debug, Clone)]
pub struct KnownIssue {
    /// Issue description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Affected firmware versions
    pub affects_versions: Vec<String>,
    /// Whether workaround is available
    pub workaround_available: bool,
}

/// Issue severity levels
#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Enterprise firewall profile
#[derive(Debug, Clone)]
pub struct FirewallProfile {
    /// Vendor name
    pub vendor: String,
    /// Model
    pub model: String,
    /// Software version
    pub software_version: String,
    /// NAT configuration
    pub nat_config: NatConfiguration,
    /// Security features
    pub security_features: SecurityFeatures,
    /// Policy restrictions
    pub policy_restrictions: Vec<PolicyRestriction>,
}

/// Security features
#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    /// Deep packet inspection enabled
    pub deep_packet_inspection: bool,
    /// Intrusion prevention enabled
    pub intrusion_prevention: bool,
    /// Application control enabled
    pub application_control: bool,
    /// SSL inspection enabled
    pub ssl_inspection: bool,
}

/// Policy restriction
#[derive(Debug, Clone)]
pub struct PolicyRestriction {
    /// Policy name
    pub name: String,
    /// Blocked ports
    pub blocked_ports: Vec<u16>,
    /// Blocked protocols
    pub blocked_protocols: Vec<String>,
}

/// Carrier-grade NAT profile
#[derive(Debug, Clone)]
pub struct CgNatProfile {
    /// Carrier name
    pub carrier: String,
    /// Region
    pub region: String,
    /// Network technology (3G, 4G, 5G)
    pub technology: String,
    /// NAT configuration
    pub nat_config: NatConfiguration,
    /// Whether multi-layer NAT is used
    pub multi_layer_nat: bool,
    /// IPv6 support
    pub ipv6_support: bool,
    /// Typical latency in ms
    pub typical_latency_ms: u32,
}

/// Public WiFi profile
#[derive(Debug, Clone)]
pub struct PublicWiFiProfile {
    /// Venue type
    pub venue_type: String,
    /// Typical equipment used
    pub typical_equipment: String,
    /// NAT configuration
    pub nat_config: NatConfiguration,
    /// Whether captive portal is used
    pub captive_portal: bool,
    /// Session timeout
    pub session_timeout: Option<Duration>,
    /// Bandwidth limit per client
    pub bandwidth_per_client_mbps: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_profiles_loading() {
        let home_routers = RealWorldNatProfiles::home_routers();
        assert!(!home_routers.is_empty());
        
        let firewalls = RealWorldNatProfiles::enterprise_firewalls();
        assert!(!firewalls.is_empty());
        
        let carrier_nats = RealWorldNatProfiles::carrier_grade_nats();
        assert!(!carrier_nats.is_empty());
        
        let public_wifi = RealWorldNatProfiles::public_wifi_profiles();
        assert!(!public_wifi.is_empty());
    }

    #[test]
    fn test_timeout_behavior() {
        let timeout = TimeoutBehavior {
            udp_timeout: Duration::from_secs(180),
            tcp_established_timeout: Duration::from_secs(7440),
            tcp_transitory_timeout: Duration::from_secs(300),
            icmp_timeout: Duration::from_secs(60),
            refresh_on_activity: true,
            aggressive_timeout_threshold: Some(1000),
        };
        
        assert_eq!(timeout.udp_timeout.as_secs(), 180);
        assert!(timeout.refresh_on_activity);
    }
}