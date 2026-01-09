use crate::registry::{
    ConnectionMethod, ConnectionTechnique, FilteringBehavior, MappingBehavior, NatBehavior,
    NatScenario, NatType, NetworkProfile, TemporalScenario, TestPattern, TestSuite,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use humantime_serde;

use super::IpMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSpec {
    pub id: String,
    pub name: String,
    pub description: String,
    pub suite: TestSuite,
    pub topology: TopologySpec,
    pub nat_profiles: Vec<NatProfileSpec>,
    pub test_matrix: TestMatrixSpec,
    pub thresholds: ThresholdSpec,
    pub timing: TimingSpec,
    pub artifacts: ArtifactSpec,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl ScenarioSpec {
    pub fn connectivity_matrix() -> Self {
        Self {
            id: "connectivity_matrix".to_string(),
            name: "NAT Connectivity Matrix".to_string(),
            description: "Full 225-combination NAT type matrix test".to_string(),
            suite: TestSuite::Full,
            topology: TopologySpec::mesh(4),
            nat_profiles: NatProfileSpec::all_standard(),
            test_matrix: TestMatrixSpec::full_matrix(),
            thresholds: ThresholdSpec::production(),
            timing: TimingSpec::default(),
            artifacts: ArtifactSpec::default(),
            seed: None,
            metadata: HashMap::new(),
        }
    }

    pub fn ci_fast() -> Self {
        Self {
            id: "ci_fast".to_string(),
            name: "CI Fast Check".to_string(),
            description: "Quick connectivity validation for CI".to_string(),
            suite: TestSuite::CiFast,
            topology: TopologySpec::pair(),
            nat_profiles: NatProfileSpec::ci_subset(),
            test_matrix: TestMatrixSpec::ci_fast(),
            thresholds: ThresholdSpec::ci(),
            timing: TimingSpec::ci_fast(),
            artifacts: ArtifactSpec::minimal(),
            seed: None,
            metadata: HashMap::new(),
        }
    }

    pub fn gossip_coverage() -> Self {
        Self {
            id: "gossip_coverage".to_string(),
            name: "Gossip Crate Coverage".to_string(),
            description: "Full coverage of all saorsa-gossip crates".to_string(),
            suite: TestSuite::NightlyDeep,
            topology: TopologySpec::mesh(8),
            nat_profiles: NatProfileSpec::all_standard(),
            test_matrix: TestMatrixSpec::gossip_focused(),
            thresholds: ThresholdSpec::gossip(),
            timing: TimingSpec::default(),
            artifacts: ArtifactSpec::default(),
            seed: None,
            metadata: HashMap::new(),
        }
    }

    pub fn oracle_suite() -> Self {
        Self {
            id: "oracle_suite".to_string(),
            name: "Oracle Validation Suite".to_string(),
            description: "Known-good and known-bad scenarios for harness validation".to_string(),
            suite: TestSuite::CiFast,
            topology: TopologySpec::pair(),
            nat_profiles: vec![NatProfileSpec::none(), NatProfileSpec::full_cone()],
            test_matrix: TestMatrixSpec::oracle(),
            thresholds: ThresholdSpec::oracle(),
            timing: TimingSpec::oracle(),
            artifacts: ArtifactSpec::full(),
            seed: Some(42),
            metadata: HashMap::new(),
        }
    }

    pub fn estimated_duration(&self) -> Duration {
        let attempts_per_cell = self.test_matrix.attempts_per_cell;
        let total_cells = self.nat_profiles.len().pow(2)
            * self.test_matrix.ip_modes.len()
            * self.test_matrix.test_patterns.len();
        let total_attempts = total_cells * attempts_per_cell as usize;

        let per_attempt_ms = self.timing.attempt_timeout.as_millis() as u64 / 2;
        Duration::from_millis(per_attempt_ms * total_attempts as u64)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.id.is_empty() {
            errors.push("Scenario ID cannot be empty".to_string());
        }
        if self.nat_profiles.is_empty() {
            errors.push("At least one NAT profile required".to_string());
        }
        if self.test_matrix.attempts_per_cell == 0 {
            errors.push("attempts_per_cell must be > 0".to_string());
        }
        if self.thresholds.min_success_rate > 1.0 || self.thresholds.min_success_rate < 0.0 {
            errors.push("min_success_rate must be between 0.0 and 1.0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySpec {
    pub node_count: usize,
    pub topology_type: TopologyType,
    pub agent_assignments: Vec<AgentAssignment>,
}

impl TopologySpec {
    pub fn pair() -> Self {
        Self {
            node_count: 2,
            topology_type: TopologyType::Pair,
            agent_assignments: vec![
                AgentAssignment {
                    agent_id: "agent-a".into(),
                    role: AgentRole::Initiator,
                },
                AgentAssignment {
                    agent_id: "agent-b".into(),
                    role: AgentRole::Responder,
                },
            ],
        }
    }

    pub fn mesh(count: usize) -> Self {
        let assignments: Vec<_> = (0..count)
            .map(|i| AgentAssignment {
                agent_id: format!("agent-{}", i),
                role: AgentRole::Peer,
            })
            .collect();
        Self {
            node_count: count,
            topology_type: TopologyType::Mesh,
            agent_assignments: assignments,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    Pair,
    Star,
    Mesh,
    Ring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAssignment {
    pub agent_id: String,
    pub role: AgentRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Initiator,
    Responder,
    Coordinator,
    Relay,
    Peer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatProfileSpec {
    pub name: String,
    pub nat_type: NatType,
    pub docker_image: Option<String>,
    pub iptables_rules: Option<Vec<String>>,
    pub tc_rules: Option<Vec<String>>,
    #[serde(default)]
    pub network_impairment: Option<NetworkProfile>,
}

impl NatProfileSpec {
    pub fn none() -> Self {
        Self {
            name: "none".into(),
            nat_type: NatType::None,
            docker_image: None,
            iptables_rules: None,
            tc_rules: None,
            network_impairment: None,
        }
    }

    pub fn full_cone() -> Self {
        Self {
            name: "full_cone".into(),
            nat_type: NatType::FullCone,
            docker_image: Some("saorsa/nat-simulator:full-cone".into()),
            iptables_rules: Some(vec![
                "-t nat -A POSTROUTING -o eth0 -j MASQUERADE --random".into(),
                "-A FORWARD -i eth0 -o docker0 -j ACCEPT".into(),
            ]),
            tc_rules: None,
            network_impairment: None,
        }
    }

    pub fn symmetric() -> Self {
        Self {
            name: "symmetric".into(),
            nat_type: NatType::Symmetric,
            docker_image: Some("saorsa/nat-simulator:symmetric".into()),
            iptables_rules: Some(vec![
                "-t nat -A POSTROUTING -o eth0 -j MASQUERADE --random-fully".into(),
                "-A FORWARD -i eth0 -o docker0 -m state --state ESTABLISHED -j ACCEPT".into(),
            ]),
            tc_rules: None,
            network_impairment: None,
        }
    }

    pub fn cgnat() -> Self {
        Self {
            name: "cgnat".into(),
            nat_type: NatType::Cgnat,
            docker_image: Some("saorsa/nat-simulator:cgnat".into()),
            iptables_rules: Some(vec![
                "-t nat -A POSTROUTING -o eth0 -j MASQUERADE --random-fully".into(),
                "-t nat -A POSTROUTING -p udp -j MASQUERADE --to-ports 32768-33023".into(),
            ]),
            tc_rules: None,
            network_impairment: None,
        }
    }

    pub fn all_standard() -> Vec<Self> {
        vec![
            Self::none(),
            Self::full_cone(),
            Self {
                name: "address_restricted".into(),
                nat_type: NatType::AddressRestricted,
                docker_image: Some("saorsa/nat-simulator:addr-restricted".into()),
                iptables_rules: None,
                tc_rules: None,
                network_impairment: None,
            },
            Self {
                name: "port_restricted".into(),
                nat_type: NatType::PortRestricted,
                docker_image: Some("saorsa/nat-simulator:port-restricted".into()),
                iptables_rules: None,
                tc_rules: None,
                network_impairment: None,
            },
            Self::symmetric(),
        ]
    }

    pub fn ci_subset() -> Vec<Self> {
        vec![Self::none(), Self::full_cone(), Self::symmetric()]
    }
}

/// Comprehensive NAT behavior profile for Docker simulation.
///
/// Extends `NatProfileSpec` with full RFC 4787 behavioral details for accurate
/// NAT simulation in Docker-based test environments. This profile defines:
/// - Complete RFC 4787 mapping and filtering behaviors
/// - Port preservation and timeout characteristics
/// - Docker container and iptables configuration
/// - Expected hole-punching success rates
///
/// # Docker Integration
///
/// Profiles can reference either:
/// 1. Local Docker build context via `docker_build_context` (preferred)
/// 2. Pre-built image via `docker_image`
///
/// The `docker/nat-emulation/` directory contains Dockerfiles and entrypoint
/// scripts for each NAT type. The `iptables_rules` field documents the key
/// rules used by the entrypoint scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatBehaviorProfile {
    /// Human-readable profile name (e.g., "symmetric_cgnat")
    pub name: String,
    /// Full RFC 4787 behavior specification
    pub behavior: NatBehavior,
    /// Docker build context path relative to project root (e.g., "docker/nat-emulation/nat-symmetric")
    pub docker_build_context: Option<String>,
    /// Docker container image for NAT simulation (for remote/pre-built images)
    pub docker_image: Option<String>,
    /// Key iptables rules that define NAT behavior (from entrypoint.sh)
    pub iptables_rules: Vec<String>,
    /// tc (traffic control) rules for network shaping
    pub tc_rules: Vec<String>,
    /// Additional network impairments (latency, loss, etc.)
    pub network_impairment: Option<NetworkProfile>,
    /// Whether this profile is suitable for CI testing (fast, reliable)
    pub ci_compatible: bool,
    /// Priority for test ordering (lower = test first)
    pub test_priority: u8,
}

impl NatBehaviorProfile {
    /// Create a profile for no NAT (direct connectivity).
    ///
    /// Used for baseline testing with direct public IP connectivity.
    #[must_use]
    pub fn none() -> Self {
        Self {
            name: "none".into(),
            behavior: NatBehavior::from_nat_type(NatType::None),
            docker_build_context: None,
            docker_image: None,
            iptables_rules: vec![],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 0,
        }
    }

    /// Create a Full Cone NAT profile (EIM/EIF).
    ///
    /// Full Cone NAT (RFC 3489):
    /// - Endpoint Independent Mapping (EIM): same external port for all destinations
    /// - Endpoint Independent Filtering (EIF): accept from ANY external host on mapped port
    ///
    /// This is the most permissive NAT type and easiest to hole-punch through.
    /// Docker: `docker/nat-emulation/nat-fullcone/`
    #[must_use]
    pub fn full_cone() -> Self {
        Self {
            name: "full_cone".into(),
            behavior: NatBehavior::from_nat_type(NatType::FullCone),
            docker_build_context: Some("docker/nat-emulation/nat-fullcone".into()),
            docker_image: None,
            iptables_rules: vec![
                // NAT: Masquerade outgoing (preserves source port when possible)
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE".into(),
                // Forward: Allow all traffic in both directions (key for full cone)
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j ACCEPT".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 1,
        }
    }

    /// Create an Address-Restricted NAT profile (EIM/ADF).
    ///
    /// Address-Restricted Cone NAT (RFC 3489):
    /// - Endpoint Independent Mapping (EIM): same external port for all destinations
    /// - Address Dependent Filtering (ADF): only accept from IPs we've sent to
    ///
    /// To receive from X, we must have previously sent to X (any port).
    /// Docker: `docker/nat-emulation/nat-restricted/`
    #[must_use]
    pub fn address_restricted() -> Self {
        Self {
            name: "address_restricted".into(),
            behavior: NatBehavior::from_nat_type(NatType::AddressRestricted),
            docker_build_context: Some("docker/nat-emulation/nat-restricted".into()),
            docker_image: None,
            iptables_rules: vec![
                // NAT: Masquerade outgoing
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE".into(),
                // Forward: Allow outgoing
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Only allow established/related (address-restricted)
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 2,
        }
    }

    /// Create a Port-Restricted NAT profile (EIM/APDF).
    ///
    /// Port-Restricted Cone NAT (RFC 3489):
    /// - Endpoint Independent Mapping (EIM): same external port for all destinations
    /// - Address and Port Dependent Filtering (APDF): only accept from exact IP:port
    ///
    /// This is the default behavior of Linux iptables MASQUERADE.
    /// Docker: `docker/nat-emulation/nat-portrestricted/`
    #[must_use]
    pub fn port_restricted() -> Self {
        Self {
            name: "port_restricted".into(),
            behavior: NatBehavior::from_nat_type(NatType::PortRestricted),
            docker_build_context: Some("docker/nat-emulation/nat-portrestricted".into()),
            docker_image: None,
            iptables_rules: vec![
                // NAT: Standard masquerade (default Linux behavior is port-restricted)
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE".into(),
                // Forward: Allow outgoing
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Only established (port-restricted by default for UDP)
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 3,
        }
    }

    /// Create a Symmetric NAT profile (APDM/APDF).
    ///
    /// Symmetric NAT (RFC 3489):
    /// - Address and Port Dependent Mapping (APDM): different port per destination
    /// - Address and Port Dependent Filtering (APDF): only from exact IP:port
    ///
    /// The --random-fully flag causes iptables to randomize ports per connection.
    /// This is the HARDEST NAT type to traverse. Hole-punching typically requires relay.
    /// Docker: `docker/nat-emulation/nat-symmetric/`
    #[must_use]
    pub fn symmetric() -> Self {
        Self {
            name: "symmetric".into(),
            behavior: NatBehavior::from_nat_type(NatType::Symmetric),
            docker_build_context: Some("docker/nat-emulation/nat-symmetric".into()),
            docker_image: None,
            iptables_rules: vec![
                // NAT: Masquerade with --random-fully to randomize source ports
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE --random-fully".into(),
                // Forward: Allow outgoing
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Only established
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 4,
        }
    }

    /// Create a CGNAT profile (shared IP, limited ports).
    ///
    /// CGNAT (Carrier-Grade NAT) characteristics:
    /// - Shared public IP across multiple subscribers
    /// - Limited port range per subscriber (256 ports: 32768-33023)
    /// - Often uses RFC 6598 address space (100.64.0.0/10)
    ///
    /// Port exhaustion is a real problem with CGNAT.
    /// Docker: `docker/nat-emulation/nat-cgnat/`
    #[must_use]
    pub fn cgnat() -> Self {
        Self {
            name: "cgnat".into(),
            behavior: NatBehavior::from_nat_type(NatType::Cgnat),
            docker_build_context: Some("docker/nat-emulation/nat-cgnat".into()),
            docker_image: None,
            iptables_rules: vec![
                // NAT: SNAT with explicit port range (256 ports only)
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j SNAT --to-source $SHARED_IP:32768-33023".into(),
                // Forward: Allow outgoing
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Only established/related
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP".into(),
            ],
            tc_rules: vec![
                // Restrict local port range to simulate CGNAT constraints
                "echo '32768 33023' > /proc/sys/net/ipv4/ip_local_port_range".into(),
            ],
            network_impairment: None,
            ci_compatible: false, // CGNAT tests are slower
            test_priority: 5,
        }
    }

    /// Create a Hairpin NAT profile (NAT loopback/reflection).
    ///
    /// Hairpin NAT allows internal hosts to access services via their external IP.
    /// Important for P2P because:
    /// - Helps nodes discover their external address
    /// - Enables testing connectivity to self
    ///
    /// Docker: `docker/nat-emulation/nat-hairpin/`
    #[must_use]
    pub fn hairpin() -> Self {
        Self {
            name: "hairpin".into(),
            behavior: {
                let mut behavior = NatBehavior::from_nat_type(NatType::PortRestricted);
                behavior.hairpin = true;
                behavior.estimated_success_rate = 0.85;
                behavior
            },
            docker_build_context: Some("docker/nat-emulation/nat-hairpin".into()),
            docker_image: None,
            iptables_rules: vec![
                // Standard masquerade for outgoing
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE".into(),
                // Hairpin: Masquerade traffic from internal to external back to internal
                "-t nat -A POSTROUTING -o $INTERNAL_IFACE -s $INTERNAL_SUBNET -d $INTERNAL_SUBNET -j MASQUERADE".into(),
                // Forward: Allow outgoing
                "-A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Allow hairpin (internal to internal via external)
                "-A FORWARD -i $INTERNAL_IFACE -o $INTERNAL_IFACE -j ACCEPT".into(),
                // Forward: Allow established
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT".into(),
                "-A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: true,
            test_priority: 5,
        }
    }

    /// Create a Mobile Carrier profile (aggressive CGNAT).
    ///
    /// Mobile networks typically have:
    /// - CGNAT with aggressive state timeouts (30s)
    /// - Higher latency and jitter
    /// - Lower MTU (1400 bytes typical)
    /// - Packet loss under poor conditions
    ///
    /// No Docker infrastructure - used for VPS testing only.
    #[must_use]
    pub fn mobile_carrier() -> Self {
        Self {
            name: "mobile_carrier".into(),
            behavior: NatBehavior::from_nat_type(NatType::MobileCarrier),
            docker_build_context: None, // No Docker equivalent
            docker_image: None,
            iptables_rules: vec![
                "-t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE --random-fully".into(),
                "-t nat -A POSTROUTING -p udp -j MASQUERADE --to-ports 32768-40959".into(),
            ],
            tc_rules: vec![
                // Simulate mobile latency variability
                "qdisc add dev eth0 root netem delay 50ms 30ms distribution normal".into(),
            ],
            network_impairment: Some(NetworkProfile {
                name: "mobile_network".into(),
                mtu: 1400, // Mobile networks often have lower MTU
                latency_ms: 50,
                loss_percent: 1.0,
                jitter_ms: 30,
                bandwidth_kbps: Some(10000), // 10 Mbps typical
            }),
            ci_compatible: false,
            test_priority: 7,
        }
    }

    /// Create a Double NAT profile (router behind router).
    ///
    /// Double NAT is common in:
    /// - Apartments/dorms with shared ISP equipment
    /// - VM environments
    /// - Complex enterprise networks
    ///
    /// Docker: `docker/nat-emulation/nat-doublenat-outer` + `nat-doublenat-inner`
    #[must_use]
    pub fn double_nat() -> Self {
        Self {
            name: "double_nat".into(),
            behavior: NatBehavior::from_nat_type(NatType::DoubleNat),
            docker_build_context: Some("docker/nat-emulation".into()), // Uses two containers
            docker_image: None,
            iptables_rules: vec![
                // Outer NAT (ISP layer)
                "-t nat -A POSTROUTING -o eth0 -j MASQUERADE".into(),
                // Inner NAT (home router layer)
                "-t nat -A POSTROUTING -o eth1 -j MASQUERADE --random-fully".into(),
            ],
            tc_rules: vec![],
            network_impairment: None,
            ci_compatible: false,
            test_priority: 8,
        }
    }

    /// Get all standard profiles for comprehensive testing.
    #[must_use]
    pub fn all_standard() -> Vec<Self> {
        vec![
            Self::none(),
            Self::full_cone(),
            Self::address_restricted(),
            Self::port_restricted(),
            Self::symmetric(),
        ]
    }

    /// Get all profiles including extended NAT types.
    ///
    /// Returns 9 profiles covering all NAT behaviors in the Docker infrastructure:
    /// - none: Direct connectivity (baseline)
    /// - full_cone: EIM/EIF (easiest to traverse)
    /// - address_restricted: EIM/ADF
    /// - port_restricted: EIM/APDF (most common home NAT)
    /// - symmetric: APDM/APDF (hardest to traverse)
    /// - cgnat: Limited port range
    /// - hairpin: NAT loopback support
    /// - mobile_carrier: Aggressive CGNAT (VPS only)
    /// - double_nat: Two-layer NAT
    #[must_use]
    pub fn all_profiles() -> Vec<Self> {
        vec![
            Self::none(),
            Self::full_cone(),
            Self::address_restricted(),
            Self::port_restricted(),
            Self::symmetric(),
            Self::cgnat(),
            Self::hairpin(),
            Self::mobile_carrier(),
            Self::double_nat(),
        ]
    }

    /// Get profiles that have Docker infrastructure.
    ///
    /// Excludes profiles that only make sense for VPS testing (mobile_carrier).
    #[must_use]
    pub fn docker_profiles() -> Vec<Self> {
        Self::all_profiles()
            .into_iter()
            .filter(|p| p.docker_build_context.is_some())
            .collect()
    }

    /// Get CI-compatible subset for fast testing.
    #[must_use]
    pub fn ci_subset() -> Vec<Self> {
        Self::all_profiles()
            .into_iter()
            .filter(|p| p.ci_compatible)
            .collect()
    }

    /// Get the mapping behavior shorthand (EIM, ADM, APDM).
    #[must_use]
    pub fn mapping_shorthand(&self) -> &'static str {
        match self.behavior.mapping {
            MappingBehavior::EndpointIndependent => "EIM",
            MappingBehavior::AddressDependent => "ADM",
            MappingBehavior::AddressPortDependent => "APDM",
        }
    }

    /// Get the filtering behavior shorthand (EIF, ADF, APDF).
    #[must_use]
    pub fn filtering_shorthand(&self) -> &'static str {
        match self.behavior.filtering {
            FilteringBehavior::EndpointIndependent => "EIF",
            FilteringBehavior::AddressDependent => "ADF",
            FilteringBehavior::AddressPortDependent => "APDF",
        }
    }

    /// Get RFC 4787 classification string (e.g., "EIM/APDF").
    #[must_use]
    pub fn rfc4787_classification(&self) -> String {
        format!(
            "{}/{}",
            self.mapping_shorthand(),
            self.filtering_shorthand()
        )
    }

    /// Predict hole-punch success rate when connecting to another profile.
    #[must_use]
    pub fn predict_success_rate(&self, other: &Self) -> f64 {
        NatBehavior::estimate_pair_success_rate(&self.behavior, &other.behavior)
    }
}

// =============================================================================
// Connection Path Classification
// =============================================================================

/// Classification of connection paths based on NAT and IP mode.
///
/// This classifies how two peers can potentially connect based on their
/// NAT types and IP addressing modes. The classification predicts:
/// - Which techniques are viable
/// - Expected success rates
/// - Recommended technique ordering
/// - Whether relay fallback is needed
///
/// # Path Categories
///
/// - **Direct**: No NAT traversal needed (both public, same address family)
/// - **HolePunchable**: Standard hole-punch will work (cone NATs)
/// - **CoordinatedOnly**: Needs third-party coordination (port-restricted)
/// - **RelayRequired**: Hole-punch not viable (symmetric-symmetric)
/// - **IpMismatch**: Different address families, needs protocol translation
///
/// # Example
///
/// ```ignore
/// let path = ConnectionPath::classify(&full_cone, &port_restricted, &IpMode::Ipv4Only);
/// assert_eq!(path.category, PathCategory::HolePunchable);
/// assert!(path.viable_techniques().contains(&ConnectionTechnique::HolePunch));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPath {
    /// High-level category of the connection path.
    pub category: PathCategory,
    /// NAT profile of peer A.
    pub nat_a: String,
    /// NAT profile of peer B.
    pub nat_b: String,
    /// IP mode for this path.
    pub ip_mode: IpMode,
    /// Ordered list of techniques to attempt (best first).
    pub technique_priority: Vec<TechniquePriority>,
    /// Estimated success rate (0.0 - 1.0).
    pub estimated_success_rate: f64,
    /// Whether relay fallback should be pre-staged.
    pub relay_recommended: bool,
    /// Additional notes about this path.
    pub notes: Vec<String>,
}

/// High-level category of a connection path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCategory {
    /// Direct connection possible (no NAT or easy NAT).
    Direct,
    /// Hole-punching likely to succeed (cone NATs).
    HolePunchable,
    /// Needs coordinator but hole-punch possible.
    CoordinatedOnly,
    /// Relay required (symmetric-symmetric or CGNAT).
    RelayRequired,
    /// IP address family mismatch (IPv4 vs IPv6).
    IpMismatch,
    /// Unknown or unclassified path.
    Unknown,
}

impl std::fmt::Display for PathCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::HolePunchable => write!(f, "Hole-Punchable"),
            Self::CoordinatedOnly => write!(f, "Coordinated-Only"),
            Self::RelayRequired => write!(f, "Relay-Required"),
            Self::IpMismatch => write!(f, "IP-Mismatch"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl PathCategory {
    /// Get all path categories.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Direct,
            Self::HolePunchable,
            Self::CoordinatedOnly,
            Self::RelayRequired,
            Self::IpMismatch,
            Self::Unknown,
        ]
    }

    /// Is this a path where direct communication is possible?
    #[must_use]
    pub fn is_direct_capable(&self) -> bool {
        matches!(self, Self::Direct | Self::HolePunchable)
    }

    /// Does this path require relay for reliable connectivity?
    #[must_use]
    pub fn requires_relay(&self) -> bool {
        matches!(self, Self::RelayRequired | Self::IpMismatch)
    }

    /// Expected baseline success rate for this category.
    #[must_use]
    pub fn baseline_success_rate(&self) -> f64 {
        match self {
            Self::Direct => 0.99,
            Self::HolePunchable => 0.85,
            Self::CoordinatedOnly => 0.70,
            Self::RelayRequired => 0.95, // High when relay available
            Self::IpMismatch => 0.40,    // Needs protocol translation
            Self::Unknown => 0.50,
        }
    }

    /// Short identifier for dimension keys.
    #[must_use]
    pub fn short_id(&self) -> &'static str {
        match self {
            Self::Direct => "dir",
            Self::HolePunchable => "hp",
            Self::CoordinatedOnly => "coord",
            Self::RelayRequired => "relay",
            Self::IpMismatch => "mismatch",
            Self::Unknown => "unk",
        }
    }
}

/// Priority entry for a connection technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniquePriority {
    /// The connection technique.
    pub technique: ConnectionTechnique,
    /// Priority level (lower = higher priority).
    pub priority: u8,
    /// Whether this technique is viable for this path.
    pub viable: bool,
    /// Estimated success rate for this technique on this path.
    pub estimated_success_rate: f64,
    /// Reason for viability assessment.
    pub reason: String,
}

impl TechniquePriority {
    /// Create a viable technique entry.
    #[must_use]
    pub fn viable(technique: ConnectionTechnique, priority: u8, success_rate: f64) -> Self {
        Self {
            technique,
            priority,
            viable: true,
            estimated_success_rate: success_rate,
            reason: "Viable for this path".into(),
        }
    }

    /// Create a non-viable technique entry.
    #[must_use]
    pub fn not_viable(technique: ConnectionTechnique, reason: &str) -> Self {
        Self {
            technique,
            priority: u8::MAX,
            viable: false,
            estimated_success_rate: 0.0,
            reason: reason.into(),
        }
    }
}

impl ConnectionPath {
    /// Classify a connection path based on NAT profiles and IP mode.
    #[must_use]
    pub fn classify(
        profile_a: &NatBehaviorProfile,
        profile_b: &NatBehaviorProfile,
        ip_mode: &IpMode,
    ) -> Self {
        let category = Self::determine_category(&profile_a.behavior, &profile_b.behavior);
        let technique_priority =
            Self::build_technique_priority(&profile_a.behavior, &profile_b.behavior, ip_mode);
        let estimated_success_rate =
            Self::calculate_success_rate(&profile_a.behavior, &profile_b.behavior, ip_mode);

        let relay_recommended = matches!(
            category,
            PathCategory::RelayRequired | PathCategory::CoordinatedOnly
        );

        let notes = Self::generate_notes(&profile_a.behavior, &profile_b.behavior, ip_mode);

        Self {
            category,
            nat_a: profile_a.name.clone(),
            nat_b: profile_b.name.clone(),
            ip_mode: *ip_mode,
            technique_priority,
            estimated_success_rate,
            relay_recommended,
            notes,
        }
    }

    /// Classify using NAT behaviors directly.
    #[must_use]
    pub fn classify_behaviors(
        behavior_a: &NatBehavior,
        behavior_b: &NatBehavior,
        ip_mode: &IpMode,
    ) -> Self {
        let category = Self::determine_category(behavior_a, behavior_b);
        let technique_priority = Self::build_technique_priority(behavior_a, behavior_b, ip_mode);
        let estimated_success_rate = Self::calculate_success_rate(behavior_a, behavior_b, ip_mode);

        let relay_recommended = matches!(
            category,
            PathCategory::RelayRequired | PathCategory::CoordinatedOnly
        );

        let notes = Self::generate_notes(behavior_a, behavior_b, ip_mode);

        Self {
            category,
            nat_a: format!("{:?}/{:?}", behavior_a.mapping, behavior_a.filtering),
            nat_b: format!("{:?}/{:?}", behavior_b.mapping, behavior_b.filtering),
            ip_mode: *ip_mode,
            technique_priority,
            estimated_success_rate,
            relay_recommended,
            notes,
        }
    }

    /// Determine the path category from NAT behaviors.
    fn determine_category(behavior_a: &NatBehavior, behavior_b: &NatBehavior) -> PathCategory {
        // Both have no NAT (direct connectivity)
        if behavior_a.mapping == MappingBehavior::EndpointIndependent
            && behavior_a.filtering == FilteringBehavior::EndpointIndependent
            && behavior_b.mapping == MappingBehavior::EndpointIndependent
            && behavior_b.filtering == FilteringBehavior::EndpointIndependent
        {
            return PathCategory::Direct;
        }

        // At least one is symmetric (APDM)
        let a_symmetric = behavior_a.mapping == MappingBehavior::AddressPortDependent;
        let b_symmetric = behavior_b.mapping == MappingBehavior::AddressPortDependent;

        // Both symmetric: relay required
        if a_symmetric && b_symmetric {
            return PathCategory::RelayRequired;
        }

        // One symmetric, one endpoint-independent: coordinated hole-punch possible
        if (a_symmetric || b_symmetric)
            && (behavior_a.filtering == FilteringBehavior::EndpointIndependent
                || behavior_b.filtering == FilteringBehavior::EndpointIndependent)
        {
            return PathCategory::CoordinatedOnly;
        }

        // One symmetric: likely needs relay
        if a_symmetric || b_symmetric {
            return PathCategory::RelayRequired;
        }

        // Both EIM (cone NATs)
        if behavior_a.mapping == MappingBehavior::EndpointIndependent
            && behavior_b.mapping == MappingBehavior::EndpointIndependent
        {
            // Check filtering - easy filtering allows hole-punch
            let easy_filter = |f: &FilteringBehavior| {
                matches!(
                    f,
                    FilteringBehavior::EndpointIndependent | FilteringBehavior::AddressDependent
                )
            };

            // At least one has easy filtering: standard hole-punch
            if easy_filter(&behavior_a.filtering) || easy_filter(&behavior_b.filtering) {
                return PathCategory::HolePunchable;
            }

            // Both APDF: coordinated hole-punch needed
            return PathCategory::CoordinatedOnly;
        }

        PathCategory::Unknown
    }

    /// Build ordered list of techniques for this path.
    fn build_technique_priority(
        behavior_a: &NatBehavior,
        behavior_b: &NatBehavior,
        ip_mode: &IpMode,
    ) -> Vec<TechniquePriority> {
        let mut techniques = Vec::new();
        let category = Self::determine_category(behavior_a, behavior_b);

        // Direct techniques based on IP mode
        match ip_mode {
            IpMode::Ipv4Only => {
                let direct_viable = category == PathCategory::Direct;
                if direct_viable {
                    techniques.push(TechniquePriority::viable(
                        ConnectionTechnique::DirectIpv4,
                        0,
                        0.99,
                    ));
                } else {
                    techniques.push(TechniquePriority::not_viable(
                        ConnectionTechnique::DirectIpv4,
                        "NAT prevents direct connection",
                    ));
                }
            }
            IpMode::Ipv6Only => {
                let direct_viable = category == PathCategory::Direct;
                if direct_viable {
                    techniques.push(TechniquePriority::viable(
                        ConnectionTechnique::DirectIpv6,
                        0,
                        0.99,
                    ));
                } else {
                    techniques.push(TechniquePriority::not_viable(
                        ConnectionTechnique::DirectIpv6,
                        "NAT prevents direct connection",
                    ));
                }
            }
            IpMode::DualStack => {
                let direct_viable = category == PathCategory::Direct;
                if direct_viable {
                    // Prefer IPv6 (Happy Eyeballs)
                    techniques.push(TechniquePriority::viable(
                        ConnectionTechnique::DirectIpv6,
                        0,
                        0.99,
                    ));
                    techniques.push(TechniquePriority::viable(
                        ConnectionTechnique::DirectIpv4,
                        1,
                        0.98,
                    ));
                } else {
                    techniques.push(TechniquePriority::not_viable(
                        ConnectionTechnique::DirectIpv6,
                        "NAT prevents direct connection",
                    ));
                    techniques.push(TechniquePriority::not_viable(
                        ConnectionTechnique::DirectIpv4,
                        "NAT prevents direct connection",
                    ));
                }
            }
        }

        // Hole-punch techniques
        match category {
            PathCategory::Direct => {
                // Hole-punch not needed but can still work
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunch,
                    5,
                    0.95,
                ));
            }
            PathCategory::HolePunchable => {
                // Standard hole-punch
                let success_rate = NatBehavior::estimate_pair_success_rate(behavior_a, behavior_b);
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunch,
                    2,
                    success_rate,
                ));
                // Coordinated as backup
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunchCoordinated,
                    3,
                    success_rate * 1.1_f64.min(1.0),
                ));
            }
            PathCategory::CoordinatedOnly => {
                // Only coordinated hole-punch works
                techniques.push(TechniquePriority::not_viable(
                    ConnectionTechnique::HolePunch,
                    "Requires coordination for this NAT combination",
                ));
                let success_rate =
                    NatBehavior::estimate_pair_success_rate(behavior_a, behavior_b) * 1.2;
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunchCoordinated,
                    2,
                    success_rate.min(0.85),
                ));
            }
            PathCategory::RelayRequired | PathCategory::IpMismatch => {
                // Hole-punch not viable
                techniques.push(TechniquePriority::not_viable(
                    ConnectionTechnique::HolePunch,
                    "Symmetric NAT prevents hole-punch",
                ));
                techniques.push(TechniquePriority::not_viable(
                    ConnectionTechnique::HolePunchCoordinated,
                    "Even coordinated hole-punch unlikely to succeed",
                ));
            }
            PathCategory::Unknown => {
                // Try anyway with low confidence
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunch,
                    3,
                    0.30,
                ));
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::HolePunchCoordinated,
                    4,
                    0.40,
                ));
            }
        }

        // Relay techniques (always viable as fallback)
        let relay_priority = match category {
            PathCategory::RelayRequired => 1, // Primary for these
            PathCategory::IpMismatch => 1,
            PathCategory::CoordinatedOnly => 4,
            PathCategory::HolePunchable => 5,
            PathCategory::Direct => 6,
            PathCategory::Unknown => 3,
        };
        techniques.push(TechniquePriority::viable(
            ConnectionTechnique::Relay,
            relay_priority,
            0.95,
        ));

        // MASQUE relay (for IP translation scenarios)
        match (ip_mode, category) {
            (IpMode::DualStack, PathCategory::IpMismatch) => {
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::MasqueRelay,
                    1,
                    0.90,
                ));
            }
            (IpMode::Ipv4Only, _) => {
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::MasqueRelayIpv4,
                    relay_priority + 1,
                    0.90,
                ));
            }
            (IpMode::Ipv6Only, _) => {
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::MasqueRelayIpv6,
                    relay_priority + 1,
                    0.90,
                ));
            }
            _ => {
                techniques.push(TechniquePriority::viable(
                    ConnectionTechnique::MasqueRelay,
                    relay_priority + 1,
                    0.90,
                ));
            }
        }

        // UPnP/NAT-PMP (only if either NAT supports it)
        let upnp_viable = behavior_a.upnp_available || behavior_b.upnp_available;
        if upnp_viable {
            techniques.push(TechniquePriority::viable(
                ConnectionTechnique::UPnP,
                2,
                0.80,
            ));
            techniques.push(TechniquePriority::viable(
                ConnectionTechnique::NatPmp,
                3,
                0.75,
            ));
        } else {
            techniques.push(TechniquePriority::not_viable(
                ConnectionTechnique::UPnP,
                "UPnP not available on either NAT",
            ));
            techniques.push(TechniquePriority::not_viable(
                ConnectionTechnique::NatPmp,
                "NAT-PMP not available on either NAT",
            ));
        }

        // Sort by priority
        techniques.sort_by_key(|t| (if t.viable { 0 } else { 1 }, t.priority));

        techniques
    }

    /// Calculate overall success rate for this path.
    fn calculate_success_rate(
        behavior_a: &NatBehavior,
        behavior_b: &NatBehavior,
        ip_mode: &IpMode,
    ) -> f64 {
        let base_rate = NatBehavior::estimate_pair_success_rate(behavior_a, behavior_b);

        // Apply IP mode modifier
        let ip_modifier = match ip_mode {
            IpMode::Ipv6Only => 1.15,  // IPv6 often has better direct connectivity
            IpMode::DualStack => 1.10, // Can use best available
            IpMode::Ipv4Only => 1.0,   // Baseline
        };

        // Apply hairpin bonus if both support it
        let hairpin_modifier = if behavior_a.hairpin && behavior_b.hairpin {
            1.05
        } else {
            1.0
        };

        (base_rate * ip_modifier * hairpin_modifier).min(0.99)
    }

    /// Generate notes about this path.
    fn generate_notes(
        behavior_a: &NatBehavior,
        behavior_b: &NatBehavior,
        ip_mode: &IpMode,
    ) -> Vec<String> {
        let mut notes = Vec::new();

        // NAT combination notes
        if behavior_a.mapping == MappingBehavior::AddressPortDependent
            && behavior_b.mapping == MappingBehavior::AddressPortDependent
        {
            notes.push("Both NATs are symmetric (APDM) - relay strongly recommended".into());
        }

        // Timeout notes
        let min_timeout = behavior_a
            .mapping_timeout_secs
            .min(behavior_b.mapping_timeout_secs);
        if min_timeout < 60 {
            notes.push(format!(
                "Short NAT timeout ({min_timeout}s) - keepalives needed"
            ));
        }

        // Port preservation notes
        use crate::registry::PortPreservation;
        if behavior_a.port_preservation == PortPreservation::NotPreserved
            || behavior_b.port_preservation == PortPreservation::NotPreserved
        {
            notes.push("Port not preserved - port prediction required".into());
        }

        // IP mode notes
        match ip_mode {
            IpMode::Ipv6Only => {
                notes.push("IPv6-only mode - NAT64/DNS64 may be needed for IPv4 targets".into());
            }
            IpMode::DualStack => {
                notes.push("Dual-stack mode - Happy Eyeballs will prefer IPv6".into());
            }
            IpMode::Ipv4Only => {}
        }

        // Hairpin notes
        if behavior_a.hairpin || behavior_b.hairpin {
            notes.push("Hairpin NAT available - can test local connectivity".into());
        }

        notes
    }

    /// Get viable techniques only, ordered by priority.
    #[must_use]
    pub fn viable_techniques(&self) -> Vec<ConnectionTechnique> {
        self.technique_priority
            .iter()
            .filter(|t| t.viable)
            .map(|t| t.technique)
            .collect()
    }

    /// Get the best technique for this path.
    #[must_use]
    pub fn best_technique(&self) -> Option<ConnectionTechnique> {
        self.technique_priority
            .iter()
            .filter(|t| t.viable)
            .min_by_key(|t| t.priority)
            .map(|t| t.technique)
    }

    /// Get the corresponding high-level ConnectionMethod.
    #[must_use]
    pub fn to_connection_method(&self) -> ConnectionMethod {
        match self.category {
            PathCategory::Direct => ConnectionMethod::Direct,
            PathCategory::HolePunchable | PathCategory::CoordinatedOnly => {
                ConnectionMethod::HolePunched
            }
            PathCategory::RelayRequired | PathCategory::IpMismatch | PathCategory::Unknown => {
                ConnectionMethod::Relayed
            }
        }
    }

    /// Create a dimension key for this path.
    #[must_use]
    pub fn dimension_key(&self) -> String {
        format!(
            "{}_{}_{}",
            self.nat_a.to_lowercase().replace(' ', "_"),
            self.nat_b.to_lowercase().replace(' ', "_"),
            self.ip_mode.short_id()
        )
    }
}

/// Build a full connection path matrix for all NAT profile combinations.
#[must_use]
pub fn build_connection_matrix(
    profiles: &[NatBehaviorProfile],
    ip_modes: &[IpMode],
) -> Vec<ConnectionPath> {
    let mut paths = Vec::new();

    for profile_a in profiles {
        for profile_b in profiles {
            for ip_mode in ip_modes {
                paths.push(ConnectionPath::classify(profile_a, profile_b, ip_mode));
            }
        }
    }

    paths
}

/// Analyze a connection matrix and generate summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMatrixAnalysis {
    /// Total number of paths.
    pub total_paths: usize,
    /// Paths by category.
    pub by_category: HashMap<String, usize>,
    /// Average success rate.
    pub avg_success_rate: f64,
    /// Paths requiring relay.
    pub relay_required_count: usize,
    /// Most common techniques.
    pub technique_distribution: HashMap<String, usize>,
}

impl ConnectionMatrixAnalysis {
    /// Analyze a set of connection paths.
    #[must_use]
    pub fn from_paths(paths: &[ConnectionPath]) -> Self {
        let total_paths = paths.len();

        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut technique_distribution: HashMap<String, usize> = HashMap::new();
        let mut total_success_rate = 0.0;
        let mut relay_required_count = 0;

        for path in paths {
            *by_category.entry(path.category.to_string()).or_insert(0) += 1;

            if path.relay_recommended {
                relay_required_count += 1;
            }

            total_success_rate += path.estimated_success_rate;

            if let Some(tech) = path.best_technique() {
                *technique_distribution
                    .entry(format!("{:?}", tech))
                    .or_insert(0) += 1;
            }
        }

        let avg_success_rate = if total_paths > 0 {
            total_success_rate / total_paths as f64
        } else {
            0.0
        };

        Self {
            total_paths,
            by_category,
            avg_success_rate,
            relay_required_count,
            technique_distribution,
        }
    }

    /// Get the percentage of paths in each category.
    #[must_use]
    pub fn category_percentages(&self) -> HashMap<String, f64> {
        self.by_category
            .iter()
            .map(|(cat, count)| {
                let pct = if self.total_paths > 0 {
                    (*count as f64 / self.total_paths as f64) * 100.0
                } else {
                    0.0
                };
                (cat.clone(), pct)
            })
            .collect()
    }

    /// Check if this matrix meets production viability thresholds.
    #[must_use]
    pub fn meets_production_threshold(&self, min_success_rate: f64) -> bool {
        self.avg_success_rate >= min_success_rate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMatrixSpec {
    pub nat_scenarios: Vec<NatScenario>,
    pub ip_modes: Vec<IpMode>,
    pub test_patterns: Vec<TestPattern>,
    pub temporal_scenarios: Vec<TemporalScenario>,
    pub network_profiles: Vec<NetworkProfile>,
    pub attempts_per_cell: u32,
    pub enable_migration_tests: bool,
    pub enable_relay_tests: bool,
    pub enable_gossip_tests: bool,
}

impl TestMatrixSpec {
    pub fn full_matrix() -> Self {
        Self {
            nat_scenarios: vec![
                NatScenario::BothPublic,
                NatScenario::SingleNatOnePublic,
                NatScenario::SingleNatBoth,
                NatScenario::Cgnat,
                NatScenario::DoubleNat,
                NatScenario::Hairpin,
                NatScenario::SymmetricBoth,
            ],
            ip_modes: vec![
                super::IpMode::Ipv4Only,
                super::IpMode::Ipv6Only,
                super::IpMode::DualStack,
            ],
            test_patterns: vec![
                TestPattern::Outbound,
                TestPattern::Inbound,
                TestPattern::Simultaneous,
            ],
            temporal_scenarios: vec![TemporalScenario::ColdStart],
            network_profiles: vec![NetworkProfile::ideal()],
            attempts_per_cell: 100,
            enable_migration_tests: true,
            enable_relay_tests: true,
            enable_gossip_tests: false,
        }
    }

    pub fn ci_fast() -> Self {
        Self {
            nat_scenarios: vec![NatScenario::BothPublic, NatScenario::SingleNatBoth],
            ip_modes: vec![super::IpMode::Ipv4Only],
            test_patterns: vec![TestPattern::Outbound],
            temporal_scenarios: vec![TemporalScenario::ColdStart],
            network_profiles: vec![NetworkProfile::ideal()],
            attempts_per_cell: 3,
            enable_migration_tests: false,
            enable_relay_tests: false,
            enable_gossip_tests: false,
        }
    }

    pub fn gossip_focused() -> Self {
        Self {
            nat_scenarios: vec![NatScenario::SingleNatBoth],
            ip_modes: vec![super::IpMode::Ipv4Only],
            test_patterns: vec![TestPattern::Outbound],
            temporal_scenarios: vec![TemporalScenario::ColdStart],
            network_profiles: vec![NetworkProfile::ideal()],
            attempts_per_cell: 10,
            enable_migration_tests: false,
            enable_relay_tests: false,
            enable_gossip_tests: true,
        }
    }

    pub fn oracle() -> Self {
        Self {
            nat_scenarios: vec![NatScenario::BothPublic],
            ip_modes: vec![super::IpMode::Ipv4Only],
            test_patterns: vec![TestPattern::Outbound],
            temporal_scenarios: vec![TemporalScenario::ColdStart],
            network_profiles: vec![NetworkProfile::ideal()],
            attempts_per_cell: 5,
            enable_migration_tests: false,
            enable_relay_tests: false,
            enable_gossip_tests: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSpec {
    pub min_success_rate: f64,
    pub max_harness_failure_rate: f64,
    pub max_p95_latency_ms: u64,
    pub min_data_proof_rate: f64,
    pub min_method_proof_rate: f64,
}

impl ThresholdSpec {
    pub fn production() -> Self {
        Self {
            min_success_rate: 0.95,
            max_harness_failure_rate: 0.001,
            max_p95_latency_ms: 2000,
            min_data_proof_rate: 0.99,
            min_method_proof_rate: 0.95,
        }
    }

    pub fn ci() -> Self {
        Self {
            min_success_rate: 0.90,
            max_harness_failure_rate: 0.01,
            max_p95_latency_ms: 5000,
            min_data_proof_rate: 0.95,
            min_method_proof_rate: 0.90,
        }
    }

    pub fn gossip() -> Self {
        Self {
            min_success_rate: 0.99,
            max_harness_failure_rate: 0.001,
            max_p95_latency_ms: 3000,
            min_data_proof_rate: 0.99,
            min_method_proof_rate: 0.95,
        }
    }

    pub fn oracle() -> Self {
        Self {
            min_success_rate: 0.999,
            max_harness_failure_rate: 0.0,
            max_p95_latency_ms: 1000,
            min_data_proof_rate: 1.0,
            min_method_proof_rate: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSpec {
    #[serde(with = "humantime_serde")]
    pub attempt_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub round_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub barrier_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub artifact_upload_timeout: Duration,
    pub max_retries: u32,
}

impl Default for TimingSpec {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(30),
            round_timeout: Duration::from_secs(300),
            barrier_timeout: Duration::from_secs(60),
            artifact_upload_timeout: Duration::from_secs(120),
            max_retries: 3,
        }
    }
}

impl TimingSpec {
    pub fn ci_fast() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(15),
            round_timeout: Duration::from_secs(120),
            barrier_timeout: Duration::from_secs(30),
            artifact_upload_timeout: Duration::from_secs(60),
            max_retries: 1,
        }
    }

    pub fn oracle() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(10),
            round_timeout: Duration::from_secs(60),
            barrier_timeout: Duration::from_secs(15),
            artifact_upload_timeout: Duration::from_secs(30),
            max_retries: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSpec {
    pub capture_pcaps: bool,
    pub capture_nat_state: bool,
    pub capture_process_state: bool,
    pub capture_docker_logs: bool,
    pub compress_artifacts: bool,
    #[serde(with = "humantime_serde")]
    pub retention: Duration,
}

impl Default for ArtifactSpec {
    fn default() -> Self {
        Self {
            capture_pcaps: true,
            capture_nat_state: true,
            capture_process_state: true,
            capture_docker_logs: true,
            compress_artifacts: true,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

impl ArtifactSpec {
    pub fn minimal() -> Self {
        Self {
            capture_pcaps: false,
            capture_nat_state: false,
            capture_process_state: false,
            capture_docker_logs: true,
            compress_artifacts: true,
            retention: Duration::from_secs(24 * 60 * 60),
        }
    }

    pub fn full() -> Self {
        Self {
            capture_pcaps: true,
            capture_nat_state: true,
            capture_process_state: true,
            capture_docker_logs: true,
            compress_artifacts: true,
            retention: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_spec_validate() {
        let spec = ScenarioSpec::ci_fast();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_scenario_spec_invalid() {
        let mut spec = ScenarioSpec::ci_fast();
        spec.id = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn test_nat_profile_spec_all_standard() {
        let profiles = NatProfileSpec::all_standard();
        assert_eq!(profiles.len(), 5);
    }

    #[test]
    fn test_topology_spec_mesh() {
        let topology = TopologySpec::mesh(4);
        assert_eq!(topology.node_count, 4);
        assert_eq!(topology.agent_assignments.len(), 4);
    }

    #[test]
    fn test_threshold_spec_production() {
        let thresholds = ThresholdSpec::production();
        assert!(thresholds.min_success_rate >= 0.95);
        assert!(thresholds.max_harness_failure_rate <= 0.01);
    }

    #[test]
    fn test_nat_behavior_profile_all_profiles() {
        let profiles = NatBehaviorProfile::all_profiles();
        assert_eq!(profiles.len(), 9); // Including hairpin

        // Verify each profile has correct RFC 4787 classification
        let classifications: Vec<_> = profiles
            .iter()
            .map(|p| (p.name.clone(), p.rfc4787_classification()))
            .collect();

        // None (no NAT) - EIM/EIF
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "none" && c == "EIM/EIF")
        );
        // Full Cone - EIM/EIF
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "full_cone" && c == "EIM/EIF")
        );
        // Address Restricted - EIM/ADF
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "address_restricted" && c == "EIM/ADF")
        );
        // Port Restricted - EIM/APDF
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "port_restricted" && c == "EIM/APDF")
        );
        // Symmetric - APDM/APDF
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "symmetric" && c == "APDM/APDF")
        );
        // Hairpin - EIM/APDF with hairpin enabled
        assert!(
            classifications
                .iter()
                .any(|(n, c)| n == "hairpin" && c == "EIM/APDF")
        );
    }

    #[test]
    fn test_nat_behavior_profile_docker_profiles() {
        let docker_profiles = NatBehaviorProfile::docker_profiles();
        // 7 profiles have Docker build contexts (none and mobile_carrier don't)
        assert_eq!(docker_profiles.len(), 7);

        // All docker profiles should have a build context
        assert!(
            docker_profiles
                .iter()
                .all(|p| p.docker_build_context.is_some())
        );

        // Verify specific Docker paths
        let paths: Vec<_> = docker_profiles
            .iter()
            .filter_map(|p| p.docker_build_context.as_ref())
            .collect();
        assert!(paths.contains(&&"docker/nat-emulation/nat-fullcone".to_string()));
        assert!(paths.contains(&&"docker/nat-emulation/nat-symmetric".to_string()));
        assert!(paths.contains(&&"docker/nat-emulation/nat-hairpin".to_string()));
    }

    #[test]
    fn test_nat_behavior_profile_hairpin() {
        let hairpin = NatBehaviorProfile::hairpin();
        assert_eq!(hairpin.name, "hairpin");
        assert!(hairpin.behavior.hairpin); // Hairpin must be enabled
        assert!(hairpin.docker_build_context.is_some());
        assert!(hairpin.ci_compatible);

        // Hairpin should have specific iptables rules for loopback
        assert!(
            hairpin
                .iptables_rules
                .iter()
                .any(|r| r.contains("$INTERNAL_IFACE -o $INTERNAL_IFACE"))
        );
    }

    #[test]
    fn test_nat_behavior_profile_ci_subset() {
        let ci_profiles = NatBehaviorProfile::ci_subset();
        // All CI profiles should be CI compatible
        assert!(ci_profiles.iter().all(|p| p.ci_compatible));
        // Should include at least none and full_cone
        assert!(ci_profiles.iter().any(|p| p.name == "none"));
        assert!(ci_profiles.iter().any(|p| p.name == "full_cone"));
    }

    #[test]
    fn test_nat_behavior_profile_success_rate_prediction() {
        let none = NatBehaviorProfile::none();
        let symmetric = NatBehaviorProfile::symmetric();
        let full_cone = NatBehaviorProfile::full_cone();

        // None to none should have high success rate
        assert!(none.predict_success_rate(&none) >= 0.95);

        // Full cone to symmetric should work reasonably well
        let fc_sym = full_cone.predict_success_rate(&symmetric);
        assert!(fc_sym > 0.5); // Full cone's EIF allows incoming

        // Symmetric to symmetric is harder
        let sym_sym = symmetric.predict_success_rate(&symmetric);
        assert!(sym_sym < fc_sym); // Both APDM/APDF is harder
    }

    #[test]
    fn test_nat_behavior_rfc4787_fields() {
        use crate::registry::PortPreservation;

        // Test that port preservation is correctly set for different NAT types
        let none = NatBehaviorProfile::none();
        assert_eq!(none.behavior.port_preservation, PortPreservation::Preferred);
        assert_eq!(none.behavior.mapping_timeout_secs, u32::MAX); // No timeout

        let symmetric = NatBehaviorProfile::symmetric();
        assert_eq!(
            symmetric.behavior.port_preservation,
            PortPreservation::NotPreserved
        );
        assert!(symmetric.behavior.mapping_timeout_secs <= 120);

        let mobile = NatBehaviorProfile::mobile_carrier();
        assert_eq!(
            mobile.behavior.port_preservation,
            PortPreservation::NotPreserved
        );
        assert!(mobile.behavior.mapping_timeout_secs <= 60); // Aggressive timeout

        // Full cone should preserve ports
        let full_cone = NatBehaviorProfile::full_cone();
        assert_eq!(
            full_cone.behavior.port_preservation,
            PortPreservation::Preferred
        );
        assert!(full_cone.behavior.port_parity); // Quality routers preserve parity
    }

    #[test]
    fn test_nat_behavior_profile_test_priority_ordering() {
        let profiles = NatBehaviorProfile::all_profiles();
        // Profiles should be in increasing priority order (easier tests first)
        for i in 0..profiles.len() - 1 {
            assert!(
                profiles[i].test_priority <= profiles[i + 1].test_priority,
                "Profile {} (priority {}) should be <= {} (priority {})",
                profiles[i].name,
                profiles[i].test_priority,
                profiles[i + 1].name,
                profiles[i + 1].test_priority
            );
        }
    }

    // =========================================================================
    // Connection Path Classification tests
    // =========================================================================

    #[test]
    fn test_path_category_all() {
        let categories = PathCategory::all();
        assert_eq!(categories.len(), 6);
        assert!(categories.contains(&PathCategory::Direct));
        assert!(categories.contains(&PathCategory::HolePunchable));
        assert!(categories.contains(&PathCategory::CoordinatedOnly));
        assert!(categories.contains(&PathCategory::RelayRequired));
        assert!(categories.contains(&PathCategory::IpMismatch));
        assert!(categories.contains(&PathCategory::Unknown));
    }

    #[test]
    fn test_path_category_display() {
        assert_eq!(PathCategory::Direct.to_string(), "Direct");
        assert_eq!(PathCategory::HolePunchable.to_string(), "Hole-Punchable");
        assert_eq!(PathCategory::RelayRequired.to_string(), "Relay-Required");
    }

    #[test]
    fn test_path_category_short_id() {
        assert_eq!(PathCategory::Direct.short_id(), "dir");
        assert_eq!(PathCategory::HolePunchable.short_id(), "hp");
        assert_eq!(PathCategory::CoordinatedOnly.short_id(), "coord");
        assert_eq!(PathCategory::RelayRequired.short_id(), "relay");
    }

    #[test]
    fn test_path_category_is_direct_capable() {
        assert!(PathCategory::Direct.is_direct_capable());
        assert!(PathCategory::HolePunchable.is_direct_capable());
        assert!(!PathCategory::RelayRequired.is_direct_capable());
        assert!(!PathCategory::IpMismatch.is_direct_capable());
    }

    #[test]
    fn test_path_category_requires_relay() {
        assert!(!PathCategory::Direct.requires_relay());
        assert!(!PathCategory::HolePunchable.requires_relay());
        assert!(PathCategory::RelayRequired.requires_relay());
        assert!(PathCategory::IpMismatch.requires_relay());
    }

    #[test]
    fn test_path_category_baseline_success_rate() {
        // Direct should have highest baseline
        assert!(PathCategory::Direct.baseline_success_rate() > 0.95);
        // Hole-punchable should be reasonably high
        assert!(PathCategory::HolePunchable.baseline_success_rate() > 0.70);
        // Relay required is high because relay works
        assert!(PathCategory::RelayRequired.baseline_success_rate() > 0.90);
        // IP mismatch is lower due to translation needs
        assert!(PathCategory::IpMismatch.baseline_success_rate() < 0.60);
    }

    #[test]
    fn test_connection_path_classify_none_to_none() {
        let none = NatBehaviorProfile::none();
        let path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);

        assert_eq!(path.category, PathCategory::Direct);
        assert!(path.estimated_success_rate >= 0.95);
        assert!(!path.relay_recommended);
        assert!(
            path.viable_techniques()
                .contains(&ConnectionTechnique::DirectIpv4)
        );
    }

    #[test]
    fn test_connection_path_classify_full_cone_to_full_cone() {
        let full_cone = NatBehaviorProfile::full_cone();
        let path = ConnectionPath::classify(&full_cone, &full_cone, &super::IpMode::Ipv4Only);

        // Full cone to full cone should be hole-punchable (EIM/EIF on both sides)
        assert_eq!(path.category, PathCategory::Direct);
        assert!(path.estimated_success_rate >= 0.90);
    }

    #[test]
    fn test_connection_path_classify_symmetric_to_symmetric() {
        let symmetric = NatBehaviorProfile::symmetric();
        let path = ConnectionPath::classify(&symmetric, &symmetric, &super::IpMode::Ipv4Only);

        // Symmetric to symmetric requires relay
        assert_eq!(path.category, PathCategory::RelayRequired);
        assert!(path.relay_recommended);
        // Hole-punch should not be viable
        let viable = path.viable_techniques();
        assert!(!viable.contains(&ConnectionTechnique::HolePunch));
        assert!(viable.contains(&ConnectionTechnique::Relay));
    }

    #[test]
    fn test_connection_path_classify_port_restricted_both() {
        let pr = NatBehaviorProfile::port_restricted();
        let path = ConnectionPath::classify(&pr, &pr, &super::IpMode::Ipv4Only);

        // Port restricted both sides (EIM/APDF) needs coordination
        assert_eq!(path.category, PathCategory::CoordinatedOnly);
        assert!(path.relay_recommended);
        // Coordinated hole-punch should be viable
        let viable = path.viable_techniques();
        assert!(viable.contains(&ConnectionTechnique::HolePunchCoordinated));
    }

    #[test]
    fn test_connection_path_classify_full_cone_to_symmetric() {
        let full_cone = NatBehaviorProfile::full_cone();
        let symmetric = NatBehaviorProfile::symmetric();
        let path = ConnectionPath::classify(&full_cone, &symmetric, &super::IpMode::Ipv4Only);

        // Full cone (EIF) + Symmetric: coordinated can work
        assert!(
            path.category == PathCategory::CoordinatedOnly
                || path.category == PathCategory::RelayRequired
        );
    }

    #[test]
    fn test_connection_path_ip_mode_affects_techniques() {
        let none = NatBehaviorProfile::none();

        // IPv4 only
        let v4_path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);
        let v4_viable = v4_path.viable_techniques();
        assert!(v4_viable.contains(&ConnectionTechnique::DirectIpv4));
        assert!(!v4_viable.contains(&ConnectionTechnique::DirectIpv6));

        // IPv6 only
        let v6_path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv6Only);
        let v6_viable = v6_path.viable_techniques();
        assert!(v6_viable.contains(&ConnectionTechnique::DirectIpv6));
        assert!(!v6_viable.contains(&ConnectionTechnique::DirectIpv4));

        // Dual stack - both should be viable
        let ds_path = ConnectionPath::classify(&none, &none, &super::IpMode::DualStack);
        let ds_viable = ds_path.viable_techniques();
        assert!(ds_viable.contains(&ConnectionTechnique::DirectIpv4));
        assert!(ds_viable.contains(&ConnectionTechnique::DirectIpv6));
    }

    #[test]
    fn test_connection_path_best_technique() {
        let none = NatBehaviorProfile::none();
        let path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);

        // Direct should be best for none-to-none
        let best = path.best_technique();
        assert!(best.is_some());
        assert_eq!(best.unwrap(), ConnectionTechnique::DirectIpv4);
    }

    #[test]
    fn test_connection_path_to_connection_method() {
        let none = NatBehaviorProfile::none();
        let symmetric = NatBehaviorProfile::symmetric();

        let direct_path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);
        assert_eq!(direct_path.to_connection_method(), ConnectionMethod::Direct);

        let relay_path = ConnectionPath::classify(&symmetric, &symmetric, &super::IpMode::Ipv4Only);
        assert_eq!(relay_path.to_connection_method(), ConnectionMethod::Relayed);
    }

    #[test]
    fn test_connection_path_dimension_key() {
        let none = NatBehaviorProfile::none();
        let path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);

        let key = path.dimension_key();
        assert!(key.contains("none"));
        assert!(key.contains("v4"));
    }

    #[test]
    fn test_connection_path_generates_notes() {
        let mobile = NatBehaviorProfile::mobile_carrier();
        let path = ConnectionPath::classify(&mobile, &mobile, &super::IpMode::Ipv4Only);

        // Should have notes about short timeout (mobile has aggressive timeouts)
        assert!(!path.notes.is_empty());
        // Mobile carrier has 30s timeout which triggers the note
        assert!(
            path.notes
                .iter()
                .any(|n| n.contains("timeout") || n.contains("keepalive")),
            "Expected timeout note, got: {:?}",
            path.notes
        );
    }

    #[test]
    fn test_connection_path_dual_stack_notes() {
        let none = NatBehaviorProfile::none();
        let path = ConnectionPath::classify(&none, &none, &super::IpMode::DualStack);

        // Should have note about Happy Eyeballs
        assert!(path.notes.iter().any(|n| n.contains("Happy Eyeballs")));
    }

    #[test]
    fn test_connection_path_hairpin_notes() {
        let hairpin = NatBehaviorProfile::hairpin();
        let path = ConnectionPath::classify(&hairpin, &hairpin, &super::IpMode::Ipv4Only);

        // Should have note about hairpin NAT
        assert!(path.notes.iter().any(|n| n.contains("Hairpin")));
    }

    #[test]
    fn test_technique_priority_viable() {
        let tp = TechniquePriority::viable(ConnectionTechnique::HolePunch, 2, 0.85);
        assert!(tp.viable);
        assert_eq!(tp.priority, 2);
        assert_eq!(tp.estimated_success_rate, 0.85);
    }

    #[test]
    fn test_technique_priority_not_viable() {
        let tp = TechniquePriority::not_viable(
            ConnectionTechnique::HolePunch,
            "Symmetric NAT prevents hole-punch",
        );
        assert!(!tp.viable);
        assert_eq!(tp.priority, u8::MAX);
        assert_eq!(tp.estimated_success_rate, 0.0);
        assert!(tp.reason.contains("Symmetric"));
    }

    #[test]
    fn test_build_connection_matrix() {
        let profiles = vec![NatBehaviorProfile::none(), NatBehaviorProfile::full_cone()];
        let ip_modes = vec![super::IpMode::Ipv4Only];

        let matrix = build_connection_matrix(&profiles, &ip_modes);

        // 2 profiles * 2 profiles * 1 ip_mode = 4 paths
        assert_eq!(matrix.len(), 4);
    }

    #[test]
    fn test_build_connection_matrix_all_profiles() {
        let profiles = NatBehaviorProfile::all_standard();
        let ip_modes = super::IpMode::all();

        let matrix = build_connection_matrix(&profiles, ip_modes);

        // 5 profiles * 5 profiles * 3 ip_modes = 75 paths
        assert_eq!(matrix.len(), 75);
    }

    #[test]
    fn test_connection_matrix_analysis() {
        let profiles = vec![
            NatBehaviorProfile::none(),
            NatBehaviorProfile::full_cone(),
            NatBehaviorProfile::symmetric(),
        ];
        let ip_modes = vec![super::IpMode::Ipv4Only];

        let matrix = build_connection_matrix(&profiles, &ip_modes);
        let analysis = ConnectionMatrixAnalysis::from_paths(&matrix);

        // 3 profiles * 3 profiles * 1 ip_mode = 9 paths
        assert_eq!(analysis.total_paths, 9);

        // Should have some paths in each category
        assert!(!analysis.by_category.is_empty());

        // Average success rate should be reasonable
        assert!(analysis.avg_success_rate > 0.5);
        assert!(analysis.avg_success_rate <= 1.0);

        // Some paths should require relay (symmetric-symmetric)
        assert!(analysis.relay_required_count > 0);
    }

    #[test]
    fn test_connection_matrix_analysis_category_percentages() {
        let profiles = vec![NatBehaviorProfile::none(), NatBehaviorProfile::symmetric()];
        let ip_modes = vec![super::IpMode::Ipv4Only];

        let matrix = build_connection_matrix(&profiles, &ip_modes);
        let analysis = ConnectionMatrixAnalysis::from_paths(&matrix);

        let percentages = analysis.category_percentages();

        // Total should sum to 100% (approximately due to floating point)
        let total: f64 = percentages.values().sum();
        assert!((total - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_connection_matrix_analysis_meets_production_threshold() {
        let profiles = vec![NatBehaviorProfile::none()];
        let ip_modes = vec![super::IpMode::Ipv4Only];

        let matrix = build_connection_matrix(&profiles, &ip_modes);
        let analysis = ConnectionMatrixAnalysis::from_paths(&matrix);

        // None to none should meet high threshold
        assert!(analysis.meets_production_threshold(0.90));
    }

    #[test]
    fn test_connection_path_classify_behaviors_directly() {
        use crate::registry::NatBehavior;

        let behavior_a = NatBehavior::from_nat_type(NatType::FullCone);
        let behavior_b = NatBehavior::from_nat_type(NatType::PortRestricted);

        let path =
            ConnectionPath::classify_behaviors(&behavior_a, &behavior_b, &super::IpMode::Ipv4Only);

        // Should classify correctly
        assert!(
            path.category == PathCategory::HolePunchable
                || path.category == PathCategory::CoordinatedOnly
                || path.category == PathCategory::Direct
        );
        assert!(!path.nat_a.is_empty());
        assert!(!path.nat_b.is_empty());
    }

    #[test]
    fn test_connection_path_upnp_techniques() {
        // Create a profile with UPnP available
        let mut upnp_behavior = NatBehavior::from_nat_type(NatType::FullCone);
        upnp_behavior.upnp_available = true;

        let no_upnp = NatBehavior::from_nat_type(NatType::FullCone);

        // When at least one has UPnP, techniques should include UPnP
        let path =
            ConnectionPath::classify_behaviors(&upnp_behavior, &no_upnp, &super::IpMode::Ipv4Only);

        let viable = path.viable_techniques();
        assert!(viable.contains(&ConnectionTechnique::UPnP));
        assert!(viable.contains(&ConnectionTechnique::NatPmp));
    }

    #[test]
    fn test_connection_path_no_upnp_techniques() {
        let no_upnp_a = NatBehavior::from_nat_type(NatType::Symmetric);
        let no_upnp_b = NatBehavior::from_nat_type(NatType::Symmetric);

        let path =
            ConnectionPath::classify_behaviors(&no_upnp_a, &no_upnp_b, &super::IpMode::Ipv4Only);

        // When neither has UPnP, it shouldn't be in viable techniques
        let viable = path.viable_techniques();
        assert!(!viable.contains(&ConnectionTechnique::UPnP));
        assert!(!viable.contains(&ConnectionTechnique::NatPmp));
    }

    #[test]
    fn test_connection_path_relay_always_viable() {
        let symmetric = NatBehaviorProfile::symmetric();
        let path = ConnectionPath::classify(&symmetric, &symmetric, &super::IpMode::Ipv4Only);

        // Relay should always be in viable techniques as fallback
        let viable = path.viable_techniques();
        assert!(viable.contains(&ConnectionTechnique::Relay));
    }

    #[test]
    fn test_connection_path_masque_relay_variants() {
        let none = NatBehaviorProfile::none();

        // IPv4 should have MasqueRelayIpv4
        let v4_path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv4Only);
        let v4_viable = v4_path.viable_techniques();
        assert!(v4_viable.contains(&ConnectionTechnique::MasqueRelayIpv4));

        // IPv6 should have MasqueRelayIpv6
        let v6_path = ConnectionPath::classify(&none, &none, &super::IpMode::Ipv6Only);
        let v6_viable = v6_path.viable_techniques();
        assert!(v6_viable.contains(&ConnectionTechnique::MasqueRelayIpv6));

        // Dual-stack should have generic MasqueRelay
        let ds_path = ConnectionPath::classify(&none, &none, &super::IpMode::DualStack);
        let ds_viable = ds_path.viable_techniques();
        assert!(ds_viable.contains(&ConnectionTechnique::MasqueRelay));
    }
}
