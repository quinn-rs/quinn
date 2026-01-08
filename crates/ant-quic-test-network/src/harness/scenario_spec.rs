use crate::registry::{
    NatScenario, NatType, NetworkProfile, TemporalScenario, TestPattern, TestSuite,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use humantime_serde;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMatrixSpec {
    pub nat_scenarios: Vec<NatScenario>,
    pub ip_modes: Vec<super::IpMode>,
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
}
