use crate::registry::{
    ConnectionMethod, ConnectionTechnique, ConnectivityMatrix, DataProof, FailureReasonCode,
    ImpairmentMetrics, MethodProof, MigrationMetrics, NatScenario, NatType, NetworkProfile,
    RelayMetrics, SuccessLevel, TemporalMetrics, TemporalScenario, TestPattern,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::FailureCategory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptResult {
    pub run_id: Uuid,
    pub scenario_id: String,
    pub attempt_id: u32,
    pub timestamp_ms: u64,

    pub nat_a: NatType,
    pub nat_b: NatType,
    pub ip_mode: IpMode,
    pub nat_scenario: NatScenario,
    pub temporal_scenario: TemporalScenario,
    pub retry_index: u32,

    pub success: bool,
    pub path_used: Option<ConnectionMethod>,
    pub connect_time_ms: Option<u64>,
    pub error: Option<String>,
    pub failure_code: Option<FailureReasonCode>,
    pub failure_category: Option<FailureCategory>,

    pub success_level: SuccessLevel,
    pub data_proof: Option<DataProof>,
    pub method_proof: Option<MethodProof>,

    pub technique_sequence: Vec<TechniqueResult>,
    pub connectivity_matrix: Option<ConnectivityMatrix>,

    pub test_pattern: TestPattern,
    pub network_profile: Option<NetworkProfile>,
    pub impairment_metrics: Option<ImpairmentMetrics>,
    pub temporal_metrics: Option<TemporalMetrics>,
    pub migration_metrics: Option<MigrationMetrics>,
    pub relay_metrics: Option<RelayMetrics>,

    pub frames: FrameCounters,

    pub agent_a_id: String,
    pub agent_b_id: String,
    pub peer_a_id: String,
    pub peer_b_id: String,

    pub artifacts: Option<ArtifactReferences>,
    pub metadata: HashMap<String, String>,
}

impl AttemptResult {
    pub fn new(run_id: Uuid, scenario_id: &str, attempt_id: u32) -> Self {
        Self {
            run_id,
            scenario_id: scenario_id.to_string(),
            attempt_id,
            timestamp_ms: crate::registry::unix_timestamp_ms(),
            nat_a: NatType::Unknown,
            nat_b: NatType::Unknown,
            ip_mode: IpMode::Ipv4Only,
            nat_scenario: NatScenario::BothPublic,
            temporal_scenario: TemporalScenario::ColdStart,
            retry_index: 0,
            success: false,
            path_used: None,
            connect_time_ms: None,
            error: None,
            failure_code: None,
            failure_category: None,
            success_level: SuccessLevel::Failed,
            data_proof: None,
            method_proof: None,
            technique_sequence: Vec::new(),
            connectivity_matrix: None,
            test_pattern: TestPattern::Outbound,
            network_profile: None,
            impairment_metrics: None,
            temporal_metrics: None,
            migration_metrics: None,
            relay_metrics: None,
            frames: FrameCounters::default(),
            agent_a_id: String::new(),
            agent_b_id: String::new(),
            peer_a_id: String::new(),
            peer_b_id: String::new(),
            artifacts: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_dimensions(mut self, nat_a: NatType, nat_b: NatType, ip_mode: IpMode) -> Self {
        self.nat_a = nat_a;
        self.nat_b = nat_b;
        self.ip_mode = ip_mode;
        self
    }

    pub fn with_scenario_dimensions(
        mut self,
        nat_scenario: NatScenario,
        temporal_scenario: TemporalScenario,
    ) -> Self {
        self.nat_scenario = nat_scenario;
        self.temporal_scenario = temporal_scenario;
        self
    }

    pub fn with_retry_index(mut self, retry_index: u32) -> Self {
        self.retry_index = retry_index;
        self
    }

    pub fn with_agents(mut self, agent_a: &str, agent_b: &str) -> Self {
        self.agent_a_id = agent_a.to_string();
        self.agent_b_id = agent_b.to_string();
        self
    }

    pub fn with_peers(mut self, peer_a: &str, peer_b: &str) -> Self {
        self.peer_a_id = peer_a.to_string();
        self.peer_b_id = peer_b.to_string();
        self
    }

    pub fn record_success(
        &mut self,
        path: ConnectionMethod,
        connect_time_ms: u64,
        success_level: SuccessLevel,
    ) {
        self.success = true;
        self.path_used = Some(path);
        self.connect_time_ms = Some(connect_time_ms);
        self.success_level = success_level;
        self.failure_code = Some(FailureReasonCode::Success);
        self.failure_category = None;
    }

    pub fn record_failure(
        &mut self,
        error: &str,
        failure_code: FailureReasonCode,
        failure_category: FailureCategory,
    ) {
        self.success = false;
        self.error = Some(error.to_string());
        self.failure_code = Some(failure_code);
        self.failure_category = Some(failure_category);
        self.success_level = SuccessLevel::Failed;
    }

    pub fn add_technique_result(&mut self, technique: TechniqueResult) {
        self.technique_sequence.push(technique);
    }

    pub fn is_harness_failure(&self) -> bool {
        matches!(
            self.failure_category,
            Some(FailureCategory::HarnessPreflightError)
                | Some(FailureCategory::HarnessOrchestrationError)
                | Some(FailureCategory::HarnessObservationError)
        )
    }

    pub fn is_sut_failure(&self) -> bool {
        matches!(
            self.failure_category,
            Some(FailureCategory::SutConnectivityFailure)
                | Some(FailureCategory::SutBehaviorMismatch)
        )
    }

    pub fn is_infrastructure_failure(&self) -> bool {
        matches!(
            self.failure_category,
            Some(FailureCategory::InfrastructureFlake)
        )
    }

    pub fn is_passing(&self) -> bool {
        self.success && self.success_level.is_passing()
    }

    pub fn is_fully_proven(&self) -> bool {
        self.is_passing()
            && self
                .data_proof
                .as_ref()
                .is_some_and(|p| p.is_bidirectional())
            && self
                .method_proof
                .as_ref()
                .is_some_and(|p| p.has_sufficient_evidence())
    }

    pub fn dimension_key(&self) -> String {
        format!(
            "{}_{}_{}_{}_{}",
            to_snake_case(&format!("{:?}", self.nat_a)),
            to_snake_case(&format!("{:?}", self.nat_b)),
            to_snake_case(&format!("{:?}", self.ip_mode)),
            to_snake_case(&format!("{:?}", self.nat_scenario)),
            to_snake_case(&format!("{:?}", self.temporal_scenario)),
        )
    }

    pub fn full_dimension_key(&self) -> String {
        format!(
            "{}_{}_{}_{}_{}_{}",
            to_snake_case(&format!("{:?}", self.nat_a)),
            to_snake_case(&format!("{:?}", self.nat_b)),
            to_snake_case(&format!("{:?}", self.ip_mode)),
            to_snake_case(&format!("{:?}", self.nat_scenario)),
            to_snake_case(&format!("{:?}", self.temporal_scenario)),
            to_snake_case(&format!("{:?}", self.test_pattern)),
        )
    }

    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// IP addressing mode for connectivity testing.
///
/// Controls which IP address families are used for connection attempts.
/// This affects socket binding, address selection, and NAT traversal behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
    /// IPv4-only mode - uses only IPv4 addresses.
    #[default]
    Ipv4Only,
    /// IPv6-only mode - uses only IPv6 addresses.
    Ipv6Only,
    /// Dual-stack mode - can use both IPv4 and IPv6 addresses.
    /// Prefers IPv6 when available (Happy Eyeballs behavior).
    DualStack,
}

impl std::fmt::Display for IpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Only => write!(f, "IPv4"),
            Self::Ipv6Only => write!(f, "IPv6"),
            Self::DualStack => write!(f, "Dual-Stack"),
        }
    }
}

impl IpMode {
    /// Returns all IP modes for comprehensive testing.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Ipv4Only, Self::Ipv6Only, Self::DualStack]
    }

    /// Returns CI-compatible subset (IPv4 only for faster tests).
    #[must_use]
    pub fn ci_subset() -> &'static [Self] {
        &[Self::Ipv4Only]
    }

    /// Returns modes suitable for Docker testing (IPv4 only currently).
    #[must_use]
    pub fn docker_compatible() -> &'static [Self] {
        // Docker NAT emulation currently only supports IPv4
        &[Self::Ipv4Only]
    }

    /// Returns modes suitable for VPS testing (all modes).
    #[must_use]
    pub fn vps_compatible() -> &'static [Self] {
        // VPS nodes can test all IP modes
        &[Self::Ipv4Only, Self::Ipv6Only, Self::DualStack]
    }

    /// Check if this mode accepts IPv4 addresses.
    #[must_use]
    pub fn accepts_ipv4(&self) -> bool {
        matches!(self, Self::Ipv4Only | Self::DualStack)
    }

    /// Check if this mode accepts IPv6 addresses.
    #[must_use]
    pub fn accepts_ipv6(&self) -> bool {
        matches!(self, Self::Ipv6Only | Self::DualStack)
    }

    /// Check if an address is compatible with this IP mode.
    #[must_use]
    pub fn is_address_compatible(&self, addr: &std::net::IpAddr) -> bool {
        matches!(
            (self, addr),
            (Self::Ipv4Only, std::net::IpAddr::V4(_))
                | (Self::Ipv6Only, std::net::IpAddr::V6(_))
                | (Self::DualStack, _)
        )
    }

    /// Check if a socket address is compatible with this IP mode.
    #[must_use]
    pub fn is_socket_addr_compatible(&self, addr: &std::net::SocketAddr) -> bool {
        self.is_address_compatible(&addr.ip())
    }

    /// Filter addresses to only those compatible with this mode.
    pub fn filter_addresses<'a>(
        &self,
        addrs: impl IntoIterator<Item = &'a std::net::IpAddr>,
    ) -> Vec<std::net::IpAddr> {
        addrs
            .into_iter()
            .filter(|addr| self.is_address_compatible(addr))
            .copied()
            .collect()
    }

    /// Filter socket addresses to only those compatible with this mode.
    pub fn filter_socket_addrs<'a>(
        &self,
        addrs: impl IntoIterator<Item = &'a std::net::SocketAddr>,
    ) -> Vec<std::net::SocketAddr> {
        addrs
            .into_iter()
            .filter(|addr| self.is_socket_addr_compatible(addr))
            .copied()
            .collect()
    }

    /// Get the bind address for this IP mode.
    ///
    /// Returns the appropriate wildcard address for socket binding.
    #[must_use]
    pub fn bind_address(&self, port: u16) -> std::net::SocketAddr {
        match self {
            Self::Ipv4Only => std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port,
            ),
            Self::Ipv6Only => std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                port,
            ),
            Self::DualStack => {
                // Dual-stack uses IPv6 socket with V6ONLY=false
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    port,
                )
            }
        }
    }

    /// Get localhost address for this IP mode.
    #[must_use]
    pub fn localhost(&self, port: u16) -> std::net::SocketAddr {
        match self {
            Self::Ipv4Only => {
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
            }
            Self::Ipv6Only | Self::DualStack => {
                std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port)
            }
        }
    }

    /// Predict success rate modifier for this IP mode combination.
    ///
    /// IPv6 generally has better NAT traversal characteristics because:
    /// - Less NAT (more end-to-end connectivity)
    /// - Better support for hole punching
    /// - No CGNAT issues
    #[must_use]
    pub fn success_rate_modifier(&self, other: &Self) -> f64 {
        match (self, other) {
            // IPv6 to IPv6: Best case, often direct connectivity
            (Self::Ipv6Only, Self::Ipv6Only) => 1.15,
            // Dual-stack to dual-stack: Good, can use best available
            (Self::DualStack, Self::DualStack) => 1.10,
            // IPv4 to IPv4: Baseline
            (Self::Ipv4Only, Self::Ipv4Only) => 1.0,
            // Mixed modes with dual-stack: Works but may need fallback
            (Self::DualStack, _) | (_, Self::DualStack) => 1.05,
            // IPv4 to IPv6 or vice versa: Incompatible, needs relay
            (Self::Ipv4Only, Self::Ipv6Only) | (Self::Ipv6Only, Self::Ipv4Only) => 0.3,
        }
    }

    /// Check if two modes are directly compatible (can communicate).
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        match (self, other) {
            // Same mode: always compatible
            (Self::Ipv4Only, Self::Ipv4Only) => true,
            (Self::Ipv6Only, Self::Ipv6Only) => true,
            (Self::DualStack, Self::DualStack) => true,
            // Dual-stack is compatible with either
            (Self::DualStack, _) | (_, Self::DualStack) => true,
            // IPv4-only and IPv6-only are incompatible
            (Self::Ipv4Only, Self::Ipv6Only) | (Self::Ipv6Only, Self::Ipv4Only) => false,
        }
    }

    /// Get the address family preference for dual-stack mode.
    ///
    /// Returns IPv6 first (Happy Eyeballs preference).
    #[must_use]
    pub fn address_family_preference(&self) -> Vec<std::net::IpAddr> {
        match self {
            Self::Ipv4Only => vec![std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)],
            Self::Ipv6Only => vec![std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)],
            Self::DualStack => vec![
                // Prefer IPv6 (Happy Eyeballs)
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            ],
        }
    }

    /// Short identifier for dimension keys.
    #[must_use]
    pub fn short_id(&self) -> &'static str {
        match self {
            Self::Ipv4Only => "v4",
            Self::Ipv6Only => "v6",
            Self::DualStack => "ds",
        }
    }
}

/// Configuration for IP mode testing.
///
/// Provides detailed configuration for testing connectivity across
/// different IP addressing modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpModeConfig {
    /// The IP mode to test.
    pub mode: IpMode,
    /// Whether to require IPv6 support (fail if unavailable).
    pub require_ipv6: bool,
    /// Whether to test IPv4-mapped IPv6 addresses.
    pub test_ipv4_mapped: bool,
    /// Happy Eyeballs delay (ms) for dual-stack connection racing.
    pub happy_eyeballs_delay_ms: u32,
    /// Whether this config is CI-compatible.
    pub ci_compatible: bool,
    /// Docker network configuration (if applicable).
    pub docker_network: Option<DockerIpConfig>,
}

impl Default for IpModeConfig {
    fn default() -> Self {
        Self {
            mode: IpMode::Ipv4Only,
            require_ipv6: false,
            test_ipv4_mapped: false,
            happy_eyeballs_delay_ms: 250,
            ci_compatible: true,
            docker_network: None,
        }
    }
}

impl IpModeConfig {
    /// Create config for IPv4-only testing.
    #[must_use]
    pub fn ipv4_only() -> Self {
        Self {
            mode: IpMode::Ipv4Only,
            require_ipv6: false,
            test_ipv4_mapped: false,
            happy_eyeballs_delay_ms: 0, // Not applicable
            ci_compatible: true,
            docker_network: Some(DockerIpConfig::ipv4_only()),
        }
    }

    /// Create config for IPv6-only testing.
    #[must_use]
    pub fn ipv6_only() -> Self {
        Self {
            mode: IpMode::Ipv6Only,
            require_ipv6: true,
            test_ipv4_mapped: false,
            happy_eyeballs_delay_ms: 0, // Not applicable
            ci_compatible: false,       // IPv6 not always available in CI
            docker_network: Some(DockerIpConfig::ipv6_only()),
        }
    }

    /// Create config for dual-stack testing.
    #[must_use]
    pub fn dual_stack() -> Self {
        Self {
            mode: IpMode::DualStack,
            require_ipv6: false, // Graceful fallback to IPv4
            test_ipv4_mapped: true,
            happy_eyeballs_delay_ms: 250,
            ci_compatible: false, // Dual-stack not always available in CI
            docker_network: Some(DockerIpConfig::dual_stack()),
        }
    }

    /// Get all configurations for comprehensive testing.
    #[must_use]
    pub fn all_configs() -> Vec<Self> {
        vec![Self::ipv4_only(), Self::ipv6_only(), Self::dual_stack()]
    }

    /// Get CI-compatible configurations.
    #[must_use]
    pub fn ci_configs() -> Vec<Self> {
        vec![Self::ipv4_only()]
    }
}

/// Docker network IP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerIpConfig {
    /// Enable IPv6 in Docker network.
    pub enable_ipv6: bool,
    /// IPv4 subnet (e.g., "10.100.1.0/24").
    pub ipv4_subnet: Option<String>,
    /// IPv6 subnet (e.g., "fd00:1::/64").
    pub ipv6_subnet: Option<String>,
    /// IPv4 gateway address.
    pub ipv4_gateway: Option<String>,
    /// IPv6 gateway address.
    pub ipv6_gateway: Option<String>,
}

impl DockerIpConfig {
    /// Create IPv4-only Docker network config.
    #[must_use]
    pub fn ipv4_only() -> Self {
        Self {
            enable_ipv6: false,
            ipv4_subnet: Some("10.100.1.0/24".into()),
            ipv6_subnet: None,
            ipv4_gateway: Some("10.100.1.1".into()),
            ipv6_gateway: None,
        }
    }

    /// Create IPv6-only Docker network config.
    #[must_use]
    pub fn ipv6_only() -> Self {
        Self {
            enable_ipv6: true,
            ipv4_subnet: None,
            ipv6_subnet: Some("fd00:1::/64".into()),
            ipv4_gateway: None,
            ipv6_gateway: Some("fd00:1::1".into()),
        }
    }

    /// Create dual-stack Docker network config.
    #[must_use]
    pub fn dual_stack() -> Self {
        Self {
            enable_ipv6: true,
            ipv4_subnet: Some("10.100.1.0/24".into()),
            ipv6_subnet: Some("fd00:1::/64".into()),
            ipv4_gateway: Some("10.100.1.1".into()),
            ipv6_gateway: Some("fd00:1::1".into()),
        }
    }

    /// Generate Docker Compose network configuration YAML snippet.
    #[must_use]
    pub fn to_compose_yaml(&self, network_name: &str) -> String {
        let mut yaml = format!("  {}:\n", network_name);
        yaml.push_str("    driver: bridge\n");

        if self.enable_ipv6 {
            yaml.push_str("    enable_ipv6: true\n");
        }

        yaml.push_str("    ipam:\n");
        yaml.push_str("      config:\n");

        if let Some(ref subnet) = self.ipv4_subnet {
            yaml.push_str(&format!("        - subnet: {}\n", subnet));
            if let Some(ref gateway) = self.ipv4_gateway {
                yaml.push_str(&format!("          gateway: {}\n", gateway));
            }
        }

        if let Some(ref subnet) = self.ipv6_subnet {
            yaml.push_str(&format!("        - subnet: {}\n", subnet));
            if let Some(ref gateway) = self.ipv6_gateway {
                yaml.push_str(&format!("          gateway: {}\n", gateway));
            }
        }

        yaml
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueResult {
    pub technique: ConnectionTechnique,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub timestamp_ms: u64,
    pub data_proof: Option<DataProof>,
    pub method_proof: Option<MethodProof>,
}

impl TechniqueResult {
    pub fn success(technique: ConnectionTechnique, duration_ms: u64) -> Self {
        Self {
            technique,
            success: true,
            duration_ms,
            error: None,
            timestamp_ms: crate::registry::unix_timestamp_ms(),
            data_proof: None,
            method_proof: None,
        }
    }

    pub fn failure(technique: ConnectionTechnique, duration_ms: u64, error: &str) -> Self {
        Self {
            technique,
            success: false,
            duration_ms,
            error: Some(error.to_string()),
            timestamp_ms: crate::registry::unix_timestamp_ms(),
            data_proof: None,
            method_proof: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameCounters {
    pub add_address_sent: u32,
    pub add_address_received: u32,
    pub punch_me_now_sent: u32,
    pub punch_me_now_received: u32,
    pub observed_address_sent: u32,
    pub observed_address_received: u32,
    pub remove_address_sent: u32,
    pub remove_address_received: u32,
}

impl FrameCounters {
    pub fn total_sent(&self) -> u32 {
        self.add_address_sent
            + self.punch_me_now_sent
            + self.observed_address_sent
            + self.remove_address_sent
    }

    pub fn total_received(&self) -> u32 {
        self.add_address_received
            + self.punch_me_now_received
            + self.observed_address_received
            + self.remove_address_received
    }

    pub fn total(&self) -> u32 {
        self.total_sent() + self.total_received()
    }

    pub fn has_nat_activity(&self) -> bool {
        self.total() > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReferences {
    pub agent_a_log: Option<String>,
    pub agent_b_log: Option<String>,
    pub sut_a_log: Option<String>,
    pub sut_b_log: Option<String>,
    pub pcap_a: Option<String>,
    pub pcap_b: Option<String>,
    pub nat_state_a: Option<String>,
    pub nat_state_b: Option<String>,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: Uuid,
    pub scenario_id: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub total_attempts: u32,
    pub successful_attempts: u32,
    pub failed_attempts: u32,
    pub success_rate: f64,
    pub harness_failures: u32,
    pub sut_failures: u32,
    pub infrastructure_failures: u32,
    pub by_dimension: HashMap<String, DimensionStats>,
    pub by_path: HashMap<String, u32>,
    pub latency_p50_ms: Option<u64>,
    pub latency_p95_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
}

impl RunSummary {
    pub fn from_attempts(run_id: Uuid, scenario_id: &str, attempts: &[AttemptResult]) -> Self {
        let successful = attempts.iter().filter(|a| a.success).count() as u32;
        let failed = attempts.len() as u32 - successful;
        let success_rate = if attempts.is_empty() {
            0.0
        } else {
            successful as f64 / attempts.len() as f64
        };

        let harness_failures = attempts.iter().filter(|a| a.is_harness_failure()).count() as u32;
        let sut_failures = attempts.iter().filter(|a| a.is_sut_failure()).count() as u32;
        let infrastructure_failures = attempts
            .iter()
            .filter(|a| a.is_infrastructure_failure())
            .count() as u32;

        let mut by_dimension: HashMap<String, DimensionStats> = HashMap::new();
        let mut by_path: HashMap<String, u32> = HashMap::new();

        for attempt in attempts {
            let key = attempt.dimension_key();
            let stats = by_dimension.entry(key).or_default();
            stats.total += 1;
            if attempt.success {
                stats.successful += 1;
            }

            if let Some(path) = &attempt.path_used {
                *by_path.entry(format!("{:?}", path)).or_insert(0) += 1;
            }
        }

        for stats in by_dimension.values_mut() {
            stats.success_rate = if stats.total > 0 {
                stats.successful as f64 / stats.total as f64
            } else {
                0.0
            };
        }

        let mut latencies: Vec<u64> = attempts.iter().filter_map(|a| a.connect_time_ms).collect();
        latencies.sort_unstable();

        let latency_p50_ms = percentile(&latencies, 50);
        let latency_p95_ms = percentile(&latencies, 95);
        let latency_p99_ms = percentile(&latencies, 99);

        let started_at_ms = attempts.iter().map(|a| a.timestamp_ms).min().unwrap_or(0);
        let completed_at_ms = attempts.iter().map(|a| a.timestamp_ms).max().unwrap_or(0);

        Self {
            run_id,
            scenario_id: scenario_id.to_string(),
            started_at_ms,
            completed_at_ms,
            total_attempts: attempts.len() as u32,
            successful_attempts: successful,
            failed_attempts: failed,
            success_rate,
            harness_failures,
            sut_failures,
            infrastructure_failures,
            by_dimension,
            by_path,
            latency_p50_ms,
            latency_p95_ms,
            latency_p99_ms,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.harness_failures == 0 && self.success_rate >= 0.95
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DimensionStats {
    pub total: u32,
    pub successful: u32,
    pub success_rate: f64,
}

fn percentile(sorted: &[u64], p: u32) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = (sorted.len() as f64 * (p as f64 / 100.0)).ceil() as usize;
    Some(sorted[idx.saturating_sub(1).min(sorted.len() - 1)])
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{NatScenario, TemporalScenario};

    #[test]
    fn test_attempt_result_new() {
        let run_id = Uuid::new_v4();
        let result = AttemptResult::new(run_id, "connectivity_matrix", 1);
        assert_eq!(result.run_id, run_id);
        assert_eq!(result.scenario_id, "connectivity_matrix");
        assert_eq!(result.attempt_id, 1);
        assert!(!result.success);
    }

    #[test]
    fn test_attempt_result_success() {
        let mut result = AttemptResult::new(Uuid::new_v4(), "test", 1);
        result.record_success(ConnectionMethod::HolePunched, 150, SuccessLevel::Usable);
        assert!(result.success);
        assert_eq!(result.path_used, Some(ConnectionMethod::HolePunched));
        assert_eq!(result.connect_time_ms, Some(150));
        assert!(result.is_passing());
    }

    #[test]
    fn test_attempt_result_failure() {
        let mut result = AttemptResult::new(Uuid::new_v4(), "test", 1);
        result.record_failure(
            "Connection timed out",
            FailureReasonCode::Timeout,
            FailureCategory::SutConnectivityFailure,
        );
        assert!(!result.success);
        assert!(result.is_sut_failure());
        assert!(!result.is_harness_failure());
    }

    #[test]
    fn test_ip_mode_display() {
        assert_eq!(IpMode::Ipv4Only.to_string(), "IPv4");
        assert_eq!(IpMode::Ipv6Only.to_string(), "IPv6");
        assert_eq!(IpMode::DualStack.to_string(), "Dual-Stack");
    }

    #[test]
    fn test_frame_counters() {
        let mut frames = FrameCounters::default();
        assert!(!frames.has_nat_activity());

        frames.add_address_sent = 2;
        frames.punch_me_now_received = 1;
        assert!(frames.has_nat_activity());
        assert_eq!(frames.total_sent(), 2);
        assert_eq!(frames.total_received(), 1);
        assert_eq!(frames.total(), 3);
    }

    #[test]
    fn test_run_summary() {
        let run_id = Uuid::new_v4();
        let mut attempts = vec![];

        for i in 0..10 {
            let mut result = AttemptResult::new(run_id, "test", i);
            if i < 8 {
                result.record_success(
                    ConnectionMethod::Direct,
                    50 + i as u64 * 10,
                    SuccessLevel::Usable,
                );
            } else {
                result.record_failure(
                    "timeout",
                    FailureReasonCode::Timeout,
                    FailureCategory::SutConnectivityFailure,
                );
            }
            attempts.push(result);
        }

        let summary = RunSummary::from_attempts(run_id, "test", &attempts);
        assert_eq!(summary.total_attempts, 10);
        assert_eq!(summary.successful_attempts, 8);
        assert_eq!(summary.failed_attempts, 2);
        assert!((summary.success_rate - 0.8).abs() < 0.01);
        assert_eq!(summary.sut_failures, 2);
        assert_eq!(summary.harness_failures, 0);
    }

    #[test]
    fn test_attempt_result_has_nat_scenario() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1);
        assert_eq!(result.nat_scenario, NatScenario::BothPublic);
    }

    #[test]
    fn test_attempt_result_has_temporal_scenario() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1);
        assert_eq!(result.temporal_scenario, TemporalScenario::ColdStart);
    }

    #[test]
    fn test_attempt_result_has_retry_index() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1);
        assert_eq!(result.retry_index, 0);
    }

    #[test]
    fn test_with_full_dimensions() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1)
            .with_dimensions(NatType::FullCone, NatType::Symmetric, IpMode::DualStack)
            .with_scenario_dimensions(NatScenario::DoubleNat, TemporalScenario::WarmReconnect);

        assert_eq!(result.nat_a, NatType::FullCone);
        assert_eq!(result.nat_b, NatType::Symmetric);
        assert_eq!(result.ip_mode, IpMode::DualStack);
        assert_eq!(result.nat_scenario, NatScenario::DoubleNat);
        assert_eq!(result.temporal_scenario, TemporalScenario::WarmReconnect);
    }

    #[test]
    fn test_dimension_key_includes_all_dimensions() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1)
            .with_dimensions(NatType::FullCone, NatType::Symmetric, IpMode::DualStack)
            .with_scenario_dimensions(NatScenario::DoubleNat, TemporalScenario::WarmReconnect);

        let key = result.dimension_key();
        assert!(key.contains("full_cone"), "Key should contain nat_a");
        assert!(key.contains("symmetric"), "Key should contain nat_b");
        assert!(key.contains("dual_stack"), "Key should contain ip_mode");
        assert!(
            key.contains("double_nat"),
            "Key should contain nat_scenario"
        );
        assert!(
            key.contains("warm_reconnect"),
            "Key should contain temporal_scenario"
        );
    }

    #[test]
    fn test_full_dimension_key_stable_format() {
        let result = AttemptResult::new(Uuid::new_v4(), "test", 1)
            .with_dimensions(NatType::FullCone, NatType::Symmetric, IpMode::Ipv4Only)
            .with_scenario_dimensions(NatScenario::BothPublic, TemporalScenario::ColdStart);

        let key = result.full_dimension_key();
        assert_eq!(
            key,
            "full_cone_symmetric_ipv4_only_both_public_cold_start_outbound"
        );
    }

    // =========================================================================
    // IpMode tests
    // =========================================================================

    #[test]
    fn test_ip_mode_all() {
        let modes = IpMode::all();
        assert_eq!(modes.len(), 3);
        assert!(modes.contains(&IpMode::Ipv4Only));
        assert!(modes.contains(&IpMode::Ipv6Only));
        assert!(modes.contains(&IpMode::DualStack));
    }

    #[test]
    fn test_ip_mode_ci_subset() {
        let modes = IpMode::ci_subset();
        assert_eq!(modes.len(), 1);
        assert!(modes.contains(&IpMode::Ipv4Only));
    }

    #[test]
    fn test_ip_mode_accepts() {
        // IPv4Only
        assert!(IpMode::Ipv4Only.accepts_ipv4());
        assert!(!IpMode::Ipv4Only.accepts_ipv6());

        // IPv6Only
        assert!(!IpMode::Ipv6Only.accepts_ipv4());
        assert!(IpMode::Ipv6Only.accepts_ipv6());

        // DualStack
        assert!(IpMode::DualStack.accepts_ipv4());
        assert!(IpMode::DualStack.accepts_ipv6());
    }

    #[test]
    fn test_ip_mode_address_compatibility() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        // IPv4Only mode
        assert!(IpMode::Ipv4Only.is_address_compatible(&v4));
        assert!(!IpMode::Ipv4Only.is_address_compatible(&v6));

        // IPv6Only mode
        assert!(!IpMode::Ipv6Only.is_address_compatible(&v4));
        assert!(IpMode::Ipv6Only.is_address_compatible(&v6));

        // DualStack mode
        assert!(IpMode::DualStack.is_address_compatible(&v4));
        assert!(IpMode::DualStack.is_address_compatible(&v6));
    }

    #[test]
    fn test_ip_mode_filter_addresses() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        // IPv4Only keeps only IPv4
        let filtered = IpMode::Ipv4Only.filter_addresses(&addrs);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|a| a.is_ipv4()));

        // IPv6Only keeps only IPv6
        let filtered = IpMode::Ipv6Only.filter_addresses(&addrs);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.iter().all(|a| a.is_ipv6()));

        // DualStack keeps all
        let filtered = IpMode::DualStack.filter_addresses(&addrs);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_ip_mode_bind_address() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let v4_bind = IpMode::Ipv4Only.bind_address(9000);
        assert_eq!(v4_bind.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(v4_bind.port(), 9000);

        let v6_bind = IpMode::Ipv6Only.bind_address(9000);
        assert_eq!(v6_bind.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(v6_bind.port(), 9000);

        // DualStack uses IPv6 socket (with V6ONLY=false)
        let ds_bind = IpMode::DualStack.bind_address(9000);
        assert_eq!(ds_bind.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(ds_bind.port(), 9000);
    }

    #[test]
    fn test_ip_mode_localhost() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let v4_local = IpMode::Ipv4Only.localhost(8080);
        assert_eq!(v4_local.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

        let v6_local = IpMode::Ipv6Only.localhost(8080);
        assert_eq!(v6_local.ip(), std::net::IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_ip_mode_compatibility() {
        // Same mode is always compatible
        assert!(IpMode::Ipv4Only.is_compatible_with(&IpMode::Ipv4Only));
        assert!(IpMode::Ipv6Only.is_compatible_with(&IpMode::Ipv6Only));
        assert!(IpMode::DualStack.is_compatible_with(&IpMode::DualStack));

        // DualStack is compatible with both
        assert!(IpMode::DualStack.is_compatible_with(&IpMode::Ipv4Only));
        assert!(IpMode::DualStack.is_compatible_with(&IpMode::Ipv6Only));
        assert!(IpMode::Ipv4Only.is_compatible_with(&IpMode::DualStack));
        assert!(IpMode::Ipv6Only.is_compatible_with(&IpMode::DualStack));

        // IPv4 and IPv6 only are NOT compatible
        assert!(!IpMode::Ipv4Only.is_compatible_with(&IpMode::Ipv6Only));
        assert!(!IpMode::Ipv6Only.is_compatible_with(&IpMode::Ipv4Only));
    }

    #[test]
    fn test_ip_mode_success_rate_modifier() {
        // IPv6 to IPv6 is best
        assert!(IpMode::Ipv6Only.success_rate_modifier(&IpMode::Ipv6Only) > 1.0);

        // IPv4 to IPv4 is baseline
        assert_eq!(
            IpMode::Ipv4Only.success_rate_modifier(&IpMode::Ipv4Only),
            1.0
        );

        // Incompatible modes have low success rate
        assert!(IpMode::Ipv4Only.success_rate_modifier(&IpMode::Ipv6Only) < 0.5);
    }

    #[test]
    fn test_ip_mode_short_id() {
        assert_eq!(IpMode::Ipv4Only.short_id(), "v4");
        assert_eq!(IpMode::Ipv6Only.short_id(), "v6");
        assert_eq!(IpMode::DualStack.short_id(), "ds");
    }

    // =========================================================================
    // IpModeConfig tests
    // =========================================================================

    #[test]
    fn test_ip_mode_config_ipv4_only() {
        let config = IpModeConfig::ipv4_only();
        assert_eq!(config.mode, IpMode::Ipv4Only);
        assert!(!config.require_ipv6);
        assert!(config.ci_compatible);
        assert!(config.docker_network.is_some());
    }

    #[test]
    fn test_ip_mode_config_ipv6_only() {
        let config = IpModeConfig::ipv6_only();
        assert_eq!(config.mode, IpMode::Ipv6Only);
        assert!(config.require_ipv6);
        assert!(!config.ci_compatible); // IPv6 not always available
    }

    #[test]
    fn test_ip_mode_config_dual_stack() {
        let config = IpModeConfig::dual_stack();
        assert_eq!(config.mode, IpMode::DualStack);
        assert!(config.test_ipv4_mapped);
        assert_eq!(config.happy_eyeballs_delay_ms, 250);
    }

    #[test]
    fn test_ip_mode_config_all_configs() {
        let configs = IpModeConfig::all_configs();
        assert_eq!(configs.len(), 3);
    }

    #[test]
    fn test_ip_mode_config_ci_configs() {
        let configs = IpModeConfig::ci_configs();
        assert!(configs.iter().all(|c| c.ci_compatible));
    }

    // =========================================================================
    // DockerIpConfig tests
    // =========================================================================

    #[test]
    fn test_docker_ip_config_ipv4_only() {
        let config = DockerIpConfig::ipv4_only();
        assert!(!config.enable_ipv6);
        assert!(config.ipv4_subnet.is_some());
        assert!(config.ipv6_subnet.is_none());
    }

    #[test]
    fn test_docker_ip_config_ipv6_only() {
        let config = DockerIpConfig::ipv6_only();
        assert!(config.enable_ipv6);
        assert!(config.ipv4_subnet.is_none());
        assert!(config.ipv6_subnet.is_some());
    }

    #[test]
    fn test_docker_ip_config_dual_stack() {
        let config = DockerIpConfig::dual_stack();
        assert!(config.enable_ipv6);
        assert!(config.ipv4_subnet.is_some());
        assert!(config.ipv6_subnet.is_some());
    }

    #[test]
    fn test_docker_ip_config_to_compose_yaml() {
        let config = DockerIpConfig::dual_stack();
        let yaml = config.to_compose_yaml("test-network");

        assert!(yaml.contains("test-network:"));
        assert!(yaml.contains("driver: bridge"));
        assert!(yaml.contains("enable_ipv6: true"));
        assert!(yaml.contains("10.100.1.0/24")); // IPv4 subnet
        assert!(yaml.contains("fd00:1::/64")); // IPv6 subnet
    }
}
