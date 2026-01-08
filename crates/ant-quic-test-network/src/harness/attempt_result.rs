use crate::registry::{
    ConnectionMethod, ConnectionTechnique, ConnectivityMatrix, DataProof, FailureReasonCode,
    ImpairmentMetrics, MethodProof, MigrationMetrics, NatType, NetworkProfile, RelayMetrics,
    SuccessLevel, TemporalMetrics, TestPattern,
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
        format!("{:?}_{:?}_{:?}", self.nat_a, self.nat_b, self.ip_mode)
    }

    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
    #[default]
    Ipv4Only,
    Ipv6Only,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
