//! Harness Correctness Metrics
//!
//! Metrics for measuring harness health and distinguishing harness bugs from SUT failures.
//!
//! # Metrics
//!
//! - **Run Completeness**: Percentage of expected tests that completed
//! - **Stage Health**: Time spent in stages, timeout counts
//! - **Agent Health**: Heartbeat status, resource utilization
//! - **Artifact Integrity**: Manifest validation, checksum verification
//! - **Determinism Score**: Same inputs should produce same classification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Top-level harness metrics container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessMetrics {
    pub run_id: Uuid,
    pub collected_at_ms: u64,
    pub completeness: RunCompletenessMetric,
    pub stage_health: StageHealthMetric,
    pub agent_health: AgentHealthMetric,
    pub artifact_integrity: ArtifactIntegrityMetric,
    pub determinism: DeterminismScore,
}

impl HarnessMetrics {
    /// Create a new metrics container for a run
    pub fn new(run_id: Uuid) -> Self {
        Self {
            run_id,
            collected_at_ms: crate::registry::unix_timestamp_ms(),
            completeness: RunCompletenessMetric::default(),
            stage_health: StageHealthMetric::default(),
            agent_health: AgentHealthMetric::default(),
            artifact_integrity: ArtifactIntegrityMetric::default(),
            determinism: DeterminismScore::default(),
        }
    }

    /// Returns true if the harness itself is healthy (not the SUT)
    pub fn is_harness_healthy(&self) -> bool {
        self.completeness.is_healthy()
            && self.stage_health.is_healthy()
            && self.agent_health.is_healthy()
            && self.artifact_integrity.is_healthy()
    }

    /// Overall harness health score (0.0 - 1.0)
    pub fn health_score(&self) -> f64 {
        let scores = [
            self.completeness.score(),
            self.stage_health.score(),
            self.agent_health.score(),
            self.artifact_integrity.score(),
        ];
        scores.iter().sum::<f64>() / scores.len() as f64
    }
}

/// Tracks run completeness - what percentage of expected tests completed
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunCompletenessMetric {
    pub expected_attempts: u32,
    pub completed_attempts: u32,
    pub started_attempts: u32,
    pub skipped_attempts: u32,
    pub timed_out_attempts: u32,
}

impl RunCompletenessMetric {
    /// Completion percentage (0.0 - 1.0)
    pub fn completion_rate(&self) -> f64 {
        if self.expected_attempts == 0 {
            return 1.0;
        }
        self.completed_attempts as f64 / self.expected_attempts as f64
    }

    /// Started but not completed rate (indicates hangs/crashes)
    pub fn incomplete_rate(&self) -> f64 {
        if self.started_attempts == 0 {
            return 0.0;
        }
        let incomplete = self
            .started_attempts
            .saturating_sub(self.completed_attempts);
        incomplete as f64 / self.started_attempts as f64
    }

    /// Timeout rate (indicates slow tests or resource starvation)
    pub fn timeout_rate(&self) -> f64 {
        if self.expected_attempts == 0 {
            return 0.0;
        }
        self.timed_out_attempts as f64 / self.expected_attempts as f64
    }

    /// Is completeness healthy? (≥95% completion, <5% timeout)
    pub fn is_healthy(&self) -> bool {
        self.completion_rate() >= 0.95 && self.timeout_rate() < 0.05
    }

    /// Score (0.0 - 1.0) based on completion and timeout rates
    pub fn score(&self) -> f64 {
        let completion_score = self.completion_rate();
        let timeout_penalty = self.timeout_rate() * 0.5;
        (completion_score - timeout_penalty).max(0.0)
    }
}

/// Tracks stage health - time spent in each stage and timeouts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageHealthMetric {
    pub stages: HashMap<String, StageTiming>,
}

/// Timing information for a single stage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTiming {
    pub stage_name: String,
    pub invocations: u32,
    pub total_duration_ms: u64,
    pub min_duration_ms: Option<u64>,
    pub max_duration_ms: Option<u64>,
    pub timeouts: u32,
    pub failures: u32,
}

impl StageTiming {
    /// Average duration in milliseconds
    pub fn avg_duration_ms(&self) -> Option<u64> {
        if self.invocations == 0 {
            return None;
        }
        Some(self.total_duration_ms / self.invocations as u64)
    }

    /// Timeout rate for this stage
    pub fn timeout_rate(&self) -> f64 {
        if self.invocations == 0 {
            return 0.0;
        }
        self.timeouts as f64 / self.invocations as f64
    }

    /// Failure rate for this stage
    pub fn failure_rate(&self) -> f64 {
        if self.invocations == 0 {
            return 0.0;
        }
        self.failures as f64 / self.invocations as f64
    }

    /// Record a stage execution
    pub fn record(&mut self, duration_ms: u64, timed_out: bool, failed: bool) {
        self.invocations += 1;
        self.total_duration_ms += duration_ms;
        self.min_duration_ms = Some(
            self.min_duration_ms
                .map(|m| m.min(duration_ms))
                .unwrap_or(duration_ms),
        );
        self.max_duration_ms = Some(
            self.max_duration_ms
                .map(|m| m.max(duration_ms))
                .unwrap_or(duration_ms),
        );
        if timed_out {
            self.timeouts += 1;
        }
        if failed {
            self.failures += 1;
        }
    }
}

impl StageHealthMetric {
    /// Record timing for a stage
    pub fn record_stage(&mut self, stage: &str, duration_ms: u64, timed_out: bool, failed: bool) {
        let timing = self
            .stages
            .entry(stage.to_string())
            .or_insert_with(|| StageTiming {
                stage_name: stage.to_string(),
                ..Default::default()
            });
        timing.record(duration_ms, timed_out, failed);
    }

    /// Overall stage health - no stage with >5% timeout or >10% failure
    pub fn is_healthy(&self) -> bool {
        self.stages
            .values()
            .all(|s| s.timeout_rate() < 0.05 && s.failure_rate() < 0.10)
    }

    /// Score based on stage health (0.0 - 1.0)
    pub fn score(&self) -> f64 {
        if self.stages.is_empty() {
            return 1.0;
        }
        let stage_scores: Vec<f64> = self
            .stages
            .values()
            .map(|s| {
                let timeout_penalty = s.timeout_rate() * 0.3;
                let failure_penalty = s.failure_rate() * 0.5;
                (1.0 - timeout_penalty - failure_penalty).max(0.0)
            })
            .collect();
        stage_scores.iter().sum::<f64>() / stage_scores.len() as f64
    }
}

/// Tracks agent health - heartbeat, resources, connectivity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHealthMetric {
    pub agents: HashMap<String, AgentHealthStatus>,
}

/// Health status for a single agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthStatus {
    pub agent_id: String,
    pub last_heartbeat_ms: u64,
    pub heartbeat_count: u32,
    pub missed_heartbeats: u32,
    pub cpu_percent: Option<f32>,
    pub memory_percent: Option<f32>,
    pub disk_percent: Option<f32>,
    pub connection_failures: u32,
    pub is_responsive: bool,
}

impl Default for AgentHealthStatus {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            last_heartbeat_ms: 0,
            heartbeat_count: 0,
            missed_heartbeats: 0,
            cpu_percent: None,
            memory_percent: None,
            disk_percent: None,
            connection_failures: 0,
            is_responsive: true,
        }
    }
}

impl AgentHealthStatus {
    /// Create a new agent health status
    pub fn new(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            ..Default::default()
        }
    }

    /// Record a successful heartbeat
    pub fn record_heartbeat(&mut self, timestamp_ms: u64) {
        self.last_heartbeat_ms = timestamp_ms;
        self.heartbeat_count += 1;
        self.is_responsive = true;
    }

    /// Record a missed heartbeat
    pub fn record_missed_heartbeat(&mut self) {
        self.missed_heartbeats += 1;
        // After 3 consecutive misses, mark as unresponsive
        if self.missed_heartbeats >= 3 {
            self.is_responsive = false;
        }
    }

    /// Record resource usage
    pub fn record_resources(&mut self, cpu: Option<f32>, memory: Option<f32>, disk: Option<f32>) {
        self.cpu_percent = cpu;
        self.memory_percent = memory;
        self.disk_percent = disk;
    }

    /// Is this agent under resource pressure?
    pub fn is_resource_constrained(&self) -> bool {
        self.cpu_percent.is_some_and(|c| c > 90.0)
            || self.memory_percent.is_some_and(|m| m > 90.0)
            || self.disk_percent.is_some_and(|d| d > 95.0)
    }

    /// Heartbeat reliability (0.0 - 1.0)
    pub fn heartbeat_reliability(&self) -> f64 {
        let total = self.heartbeat_count + self.missed_heartbeats;
        if total == 0 {
            return 1.0;
        }
        self.heartbeat_count as f64 / total as f64
    }
}

impl AgentHealthMetric {
    /// Record a heartbeat for an agent
    pub fn record_heartbeat(&mut self, agent_id: &str, timestamp_ms: u64) {
        let status = self
            .agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentHealthStatus::new(agent_id));
        status.record_heartbeat(timestamp_ms);
    }

    /// Record a missed heartbeat for an agent
    pub fn record_missed_heartbeat(&mut self, agent_id: &str) {
        let status = self
            .agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentHealthStatus::new(agent_id));
        status.record_missed_heartbeat();
    }

    /// Get count of responsive agents
    pub fn responsive_count(&self) -> usize {
        self.agents.values().filter(|a| a.is_responsive).count()
    }

    /// Get count of unresponsive agents
    pub fn unresponsive_count(&self) -> usize {
        self.agents.values().filter(|a| !a.is_responsive).count()
    }

    /// Is agent health acceptable? (all agents responsive)
    pub fn is_healthy(&self) -> bool {
        self.agents.values().all(|a| a.is_responsive)
    }

    /// Score based on agent health (0.0 - 1.0)
    pub fn score(&self) -> f64 {
        if self.agents.is_empty() {
            return 1.0;
        }
        let responsive = self.responsive_count();
        responsive as f64 / self.agents.len() as f64
    }
}

/// Tracks artifact integrity - manifest validation and checksums
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactIntegrityMetric {
    pub total_artifacts: u32,
    pub valid_artifacts: u32,
    pub missing_artifacts: u32,
    pub corrupted_artifacts: u32,
    pub checksum_failures: u32,
    pub manifest_errors: u32,
}

impl ArtifactIntegrityMetric {
    /// Record a valid artifact
    pub fn record_valid(&mut self) {
        self.total_artifacts += 1;
        self.valid_artifacts += 1;
    }

    /// Record a missing artifact
    pub fn record_missing(&mut self) {
        self.total_artifacts += 1;
        self.missing_artifacts += 1;
    }

    /// Record a corrupted artifact (checksum mismatch)
    pub fn record_corrupted(&mut self) {
        self.total_artifacts += 1;
        self.corrupted_artifacts += 1;
        self.checksum_failures += 1;
    }

    /// Record a manifest error
    pub fn record_manifest_error(&mut self) {
        self.manifest_errors += 1;
    }

    /// Integrity rate (valid / total)
    pub fn integrity_rate(&self) -> f64 {
        if self.total_artifacts == 0 {
            return 1.0;
        }
        self.valid_artifacts as f64 / self.total_artifacts as f64
    }

    /// Is artifact integrity acceptable? (≥99% valid, 0 manifest errors)
    pub fn is_healthy(&self) -> bool {
        self.integrity_rate() >= 0.99 && self.manifest_errors == 0
    }

    /// Score based on integrity (0.0 - 1.0)
    pub fn score(&self) -> f64 {
        let base_score = self.integrity_rate();
        let manifest_penalty = if self.manifest_errors > 0 { 0.2 } else { 0.0 };
        (base_score - manifest_penalty).max(0.0)
    }
}

/// Determinism score - same inputs should produce same classification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeterminismScore {
    pub total_comparisons: u32,
    pub matching_classifications: u32,
    pub divergent_classifications: u32,
    pub divergences: Vec<DeterminismDivergence>,
}

/// Records a single divergence in classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismDivergence {
    pub attempt_id: String,
    pub run_a: Uuid,
    pub run_b: Uuid,
    pub classification_a: String,
    pub classification_b: String,
    pub input_hash: String,
}

impl DeterminismScore {
    /// Record a comparison between two runs with same inputs
    pub fn record_comparison(&mut self, matched: bool) {
        self.total_comparisons += 1;
        if matched {
            self.matching_classifications += 1;
        } else {
            self.divergent_classifications += 1;
        }
    }

    /// Record a specific divergence
    pub fn record_divergence(&mut self, divergence: DeterminismDivergence) {
        self.divergent_classifications += 1;
        self.total_comparisons += 1;
        self.divergences.push(divergence);
    }

    /// Determinism rate (0.0 - 1.0)
    pub fn determinism_rate(&self) -> f64 {
        if self.total_comparisons == 0 {
            return 1.0;
        }
        self.matching_classifications as f64 / self.total_comparisons as f64
    }

    /// Is determinism acceptable? (≥99% matching)
    pub fn is_deterministic(&self) -> bool {
        self.determinism_rate() >= 0.99
    }

    /// Score (same as determinism rate)
    pub fn score(&self) -> f64 {
        self.determinism_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // HarnessMetrics Tests
    // ============================================================

    #[test]
    fn test_harness_metrics_new() {
        let run_id = Uuid::new_v4();
        let metrics = HarnessMetrics::new(run_id);
        assert_eq!(metrics.run_id, run_id);
        assert!(metrics.collected_at_ms > 0);
    }

    #[test]
    fn test_harness_metrics_healthy_when_all_healthy() {
        let mut metrics = HarnessMetrics::new(Uuid::new_v4());

        // Set up healthy metrics
        metrics.completeness.expected_attempts = 100;
        metrics.completeness.completed_attempts = 100;
        metrics.completeness.started_attempts = 100;

        metrics.agent_health.record_heartbeat("agent-1", 1000);
        metrics.agent_health.record_heartbeat("agent-2", 1000);

        metrics.artifact_integrity.valid_artifacts = 50;
        metrics.artifact_integrity.total_artifacts = 50;

        assert!(metrics.is_harness_healthy());
        assert!(metrics.health_score() > 0.9);
    }

    #[test]
    fn test_harness_metrics_unhealthy_when_completion_low() {
        let mut metrics = HarnessMetrics::new(Uuid::new_v4());

        metrics.completeness.expected_attempts = 100;
        metrics.completeness.completed_attempts = 50; // Only 50% completion
        metrics.completeness.started_attempts = 100;

        assert!(!metrics.is_harness_healthy());
    }

    // ============================================================
    // RunCompletenessMetric Tests
    // ============================================================

    #[test]
    fn test_completeness_rate_calculation() {
        let metric = RunCompletenessMetric {
            expected_attempts: 100,
            completed_attempts: 80,
            ..Default::default()
        };

        assert!((metric.completion_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_completeness_rate_empty() {
        let metric = RunCompletenessMetric::default();
        assert!((metric.completion_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_incomplete_rate_calculation() {
        let metric = RunCompletenessMetric {
            started_attempts: 100,
            completed_attempts: 90,
            ..Default::default()
        };

        assert!((metric.incomplete_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_timeout_rate_calculation() {
        let metric = RunCompletenessMetric {
            expected_attempts: 100,
            timed_out_attempts: 5,
            ..Default::default()
        };

        assert!((metric.timeout_rate() - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_completeness_healthy() {
        let metric = RunCompletenessMetric {
            expected_attempts: 100,
            completed_attempts: 98,
            timed_out_attempts: 2,
            ..Default::default()
        };

        assert!(metric.is_healthy());
    }

    #[test]
    fn test_completeness_unhealthy_low_completion() {
        let metric = RunCompletenessMetric {
            expected_attempts: 100,
            completed_attempts: 90, // Below 95%
            ..Default::default()
        };

        assert!(!metric.is_healthy());
    }

    #[test]
    fn test_completeness_unhealthy_high_timeout() {
        let metric = RunCompletenessMetric {
            expected_attempts: 100,
            completed_attempts: 95,
            timed_out_attempts: 10, // 10% timeout
            ..Default::default()
        };

        assert!(!metric.is_healthy());
    }

    // ============================================================
    // StageHealthMetric Tests
    // ============================================================

    #[test]
    fn test_stage_timing_record() {
        let mut timing = StageTiming::default();
        timing.record(100, false, false);
        timing.record(200, false, false);
        timing.record(150, true, false);

        assert_eq!(timing.invocations, 3);
        assert_eq!(timing.total_duration_ms, 450);
        assert_eq!(timing.min_duration_ms, Some(100));
        assert_eq!(timing.max_duration_ms, Some(200));
        assert_eq!(timing.timeouts, 1);
    }

    #[test]
    fn test_stage_timing_avg_duration() {
        let mut timing = StageTiming::default();
        timing.record(100, false, false);
        timing.record(200, false, false);

        assert_eq!(timing.avg_duration_ms(), Some(150));
    }

    #[test]
    fn test_stage_timing_timeout_rate() {
        let mut timing = StageTiming::default();
        timing.record(100, false, false);
        timing.record(100, true, false);
        timing.record(100, false, false);
        timing.record(100, true, false);

        assert!((timing.timeout_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_stage_health_record() {
        let mut health = StageHealthMetric::default();
        health.record_stage("preflight", 100, false, false);
        health.record_stage("preflight", 150, false, false);
        health.record_stage("execution", 500, false, false);

        assert_eq!(health.stages.len(), 2);
        assert_eq!(health.stages["preflight"].invocations, 2);
        assert_eq!(health.stages["execution"].invocations, 1);
    }

    #[test]
    fn test_stage_health_healthy() {
        let mut health = StageHealthMetric::default();
        for _ in 0..100 {
            health.record_stage("preflight", 100, false, false);
        }
        health.record_stage("preflight", 100, true, false); // 1% timeout

        assert!(health.is_healthy());
    }

    #[test]
    fn test_stage_health_unhealthy_high_timeout() {
        let mut health = StageHealthMetric::default();
        for _ in 0..10 {
            health.record_stage("preflight", 100, true, false); // 100% timeout
        }

        assert!(!health.is_healthy());
    }

    // ============================================================
    // AgentHealthMetric Tests
    // ============================================================

    #[test]
    fn test_agent_health_record_heartbeat() {
        let mut health = AgentHealthMetric::default();
        health.record_heartbeat("agent-1", 1000);
        health.record_heartbeat("agent-1", 2000);

        let agent = &health.agents["agent-1"];
        assert_eq!(agent.heartbeat_count, 2);
        assert_eq!(agent.last_heartbeat_ms, 2000);
        assert!(agent.is_responsive);
    }

    #[test]
    fn test_agent_health_missed_heartbeats() {
        let mut health = AgentHealthMetric::default();
        health.record_heartbeat("agent-1", 1000);
        health.record_missed_heartbeat("agent-1");
        health.record_missed_heartbeat("agent-1");

        let agent = &health.agents["agent-1"];
        assert_eq!(agent.missed_heartbeats, 2);
        assert!(agent.is_responsive); // Still responsive after 2 misses
    }

    #[test]
    fn test_agent_health_unresponsive_after_3_misses() {
        let mut health = AgentHealthMetric::default();
        health.record_heartbeat("agent-1", 1000);
        health.record_missed_heartbeat("agent-1");
        health.record_missed_heartbeat("agent-1");
        health.record_missed_heartbeat("agent-1");

        let agent = &health.agents["agent-1"];
        assert!(!agent.is_responsive);
    }

    #[test]
    fn test_agent_health_resource_constrained() {
        let mut status = AgentHealthStatus::new("agent-1");
        status.record_resources(Some(95.0), Some(50.0), Some(50.0));
        assert!(status.is_resource_constrained());

        status.record_resources(Some(50.0), Some(95.0), Some(50.0));
        assert!(status.is_resource_constrained());

        status.record_resources(Some(50.0), Some(50.0), Some(50.0));
        assert!(!status.is_resource_constrained());
    }

    #[test]
    fn test_agent_health_responsive_count() {
        let mut health = AgentHealthMetric::default();
        health.record_heartbeat("agent-1", 1000);
        health.record_heartbeat("agent-2", 1000);
        health.record_heartbeat("agent-3", 1000);

        // Make agent-3 unresponsive
        health.record_missed_heartbeat("agent-3");
        health.record_missed_heartbeat("agent-3");
        health.record_missed_heartbeat("agent-3");

        assert_eq!(health.responsive_count(), 2);
        assert_eq!(health.unresponsive_count(), 1);
    }

    #[test]
    fn test_agent_health_is_healthy() {
        let mut health = AgentHealthMetric::default();
        health.record_heartbeat("agent-1", 1000);
        health.record_heartbeat("agent-2", 1000);

        assert!(health.is_healthy());

        // Make agent-2 unresponsive
        for _ in 0..3 {
            health.record_missed_heartbeat("agent-2");
        }

        assert!(!health.is_healthy());
    }

    // ============================================================
    // ArtifactIntegrityMetric Tests
    // ============================================================

    #[test]
    fn test_artifact_integrity_valid() {
        let mut integrity = ArtifactIntegrityMetric::default();
        integrity.record_valid();
        integrity.record_valid();
        integrity.record_valid();

        assert_eq!(integrity.total_artifacts, 3);
        assert_eq!(integrity.valid_artifacts, 3);
        assert!((integrity.integrity_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_artifact_integrity_with_failures() {
        let mut integrity = ArtifactIntegrityMetric::default();
        for _ in 0..98 {
            integrity.record_valid();
        }
        integrity.record_missing();
        integrity.record_corrupted();

        assert_eq!(integrity.total_artifacts, 100);
        assert_eq!(integrity.valid_artifacts, 98);
        assert!((integrity.integrity_rate() - 0.98).abs() < 0.001);
    }

    #[test]
    fn test_artifact_integrity_healthy() {
        let mut integrity = ArtifactIntegrityMetric::default();
        for _ in 0..100 {
            integrity.record_valid();
        }

        assert!(integrity.is_healthy());
    }

    #[test]
    fn test_artifact_integrity_unhealthy_corruption() {
        let mut integrity = ArtifactIntegrityMetric::default();
        for _ in 0..97 {
            integrity.record_valid();
        }
        integrity.record_corrupted();
        integrity.record_corrupted();
        integrity.record_corrupted();

        assert!(!integrity.is_healthy()); // 97% < 99%
    }

    #[test]
    fn test_artifact_integrity_unhealthy_manifest_error() {
        let mut integrity = ArtifactIntegrityMetric::default();
        for _ in 0..100 {
            integrity.record_valid();
        }
        integrity.record_manifest_error();

        assert!(!integrity.is_healthy()); // Manifest errors always unhealthy
    }

    // ============================================================
    // DeterminismScore Tests
    // ============================================================

    #[test]
    fn test_determinism_matching() {
        let mut determinism = DeterminismScore::default();
        determinism.record_comparison(true);
        determinism.record_comparison(true);
        determinism.record_comparison(true);

        assert_eq!(determinism.total_comparisons, 3);
        assert_eq!(determinism.matching_classifications, 3);
        assert!((determinism.determinism_rate() - 1.0).abs() < 0.001);
        assert!(determinism.is_deterministic());
    }

    #[test]
    fn test_determinism_with_divergence() {
        let mut determinism = DeterminismScore::default();
        for _ in 0..99 {
            determinism.record_comparison(true);
        }
        determinism.record_comparison(false);

        assert_eq!(determinism.total_comparisons, 100);
        assert_eq!(determinism.divergent_classifications, 1);
        assert!((determinism.determinism_rate() - 0.99).abs() < 0.001);
        assert!(determinism.is_deterministic()); // Exactly 99%
    }

    #[test]
    fn test_determinism_not_deterministic() {
        let mut determinism = DeterminismScore::default();
        for _ in 0..95 {
            determinism.record_comparison(true);
        }
        for _ in 0..5 {
            determinism.record_comparison(false);
        }

        assert!(!determinism.is_deterministic()); // 95% < 99%
    }

    #[test]
    fn test_determinism_record_divergence() {
        let mut determinism = DeterminismScore::default();
        determinism.record_divergence(DeterminismDivergence {
            attempt_id: "test-1".to_string(),
            run_a: Uuid::new_v4(),
            run_b: Uuid::new_v4(),
            classification_a: "success".to_string(),
            classification_b: "failure".to_string(),
            input_hash: "abc123".to_string(),
        });

        assert_eq!(determinism.divergences.len(), 1);
        assert_eq!(determinism.divergent_classifications, 1);
    }

    #[test]
    fn test_determinism_empty_is_deterministic() {
        let determinism = DeterminismScore::default();
        assert!(determinism.is_deterministic());
        assert!((determinism.determinism_rate() - 1.0).abs() < 0.001);
    }
}
