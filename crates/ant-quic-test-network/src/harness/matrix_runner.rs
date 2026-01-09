//! Connectivity Matrix Runner
//!
//! Orchestrates connectivity tests across the full NAT matrix using
//! the connection path classification system. This module coordinates
//! test execution across multiple VPS agents and aggregates results.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    ConnectivityMatrixRunner                          │
//! │  ┌──────────────────────────────────────────────────────────────┐  │
//! │  │                    Matrix Generation                          │  │
//! │  │  build_connection_matrix() → Vec<ConnectionPath>             │  │
//! │  └──────────────────────────────────────────────────────────────┘  │
//! │                              │                                      │
//! │                              ▼                                      │
//! │  ┌──────────────────────────────────────────────────────────────┐  │
//! │  │                    Test Scheduling                            │  │
//! │  │  group_by_category() → ParallelGroups + BarrierSynced        │  │
//! │  └──────────────────────────────────────────────────────────────┘  │
//! │                              │                                      │
//! │                              ▼                                      │
//! │  ┌──────────────────────────────────────────────────────────────┐  │
//! │  │                    Agent Coordination                         │  │
//! │  │  dispatch_to_agents() → Barriers → collect_results()         │  │
//! │  └──────────────────────────────────────────────────────────────┘  │
//! │                              │                                      │
//! │                              ▼                                      │
//! │  ┌──────────────────────────────────────────────────────────────┐  │
//! │  │                    Result Aggregation                         │  │
//! │  │  ConnectionMatrixAnalysis + MatrixRunReport                  │  │
//! │  └──────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

use super::{AgentClient, PeerAgentInfo};
use super::{
    ConnectionMatrixAnalysis, ConnectionPath, IpMode, NatBehaviorProfile, PathCategory,
};
use crate::registry::ConnectionTechnique;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Request to start a matrix test run on an agent.
///
/// This is specific to the matrix runner's needs and differs from the
/// harness's `StartRunRequest` which is designed for scenario-based testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixStartRunRequest {
    /// Test case ID.
    pub run_id: String,
    /// Scenario identifier for this matrix test.
    pub scenario_id: String,
    /// Peer agents to connect to.
    pub peer_agents: Vec<PeerAgentInfo>,
    /// Target address to connect to (if initiator).
    pub connection_target: Option<String>,
    /// Whether this agent is the initiator.
    pub initiator: bool,
    /// Connection techniques to try.
    pub techniques: Vec<String>,
    /// Number of connection attempts.
    pub attempts: u32,
    /// Timeout per attempt in milliseconds.
    pub timeout_ms: u64,
}

/// Request for barrier synchronization in matrix tests.
///
/// This type represents a barrier point where all participants must arrive
/// before proceeding. Used for coordinated NAT traversal tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixBarrierRequest {
    /// Barrier identifier.
    pub barrier_id: String,
    /// Agent IDs that must participate.
    pub participants: Vec<String>,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

// ============================================================================
// SUCCESS CRITERIA TYPES
// ============================================================================

/// Comprehensive success criteria for connectivity matrix testing.
///
/// This defines what constitutes a "successful" matrix test run across
/// all path categories, techniques, and quality metrics. The criteria
/// are designed to match production requirements for the Autonomi network.
///
/// # Design Philosophy
///
/// Success criteria are tiered by path category because different NAT
/// combinations have fundamentally different connectivity expectations:
///
/// - **Direct paths**: Should be near 100% (no NAT traversal needed)
/// - **Hole-punchable paths**: 80-95% expected (NAT traversal works)
/// - **Coordinated paths**: 60-85% expected (requires timing coordination)
/// - **Relay paths**: 95%+ expected (relay should always work)
/// - **IP mismatch**: Not expected to work directly
///
/// # Example
///
/// ```
/// use ant_quic_test_network::harness::MatrixSuccessCriteria;
///
/// let criteria = MatrixSuccessCriteria::production();
/// assert!(criteria.overall_min_success_rate >= 0.90);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixSuccessCriteria {
    /// Minimum overall success rate across all paths.
    pub overall_min_success_rate: f64,
    /// Per-category success criteria.
    pub category_criteria: HashMap<PathCategory, CategorySuccessCriteria>,
    /// Per-technique success criteria.
    pub technique_criteria: HashMap<ConnectionTechnique, TechniqueSuccessCriteria>,
    /// RTT quality thresholds.
    pub rtt_thresholds: RttThresholds,
    /// Regression detection criteria.
    pub regression_criteria: RegressionCriteria,
    /// Whether to fail the entire matrix if any category fails.
    pub fail_on_category_failure: bool,
    /// Minimum number of test cases required per category for valid results.
    pub min_cases_per_category: u32,
}

impl MatrixSuccessCriteria {
    /// Production-grade success criteria for the Autonomi network.
    ///
    /// These criteria are designed for real-world deployment validation
    /// and require high success rates across most categories.
    #[must_use]
    pub fn production() -> Self {
        let mut category_criteria = HashMap::new();
        category_criteria.insert(
            PathCategory::Direct,
            CategorySuccessCriteria::for_direct(),
        );
        category_criteria.insert(
            PathCategory::HolePunchable,
            CategorySuccessCriteria::for_holepunchable(),
        );
        category_criteria.insert(
            PathCategory::CoordinatedOnly,
            CategorySuccessCriteria::for_coordinated(),
        );
        category_criteria.insert(
            PathCategory::RelayRequired,
            CategorySuccessCriteria::for_relay(),
        );
        category_criteria.insert(
            PathCategory::IpMismatch,
            CategorySuccessCriteria::for_ip_mismatch(),
        );

        let mut technique_criteria = HashMap::new();
        technique_criteria.insert(
            ConnectionTechnique::DirectIpv4,
            TechniqueSuccessCriteria::for_direct(),
        );
        technique_criteria.insert(
            ConnectionTechnique::DirectIpv6,
            TechniqueSuccessCriteria::for_direct(),
        );
        technique_criteria.insert(
            ConnectionTechnique::HolePunch,
            TechniqueSuccessCriteria::for_hole_punch(),
        );
        technique_criteria.insert(
            ConnectionTechnique::HolePunchCoordinated,
            TechniqueSuccessCriteria::for_coordinated_hole_punch(),
        );
        technique_criteria.insert(
            ConnectionTechnique::Relay,
            TechniqueSuccessCriteria::for_relay(),
        );
        technique_criteria.insert(
            ConnectionTechnique::MasqueRelay,
            TechniqueSuccessCriteria::for_relay(),
        );

        Self {
            overall_min_success_rate: 0.90,
            category_criteria,
            technique_criteria,
            rtt_thresholds: RttThresholds::production(),
            regression_criteria: RegressionCriteria::production(),
            fail_on_category_failure: false,
            min_cases_per_category: 10,
        }
    }

    /// CI/testing success criteria (more lenient for faster iteration).
    #[must_use]
    pub fn ci() -> Self {
        let mut criteria = Self::production();
        criteria.overall_min_success_rate = 0.80;
        criteria.rtt_thresholds = RttThresholds::ci();
        criteria.regression_criteria = RegressionCriteria::ci();
        criteria.fail_on_category_failure = false;
        criteria.min_cases_per_category = 3;

        // Relax category criteria for CI
        for (_, cat_criteria) in criteria.category_criteria.iter_mut() {
            cat_criteria.min_success_rate -= 0.10;
            cat_criteria.min_success_rate = cat_criteria.min_success_rate.max(0.0);
        }

        criteria
    }

    /// Strict success criteria for release validation.
    #[must_use]
    pub fn release() -> Self {
        let mut criteria = Self::production();
        criteria.overall_min_success_rate = 0.95;
        criteria.fail_on_category_failure = true;
        criteria.min_cases_per_category = 50;
        criteria
    }

    /// Check if a test result meets the criteria.
    #[must_use]
    pub fn evaluate(&self, report: &MatrixRunReport) -> MatrixEvaluationResult {
        let mut category_results = HashMap::new();
        let mut all_categories_pass = true;

        for result in report.results_by_category.values() {
            if let Some(criteria) = self.category_criteria.get(&result.category) {
                let passes = criteria.evaluate(result);
                category_results.insert(result.category, passes);
                if !passes {
                    all_categories_pass = false;
                }
            }
        }

        let overall_passes = report.overall_success_rate >= self.overall_min_success_rate;

        let final_pass = if self.fail_on_category_failure {
            overall_passes && all_categories_pass
        } else {
            overall_passes
        };

        MatrixEvaluationResult {
            passes: final_pass,
            overall_success_rate: report.overall_success_rate,
            min_required_rate: self.overall_min_success_rate,
            category_results,
            notes: if final_pass {
                vec!["Matrix meets all success criteria".to_string()]
            } else {
                vec![format!(
                    "Matrix fails criteria: overall rate {:.1}% vs required {:.1}%",
                    report.overall_success_rate * 100.0,
                    self.overall_min_success_rate * 100.0
                )]
            },
        }
    }
}

impl Default for MatrixSuccessCriteria {
    fn default() -> Self {
        Self::production()
    }
}

/// Success criteria for a specific path category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySuccessCriteria {
    /// Minimum success rate for this category.
    pub min_success_rate: f64,
    /// Maximum acceptable P95 RTT in milliseconds.
    pub max_p95_rtt_ms: u64,
    /// Whether this category is required to pass.
    pub required: bool,
    /// Weight for overall score calculation.
    pub weight: f64,
    /// Notes about expectations for this category.
    pub notes: String,
}

impl CategorySuccessCriteria {
    /// Criteria for direct connections (no NAT traversal).
    #[must_use]
    pub fn for_direct() -> Self {
        Self {
            min_success_rate: 0.99,
            max_p95_rtt_ms: 100,
            required: true,
            weight: 1.0,
            notes: "Direct connections should work reliably".to_string(),
        }
    }

    /// Criteria for hole-punchable paths.
    #[must_use]
    pub fn for_holepunchable() -> Self {
        Self {
            min_success_rate: 0.85,
            max_p95_rtt_ms: 500,
            required: true,
            weight: 1.2,
            notes: "Hole-punching should succeed for compatible NAT types".to_string(),
        }
    }

    /// Criteria for coordinated-only paths.
    #[must_use]
    pub fn for_coordinated() -> Self {
        Self {
            min_success_rate: 0.70,
            max_p95_rtt_ms: 1000,
            required: false,
            weight: 0.8,
            notes: "Coordinated paths are challenging and may not always succeed".to_string(),
        }
    }

    /// Criteria for relay-required paths.
    #[must_use]
    pub fn for_relay() -> Self {
        Self {
            min_success_rate: 0.95,
            max_p95_rtt_ms: 2000,
            required: true,
            weight: 0.5,
            notes: "Relay should always work as a fallback".to_string(),
        }
    }

    /// Criteria for IP mismatch paths (IPv4 to IPv6 or vice versa).
    #[must_use]
    pub fn for_ip_mismatch() -> Self {
        Self {
            min_success_rate: 0.0,
            max_p95_rtt_ms: 0,
            required: false,
            weight: 0.0,
            notes: "IP mismatches are not expected to connect directly".to_string(),
        }
    }

    /// Evaluate if a category result meets these criteria.
    #[must_use]
    pub fn evaluate(&self, result: &CategoryResult) -> bool {
        if result.completed_cases == 0 {
            return !self.required;
        }
        result.avg_success_rate >= self.min_success_rate
    }
}

/// Success criteria for a specific connection technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueSuccessCriteria {
    /// Minimum success rate when this technique is attempted.
    pub min_success_rate: f64,
    /// Maximum acceptable average RTT in milliseconds.
    pub max_avg_rtt_ms: u64,
    /// Whether this technique must be available.
    pub required: bool,
}

impl TechniqueSuccessCriteria {
    /// Criteria for direct connection techniques.
    #[must_use]
    pub fn for_direct() -> Self {
        Self {
            min_success_rate: 0.99,
            max_avg_rtt_ms: 50,
            required: true,
        }
    }

    /// Criteria for standard hole punching.
    #[must_use]
    pub fn for_hole_punch() -> Self {
        Self {
            min_success_rate: 0.80,
            max_avg_rtt_ms: 200,
            required: true,
        }
    }

    /// Criteria for coordinated hole punching.
    #[must_use]
    pub fn for_coordinated_hole_punch() -> Self {
        Self {
            min_success_rate: 0.65,
            max_avg_rtt_ms: 500,
            required: false,
        }
    }

    /// Criteria for relay techniques.
    #[must_use]
    pub fn for_relay() -> Self {
        Self {
            min_success_rate: 0.95,
            max_avg_rtt_ms: 1000,
            required: true,
        }
    }
}

/// RTT quality thresholds for connection quality assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttThresholds {
    /// Excellent RTT threshold (ms).
    pub excellent_ms: u64,
    /// Good RTT threshold (ms).
    pub good_ms: u64,
    /// Acceptable RTT threshold (ms).
    pub acceptable_ms: u64,
    /// Poor RTT threshold (anything above is poor).
    pub poor_ms: u64,
}

impl RttThresholds {
    /// Production RTT thresholds based on real-world latency expectations.
    #[must_use]
    pub fn production() -> Self {
        Self {
            excellent_ms: 50,
            good_ms: 150,
            acceptable_ms: 500,
            poor_ms: 2000,
        }
    }

    /// CI RTT thresholds (more lenient for local/containerized testing).
    #[must_use]
    pub fn ci() -> Self {
        Self {
            excellent_ms: 100,
            good_ms: 500,
            acceptable_ms: 2000,
            poor_ms: 5000,
        }
    }

    /// Classify an RTT measurement.
    #[must_use]
    pub fn classify(&self, rtt_ms: u64) -> RttQuality {
        if rtt_ms <= self.excellent_ms {
            RttQuality::Excellent
        } else if rtt_ms <= self.good_ms {
            RttQuality::Good
        } else if rtt_ms <= self.acceptable_ms {
            RttQuality::Acceptable
        } else if rtt_ms <= self.poor_ms {
            RttQuality::Poor
        } else {
            RttQuality::Unacceptable
        }
    }
}

impl Default for RttThresholds {
    fn default() -> Self {
        Self::production()
    }
}

/// RTT quality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RttQuality {
    /// Excellent latency (suitable for real-time applications).
    Excellent,
    /// Good latency (suitable for interactive use).
    Good,
    /// Acceptable latency (usable but noticeable).
    Acceptable,
    /// Poor latency (significant user impact).
    Poor,
    /// Unacceptable latency (likely unusable).
    Unacceptable,
}

impl RttQuality {
    /// Check if this quality level meets the minimum acceptable standard.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::Excellent | Self::Good | Self::Acceptable)
    }
}

/// Regression detection criteria for comparing against baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionCriteria {
    /// Maximum allowed decrease in success rate from baseline.
    pub max_success_rate_decrease: f64,
    /// Maximum allowed increase in average RTT (as a multiplier).
    pub max_rtt_increase_factor: f64,
    /// Number of standard deviations for statistical significance.
    pub z_score_threshold: f64,
    /// Minimum number of data points for valid comparison.
    pub min_baseline_samples: u32,
}

impl RegressionCriteria {
    /// Production regression detection criteria.
    #[must_use]
    pub fn production() -> Self {
        Self {
            max_success_rate_decrease: 0.05, // 5% decrease triggers alert
            max_rtt_increase_factor: 1.5,    // 50% increase triggers alert
            z_score_threshold: 2.0,          // 2 standard deviations
            min_baseline_samples: 100,
        }
    }

    /// CI regression detection criteria (more lenient).
    #[must_use]
    pub fn ci() -> Self {
        Self {
            max_success_rate_decrease: 0.10, // 10% decrease
            max_rtt_increase_factor: 2.0,    // 100% increase
            z_score_threshold: 3.0,          // 3 standard deviations
            min_baseline_samples: 10,
        }
    }

    /// Check if a result represents a regression from baseline.
    #[must_use]
    pub fn is_regression(
        &self,
        baseline_rate: f64,
        current_rate: f64,
        baseline_rtt_ms: f64,
        current_rtt_ms: f64,
    ) -> RegressionStatus {
        let rate_decrease = baseline_rate - current_rate;
        let rtt_factor = if baseline_rtt_ms > 0.0 {
            current_rtt_ms / baseline_rtt_ms
        } else {
            1.0
        };

        if rate_decrease > self.max_success_rate_decrease {
            RegressionStatus::Regression(format!(
                "Success rate decreased by {:.1}% (from {:.1}% to {:.1}%)",
                rate_decrease * 100.0,
                baseline_rate * 100.0,
                current_rate * 100.0
            ))
        } else if rtt_factor > self.max_rtt_increase_factor {
            RegressionStatus::Regression(format!(
                "RTT increased by {:.0}x (from {:.0}ms to {:.0}ms)",
                rtt_factor, baseline_rtt_ms, current_rtt_ms
            ))
        } else if rate_decrease.abs() < 0.02 && rtt_factor < 1.1 {
            RegressionStatus::NoChange
        } else if rate_decrease < 0.0 {
            RegressionStatus::Improvement(format!(
                "Success rate improved by {:.1}%",
                (-rate_decrease) * 100.0
            ))
        } else {
            RegressionStatus::NoChange
        }
    }
}

impl Default for RegressionCriteria {
    fn default() -> Self {
        Self::production()
    }
}

/// Regression detection status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionStatus {
    /// Performance regressed.
    Regression(String),
    /// No significant change.
    NoChange,
    /// Performance improved.
    Improvement(String),
}

/// Result of evaluating matrix results against success criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixEvaluationResult {
    /// Whether the matrix passes all criteria.
    pub passes: bool,
    /// Observed overall success rate.
    pub overall_success_rate: f64,
    /// Minimum required success rate.
    pub min_required_rate: f64,
    /// Per-category pass/fail status.
    pub category_results: HashMap<PathCategory, bool>,
    /// Evaluation notes.
    pub notes: Vec<String>,
}

impl MatrixEvaluationResult {
    /// Generate a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        let status = if self.passes { "PASS" } else { "FAIL" };
        format!(
            "{}: {:.1}% success rate (required: {:.1}%)",
            status,
            self.overall_success_rate * 100.0,
            self.min_required_rate * 100.0
        )
    }
}

// ============================================================================
// MATRIX RUNNER CONFIGURATION
// ============================================================================

/// Configuration for the matrix runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRunnerConfig {
    /// NAT profiles to test.
    pub profiles: Vec<NatBehaviorProfile>,
    /// IP modes to test.
    pub ip_modes: Vec<IpMode>,
    /// Number of attempts per path.
    pub attempts_per_path: u32,
    /// Timeout per connection attempt.
    #[serde(with = "humantime_serde")]
    pub attempt_timeout: Duration,
    /// Timeout for barrier synchronization.
    #[serde(with = "humantime_serde")]
    pub barrier_timeout: Duration,
    /// Maximum concurrent tests per agent.
    pub max_concurrent_per_agent: usize,
    /// Whether to skip relay-required paths.
    pub skip_relay_required: bool,
    /// Minimum success rate threshold.
    pub min_success_rate: f64,
    /// Enable detailed per-technique metrics.
    pub detailed_metrics: bool,
    /// Minimum idle time before NAT traversal test (to ensure NAT mappings expire).
    ///
    /// For proper NAT traversal testing, we need to ensure that any previous
    /// NAT mappings have expired. This duration specifies how long we must
    /// wait since the last communication before testing.
    ///
    /// RFC 4787 recommends NAT mappings persist for at least 2 minutes,
    /// but many consumer NATs use 30-60 seconds. A 30-second minimum
    /// ensures we're testing true NAT traversal, not cached mappings.
    #[serde(with = "humantime_serde")]
    pub nat_mapping_cooldown: Duration,
    /// Whether to enforce strict cooldown (fail test if not met).
    pub strict_cooldown: bool,
}

impl Default for MatrixRunnerConfig {
    fn default() -> Self {
        Self {
            profiles: NatBehaviorProfile::all_standard(),
            ip_modes: vec![IpMode::Ipv4Only, IpMode::Ipv6Only, IpMode::DualStack],
            attempts_per_path: 10,
            attempt_timeout: Duration::from_secs(30),
            barrier_timeout: Duration::from_secs(60),
            max_concurrent_per_agent: 4,
            skip_relay_required: false,
            min_success_rate: 0.90,
            detailed_metrics: true,
            // 30 seconds ensures NAT mappings have expired for proper testing
            nat_mapping_cooldown: Duration::from_secs(30),
            strict_cooldown: true,
        }
    }
}

impl MatrixRunnerConfig {
    /// Create a CI-fast configuration.
    ///
    /// Uses shorter cooldown (15s) for faster CI runs, with non-strict
    /// enforcement since CI environments typically have simpler NAT setups.
    #[must_use]
    pub fn ci_fast() -> Self {
        Self {
            profiles: NatBehaviorProfile::ci_subset(),
            ip_modes: vec![IpMode::Ipv4Only],
            attempts_per_path: 3,
            attempt_timeout: Duration::from_secs(15),
            barrier_timeout: Duration::from_secs(30),
            max_concurrent_per_agent: 2,
            skip_relay_required: true,
            min_success_rate: 0.80,
            detailed_metrics: false,
            // Shorter cooldown for CI, non-strict
            nat_mapping_cooldown: Duration::from_secs(15),
            strict_cooldown: false,
        }
    }

    /// Create a production configuration.
    ///
    /// Uses strict 30-second cooldown to ensure proper NAT traversal testing.
    /// This matches the lower bound of typical consumer NAT timeouts.
    #[must_use]
    pub fn production() -> Self {
        Self {
            profiles: NatBehaviorProfile::all_profiles(),
            ip_modes: vec![IpMode::Ipv4Only, IpMode::Ipv6Only, IpMode::DualStack],
            attempts_per_path: 100,
            attempt_timeout: Duration::from_secs(45),
            barrier_timeout: Duration::from_secs(120),
            max_concurrent_per_agent: 8,
            skip_relay_required: false,
            min_success_rate: 0.95,
            detailed_metrics: true,
            // Strict 30-second cooldown for proper NAT traversal testing
            nat_mapping_cooldown: Duration::from_secs(30),
            strict_cooldown: true,
        }
    }

    /// Minimum cooldown for true NAT traversal tests.
    ///
    /// RFC 4787 recommends minimum 2-minute NAT mapping lifetime, but many
    /// consumer NATs use 30-60 seconds. 30 seconds is the safe minimum.
    pub const MIN_NAT_COOLDOWN_SECS: u64 = 30;
}

/// Agent information for the matrix runner.
///
/// This is a simplified representation of an agent for matrix testing purposes.
/// It focuses on the fields needed for test coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixAgentInfo {
    /// Unique agent identifier.
    pub agent_id: String,
    /// API base URL for control plane communication.
    pub api_base_url: String,
    /// P2P listen address for the agent.
    pub p2p_listen_addr: SocketAddr,
    /// NAT profile assigned to this agent.
    pub nat_profile: String,
    /// Whether the agent is ready for testing.
    pub is_ready: bool,
}

impl MatrixAgentInfo {
    /// Create a new agent info.
    #[must_use]
    pub fn new(
        agent_id: impl Into<String>,
        api_base_url: impl Into<String>,
        p2p_listen_addr: SocketAddr,
        nat_profile: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            api_base_url: api_base_url.into(),
            p2p_listen_addr,
            nat_profile: nat_profile.into(),
            is_ready: true,
        }
    }
}

/// Assignment of an agent to a NAT profile for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixAgentAssignment {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent control plane URL.
    pub control_url: String,
    /// Agent's P2P listen address.
    pub p2p_addr: SocketAddr,
    /// Assigned NAT profile name.
    pub nat_profile: String,
    /// Current status.
    pub status: MatrixAgentAssignmentStatus,
    /// Last time this agent communicated with the target peer (if known).
    ///
    /// Used to enforce the NAT mapping cooldown period. If this is Some and
    /// within the cooldown window, we must wait before starting the test.
    pub last_peer_contact: Option<DateTime<Utc>>,
}

/// Status of an agent assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixAgentAssignmentStatus {
    /// Agent is available and ready.
    Ready,
    /// Agent is currently running a test.
    Testing,
    /// Agent completed its current test.
    Completed,
    /// Agent failed.
    Failed,
    /// Agent is unreachable.
    Unreachable,
}

/// A single test case in the matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixTestCase {
    /// Unique test case ID.
    pub id: String,
    /// Connection path being tested.
    pub path: ConnectionPath,
    /// Agent A assignment.
    pub agent_a: MatrixAgentAssignment,
    /// Agent B assignment.
    pub agent_b: MatrixAgentAssignment,
    /// Techniques to test (ordered by priority).
    pub techniques: Vec<ConnectionTechnique>,
    /// Number of attempts.
    pub attempts: u32,
    /// Test status.
    pub status: TestCaseStatus,
    /// Cooldown status for this test case.
    pub cooldown_status: CooldownStatus,
}

/// Status of the NAT mapping cooldown period.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooldownStatus {
    /// Cooldown satisfied - can start test immediately.
    Ready,
    /// Waiting for cooldown to expire.
    WaitingUntil(DateTime<Utc>),
    /// Unknown - no previous contact information available.
    #[default]
    Unknown,
    /// Cooldown skipped (non-strict mode).
    Skipped,
}

impl MatrixTestCase {
    /// Check if the test case is ready to run (cooldown satisfied).
    #[must_use]
    pub fn is_cooldown_satisfied(&self) -> bool {
        match &self.cooldown_status {
            CooldownStatus::Ready | CooldownStatus::Unknown | CooldownStatus::Skipped => true,
            CooldownStatus::WaitingUntil(until) => Utc::now() >= *until,
        }
    }

    /// Calculate remaining cooldown time (if any).
    #[must_use]
    pub fn remaining_cooldown(&self) -> Option<Duration> {
        match &self.cooldown_status {
            CooldownStatus::WaitingUntil(until) => {
                let now = Utc::now();
                if now < *until {
                    Some((*until - now).to_std().unwrap_or(Duration::ZERO))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Update cooldown status based on agent contact times and config.
    pub fn update_cooldown_status(&mut self, cooldown_duration: Duration, strict: bool) {
        let now = Utc::now();

        // Get the most recent contact time from either agent
        let most_recent_contact = match (
            self.agent_a.last_peer_contact,
            self.agent_b.last_peer_contact,
        ) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        self.cooldown_status = match most_recent_contact {
            Some(contact_time) => {
                let elapsed = now.signed_duration_since(contact_time);
                let cooldown_chrono = chrono::Duration::from_std(cooldown_duration)
                    .unwrap_or(chrono::Duration::seconds(30));

                if elapsed >= cooldown_chrono {
                    CooldownStatus::Ready
                } else if strict {
                    let wait_until = contact_time + cooldown_chrono;
                    CooldownStatus::WaitingUntil(wait_until)
                } else {
                    CooldownStatus::Skipped
                }
            }
            None => CooldownStatus::Unknown,
        };
    }
}

/// Status of a test case.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCaseStatus {
    /// Test is pending.
    #[default]
    Pending,
    /// Test is waiting for barrier sync.
    WaitingBarrier,
    /// Test is running.
    Running,
    /// Test completed successfully.
    Completed(TestCaseResult),
    /// Test failed with error.
    Failed(String),
    /// Test was skipped.
    Skipped(String),
}

/// Result of a single test case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestCaseResult {
    /// Total attempts made.
    pub attempts: u32,
    /// Successful attempts.
    pub successes: u32,
    /// Success rate (0.0 - 1.0).
    pub success_rate: f64,
    /// Technique that succeeded (if any).
    pub successful_technique: Option<ConnectionTechnique>,
    /// Average RTT in milliseconds.
    pub avg_rtt_ms: Option<f64>,
    /// P95 RTT in milliseconds.
    pub p95_rtt_ms: Option<f64>,
    /// Per-technique results.
    pub technique_results: HashMap<String, MatrixTechniqueResult>,
}

impl Eq for TestCaseResult {}

/// Result for a specific technique.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatrixTechniqueResult {
    /// Attempts for this technique.
    pub attempts: u32,
    /// Successes for this technique.
    pub successes: u32,
    /// Average RTT for successful connections.
    pub avg_rtt_ms: Option<f64>,
    /// Reason for failures (if any).
    pub failure_reason: Option<String>,
}

impl Eq for MatrixTechniqueResult {}

/// Report for a complete matrix run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRunReport {
    /// Run identifier.
    pub run_id: String,
    /// When the run started.
    pub started_at: DateTime<Utc>,
    /// When the run completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Configuration used.
    pub config: MatrixRunnerConfig,
    /// Matrix analysis from paths.
    pub matrix_analysis: ConnectionMatrixAnalysis,
    /// All test cases with results.
    pub test_cases: Vec<MatrixTestCase>,
    /// Aggregated results by category.
    pub results_by_category: HashMap<String, CategoryResult>,
    /// Overall success rate.
    pub overall_success_rate: f64,
    /// Whether the run met thresholds.
    pub passed: bool,
    /// Summary notes.
    pub notes: Vec<String>,
}

/// Aggregated results for a path category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryResult {
    /// Path category.
    pub category: PathCategory,
    /// Total test cases.
    pub total_cases: usize,
    /// Completed test cases.
    pub completed_cases: usize,
    /// Average success rate.
    pub avg_success_rate: f64,
    /// Best technique for this category.
    pub best_technique: Option<ConnectionTechnique>,
    /// Notes about this category.
    pub notes: Vec<String>,
}

// ============================================================================
// REPORT GENERATION
// ============================================================================

/// Report format for output generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Human-readable text with ANSI colors.
    Text,
    /// Plain text without colors.
    PlainText,
    /// JSON for machine parsing.
    Json,
    /// Compact JSON (no pretty-print).
    JsonCompact,
    /// Markdown for PR comments and documentation.
    Markdown,
    /// CI summary format (compact, exit-code focused).
    CiSummary,
}

/// Matrix report generator for multiple output formats.
///
/// Generates comprehensive connectivity matrix reports in various formats
/// suitable for human review, CI integration, and machine parsing.
///
/// # Example
///
/// ```ignore
/// use ant_quic_test_network::harness::{MatrixReportGenerator, ReportFormat};
///
/// let report = runner.aggregate_results(test_cases);
/// let generator = MatrixReportGenerator::new(&report);
///
/// // Generate human-readable text
/// println!("{}", generator.generate(ReportFormat::Text));
///
/// // Generate JSON for CI
/// std::fs::write("report.json", generator.generate(ReportFormat::Json));
/// ```
pub struct MatrixReportGenerator<'a> {
    report: &'a MatrixRunReport,
    evaluation: Option<MatrixEvaluationResult>,
    baseline: Option<&'a MatrixRunReport>,
}

impl<'a> MatrixReportGenerator<'a> {
    /// Create a new report generator.
    #[must_use]
    pub fn new(report: &'a MatrixRunReport) -> Self {
        Self {
            report,
            evaluation: None,
            baseline: None,
        }
    }

    /// Add evaluation results from success criteria.
    #[must_use]
    pub fn with_evaluation(mut self, evaluation: MatrixEvaluationResult) -> Self {
        self.evaluation = Some(evaluation);
        self
    }

    /// Add baseline report for regression comparison.
    #[must_use]
    pub fn with_baseline(mut self, baseline: &'a MatrixRunReport) -> Self {
        self.baseline = Some(baseline);
        self
    }

    /// Generate report in the specified format.
    #[must_use]
    pub fn generate(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Text => self.to_text(true),
            ReportFormat::PlainText => self.to_text(false),
            ReportFormat::Json => self.to_json(true),
            ReportFormat::JsonCompact => self.to_json(false),
            ReportFormat::Markdown => self.to_markdown(),
            ReportFormat::CiSummary => self.to_ci_summary(),
        }
    }

    /// Generate human-readable text report.
    fn to_text(&self, use_colors: bool) -> String {
        let mut output = String::new();

        // Header
        let status_emoji = if self.report.passed { "✓" } else { "✗" };
        let status_text = if self.report.passed { "PASSED" } else { "FAILED" };
        let status_color = if use_colors {
            if self.report.passed { "\x1b[32m" } else { "\x1b[31m" }
        } else {
            ""
        };
        let reset = if use_colors { "\x1b[0m" } else { "" };

        output.push_str(&format!(
            "\n{status_color}═══════════════════════════════════════════════════════════════{reset}\n"
        ));
        output.push_str(&format!(
            "{status_color}  {status_emoji} CONNECTIVITY MATRIX REPORT - {status_text}{reset}\n"
        ));
        output.push_str(&format!(
            "{status_color}═══════════════════════════════════════════════════════════════{reset}\n\n"
        ));

        // Summary
        output.push_str("SUMMARY\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str(&format!("  Run ID:           {}\n", self.report.run_id));
        output.push_str(&format!(
            "  Started:          {}\n",
            self.report.started_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if let Some(completed) = self.report.completed_at {
            output.push_str(&format!(
                "  Completed:        {}\n",
                completed.format("%Y-%m-%d %H:%M:%S UTC")
            ));
            let duration = completed - self.report.started_at;
            output.push_str(&format!("  Duration:         {}s\n", duration.num_seconds()));
        }
        output.push_str(&format!(
            "  Overall Success:  {}{:.1}%{}\n",
            status_color,
            self.report.overall_success_rate * 100.0,
            reset
        ));
        output.push_str(&format!(
            "  Min Required:     {:.1}%\n",
            self.report.config.min_success_rate * 100.0
        ));
        output.push_str(&format!(
            "  Test Cases:       {}\n",
            self.report.test_cases.len()
        ));
        output.push('\n');

        // Matrix Analysis
        output.push_str("MATRIX ANALYSIS\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Total Paths:      {}\n",
            self.report.matrix_analysis.total_paths
        ));
        output.push_str(&format!(
            "  Estimated Rate:   {:.1}%\n",
            self.report.matrix_analysis.avg_success_rate * 100.0
        ));
        output.push('\n');

        // Category breakdown
        output.push_str("RESULTS BY CATEGORY\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");

        // Sort categories for consistent output
        let mut categories: Vec<_> = self.report.results_by_category.iter().collect();
        categories.sort_by_key(|(name, _)| *name);

        for (category_name, result) in categories {
            let rate_color = if use_colors {
                self.rate_color(result.avg_success_rate)
            } else {
                ""
            };

            let best_tech = result
                .best_technique
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "N/A".to_string());

            output.push_str(&format!(
                "  {:<20} {rate_color}{:>6.1}%{reset}  ({}/{} cases)  Best: {}\n",
                category_name,
                result.avg_success_rate * 100.0,
                result.completed_cases,
                result.total_cases,
                best_tech
            ));
        }
        output.push('\n');

        // Evaluation results if available
        if let Some(eval) = &self.evaluation {
            output.push_str("EVALUATION\n");
            output.push_str("───────────────────────────────────────────────────────────────\n");
            output.push_str(&format!("  Status:           {}\n", eval.summary()));

            if !eval.category_results.is_empty() {
                output.push_str("  Category Status:\n");
                for (category, passes) in &eval.category_results {
                    let status = if *passes {
                        if use_colors { "\x1b[32m✓\x1b[0m" } else { "✓" }
                    } else if use_colors {
                        "\x1b[31m✗\x1b[0m"
                    } else {
                        "✗"
                    };
                    output.push_str(&format!("    {status} {category:?}\n"));
                }
            }

            if !eval.notes.is_empty() {
                output.push_str("  Notes:\n");
                for note in &eval.notes {
                    output.push_str(&format!("    - {note}\n"));
                }
            }
            output.push('\n');
        }

        // Baseline comparison if available
        if let Some(baseline) = &self.baseline {
            output.push_str("REGRESSION ANALYSIS\n");
            output.push_str("───────────────────────────────────────────────────────────────\n");

            let criteria = RegressionCriteria::production();
            let status = criteria.is_regression(
                baseline.overall_success_rate,
                self.report.overall_success_rate,
                0.0, // Would need RTT from baseline
                0.0,
            );

            let status_str = match &status {
                RegressionStatus::Regression(msg) => {
                    let color = if use_colors { "\x1b[31m" } else { "" };
                    format!("{color}REGRESSION: {msg}{reset}")
                }
                RegressionStatus::NoChange => {
                    let color = if use_colors { "\x1b[33m" } else { "" };
                    format!("{color}No significant change{reset}")
                }
                RegressionStatus::Improvement(msg) => {
                    let color = if use_colors { "\x1b[32m" } else { "" };
                    format!("{color}IMPROVEMENT: {msg}{reset}")
                }
            };

            output.push_str(&format!("  Baseline Run:     {}\n", baseline.run_id));
            output.push_str(&format!(
                "  Baseline Rate:    {:.1}%\n",
                baseline.overall_success_rate * 100.0
            ));
            output.push_str(&format!("  Status:           {status_str}\n"));
            output.push('\n');
        }

        // Notes
        if !self.report.notes.is_empty() {
            output.push_str("NOTES\n");
            output.push_str("───────────────────────────────────────────────────────────────\n");
            for note in &self.report.notes {
                output.push_str(&format!("  • {note}\n"));
            }
            output.push('\n');
        }

        // Configuration summary
        output.push_str("CONFIGURATION\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Attempts/Path:    {}\n",
            self.report.config.attempts_per_path
        ));
        output.push_str(&format!(
            "  Timeout:          {:?}\n",
            self.report.config.attempt_timeout
        ));
        output.push_str(&format!(
            "  NAT Cooldown:     {:?}\n",
            self.report.config.nat_mapping_cooldown
        ));
        output.push_str(&format!(
            "  Strict Cooldown:  {}\n",
            self.report.config.strict_cooldown
        ));

        output.push_str(&format!(
            "\n{status_color}═══════════════════════════════════════════════════════════════{reset}\n"
        ));

        output
    }

    /// Get ANSI color code for a success rate.
    fn rate_color(&self, rate: f64) -> &'static str {
        if rate >= 0.95 {
            "\x1b[32m" // Green
        } else if rate >= 0.80 {
            "\x1b[33m" // Yellow
        } else if rate >= 0.60 {
            "\x1b[91m" // Light red
        } else {
            "\x1b[31m" // Red
        }
    }

    /// Generate JSON report.
    fn to_json(&self, pretty: bool) -> String {
        #[derive(Serialize)]
        struct JsonReport<'a> {
            report: &'a MatrixRunReport,
            evaluation: Option<&'a MatrixEvaluationResult>,
            regression: Option<RegressionInfo>,
        }

        #[derive(Serialize)]
        struct RegressionInfo {
            baseline_run_id: String,
            baseline_success_rate: f64,
            current_success_rate: f64,
            status: String,
        }

        let regression = self.baseline.map(|baseline| {
            let criteria = RegressionCriteria::production();
            let status = criteria.is_regression(
                baseline.overall_success_rate,
                self.report.overall_success_rate,
                0.0,
                0.0,
            );
            RegressionInfo {
                baseline_run_id: baseline.run_id.clone(),
                baseline_success_rate: baseline.overall_success_rate,
                current_success_rate: self.report.overall_success_rate,
                status: match status {
                    RegressionStatus::Regression(msg) => format!("regression: {msg}"),
                    RegressionStatus::NoChange => "no_change".to_string(),
                    RegressionStatus::Improvement(msg) => format!("improvement: {msg}"),
                },
            }
        });

        let json_report = JsonReport {
            report: self.report,
            evaluation: self.evaluation.as_ref(),
            regression,
        };

        if pretty {
            serde_json::to_string_pretty(&json_report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
        } else {
            serde_json::to_string(&json_report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
        }
    }

    /// Generate Markdown report for PR comments.
    fn to_markdown(&self) -> String {
        let mut output = String::new();

        // Header with status badge
        let status_badge = if self.report.passed {
            "![Status](https://img.shields.io/badge/status-PASSED-brightgreen)"
        } else {
            "![Status](https://img.shields.io/badge/status-FAILED-red)"
        };

        output.push_str(&format!("# Connectivity Matrix Report {status_badge}\n\n"));

        // Summary table
        output.push_str("## Summary\n\n");
        output.push_str("| Metric | Value |\n");
        output.push_str("|--------|-------|\n");
        output.push_str(&format!("| Run ID | `{}` |\n", self.report.run_id));
        output.push_str(&format!(
            "| Overall Success Rate | **{:.1}%** |\n",
            self.report.overall_success_rate * 100.0
        ));
        output.push_str(&format!(
            "| Required Rate | {:.1}% |\n",
            self.report.config.min_success_rate * 100.0
        ));
        output.push_str(&format!(
            "| Test Cases | {} |\n",
            self.report.test_cases.len()
        ));
        output.push_str(&format!(
            "| Status | {} |\n",
            if self.report.passed { "✅ PASSED" } else { "❌ FAILED" }
        ));
        output.push('\n');

        // Category breakdown table
        output.push_str("## Results by Category\n\n");
        output.push_str("| Category | Success Rate | Completed | Total | Best Technique |\n");
        output.push_str("|----------|--------------|-----------|-------|----------------|\n");

        let mut categories: Vec<_> = self.report.results_by_category.iter().collect();
        categories.sort_by_key(|(name, _)| *name);

        for (category_name, result) in categories {
            let rate_emoji = if result.avg_success_rate >= 0.95 {
                "🟢"
            } else if result.avg_success_rate >= 0.80 {
                "🟡"
            } else if result.avg_success_rate >= 0.60 {
                "🟠"
            } else {
                "🔴"
            };

            let best_tech = result
                .best_technique
                .map(|t| format!("`{t:?}`"))
                .unwrap_or_else(|| "N/A".to_string());

            output.push_str(&format!(
                "| {} | {} {:.1}% | {} | {} | {} |\n",
                category_name,
                rate_emoji,
                result.avg_success_rate * 100.0,
                result.completed_cases,
                result.total_cases,
                best_tech
            ));
        }
        output.push('\n');

        // Evaluation details if available
        if let Some(eval) = &self.evaluation {
            output.push_str("## Evaluation\n\n");
            output.push_str(&format!("**{}**\n\n", eval.summary()));

            if !eval.notes.is_empty() {
                output.push_str("### Notes\n\n");
                for note in &eval.notes {
                    output.push_str(&format!("- {note}\n"));
                }
                output.push('\n');
            }
        }

        // Regression info if available
        if let Some(baseline) = &self.baseline {
            output.push_str("## Regression Analysis\n\n");

            let criteria = RegressionCriteria::production();
            let status = criteria.is_regression(
                baseline.overall_success_rate,
                self.report.overall_success_rate,
                0.0,
                0.0,
            );

            let (emoji, status_text) = match &status {
                RegressionStatus::Regression(msg) => ("⚠️", format!("Regression detected: {msg}")),
                RegressionStatus::NoChange => ("➡️", "No significant change".to_string()),
                RegressionStatus::Improvement(msg) => ("📈", format!("Improvement: {msg}")),
            };

            output.push_str(&format!(
                "| | Baseline | Current |\n|---|---|---|\n| Run ID | `{}` | `{}` |\n| Success Rate | {:.1}% | {:.1}% |\n\n",
                baseline.run_id,
                self.report.run_id,
                baseline.overall_success_rate * 100.0,
                self.report.overall_success_rate * 100.0
            ));
            output.push_str(&format!("{emoji} **{status_text}**\n\n"));
        }

        // Configuration collapsible
        output.push_str("<details>\n<summary>Configuration</summary>\n\n");
        output.push_str("```yaml\n");
        output.push_str(&format!(
            "attempts_per_path: {}\n",
            self.report.config.attempts_per_path
        ));
        output.push_str(&format!(
            "attempt_timeout: {:?}\n",
            self.report.config.attempt_timeout
        ));
        output.push_str(&format!(
            "barrier_timeout: {:?}\n",
            self.report.config.barrier_timeout
        ));
        output.push_str(&format!(
            "nat_mapping_cooldown: {:?}\n",
            self.report.config.nat_mapping_cooldown
        ));
        output.push_str(&format!(
            "strict_cooldown: {}\n",
            self.report.config.strict_cooldown
        ));
        output.push_str(&format!(
            "min_success_rate: {}\n",
            self.report.config.min_success_rate
        ));
        output.push_str("```\n\n");
        output.push_str("</details>\n");

        output
    }

    /// Generate compact CI summary.
    fn to_ci_summary(&self) -> String {
        let mut output = String::new();

        // Single-line status
        let status = if self.report.passed { "PASS" } else { "FAIL" };
        output.push_str(&format!(
            "[{}] Connectivity Matrix: {:.1}% success ({} test cases)\n",
            status,
            self.report.overall_success_rate * 100.0,
            self.report.test_cases.len()
        ));

        // Category one-liners
        let mut categories: Vec<_> = self.report.results_by_category.iter().collect();
        categories.sort_by_key(|(name, _)| *name);

        for (name, result) in categories {
            let status = if result.avg_success_rate >= self.report.config.min_success_rate {
                "OK"
            } else {
                "LOW"
            };
            output.push_str(&format!(
                "  [{status}] {name}: {:.1}% ({}/{})\n",
                result.avg_success_rate * 100.0,
                result.completed_cases,
                result.total_cases
            ));
        }

        // Regression line if applicable
        if let Some(baseline) = &self.baseline {
            let diff = self.report.overall_success_rate - baseline.overall_success_rate;
            let sign = if diff >= 0.0 { "+" } else { "" };
            output.push_str(&format!(
                "  [ΔBASE] vs {}: {sign}{:.1}%\n",
                baseline.run_id,
                diff * 100.0
            ));
        }

        output
    }

    /// Get exit code suitable for CI (0 = pass, 1 = fail).
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.report.passed { 0 } else { 1 }
    }

    /// Write report to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn write_to_file(
        &self,
        path: &std::path::Path,
        format: ReportFormat,
    ) -> std::io::Result<()> {
        let content = self.generate(format);
        std::fs::write(path, content)
    }
}

/// Trait for report output adapters.
pub trait ReportOutput {
    /// Write the report content.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write(&self, content: &str) -> std::io::Result<()>;
}

/// Console output adapter.
pub struct ConsoleOutput;

impl ReportOutput for ConsoleOutput {
    fn write(&self, content: &str) -> std::io::Result<()> {
        print!("{content}");
        Ok(())
    }
}

/// File output adapter.
pub struct FileOutput {
    path: std::path::PathBuf,
}

impl FileOutput {
    /// Create a new file output adapter.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ReportOutput for FileOutput {
    fn write(&self, content: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, content)
    }
}

/// Test group for parallel or synchronized execution.
#[derive(Debug, Clone)]
pub struct TestGroup {
    /// Group identifier.
    pub id: String,
    /// Test cases in this group.
    pub test_cases: Vec<MatrixTestCase>,
    /// Whether this group requires barrier synchronization.
    pub requires_barrier: bool,
    /// Group priority (lower = run first).
    pub priority: u8,
}

/// The main connectivity matrix runner.
pub struct ConnectivityMatrixRunner {
    /// Configuration.
    config: MatrixRunnerConfig,
    /// Available agents.
    agents: Vec<MatrixAgentInfo>,
    /// Connection paths to test.
    paths: Vec<ConnectionPath>,
    /// Agent clients for communication.
    clients: HashMap<String, AgentClient>,
    /// Current run ID.
    run_id: Option<String>,
}

impl ConnectivityMatrixRunner {
    /// Create a new matrix runner with the given configuration.
    #[must_use]
    pub fn new(config: MatrixRunnerConfig) -> Self {
        Self {
            paths: super::build_connection_matrix(&config.profiles, &config.ip_modes),
            config,
            agents: Vec::new(),
            clients: HashMap::new(),
            run_id: None,
        }
    }

    /// Register an agent for testing.
    pub fn register_agent(&mut self, agent: MatrixAgentInfo) {
        let client = AgentClient::new(
            &agent.api_base_url,
            &agent.agent_id,
            agent.p2p_listen_addr,
        );
        self.clients.insert(agent.agent_id.clone(), client);
        self.agents.push(agent);
    }

    /// Get the connection paths to test.
    #[must_use]
    pub fn paths(&self) -> &[ConnectionPath] {
        &self.paths
    }

    /// Get the matrix analysis.
    #[must_use]
    pub fn analysis(&self) -> ConnectionMatrixAnalysis {
        ConnectionMatrixAnalysis::from_paths(&self.paths)
    }

    /// Generate test cases from paths and agent assignments.
    #[must_use]
    pub fn generate_test_cases(&self) -> Vec<MatrixTestCase> {
        let mut test_cases = Vec::new();

        // Group agents by their assigned NAT profile
        let agents_by_profile: HashMap<String, Vec<&MatrixAgentInfo>> = self
            .agents
            .iter()
            .fold(HashMap::new(), |mut acc, agent| {
                acc.entry(agent.nat_profile.clone())
                    .or_default()
                    .push(agent);
                acc
            });

        for path in &self.paths {
            // Skip relay-required paths if configured
            if self.config.skip_relay_required
                && matches!(path.category, PathCategory::RelayRequired)
            {
                continue;
            }

            // Find agents for this path
            let agents_a = agents_by_profile.get(&path.nat_a);
            let agents_b = agents_by_profile.get(&path.nat_b);

            if let (Some(agents_a), Some(agents_b)) = (agents_a, agents_b) {
                if let (Some(agent_a), Some(agent_b)) =
                    (agents_a.first(), agents_b.first())
                {
                    let mut test_case = MatrixTestCase {
                        id: format!("{}_{}", self.run_id.as_deref().unwrap_or("run"), path.dimension_key()),
                        path: path.clone(),
                        agent_a: MatrixAgentAssignment {
                            agent_id: agent_a.agent_id.clone(),
                            control_url: agent_a.api_base_url.clone(),
                            p2p_addr: agent_a.p2p_listen_addr,
                            nat_profile: path.nat_a.clone(),
                            status: MatrixAgentAssignmentStatus::Ready,
                            last_peer_contact: None, // Will be populated when available
                        },
                        agent_b: MatrixAgentAssignment {
                            agent_id: agent_b.agent_id.clone(),
                            control_url: agent_b.api_base_url.clone(),
                            p2p_addr: agent_b.p2p_listen_addr,
                            nat_profile: path.nat_b.clone(),
                            status: MatrixAgentAssignmentStatus::Ready,
                            last_peer_contact: None, // Will be populated when available
                        },
                        techniques: path.viable_techniques(),
                        attempts: self.config.attempts_per_path,
                        status: TestCaseStatus::Pending,
                        cooldown_status: CooldownStatus::Unknown, // Default until contact times known
                    };

                    // Update cooldown status based on config
                    test_case.update_cooldown_status(
                        self.config.nat_mapping_cooldown,
                        self.config.strict_cooldown,
                    );

                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Group test cases for execution.
    ///
    /// Returns groups that can be run in parallel and groups that
    /// require barrier synchronization.
    #[must_use]
    pub fn group_test_cases(&self, test_cases: &[MatrixTestCase]) -> Vec<TestGroup> {
        let mut groups = Vec::new();

        // Group 1: Direct paths (can run in parallel)
        let direct_cases: Vec<_> = test_cases
            .iter()
            .filter(|tc| tc.path.category == PathCategory::Direct)
            .cloned()
            .collect();

        if !direct_cases.is_empty() {
            groups.push(TestGroup {
                id: "direct".to_string(),
                test_cases: direct_cases,
                requires_barrier: false,
                priority: 0,
            });
        }

        // Group 2: Hole-punchable paths (can run in parallel)
        let holepunch_cases: Vec<_> = test_cases
            .iter()
            .filter(|tc| tc.path.category == PathCategory::HolePunchable)
            .cloned()
            .collect();

        if !holepunch_cases.is_empty() {
            groups.push(TestGroup {
                id: "holepunchable".to_string(),
                test_cases: holepunch_cases,
                requires_barrier: false,
                priority: 1,
            });
        }

        // Group 3: Coordinated-only paths (require barrier sync)
        let coordinated_cases: Vec<_> = test_cases
            .iter()
            .filter(|tc| tc.path.category == PathCategory::CoordinatedOnly)
            .cloned()
            .collect();

        if !coordinated_cases.is_empty() {
            groups.push(TestGroup {
                id: "coordinated".to_string(),
                test_cases: coordinated_cases,
                requires_barrier: true,
                priority: 2,
            });
        }

        // Group 4: Relay-required paths
        let relay_cases: Vec<_> = test_cases
            .iter()
            .filter(|tc| tc.path.category == PathCategory::RelayRequired)
            .cloned()
            .collect();

        if !relay_cases.is_empty() {
            groups.push(TestGroup {
                id: "relay_required".to_string(),
                test_cases: relay_cases,
                requires_barrier: false,
                priority: 3,
            });
        }

        // Group 5: IP mismatch paths
        let mismatch_cases: Vec<_> = test_cases
            .iter()
            .filter(|tc| tc.path.category == PathCategory::IpMismatch)
            .cloned()
            .collect();

        if !mismatch_cases.is_empty() {
            groups.push(TestGroup {
                id: "ip_mismatch".to_string(),
                test_cases: mismatch_cases,
                requires_barrier: false,
                priority: 4,
            });
        }

        // Sort by priority
        groups.sort_by_key(|g| g.priority);

        groups
    }

    /// Build a barrier request for synchronized testing.
    #[must_use]
    pub fn build_barrier_request(&self, test_case: &MatrixTestCase) -> MatrixBarrierRequest {
        MatrixBarrierRequest {
            barrier_id: format!("barrier_{}", test_case.id),
            participants: vec![
                test_case.agent_a.agent_id.clone(),
                test_case.agent_b.agent_id.clone(),
            ],
            timeout_ms: self.config.barrier_timeout.as_millis() as u64,
        }
    }

    /// Build a start run request for an agent.
    #[must_use]
    pub fn build_start_request(&self, test_case: &MatrixTestCase, agent_id: &str) -> MatrixStartRunRequest {
        let (target_addr, initiator) = if agent_id == test_case.agent_a.agent_id {
            (test_case.agent_b.p2p_addr, true)
        } else {
            (test_case.agent_a.p2p_addr, false)
        };

        // Build peer agents list (the other agent)
        let peer_agents = if agent_id == test_case.agent_a.agent_id {
            vec![PeerAgentInfo {
                agent_id: test_case.agent_b.agent_id.clone(),
                api_base_url: Some(test_case.agent_b.control_url.clone()),
                p2p_listen_addr: test_case.agent_b.p2p_addr,
                nat_profile: Some(test_case.agent_b.nat_profile.clone()),
            }]
        } else {
            vec![PeerAgentInfo {
                agent_id: test_case.agent_a.agent_id.clone(),
                api_base_url: Some(test_case.agent_a.control_url.clone()),
                p2p_listen_addr: test_case.agent_a.p2p_addr,
                nat_profile: Some(test_case.agent_a.nat_profile.clone()),
            }]
        };

        MatrixStartRunRequest {
            run_id: test_case.id.clone(),
            scenario_id: format!("matrix_{}", test_case.path.category.short_id()),
            peer_agents,
            connection_target: Some(target_addr.to_string()),
            initiator,
            techniques: test_case.techniques.iter().map(|t| format!("{t:?}")).collect(),
            attempts: test_case.attempts,
            timeout_ms: self.config.attempt_timeout.as_millis() as u64,
        }
    }

    /// Aggregate results from test cases into a report.
    #[must_use]
    pub fn aggregate_results(&self, test_cases: Vec<MatrixTestCase>) -> MatrixRunReport {
        let mut results_by_category: HashMap<String, CategoryResult> = HashMap::new();
        let mut total_successes = 0.0;
        let mut total_cases = 0;
        let mut notes = Vec::new();

        for test_case in &test_cases {
            let category_key = test_case.path.category.to_string();

            let category_result = results_by_category
                .entry(category_key.clone())
                .or_insert_with(|| CategoryResult {
                    category: test_case.path.category,
                    total_cases: 0,
                    completed_cases: 0,
                    avg_success_rate: 0.0,
                    best_technique: None,
                    notes: Vec::new(),
                });

            category_result.total_cases += 1;

            if let TestCaseStatus::Completed(result) = &test_case.status {
                category_result.completed_cases += 1;
                category_result.avg_success_rate += result.success_rate;
                total_successes += result.success_rate;
                total_cases += 1;

                // Track best technique
                if let Some(tech) = result.successful_technique {
                    if category_result.best_technique.is_none()
                        || result.success_rate > 0.9
                    {
                        category_result.best_technique = Some(tech);
                    }
                }
            }
        }

        // Calculate averages
        for category_result in results_by_category.values_mut() {
            if category_result.completed_cases > 0 {
                category_result.avg_success_rate /= category_result.completed_cases as f64;
            }
        }

        let overall_success_rate = if total_cases > 0 {
            total_successes / total_cases as f64
        } else {
            0.0
        };

        let passed = overall_success_rate >= self.config.min_success_rate;

        if !passed {
            notes.push(format!(
                "Run failed: success rate {:.1}% below threshold {:.1}%",
                overall_success_rate * 100.0,
                self.config.min_success_rate * 100.0
            ));
        }

        // Add notes about problematic categories
        for (category_name, result) in &results_by_category {
            if result.avg_success_rate < 0.5 && result.completed_cases > 0 {
                notes.push(format!(
                    "{} category has low success rate: {:.1}%",
                    category_name,
                    result.avg_success_rate * 100.0
                ));
            }
        }

        MatrixRunReport {
            run_id: self.run_id.clone().unwrap_or_else(|| "unknown".to_string()),
            started_at: Utc::now(), // Would be tracked during actual run
            completed_at: Some(Utc::now()),
            config: self.config.clone(),
            matrix_analysis: self.analysis(),
            test_cases,
            results_by_category,
            overall_success_rate,
            passed,
            notes,
        }
    }

    /// Set the run ID.
    pub fn set_run_id(&mut self, run_id: String) {
        self.run_id = Some(run_id);
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &MatrixRunnerConfig {
        &self.config
    }

    /// Get registered agents.
    #[must_use]
    pub fn agents(&self) -> &[MatrixAgentInfo] {
        &self.agents
    }

    /// Check if runner has enough agents for the matrix.
    #[must_use]
    pub fn has_sufficient_agents(&self) -> bool {
        // Need at least 2 agents
        if self.agents.len() < 2 {
            return false;
        }

        // Check we have agents for each profile needed
        let profiles_needed: std::collections::HashSet<_> = self
            .paths
            .iter()
            .flat_map(|p| vec![p.nat_a.clone(), p.nat_b.clone()])
            .collect();

        let profiles_available: std::collections::HashSet<_> = self
            .agents
            .iter()
            .map(|a| a.nat_profile.clone())
            .collect();

        profiles_needed.is_subset(&profiles_available)
    }

    /// Get missing profiles that need agents.
    #[must_use]
    pub fn missing_profiles(&self) -> Vec<String> {
        let profiles_needed: std::collections::HashSet<_> = self
            .paths
            .iter()
            .flat_map(|p| vec![p.nat_a.clone(), p.nat_b.clone()])
            .collect();

        let profiles_available: std::collections::HashSet<_> = self
            .agents
            .iter()
            .map(|a| a.nat_profile.clone())
            .collect();

        profiles_needed
            .difference(&profiles_available)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = MatrixRunnerConfig::default();
        assert_eq!(config.attempts_per_path, 10);
        assert!(!config.skip_relay_required);
        assert!(config.detailed_metrics);
    }

    #[test]
    fn test_ci_fast_config() {
        let config = MatrixRunnerConfig::ci_fast();
        assert_eq!(config.attempts_per_path, 3);
        assert!(config.skip_relay_required);
        assert!(!config.detailed_metrics);
    }

    #[test]
    fn test_production_config() {
        let config = MatrixRunnerConfig::production();
        assert_eq!(config.attempts_per_path, 100);
        assert!(!config.skip_relay_required);
        assert!(config.detailed_metrics);
    }

    #[test]
    fn test_runner_creation() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());
        // Default profiles: none, full_cone, address_restricted, port_restricted, symmetric (5)
        // Default IP modes: 3
        // Total paths: 5 * 5 * 3 = 75
        assert_eq!(runner.paths().len(), 75);
    }

    #[test]
    fn test_analysis() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());
        let analysis = runner.analysis();
        assert_eq!(analysis.total_paths, 75);
        assert!(analysis.avg_success_rate > 0.0);
    }

    #[test]
    fn test_group_test_cases() {
        let mut runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::ci_fast());

        // Add mock agents
        runner.register_agent(MatrixAgentInfo::new(
            "agent-a",
            "http://localhost:8080",
            "127.0.0.1:9000".parse().unwrap(),
            "none",
        ));

        runner.register_agent(MatrixAgentInfo::new(
            "agent-b",
            "http://localhost:8081",
            "127.0.0.1:9001".parse().unwrap(),
            "full_cone",
        ));

        let test_cases = runner.generate_test_cases();
        let groups = runner.group_test_cases(&test_cases);

        // Should have at least one group
        assert!(!groups.is_empty());

        // Groups should be sorted by priority
        for i in 1..groups.len() {
            assert!(groups[i].priority >= groups[i - 1].priority);
        }
    }

    #[test]
    fn test_barrier_request() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());

        let test_case = MatrixTestCase {
            id: "test_1".to_string(),
            path: ConnectionPath {
                category: PathCategory::CoordinatedOnly,
                nat_a: "symmetric".to_string(),
                nat_b: "full_cone".to_string(),
                ip_mode: IpMode::Ipv4Only,
                technique_priority: vec![],
                estimated_success_rate: 0.7,
                relay_recommended: true,
                notes: vec![],
            },
            agent_a: MatrixAgentAssignment {
                agent_id: "agent-a".to_string(),
                control_url: "http://localhost:8080".to_string(),
                p2p_addr: "127.0.0.1:9000".parse().unwrap(),
                nat_profile: "symmetric".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            agent_b: MatrixAgentAssignment {
                agent_id: "agent-b".to_string(),
                control_url: "http://localhost:8081".to_string(),
                p2p_addr: "127.0.0.1:9001".parse().unwrap(),
                nat_profile: "full_cone".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            techniques: vec![ConnectionTechnique::HolePunchCoordinated],
            attempts: 10,
            status: TestCaseStatus::Pending,
            cooldown_status: CooldownStatus::Unknown,
        };

        let barrier = runner.build_barrier_request(&test_case);
        assert_eq!(barrier.barrier_id, "barrier_test_1");
        assert_eq!(barrier.participants.len(), 2);
        assert!(barrier.participants.contains(&"agent-a".to_string()));
        assert!(barrier.participants.contains(&"agent-b".to_string()));
    }

    #[test]
    fn test_start_request_initiator() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());

        let test_case = MatrixTestCase {
            id: "test_1".to_string(),
            path: ConnectionPath {
                category: PathCategory::HolePunchable,
                nat_a: "none".to_string(),
                nat_b: "full_cone".to_string(),
                ip_mode: IpMode::Ipv4Only,
                technique_priority: vec![],
                estimated_success_rate: 0.9,
                relay_recommended: false,
                notes: vec![],
            },
            agent_a: MatrixAgentAssignment {
                agent_id: "agent-a".to_string(),
                control_url: "http://localhost:8080".to_string(),
                p2p_addr: "127.0.0.1:9000".parse().unwrap(),
                nat_profile: "none".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            agent_b: MatrixAgentAssignment {
                agent_id: "agent-b".to_string(),
                control_url: "http://localhost:8081".to_string(),
                p2p_addr: "127.0.0.1:9001".parse().unwrap(),
                nat_profile: "full_cone".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            techniques: vec![ConnectionTechnique::HolePunch],
            attempts: 10,
            status: TestCaseStatus::Pending,
            cooldown_status: CooldownStatus::Unknown,
        };

        // Agent A should be initiator
        let request_a = runner.build_start_request(&test_case, "agent-a");
        assert!(request_a.initiator);
        assert_eq!(request_a.connection_target, Some("127.0.0.1:9001".to_string()));

        // Agent B should not be initiator
        let request_b = runner.build_start_request(&test_case, "agent-b");
        assert!(!request_b.initiator);
        assert_eq!(request_b.connection_target, Some("127.0.0.1:9000".to_string()));
    }

    #[test]
    fn test_aggregate_results_empty() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());
        let report = runner.aggregate_results(vec![]);

        assert_eq!(report.overall_success_rate, 0.0);
        assert!(!report.passed);
        assert!(report.test_cases.is_empty());
    }

    #[test]
    fn test_aggregate_results_with_data() {
        let mut runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());
        runner.set_run_id("test_run_1".to_string());

        let test_cases = vec![
            MatrixTestCase {
                id: "test_1".to_string(),
                path: ConnectionPath {
                    category: PathCategory::Direct,
                    nat_a: "none".to_string(),
                    nat_b: "none".to_string(),
                    ip_mode: IpMode::Ipv4Only,
                    technique_priority: vec![],
                    estimated_success_rate: 0.99,
                    relay_recommended: false,
                    notes: vec![],
                },
                agent_a: MatrixAgentAssignment {
                    agent_id: "agent-a".to_string(),
                    control_url: "http://localhost:8080".to_string(),
                    p2p_addr: "127.0.0.1:9000".parse().unwrap(),
                    nat_profile: "none".to_string(),
                    status: MatrixAgentAssignmentStatus::Completed,
                    last_peer_contact: None,
                },
                agent_b: MatrixAgentAssignment {
                    agent_id: "agent-b".to_string(),
                    control_url: "http://localhost:8081".to_string(),
                    p2p_addr: "127.0.0.1:9001".parse().unwrap(),
                    nat_profile: "none".to_string(),
                    status: MatrixAgentAssignmentStatus::Completed,
                    last_peer_contact: None,
                },
                techniques: vec![ConnectionTechnique::DirectIpv4],
                attempts: 10,
                status: TestCaseStatus::Completed(TestCaseResult {
                    attempts: 10,
                    successes: 10,
                    success_rate: 1.0,
                    successful_technique: Some(ConnectionTechnique::DirectIpv4),
                    avg_rtt_ms: Some(5.0),
                    p95_rtt_ms: Some(8.0),
                    technique_results: HashMap::new(),
                }),
                cooldown_status: CooldownStatus::Ready,
            },
        ];

        let report = runner.aggregate_results(test_cases);

        assert_eq!(report.run_id, "test_run_1");
        assert_eq!(report.overall_success_rate, 1.0);
        assert!(report.passed);
        assert_eq!(report.test_cases.len(), 1);

        let direct_result = report.results_by_category.get("Direct").unwrap();
        assert_eq!(direct_result.total_cases, 1);
        assert_eq!(direct_result.completed_cases, 1);
        assert_eq!(direct_result.avg_success_rate, 1.0);
    }

    #[test]
    fn test_cooldown_status() {
        // Test with no contact history - should be Unknown
        let mut test_case = MatrixTestCase {
            id: "test_1".to_string(),
            path: ConnectionPath {
                category: PathCategory::HolePunchable,
                nat_a: "none".to_string(),
                nat_b: "full_cone".to_string(),
                ip_mode: IpMode::Ipv4Only,
                technique_priority: vec![],
                estimated_success_rate: 0.9,
                relay_recommended: false,
                notes: vec![],
            },
            agent_a: MatrixAgentAssignment {
                agent_id: "agent-a".to_string(),
                control_url: "http://localhost:8080".to_string(),
                p2p_addr: "127.0.0.1:9000".parse().unwrap(),
                nat_profile: "none".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            agent_b: MatrixAgentAssignment {
                agent_id: "agent-b".to_string(),
                control_url: "http://localhost:8081".to_string(),
                p2p_addr: "127.0.0.1:9001".parse().unwrap(),
                nat_profile: "full_cone".to_string(),
                status: MatrixAgentAssignmentStatus::Ready,
                last_peer_contact: None,
            },
            techniques: vec![ConnectionTechnique::HolePunch],
            attempts: 10,
            status: TestCaseStatus::Pending,
            cooldown_status: CooldownStatus::Unknown,
        };

        test_case.update_cooldown_status(Duration::from_secs(30), true);
        assert_eq!(test_case.cooldown_status, CooldownStatus::Unknown);
        assert!(test_case.is_cooldown_satisfied());

        // Test with recent contact - should be WaitingUntil
        test_case.agent_a.last_peer_contact = Some(Utc::now());
        test_case.update_cooldown_status(Duration::from_secs(30), true);
        assert!(matches!(test_case.cooldown_status, CooldownStatus::WaitingUntil(_)));
        assert!(!test_case.is_cooldown_satisfied());

        // Test with old contact - should be Ready
        test_case.agent_a.last_peer_contact = Some(Utc::now() - chrono::Duration::seconds(60));
        test_case.update_cooldown_status(Duration::from_secs(30), true);
        assert_eq!(test_case.cooldown_status, CooldownStatus::Ready);
        assert!(test_case.is_cooldown_satisfied());

        // Test non-strict mode - should be Skipped
        test_case.agent_a.last_peer_contact = Some(Utc::now());
        test_case.update_cooldown_status(Duration::from_secs(30), false);
        assert_eq!(test_case.cooldown_status, CooldownStatus::Skipped);
        assert!(test_case.is_cooldown_satisfied());
    }

    #[test]
    fn test_config_nat_cooldown() {
        let config = MatrixRunnerConfig::default();
        assert_eq!(config.nat_mapping_cooldown, Duration::from_secs(30));
        assert!(config.strict_cooldown);

        let ci_config = MatrixRunnerConfig::ci_fast();
        assert_eq!(ci_config.nat_mapping_cooldown, Duration::from_secs(15));
        assert!(!ci_config.strict_cooldown);

        let prod_config = MatrixRunnerConfig::production();
        assert_eq!(prod_config.nat_mapping_cooldown, Duration::from_secs(30));
        assert!(prod_config.strict_cooldown);
    }

    #[test]
    fn test_missing_profiles() {
        let runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::default());

        // No agents registered, should have missing profiles
        let missing = runner.missing_profiles();
        assert!(!missing.is_empty());

        // Should include standard profiles
        let profiles: std::collections::HashSet<_> = missing.into_iter().collect();
        assert!(profiles.contains("none"));
        assert!(profiles.contains("full_cone"));
    }

    #[test]
    fn test_has_sufficient_agents() {
        let mut runner = ConnectivityMatrixRunner::new(MatrixRunnerConfig::ci_fast());

        // Initially no agents
        assert!(!runner.has_sufficient_agents());

        // Add one agent - still not enough
        runner.register_agent(MatrixAgentInfo::new(
            "agent-a",
            "http://localhost:8080",
            "127.0.0.1:9000".parse().unwrap(),
            "none",
        ));
        assert!(!runner.has_sufficient_agents());
    }

    // =========================================================================
    // Success Criteria Tests
    // =========================================================================

    #[test]
    fn test_success_criteria_production() {
        let criteria = MatrixSuccessCriteria::production();
        assert!(criteria.overall_min_success_rate >= 0.90);
        assert!(criteria.category_criteria.contains_key(&PathCategory::Direct));
        assert!(criteria.category_criteria.contains_key(&PathCategory::HolePunchable));
        assert!(criteria.category_criteria.contains_key(&PathCategory::RelayRequired));
        assert!(!criteria.fail_on_category_failure);
    }

    #[test]
    fn test_success_criteria_ci() {
        let criteria = MatrixSuccessCriteria::ci();
        assert!(criteria.overall_min_success_rate < 0.90);
        assert!(criteria.min_cases_per_category < 10);
    }

    #[test]
    fn test_success_criteria_release() {
        let criteria = MatrixSuccessCriteria::release();
        assert!(criteria.overall_min_success_rate >= 0.95);
        assert!(criteria.fail_on_category_failure);
        assert!(criteria.min_cases_per_category >= 50);
    }

    #[test]
    fn test_category_success_criteria() {
        // Direct should have highest requirements
        let direct = CategorySuccessCriteria::for_direct();
        assert!(direct.min_success_rate >= 0.99);
        assert!(direct.required);

        // Hole-punchable should be slightly lower
        let holepunch = CategorySuccessCriteria::for_holepunchable();
        assert!(holepunch.min_success_rate >= 0.80);
        assert!(holepunch.min_success_rate < direct.min_success_rate);

        // IP mismatch should not be required
        let ip_mismatch = CategorySuccessCriteria::for_ip_mismatch();
        assert!(!ip_mismatch.required);
        assert!(ip_mismatch.weight == 0.0);
    }

    #[test]
    fn test_technique_success_criteria() {
        let direct = TechniqueSuccessCriteria::for_direct();
        assert!(direct.min_success_rate >= 0.99);
        assert!(direct.required);

        let relay = TechniqueSuccessCriteria::for_relay();
        assert!(relay.min_success_rate >= 0.95);
        assert!(relay.required);
    }

    #[test]
    fn test_rtt_thresholds_classification() {
        let thresholds = RttThresholds::production();

        assert_eq!(thresholds.classify(10), RttQuality::Excellent);
        assert_eq!(thresholds.classify(100), RttQuality::Good);
        assert_eq!(thresholds.classify(300), RttQuality::Acceptable);
        assert_eq!(thresholds.classify(1000), RttQuality::Poor);
        assert_eq!(thresholds.classify(5000), RttQuality::Unacceptable);
    }

    #[test]
    fn test_rtt_quality_acceptable() {
        assert!(RttQuality::Excellent.is_acceptable());
        assert!(RttQuality::Good.is_acceptable());
        assert!(RttQuality::Acceptable.is_acceptable());
        assert!(!RttQuality::Poor.is_acceptable());
        assert!(!RttQuality::Unacceptable.is_acceptable());
    }

    #[test]
    fn test_regression_criteria_detection() {
        let criteria = RegressionCriteria::production();

        // Test regression detection
        let status = criteria.is_regression(0.95, 0.85, 100.0, 100.0);
        assert!(matches!(status, RegressionStatus::Regression(_)));

        // Test no change
        let status = criteria.is_regression(0.95, 0.94, 100.0, 105.0);
        assert!(matches!(status, RegressionStatus::NoChange));

        // Test improvement
        let status = criteria.is_regression(0.90, 0.98, 100.0, 90.0);
        assert!(matches!(status, RegressionStatus::Improvement(_)));

        // Test RTT regression
        let status = criteria.is_regression(0.95, 0.95, 100.0, 200.0);
        assert!(matches!(status, RegressionStatus::Regression(_)));
    }

    #[test]
    fn test_matrix_evaluation_result_summary() {
        let result = MatrixEvaluationResult {
            passes: true,
            overall_success_rate: 0.95,
            min_required_rate: 0.90,
            category_results: HashMap::new(),
            notes: vec![],
        };

        let summary = result.summary();
        assert!(summary.contains("PASS"));
        assert!(summary.contains("95.0%"));

        let result_fail = MatrixEvaluationResult {
            passes: false,
            overall_success_rate: 0.80,
            min_required_rate: 0.90,
            category_results: HashMap::new(),
            notes: vec![],
        };

        let summary = result_fail.summary();
        assert!(summary.contains("FAIL"));
    }

    // =========================================================================
    // Report Generation Tests
    // =========================================================================

    fn create_test_report(passed: bool, success_rate: f64) -> MatrixRunReport {
        let mut results_by_category = HashMap::new();
        results_by_category.insert(
            "Direct".to_string(),
            CategoryResult {
                category: PathCategory::Direct,
                total_cases: 10,
                completed_cases: 10,
                avg_success_rate: 0.99,
                best_technique: Some(ConnectionTechnique::DirectIpv4),
                notes: vec![],
            },
        );
        results_by_category.insert(
            "HolePunchable".to_string(),
            CategoryResult {
                category: PathCategory::HolePunchable,
                total_cases: 20,
                completed_cases: 18,
                avg_success_rate: 0.85,
                best_technique: Some(ConnectionTechnique::HolePunch),
                notes: vec![],
            },
        );

        let mut by_category_analysis = HashMap::new();
        by_category_analysis.insert("Direct".to_string(), 15);
        by_category_analysis.insert("HolePunchable".to_string(), 30);
        by_category_analysis.insert("CoordinatedOnly".to_string(), 15);
        by_category_analysis.insert("RelayRequired".to_string(), 10);
        by_category_analysis.insert("IpMismatch".to_string(), 5);

        MatrixRunReport {
            run_id: "test_run_001".to_string(),
            started_at: Utc::now() - chrono::Duration::seconds(120),
            completed_at: Some(Utc::now()),
            config: MatrixRunnerConfig::default(),
            matrix_analysis: ConnectionMatrixAnalysis {
                total_paths: 75,
                by_category: by_category_analysis,
                avg_success_rate: success_rate,
                relay_required_count: 10,
                technique_distribution: HashMap::new(),
            },
            test_cases: vec![],
            results_by_category,
            overall_success_rate: success_rate,
            passed,
            notes: if passed {
                vec![]
            } else {
                vec!["Test failed due to low success rate".to_string()]
            },
        }
    }

    #[test]
    fn test_report_generator_text_format() {
        let report = create_test_report(true, 0.95);
        let generator = MatrixReportGenerator::new(&report);

        let text = generator.generate(ReportFormat::Text);

        // Check for key sections
        assert!(text.contains("CONNECTIVITY MATRIX REPORT"));
        assert!(text.contains("PASSED"));
        assert!(text.contains("SUMMARY"));
        assert!(text.contains("test_run_001"));
        assert!(text.contains("95.0%"));
        assert!(text.contains("RESULTS BY CATEGORY"));
        assert!(text.contains("Direct"));
        assert!(text.contains("HolePunchable"));
        assert!(text.contains("CONFIGURATION"));
    }

    #[test]
    fn test_report_generator_plain_text_format() {
        let report = create_test_report(false, 0.75);
        let generator = MatrixReportGenerator::new(&report);

        let text = generator.generate(ReportFormat::PlainText);

        // Should not contain ANSI color codes
        assert!(!text.contains("\x1b["));
        assert!(text.contains("FAILED"));
        assert!(text.contains("75.0%"));
    }

    #[test]
    fn test_report_generator_json_format() {
        let report = create_test_report(true, 0.92);
        let generator = MatrixReportGenerator::new(&report);

        let json = generator.generate(ReportFormat::Json);

        // Parse the JSON to validate it
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Valid JSON");

        assert!(parsed.get("report").is_some());
        assert_eq!(
            parsed["report"]["run_id"].as_str().unwrap(),
            "test_run_001"
        );
        assert!(parsed["report"]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_report_generator_json_compact_format() {
        let report = create_test_report(true, 0.92);
        let generator = MatrixReportGenerator::new(&report);

        let json_pretty = generator.generate(ReportFormat::Json);
        let json_compact = generator.generate(ReportFormat::JsonCompact);

        // Compact should be shorter (no extra whitespace)
        assert!(json_compact.len() < json_pretty.len());

        // Both should be valid JSON
        let _: serde_json::Value = serde_json::from_str(&json_compact).expect("Valid JSON");
    }

    #[test]
    fn test_report_generator_markdown_format() {
        let report = create_test_report(true, 0.95);
        let generator = MatrixReportGenerator::new(&report);

        let markdown = generator.generate(ReportFormat::Markdown);

        // Check for Markdown elements
        assert!(markdown.contains("# Connectivity Matrix Report"));
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("| Metric | Value |"));
        assert!(markdown.contains("## Results by Category"));
        assert!(markdown.contains("`test_run_001`"));
        assert!(markdown.contains("✅ PASSED"));
        assert!(markdown.contains("<details>"));
        assert!(markdown.contains("</details>"));
    }

    #[test]
    fn test_report_generator_markdown_failed() {
        let report = create_test_report(false, 0.70);
        let generator = MatrixReportGenerator::new(&report);

        let markdown = generator.generate(ReportFormat::Markdown);

        assert!(markdown.contains("❌ FAILED"));
        assert!(markdown.contains("status-FAILED-red"));
    }

    #[test]
    fn test_report_generator_ci_summary_format() {
        let report = create_test_report(true, 0.95);
        let generator = MatrixReportGenerator::new(&report);

        let ci = generator.generate(ReportFormat::CiSummary);

        // Should be compact
        assert!(ci.lines().count() <= 10);
        assert!(ci.contains("[PASS]"));
        assert!(ci.contains("95.0%"));
        assert!(ci.contains("[OK]"));
    }

    #[test]
    fn test_report_generator_ci_summary_failed() {
        let report = create_test_report(false, 0.65);
        let generator = MatrixReportGenerator::new(&report);

        let ci = generator.generate(ReportFormat::CiSummary);

        assert!(ci.contains("[FAIL]"));
        assert!(ci.contains("[LOW]"));
    }

    #[test]
    fn test_report_generator_with_evaluation() {
        let report = create_test_report(true, 0.95);
        let evaluation = MatrixEvaluationResult {
            passes: true,
            overall_success_rate: 0.95,
            min_required_rate: 0.90,
            category_results: {
                let mut map = HashMap::new();
                map.insert(PathCategory::Direct, true);
                map.insert(PathCategory::HolePunchable, true);
                map
            },
            notes: vec!["All criteria met".to_string()],
        };

        let generator = MatrixReportGenerator::new(&report).with_evaluation(evaluation);

        let text = generator.generate(ReportFormat::Text);

        assert!(text.contains("EVALUATION"));
        assert!(text.contains("All criteria met"));
    }

    #[test]
    fn test_report_generator_with_baseline() {
        let current = create_test_report(true, 0.95);
        let baseline = create_test_report(true, 0.90);

        let generator = MatrixReportGenerator::new(&current).with_baseline(&baseline);

        let text = generator.generate(ReportFormat::Text);

        assert!(text.contains("REGRESSION ANALYSIS"));
        assert!(text.contains("Baseline Run"));
        assert!(text.contains("90.0%"));

        let markdown = generator.generate(ReportFormat::Markdown);
        assert!(markdown.contains("## Regression Analysis"));
    }

    #[test]
    fn test_report_generator_with_baseline_regression() {
        let current = create_test_report(false, 0.75);
        let baseline = create_test_report(true, 0.95);

        let generator = MatrixReportGenerator::new(&current).with_baseline(&baseline);

        let text = generator.generate(ReportFormat::Text);

        assert!(text.contains("REGRESSION"));

        let ci = generator.generate(ReportFormat::CiSummary);
        assert!(ci.contains("[ΔBASE]"));
        assert!(ci.contains("-20.0%"));
    }

    #[test]
    fn test_report_generator_exit_code() {
        let passed_report = create_test_report(true, 0.95);
        let failed_report = create_test_report(false, 0.75);

        let passed_gen = MatrixReportGenerator::new(&passed_report);
        let failed_gen = MatrixReportGenerator::new(&failed_report);

        assert_eq!(passed_gen.exit_code(), 0);
        assert_eq!(failed_gen.exit_code(), 1);
    }

    #[test]
    fn test_report_format_enum() {
        // Test that all formats are distinct
        assert_ne!(ReportFormat::Text, ReportFormat::PlainText);
        assert_ne!(ReportFormat::Json, ReportFormat::JsonCompact);
        assert_ne!(ReportFormat::Markdown, ReportFormat::CiSummary);
    }

    #[test]
    fn test_console_output_adapter() {
        let adapter = ConsoleOutput;
        // ConsoleOutput just prints, verify it doesn't error
        assert!(adapter.write("test output").is_ok());
    }

    #[test]
    fn test_file_output_adapter_creation() {
        let adapter = FileOutput::new("/tmp/test_report.txt");
        assert_eq!(
            adapter.path.to_string_lossy(),
            "/tmp/test_report.txt"
        );
    }
}
