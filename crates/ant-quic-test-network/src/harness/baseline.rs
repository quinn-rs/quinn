//! Baseline Measurements
//!
//! Environment fingerprinting and golden run baselines for reproducible testing.
//!
//! # Components
//!
//! - **EnvironmentFingerprint**: Captures agent environment (OS, NICs, NAT, clock, versions)
//! - **GoldenRunBaseline**: Reference runs for known-good and known-bad scenarios
//! - **BaselineDrift**: Detects environment changes between runs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// Complete environment fingerprint for an agent
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentFingerprint {
    pub agent_id: String,
    pub captured_at_ms: u64,

    // System info
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,

    // Network interfaces
    pub network_interfaces: Vec<NetworkInterface>,

    // IP configuration
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub default_gateway_v4: Option<IpAddr>,
    pub default_gateway_v6: Option<IpAddr>,

    // NAT configuration
    pub nat_rules_hash: Option<String>,
    pub nat_rules_count: u32,

    // Time sync
    pub clock_offset_ms: i64,
    pub ntp_synced: bool,

    // Binary versions
    pub binary_versions: HashMap<String, String>,

    // Hardware identifiers (for drift detection)
    pub cpu_model: Option<String>,
    pub total_memory_mb: Option<u64>,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<IpAddr>,
    pub ipv6_addresses: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub mtu: Option<u32>,
}

impl EnvironmentFingerprint {
    /// Create a new fingerprint for an agent
    pub fn new(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            captured_at_ms: crate::registry::unix_timestamp_ms(),
            os_name: String::new(),
            os_version: String::new(),
            kernel_version: String::new(),
            hostname: String::new(),
            network_interfaces: Vec::new(),
            ipv4_enabled: false,
            ipv6_enabled: false,
            default_gateway_v4: None,
            default_gateway_v6: None,
            nat_rules_hash: None,
            nat_rules_count: 0,
            clock_offset_ms: 0,
            ntp_synced: false,
            binary_versions: HashMap::new(),
            cpu_model: None,
            total_memory_mb: None,
        }
    }

    /// Generate a stable hash of the fingerprint for comparison
    pub fn content_hash(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Hash stable components (not timestamps)
        self.os_name.hash(&mut hasher);
        self.os_version.hash(&mut hasher);
        self.kernel_version.hash(&mut hasher);

        for nic in &self.network_interfaces {
            nic.name.hash(&mut hasher);
            nic.mac_address.hash(&mut hasher);
        }

        self.nat_rules_hash.hash(&mut hasher);
        self.nat_rules_count.hash(&mut hasher);

        for (k, v) in &self.binary_versions {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }

        format!("{:016x}", hasher.finish())
    }

    /// Check if IPv4 is available
    pub fn has_ipv4(&self) -> bool {
        self.ipv4_enabled
            && self
                .network_interfaces
                .iter()
                .any(|n| !n.is_loopback && !n.ipv4_addresses.is_empty())
    }

    /// Check if IPv6 is available
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_enabled
            && self
                .network_interfaces
                .iter()
                .any(|n| !n.is_loopback && !n.ipv6_addresses.is_empty())
    }

    /// Check if this is a dual-stack environment
    pub fn is_dual_stack(&self) -> bool {
        self.has_ipv4() && self.has_ipv6()
    }

    /// Get count of non-loopback interfaces
    pub fn active_interface_count(&self) -> usize {
        self.network_interfaces
            .iter()
            .filter(|n| n.is_up && !n.is_loopback)
            .count()
    }

    /// Compare with another fingerprint and return drift details
    pub fn compare(&self, other: &EnvironmentFingerprint) -> EnvironmentDrift {
        let mut drift = EnvironmentDrift::new(&self.agent_id);

        // OS changes
        if self.os_version != other.os_version {
            drift.record_change(
                DriftCategory::OsVersion,
                &self.os_version,
                &other.os_version,
            );
        }
        if self.kernel_version != other.kernel_version {
            drift.record_change(
                DriftCategory::KernelVersion,
                &self.kernel_version,
                &other.kernel_version,
            );
        }

        // Network changes
        let self_nics: Vec<_> = self
            .network_interfaces
            .iter()
            .filter(|n| !n.is_loopback)
            .map(|n| &n.name)
            .collect();
        let other_nics: Vec<_> = other
            .network_interfaces
            .iter()
            .filter(|n| !n.is_loopback)
            .map(|n| &n.name)
            .collect();
        if self_nics != other_nics {
            drift.record_change(
                DriftCategory::NetworkInterfaces,
                &format!("{:?}", self_nics),
                &format!("{:?}", other_nics),
            );
        }

        // NAT changes
        if self.nat_rules_hash != other.nat_rules_hash {
            drift.record_change(
                DriftCategory::NatRules,
                &self.nat_rules_hash.clone().unwrap_or_default(),
                &other.nat_rules_hash.clone().unwrap_or_default(),
            );
        }

        // Binary version changes
        for (name, version) in &self.binary_versions {
            if let Some(other_version) = other.binary_versions.get(name) {
                if version != other_version {
                    drift.record_change(
                        DriftCategory::BinaryVersion,
                        &format!("{}={}", name, version),
                        &format!("{}={}", name, other_version),
                    );
                }
            }
        }

        // Clock drift
        let clock_diff = (self.clock_offset_ms - other.clock_offset_ms).abs();
        if clock_diff > 1000 {
            // >1 second drift
            drift.record_change(
                DriftCategory::ClockOffset,
                &format!("{}ms", self.clock_offset_ms),
                &format!("{}ms", other.clock_offset_ms),
            );
        }

        drift
    }
}

/// Categories of environment drift
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriftCategory {
    OsVersion,
    KernelVersion,
    NetworkInterfaces,
    NatRules,
    BinaryVersion,
    ClockOffset,
    Hardware,
}

/// Record of environment changes between fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentDrift {
    pub agent_id: String,
    pub changes: Vec<DriftChange>,
}

/// A single change detected between fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftChange {
    pub category: DriftCategory,
    pub old_value: String,
    pub new_value: String,
}

impl EnvironmentDrift {
    /// Create a new drift record
    pub fn new(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            changes: Vec::new(),
        }
    }

    /// Record a change
    pub fn record_change(&mut self, category: DriftCategory, old: &str, new: &str) {
        self.changes.push(DriftChange {
            category,
            old_value: old.to_string(),
            new_value: new.to_string(),
        });
    }

    /// Check if there are any changes
    pub fn has_drift(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Check if drift includes critical changes
    pub fn has_critical_drift(&self) -> bool {
        self.changes.iter().any(|c| {
            matches!(
                c.category,
                DriftCategory::NatRules | DriftCategory::NetworkInterfaces
            )
        })
    }

    /// Get count of changes by category
    pub fn changes_by_category(&self) -> HashMap<DriftCategory, usize> {
        let mut counts = HashMap::new();
        for change in &self.changes {
            *counts.entry(change.category).or_insert(0) += 1;
        }
        counts
    }
}

/// Golden run baseline for known scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenRunBaseline {
    pub baseline_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at_ms: u64,

    /// Scenario type
    pub scenario_type: GoldenScenarioType,

    /// Expected outcome
    pub expected_outcome: ExpectedOutcome,

    /// Environment fingerprints at baseline creation
    pub environment_fingerprints: HashMap<String, EnvironmentFingerprint>,

    /// Actual results from baseline runs
    pub baseline_results: Vec<BaselineRunResult>,

    /// Statistical thresholds
    pub thresholds: BaselineThresholds,
}

/// Type of golden scenario
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoldenScenarioType {
    /// No NAT, same L2 network - should always succeed
    NoNatSameL2,
    /// UDP blocked - should always fail
    UdpBlocked,
    /// Known NAT type with expected behavior
    KnownNatType,
    /// Custom scenario
    Custom,
}

/// Expected outcome for a golden scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    /// Expected success rate (0.0 - 1.0)
    pub success_rate: f64,
    /// Acceptable variance (+/- this amount)
    pub variance: f64,
    /// Expected connection method (if success)
    pub expected_method: Option<String>,
    /// Expected failure reason (if failure)
    pub expected_failure: Option<String>,
}

impl ExpectedOutcome {
    /// Create an outcome expecting success
    pub fn success(rate: f64, variance: f64) -> Self {
        Self {
            success_rate: rate,
            variance,
            expected_method: None,
            expected_failure: None,
        }
    }

    /// Create an outcome expecting failure
    pub fn failure(expected_failure: &str) -> Self {
        Self {
            success_rate: 0.0,
            variance: 0.05, // Allow up to 5% unexpected successes
            expected_method: None,
            expected_failure: Some(expected_failure.to_string()),
        }
    }

    /// Check if an observed rate matches expectations
    pub fn matches(&self, observed_rate: f64) -> bool {
        let min = (self.success_rate - self.variance).max(0.0);
        let max = (self.success_rate + self.variance).min(1.0);
        observed_rate >= min && observed_rate <= max
    }
}

/// Results from a single baseline run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRunResult {
    pub run_id: Uuid,
    pub executed_at_ms: u64,
    pub total_attempts: u32,
    pub successful_attempts: u32,
    pub success_rate: f64,
    pub avg_latency_ms: Option<u64>,
    pub methods_used: HashMap<String, u32>,
    pub failure_reasons: HashMap<String, u32>,
}

impl BaselineRunResult {
    /// Create from attempt counts
    pub fn new(run_id: Uuid, total: u32, successful: u32) -> Self {
        let success_rate = if total > 0 {
            successful as f64 / total as f64
        } else {
            0.0
        };
        Self {
            run_id,
            executed_at_ms: crate::registry::unix_timestamp_ms(),
            total_attempts: total,
            successful_attempts: successful,
            success_rate,
            avg_latency_ms: None,
            methods_used: HashMap::new(),
            failure_reasons: HashMap::new(),
        }
    }
}

/// Statistical thresholds for baseline comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineThresholds {
    /// Minimum runs required for statistical significance
    pub min_runs: u32,
    /// Minimum attempts per run
    pub min_attempts_per_run: u32,
    /// Maximum allowed standard deviation
    pub max_std_dev: f64,
    /// Confidence level for comparisons (e.g., 0.95)
    pub confidence_level: f64,
}

impl Default for BaselineThresholds {
    fn default() -> Self {
        Self {
            min_runs: 3,
            min_attempts_per_run: 10,
            max_std_dev: 0.05,
            confidence_level: 0.95,
        }
    }
}

impl GoldenRunBaseline {
    /// Create a new golden baseline
    pub fn new(name: &str, scenario_type: GoldenScenarioType, expected: ExpectedOutcome) -> Self {
        Self {
            baseline_id: Uuid::new_v4(),
            name: name.to_string(),
            description: String::new(),
            created_at_ms: crate::registry::unix_timestamp_ms(),
            scenario_type,
            expected_outcome: expected,
            environment_fingerprints: HashMap::new(),
            baseline_results: Vec::new(),
            thresholds: BaselineThresholds::default(),
        }
    }

    /// Create a no-NAT same-L2 golden baseline (should be ~100% success)
    pub fn no_nat_same_l2() -> Self {
        Self::new(
            "no_nat_same_l2",
            GoldenScenarioType::NoNatSameL2,
            ExpectedOutcome::success(1.0, 0.01), // 99-100% success
        )
    }

    /// Create a UDP-blocked golden baseline (should fail)
    pub fn udp_blocked() -> Self {
        Self::new(
            "udp_blocked",
            GoldenScenarioType::UdpBlocked,
            ExpectedOutcome::failure("udp_blocked"),
        )
    }

    /// Add an environment fingerprint
    pub fn add_fingerprint(&mut self, fingerprint: EnvironmentFingerprint) {
        self.environment_fingerprints
            .insert(fingerprint.agent_id.clone(), fingerprint);
    }

    /// Add a baseline run result
    pub fn add_result(&mut self, result: BaselineRunResult) {
        self.baseline_results.push(result);
    }

    /// Check if baseline has enough data
    pub fn has_sufficient_data(&self) -> bool {
        self.baseline_results.len() >= self.thresholds.min_runs as usize
            && self
                .baseline_results
                .iter()
                .all(|r| r.total_attempts >= self.thresholds.min_attempts_per_run)
    }

    /// Calculate mean success rate across baseline runs
    pub fn mean_success_rate(&self) -> Option<f64> {
        if self.baseline_results.is_empty() {
            return None;
        }
        let sum: f64 = self.baseline_results.iter().map(|r| r.success_rate).sum();
        Some(sum / self.baseline_results.len() as f64)
    }

    /// Calculate standard deviation of success rates
    pub fn std_dev_success_rate(&self) -> Option<f64> {
        let mean = self.mean_success_rate()?;
        if self.baseline_results.len() < 2 {
            return None;
        }
        let variance: f64 = self
            .baseline_results
            .iter()
            .map(|r| (r.success_rate - mean).powi(2))
            .sum::<f64>()
            / (self.baseline_results.len() - 1) as f64;
        Some(variance.sqrt())
    }

    /// Check if baseline is stable (low variance)
    pub fn is_stable(&self) -> bool {
        if !self.has_sufficient_data() {
            return false;
        }
        self.std_dev_success_rate()
            .is_some_and(|sd| sd <= self.thresholds.max_std_dev)
    }

    /// Compare a new run against the baseline
    pub fn compare_run(&self, result: &BaselineRunResult) -> BaselineComparison {
        let mut comparison = BaselineComparison {
            baseline_id: self.baseline_id,
            run_id: result.run_id,
            matches_expectation: self.expected_outcome.matches(result.success_rate),
            observed_rate: result.success_rate,
            expected_rate: self.expected_outcome.success_rate,
            deviation: (result.success_rate - self.expected_outcome.success_rate).abs(),
            within_historical_range: false,
            issues: Vec::new(),
        };

        // Check against historical data
        if let (Some(mean), Some(std_dev)) = (self.mean_success_rate(), self.std_dev_success_rate())
        {
            let z_score = (result.success_rate - mean) / std_dev.max(0.001);
            comparison.within_historical_range = z_score.abs() < 2.0; // Within 2 standard deviations

            if !comparison.within_historical_range {
                comparison.issues.push(format!(
                    "Success rate {:.1}% is outside historical range ({:.1}% ± {:.1}%)",
                    result.success_rate * 100.0,
                    mean * 100.0,
                    std_dev * 100.0 * 2.0
                ));
            }
        }

        if !comparison.matches_expectation {
            comparison.issues.push(format!(
                "Success rate {:.1}% does not match expected {:.1}% (±{:.1}%)",
                result.success_rate * 100.0,
                self.expected_outcome.success_rate * 100.0,
                self.expected_outcome.variance * 100.0
            ));
        }

        comparison
    }
}

/// Result of comparing a run against baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_id: Uuid,
    pub run_id: Uuid,
    pub matches_expectation: bool,
    pub observed_rate: f64,
    pub expected_rate: f64,
    pub deviation: f64,
    pub within_historical_range: bool,
    pub issues: Vec<String>,
}

impl BaselineComparison {
    /// Check if this is a passing comparison
    pub fn is_passing(&self) -> bool {
        self.matches_expectation && self.issues.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // EnvironmentFingerprint Tests
    // ============================================================

    #[test]
    fn test_fingerprint_new() {
        let fp = EnvironmentFingerprint::new("agent-1");
        assert_eq!(fp.agent_id, "agent-1");
        assert!(fp.captured_at_ms > 0);
    }

    #[test]
    fn test_fingerprint_content_hash_stable() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.os_name = "Linux".to_string();
        fp1.os_version = "6.1.0".to_string();

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.os_name = "Linux".to_string();
        fp2.os_version = "6.1.0".to_string();
        fp2.captured_at_ms = fp1.captured_at_ms + 1000; // Different timestamp

        // Hash should be same despite different timestamps
        assert_eq!(fp1.content_hash(), fp2.content_hash());
    }

    #[test]
    fn test_fingerprint_content_hash_changes_on_diff() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.os_version = "6.1.0".to_string();

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.os_version = "6.2.0".to_string();

        assert_ne!(fp1.content_hash(), fp2.content_hash());
    }

    #[test]
    fn test_fingerprint_has_ipv4() {
        let mut fp = EnvironmentFingerprint::new("agent-1");
        fp.ipv4_enabled = true;
        fp.network_interfaces.push(NetworkInterface {
            name: "eth0".to_string(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            ipv4_addresses: vec!["192.168.1.100".parse().unwrap()],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: false,
            mtu: Some(1500),
        });

        assert!(fp.has_ipv4());
        assert!(!fp.has_ipv6());
    }

    #[test]
    fn test_fingerprint_has_ipv6() {
        let mut fp = EnvironmentFingerprint::new("agent-1");
        fp.ipv6_enabled = true;
        fp.network_interfaces.push(NetworkInterface {
            name: "eth0".to_string(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            ipv4_addresses: vec![],
            ipv6_addresses: vec!["2001:db8::1".parse().unwrap()],
            is_up: true,
            is_loopback: false,
            mtu: Some(1500),
        });

        assert!(!fp.has_ipv4());
        assert!(fp.has_ipv6());
    }

    #[test]
    fn test_fingerprint_dual_stack() {
        let mut fp = EnvironmentFingerprint::new("agent-1");
        fp.ipv4_enabled = true;
        fp.ipv6_enabled = true;
        fp.network_interfaces.push(NetworkInterface {
            name: "eth0".to_string(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            ipv4_addresses: vec!["192.168.1.100".parse().unwrap()],
            ipv6_addresses: vec!["2001:db8::1".parse().unwrap()],
            is_up: true,
            is_loopback: false,
            mtu: Some(1500),
        });

        assert!(fp.is_dual_stack());
    }

    #[test]
    fn test_fingerprint_loopback_not_counted() {
        let mut fp = EnvironmentFingerprint::new("agent-1");
        fp.ipv4_enabled = true;
        fp.network_interfaces.push(NetworkInterface {
            name: "lo".to_string(),
            mac_address: None,
            ipv4_addresses: vec!["127.0.0.1".parse().unwrap()],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: true,
            mtu: Some(65536),
        });

        assert!(!fp.has_ipv4()); // Loopback doesn't count
        assert_eq!(fp.active_interface_count(), 0);
    }

    #[test]
    fn test_fingerprint_active_interface_count() {
        let mut fp = EnvironmentFingerprint::new("agent-1");
        fp.network_interfaces.push(NetworkInterface {
            name: "eth0".to_string(),
            mac_address: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: false,
            mtu: None,
        });
        fp.network_interfaces.push(NetworkInterface {
            name: "eth1".to_string(),
            mac_address: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            is_up: false, // Down
            is_loopback: false,
            mtu: None,
        });
        fp.network_interfaces.push(NetworkInterface {
            name: "lo".to_string(),
            mac_address: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: true,
            mtu: None,
        });

        assert_eq!(fp.active_interface_count(), 1); // Only eth0
    }

    // ============================================================
    // EnvironmentDrift Tests
    // ============================================================

    #[test]
    fn test_drift_no_changes() {
        let fp1 = EnvironmentFingerprint::new("agent-1");
        let fp2 = EnvironmentFingerprint::new("agent-1");

        let drift = fp1.compare(&fp2);
        assert!(!drift.has_drift());
        assert!(!drift.has_critical_drift());
    }

    #[test]
    fn test_drift_os_version_change() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.os_version = "6.1.0".to_string();

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.os_version = "6.2.0".to_string();

        let drift = fp1.compare(&fp2);
        assert!(drift.has_drift());
        assert!(!drift.has_critical_drift()); // OS version is not critical
    }

    #[test]
    fn test_drift_nat_rules_critical() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.nat_rules_hash = Some("abc123".to_string());

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.nat_rules_hash = Some("def456".to_string());

        let drift = fp1.compare(&fp2);
        assert!(drift.has_drift());
        assert!(drift.has_critical_drift()); // NAT rules are critical
    }

    #[test]
    fn test_drift_network_interfaces_critical() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.network_interfaces.push(NetworkInterface {
            name: "eth0".to_string(),
            mac_address: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: false,
            mtu: None,
        });

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.network_interfaces.push(NetworkInterface {
            name: "ens192".to_string(), // Different interface name
            mac_address: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            is_up: true,
            is_loopback: false,
            mtu: None,
        });

        let drift = fp1.compare(&fp2);
        assert!(drift.has_drift());
        assert!(drift.has_critical_drift()); // Network changes are critical
    }

    #[test]
    fn test_drift_clock_offset_significant() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.clock_offset_ms = 0;

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.clock_offset_ms = 2000; // 2 second drift

        let drift = fp1.compare(&fp2);
        assert!(drift.has_drift());

        let categories = drift.changes_by_category();
        assert!(categories.contains_key(&DriftCategory::ClockOffset));
    }

    #[test]
    fn test_drift_clock_offset_insignificant() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.clock_offset_ms = 0;

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.clock_offset_ms = 500; // 0.5 second drift - not significant

        let drift = fp1.compare(&fp2);
        assert!(!drift.has_drift());
    }

    #[test]
    fn test_drift_binary_version_change() {
        let mut fp1 = EnvironmentFingerprint::new("agent-1");
        fp1.binary_versions
            .insert("ant-quic".to_string(), "0.14.0".to_string());

        let mut fp2 = EnvironmentFingerprint::new("agent-1");
        fp2.binary_versions
            .insert("ant-quic".to_string(), "0.15.0".to_string());

        let drift = fp1.compare(&fp2);
        assert!(drift.has_drift());

        let categories = drift.changes_by_category();
        assert!(categories.contains_key(&DriftCategory::BinaryVersion));
    }

    // ============================================================
    // GoldenRunBaseline Tests
    // ============================================================

    #[test]
    fn test_golden_no_nat_same_l2() {
        let baseline = GoldenRunBaseline::no_nat_same_l2();
        assert_eq!(baseline.name, "no_nat_same_l2");
        assert_eq!(baseline.scenario_type, GoldenScenarioType::NoNatSameL2);
        assert!((baseline.expected_outcome.success_rate - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_golden_udp_blocked() {
        let baseline = GoldenRunBaseline::udp_blocked();
        assert_eq!(baseline.name, "udp_blocked");
        assert_eq!(baseline.scenario_type, GoldenScenarioType::UdpBlocked);
        assert!((baseline.expected_outcome.success_rate - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_expected_outcome_success_matches() {
        let outcome = ExpectedOutcome::success(0.95, 0.05);
        assert!(outcome.matches(0.95));
        assert!(outcome.matches(0.92)); // Within variance
        assert!(outcome.matches(0.99)); // Within variance
        assert!(!outcome.matches(0.85)); // Below range
    }

    #[test]
    fn test_expected_outcome_failure_matches() {
        let outcome = ExpectedOutcome::failure("timeout");
        assert!(outcome.matches(0.0));
        assert!(outcome.matches(0.03)); // Within 5% variance
        assert!(!outcome.matches(0.10)); // Too many successes
    }

    #[test]
    fn test_baseline_add_results() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 99));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));

        assert_eq!(baseline.baseline_results.len(), 3);
    }

    #[test]
    fn test_baseline_has_sufficient_data() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();

        // Not enough runs
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        assert!(!baseline.has_sufficient_data());

        // Still not enough
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        assert!(!baseline.has_sufficient_data());

        // Now sufficient (3 runs)
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        assert!(baseline.has_sufficient_data());
    }

    #[test]
    fn test_baseline_mean_success_rate() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100)); // 100%
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 98)); // 98%
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 99)); // 99%

        let mean = baseline.mean_success_rate().unwrap();
        assert!((mean - 0.99).abs() < 0.001); // (1.0 + 0.98 + 0.99) / 3 = 0.99
    }

    #[test]
    fn test_baseline_std_dev() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));

        let std_dev = baseline.std_dev_success_rate().unwrap();
        assert!(std_dev < 0.001); // All same, so ~0 std dev
    }

    #[test]
    fn test_baseline_is_stable() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 99));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));

        assert!(baseline.is_stable()); // Low variance
    }

    #[test]
    fn test_baseline_not_stable_high_variance() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100)); // 100%
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 80)); // 80%
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 90)); // 90%

        assert!(!baseline.is_stable()); // High variance
    }

    #[test]
    fn test_baseline_compare_run_matching() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 99));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));

        let new_run = BaselineRunResult::new(Uuid::new_v4(), 100, 99);
        let comparison = baseline.compare_run(&new_run);

        assert!(comparison.matches_expectation);
        assert!(comparison.is_passing());
    }

    #[test]
    fn test_baseline_compare_run_failing() {
        let mut baseline = GoldenRunBaseline::no_nat_same_l2();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 100));

        let new_run = BaselineRunResult::new(Uuid::new_v4(), 100, 80); // Only 80%
        let comparison = baseline.compare_run(&new_run);

        assert!(!comparison.matches_expectation);
        assert!(!comparison.is_passing());
        assert!(!comparison.issues.is_empty());
    }

    #[test]
    fn test_baseline_udp_blocked_comparison() {
        let mut baseline = GoldenRunBaseline::udp_blocked();
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 0));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 2));
        baseline.add_result(BaselineRunResult::new(Uuid::new_v4(), 100, 1));

        // Should fail with 0% success
        let good_run = BaselineRunResult::new(Uuid::new_v4(), 100, 0);
        let comparison = baseline.compare_run(&good_run);
        assert!(comparison.matches_expectation);

        // Should fail if too many successes
        let bad_run = BaselineRunResult::new(Uuid::new_v4(), 100, 20); // 20% success
        let comparison = baseline.compare_run(&bad_run);
        assert!(!comparison.matches_expectation);
    }

    // ============================================================
    // BaselineRunResult Tests
    // ============================================================

    #[test]
    fn test_baseline_run_result_new() {
        let result = BaselineRunResult::new(Uuid::new_v4(), 100, 95);
        assert_eq!(result.total_attempts, 100);
        assert_eq!(result.successful_attempts, 95);
        assert!((result.success_rate - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_baseline_run_result_zero_attempts() {
        let result = BaselineRunResult::new(Uuid::new_v4(), 0, 0);
        assert!((result.success_rate - 0.0).abs() < 0.001);
    }
}
