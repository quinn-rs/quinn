//! Test Orchestrator for autonomous network testing.
//!
//! The orchestrator runs on the registry server and coordinates test rounds
//! across all connected nodes. It triggers tests every few minutes and
//! aggregates results for the dashboard.

use crate::registry::{ConnectionMethod, NatBehavior, NatType, PeerStore};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Get current unix timestamp in seconds.
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Test round result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestRound {
    /// Round number
    pub round_id: u64,
    /// Unix timestamp when round started
    pub started_at: u64,
    /// Unix timestamp when round completed
    pub completed_at: u64,
    /// Number of peers that participated
    pub participants: usize,
    /// Number of test connections attempted
    pub connections_attempted: usize,
    /// Number of successful connections
    pub connections_successful: usize,
    /// Success rate (0.0-1.0)
    pub success_rate: f64,
    /// Per-peer results
    pub peer_results: Vec<PeerTestResult>,
}

/// Result of tests from a single peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerTestResult {
    /// Peer ID (truncated)
    pub peer_id: String,
    /// Number of targets tested
    pub targets_tested: usize,
    /// Number of successful connections
    pub successful: usize,
    /// Number of failed connections
    pub failed: usize,
    /// Average RTT in ms (for successful connections)
    pub avg_rtt_ms: Option<u64>,
    /// Connection methods that worked
    pub methods_used: Vec<ConnectionMethod>,
    /// Expected success rate based on NAT behavior analysis (0.0-1.0)
    #[serde(default)]
    pub expected_success_rate: f64,
}

/// Test command sent to agents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestCommand {
    /// Round ID
    pub round_id: u64,
    /// Targets to test (peer addresses)
    pub targets: Vec<TestTarget>,
}

/// A target for testing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestTarget {
    /// Peer ID
    pub peer_id: String,
    /// Addresses to try
    pub addresses: Vec<String>,
}

/// Test Orchestrator configuration.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Interval between test rounds
    pub round_interval: Duration,
    /// Timeout for each test
    pub test_timeout: Duration,
    /// Maximum concurrent tests per node
    pub max_concurrent_tests: usize,
    /// Minimum peers required to run a round
    pub min_peers: usize,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            round_interval: Duration::from_secs(300), // 5 minutes
            test_timeout: Duration::from_secs(30),
            max_concurrent_tests: 5,
            min_peers: 2,
        }
    }
}

/// Autonomous test orchestrator.
pub struct TestOrchestrator {
    /// Peer store
    store: Arc<PeerStore>,
    /// Configuration
    config: OrchestratorConfig,
    /// Current round number
    current_round: AtomicU64,
    /// Latest round result
    latest_round: RwLock<Option<TestRound>>,
    /// HTTP client for agent communication (Phase 5)
    _client: reqwest::Client,
    /// Running flag
    running: std::sync::atomic::AtomicBool,
}

impl TestOrchestrator {
    /// Create a new orchestrator.
    pub fn new(store: Arc<PeerStore>, config: OrchestratorConfig) -> Arc<Self> {
        Arc::new(Self {
            store,
            config,
            current_round: AtomicU64::new(0),
            latest_round: RwLock::new(None),
            _client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to create HTTP client"),
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Start continuous test loop.
    pub async fn run_continuous(self: Arc<Self>) {
        if self.running.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!("Orchestrator already running");
            return;
        }

        tracing::info!(
            "Starting test orchestrator with {}s interval",
            self.config.round_interval.as_secs()
        );

        loop {
            // Wait for next round
            tokio::time::sleep(self.config.round_interval).await;

            // Execute test round
            match self.execute_round().await {
                Ok(round) => {
                    tracing::info!(
                        "Round {} completed: {}/{} successful ({:.1}%)",
                        round.round_id,
                        round.connections_successful,
                        round.connections_attempted,
                        round.success_rate * 100.0
                    );

                    // Store latest round
                    let mut latest = self.latest_round.write().await;
                    *latest = Some(round);
                }
                Err(e) => {
                    tracing::error!("Test round failed: {}", e);
                }
            }
        }
    }

    /// Execute a single test round.
    pub async fn execute_round(&self) -> anyhow::Result<TestRound> {
        let round_id = self.current_round.fetch_add(1, Ordering::SeqCst);
        let started_at = unix_timestamp();

        tracing::info!("Starting test round {}", round_id);

        // Get all active peers
        let peers = self.store.get_all_peers();

        if peers.len() < self.config.min_peers {
            return Err(anyhow::anyhow!(
                "Not enough peers for test round: {} < {}",
                peers.len(),
                self.config.min_peers
            ));
        }

        // Build test targets for each peer (used when agents become active)
        let _targets: Vec<TestTarget> = peers
            .iter()
            .map(|p| TestTarget {
                peer_id: p.peer_id.clone(),
                addresses: p.addresses.iter().map(|a| a.to_string()).collect(),
            })
            .collect();

        // Collect results based on current peer connection data
        let mut peer_results = Vec::new();
        let mut total_attempted = 0usize;
        let mut total_successful = 0usize;

        for peer in &peers {
            // Other potential targets for this peer
            let other_count = peers.len().saturating_sub(1);

            // Use actual connected_peers count as successful connections
            let successful = peer.connected_peers.min(other_count);
            let failed = other_count.saturating_sub(successful);

            // Determine connection methods based on NAT type
            let methods_used = if successful > 0 {
                match peer.nat_type {
                    NatType::None | NatType::FullCone | NatType::Upnp | NatType::NatPmp => {
                        vec![ConnectionMethod::Direct]
                    }
                    NatType::PortRestricted | NatType::AddressRestricted | NatType::HairpinNat => {
                        vec![ConnectionMethod::HolePunched]
                    }
                    NatType::Symmetric | NatType::Cgnat => {
                        vec![ConnectionMethod::HolePunched, ConnectionMethod::Relayed]
                    }
                    NatType::DoubleNat | NatType::MobileCarrier => {
                        // These typically require relay
                        vec![ConnectionMethod::Relayed]
                    }
                    NatType::Unknown => vec![ConnectionMethod::Direct],
                }
            } else {
                vec![]
            };

            // Calculate expected success rate based on NAT behavior analysis
            let peer_behavior = NatBehavior::from_nat_type(peer.nat_type);
            let avg_expected_rate = if other_count > 0 {
                // Average expected rate against all other peers
                let total: f64 = peers
                    .iter()
                    .filter(|p| p.peer_id != peer.peer_id)
                    .map(|other| {
                        let other_behavior = NatBehavior::from_nat_type(other.nat_type);
                        NatBehavior::estimate_pair_success_rate(&peer_behavior, &other_behavior)
                    })
                    .sum();
                total / other_count as f64
            } else {
                1.0
            };

            let result = PeerTestResult {
                peer_id: peer.peer_id[..8.min(peer.peer_id.len())].to_string(),
                targets_tested: other_count,
                successful,
                failed,
                avg_rtt_ms: None, // RTT data would come from active testing
                methods_used,
                expected_success_rate: avg_expected_rate,
            };

            total_attempted += other_count;
            total_successful += successful;
            peer_results.push(result);
        }

        let completed_at = unix_timestamp();

        let success_rate = if total_attempted > 0 {
            total_successful as f64 / total_attempted as f64
        } else {
            0.0
        };

        Ok(TestRound {
            round_id,
            started_at,
            completed_at,
            participants: peers.len(),
            connections_attempted: total_attempted,
            connections_successful: total_successful,
            success_rate,
            peer_results,
        })
    }

    /// Get the latest round result.
    pub async fn get_latest_round(&self) -> Option<TestRound> {
        self.latest_round.read().await.clone()
    }

    /// Get current round number.
    pub fn current_round_id(&self) -> u64 {
        self.current_round.load(Ordering::Relaxed)
    }

    /// Check if orchestrator is running.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Response from /api/orchestrator/status endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrchestratorStatus {
    /// Whether the orchestrator is running
    pub running: bool,
    /// Current round number
    pub current_round: u64,
    /// Interval between rounds (seconds)
    pub round_interval_secs: u64,
    /// Latest round result (if any)
    pub latest_round: Option<TestRound>,
}

/// Expected connection method for a NAT pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedMethod {
    /// Direct connection should work
    Direct,
    /// Hole-punching required
    HolePunch,
    /// Relay required (hardest NAT combinations)
    Relay,
    /// Either hole-punch or relay may work
    HolePunchOrRelay,
}

impl std::fmt::Display for ExpectedMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::HolePunch => write!(f, "Hole Punch"),
            Self::Relay => write!(f, "Relay"),
            Self::HolePunchOrRelay => write!(f, "Hole Punch or Relay"),
        }
    }
}

/// A single NAT pair test configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatPairTest {
    /// Source NAT type
    pub source_nat: NatType,
    /// Destination NAT type
    pub dest_nat: NatType,
    /// Expected connection method
    pub expected_method: ExpectedMethod,
    /// Expected success rate (0.0-1.0)
    pub expected_success_rate: f64,
    /// Description of this pair's connectivity challenges
    pub description: String,
}

/// Comprehensive NAT test matrix for systematic testing.
///
/// This matrix defines all NAT type combinations and their expected
/// connectivity characteristics based on RFC 4787 behaviors.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatTestMatrix {
    /// All NAT pair combinations to test
    pub combinations: Vec<NatPairTest>,
}

impl Default for NatTestMatrix {
    fn default() -> Self {
        Self::comprehensive()
    }
}

impl NatTestMatrix {
    /// Create a comprehensive test matrix covering all NAT type combinations.
    pub fn comprehensive() -> Self {
        let nat_types = vec![
            NatType::None,
            NatType::FullCone,
            NatType::AddressRestricted,
            NatType::PortRestricted,
            NatType::Symmetric,
            NatType::Cgnat,
            NatType::DoubleNat,
            NatType::HairpinNat,
            NatType::MobileCarrier,
            NatType::Upnp,
            NatType::NatPmp,
        ];

        let mut combinations = Vec::new();
        for src in &nat_types {
            for dst in &nat_types {
                let expected_method = Self::expected_method(*src, *dst);
                let expected_success_rate = Self::expected_rate(*src, *dst);
                let description = Self::describe_pair(*src, *dst);

                combinations.push(NatPairTest {
                    source_nat: *src,
                    dest_nat: *dst,
                    expected_method,
                    expected_success_rate,
                    description,
                });
            }
        }
        Self { combinations }
    }

    /// Create a minimal test matrix for quick validation.
    pub fn minimal() -> Self {
        let core_types = vec![
            NatType::None,
            NatType::FullCone,
            NatType::PortRestricted,
            NatType::Symmetric,
        ];

        let mut combinations = Vec::new();
        for src in &core_types {
            for dst in &core_types {
                let expected_method = Self::expected_method(*src, *dst);
                let expected_success_rate = Self::expected_rate(*src, *dst);
                let description = Self::describe_pair(*src, *dst);

                combinations.push(NatPairTest {
                    source_nat: *src,
                    dest_nat: *dst,
                    expected_method,
                    expected_success_rate,
                    description,
                });
            }
        }
        Self { combinations }
    }

    /// Determine the expected connection method for a NAT pair.
    pub fn expected_method(src: NatType, dst: NatType) -> ExpectedMethod {
        match (src, dst) {
            // Direct: At least one side has public IP or easy NAT
            (NatType::None, _) | (_, NatType::None) => ExpectedMethod::Direct,
            (NatType::Upnp, _) | (_, NatType::Upnp) => ExpectedMethod::Direct,
            (NatType::NatPmp, _) | (_, NatType::NatPmp) => ExpectedMethod::Direct,

            // Easy hole-punch: At least one side is Full Cone
            (NatType::FullCone, _) | (_, NatType::FullCone) => ExpectedMethod::HolePunch,

            // Moderate hole-punch: Cone NATs can punch to each other
            (NatType::AddressRestricted, NatType::AddressRestricted)
            | (NatType::AddressRestricted, NatType::PortRestricted)
            | (NatType::PortRestricted, NatType::AddressRestricted)
            | (NatType::PortRestricted, NatType::PortRestricted)
            | (NatType::HairpinNat, NatType::HairpinNat)
            | (NatType::HairpinNat, NatType::AddressRestricted)
            | (NatType::HairpinNat, NatType::PortRestricted)
            | (NatType::AddressRestricted, NatType::HairpinNat)
            | (NatType::PortRestricted, NatType::HairpinNat) => ExpectedMethod::HolePunch,

            // Hard cases: Symmetric NAT to cone NATs - may or may not work
            (NatType::Symmetric, NatType::AddressRestricted)
            | (NatType::Symmetric, NatType::PortRestricted)
            | (NatType::Symmetric, NatType::HairpinNat)
            | (NatType::AddressRestricted, NatType::Symmetric)
            | (NatType::PortRestricted, NatType::Symmetric)
            | (NatType::HairpinNat, NatType::Symmetric) => ExpectedMethod::HolePunchOrRelay,

            // Very hard: Both symmetric
            (NatType::Symmetric, NatType::Symmetric) => ExpectedMethod::Relay,

            // CGNAT pairs: Very limited port ranges, usually need relay
            (NatType::Cgnat, NatType::Cgnat) => ExpectedMethod::Relay,
            (NatType::Cgnat, NatType::Symmetric) | (NatType::Symmetric, NatType::Cgnat) => {
                ExpectedMethod::Relay
            }
            (NatType::Cgnat, _) | (_, NatType::Cgnat) => ExpectedMethod::HolePunchOrRelay,

            // Double NAT: Usually requires relay
            (NatType::DoubleNat, NatType::DoubleNat) => ExpectedMethod::Relay,
            (NatType::DoubleNat, NatType::Symmetric) | (NatType::Symmetric, NatType::DoubleNat) => {
                ExpectedMethod::Relay
            }
            (NatType::DoubleNat, _) | (_, NatType::DoubleNat) => ExpectedMethod::HolePunchOrRelay,

            // Mobile carrier: Typically symmetric + CGNAT characteristics
            (NatType::MobileCarrier, NatType::MobileCarrier) => ExpectedMethod::Relay,
            (NatType::MobileCarrier, NatType::Symmetric)
            | (NatType::Symmetric, NatType::MobileCarrier) => ExpectedMethod::Relay,
            (NatType::MobileCarrier, _) | (_, NatType::MobileCarrier) => {
                ExpectedMethod::HolePunchOrRelay
            }

            // Unknown: Assume moderate difficulty
            (NatType::Unknown, _) | (_, NatType::Unknown) => ExpectedMethod::HolePunchOrRelay,
        }
    }

    /// Estimate expected success rate for a NAT pair.
    pub fn expected_rate(src: NatType, dst: NatType) -> f64 {
        match (src, dst) {
            // Easy cases
            (NatType::None, _) | (_, NatType::None) => 0.99,
            (NatType::Upnp, _) | (_, NatType::Upnp) => 0.98,
            (NatType::NatPmp, _) | (_, NatType::NatPmp) => 0.97,
            (NatType::FullCone, _) | (_, NatType::FullCone) => 0.95,

            // Moderate cases
            (NatType::AddressRestricted, NatType::AddressRestricted) => 0.90,
            (NatType::AddressRestricted, NatType::PortRestricted)
            | (NatType::PortRestricted, NatType::AddressRestricted) => 0.88,
            (NatType::PortRestricted, NatType::PortRestricted) => 0.85,
            (NatType::HairpinNat, _) | (_, NatType::HairpinNat) => 0.85,

            // Hard cases
            (NatType::Symmetric, NatType::AddressRestricted)
            | (NatType::AddressRestricted, NatType::Symmetric) => 0.70,
            (NatType::Symmetric, NatType::PortRestricted)
            | (NatType::PortRestricted, NatType::Symmetric) => 0.65,
            (NatType::Symmetric, NatType::Symmetric) => 0.50,

            // CGNAT - limited ports
            (NatType::Cgnat, NatType::Cgnat) => 0.40,
            (NatType::Cgnat, NatType::Symmetric) | (NatType::Symmetric, NatType::Cgnat) => 0.45,
            (NatType::Cgnat, _) | (_, NatType::Cgnat) => 0.60,

            // Double NAT - two layers to traverse
            (NatType::DoubleNat, NatType::DoubleNat) => 0.30,
            (NatType::DoubleNat, NatType::Symmetric) | (NatType::Symmetric, NatType::DoubleNat) => {
                0.35
            }
            (NatType::DoubleNat, _) | (_, NatType::DoubleNat) => 0.50,

            // Mobile carrier - unpredictable
            (NatType::MobileCarrier, NatType::MobileCarrier) => 0.35,
            (NatType::MobileCarrier, NatType::Symmetric)
            | (NatType::Symmetric, NatType::MobileCarrier) => 0.40,
            (NatType::MobileCarrier, _) | (_, NatType::MobileCarrier) => 0.55,

            // Unknown - conservative estimate
            (NatType::Unknown, NatType::Unknown) => 0.60,
            (NatType::Unknown, _) | (_, NatType::Unknown) => 0.70,
        }
    }

    /// Generate a human-readable description for a NAT pair.
    fn describe_pair(src: NatType, dst: NatType) -> String {
        let method = Self::expected_method(src, dst);
        let rate = Self::expected_rate(src, dst);

        let difficulty = if rate >= 0.90 {
            "Easy"
        } else if rate >= 0.75 {
            "Moderate"
        } else if rate >= 0.50 {
            "Hard"
        } else {
            "Very Hard"
        };

        format!(
            "{} -> {}: {} ({} - {:.0}% expected)",
            src,
            dst,
            method,
            difficulty,
            rate * 100.0
        )
    }

    /// Get all pairs that require relay.
    pub fn relay_required_pairs(&self) -> Vec<&NatPairTest> {
        self.combinations
            .iter()
            .filter(|p| p.expected_method == ExpectedMethod::Relay)
            .collect()
    }

    /// Get all easy pairs (direct connection).
    pub fn easy_pairs(&self) -> Vec<&NatPairTest> {
        self.combinations
            .iter()
            .filter(|p| p.expected_method == ExpectedMethod::Direct)
            .collect()
    }

    /// Get pairs filtered by source NAT type.
    pub fn pairs_with_source(&self, nat_type: NatType) -> Vec<&NatPairTest> {
        self.combinations
            .iter()
            .filter(|p| p.source_nat == nat_type)
            .collect()
    }

    /// Get total number of combinations.
    pub fn total_combinations(&self) -> usize {
        self.combinations.len()
    }

    /// Get a summary of expected success rates by category.
    pub fn rate_summary(&self) -> NatTestMatrixSummary {
        let easy = self
            .combinations
            .iter()
            .filter(|p| p.expected_success_rate >= 0.90)
            .count();
        let moderate = self
            .combinations
            .iter()
            .filter(|p| p.expected_success_rate >= 0.70 && p.expected_success_rate < 0.90)
            .count();
        let hard = self
            .combinations
            .iter()
            .filter(|p| p.expected_success_rate >= 0.50 && p.expected_success_rate < 0.70)
            .count();
        let very_hard = self
            .combinations
            .iter()
            .filter(|p| p.expected_success_rate < 0.50)
            .count();

        NatTestMatrixSummary {
            total: self.combinations.len(),
            easy,
            moderate,
            hard,
            very_hard,
            avg_expected_rate: self
                .combinations
                .iter()
                .map(|p| p.expected_success_rate)
                .sum::<f64>()
                / self.combinations.len() as f64,
        }
    }
}

/// Summary statistics for the NAT test matrix.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatTestMatrixSummary {
    /// Total number of NAT pair combinations
    pub total: usize,
    /// Easy pairs (>= 90% expected success)
    pub easy: usize,
    /// Moderate pairs (70-89% expected success)
    pub moderate: usize,
    /// Hard pairs (50-69% expected success)
    pub hard: usize,
    /// Very hard pairs (< 50% expected success)
    pub very_hard: usize,
    /// Average expected success rate across all pairs
    pub avg_expected_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_config_default() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.round_interval.as_secs(), 300);
        assert_eq!(config.min_peers, 2);
    }

    #[test]
    fn test_test_target_serialization() {
        let target = TestTarget {
            peer_id: "abc123".to_string(),
            addresses: vec!["192.168.1.1:9000".to_string()],
        };

        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("192.168.1.1:9000"));
    }

    #[test]
    fn test_nat_test_matrix_comprehensive() {
        let matrix = NatTestMatrix::comprehensive();

        // 11 NAT types x 11 NAT types = 121 combinations
        assert_eq!(matrix.total_combinations(), 121);

        // Check summary
        let summary = matrix.rate_summary();
        assert_eq!(summary.total, 121);
        assert!(summary.avg_expected_rate > 0.0);
        assert!(summary.avg_expected_rate < 1.0);
    }

    #[test]
    fn test_nat_test_matrix_minimal() {
        let matrix = NatTestMatrix::minimal();

        // 4 core types x 4 core types = 16 combinations
        assert_eq!(matrix.total_combinations(), 16);
    }

    #[test]
    fn test_expected_method_direct() {
        // Public IP should always be direct
        assert_eq!(
            NatTestMatrix::expected_method(NatType::None, NatType::Symmetric),
            ExpectedMethod::Direct
        );
        assert_eq!(
            NatTestMatrix::expected_method(NatType::Symmetric, NatType::None),
            ExpectedMethod::Direct
        );
        // UPnP should be direct
        assert_eq!(
            NatTestMatrix::expected_method(NatType::Upnp, NatType::Cgnat),
            ExpectedMethod::Direct
        );
    }

    #[test]
    fn test_expected_method_relay() {
        // Symmetric-Symmetric needs relay
        assert_eq!(
            NatTestMatrix::expected_method(NatType::Symmetric, NatType::Symmetric),
            ExpectedMethod::Relay
        );
        // CGNAT-CGNAT needs relay
        assert_eq!(
            NatTestMatrix::expected_method(NatType::Cgnat, NatType::Cgnat),
            ExpectedMethod::Relay
        );
        // Double NAT pairs need relay
        assert_eq!(
            NatTestMatrix::expected_method(NatType::DoubleNat, NatType::DoubleNat),
            ExpectedMethod::Relay
        );
    }

    #[test]
    fn test_expected_rate_ordering() {
        // Easy cases should have higher rates than hard cases
        let easy_rate = NatTestMatrix::expected_rate(NatType::None, NatType::FullCone);
        let hard_rate = NatTestMatrix::expected_rate(NatType::Symmetric, NatType::Symmetric);
        let very_hard_rate = NatTestMatrix::expected_rate(NatType::DoubleNat, NatType::DoubleNat);

        assert!(easy_rate > hard_rate);
        assert!(hard_rate > very_hard_rate);
    }

    #[test]
    fn test_relay_required_pairs() {
        let matrix = NatTestMatrix::comprehensive();
        let relay_pairs = matrix.relay_required_pairs();

        // Should have some relay-required pairs
        assert!(!relay_pairs.is_empty());

        // All should have Relay as expected method
        for pair in relay_pairs {
            assert_eq!(pair.expected_method, ExpectedMethod::Relay);
        }
    }

    #[test]
    fn test_easy_pairs() {
        let matrix = NatTestMatrix::comprehensive();
        let easy_pairs = matrix.easy_pairs();

        // Should have many easy pairs (involving None, UPnP, NatPmp)
        assert!(!easy_pairs.is_empty());

        // All should have Direct as expected method
        for pair in easy_pairs {
            assert_eq!(pair.expected_method, ExpectedMethod::Direct);
        }
    }

    #[test]
    fn test_pairs_with_source() {
        let matrix = NatTestMatrix::comprehensive();
        let symmetric_pairs = matrix.pairs_with_source(NatType::Symmetric);

        // Should have 11 pairs (one for each destination NAT type)
        assert_eq!(symmetric_pairs.len(), 11);

        // All should have Symmetric as source
        for pair in symmetric_pairs {
            assert_eq!(pair.source_nat, NatType::Symmetric);
        }
    }

    #[test]
    fn test_nat_pair_test_serialization() {
        let pair = NatPairTest {
            source_nat: NatType::PortRestricted,
            dest_nat: NatType::Symmetric,
            expected_method: ExpectedMethod::HolePunchOrRelay,
            expected_success_rate: 0.65,
            description: "Port Restricted -> Symmetric: Hard".to_string(),
        };

        let json = serde_json::to_string(&pair).unwrap();
        assert!(json.contains("port_restricted"));
        assert!(json.contains("symmetric"));
        assert!(json.contains("hole_punch_or_relay"));
    }

    #[test]
    fn test_expected_method_display() {
        assert_eq!(ExpectedMethod::Direct.to_string(), "Direct");
        assert_eq!(ExpectedMethod::HolePunch.to_string(), "Hole Punch");
        assert_eq!(ExpectedMethod::Relay.to_string(), "Relay");
        assert_eq!(
            ExpectedMethod::HolePunchOrRelay.to_string(),
            "Hole Punch or Relay"
        );
    }
}
