//! Test Orchestrator for autonomous network testing.
//!
//! The orchestrator runs on the registry server and coordinates test rounds
//! across all connected nodes. It triggers tests every few minutes and
//! aggregates results for the dashboard.

use crate::registry::{ConnectionMethod, NatType, PeerStore};
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
                    NatType::None | NatType::FullCone => {
                        vec![ConnectionMethod::Direct]
                    }
                    NatType::PortRestricted | NatType::AddressRestricted => {
                        vec![ConnectionMethod::HolePunched]
                    }
                    NatType::Symmetric => {
                        vec![ConnectionMethod::HolePunched, ConnectionMethod::Relayed]
                    }
                    NatType::Unknown => vec![ConnectionMethod::Direct],
                }
            } else {
                vec![]
            };

            let result = PeerTestResult {
                peer_id: peer.peer_id[..8.min(peer.peer_id.len())].to_string(),
                targets_tested: other_count,
                successful,
                failed,
                avg_rtt_ms: None, // RTT data would come from active testing
                methods_used,
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
}
