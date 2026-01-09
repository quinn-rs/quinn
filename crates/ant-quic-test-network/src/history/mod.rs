//! History persistence for test results.
//!
//! Stores connectivity test results and gossip crate status in a 24-hour rolling window.
//! Each hour gets its own JSON file, making it easy to prune old data.
//!
//! # File Structure
//!
//! ```text
//! ~/.ant-quic-test/history/
//!   history-2026-01-08-12.json
//!   history-2026-01-08-13.json
//!   ...
//! ```

mod storage;

pub use storage::{HistoryEntry, HistoryManager, HistoryStorage};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for history persistence.
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Base directory for history files.
    pub base_dir: PathBuf,
    /// How long to keep history (default: 24 hours).
    pub retention_hours: u32,
    /// Whether to auto-save on changes.
    pub auto_save: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ant-quic-test")
            .join("history");

        Self {
            base_dir,
            retention_hours: 24,
            auto_save: true,
        }
    }
}

/// Status of a connectivity test method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "status")]
pub enum ConnectivityStatus {
    /// Test succeeded with RTT measurement.
    #[serde(rename = "success")]
    Success { rtt_ms: u32 },
    /// Test failed with a reason.
    #[serde(rename = "failed")]
    Failed { reason: String },
    /// Test was not attempted.
    #[serde(rename = "untested")]
    #[default]
    Untested,
}

/// Connectivity results for a single peer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerConnectivity {
    /// IPv4 direct connection result.
    pub ipv4_direct: ConnectivityStatus,
    /// IPv6 direct connection result.
    pub ipv6_direct: ConnectivityStatus,
    /// NAT traversal result.
    pub nat_traversal: ConnectivityStatus,
    /// Relay connection result.
    pub relay: ConnectivityStatus,
    /// MASQUE relay result.
    pub masque: ConnectivityStatus,
}

impl PeerConnectivity {
    /// Returns true if any method succeeded.
    pub fn any_success(&self) -> bool {
        matches!(self.ipv4_direct, ConnectivityStatus::Success { .. })
            || matches!(self.ipv6_direct, ConnectivityStatus::Success { .. })
            || matches!(self.nat_traversal, ConnectivityStatus::Success { .. })
            || matches!(self.relay, ConnectivityStatus::Success { .. })
            || matches!(self.masque, ConnectivityStatus::Success { .. })
    }

    /// Count how many methods succeeded.
    pub fn success_count(&self) -> usize {
        [
            &self.ipv4_direct,
            &self.ipv6_direct,
            &self.nat_traversal,
            &self.relay,
            &self.masque,
        ]
        .iter()
        .filter(|s| matches!(s, ConnectivityStatus::Success { .. }))
        .count()
    }

    /// Count how many methods were tested.
    pub fn tested_count(&self) -> usize {
        [
            &self.ipv4_direct,
            &self.ipv6_direct,
            &self.nat_traversal,
            &self.relay,
            &self.masque,
        ]
        .iter()
        .filter(|s| !matches!(s, ConnectivityStatus::Untested))
        .count()
    }
}

/// Result of a single gossip crate test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipCrateResult {
    /// Whether the test passed.
    pub status: GossipStatus,
    /// Number of tests that passed.
    pub tests_passed: u32,
    /// Total number of tests.
    pub tests_total: u32,
}

/// Status of gossip crate testing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GossipStatus {
    /// All tests passed.
    Pass,
    /// Some tests failed.
    Fail,
    /// Tests were not run.
    NotRun,
}

impl Default for GossipCrateResult {
    fn default() -> Self {
        Self {
            status: GossipStatus::NotRun,
            tests_passed: 0,
            tests_total: 0,
        }
    }
}

/// Results for all 9 gossip crates.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GossipResults {
    pub types: GossipCrateResult,
    pub identity: GossipCrateResult,
    pub transport: GossipCrateResult,
    pub membership: GossipCrateResult,
    pub pubsub: GossipCrateResult,
    pub crdt_sync: GossipCrateResult,
    pub groups: GossipCrateResult,
    pub coordinator: GossipCrateResult,
    pub rendezvous: GossipCrateResult,
}

impl GossipResults {
    /// Count how many crates passed.
    pub fn passed_count(&self) -> usize {
        [
            &self.types,
            &self.identity,
            &self.transport,
            &self.membership,
            &self.pubsub,
            &self.crdt_sync,
            &self.groups,
            &self.coordinator,
            &self.rendezvous,
        ]
        .iter()
        .filter(|r| r.status == GossipStatus::Pass)
        .count()
    }

    /// Returns true if all crates passed.
    pub fn all_passed(&self) -> bool {
        self.passed_count() == 9
    }
}

/// A single history file containing entries for one hour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFile {
    /// Version of the history format.
    pub version: u32,
    /// Node ID that created this history.
    pub node_id: String,
    /// When this file was created.
    pub created_at: DateTime<Utc>,
    /// Hour this file covers (YYYY-MM-DD-HH format).
    pub hour: String,
    /// Connectivity test entries.
    pub entries: Vec<HistoryEntry>,
    /// Most recent gossip results (updated periodically).
    #[serde(default)]
    pub gossip_results: Option<GossipResults>,
}

impl HistoryFile {
    /// Create a new history file for the current hour.
    pub fn new(node_id: &str) -> Self {
        let now = Utc::now();
        Self {
            version: 1,
            node_id: node_id.to_string(),
            created_at: now,
            hour: now.format("%Y-%m-%d-%H").to_string(),
            entries: Vec::new(),
            gossip_results: None,
        }
    }

    /// Get the filename for this history file.
    pub fn filename(&self) -> String {
        format!("history-{}.json", self.hour)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connectivity_status_serialization() {
        let success = ConnectivityStatus::Success { rtt_ms: 45 };
        let json = serde_json::to_string(&success).unwrap();
        assert!(json.contains("success"));
        assert!(json.contains("45"));

        let failed = ConnectivityStatus::Failed {
            reason: "timeout".to_string(),
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("failed"));
        assert!(json.contains("timeout"));
    }

    #[test]
    fn test_peer_connectivity_any_success() {
        let mut conn = PeerConnectivity::default();
        assert!(!conn.any_success());

        conn.ipv4_direct = ConnectivityStatus::Success { rtt_ms: 10 };
        assert!(conn.any_success());
    }

    #[test]
    fn test_peer_connectivity_counts() {
        let mut conn = PeerConnectivity::default();
        assert_eq!(conn.success_count(), 0);
        assert_eq!(conn.tested_count(), 0);

        conn.ipv4_direct = ConnectivityStatus::Success { rtt_ms: 10 };
        conn.ipv6_direct = ConnectivityStatus::Failed {
            reason: "no route".to_string(),
        };

        assert_eq!(conn.success_count(), 1);
        assert_eq!(conn.tested_count(), 2);
    }

    #[test]
    fn test_gossip_results_counts() {
        let mut results = GossipResults::default();
        assert_eq!(results.passed_count(), 0);
        assert!(!results.all_passed());

        results.types.status = GossipStatus::Pass;
        results.identity.status = GossipStatus::Pass;
        assert_eq!(results.passed_count(), 2);
        assert!(!results.all_passed());
    }

    #[test]
    fn test_history_file_creation() {
        let file = HistoryFile::new("test_node_123");
        assert_eq!(file.version, 1);
        assert_eq!(file.node_id, "test_node_123");
        assert!(file.entries.is_empty());
        assert!(file.filename().starts_with("history-"));
        assert!(file.filename().ends_with(".json"));
    }

    #[test]
    fn test_history_config_default() {
        let config = HistoryConfig::default();
        assert_eq!(config.retention_hours, 24);
        assert!(config.auto_save);
        assert!(config.base_dir.to_string_lossy().contains(".ant-quic-test"));
    }
}
