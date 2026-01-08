//! Comprehensive testing infrastructure for all 9 saorsa-gossip crates.
//!
//! This module provides systematic testing of the entire gossip stack:
//! - types: Wire format serialization/deserialization
//! - identity: ML-DSA-65 key generation and signing
//! - transport: QUIC stream management (3 control streams)
//! - membership: HyParView + SWIM failure detection
//! - pubsub: Plumtree epidemic broadcast (EAGER/IHAVE/IWANT)
//! - crdt-sync: OR-Set delta merge and convergence
//! - groups: MLS group management and presence
//! - coordinator: Bootstrap and advert discovery
//! - rendezvous: Shard calculation and provider lookup

pub mod crate_tests;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Test status for individual tests.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestStatus {
    /// Test has not been run yet.
    #[default]
    Pending,
    /// Test is currently running.
    Running,
    /// Test passed successfully.
    Passed,
    /// Test failed with error.
    Failed,
    /// Test was skipped (e.g., dependency not available).
    Skipped,
}

impl TestStatus {
    /// Returns true if the test passed.
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Returns true if the test failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }
}

impl std::fmt::Display for TestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::Running => write!(f, "RUNNING"),
            Self::Passed => write!(f, "PASSED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Skipped => write!(f, "SKIPPED"),
        }
    }
}

/// Individual test detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDetail {
    /// Name of the test.
    pub name: String,
    /// Test status.
    pub status: TestStatus,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Error message if failed.
    pub error: Option<String>,
    /// Timestamp when test was run.
    pub timestamp: DateTime<Utc>,
}

impl TestDetail {
    /// Create a new pending test detail.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: TestStatus::Pending,
            duration_ms: 0,
            error: None,
            timestamp: Utc::now(),
        }
    }

    /// Mark test as passed.
    pub fn pass(&mut self, duration_ms: u64) {
        self.status = TestStatus::Passed;
        self.duration_ms = duration_ms;
        self.timestamp = Utc::now();
    }

    /// Mark test as failed.
    pub fn fail(&mut self, duration_ms: u64, error: impl Into<String>) {
        self.status = TestStatus::Failed;
        self.duration_ms = duration_ms;
        self.error = Some(error.into());
        self.timestamp = Utc::now();
    }

    /// Mark test as skipped.
    pub fn skip(&mut self, reason: impl Into<String>) {
        self.status = TestStatus::Skipped;
        self.error = Some(reason.into());
        self.timestamp = Utc::now();
    }
}

/// Result of testing a single gossip crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateTestResult {
    /// Name of the crate being tested.
    pub crate_name: String,
    /// Overall status of all tests for this crate.
    pub status: TestStatus,
    /// Number of tests that passed.
    pub tests_passed: u32,
    /// Number of tests that failed.
    pub tests_failed: u32,
    /// Number of tests that were skipped.
    pub tests_skipped: u32,
    /// Total number of tests.
    pub tests_total: u32,
    /// When the tests were last run.
    pub last_run: DateTime<Utc>,
    /// Individual test details.
    pub details: Vec<TestDetail>,
}

impl CrateTestResult {
    /// Create a new crate test result.
    pub fn new(crate_name: impl Into<String>) -> Self {
        Self {
            crate_name: crate_name.into(),
            status: TestStatus::Pending,
            tests_passed: 0,
            tests_failed: 0,
            tests_skipped: 0,
            tests_total: 0,
            last_run: Utc::now(),
            details: Vec::new(),
        }
    }

    /// Add a test detail.
    pub fn add_test(&mut self, detail: TestDetail) {
        match detail.status {
            TestStatus::Passed => self.tests_passed += 1,
            TestStatus::Failed => self.tests_failed += 1,
            TestStatus::Skipped => self.tests_skipped += 1,
            _ => {}
        }
        self.tests_total += 1;
        self.details.push(detail);
    }

    /// Finalize the crate result and compute overall status.
    pub fn finalize(&mut self) {
        self.last_run = Utc::now();
        if self.tests_failed > 0 {
            self.status = TestStatus::Failed;
        } else if self.tests_passed > 0 {
            self.status = TestStatus::Passed;
        } else if self.tests_skipped > 0 {
            self.status = TestStatus::Skipped;
        } else {
            self.status = TestStatus::Pending;
        }
    }

    /// Get pass rate as percentage (0-100).
    pub fn pass_rate(&self) -> f32 {
        if self.tests_total == 0 {
            return 0.0;
        }
        (self.tests_passed as f32 / self.tests_total as f32) * 100.0
    }
}

/// Comprehensive test results for all 9 saorsa-gossip crates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipTestResults {
    /// saorsa-gossip-types: Wire format serialization.
    pub types: CrateTestResult,
    /// saorsa-gossip-identity: ML-DSA-65 cryptography.
    pub identity: CrateTestResult,
    /// saorsa-gossip-transport: QUIC stream management.
    pub transport: CrateTestResult,
    /// saorsa-gossip-membership: HyParView + SWIM.
    pub membership: CrateTestResult,
    /// saorsa-gossip-pubsub: Plumtree epidemic broadcast.
    pub pubsub: CrateTestResult,
    /// saorsa-gossip-crdt-sync: OR-Set delta merge.
    pub crdt_sync: CrateTestResult,
    /// saorsa-gossip-groups: MLS group management.
    pub groups: CrateTestResult,
    /// saorsa-gossip-coordinator: Bootstrap and discovery.
    pub coordinator: CrateTestResult,
    /// saorsa-gossip-rendezvous: Shard calculation.
    pub rendezvous: CrateTestResult,
}

impl Default for GossipTestResults {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipTestResults {
    /// Create new empty results for all crates.
    pub fn new() -> Self {
        Self {
            types: CrateTestResult::new("saorsa-gossip-types"),
            identity: CrateTestResult::new("saorsa-gossip-identity"),
            transport: CrateTestResult::new("saorsa-gossip-transport"),
            membership: CrateTestResult::new("saorsa-gossip-membership"),
            pubsub: CrateTestResult::new("saorsa-gossip-pubsub"),
            crdt_sync: CrateTestResult::new("saorsa-gossip-crdt-sync"),
            groups: CrateTestResult::new("saorsa-gossip-groups"),
            coordinator: CrateTestResult::new("saorsa-gossip-coordinator"),
            rendezvous: CrateTestResult::new("saorsa-gossip-rendezvous"),
        }
    }

    /// Get total number of crates passing.
    pub fn crates_passing(&self) -> u32 {
        let mut count = 0;
        if self.types.status.is_passed() {
            count += 1;
        }
        if self.identity.status.is_passed() {
            count += 1;
        }
        if self.transport.status.is_passed() {
            count += 1;
        }
        if self.membership.status.is_passed() {
            count += 1;
        }
        if self.pubsub.status.is_passed() {
            count += 1;
        }
        if self.crdt_sync.status.is_passed() {
            count += 1;
        }
        if self.groups.status.is_passed() {
            count += 1;
        }
        if self.coordinator.status.is_passed() {
            count += 1;
        }
        if self.rendezvous.status.is_passed() {
            count += 1;
        }
        count
    }

    /// Get total number of crates (always 9).
    pub const fn total_crates() -> u32 {
        9
    }

    /// Check if all crates are passing.
    pub fn all_passing(&self) -> bool {
        self.crates_passing() == Self::total_crates()
    }

    /// Get overall pass rate as percentage.
    pub fn overall_pass_rate(&self) -> f32 {
        (self.crates_passing() as f32 / Self::total_crates() as f32) * 100.0
    }

    /// Get a summary string like "9/9 passing" or "7/9 passing".
    pub fn summary(&self) -> String {
        format!("{}/{} passing", self.crates_passing(), Self::total_crates())
    }

    /// Get iterator over all crate results.
    pub fn iter(&self) -> impl Iterator<Item = &CrateTestResult> {
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
        .into_iter()
    }

    /// Get mutable iterator over all crate results.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CrateTestResult> {
        [
            &mut self.types,
            &mut self.identity,
            &mut self.transport,
            &mut self.membership,
            &mut self.pubsub,
            &mut self.crdt_sync,
            &mut self.groups,
            &mut self.coordinator,
            &mut self.rendezvous,
        ]
        .into_iter()
    }
}

/// Gossip test coordinator that manages running tests for all crates.
pub struct GossipTestCoordinator {
    /// Current test results.
    results: Arc<RwLock<GossipTestResults>>,
    /// Whether tests are currently running.
    running: Arc<RwLock<bool>>,
}

impl Default for GossipTestCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipTestCoordinator {
    /// Create a new coordinator.
    pub fn new() -> Self {
        Self {
            results: Arc::new(RwLock::new(GossipTestResults::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Get current results.
    pub async fn get_results(&self) -> GossipTestResults {
        self.results.read().await.clone()
    }

    /// Check if tests are currently running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Run all gossip crate tests.
    ///
    /// This runs tests for all 9 crates in sequence and updates the results.
    pub async fn run_all_tests(&self) -> GossipTestResults {
        // Mark as running
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Reset results
        {
            let mut results = self.results.write().await;
            *results = GossipTestResults::new();
        }

        // Run tests for each crate
        let types_result = crate_tests::test_types_crate().await;
        {
            let mut results = self.results.write().await;
            results.types = types_result;
        }

        let identity_result = crate_tests::test_identity_crate().await;
        {
            let mut results = self.results.write().await;
            results.identity = identity_result;
        }

        let transport_result = crate_tests::test_transport_crate().await;
        {
            let mut results = self.results.write().await;
            results.transport = transport_result;
        }

        let membership_result = crate_tests::test_membership_crate().await;
        {
            let mut results = self.results.write().await;
            results.membership = membership_result;
        }

        let pubsub_result = crate_tests::test_pubsub_crate().await;
        {
            let mut results = self.results.write().await;
            results.pubsub = pubsub_result;
        }

        let crdt_sync_result = crate_tests::test_crdt_sync_crate().await;
        {
            let mut results = self.results.write().await;
            results.crdt_sync = crdt_sync_result;
        }

        let groups_result = crate_tests::test_groups_crate().await;
        {
            let mut results = self.results.write().await;
            results.groups = groups_result;
        }

        let coordinator_result = crate_tests::test_coordinator_crate().await;
        {
            let mut results = self.results.write().await;
            results.coordinator = coordinator_result;
        }

        let rendezvous_result = crate_tests::test_rendezvous_crate().await;
        {
            let mut results = self.results.write().await;
            results.rendezvous = rendezvous_result;
        }

        // Mark as complete
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        self.results.read().await.clone()
    }

    /// Run tests for a specific crate by name.
    pub async fn run_crate_tests(&self, crate_name: &str) -> Option<CrateTestResult> {
        let result = match crate_name {
            "types" | "saorsa-gossip-types" => Some(crate_tests::test_types_crate().await),
            "identity" | "saorsa-gossip-identity" => Some(crate_tests::test_identity_crate().await),
            "transport" | "saorsa-gossip-transport" => {
                Some(crate_tests::test_transport_crate().await)
            }
            "membership" | "saorsa-gossip-membership" => {
                Some(crate_tests::test_membership_crate().await)
            }
            "pubsub" | "saorsa-gossip-pubsub" => Some(crate_tests::test_pubsub_crate().await),
            "crdt-sync" | "saorsa-gossip-crdt-sync" => {
                Some(crate_tests::test_crdt_sync_crate().await)
            }
            "groups" | "saorsa-gossip-groups" => Some(crate_tests::test_groups_crate().await),
            "coordinator" | "saorsa-gossip-coordinator" => {
                Some(crate_tests::test_coordinator_crate().await)
            }
            "rendezvous" | "saorsa-gossip-rendezvous" => {
                Some(crate_tests::test_rendezvous_crate().await)
            }
            _ => None,
        };

        // Update results if we ran a test
        if let Some(ref crate_result) = result {
            let mut results = self.results.write().await;
            match crate_name {
                "types" | "saorsa-gossip-types" => results.types = crate_result.clone(),
                "identity" | "saorsa-gossip-identity" => results.identity = crate_result.clone(),
                "transport" | "saorsa-gossip-transport" => results.transport = crate_result.clone(),
                "membership" | "saorsa-gossip-membership" => {
                    results.membership = crate_result.clone()
                }
                "pubsub" | "saorsa-gossip-pubsub" => results.pubsub = crate_result.clone(),
                "crdt-sync" | "saorsa-gossip-crdt-sync" => results.crdt_sync = crate_result.clone(),
                "groups" | "saorsa-gossip-groups" => results.groups = crate_result.clone(),
                "coordinator" | "saorsa-gossip-coordinator" => {
                    results.coordinator = crate_result.clone()
                }
                "rendezvous" | "saorsa-gossip-rendezvous" => {
                    results.rendezvous = crate_result.clone()
                }
                _ => {}
            }
        }

        result
    }
}
