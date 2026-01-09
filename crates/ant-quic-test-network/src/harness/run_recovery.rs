//! Idempotent Run Recovery (Checkpoint/Resume)
//!
//! This module provides checkpoint and resume capabilities for distributed
//! test runs. It enables:
//! - Saving run state at key milestones
//! - Resuming interrupted runs from last checkpoint
//! - Idempotent retry of failed stages
//! - Recovery from partial failures
//!
//! Checkpoints capture the complete state needed to resume a run,
//! including agent statuses, completed tests, and partial results.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use super::RunStatus;

/// Stage of a test run where checkpoints can be taken
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum RunStage {
    /// Initial setup, before any agents contacted
    #[default]
    Init,
    /// Preflight checks completed
    Preflight,
    /// Agents discovered and registered
    Discovery,
    /// Test execution started
    Running,
    /// Test execution paused (recoverable)
    Paused,
    /// Collecting results from agents
    Collecting,
    /// Results uploaded
    Uploading,
    /// Run completed successfully
    Completed,
    /// Run failed (terminal)
    Failed,
    /// Run cancelled (terminal)
    Cancelled,
}

impl RunStage {
    /// Check if this is a terminal stage
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Check if checkpoints can be taken at this stage
    pub fn is_checkpointable(&self) -> bool {
        !self.is_terminal() && *self != Self::Init
    }

    /// Check if this stage can be resumed
    pub fn is_resumable(&self) -> bool {
        matches!(
            self,
            Self::Preflight | Self::Discovery | Self::Running | Self::Paused | Self::Collecting
        )
    }

    /// Get the next stage in normal progression
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Init => Some(Self::Preflight),
            Self::Preflight => Some(Self::Discovery),
            Self::Discovery => Some(Self::Running),
            Self::Running => Some(Self::Collecting),
            Self::Paused => Some(Self::Running),
            Self::Collecting => Some(Self::Uploading),
            Self::Uploading => Some(Self::Completed),
            Self::Completed | Self::Failed | Self::Cancelled => None,
        }
    }
}

/// Agent state captured in a checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckpointState {
    /// Agent ID
    pub agent_id: String,
    /// Agent URL
    pub url: String,
    /// Current status
    pub status: RunStatus,
    /// Last successful heartbeat
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<SystemTime>,
    /// Tests assigned to this agent
    pub assigned_tests: Vec<Uuid>,
    /// Tests completed by this agent
    pub completed_tests: Vec<Uuid>,
    /// Number of retry attempts
    pub retry_count: u32,
}

impl AgentCheckpointState {
    /// Create a new agent checkpoint state
    pub fn new(agent_id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            url: url.into(),
            status: RunStatus::Pending,
            last_heartbeat: None,
            assigned_tests: Vec::new(),
            completed_tests: Vec::new(),
            retry_count: 0,
        }
    }

    /// Check if agent has pending work
    pub fn has_pending_work(&self) -> bool {
        self.assigned_tests.len() > self.completed_tests.len()
    }

    /// Get tests that are still pending
    pub fn pending_tests(&self) -> Vec<Uuid> {
        self.assigned_tests
            .iter()
            .filter(|t| !self.completed_tests.contains(t))
            .copied()
            .collect()
    }
}

/// Data contained in a checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointData {
    /// Run ID
    pub run_id: Uuid,
    /// Current stage
    pub stage: RunStage,
    /// Agent states
    pub agents: HashMap<String, AgentCheckpointState>,
    /// Completed test IDs
    pub completed_tests: Vec<Uuid>,
    /// Failed test IDs
    pub failed_tests: Vec<Uuid>,
    /// Partial results collected so far (serialized)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_results: Option<String>,
    /// Configuration snapshot
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, String>,
    /// Run metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl CheckpointData {
    /// Create new checkpoint data
    pub fn new(run_id: Uuid, stage: RunStage) -> Self {
        Self {
            run_id,
            stage,
            agents: HashMap::new(),
            completed_tests: Vec::new(),
            failed_tests: Vec::new(),
            partial_results: None,
            config: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add agent state
    pub fn add_agent(&mut self, agent: AgentCheckpointState) {
        self.agents.insert(agent.agent_id.clone(), agent);
    }

    /// Mark test as completed
    pub fn complete_test(&mut self, test_id: Uuid) {
        if !self.completed_tests.contains(&test_id) {
            self.completed_tests.push(test_id);
        }
    }

    /// Mark test as failed
    pub fn fail_test(&mut self, test_id: Uuid) {
        if !self.failed_tests.contains(&test_id) {
            self.failed_tests.push(test_id);
        }
    }

    /// Get total tests processed
    pub fn tests_processed(&self) -> usize {
        self.completed_tests.len() + self.failed_tests.len()
    }

    /// Get agent by ID
    pub fn get_agent(&self, agent_id: &str) -> Option<&AgentCheckpointState> {
        self.agents.get(agent_id)
    }

    /// Get mutable agent by ID
    pub fn get_agent_mut(&mut self, agent_id: &str) -> Option<&mut AgentCheckpointState> {
        self.agents.get_mut(agent_id)
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A checkpoint representing run state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint ID
    pub id: Uuid,
    /// Sequence number (monotonically increasing)
    pub sequence: u64,
    /// When checkpoint was created
    pub created_at: SystemTime,
    /// Checkpoint data
    pub data: CheckpointData,
    /// SHA-256 hash for integrity verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// Previous checkpoint ID (for chain verification)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_id: Option<Uuid>,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(sequence: u64, data: CheckpointData) -> Self {
        Self {
            id: Uuid::new_v4(),
            sequence,
            created_at: SystemTime::now(),
            data,
            checksum: None,
            previous_id: None,
        }
    }

    /// Create checkpoint with link to previous
    pub fn with_previous(mut self, previous: &Checkpoint) -> Self {
        self.previous_id = Some(previous.id);
        self
    }

    /// Set checksum
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Get run ID
    pub fn run_id(&self) -> Uuid {
        self.data.run_id
    }

    /// Get current stage
    pub fn stage(&self) -> RunStage {
        self.data.stage
    }

    /// Validate checkpoint integrity
    pub fn validate(&self) -> bool {
        // Basic validation - stage should be checkpointable
        self.data.stage.is_checkpointable() || self.data.stage.is_terminal()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Result of a recovery operation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryResult {
    /// Successfully recovered
    Recovered {
        /// Number of completed tests preserved
        preserved_tests: usize,
        /// Number of agents restored
        restored_agents: usize,
    },
    /// No checkpoint available
    NoCheckpoint,
    /// Checkpoint too old or incompatible
    CheckpointStale,
    /// Checkpoint corrupted
    CheckpointCorrupted,
    /// Recovery not possible from this stage
    UnrecoverableStage,
    /// Recovery failed with error
    Failed { reason: String },
}

impl RecoveryResult {
    /// Check if recovery was successful
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Recovered { .. })
    }

    /// Create a successful recovery result
    pub fn success(preserved_tests: usize, restored_agents: usize) -> Self {
        Self::Recovered {
            preserved_tests,
            restored_agents,
        }
    }

    /// Create a failed recovery result
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }
}

/// Manager for run checkpoints and recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecoveryManager {
    /// Run ID being managed
    pub run_id: Uuid,
    /// Latest checkpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_checkpoint: Option<Checkpoint>,
    /// All checkpoints (for audit trail)
    pub checkpoints: Vec<Checkpoint>,
    /// Next sequence number (monotonically increasing)
    next_sequence: u64,
    /// Checkpoint storage path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<PathBuf>,
    /// Maximum checkpoints to retain
    pub max_checkpoints: usize,
    /// Checkpoint interval (time between auto-checkpoints)
    #[serde(with = "humantime_serde", default = "default_interval")]
    pub checkpoint_interval: Duration,
    /// Last checkpoint time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checkpoint_time: Option<SystemTime>,
}

fn default_interval() -> Duration {
    Duration::from_secs(60) // 1 minute
}

impl RunRecoveryManager {
    /// Create a new recovery manager
    pub fn new(run_id: Uuid) -> Self {
        Self {
            run_id,
            latest_checkpoint: None,
            checkpoints: Vec::new(),
            next_sequence: 0,
            storage_path: None,
            max_checkpoints: 10,
            checkpoint_interval: default_interval(),
            last_checkpoint_time: None,
        }
    }

    /// Set storage path
    pub fn with_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Set max checkpoints
    pub fn with_max_checkpoints(mut self, max: usize) -> Self {
        self.max_checkpoints = max;
        self
    }

    /// Set checkpoint interval
    pub fn with_checkpoint_interval(mut self, interval: Duration) -> Self {
        self.checkpoint_interval = interval;
        self
    }

    /// Create a new checkpoint
    pub fn checkpoint(&mut self, data: CheckpointData) -> &Checkpoint {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let mut checkpoint = Checkpoint::new(sequence, data);

        // Link to previous checkpoint
        if let Some(prev) = self.latest_checkpoint.as_ref() {
            checkpoint = checkpoint.with_previous(prev);
        }

        self.checkpoints.push(checkpoint.clone());
        self.latest_checkpoint = Some(checkpoint);
        self.last_checkpoint_time = Some(SystemTime::now());

        // Prune old checkpoints if needed
        self.prune_checkpoints();

        self.latest_checkpoint.as_ref().unwrap()
    }

    /// Prune old checkpoints beyond max_checkpoints
    fn prune_checkpoints(&mut self) {
        if self.checkpoints.len() > self.max_checkpoints {
            let remove_count = self.checkpoints.len() - self.max_checkpoints;
            self.checkpoints.drain(0..remove_count);
        }
    }

    /// Get latest checkpoint
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.latest_checkpoint.as_ref()
    }

    /// Check if checkpoint is needed based on interval
    pub fn needs_checkpoint(&self) -> bool {
        match self.last_checkpoint_time {
            None => true,
            Some(last) => {
                let elapsed = SystemTime::now()
                    .duration_since(last)
                    .unwrap_or(Duration::ZERO);
                elapsed >= self.checkpoint_interval
            }
        }
    }

    /// Attempt to recover from the latest checkpoint
    pub fn recover(&self) -> RecoveryResult {
        let checkpoint = match self.latest_checkpoint.as_ref() {
            Some(cp) => cp,
            None => return RecoveryResult::NoCheckpoint,
        };

        // Validate checkpoint
        if !checkpoint.validate() {
            return RecoveryResult::CheckpointCorrupted;
        }

        // Check if stage is resumable
        if !checkpoint.data.stage.is_resumable() {
            return RecoveryResult::UnrecoverableStage;
        }

        RecoveryResult::success(
            checkpoint.data.completed_tests.len(),
            checkpoint.data.agents.len(),
        )
    }

    /// Recover from a specific checkpoint by ID
    pub fn recover_from(&self, checkpoint_id: Uuid) -> RecoveryResult {
        let checkpoint = match self.checkpoints.iter().find(|cp| cp.id == checkpoint_id) {
            Some(cp) => cp,
            None => return RecoveryResult::NoCheckpoint,
        };

        if !checkpoint.validate() {
            return RecoveryResult::CheckpointCorrupted;
        }

        if !checkpoint.data.stage.is_resumable() {
            return RecoveryResult::UnrecoverableStage;
        }

        RecoveryResult::success(
            checkpoint.data.completed_tests.len(),
            checkpoint.data.agents.len(),
        )
    }

    /// Get checkpoint count
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Get checkpoint by sequence number
    pub fn get_by_sequence(&self, sequence: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|cp| cp.sequence == sequence)
    }

    /// Clear all checkpoints (for testing or reset)
    pub fn clear(&mut self) {
        self.checkpoints.clear();
        self.latest_checkpoint = None;
        self.last_checkpoint_time = None;
        self.next_sequence = 0;
    }
}

/// Configuration for recovery behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable automatic checkpointing
    pub auto_checkpoint: bool,
    /// Checkpoint at stage transitions
    pub checkpoint_on_stage_change: bool,
    /// Checkpoint after N tests complete
    pub checkpoint_every_n_tests: Option<usize>,
    /// Maximum age for valid checkpoint
    #[serde(with = "humantime_serde")]
    pub max_checkpoint_age: Duration,
    /// Retry count for recovery attempts
    pub max_recovery_retries: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            auto_checkpoint: true,
            checkpoint_on_stage_change: true,
            checkpoint_every_n_tests: Some(10),
            max_checkpoint_age: Duration::from_secs(3600), // 1 hour
            max_recovery_retries: 3,
        }
    }
}

impl RecoveryConfig {
    /// Disable auto-checkpointing
    pub fn without_auto_checkpoint(mut self) -> Self {
        self.auto_checkpoint = false;
        self
    }

    /// Set test checkpoint interval
    pub fn with_test_interval(mut self, n: usize) -> Self {
        self.checkpoint_every_n_tests = Some(n);
        self
    }

    /// Set max checkpoint age
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_checkpoint_age = age;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== RunStage Tests ====================

    #[test]
    fn test_run_stage_default() {
        assert_eq!(RunStage::default(), RunStage::Init);
    }

    #[test]
    fn test_run_stage_is_terminal() {
        assert!(!RunStage::Init.is_terminal());
        assert!(!RunStage::Running.is_terminal());
        assert!(RunStage::Completed.is_terminal());
        assert!(RunStage::Failed.is_terminal());
        assert!(RunStage::Cancelled.is_terminal());
    }

    #[test]
    fn test_run_stage_is_checkpointable() {
        assert!(!RunStage::Init.is_checkpointable());
        assert!(RunStage::Preflight.is_checkpointable());
        assert!(RunStage::Running.is_checkpointable());
        assert!(!RunStage::Completed.is_checkpointable());
        assert!(!RunStage::Failed.is_checkpointable());
    }

    #[test]
    fn test_run_stage_is_resumable() {
        assert!(!RunStage::Init.is_resumable());
        assert!(RunStage::Preflight.is_resumable());
        assert!(RunStage::Discovery.is_resumable());
        assert!(RunStage::Running.is_resumable());
        assert!(RunStage::Paused.is_resumable());
        assert!(RunStage::Collecting.is_resumable());
        assert!(!RunStage::Uploading.is_resumable());
        assert!(!RunStage::Completed.is_resumable());
    }

    #[test]
    fn test_run_stage_next() {
        assert_eq!(RunStage::Init.next(), Some(RunStage::Preflight));
        assert_eq!(RunStage::Preflight.next(), Some(RunStage::Discovery));
        assert_eq!(RunStage::Discovery.next(), Some(RunStage::Running));
        assert_eq!(RunStage::Running.next(), Some(RunStage::Collecting));
        assert_eq!(RunStage::Paused.next(), Some(RunStage::Running));
        assert_eq!(RunStage::Collecting.next(), Some(RunStage::Uploading));
        assert_eq!(RunStage::Uploading.next(), Some(RunStage::Completed));
        assert_eq!(RunStage::Completed.next(), None);
        assert_eq!(RunStage::Failed.next(), None);
    }

    #[test]
    fn test_run_stage_ordering() {
        assert!(RunStage::Init < RunStage::Preflight);
        assert!(RunStage::Preflight < RunStage::Running);
        assert!(RunStage::Running < RunStage::Completed);
    }

    // ==================== AgentCheckpointState Tests ====================

    #[test]
    fn test_agent_checkpoint_state_new() {
        let state = AgentCheckpointState::new("agent-1", "http://localhost:8080");

        assert_eq!(state.agent_id, "agent-1");
        assert_eq!(state.url, "http://localhost:8080");
        assert_eq!(state.status, RunStatus::Pending);
        assert!(state.assigned_tests.is_empty());
    }

    #[test]
    fn test_agent_checkpoint_state_has_pending_work() {
        let mut state = AgentCheckpointState::new("agent-1", "http://localhost:8080");
        assert!(!state.has_pending_work());

        let test_id = Uuid::new_v4();
        state.assigned_tests.push(test_id);
        assert!(state.has_pending_work());

        state.completed_tests.push(test_id);
        assert!(!state.has_pending_work());
    }

    #[test]
    fn test_agent_checkpoint_state_pending_tests() {
        let mut state = AgentCheckpointState::new("agent-1", "http://localhost:8080");
        let test1 = Uuid::new_v4();
        let test2 = Uuid::new_v4();
        let test3 = Uuid::new_v4();

        state.assigned_tests = vec![test1, test2, test3];
        state.completed_tests = vec![test1];

        let pending = state.pending_tests();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&test2));
        assert!(pending.contains(&test3));
    }

    // ==================== CheckpointData Tests ====================

    #[test]
    fn test_checkpoint_data_new() {
        let run_id = Uuid::new_v4();
        let data = CheckpointData::new(run_id, RunStage::Running);

        assert_eq!(data.run_id, run_id);
        assert_eq!(data.stage, RunStage::Running);
        assert!(data.agents.is_empty());
        assert!(data.completed_tests.is_empty());
    }

    #[test]
    fn test_checkpoint_data_add_agent() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);

        let agent = AgentCheckpointState::new("agent-1", "http://localhost:8080");
        data.add_agent(agent);

        assert_eq!(data.agents.len(), 1);
        assert!(data.agents.contains_key("agent-1"));
    }

    #[test]
    fn test_checkpoint_data_complete_test() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);
        let test_id = Uuid::new_v4();

        data.complete_test(test_id);
        assert_eq!(data.completed_tests.len(), 1);

        // Idempotent
        data.complete_test(test_id);
        assert_eq!(data.completed_tests.len(), 1);
    }

    #[test]
    fn test_checkpoint_data_fail_test() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);
        let test_id = Uuid::new_v4();

        data.fail_test(test_id);
        assert_eq!(data.failed_tests.len(), 1);

        // Idempotent
        data.fail_test(test_id);
        assert_eq!(data.failed_tests.len(), 1);
    }

    #[test]
    fn test_checkpoint_data_tests_processed() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);

        data.complete_test(Uuid::new_v4());
        data.complete_test(Uuid::new_v4());
        data.fail_test(Uuid::new_v4());

        assert_eq!(data.tests_processed(), 3);
    }

    #[test]
    fn test_checkpoint_data_get_agent() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);
        data.add_agent(AgentCheckpointState::new(
            "agent-1",
            "http://localhost:8080",
        ));

        assert!(data.get_agent("agent-1").is_some());
        assert!(data.get_agent("agent-2").is_none());
    }

    #[test]
    fn test_checkpoint_data_with_metadata() {
        let run_id = Uuid::new_v4();
        let data = CheckpointData::new(run_id, RunStage::Running)
            .with_metadata("version", "1.0.0")
            .with_metadata("environment", "test");

        assert_eq!(data.metadata.get("version"), Some(&"1.0.0".to_string()));
        assert_eq!(data.metadata.get("environment"), Some(&"test".to_string()));
    }

    // ==================== Checkpoint Tests ====================

    #[test]
    fn test_checkpoint_new() {
        let run_id = Uuid::new_v4();
        let data = CheckpointData::new(run_id, RunStage::Running);
        let checkpoint = Checkpoint::new(0, data);

        assert_eq!(checkpoint.sequence, 0);
        assert_eq!(checkpoint.run_id(), run_id);
        assert_eq!(checkpoint.stage(), RunStage::Running);
        assert!(checkpoint.previous_id.is_none());
    }

    #[test]
    fn test_checkpoint_with_previous() {
        let run_id = Uuid::new_v4();
        let data1 = CheckpointData::new(run_id, RunStage::Preflight);
        let cp1 = Checkpoint::new(0, data1);

        let data2 = CheckpointData::new(run_id, RunStage::Running);
        let cp2 = Checkpoint::new(1, data2).with_previous(&cp1);

        assert_eq!(cp2.previous_id, Some(cp1.id));
    }

    #[test]
    fn test_checkpoint_with_checksum() {
        let run_id = Uuid::new_v4();
        let data = CheckpointData::new(run_id, RunStage::Running);
        let checkpoint = Checkpoint::new(0, data).with_checksum("abc123");

        assert_eq!(checkpoint.checksum, Some("abc123".to_string()));
    }

    #[test]
    fn test_checkpoint_validate() {
        let run_id = Uuid::new_v4();

        // Valid checkpoint
        let data = CheckpointData::new(run_id, RunStage::Running);
        let checkpoint = Checkpoint::new(0, data);
        assert!(checkpoint.validate());

        // Invalid - Init stage
        let data = CheckpointData::new(run_id, RunStage::Init);
        let checkpoint = Checkpoint::new(0, data);
        assert!(!checkpoint.validate());

        // Terminal stage is valid (for final checkpoint)
        let data = CheckpointData::new(run_id, RunStage::Completed);
        let checkpoint = Checkpoint::new(0, data);
        assert!(checkpoint.validate());
    }

    #[test]
    fn test_checkpoint_serialization() {
        let run_id = Uuid::new_v4();
        let mut data = CheckpointData::new(run_id, RunStage::Running);
        data.add_agent(AgentCheckpointState::new(
            "agent-1",
            "http://localhost:8080",
        ));
        data.complete_test(Uuid::new_v4());

        let checkpoint = Checkpoint::new(0, data);
        let json = checkpoint.to_json().unwrap();
        let restored = Checkpoint::from_json(&json).unwrap();

        assert_eq!(restored.run_id(), checkpoint.run_id());
        assert_eq!(restored.stage(), checkpoint.stage());
        assert_eq!(restored.data.agents.len(), checkpoint.data.agents.len());
    }

    // ==================== RecoveryResult Tests ====================

    #[test]
    fn test_recovery_result_success() {
        let result = RecoveryResult::success(10, 3);
        assert!(result.is_success());

        match result {
            RecoveryResult::Recovered {
                preserved_tests,
                restored_agents,
            } => {
                assert_eq!(preserved_tests, 10);
                assert_eq!(restored_agents, 3);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_recovery_result_failed() {
        let result = RecoveryResult::failed("Something went wrong");
        assert!(!result.is_success());

        match result {
            RecoveryResult::Failed { reason } => {
                assert_eq!(reason, "Something went wrong");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_recovery_result_variants() {
        assert!(!RecoveryResult::NoCheckpoint.is_success());
        assert!(!RecoveryResult::CheckpointStale.is_success());
        assert!(!RecoveryResult::CheckpointCorrupted.is_success());
        assert!(!RecoveryResult::UnrecoverableStage.is_success());
    }

    // ==================== RunRecoveryManager Tests ====================

    #[test]
    fn test_recovery_manager_new() {
        let run_id = Uuid::new_v4();
        let manager = RunRecoveryManager::new(run_id);

        assert_eq!(manager.run_id, run_id);
        assert!(manager.latest_checkpoint.is_none());
        assert!(manager.checkpoints.is_empty());
        assert_eq!(manager.max_checkpoints, 10);
    }

    #[test]
    fn test_recovery_manager_with_storage_path() {
        let run_id = Uuid::new_v4();
        let manager = RunRecoveryManager::new(run_id).with_storage_path("/tmp/checkpoints");

        assert_eq!(
            manager.storage_path,
            Some(PathBuf::from("/tmp/checkpoints"))
        );
    }

    #[test]
    fn test_recovery_manager_checkpoint() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let data = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data);

        assert_eq!(manager.checkpoint_count(), 1);
        assert!(manager.latest().is_some());
        assert_eq!(manager.latest().unwrap().sequence, 0);
    }

    #[test]
    fn test_recovery_manager_multiple_checkpoints() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let data1 = CheckpointData::new(run_id, RunStage::Preflight);
        manager.checkpoint(data1);

        let data2 = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data2);

        assert_eq!(manager.checkpoint_count(), 2);
        assert_eq!(manager.latest().unwrap().sequence, 1);

        // Check chain linkage
        assert!(manager.latest().unwrap().previous_id.is_some());
    }

    #[test]
    fn test_recovery_manager_prune_checkpoints() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id).with_max_checkpoints(3);

        // Create 5 checkpoints
        for i in 0..5 {
            let stage = match i % 2 {
                0 => RunStage::Running,
                _ => RunStage::Collecting,
            };
            let data = CheckpointData::new(run_id, stage);
            manager.checkpoint(data);
        }

        // Should only have 3 checkpoints
        assert_eq!(manager.checkpoint_count(), 3);

        // Latest should have sequence 4
        assert_eq!(manager.latest().unwrap().sequence, 4);
    }

    #[test]
    fn test_recovery_manager_recover_no_checkpoint() {
        let run_id = Uuid::new_v4();
        let manager = RunRecoveryManager::new(run_id);

        let result = manager.recover();
        assert_eq!(result, RecoveryResult::NoCheckpoint);
    }

    #[test]
    fn test_recovery_manager_recover_success() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let mut data = CheckpointData::new(run_id, RunStage::Running);
        data.add_agent(AgentCheckpointState::new(
            "agent-1",
            "http://localhost:8080",
        ));
        data.complete_test(Uuid::new_v4());
        data.complete_test(Uuid::new_v4());
        manager.checkpoint(data);

        let result = manager.recover();
        assert!(result.is_success());

        match result {
            RecoveryResult::Recovered {
                preserved_tests,
                restored_agents,
            } => {
                assert_eq!(preserved_tests, 2);
                assert_eq!(restored_agents, 1);
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_recovery_manager_recover_unrecoverable_stage() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        // Completed stage is not resumable
        let data = CheckpointData::new(run_id, RunStage::Completed);
        manager.checkpoint(data);

        let result = manager.recover();
        assert_eq!(result, RecoveryResult::UnrecoverableStage);
    }

    #[test]
    fn test_recovery_manager_recover_from_specific() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let data1 = CheckpointData::new(run_id, RunStage::Preflight);
        manager.checkpoint(data1);

        let data2 = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data2);

        let checkpoint_id = manager.checkpoints[0].id;
        let result = manager.recover_from(checkpoint_id);
        assert!(result.is_success());
    }

    #[test]
    fn test_recovery_manager_needs_checkpoint() {
        let run_id = Uuid::new_v4();
        let mut manager =
            RunRecoveryManager::new(run_id).with_checkpoint_interval(Duration::from_secs(1));

        // Initially needs checkpoint
        assert!(manager.needs_checkpoint());

        // After checkpoint, doesn't need one
        let data = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data);
        assert!(!manager.needs_checkpoint());
    }

    #[test]
    fn test_recovery_manager_get_by_sequence() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let data = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data);

        assert!(manager.get_by_sequence(0).is_some());
        assert!(manager.get_by_sequence(1).is_none());
    }

    #[test]
    fn test_recovery_manager_clear() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let data = CheckpointData::new(run_id, RunStage::Running);
        manager.checkpoint(data);

        manager.clear();

        assert!(manager.latest().is_none());
        assert_eq!(manager.checkpoint_count(), 0);
    }

    // ==================== RecoveryConfig Tests ====================

    #[test]
    fn test_recovery_config_default() {
        let config = RecoveryConfig::default();

        assert!(config.auto_checkpoint);
        assert!(config.checkpoint_on_stage_change);
        assert_eq!(config.checkpoint_every_n_tests, Some(10));
        assert_eq!(config.max_recovery_retries, 3);
    }

    #[test]
    fn test_recovery_config_without_auto_checkpoint() {
        let config = RecoveryConfig::default().without_auto_checkpoint();
        assert!(!config.auto_checkpoint);
    }

    #[test]
    fn test_recovery_config_with_test_interval() {
        let config = RecoveryConfig::default().with_test_interval(5);
        assert_eq!(config.checkpoint_every_n_tests, Some(5));
    }

    #[test]
    fn test_recovery_config_with_max_age() {
        let config = RecoveryConfig::default().with_max_age(Duration::from_secs(7200));
        assert_eq!(config.max_checkpoint_age, Duration::from_secs(7200));
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_manager_roundtrip() {
        let run_id = Uuid::new_v4();
        let mut manager = RunRecoveryManager::new(run_id);

        let mut data = CheckpointData::new(run_id, RunStage::Running);
        data.add_agent(AgentCheckpointState::new(
            "agent-1",
            "http://localhost:8080",
        ));
        manager.checkpoint(data);

        let json = serde_json::to_string(&manager).unwrap();
        let restored: RunRecoveryManager = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.run_id, manager.run_id);
        assert_eq!(restored.checkpoint_count(), manager.checkpoint_count());
    }
}
