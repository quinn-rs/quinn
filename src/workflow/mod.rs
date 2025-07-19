//! Workflow Orchestration System for NAT Traversal
//!
//! This module provides a comprehensive workflow orchestration system that coordinates
//! the complex multi-phase NAT traversal process across distributed components.

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

pub mod definition;
pub mod engine;
pub mod state_store;
pub mod coordinator;
pub mod monitor;

pub use definition::*;
pub use engine::*;
pub use state_store::*;
pub use coordinator::*;
pub use monitor::*;

/// Unique identifier for a workflow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkflowId(pub [u8; 16]);

impl WorkflowId {
    /// Generate a new random workflow ID
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        use rand::Rng;
        rand::thread_rng().fill(&mut id);
        Self(id)
    }
}

impl fmt::Display for WorkflowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Unique identifier for a workflow stage
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StageId(pub String);

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version identifier for workflow definitions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Events that can trigger workflow state transitions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowEvent {
    /// Start the workflow
    Start,
    /// Stage completed successfully
    StageCompleted { stage_id: StageId },
    /// Stage failed with error
    StageFailed { stage_id: StageId, error: String },
    /// External event from another component
    External { event_type: String, data: Vec<u8> },
    /// Timeout occurred
    Timeout { stage_id: StageId },
    /// User-initiated cancellation
    Cancel,
    /// System error
    SystemError { error: String },
}

/// Current status of a workflow instance
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WorkflowStatus {
    /// Workflow is being initialized
    Initializing,
    /// Workflow is actively executing
    Running { current_stage: StageId },
    /// Workflow is waiting for an event
    Waiting { stage: StageId, event: String },
    /// Workflow is paused
    Paused { stage: StageId },
    /// Workflow completed successfully
    Completed { result: WorkflowResult },
    /// Workflow failed
    Failed { error: WorkflowError },
    /// Workflow was cancelled
    Cancelled,
}

/// Result of a successful workflow completion
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowResult {
    /// Final output data
    pub output: HashMap<String, Vec<u8>>,
    /// Execution duration
    pub duration: Duration,
    /// Metrics collected during execution
    pub metrics: WorkflowMetrics,
}

/// Error information for failed workflows
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowError {
    /// Error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Stage where error occurred
    pub stage: Option<StageId>,
    /// Stack trace if available
    pub trace: Option<String>,
    /// Recovery suggestions
    pub recovery_hints: Vec<String>,
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(stage) = &self.stage {
            write!(f, " at stage {}", stage)?;
        }
        Ok(())
    }
}

impl std::error::Error for WorkflowError {}

/// Metrics collected during workflow execution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkflowMetrics {
    /// Total stages executed
    pub stages_executed: u32,
    /// Number of retries
    pub retry_count: u32,
    /// Number of errors encountered
    pub error_count: u32,
    /// Time spent in each stage
    pub stage_durations: HashMap<StageId, Duration>,
    /// Custom metrics
    pub custom: HashMap<String, f64>,
}

/// Handle to interact with a running workflow
#[derive(Debug, Clone)]
pub struct WorkflowHandle {
    /// Workflow ID
    pub id: WorkflowId,
    /// Channel to send events to the workflow
    event_tx: mpsc::Sender<WorkflowEvent>,
    /// Current status
    status: Arc<RwLock<WorkflowStatus>>,
}

impl WorkflowHandle {
    /// Create a new workflow handle
    pub fn new(id: WorkflowId, event_tx: mpsc::Sender<WorkflowEvent>) -> Self {
        Self {
            id,
            event_tx,
            status: Arc::new(RwLock::new(WorkflowStatus::Initializing)),
        }
    }

    /// Send an event to the workflow
    pub async fn send_event(&self, event: WorkflowEvent) -> Result<(), WorkflowError> {
        self.event_tx.send(event).await.map_err(|_| WorkflowError {
            code: "SEND_FAILED".to_string(),
            message: "Failed to send event to workflow".to_string(),
            stage: None,
            trace: None,
            recovery_hints: vec!["Workflow may have terminated".to_string()],
        })
    }

    /// Get the current status of the workflow
    pub async fn status(&self) -> WorkflowStatus {
        self.status.read().await.clone()
    }

    /// Cancel the workflow
    pub async fn cancel(&self) -> Result<(), WorkflowError> {
        self.send_event(WorkflowEvent::Cancel).await
    }

    /// Update the status (internal use)
    pub(crate) async fn update_status(&self, status: WorkflowStatus) {
        *self.status.write().await = status;
    }
}

/// Context provided to workflow actions during execution
#[derive(Debug)]
pub struct WorkflowContext {
    /// Workflow ID
    pub workflow_id: WorkflowId,
    /// Current stage
    pub current_stage: StageId,
    /// Shared state between stages
    pub state: HashMap<String, Vec<u8>>,
    /// Metrics collector
    pub metrics: WorkflowMetrics,
    /// Start time of current stage
    pub stage_start: Instant,
}

impl WorkflowContext {
    /// Store a value in the workflow state
    pub fn set_state(&mut self, key: String, value: Vec<u8>) {
        self.state.insert(key, value);
    }

    /// Retrieve a value from the workflow state
    pub fn get_state(&self, key: &str) -> Option<&Vec<u8>> {
        self.state.get(key)
    }

    /// Record a custom metric
    pub fn record_metric(&mut self, name: String, value: f64) {
        self.metrics.custom.insert(name, value);
    }
}

/// Trait for implementing workflow actions
#[async_trait::async_trait]
pub trait WorkflowAction: Send + Sync {
    /// Execute the action
    async fn execute(&self, context: &mut WorkflowContext) -> Result<(), WorkflowError>;
    
    /// Get the action name for logging
    fn name(&self) -> &str;
}

/// Condition that must be satisfied for stage execution
#[async_trait::async_trait]
pub trait Condition: Send + Sync {
    /// Check if the condition is satisfied
    async fn check(&self, context: &WorkflowContext) -> bool;
    
    /// Get the condition description
    fn description(&self) -> &str;
}

/// Error handler for workflow stages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandler {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Fallback stage on failure
    pub fallback_stage: Option<StageId>,
    /// Whether to propagate the error
    pub propagate: bool,
}

/// Backoff strategy for retries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed { delay: Duration },
    /// Exponential backoff
    Exponential { initial: Duration, max: Duration, factor: f64 },
    /// Linear increase
    Linear { initial: Duration, increment: Duration },
}

impl BackoffStrategy {
    /// Calculate the delay for a given retry attempt
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        match self {
            BackoffStrategy::Fixed { delay } => *delay,
            BackoffStrategy::Exponential { initial, max, factor } => {
                let delay = initial.as_millis() as f64 * factor.powi(attempt as i32);
                let delay_ms = delay.min(max.as_millis() as f64) as u64;
                Duration::from_millis(delay_ms)
            }
            BackoffStrategy::Linear { initial, increment } => {
                *initial + increment.saturating_mul(attempt)
            }
        }
    }
}

/// Rollback strategy for failed stages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackStrategy {
    /// No rollback
    None,
    /// Execute compensating actions
    Compensate { actions: Vec<String> },
    /// Restore from checkpoint
    RestoreCheckpoint { checkpoint_id: String },
    /// Jump to a specific stage
    JumpToStage { stage_id: StageId },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_id_generation() {
        let id1 = WorkflowId::generate();
        let id2 = WorkflowId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_backoff_strategy() {
        let fixed = BackoffStrategy::Fixed { delay: Duration::from_secs(1) };
        assert_eq!(fixed.calculate_delay(0), Duration::from_secs(1));
        assert_eq!(fixed.calculate_delay(5), Duration::from_secs(1));

        let exponential = BackoffStrategy::Exponential {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            factor: 2.0,
        };
        assert_eq!(exponential.calculate_delay(0), Duration::from_millis(100));
        assert_eq!(exponential.calculate_delay(1), Duration::from_millis(200));
        assert_eq!(exponential.calculate_delay(2), Duration::from_millis(400));
    }

    #[test]
    fn test_version_display() {
        let version = Version { major: 1, minor: 2, patch: 3 };
        assert_eq!(version.to_string(), "1.2.3");
    }
}