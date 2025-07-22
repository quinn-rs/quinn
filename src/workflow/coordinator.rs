//! Workflow Coordination Protocol
//!
//! This module implements the distributed coordination protocol for workflow
//! execution across multiple nodes in the P2P network.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, RwLock, mpsc},
    time::{interval, timeout},
};
use tracing::{debug, error, info, instrument};

use crate::{
    nat_traversal_api::NatTraversalEndpoint,
    workflow::{StageId, WorkflowError, WorkflowId},
};

// Use String for PeerId in serializable messages
type PeerId = String;

/// Coordination message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinationMessage {
    /// Request to coordinate a workflow
    CoordinationRequest {
        workflow_id: WorkflowId,
        requester: PeerId,
        participants: Vec<PeerId>,
        timeout: Duration,
    },
    /// Accept coordination request
    CoordinationAccept {
        workflow_id: WorkflowId,
        participant: PeerId,
        capabilities: NodeCapabilities,
    },
    /// Reject coordination request
    CoordinationReject {
        workflow_id: WorkflowId,
        participant: PeerId,
        reason: String,
    },
    /// Start workflow execution
    WorkflowStart {
        workflow_id: WorkflowId,
        stage_assignments: HashMap<StageId, PeerId>,
    },
    /// Stage assignment
    StageAssignment {
        workflow_id: WorkflowId,
        stage_id: StageId,
        assigned_to: PeerId,
    },
    /// Stage status update
    StageStatusUpdate {
        workflow_id: WorkflowId,
        stage_id: StageId,
        status: StageStatus,
        metrics: StageMetrics,
    },
    /// Synchronization barrier
    SyncBarrier {
        workflow_id: WorkflowId,
        barrier_id: String,
        participants: Vec<PeerId>,
    },
    /// Barrier ready signal
    BarrierReady {
        workflow_id: WorkflowId,
        barrier_id: String,
        participant: PeerId,
    },
    /// Workflow completion notification
    WorkflowComplete {
        workflow_id: WorkflowId,
        result: WorkflowCoordinationResult,
    },
    /// Heartbeat message
    Heartbeat {
        workflow_id: WorkflowId,
        participant: PeerId,
        timestamp_ms: u64,
    },
    /// Error notification
    ErrorNotification {
        workflow_id: WorkflowId,
        participant: PeerId,
        error: String,
    },
}

/// Node capabilities for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Available CPU cores
    pub cpu_cores: u32,
    /// Available memory in MB
    pub memory_mb: u64,
    /// Network bandwidth in Mbps
    pub bandwidth_mbps: u32,
    /// Supported workflow types
    pub supported_workflows: Vec<String>,
    /// Current load (0-100)
    pub current_load: u8,
}

/// Stage execution status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Metrics for stage execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageMetrics {
    /// Start time in milliseconds since epoch
    pub start_time_ms: Option<u64>,
    /// End time in milliseconds since epoch
    pub end_time_ms: Option<u64>,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage in MB
    pub memory_usage: u64,
    /// Network bytes sent
    pub bytes_sent: u64,
    /// Network bytes received
    pub bytes_received: u64,
}

/// Result of workflow coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCoordinationResult {
    /// Overall success status
    pub success: bool,
    /// Execution duration
    pub duration: Duration,
    /// Stage results
    pub stage_results: HashMap<StageId, StageResult>,
    /// Aggregated metrics
    pub total_metrics: StageMetrics,
}

/// Result of a single stage execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    /// Executing node
    pub executor: PeerId,
    /// Execution status
    pub status: StageStatus,
    /// Stage metrics
    pub metrics: StageMetrics,
    /// Error message if failed
    pub error: Option<String>,
}

/// Workflow coordinator manages distributed workflow execution
pub struct WorkflowCoordinator {
    /// Local peer ID
    local_peer_id: PeerId,
    /// NAT traversal endpoint for communication
    endpoint: Arc<NatTraversalEndpoint>,
    /// Active coordinations
    coordinations: Arc<RwLock<HashMap<WorkflowId, CoordinationSession>>>,
    /// Message handler
    message_handler: Arc<Mutex<mpsc::Receiver<(PeerId, CoordinationMessage)>>>,
    /// Message sender
    message_tx: mpsc::Sender<(PeerId, CoordinationMessage)>,
    /// Node capabilities
    capabilities: NodeCapabilities,
}

impl WorkflowCoordinator {
    /// Create a new workflow coordinator
    pub fn new(
        local_peer_id: PeerId,
        endpoint: Arc<NatTraversalEndpoint>,
        capabilities: NodeCapabilities,
    ) -> Self {
        let (message_tx, message_rx) = mpsc::channel(1000);

        Self {
            local_peer_id,
            endpoint,
            coordinations: Arc::new(RwLock::new(HashMap::new())),
            message_handler: Arc::new(Mutex::new(message_rx)),
            message_tx,
            capabilities,
        }
    }

    /// Start the coordinator
    pub async fn start(&self) -> Result<(), WorkflowError> {
        info!(
            "Starting workflow coordinator for peer {}",
            self.local_peer_id
        );

        // Start message processing loop
        let coordinator = self.clone();
        tokio::spawn(async move {
            coordinator.message_processing_loop().await;
        });

        // Start heartbeat loop
        let coordinator = self.clone();
        tokio::spawn(async move {
            coordinator.heartbeat_loop().await;
        });

        Ok(())
    }

    /// Coordinate a workflow execution
    #[instrument(skip(self))]
    pub async fn coordinate_workflow(
        &self,
        workflow_id: WorkflowId,
        participants: Vec<PeerId>,
        stage_assignments: HashMap<StageId, PeerId>,
        coordination_timeout: Duration,
    ) -> Result<WorkflowCoordinationResult, WorkflowError> {
        info!(
            "Coordinating workflow {} with {} participants",
            workflow_id,
            participants.len()
        );

        // Create coordination session
        let session = CoordinationSession::new(
            workflow_id,
            self.local_peer_id.clone(),
            participants.clone(),
            stage_assignments.clone(),
        );

        // Register session
        {
            let mut coordinations = self.coordinations.write().await;
            coordinations.insert(workflow_id, session);
        }

        // Send coordination requests
        for participant in &participants {
            if participant != &self.local_peer_id {
                self.send_message(
                    participant.clone(),
                    CoordinationMessage::CoordinationRequest {
                        workflow_id,
                        requester: self.local_peer_id.clone(),
                        participants: participants.clone(),
                        timeout: coordination_timeout,
                    },
                )
                .await?;
            }
        }

        // Wait for acceptances with timeout
        let accept_timeout = Duration::from_secs(30);
        let accept_result = timeout(
            accept_timeout,
            self.wait_for_acceptances(workflow_id, &participants),
        )
        .await;

        if accept_result.is_err() {
            self.cleanup_coordination(workflow_id).await;
            return Err(WorkflowError {
                code: "COORDINATION_TIMEOUT".to_string(),
                message: "Timeout waiting for participant acceptances".to_string(),
                stage: None,
                trace: None,
                recovery_hints: vec!["Check network connectivity".to_string()],
            });
        }

        // Start workflow execution
        for participant in &participants {
            self.send_message(
                participant.clone(),
                CoordinationMessage::WorkflowStart {
                    workflow_id,
                    stage_assignments: stage_assignments.clone(),
                },
            )
            .await?;
        }

        // Monitor execution with timeout
        let result = timeout(
            coordination_timeout,
            self.monitor_workflow_execution(workflow_id),
        )
        .await;

        // Clean up
        self.cleanup_coordination(workflow_id).await;

        match result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(WorkflowError {
                code: "WORKFLOW_TIMEOUT".to_string(),
                message: "Workflow execution timed out".to_string(),
                stage: None,
                trace: None,
                recovery_hints: vec!["Increase timeout or optimize workflow".to_string()],
            }),
        }
    }

    /// Join a coordinated workflow as a participant
    pub async fn join_workflow(
        &self,
        workflow_id: WorkflowId,
        coordinator: PeerId,
    ) -> Result<(), WorkflowError> {
        info!(
            "Joining workflow {} coordinated by {}",
            workflow_id, coordinator
        );

        // Send acceptance
        self.send_message(
            coordinator,
            CoordinationMessage::CoordinationAccept {
                workflow_id,
                participant: self.local_peer_id.clone(),
                capabilities: self.capabilities.clone(),
            },
        )
        .await?;

        Ok(())
    }

    /// Update stage status
    pub async fn update_stage_status(
        &self,
        workflow_id: WorkflowId,
        stage_id: StageId,
        status: StageStatus,
        metrics: StageMetrics,
    ) -> Result<(), WorkflowError> {
        // Get coordinator for this workflow
        let coordinator = {
            let coordinations = self.coordinations.read().await;
            coordinations
                .get(&workflow_id)
                .map(|session| session.coordinator.clone())
        };

        if let Some(coordinator) = coordinator {
            self.send_message(
                coordinator,
                CoordinationMessage::StageStatusUpdate {
                    workflow_id,
                    stage_id,
                    status,
                    metrics,
                },
            )
            .await?;
        }

        Ok(())
    }

    /// Signal barrier readiness
    pub async fn signal_barrier_ready(
        &self,
        workflow_id: WorkflowId,
        barrier_id: String,
    ) -> Result<(), WorkflowError> {
        // Get coordinator
        let coordinator = {
            let coordinations = self.coordinations.read().await;
            coordinations
                .get(&workflow_id)
                .map(|session| session.coordinator.clone())
        };

        if let Some(coordinator) = coordinator {
            self.send_message(
                coordinator,
                CoordinationMessage::BarrierReady {
                    workflow_id,
                    barrier_id,
                    participant: self.local_peer_id.clone(),
                },
            )
            .await?;
        }

        Ok(())
    }

    /// Wait for acceptances from participants
    async fn wait_for_acceptances(
        &self,
        workflow_id: WorkflowId,
        participants: &[PeerId],
    ) -> Result<(), WorkflowError> {
        let expected_count = participants.len() - 1; // Excluding self
        let mut accepted_count = 0;

        let start_time = Instant::now();
        let check_interval = Duration::from_millis(100);

        loop {
            let coordinations = self.coordinations.read().await;
            if let Some(session) = coordinations.get(&workflow_id) {
                accepted_count = session.accepted_participants.len();
                if accepted_count >= expected_count {
                    return Ok(());
                }
            }
            drop(coordinations);

            if start_time.elapsed() > Duration::from_secs(30) {
                return Err(WorkflowError {
                    code: "ACCEPTANCE_TIMEOUT".to_string(),
                    message: format!(
                        "Only {}/{} participants accepted",
                        accepted_count, expected_count
                    ),
                    stage: None,
                    trace: None,
                    recovery_hints: vec!["Check participant availability".to_string()],
                });
            }

            tokio::time::sleep(check_interval).await;
        }
    }

    /// Monitor workflow execution
    async fn monitor_workflow_execution(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<WorkflowCoordinationResult, WorkflowError> {
        let start_time = Instant::now();

        loop {
            let coordinations = self.coordinations.read().await;
            if let Some(session) = coordinations.get(&workflow_id) {
                // Check if all stages are complete
                let all_complete = session.stage_status.iter().all(|(_, status)| {
                    matches!(status.status, StageStatus::Completed | StageStatus::Failed)
                });

                if all_complete {
                    // Calculate result
                    let success = session
                        .stage_status
                        .iter()
                        .all(|(_, status)| status.status == StageStatus::Completed);

                    let total_metrics = self.aggregate_metrics(&session.stage_status);

                    return Ok(WorkflowCoordinationResult {
                        success,
                        duration: start_time.elapsed(),
                        stage_results: session.stage_status.clone(),
                        total_metrics,
                    });
                }
            }
            drop(coordinations);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Aggregate metrics from all stages
    fn aggregate_metrics(&self, stage_results: &HashMap<StageId, StageResult>) -> StageMetrics {
        let mut total = StageMetrics {
            start_time_ms: None,
            end_time_ms: None,
            cpu_usage: 0.0,
            memory_usage: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };

        let mut cpu_sum = 0.0;
        let mut cpu_count = 0;

        for (_, result) in stage_results {
            if let Some(start) = result.metrics.start_time_ms {
                total.start_time_ms = Some(total.start_time_ms.map_or(start, |t| t.min(start)));
            }
            if let Some(end) = result.metrics.end_time_ms {
                total.end_time_ms = Some(total.end_time_ms.map_or(end, |t| t.max(end)));
            }

            cpu_sum += result.metrics.cpu_usage;
            cpu_count += 1;

            total.memory_usage = total.memory_usage.max(result.metrics.memory_usage);
            total.bytes_sent += result.metrics.bytes_sent;
            total.bytes_received += result.metrics.bytes_received;
        }

        if cpu_count > 0 {
            total.cpu_usage = cpu_sum / cpu_count as f32;
        }

        total
    }

    /// Clean up coordination session
    async fn cleanup_coordination(&self, workflow_id: WorkflowId) {
        let mut coordinations = self.coordinations.write().await;
        coordinations.remove(&workflow_id);
        debug!(
            "Cleaned up coordination session for workflow {}",
            workflow_id
        );
    }

    /// Send a coordination message
    async fn send_message(
        &self,
        peer: PeerId,
        message: CoordinationMessage,
    ) -> Result<(), WorkflowError> {
        // In a real implementation, this would use the NAT traversal endpoint
        // to send the message over the network
        debug!("Sending {:?} to peer {}", message, peer);

        // For now, just put it in our own queue if it's for us
        if peer == self.local_peer_id {
            self.message_tx
                .send((self.local_peer_id.clone(), message))
                .await
                .map_err(|_| WorkflowError {
                    code: "SEND_ERROR".to_string(),
                    message: "Failed to send message".to_string(),
                    stage: None,
                    trace: None,
                    recovery_hints: vec![],
                })?;
        }

        Ok(())
    }

    /// Message processing loop
    async fn message_processing_loop(&self) {
        let mut receiver = self.message_handler.lock().await;

        while let Some((sender, message)) = receiver.recv().await {
            if let Err(e) = self.handle_message(sender, message).await {
                error!("Error handling coordination message: {:?}", e);
            }
        }
    }

    /// Handle incoming coordination message
    async fn handle_message(
        &self,
        sender: PeerId,
        message: CoordinationMessage,
    ) -> Result<(), WorkflowError> {
        match message {
            CoordinationMessage::CoordinationRequest {
                workflow_id,
                requester,
                participants: _,
                timeout: _,
            } => {
                // Automatically accept for now
                self.join_workflow(workflow_id, requester).await?;
            }
            CoordinationMessage::CoordinationAccept {
                workflow_id,
                participant,
                capabilities,
            } => {
                let mut coordinations = self.coordinations.write().await;
                if let Some(session) = coordinations.get_mut(&workflow_id) {
                    session.accepted_participants.insert(participant.clone());
                    session
                        .participant_capabilities
                        .insert(participant, capabilities);
                }
            }
            CoordinationMessage::StageStatusUpdate {
                workflow_id,
                stage_id,
                status,
                metrics,
            } => {
                let mut coordinations = self.coordinations.write().await;
                if let Some(session) = coordinations.get_mut(&workflow_id) {
                    session.stage_status.insert(
                        stage_id,
                        StageResult {
                            executor: sender,
                            status,
                            metrics,
                            error: None,
                        },
                    );
                }
            }
            CoordinationMessage::BarrierReady {
                workflow_id,
                barrier_id,
                participant,
            } => {
                let mut coordinations = self.coordinations.write().await;
                if let Some(session) = coordinations.get_mut(&workflow_id) {
                    session
                        .barrier_ready
                        .entry(barrier_id)
                        .or_insert_with(HashSet::new)
                        .insert(participant);
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Heartbeat loop
    async fn heartbeat_loop(&self) {
        let mut interval = interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            let coordinations = self.coordinations.read().await;
            for (workflow_id, session) in coordinations.iter() {
                if session.coordinator != self.local_peer_id {
                    // Send heartbeat to coordinator
                    let _ = self
                        .send_message(
                            session.coordinator.clone(),
                            CoordinationMessage::Heartbeat {
                                workflow_id: *workflow_id,
                                participant: self.local_peer_id.clone(),
                                timestamp_ms: Instant::now().elapsed().as_millis() as u64,
                            },
                        )
                        .await;
                }
            }
        }
    }
}

impl Clone for WorkflowCoordinator {
    fn clone(&self) -> Self {
        Self {
            local_peer_id: self.local_peer_id.clone(),
            endpoint: self.endpoint.clone(),
            coordinations: self.coordinations.clone(),
            message_handler: self.message_handler.clone(),
            message_tx: self.message_tx.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
}

/// Coordination session for a workflow
struct CoordinationSession {
    /// Workflow ID
    workflow_id: WorkflowId,
    /// Coordinator peer
    coordinator: PeerId,
    /// All participants
    participants: Vec<PeerId>,
    /// Accepted participants
    accepted_participants: HashSet<PeerId>,
    /// Participant capabilities
    participant_capabilities: HashMap<PeerId, NodeCapabilities>,
    /// Stage assignments
    stage_assignments: HashMap<StageId, PeerId>,
    /// Stage execution status
    stage_status: HashMap<StageId, StageResult>,
    /// Barrier synchronization state
    barrier_ready: HashMap<String, HashSet<PeerId>>,
    /// Session start time
    start_time: Instant,
}

impl CoordinationSession {
    fn new(
        workflow_id: WorkflowId,
        coordinator: PeerId,
        participants: Vec<PeerId>,
        stage_assignments: HashMap<StageId, PeerId>,
    ) -> Self {
        Self {
            workflow_id,
            coordinator,
            participants,
            accepted_participants: HashSet::new(),
            participant_capabilities: HashMap::new(),
            stage_assignments,
            stage_status: HashMap::new(),
            barrier_ready: HashMap::new(),
            start_time: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_coordinator() {
        let peer_id = "test_peer_id".to_string();

        // Create a config with bootstrap nodes for client role
        let mut config = crate::nat_traversal_api::NatTraversalConfig::default();
        config
            .bootstrap_nodes
            .push("127.0.0.1:9000".parse().unwrap());

        let endpoint = Arc::new(NatTraversalEndpoint::new(config, None).await.unwrap());

        let capabilities = NodeCapabilities {
            cpu_cores: 4,
            memory_mb: 8192,
            bandwidth_mbps: 100,
            supported_workflows: vec!["test_workflow".to_string()],
            current_load: 20,
        };

        let coordinator = WorkflowCoordinator::new(peer_id.clone(), endpoint, capabilities);
        coordinator.start().await.unwrap();

        // Test basic coordination
        let workflow_id = WorkflowId::generate();
        let participants = vec![peer_id.clone()];
        let stage_assignments = HashMap::new();

        let result = coordinator
            .coordinate_workflow(
                workflow_id,
                participants,
                stage_assignments,
                Duration::from_secs(60),
            )
            .await;

        // Should succeed with single participant (self)
        assert!(result.is_ok());
    }
}
