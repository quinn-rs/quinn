//! Workflow Execution Engine
//!
//! This module implements the core workflow execution engine that processes
//! workflow definitions, manages state transitions, and coordinates actions.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, RwLock, Mutex},
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn, instrument, span, Level};

use crate::workflow::{
    RollbackStrategy, StageId, Version,
    WorkflowContext, WorkflowDefinition, WorkflowError, WorkflowEvent,
    WorkflowHandle, WorkflowId, WorkflowMetrics, WorkflowResult, WorkflowStage,
    WorkflowStatus, WorkflowRegistry, StateStore,
};

/// Configuration for the workflow engine
#[derive(Debug, Clone)]
pub struct WorkflowEngineConfig {
    /// Maximum concurrent workflows
    pub max_concurrent_workflows: usize,
    /// Default timeout for workflow operations
    pub default_timeout: Duration,
    /// Enable detailed tracing
    pub enable_tracing: bool,
    /// State checkpoint interval
    pub checkpoint_interval: Duration,
    /// Maximum retry attempts for system errors
    pub max_system_retries: u32,
    /// Worker thread count
    pub worker_count: usize,
}

impl Default for WorkflowEngineConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: 1000,
            default_timeout: Duration::from_secs(300),
            enable_tracing: true,
            checkpoint_interval: Duration::from_secs(10),
            max_system_retries: 3,
            worker_count: 4,
        }
    }
}

/// Workflow execution engine
pub struct WorkflowEngine {
    /// Engine configuration
    config: WorkflowEngineConfig,
    /// Workflow registry
    registry: Arc<WorkflowRegistry>,
    /// State store for persistence
    state_store: Arc<dyn StateStore>,
    /// Active workflow executors
    executors: Arc<RwLock<HashMap<WorkflowId, WorkflowExecutor>>>,
    /// Event queue for workflow events
    event_queue: Arc<Mutex<VecDeque<(WorkflowId, WorkflowEvent)>>>,
    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl WorkflowEngine {
    /// Create a new workflow engine
    pub fn new(
        config: WorkflowEngineConfig,
        registry: Arc<WorkflowRegistry>,
        state_store: Arc<dyn StateStore>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        
        Self {
            config,
            registry,
            state_store,
            executors: Arc::new(RwLock::new(HashMap::new())),
            event_queue: Arc::new(Mutex::new(VecDeque::new())),
            shutdown_tx,
            shutdown_rx: Arc::new(Mutex::new(shutdown_rx)),
        }
    }

    /// Start the workflow engine
    pub async fn start(&self) -> Result<(), WorkflowError> {
        info!("Starting workflow engine with {} workers", self.config.worker_count);
        
        // Start worker tasks
        for worker_id in 0..self.config.worker_count {
            let engine = self.clone();
            tokio::spawn(async move {
                engine.worker_loop(worker_id).await;
            });
        }
        
        // Start checkpoint task
        let engine = self.clone();
        tokio::spawn(async move {
            engine.checkpoint_loop().await;
        });
        
        Ok(())
    }

    /// Stop the workflow engine
    pub async fn stop(&self) -> Result<(), WorkflowError> {
        info!("Stopping workflow engine");
        
        // Send shutdown signal
        let _ = self.shutdown_tx.send(()).await;
        
        // Wait for all workflows to complete or timeout
        let timeout_duration = Duration::from_secs(30);
        let start = Instant::now();
        
        loop {
            let executors = self.executors.read().await;
            if executors.is_empty() {
                break;
            }
            
            if start.elapsed() > timeout_duration {
                warn!("Timeout waiting for workflows to complete");
                break;
            }
            
            drop(executors);
            sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }

    /// Start a new workflow
    #[instrument(skip(self, input))]
    pub async fn start_workflow(
        &self,
        workflow_id: &str,
        version: &Version,
        input: HashMap<String, Vec<u8>>,
    ) -> Result<WorkflowHandle, WorkflowError> {
        // Get workflow definition
        let definition = self.registry.get(workflow_id, version).await
            .ok_or_else(|| WorkflowError {
                code: "WORKFLOW_NOT_FOUND".to_string(),
                message: format!("Workflow {} version {} not found", workflow_id, version),
                stage: None,
                trace: None,
                recovery_hints: vec!["Check workflow ID and version".to_string()],
            })?;
        
        // Check concurrent workflow limit
        let executors = self.executors.read().await;
        if executors.len() >= self.config.max_concurrent_workflows {
            return Err(WorkflowError {
                code: "MAX_WORKFLOWS_REACHED".to_string(),
                message: "Maximum concurrent workflows reached".to_string(),
                stage: None,
                trace: None,
                recovery_hints: vec!["Wait for existing workflows to complete".to_string()],
            });
        }
        drop(executors);
        
        // Generate workflow instance ID
        let instance_id = WorkflowId::generate();
        
        // Create workflow executor
        let (event_tx, event_rx) = mpsc::channel(100);
        let handle = WorkflowHandle::new(instance_id, event_tx);
        
        let executor = WorkflowExecutor::new(
            instance_id,
            definition,
            input,
            event_rx,
            handle.clone(),
            self.state_store.clone(),
            self.config.clone(),
        );
        
        // Register executor
        let mut executors = self.executors.write().await;
        executors.insert(instance_id, executor);
        
        // Start workflow
        self.event_queue.lock().await.push_back((instance_id, WorkflowEvent::Start));
        
        info!("Started workflow {} instance {}", workflow_id, instance_id);
        Ok(handle)
    }

    /// Resume a workflow from saved state
    pub async fn resume_workflow(
        &self,
        instance_id: WorkflowId,
    ) -> Result<WorkflowHandle, WorkflowError> {
        // Load state from store
        let state = self.state_store.load(&instance_id).await?;
        
        // Get workflow definition
        let definition = self.registry.get(&state.workflow_id, &state.version).await
            .ok_or_else(|| WorkflowError {
                code: "WORKFLOW_NOT_FOUND".to_string(),
                message: format!("Workflow {} version {} not found", state.workflow_id, state.version),
                stage: None,
                trace: None,
                recovery_hints: vec!["Check workflow ID and version".to_string()],
            })?;
        
        // Create workflow executor
        let (event_tx, event_rx) = mpsc::channel(100);
        let handle = WorkflowHandle::new(instance_id, event_tx);
        
        let mut executor = WorkflowExecutor::new(
            instance_id,
            definition,
            state.input.clone(),
            event_rx,
            handle.clone(),
            self.state_store.clone(),
            self.config.clone(),
        );
        
        // Restore executor state
        executor.restore_state(state).await?;
        
        // Register executor
        let mut executors = self.executors.write().await;
        executors.insert(instance_id, executor);
        
        info!("Resumed workflow instance {}", instance_id);
        Ok(handle)
    }

    /// Worker loop for processing workflow events
    async fn worker_loop(&self, worker_id: usize) {
        let span = span!(Level::DEBUG, "workflow_worker", worker_id = worker_id);
        let _enter = span.enter();
        
        debug!("Worker {} started", worker_id);
        
        loop {
            // Check for shutdown
            if self.shutdown_rx.lock().await.try_recv().is_ok() {
                debug!("Worker {} shutting down", worker_id);
                break;
            }
            
            // Get next event
            let event = {
                let mut queue = self.event_queue.lock().await;
                queue.pop_front()
            };
            
            if let Some((workflow_id, event)) = event {
                // Process event
                if let Err(e) = self.process_event(workflow_id, event).await {
                    error!("Error processing event for workflow {}: {:?}", workflow_id, e);
                }
            } else {
                // No events, sleep briefly
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    /// Process a workflow event
    async fn process_event(
        &self,
        workflow_id: WorkflowId,
        event: WorkflowEvent,
    ) -> Result<(), WorkflowError> {
        let mut executors = self.executors.write().await;
        
        if let Some(executor) = executors.get_mut(&workflow_id) {
            // Process event in executor
            executor.process_event(event).await?;
            
            // Check if workflow is complete
            let status = executor.handle.status().await;
            match status {
                WorkflowStatus::Completed { .. } | 
                WorkflowStatus::Failed { .. } | 
                WorkflowStatus::Cancelled => {
                    // Remove completed workflow
                    executors.remove(&workflow_id);
                    info!("Workflow {} completed with status: {:?}", workflow_id, status);
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Checkpoint loop for saving workflow state
    async fn checkpoint_loop(&self) {
        let mut interval = tokio::time::interval(self.config.checkpoint_interval);
        
        loop {
            interval.tick().await;
            
            // Check for shutdown
            if self.shutdown_rx.lock().await.try_recv().is_ok() {
                break;
            }
            
            // Checkpoint all active workflows
            let executors = self.executors.read().await;
            for (id, executor) in executors.iter() {
                if let Err(e) = executor.checkpoint().await {
                    error!("Failed to checkpoint workflow {}: {:?}", id, e);
                }
            }
        }
    }
}

impl Clone for WorkflowEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            registry: self.registry.clone(),
            state_store: self.state_store.clone(),
            executors: self.executors.clone(),
            event_queue: self.event_queue.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}

/// Workflow executor manages execution of a single workflow instance
struct WorkflowExecutor {
    /// Workflow instance ID
    id: WorkflowId,
    /// Workflow definition
    definition: WorkflowDefinition,
    /// Workflow context
    context: WorkflowContext,
    /// Event receiver
    event_rx: mpsc::Receiver<WorkflowEvent>,
    /// Workflow handle
    handle: WorkflowHandle,
    /// State store
    state_store: Arc<dyn StateStore>,
    /// Engine configuration
    config: WorkflowEngineConfig,
    /// Current retry attempts per stage
    retry_attempts: HashMap<StageId, u32>,
    /// Workflow start time
    start_time: Instant,
    /// Last checkpoint time
    last_checkpoint: Instant,
}

impl WorkflowExecutor {
    /// Create a new workflow executor
    fn new(
        id: WorkflowId,
        definition: WorkflowDefinition,
        input: HashMap<String, Vec<u8>>,
        event_rx: mpsc::Receiver<WorkflowEvent>,
        handle: WorkflowHandle,
        state_store: Arc<dyn StateStore>,
        config: WorkflowEngineConfig,
    ) -> Self {
        let context = WorkflowContext {
            workflow_id: id,
            current_stage: definition.initial_stage.clone(),
            state: input,
            metrics: WorkflowMetrics::default(),
            stage_start: Instant::now(),
        };
        
        Self {
            id,
            definition,
            context,
            event_rx,
            handle,
            state_store,
            config,
            retry_attempts: HashMap::new(),
            start_time: Instant::now(),
            last_checkpoint: Instant::now(),
        }
    }

    /// Process a workflow event
    async fn process_event(&mut self, event: WorkflowEvent) -> Result<(), WorkflowError> {
        debug!("Processing event {:?} for workflow {}", event, self.id);
        
        match event {
            WorkflowEvent::Start => {
                self.handle.update_status(WorkflowStatus::Running {
                    current_stage: self.definition.initial_stage.clone(),
                }).await;
                self.execute_stage(self.definition.initial_stage.clone()).await?;
            }
            WorkflowEvent::StageCompleted { stage_id } => {
                self.handle_stage_completion(stage_id).await?;
            }
            WorkflowEvent::StageFailed { stage_id, error } => {
                self.handle_stage_failure(stage_id, error).await?;
            }
            WorkflowEvent::Timeout { stage_id } => {
                self.handle_stage_timeout(stage_id).await?;
            }
            WorkflowEvent::Cancel => {
                self.handle_cancellation().await?;
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Execute a workflow stage
    async fn execute_stage(&mut self, stage_id: StageId) -> Result<(), WorkflowError> {
        info!("Executing stage {} for workflow {}", stage_id, self.id);
        
        // Find stage definition
        let stage = self.definition.stages.iter()
            .find(|s| s.id == stage_id)
            .ok_or_else(|| WorkflowError {
                code: "STAGE_NOT_FOUND".to_string(),
                message: format!("Stage {} not found", stage_id),
                stage: Some(stage_id.clone()),
                trace: None,
                recovery_hints: vec![],
            })?
            .clone();
        
        // Update context
        self.context.current_stage = stage_id.clone();
        self.context.stage_start = Instant::now();
        
        // Check preconditions
        if !self.check_preconditions(&stage).await? {
            return Err(WorkflowError {
                code: "PRECONDITION_FAILED".to_string(),
                message: format!("Preconditions not met for stage {}", stage_id),
                stage: Some(stage_id),
                trace: None,
                recovery_hints: vec!["Check stage preconditions".to_string()],
            });
        }
        
        // Get stage timeout
        let stage_timeout = stage.max_duration
            .or_else(|| self.definition.timeouts.get(&stage_id).cloned())
            .unwrap_or(self.config.default_timeout);
        
        // Execute stage with timeout
        let result = timeout(stage_timeout, self.execute_stage_actions(&stage)).await;
        
        match result {
            Ok(Ok(())) => {
                // Check postconditions
                if self.check_postconditions(&stage).await? {
                    self.handle.send_event(WorkflowEvent::StageCompleted {
                        stage_id: stage_id.clone(),
                    }).await?;
                } else {
                    self.handle.send_event(WorkflowEvent::StageFailed {
                        stage_id: stage_id.clone(),
                        error: "Postconditions not met".to_string(),
                    }).await?;
                }
            }
            Ok(Err(e)) => {
                self.handle.send_event(WorkflowEvent::StageFailed {
                    stage_id: stage_id.clone(),
                    error: e.message.clone(),
                }).await?;
            }
            Err(_) => {
                self.handle.send_event(WorkflowEvent::Timeout {
                    stage_id: stage_id.clone(),
                }).await?;
            }
        }
        
        Ok(())
    }

    /// Execute actions for a stage
    async fn execute_stage_actions(&mut self, stage: &WorkflowStage) -> Result<(), WorkflowError> {
        // Execute each action in sequence
        for (i, action) in stage.actions.iter().enumerate() {
            debug!("Executing action {} for stage {}", i, stage.id);
            
            // Execute action
            action.execute(&mut self.context).await?;
            
            // Update metrics
            self.context.metrics.stages_executed += 1;
        }
        
        // Record stage duration
        let duration = self.context.stage_start.elapsed();
        self.context.metrics.stage_durations.insert(stage.id.clone(), duration);
        
        Ok(())
    }

    /// Check preconditions for a stage
    async fn check_preconditions(&self, stage: &WorkflowStage) -> Result<bool, WorkflowError> {
        for condition in &stage.preconditions {
            if !condition.check(&self.context).await {
                debug!("Precondition {} failed for stage {}", condition.description(), stage.id);
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check postconditions for a stage
    async fn check_postconditions(&self, stage: &WorkflowStage) -> Result<bool, WorkflowError> {
        for condition in &stage.postconditions {
            if !condition.check(&self.context).await {
                debug!("Postcondition {} failed for stage {}", condition.description(), stage.id);
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Handle stage completion
    async fn handle_stage_completion(&mut self, stage_id: StageId) -> Result<(), WorkflowError> {
        info!("Stage {} completed for workflow {}", stage_id, self.id);
        
        // Reset retry counter
        self.retry_attempts.remove(&stage_id);
        
        // Check if this is a final stage
        if self.definition.final_stages.contains(&stage_id) {
            self.complete_workflow().await?;
            return Ok(());
        }
        
        // Find next stage
        let event = WorkflowEvent::StageCompleted { stage_id: stage_id.clone() };
        if let Some(next_stage) = self.definition.transitions.get(&(stage_id, event)) {
            self.execute_stage(next_stage.clone()).await?;
        } else {
            // No transition defined, workflow complete
            self.complete_workflow().await?;
        }
        
        Ok(())
    }

    /// Handle stage failure
    async fn handle_stage_failure(&mut self, stage_id: StageId, error: String) -> Result<(), WorkflowError> {
        warn!("Stage {} failed for workflow {}: {}", stage_id, self.id, error);
        
        // Update metrics
        self.context.metrics.error_count += 1;
        
        // Get error handler
        if let Some(handler) = self.definition.error_handlers.get(&stage_id) {
            // Check retry count
            let attempts = self.retry_attempts.entry(stage_id.clone()).or_insert(0);
            *attempts += 1;
            
            if *attempts <= handler.max_retries {
                // Calculate backoff delay
                let delay = handler.backoff.calculate_delay(*attempts - 1);
                info!("Retrying stage {} after {:?} (attempt {}/{})", 
                      stage_id, delay, attempts, handler.max_retries);
                
                // Wait before retry
                sleep(delay).await;
                
                // Update metrics
                self.context.metrics.retry_count += 1;
                
                // Retry stage
                self.execute_stage(stage_id).await?;
            } else if let Some(fallback) = &handler.fallback_stage {
                // Max retries exceeded, go to fallback
                info!("Max retries exceeded for stage {}, going to fallback {}", stage_id, fallback);
                self.execute_stage(fallback.clone()).await?;
            } else if handler.propagate {
                // Propagate error
                self.fail_workflow(WorkflowError {
                    code: "STAGE_FAILED".to_string(),
                    message: error,
                    stage: Some(stage_id),
                    trace: None,
                    recovery_hints: vec![],
                }).await?;
            } else {
                // Handle rollback if defined
                if let Some(stage) = self.definition.stages.iter().find(|s| s.id == stage_id) {
                    if let Some(rollback) = &stage.rollback {
                        self.execute_rollback(rollback.clone(), stage_id).await?;
                    }
                }
            }
        } else {
            // No error handler, fail workflow
            self.fail_workflow(WorkflowError {
                code: "STAGE_FAILED".to_string(),
                message: error,
                stage: Some(stage_id),
                trace: None,
                recovery_hints: vec![],
            }).await?;
        }
        
        Ok(())
    }

    /// Handle stage timeout
    async fn handle_stage_timeout(&mut self, stage_id: StageId) -> Result<(), WorkflowError> {
        warn!("Stage {} timed out for workflow {}", stage_id, self.id);
        
        // Treat as failure
        self.handle_stage_failure(stage_id, "Stage execution timed out".to_string()).await
    }

    /// Execute rollback strategy
    async fn execute_rollback(&mut self, strategy: RollbackStrategy, failed_stage: StageId) -> Result<(), WorkflowError> {
        info!("Executing rollback for stage {} in workflow {}", failed_stage, self.id);
        
        match strategy {
            RollbackStrategy::None => Ok(()),
            RollbackStrategy::Compensate { actions } => {
                // Execute compensating actions
                for action_name in actions {
                    debug!("Executing compensating action: {}", action_name);
                    // In a real implementation, we would look up and execute the action
                }
                Ok(())
            }
            RollbackStrategy::RestoreCheckpoint { checkpoint_id } => {
                // Restore from checkpoint
                debug!("Restoring from checkpoint: {}", checkpoint_id);
                // In a real implementation, we would restore state
                Ok(())
            }
            RollbackStrategy::JumpToStage { stage_id } => {
                // Jump to specified stage
                self.execute_stage(stage_id).await
            }
        }
    }

    /// Handle workflow cancellation
    async fn handle_cancellation(&mut self) -> Result<(), WorkflowError> {
        info!("Workflow {} cancelled", self.id);
        
        self.handle.update_status(WorkflowStatus::Cancelled).await;
        
        // Execute cleanup if needed
        // TODO: Add cleanup logic
        
        Ok(())
    }

    /// Complete the workflow successfully
    async fn complete_workflow(&mut self) -> Result<(), WorkflowError> {
        let duration = self.start_time.elapsed();
        
        info!("Workflow {} completed successfully in {:?}", self.id, duration);
        
        let result = WorkflowResult {
            output: self.context.state.clone(),
            duration,
            metrics: self.context.metrics.clone(),
        };
        
        self.handle.update_status(WorkflowStatus::Completed { result }).await;
        
        // Save final state
        self.checkpoint().await?;
        
        Ok(())
    }

    /// Fail the workflow
    async fn fail_workflow(&mut self, error: WorkflowError) -> Result<(), WorkflowError> {
        error!("Workflow {} failed: {:?}", self.id, error);
        
        self.handle.update_status(WorkflowStatus::Failed { error: error.clone() }).await;
        
        // Save final state
        self.checkpoint().await?;
        
        Ok(())
    }

    /// Checkpoint workflow state
    async fn checkpoint(&self) -> Result<(), WorkflowError> {
        debug!("Checkpointing workflow {}", self.id);
        
        // Save state to store
        // TODO: Implement state serialization
        
        Ok(())
    }

    /// Restore workflow state
    async fn restore_state(&mut self, _state: crate::workflow::WorkflowState) -> Result<(), WorkflowError> {
        // TODO: Implement state restoration
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{WorkflowTemplates, InMemoryStateStore};

    #[tokio::test]
    async fn test_workflow_engine_basic() {
        let registry = Arc::new(WorkflowRegistry::new());
        registry.load_defaults().await.unwrap();
        
        let state_store = Arc::new(InMemoryStateStore::new());
        let engine = WorkflowEngine::new(
            WorkflowEngineConfig::default(),
            registry,
            state_store,
        );
        
        engine.start().await.unwrap();
        
        let handle = engine.start_workflow(
            "nat_traversal_basic",
            &Version { major: 1, minor: 0, patch: 0 },
            HashMap::new(),
        ).await.unwrap();
        
        assert_eq!(handle.status().await, WorkflowStatus::Initializing);
        
        engine.stop().await.unwrap();
    }
}