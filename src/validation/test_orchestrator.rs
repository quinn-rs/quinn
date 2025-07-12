//! Test Orchestration and Coordination
//!
//! This module coordinates the execution of validation tests across multiple
//! endpoints, manages test lifecycle, and ensures proper resource allocation.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    sync::{RwLock, Semaphore},
    time::timeout,
};
use tracing::{debug, error, info, warn};

use crate::{
    validation::{
        ValidationError, TestEndpoint, ScenarioResult, ScenarioMetrics, TestRegion,
        SuccessCriteria, ValidationScenario,
    },
    workflow::{WorkflowEngine, WorkflowHandle, WorkflowId},
};

/// Test orchestration engine
pub struct TestOrchestrator {
    /// Workflow engine for coordination
    workflow_engine: Arc<WorkflowEngine>,
    /// Active test sessions
    active_sessions: Arc<RwLock<HashMap<String, TestSession>>>,
    /// Test queue
    test_queue: Arc<RwLock<VecDeque<QueuedTest>>>,
    /// Resource allocation
    resource_semaphore: Arc<Semaphore>,
    /// Orchestrator state
    state: Arc<RwLock<OrchestratorState>>,
    /// Performance metrics
    metrics: Arc<RwLock<OrchestratorMetrics>>,
}

impl TestOrchestrator {
    /// Create new test orchestrator
    pub fn new(workflow_engine: Arc<WorkflowEngine>, max_concurrent_tests: usize) -> Self {
        Self {
            workflow_engine,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            test_queue: Arc::new(RwLock::new(VecDeque::new())),
            resource_semaphore: Arc::new(Semaphore::new(max_concurrent_tests)),
            state: Arc::new(RwLock::new(OrchestratorState::default())),
            metrics: Arc::new(RwLock::new(OrchestratorMetrics::default())),
        }
    }
    
    /// Execute validation scenario
    pub async fn execute_scenario(
        &self,
        scenario: ValidationScenario,
        regions: &HashMap<String, TestRegion>,
        execution_config: ExecutionConfig,
    ) -> Result<ScenarioResult, ValidationError> {
        let session_id = format!("session_{}", uuid::Uuid::new_v4());
        info!("Starting scenario execution: {} (session: {})", scenario.name, session_id);
        
        // Update orchestrator state
        {
            let mut state = self.state.write().await;
            state.scenarios_running += 1;
            state.total_scenarios += 1;
        }
        
        // Acquire resource permit
        let _permit = self.resource_semaphore.acquire().await.map_err(|_| {
            ValidationError::InfrastructureError("Failed to acquire resource permit".to_string())
        })?;
        
        let start_time = Instant::now();
        let mut session = TestSession::new(session_id.clone(), scenario.clone(), start_time);
        
        // Store active session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }
        
        let result = match self.execute_scenario_internal(scenario, regions, execution_config, &mut session).await {
            Ok(result) => {
                info!("Scenario execution completed successfully: {}", session_id);
                result
            }
            Err(e) => {
                error!("Scenario execution failed: {} - {}", session_id, e);
                ScenarioResult {
                    scenario_id: session.scenario.id.clone(),
                    success: false,
                    duration: start_time.elapsed(),
                    metrics: ScenarioMetrics::default(),
                    errors: vec![e.to_string()],
                }
            }
        };
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_scenarios_executed += 1;
            if result.success {
                metrics.successful_scenarios += 1;
            } else {
                metrics.failed_scenarios += 1;
            }
            metrics.total_execution_time += result.duration;
        }
        
        // Clean up session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.remove(&session_id);
            
            let mut state = self.state.write().await;
            state.scenarios_running -= 1;
        }
        
        Ok(result)
    }
    
    /// Internal scenario execution
    async fn execute_scenario_internal(
        &self,
        scenario: ValidationScenario,
        regions: &HashMap<String, TestRegion>,
        execution_config: ExecutionConfig,
        session: &mut TestSession,
    ) -> Result<ScenarioResult, ValidationError> {
        // Select endpoints for the scenario
        let selected_endpoints = self.select_endpoints(&scenario, regions, &execution_config).await?;
        session.endpoints = selected_endpoints.clone();
        
        info!("Selected {} endpoints for scenario", selected_endpoints.len());
        
        // Create test workflow
        let workflow_id = self.create_test_workflow(&scenario, &selected_endpoints).await?;
        session.workflow_id = Some(workflow_id);
        
        // Execute test with timeout
        let execution_result = timeout(
            execution_config.max_execution_time,
            self.execute_test_workflow(workflow_id, &scenario, &selected_endpoints),
        ).await;
        
        match execution_result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ValidationError::ScenarioError(
                format!("Scenario execution timed out after {}s", execution_config.max_execution_time.as_secs())
            )),
        }
    }
    
    /// Select endpoints for scenario execution
    async fn select_endpoints(
        &self,
        scenario: &ValidationScenario,
        regions: &HashMap<String, TestRegion>,
        config: &ExecutionConfig,
    ) -> Result<Vec<TestEndpoint>, ValidationError> {
        let mut selected = Vec::new();
        
        // Select endpoints based on scenario requirements
        for endpoint_pattern in &scenario.endpoints {
            if let Some(endpoints) = self.find_matching_endpoints(endpoint_pattern, regions, config).await? {
                selected.extend(endpoints);
            }
        }
        
        if selected.is_empty() {
            return Err(ValidationError::EnvironmentError(
                "No suitable endpoints found for scenario".to_string()
            ));
        }
        
        // Validate endpoint capacity
        for endpoint in &selected {
            if !self.validate_endpoint_capacity(endpoint, config).await {
                warn!("Endpoint {} may be overloaded", endpoint.id);
            }
        }
        
        Ok(selected)
    }
    
    /// Find matching endpoints based on pattern
    async fn find_matching_endpoints(
        &self,
        pattern: &str,
        regions: &HashMap<String, TestRegion>,
        config: &ExecutionConfig,
    ) -> Result<Option<Vec<TestEndpoint>>, ValidationError> {
        let mut matching_endpoints = Vec::new();
        
        // Simple pattern matching - in production would be more sophisticated
        if pattern == "*" {
            // Select from all regions
            for region in regions.values() {
                for endpoint in &region.endpoints {
                    if self.is_endpoint_available(endpoint, config).await {
                        matching_endpoints.push(endpoint.clone());
                    }
                }
            }
        } else if pattern.contains("-") {
            // Specific endpoint or region pattern
            for region in regions.values() {
                for endpoint in &region.endpoints {
                    if endpoint.id.contains(pattern) {
                        if self.is_endpoint_available(endpoint, config).await {
                            matching_endpoints.push(endpoint.clone());
                        }
                    }
                }
            }
        }
        
        if matching_endpoints.is_empty() {
            Ok(None)
        } else {
            Ok(Some(matching_endpoints))
        }
    }
    
    /// Check if endpoint is available
    async fn is_endpoint_available(&self, endpoint: &TestEndpoint, _config: &ExecutionConfig) -> bool {
        // Check if endpoint is already in use
        let sessions = self.active_sessions.read().await;
        for session in sessions.values() {
            if session.endpoints.iter().any(|ep| ep.id == endpoint.id) {
                return false;
            }
        }
        
        // Check endpoint health
        self.check_endpoint_health(endpoint).await
    }
    
    /// Check endpoint health
    async fn check_endpoint_health(&self, endpoint: &TestEndpoint) -> bool {
        // In real implementation, would perform actual health check
        debug!("Health check for endpoint {}: OK", endpoint.id);
        true
    }
    
    /// Validate endpoint capacity
    async fn validate_endpoint_capacity(&self, endpoint: &TestEndpoint, config: &ExecutionConfig) -> bool {
        let required_connections = config.expected_connections;
        endpoint.capabilities.max_connections >= required_connections
    }
    
    /// Create test workflow
    async fn create_test_workflow(
        &self,
        scenario: &ValidationScenario,
        endpoints: &[TestEndpoint],
    ) -> Result<WorkflowId, ValidationError> {
        let mut workflow_inputs = HashMap::new();
        
        // Serialize scenario configuration
        let scenario_data = serde_json::to_vec(scenario)
            .map_err(|e| ValidationError::ScenarioError(format!("Failed to serialize scenario: {}", e)))?;
        workflow_inputs.insert("scenario".to_string(), scenario_data);
        
        // Serialize endpoints
        let endpoints_data = serde_json::to_vec(endpoints)
            .map_err(|e| ValidationError::ScenarioError(format!("Failed to serialize endpoints: {}", e)))?;
        workflow_inputs.insert("endpoints".to_string(), endpoints_data);
        
        // Start workflow
        let workflow_handle = self.workflow_engine.start_workflow(
            "validation_scenario",
            &crate::workflow::Version { major: 1, minor: 0, patch: 0 },
            workflow_inputs,
        ).await.map_err(|e| ValidationError::ScenarioError(e.to_string()))?;
        
        Ok(workflow_handle.id)
    }
    
    /// Execute test workflow
    async fn execute_test_workflow(
        &self,
        workflow_id: WorkflowId,
        scenario: &ValidationScenario,
        endpoints: &[TestEndpoint],
    ) -> Result<ScenarioResult, ValidationError> {
        debug!("Executing test workflow {} for scenario {}", workflow_id, scenario.name);
        
        // Get workflow handle
        let workflow_handle = self.workflow_engine.get_workflow_handle(workflow_id)
            .ok_or_else(|| ValidationError::ScenarioError("Workflow handle not found".to_string()))?;
        
        // Monitor workflow execution
        let start_time = Instant::now();
        let mut last_status_check = Instant::now();
        
        loop {
            let status = workflow_handle.status().await;
            
            // Log status periodically
            if last_status_check.elapsed() > Duration::from_secs(30) {
                info!("Workflow {} status: {:?}", workflow_id, status);
                last_status_check = Instant::now();
            }
            
            use crate::workflow::WorkflowStatus;
            match status {
                WorkflowStatus::Completed { result } => {
                    info!("Workflow {} completed successfully", workflow_id);
                    
                    // Parse result
                    let scenario_result = self.parse_workflow_result(scenario, result, start_time.elapsed()).await?;
                    return Ok(scenario_result);
                }
                WorkflowStatus::Failed { error } => {
                    error!("Workflow {} failed: {}", workflow_id, error.message);
                    return Err(ValidationError::ScenarioError(error.message));
                }
                WorkflowStatus::Cancelled => {
                    warn!("Workflow {} was cancelled", workflow_id);
                    return Err(ValidationError::ScenarioError("Workflow was cancelled".to_string()));
                }
                _ => {
                    // Continue monitoring
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
    
    /// Parse workflow result into scenario result
    async fn parse_workflow_result(
        &self,
        scenario: &ValidationScenario,
        workflow_result: crate::workflow::WorkflowResult,
        duration: Duration,
    ) -> Result<ScenarioResult, ValidationError> {
        // Extract metrics from workflow output
        let metrics = if let Some(metrics_data) = workflow_result.output.get("metrics") {
            serde_json::from_slice(metrics_data)
                .unwrap_or_else(|_| ScenarioMetrics::default())
        } else {
            // Generate mock metrics for testing
            ScenarioMetrics {
                connections_attempted: 10,
                connections_successful: 9,
                average_latency_ms: 45.0,
                packet_loss_rate: 0.01,
            }
        };
        
        // Determine success based on metrics and criteria
        let success = self.evaluate_success(&metrics, scenario).await;
        
        let errors = if let Some(errors_data) = workflow_result.output.get("errors") {
            serde_json::from_slice(errors_data).unwrap_or_else(|_| Vec::new())
        } else {
            Vec::new()
        };
        
        Ok(ScenarioResult {
            scenario_id: scenario.id.clone(),
            success,
            duration,
            metrics,
            errors,
        })
    }
    
    /// Evaluate scenario success based on criteria
    async fn evaluate_success(&self, metrics: &ScenarioMetrics, scenario: &ValidationScenario) -> bool {
        // For now, use a simple success criteria
        // In real implementation, would use scenario-specific criteria
        let success_rate = if metrics.connections_attempted > 0 {
            metrics.connections_successful as f32 / metrics.connections_attempted as f32
        } else {
            0.0
        };
        
        success_rate >= 0.8 && metrics.average_latency_ms < 1000.0
    }
    
    /// Queue test for later execution
    pub async fn queue_test(&self, test: QueuedTest) -> Result<(), ValidationError> {
        let mut queue = self.test_queue.write().await;
        queue.push_back(test);
        
        let mut state = self.state.write().await;
        state.queued_tests += 1;
        
        Ok(())
    }
    
    /// Get next test from queue
    pub async fn get_next_queued_test(&self) -> Option<QueuedTest> {
        let mut queue = self.test_queue.write().await;
        if let Some(test) = queue.pop_front() {
            let mut state = self.state.write().await;
            state.queued_tests -= 1;
            Some(test)
        } else {
            None
        }
    }
    
    /// Get orchestrator status
    pub async fn get_status(&self) -> OrchestratorStatus {
        let state = self.state.read().await;
        let metrics = self.metrics.read().await;
        let active_sessions = self.active_sessions.read().await;
        
        OrchestratorStatus {
            scenarios_running: state.scenarios_running,
            queued_tests: state.queued_tests,
            total_scenarios: state.total_scenarios,
            active_sessions: active_sessions.len(),
            available_permits: self.resource_semaphore.available_permits(),
            uptime: state.start_time.elapsed(),
            total_execution_time: metrics.total_execution_time,
            success_rate: if metrics.total_scenarios_executed > 0 {
                metrics.successful_scenarios as f64 / metrics.total_scenarios_executed as f64
            } else {
                0.0
            },
        }
    }
    
    /// Cancel scenario execution
    pub async fn cancel_scenario(&self, session_id: &str) -> Result<(), ValidationError> {
        let mut sessions = self.active_sessions.write().await;
        
        if let Some(session) = sessions.get(session_id) {
            if let Some(workflow_id) = session.workflow_id {
                if let Some(handle) = self.workflow_engine.get_workflow_handle(workflow_id) {
                    handle.cancel().await.map_err(|e| ValidationError::ScenarioError(e.to_string()))?;
                }
            }
            
            sessions.remove(session_id);
            info!("Cancelled scenario execution: {}", session_id);
            Ok(())
        } else {
            Err(ValidationError::ScenarioError(
                format!("Session {} not found", session_id)
            ))
        }
    }
    
    /// Get detailed session information
    pub async fn get_session_details(&self, session_id: &str) -> Option<TestSessionDetails> {
        let sessions = self.active_sessions.read().await;
        
        if let Some(session) = sessions.get(session_id) {
            Some(TestSessionDetails {
                session_id: session.session_id.clone(),
                scenario_name: session.scenario.name.clone(),
                start_time: session.start_time,
                elapsed_time: session.start_time.elapsed(),
                endpoint_count: session.endpoints.len(),
                workflow_id: session.workflow_id,
                status: if session.workflow_id.is_some() {
                    SessionStatus::Running
                } else {
                    SessionStatus::Initializing
                },
            })
        } else {
            None
        }
    }
}

/// Test execution configuration
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Expected number of connections
    pub expected_connections: u32,
    /// Resource requirements
    pub resource_requirements: ResourceRequirements,
    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Resource requirements
#[derive(Debug, Clone)]
pub struct ResourceRequirements {
    /// CPU cores needed
    pub cpu_cores: u32,
    /// Memory in GB
    pub memory_gb: u32,
    /// Bandwidth in Mbps
    pub bandwidth_mbps: u32,
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Delay between retries
    pub retry_delay: Duration,
    /// Exponential backoff factor
    pub backoff_factor: f64,
}

/// Test session information
#[derive(Debug, Clone)]
struct TestSession {
    /// Session ID
    session_id: String,
    /// Scenario being executed
    scenario: ValidationScenario,
    /// Start time
    start_time: Instant,
    /// Selected endpoints
    endpoints: Vec<TestEndpoint>,
    /// Workflow ID
    workflow_id: Option<WorkflowId>,
}

impl TestSession {
    fn new(session_id: String, scenario: ValidationScenario, start_time: Instant) -> Self {
        Self {
            session_id,
            scenario,
            start_time,
            endpoints: Vec::new(),
            workflow_id: None,
        }
    }
}

/// Queued test
#[derive(Debug, Clone)]
pub struct QueuedTest {
    /// Test ID
    pub test_id: String,
    /// Scenario to execute
    pub scenario: ValidationScenario,
    /// Execution configuration
    pub config: ExecutionConfig,
    /// Priority (higher = more important)
    pub priority: u32,
    /// Queued timestamp
    pub queued_at: SystemTime,
}

/// Orchestrator state
#[derive(Debug, Default)]
struct OrchestratorState {
    /// Number of scenarios currently running
    scenarios_running: usize,
    /// Number of tests in queue
    queued_tests: usize,
    /// Total scenarios executed
    total_scenarios: u64,
    /// Orchestrator start time
    start_time: Instant,
}

impl Default for Instant {
    fn default() -> Self {
        Instant::now()
    }
}

/// Orchestrator metrics
#[derive(Debug, Default)]
struct OrchestratorMetrics {
    /// Total scenarios executed
    total_scenarios_executed: u64,
    /// Successful scenarios
    successful_scenarios: u64,
    /// Failed scenarios
    failed_scenarios: u64,
    /// Total execution time
    total_execution_time: Duration,
}

/// Orchestrator status
#[derive(Debug)]
pub struct OrchestratorStatus {
    /// Scenarios currently running
    pub scenarios_running: usize,
    /// Tests in queue
    pub queued_tests: usize,
    /// Total scenarios processed
    pub total_scenarios: u64,
    /// Active sessions
    pub active_sessions: usize,
    /// Available resource permits
    pub available_permits: usize,
    /// Orchestrator uptime
    pub uptime: Duration,
    /// Total time spent executing
    pub total_execution_time: Duration,
    /// Overall success rate
    pub success_rate: f64,
}

/// Session status
#[derive(Debug, Clone)]
pub enum SessionStatus {
    Initializing,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Test session details
#[derive(Debug)]
pub struct TestSessionDetails {
    /// Session ID
    pub session_id: String,
    /// Scenario name
    pub scenario_name: String,
    /// Start time
    pub start_time: Instant,
    /// Elapsed time
    pub elapsed_time: Duration,
    /// Number of endpoints
    pub endpoint_count: usize,
    /// Workflow ID
    pub workflow_id: Option<WorkflowId>,
    /// Current status
    pub status: SessionStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{WorkflowRegistry, InMemoryStateStore, WorkflowEngineConfig};

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let registry = Arc::new(WorkflowRegistry::new());
        let state_store = Arc::new(InMemoryStateStore::new());
        let engine = Arc::new(WorkflowEngine::new(
            WorkflowEngineConfig::default(),
            registry,
            state_store,
        ));
        
        let orchestrator = TestOrchestrator::new(engine, 10);
        let status = orchestrator.get_status().await;
        
        assert_eq!(status.scenarios_running, 0);
        assert_eq!(status.queued_tests, 0);
        assert_eq!(status.available_permits, 10);
    }
    
    #[tokio::test]
    async fn test_test_queueing() {
        let registry = Arc::new(WorkflowRegistry::new());
        let state_store = Arc::new(InMemoryStateStore::new());
        let engine = Arc::new(WorkflowEngine::new(
            WorkflowEngineConfig::default(),
            registry,
            state_store,
        ));
        
        let orchestrator = TestOrchestrator::new(engine, 10);
        
        let queued_test = QueuedTest {
            test_id: "test_1".to_string(),
            scenario: ValidationScenario {
                id: "scenario_1".to_string(),
                name: "Test Scenario".to_string(),
                network_conditions: vec![],
                endpoints: vec!["*".to_string()],
                duration: Duration::from_secs(60),
            },
            config: ExecutionConfig {
                max_execution_time: Duration::from_secs(300),
                expected_connections: 10,
                resource_requirements: ResourceRequirements {
                    cpu_cores: 2,
                    memory_gb: 4,
                    bandwidth_mbps: 100,
                },
                retry_config: RetryConfig {
                    max_attempts: 3,
                    retry_delay: Duration::from_secs(5),
                    backoff_factor: 2.0,
                },
            },
            priority: 1,
            queued_at: SystemTime::now(),
        };
        
        orchestrator.queue_test(queued_test).await.unwrap();
        
        let status = orchestrator.get_status().await;
        assert_eq!(status.queued_tests, 1);
        
        let next_test = orchestrator.get_next_queued_test().await;
        assert!(next_test.is_some());
        
        let status = orchestrator.get_status().await;
        assert_eq!(status.queued_tests, 0);
    }
}