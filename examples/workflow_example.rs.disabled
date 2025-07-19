//! Example demonstrating the workflow orchestration system
//!
//! This example shows how to use the workflow engine to orchestrate
//! NAT traversal operations in a structured, fault-tolerant manner.

use std::{collections::HashMap, sync::Arc, time::Duration};

use ant_quic::workflow::{
    BackoffStrategy, Condition, ErrorHandler, InMemoryStateStore, LoggingAlertHandler,
    MonitoringConfig, RollbackStrategy, StageId, Version, WorkflowAction, WorkflowContext,
    WorkflowDefinitionBuilder, WorkflowEngine, WorkflowEngineConfig, WorkflowError,
    WorkflowMonitor, WorkflowRegistry, WorkflowStage, WorkflowTemplates,
};
use tokio;
use tracing::{error, info};

/// Example action that simulates candidate discovery
struct DiscoverCandidatesAction;

#[async_trait::async_trait]
impl WorkflowAction for DiscoverCandidatesAction {
    async fn execute(&self, context: &mut WorkflowContext) -> Result<(), WorkflowError> {
        info!(
            "Discovering NAT traversal candidates for workflow {}",
            context.workflow_id
        );

        // Simulate candidate discovery
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Store some fake candidates in context
        context.set_state(
            "candidates".to_string(),
            b"192.168.1.100:5000,10.0.0.5:6000".to_vec(),
        );

        // Record a metric
        context.record_metric("candidates_discovered".to_string(), 2.0);

        Ok(())
    }

    fn name(&self) -> &str {
        "discover_candidates"
    }
}

/// Example action that simulates hole punching
struct HolePunchingAction;

#[async_trait::async_trait]
impl WorkflowAction for HolePunchingAction {
    async fn execute(&self, context: &mut WorkflowContext) -> Result<(), WorkflowError> {
        info!(
            "Executing hole punching for workflow {}",
            context.workflow_id
        );

        // Get candidates from context
        let candidates = context
            .get_state("candidates")
            .ok_or_else(|| WorkflowError {
                code: "NO_CANDIDATES".to_string(),
                message: "No candidates found in context".to_string(),
                stage: Some(context.current_stage.clone()),
                trace: None,
                recovery_hints: vec!["Run candidate discovery first".to_string()],
            })?;

        info!(
            "Using candidates: {:?}",
            String::from_utf8_lossy(candidates)
        );

        // Simulate hole punching
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 80% success rate simulation
        if rand::random::<f32>() > 0.8 {
            return Err(WorkflowError {
                code: "HOLE_PUNCH_FAILED".to_string(),
                message: "Failed to establish connection through NAT".to_string(),
                stage: Some(context.current_stage.clone()),
                trace: None,
                recovery_hints: vec!["Retry with different timing".to_string()],
            });
        }

        // Store connection info
        context.set_state(
            "connection".to_string(),
            b"established:192.168.1.100:5000".to_vec(),
        );

        Ok(())
    }

    fn name(&self) -> &str {
        "hole_punching"
    }
}

/// Example condition that checks if candidates are available
struct CandidatesAvailableCondition;

#[async_trait::async_trait]
impl Condition for CandidatesAvailableCondition {
    async fn check(&self, context: &WorkflowContext) -> bool {
        context.get_state("candidates").is_some()
    }

    fn description(&self) -> &str {
        "candidates_available"
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .init();

    info!("Starting workflow orchestration example");

    // Create workflow registry
    let registry = Arc::new(WorkflowRegistry::new());

    // Load default templates
    registry.load_defaults().await?;

    // Create a custom workflow
    let custom_workflow = WorkflowDefinitionBuilder::new(
        "custom_nat_traversal".to_string(),
        "Custom NAT Traversal Workflow".to_string(),
        Version {
            major: 1,
            minor: 0,
            patch: 0,
        },
    )
    .description("Custom workflow with specific actions".to_string())
    .add_stage(WorkflowStage {
        id: StageId("discover".to_string()),
        name: "Discover Candidates".to_string(),
        description: "Discover local and reflexive candidates".to_string(),
        actions: vec![Arc::new(DiscoverCandidatesAction)],
        action_names: vec!["discover_candidates".to_string()],
        preconditions: vec![],
        precondition_descriptions: vec![],
        postconditions: vec![Arc::new(CandidatesAvailableCondition)],
        postcondition_descriptions: vec!["candidates_available".to_string()],
        rollback: None,
        skippable: false,
        max_duration: Some(Duration::from_secs(5)),
    })
    .add_stage(WorkflowStage {
        id: StageId("punch".to_string()),
        name: "Hole Punching".to_string(),
        description: "Execute NAT hole punching".to_string(),
        actions: vec![Arc::new(HolePunchingAction)],
        action_names: vec!["hole_punching".to_string()],
        preconditions: vec![Arc::new(CandidatesAvailableCondition)],
        precondition_descriptions: vec!["candidates_available".to_string()],
        postconditions: vec![],
        postcondition_descriptions: vec![],
        rollback: Some(RollbackStrategy::JumpToStage {
            stage_id: StageId("discover".to_string()),
        }),
        skippable: false,
        max_duration: Some(Duration::from_secs(10)),
    })
    .initial_stage(StageId("discover".to_string()))
    .add_final_stage(StageId("punch".to_string()))
    .add_transition(
        StageId("discover".to_string()),
        ant_quic::workflow::WorkflowEvent::StageCompleted {
            stage_id: StageId("discover".to_string()),
        },
        StageId("punch".to_string()),
    )
    .set_error_handler(
        StageId("punch".to_string()),
        ErrorHandler {
            max_retries: 3,
            backoff: BackoffStrategy::Exponential {
                initial: Duration::from_millis(500),
                max: Duration::from_secs(5),
                factor: 2.0,
            },
            fallback_stage: None,
            propagate: true,
        },
    )
    .global_timeout(Duration::from_secs(60))
    .build();

    // Register custom workflow
    registry.register(custom_workflow).await?;

    // Create state store
    let state_store = Arc::new(InMemoryStateStore::new());

    // Create workflow engine
    let engine_config = WorkflowEngineConfig {
        max_concurrent_workflows: 100,
        default_timeout: Duration::from_secs(300),
        enable_tracing: true,
        checkpoint_interval: Duration::from_secs(5),
        max_system_retries: 3,
        worker_count: 4,
    };

    let engine = WorkflowEngine::new(engine_config, registry.clone(), state_store);
    engine.start().await?;

    // Create monitoring
    let monitor = WorkflowMonitor::new(MonitoringConfig::default());
    monitor
        .register_alert_handler(Box::new(LoggingAlertHandler))
        .await;
    monitor.start().await?;

    // Run workflows
    info!("Running basic NAT traversal workflow");
    let handle1 = engine
        .start_workflow(
            "nat_traversal_basic",
            &Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
            HashMap::new(),
        )
        .await?;

    info!("Running custom NAT traversal workflow");
    let handle2 = engine
        .start_workflow(
            "custom_nat_traversal",
            &Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
            HashMap::new(),
        )
        .await?;

    // Wait for workflows to complete
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let timeout_duration = Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    loop {
        interval.tick().await;

        let status1 = handle1.status().await;
        let status2 = handle2.status().await;

        info!("Workflow 1 status: {:?}", status1);
        info!("Workflow 2 status: {:?}", status2);

        use ant_quic::workflow::WorkflowStatus;
        let workflow1_done = matches!(
            status1,
            WorkflowStatus::Completed { .. }
                | WorkflowStatus::Failed { .. }
                | WorkflowStatus::Cancelled
        );

        let workflow2_done = matches!(
            status2,
            WorkflowStatus::Completed { .. }
                | WorkflowStatus::Failed { .. }
                | WorkflowStatus::Cancelled
        );

        if workflow1_done && workflow2_done {
            break;
        }

        if start.elapsed() > timeout_duration {
            error!("Timeout waiting for workflows to complete");
            break;
        }
    }

    // Get monitoring summary
    let summary = monitor.get_workflow_summary().await;
    info!("Workflow summary: {:?}", summary);

    // Stop engine
    engine.stop().await?;

    info!("Workflow orchestration example completed");
    Ok(())
}
