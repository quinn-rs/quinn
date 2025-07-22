//! Workflow Definition System
//!
//! This module provides the declarative workflow definition system that allows
//! complex NAT traversal workflows to be defined, composed, and versioned.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::workflow::{
    BackoffStrategy, Condition, ErrorHandler, RollbackStrategy, StageId, Version, WorkflowAction,
    WorkflowError, WorkflowEvent,
};

/// Complete workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    /// Unique identifier for this workflow type
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Version of this workflow
    pub version: Version,
    /// Description of the workflow
    pub description: String,
    /// Workflow stages
    pub stages: Vec<WorkflowStage>,
    /// State transition rules
    pub transitions: HashMap<(StageId, WorkflowEvent), StageId>,
    /// Timeout for each stage
    pub timeouts: HashMap<StageId, Duration>,
    /// Error handlers for each stage
    pub error_handlers: HashMap<StageId, ErrorHandler>,
    /// Initial stage
    pub initial_stage: StageId,
    /// Final stages (success endpoints)
    pub final_stages: Vec<StageId>,
    /// Global timeout for entire workflow
    pub global_timeout: Option<Duration>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

use std::time::Duration;

/// Definition of a workflow stage
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    /// Unique identifier for this stage
    pub id: StageId,
    /// Human-readable name
    pub name: String,
    /// Description of what this stage does
    pub description: String,
    /// Actions to execute in this stage
    #[serde(skip)]
    pub actions: Vec<Arc<dyn WorkflowAction>>,
    /// Action names for serialization
    pub action_names: Vec<String>,
    /// Preconditions that must be met
    #[serde(skip)]
    pub preconditions: Vec<Arc<dyn Condition>>,
    /// Precondition descriptions for serialization
    pub precondition_descriptions: Vec<String>,
    /// Postconditions to verify after execution
    #[serde(skip)]
    pub postconditions: Vec<Arc<dyn Condition>>,
    /// Postcondition descriptions for serialization
    pub postcondition_descriptions: Vec<String>,
    /// Rollback strategy if stage fails
    pub rollback: Option<RollbackStrategy>,
    /// Whether this stage can be skipped
    pub skippable: bool,
    /// Maximum execution time for this stage
    pub max_duration: Option<Duration>,
}

impl fmt::Debug for WorkflowStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkflowStage")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("action_names", &self.action_names)
            .field("precondition_descriptions", &self.precondition_descriptions)
            .field(
                "postcondition_descriptions",
                &self.postcondition_descriptions,
            )
            .field("rollback", &self.rollback)
            .field("skippable", &self.skippable)
            .field("max_duration", &self.max_duration)
            .finish()
    }
}

/// Builder for creating workflow definitions
pub struct WorkflowDefinitionBuilder {
    definition: WorkflowDefinition,
}

impl WorkflowDefinitionBuilder {
    /// Create a new workflow definition builder
    pub fn new(id: String, name: String, version: Version) -> Self {
        Self {
            definition: WorkflowDefinition {
                id,
                name,
                version,
                description: String::new(),
                stages: Vec::new(),
                transitions: HashMap::new(),
                timeouts: HashMap::new(),
                error_handlers: HashMap::new(),
                initial_stage: StageId("start".to_string()),
                final_stages: vec![StageId("complete".to_string())],
                global_timeout: None,
                metadata: HashMap::new(),
            },
        }
    }

    /// Set the description
    pub fn description(mut self, desc: String) -> Self {
        self.definition.description = desc;
        self
    }

    /// Add a stage to the workflow
    pub fn add_stage(mut self, stage: WorkflowStage) -> Self {
        self.definition.stages.push(stage);
        self
    }

    /// Add a transition rule
    pub fn add_transition(
        mut self,
        from_stage: StageId,
        event: WorkflowEvent,
        to_stage: StageId,
    ) -> Self {
        self.definition
            .transitions
            .insert((from_stage, event), to_stage);
        self
    }

    /// Set timeout for a stage
    pub fn set_stage_timeout(mut self, stage: StageId, timeout: Duration) -> Self {
        self.definition.timeouts.insert(stage, timeout);
        self
    }

    /// Set error handler for a stage
    pub fn set_error_handler(mut self, stage: StageId, handler: ErrorHandler) -> Self {
        self.definition.error_handlers.insert(stage, handler);
        self
    }

    /// Set the initial stage
    pub fn initial_stage(mut self, stage: StageId) -> Self {
        self.definition.initial_stage = stage;
        self
    }

    /// Add a final stage
    pub fn add_final_stage(mut self, stage: StageId) -> Self {
        self.definition.final_stages.push(stage);
        self
    }

    /// Set global timeout
    pub fn global_timeout(mut self, timeout: Duration) -> Self {
        self.definition.global_timeout = Some(timeout);
        self
    }

    /// Add metadata
    pub fn add_metadata(mut self, key: String, value: String) -> Self {
        self.definition.metadata.insert(key, value);
        self
    }

    /// Build the workflow definition
    pub fn build(self) -> WorkflowDefinition {
        self.definition
    }
}

/// Pre-built workflow templates for common NAT traversal scenarios
pub struct WorkflowTemplates;

impl WorkflowTemplates {
    /// Basic NAT traversal workflow
    pub fn basic_nat_traversal() -> WorkflowDefinition {
        WorkflowDefinitionBuilder::new(
            "nat_traversal_basic".to_string(),
            "Basic NAT Traversal".to_string(),
            Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
        )
        .description(
            "Standard NAT traversal workflow with candidate discovery and hole punching"
                .to_string(),
        )
        .add_stage(WorkflowStage {
            id: StageId("discover_candidates".to_string()),
            name: "Discover Candidates".to_string(),
            description: "Discover local and server-reflexive candidates".to_string(),
            actions: vec![],
            action_names: vec![
                "discover_local_candidates".to_string(),
                "query_stun_servers".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["network_available".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["candidates_discovered".to_string()],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(5)),
        })
        .add_stage(WorkflowStage {
            id: StageId("coordinate_with_peer".to_string()),
            name: "Coordinate with Peer".to_string(),
            description: "Exchange candidates and coordinate hole punching".to_string(),
            actions: vec![],
            action_names: vec![
                "exchange_candidates".to_string(),
                "synchronize_timing".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["candidates_available".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["coordination_complete".to_string()],
            rollback: Some(RollbackStrategy::JumpToStage {
                stage_id: StageId("discover_candidates".to_string()),
            }),
            skippable: false,
            max_duration: Some(Duration::from_secs(10)),
        })
        .add_stage(WorkflowStage {
            id: StageId("hole_punching".to_string()),
            name: "Hole Punching".to_string(),
            description: "Execute synchronized hole punching".to_string(),
            actions: vec![],
            action_names: vec![
                "execute_hole_punch".to_string(),
                "verify_connectivity".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["coordination_complete".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["connection_established".to_string()],
            rollback: Some(RollbackStrategy::Compensate {
                actions: vec!["cleanup_failed_attempts".to_string()],
            }),
            skippable: false,
            max_duration: Some(Duration::from_secs(15)),
        })
        .add_stage(WorkflowStage {
            id: StageId("connection_established".to_string()),
            name: "Connection Established".to_string(),
            description: "Connection successfully established".to_string(),
            actions: vec![],
            action_names: vec!["finalize_connection".to_string()],
            preconditions: vec![],
            precondition_descriptions: vec!["connection_verified".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec![],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(2)),
        })
        .initial_stage(StageId("discover_candidates".to_string()))
        .add_final_stage(StageId("connection_established".to_string()))
        .add_transition(
            StageId("discover_candidates".to_string()),
            WorkflowEvent::StageCompleted {
                stage_id: StageId("discover_candidates".to_string()),
            },
            StageId("coordinate_with_peer".to_string()),
        )
        .add_transition(
            StageId("coordinate_with_peer".to_string()),
            WorkflowEvent::StageCompleted {
                stage_id: StageId("coordinate_with_peer".to_string()),
            },
            StageId("hole_punching".to_string()),
        )
        .add_transition(
            StageId("hole_punching".to_string()),
            WorkflowEvent::StageCompleted {
                stage_id: StageId("hole_punching".to_string()),
            },
            StageId("connection_established".to_string()),
        )
        .set_stage_timeout(
            StageId("discover_candidates".to_string()),
            Duration::from_secs(10),
        )
        .set_stage_timeout(
            StageId("coordinate_with_peer".to_string()),
            Duration::from_secs(20),
        )
        .set_stage_timeout(
            StageId("hole_punching".to_string()),
            Duration::from_secs(30),
        )
        .set_error_handler(
            StageId("hole_punching".to_string()),
            ErrorHandler {
                max_retries: 3,
                backoff: BackoffStrategy::Exponential {
                    initial: Duration::from_millis(500),
                    max: Duration::from_secs(5),
                    factor: 2.0,
                },
                fallback_stage: Some(StageId("coordinate_with_peer".to_string())),
                propagate: false,
            },
        )
        .global_timeout(Duration::from_secs(60))
        .build()
    }

    /// Advanced NAT traversal with relay fallback
    pub fn advanced_nat_traversal() -> WorkflowDefinition {
        let mut basic = Self::basic_nat_traversal();
        basic.id = "nat_traversal_advanced".to_string();
        basic.name = "Advanced NAT Traversal with Relay".to_string();
        basic.version = Version {
            major: 1,
            minor: 0,
            patch: 0,
        };

        // Add relay fallback stage
        basic.stages.push(WorkflowStage {
            id: StageId("relay_fallback".to_string()),
            name: "Relay Fallback".to_string(),
            description: "Establish connection through relay server".to_string(),
            actions: vec![],
            action_names: vec![
                "connect_to_relay".to_string(),
                "establish_relay_path".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["relay_available".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["relay_connection_established".to_string()],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(10)),
        });

        // Add transition from hole punching failure to relay
        basic.transitions.insert(
            (
                StageId("hole_punching".to_string()),
                WorkflowEvent::StageFailed {
                    stage_id: StageId("hole_punching".to_string()),
                    error: "max_retries_exceeded".to_string(),
                },
            ),
            StageId("relay_fallback".to_string()),
        );

        // Add transition from relay to completion
        basic.transitions.insert(
            (
                StageId("relay_fallback".to_string()),
                WorkflowEvent::StageCompleted {
                    stage_id: StageId("relay_fallback".to_string()),
                },
            ),
            StageId("connection_established".to_string()),
        );

        basic
    }

    /// Multi-peer coordination workflow
    pub fn multi_peer_coordination() -> WorkflowDefinition {
        WorkflowDefinitionBuilder::new(
            "multi_peer_coordination".to_string(),
            "Multi-Peer Coordination".to_string(),
            Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
        )
        .description("Coordinate NAT traversal among multiple peers".to_string())
        .add_stage(WorkflowStage {
            id: StageId("peer_discovery".to_string()),
            name: "Peer Discovery".to_string(),
            description: "Discover available peers".to_string(),
            actions: vec![],
            action_names: vec![
                "query_bootstrap_nodes".to_string(),
                "exchange_peer_lists".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["bootstrap_available".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["peers_discovered".to_string()],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(10)),
        })
        .add_stage(WorkflowStage {
            id: StageId("establish_coordinator".to_string()),
            name: "Establish Coordinator".to_string(),
            description: "Select and establish connection to coordination node".to_string(),
            actions: vec![],
            action_names: vec![
                "select_coordinator".to_string(),
                "connect_to_coordinator".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["peers_available".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["coordinator_connected".to_string()],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(15)),
        })
        .add_stage(WorkflowStage {
            id: StageId("coordinate_connections".to_string()),
            name: "Coordinate Connections".to_string(),
            description: "Coordinate NAT traversal for all peer connections".to_string(),
            actions: vec![],
            action_names: vec![
                "plan_connection_order".to_string(),
                "execute_coordinated_traversal".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["coordinator_ready".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec!["all_connections_established".to_string()],
            rollback: Some(RollbackStrategy::Compensate {
                actions: vec!["cleanup_partial_connections".to_string()],
            }),
            skippable: false,
            max_duration: Some(Duration::from_secs(60)),
        })
        .add_stage(WorkflowStage {
            id: StageId("mesh_established".to_string()),
            name: "Mesh Established".to_string(),
            description: "Peer mesh successfully established".to_string(),
            actions: vec![],
            action_names: vec![
                "verify_mesh_connectivity".to_string(),
                "optimize_routing".to_string(),
            ],
            preconditions: vec![],
            precondition_descriptions: vec!["minimum_peers_connected".to_string()],
            postconditions: vec![],
            postcondition_descriptions: vec![],
            rollback: None,
            skippable: false,
            max_duration: Some(Duration::from_secs(5)),
        })
        .initial_stage(StageId("peer_discovery".to_string()))
        .add_final_stage(StageId("mesh_established".to_string()))
        .global_timeout(Duration::from_secs(120))
        .build()
    }
}

/// Registry for workflow definitions
pub struct WorkflowRegistry {
    definitions: RwLock<HashMap<String, WorkflowDefinition>>,
}

use tokio::sync::RwLock;

impl WorkflowRegistry {
    /// Create a new workflow registry
    pub fn new() -> Self {
        Self {
            definitions: RwLock::new(HashMap::new()),
        }
    }

    /// Register a workflow definition
    pub async fn register(&self, definition: WorkflowDefinition) -> Result<(), WorkflowError> {
        let mut definitions = self.definitions.write().await;

        let key = format!("{}:{}", definition.id, definition.version);
        if definitions.contains_key(&key) {
            return Err(WorkflowError {
                code: "ALREADY_EXISTS".to_string(),
                message: format!(
                    "Workflow {} version {} already registered",
                    definition.id, definition.version
                ),
                stage: None,
                trace: None,
                recovery_hints: vec!["Use a different version number".to_string()],
            });
        }

        info!(
            "Registered workflow: {} v{}",
            definition.id, definition.version
        );
        definitions.insert(key, definition);
        Ok(())
    }

    /// Get a workflow definition by ID and version
    pub async fn get(&self, id: &str, version: &Version) -> Option<WorkflowDefinition> {
        let definitions = self.definitions.read().await;
        let key = format!("{}:{}", id, version);
        definitions.get(&key).cloned()
    }

    /// Get the latest version of a workflow
    pub async fn get_latest(&self, id: &str) -> Option<WorkflowDefinition> {
        let definitions = self.definitions.read().await;

        definitions
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}:", id)))
            .max_by_key(|(_, def)| &def.version)
            .map(|(_, def)| def.clone())
    }

    /// List all registered workflows
    pub async fn list(&self) -> Vec<(String, Version)> {
        let definitions = self.definitions.read().await;

        definitions
            .values()
            .map(|def| (def.id.clone(), def.version.clone()))
            .collect()
    }

    /// Load default workflow templates
    pub async fn load_defaults(&self) -> Result<(), WorkflowError> {
        self.register(WorkflowTemplates::basic_nat_traversal())
            .await?;
        self.register(WorkflowTemplates::advanced_nat_traversal())
            .await?;
        self.register(WorkflowTemplates::multi_peer_coordination())
            .await?;

        info!("Loaded {} default workflow templates", 3);
        Ok(())
    }
}

impl Default for WorkflowRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_builder() {
        let workflow = WorkflowDefinitionBuilder::new(
            "test_workflow".to_string(),
            "Test Workflow".to_string(),
            Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
        )
        .description("Test workflow description".to_string())
        .add_stage(WorkflowStage {
            id: StageId("stage1".to_string()),
            name: "Stage 1".to_string(),
            description: "First stage".to_string(),
            actions: vec![],
            action_names: vec!["action1".to_string()],
            preconditions: vec![],
            precondition_descriptions: vec![],
            postconditions: vec![],
            postcondition_descriptions: vec![],
            rollback: None,
            skippable: false,
            max_duration: None,
        })
        .initial_stage(StageId("stage1".to_string()))
        .build();

        assert_eq!(workflow.id, "test_workflow");
        assert_eq!(workflow.stages.len(), 1);
        assert_eq!(workflow.initial_stage, StageId("stage1".to_string()));
    }

    #[tokio::test]
    async fn test_workflow_registry() {
        let registry = WorkflowRegistry::new();

        let workflow = WorkflowTemplates::basic_nat_traversal();
        registry.register(workflow.clone()).await.unwrap();

        let retrieved = registry.get(&workflow.id, &workflow.version).await;
        assert!(retrieved.is_some());

        let latest = registry.get_latest(&workflow.id).await;
        assert!(latest.is_some());

        let list = registry.list().await;
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_workflow_templates() {
        let basic = WorkflowTemplates::basic_nat_traversal();
        assert_eq!(basic.id, "nat_traversal_basic");
        assert!(!basic.stages.is_empty());

        let advanced = WorkflowTemplates::advanced_nat_traversal();
        assert_eq!(advanced.id, "nat_traversal_advanced");
        assert!(advanced.stages.len() > basic.stages.len());
    }
}
