//! Workflow State Store
//!
//! This module provides persistence for workflow state, enabling workflow
//! recovery and fault tolerance across system restarts.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::workflow::{
    StageId, Version, WorkflowError, WorkflowId, WorkflowMetrics, WorkflowStatus,
};

/// Workflow state that can be persisted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    /// Workflow instance ID
    pub instance_id: WorkflowId,
    /// Workflow definition ID
    pub workflow_id: String,
    /// Workflow version
    pub version: Version,
    /// Current status
    pub status: WorkflowStatus,
    /// Current stage
    pub current_stage: StageId,
    /// Input data
    pub input: HashMap<String, Vec<u8>>,
    /// Workflow state data
    pub state: HashMap<String, Vec<u8>>,
    /// Metrics
    pub metrics: WorkflowMetrics,
    /// Retry attempts per stage
    pub retry_attempts: HashMap<StageId, u32>,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last updated timestamp
    pub updated_at: SystemTime,
    /// Checkpoint version
    pub checkpoint_version: u64,
}

/// Trait for workflow state persistence
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Save workflow state
    async fn save(&self, state: &WorkflowState) -> Result<(), WorkflowError>;
    
    /// Load workflow state
    async fn load(&self, instance_id: &WorkflowId) -> Result<WorkflowState, WorkflowError>;
    
    /// Delete workflow state
    async fn delete(&self, instance_id: &WorkflowId) -> Result<(), WorkflowError>;
    
    /// List all workflow instances
    async fn list(&self) -> Result<Vec<WorkflowId>, WorkflowError>;
    
    /// List workflow instances by status
    async fn list_by_status(&self, status: WorkflowStatus) -> Result<Vec<WorkflowId>, WorkflowError>;
    
    /// Clean up old completed workflows
    async fn cleanup(&self, retention: Duration) -> Result<u64, WorkflowError>;
}

/// In-memory state store for testing
pub struct InMemoryStateStore {
    states: Arc<RwLock<HashMap<WorkflowId, WorkflowState>>>,
}

impl InMemoryStateStore {
    /// Create a new in-memory state store
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StateStore for InMemoryStateStore {
    async fn save(&self, state: &WorkflowState) -> Result<(), WorkflowError> {
        let mut states = self.states.write().await;
        states.insert(state.instance_id, state.clone());
        debug!("Saved state for workflow {}", state.instance_id);
        Ok(())
    }
    
    async fn load(&self, instance_id: &WorkflowId) -> Result<WorkflowState, WorkflowError> {
        let states = self.states.read().await;
        states.get(instance_id).cloned().ok_or_else(|| WorkflowError {
            code: "STATE_NOT_FOUND".to_string(),
            message: format!("State not found for workflow {}", instance_id),
            stage: None,
            trace: None,
            recovery_hints: vec![],
        })
    }
    
    async fn delete(&self, instance_id: &WorkflowId) -> Result<(), WorkflowError> {
        let mut states = self.states.write().await;
        states.remove(instance_id);
        debug!("Deleted state for workflow {}", instance_id);
        Ok(())
    }
    
    async fn list(&self) -> Result<Vec<WorkflowId>, WorkflowError> {
        let states = self.states.read().await;
        Ok(states.keys().cloned().collect())
    }
    
    async fn list_by_status(&self, target_status: WorkflowStatus) -> Result<Vec<WorkflowId>, WorkflowError> {
        let states = self.states.read().await;
        Ok(states.iter()
            .filter(|(_, state)| state.status == target_status)
            .map(|(id, _)| *id)
            .collect())
    }
    
    async fn cleanup(&self, retention: Duration) -> Result<u64, WorkflowError> {
        let mut states = self.states.write().await;
        let now = SystemTime::now();
        let mut removed = 0;
        
        states.retain(|_, state| {
            match &state.status {
                WorkflowStatus::Completed { .. } | WorkflowStatus::Failed { .. } | WorkflowStatus::Cancelled => {
                    if let Ok(age) = now.duration_since(state.updated_at) {
                        if age > retention {
                            removed += 1;
                            return false;
                        }
                    }
                }
                _ => {}
            }
            true
        });
        
        debug!("Cleaned up {} old workflow states", removed);
        Ok(removed)
    }
}

/// File-based state store for production use
pub struct FileStateStore {
    /// Base directory for state files
    base_dir: std::path::PathBuf,
    /// File lock for concurrent access
    locks: Arc<RwLock<HashMap<WorkflowId, Arc<tokio::sync::Mutex<()>>>>>,
}

impl FileStateStore {
    /// Create a new file-based state store
    pub fn new(base_dir: std::path::PathBuf) -> Result<Self, WorkflowError> {
        // Create base directory if it doesn't exist
        std::fs::create_dir_all(&base_dir).map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to create state directory: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check directory permissions".to_string()],
        })?;
        
        Ok(Self {
            base_dir,
            locks: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Get the file path for a workflow instance
    fn get_file_path(&self, instance_id: &WorkflowId) -> std::path::PathBuf {
        // Use full hex encoding of the WorkflowId bytes
        self.base_dir.join(format!("{}.json", hex::encode(&instance_id.0)))
    }
    
    /// Get or create a lock for a workflow instance
    async fn get_lock(&self, instance_id: &WorkflowId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.write().await;
        locks.entry(*instance_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

#[async_trait]
impl StateStore for FileStateStore {
    async fn save(&self, state: &WorkflowState) -> Result<(), WorkflowError> {
        let lock = self.get_lock(&state.instance_id).await;
        let _guard = lock.lock().await;
        
        let path = self.get_file_path(&state.instance_id);
        let mut updated_state = state.clone();
        updated_state.updated_at = SystemTime::now();
        updated_state.checkpoint_version += 1;
        
        let json = serde_json::to_string_pretty(&updated_state).map_err(|e| WorkflowError {
            code: "SERIALIZATION_ERROR".to_string(),
            message: format!("Failed to serialize state: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec![],
        })?;
        
        // Write to temporary file first
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, json).await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to write state file: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check disk space and permissions".to_string()],
        })?;
        
        // Atomically rename to final path
        tokio::fs::rename(&temp_path, &path).await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to rename state file: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check disk permissions".to_string()],
        })?;
        
        debug!("Saved state for workflow {} to {:?}", state.instance_id, path);
        Ok(())
    }
    
    async fn load(&self, instance_id: &WorkflowId) -> Result<WorkflowState, WorkflowError> {
        let lock = self.get_lock(instance_id).await;
        let _guard = lock.lock().await;
        
        let path = self.get_file_path(instance_id);
        
        let json = tokio::fs::read_to_string(&path).await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to read state file: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check if workflow exists".to_string()],
        })?;
        
        let state = serde_json::from_str(&json).map_err(|e| WorkflowError {
            code: "DESERIALIZATION_ERROR".to_string(),
            message: format!("Failed to deserialize state: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["State file may be corrupted".to_string()],
        })?;
        
        debug!("Loaded state for workflow {} from {:?}", instance_id, path);
        Ok(state)
    }
    
    async fn delete(&self, instance_id: &WorkflowId) -> Result<(), WorkflowError> {
        let lock = self.get_lock(instance_id).await;
        let _guard = lock.lock().await;
        
        let path = self.get_file_path(instance_id);
        
        tokio::fs::remove_file(&path).await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to delete state file: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check file permissions".to_string()],
        })?;
        
        // Remove lock
        let mut locks = self.locks.write().await;
        locks.remove(instance_id);
        
        debug!("Deleted state for workflow {} at {:?}", instance_id, path);
        Ok(())
    }
    
    async fn list(&self) -> Result<Vec<WorkflowId>, WorkflowError> {
        let mut entries = tokio::fs::read_dir(&self.base_dir).await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to read state directory: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec!["Check directory permissions".to_string()],
        })?;
        
        let mut workflow_ids = Vec::new();
        
        while let Some(entry) = entries.next_entry().await.map_err(|e| WorkflowError {
            code: "STORAGE_ERROR".to_string(),
            message: format!("Failed to read directory entry: {}", e),
            stage: None,
            trace: None,
            recovery_hints: vec![],
        })? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".json") {
                    // Parse workflow ID from filename
                    let id_str = &name[..name.len() - 5];
                    if let Ok(id_bytes) = hex::decode(id_str) {
                        if id_bytes.len() == 16 {
                            let mut id_array = [0u8; 16];
                            id_array.copy_from_slice(&id_bytes);
                            workflow_ids.push(WorkflowId(id_array));
                        }
                    }
                }
            }
        }
        
        Ok(workflow_ids)
    }
    
    async fn list_by_status(&self, target_status: WorkflowStatus) -> Result<Vec<WorkflowId>, WorkflowError> {
        let all_ids = self.list().await?;
        let mut matching_ids = Vec::new();
        
        for id in all_ids {
            if let Ok(state) = self.load(&id).await {
                if state.status == target_status {
                    matching_ids.push(id);
                }
            }
        }
        
        Ok(matching_ids)
    }
    
    async fn cleanup(&self, retention: Duration) -> Result<u64, WorkflowError> {
        let all_ids = self.list().await?;
        let now = SystemTime::now();
        let mut removed = 0;
        
        for id in all_ids {
            if let Ok(state) = self.load(&id).await {
                match &state.status {
                    WorkflowStatus::Completed { .. } | WorkflowStatus::Failed { .. } | WorkflowStatus::Cancelled => {
                        if let Ok(age) = now.duration_since(state.updated_at) {
                            if age > retention {
                                if self.delete(&id).await.is_ok() {
                                    removed += 1;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        
        info!("Cleaned up {} old workflow states", removed);
        Ok(removed)
    }
}

/// State store with caching for improved performance
pub struct CachedStateStore<S: StateStore> {
    /// Underlying state store
    inner: S,
    /// In-memory cache
    cache: Arc<RwLock<HashMap<WorkflowId, (WorkflowState, SystemTime)>>>,
    /// Cache TTL
    ttl: Duration,
}

impl<S: StateStore> CachedStateStore<S> {
    /// Create a new cached state store
    pub fn new(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }
    
    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = SystemTime::now();
        
        cache.retain(|_, (_, timestamp)| {
            if let Ok(age) = now.duration_since(*timestamp) {
                age < self.ttl
            } else {
                true
            }
        });
    }
}

#[async_trait]
impl<S: StateStore> StateStore for CachedStateStore<S> {
    async fn save(&self, state: &WorkflowState) -> Result<(), WorkflowError> {
        // Save to underlying store
        self.inner.save(state).await?;
        
        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(state.instance_id, (state.clone(), SystemTime::now()));
        
        Ok(())
    }
    
    async fn load(&self, instance_id: &WorkflowId) -> Result<WorkflowState, WorkflowError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some((state, timestamp)) = cache.get(instance_id) {
                if let Ok(age) = SystemTime::now().duration_since(*timestamp) {
                    if age < self.ttl {
                        return Ok(state.clone());
                    }
                }
            }
        }
        
        // Load from underlying store
        let state = self.inner.load(instance_id).await?;
        
        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(*instance_id, (state.clone(), SystemTime::now()));
        
        Ok(state)
    }
    
    async fn delete(&self, instance_id: &WorkflowId) -> Result<(), WorkflowError> {
        // Delete from underlying store
        self.inner.delete(instance_id).await?;
        
        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(instance_id);
        
        Ok(())
    }
    
    async fn list(&self) -> Result<Vec<WorkflowId>, WorkflowError> {
        self.inner.list().await
    }
    
    async fn list_by_status(&self, status: WorkflowStatus) -> Result<Vec<WorkflowId>, WorkflowError> {
        self.inner.list_by_status(status).await
    }
    
    async fn cleanup(&self, retention: Duration) -> Result<u64, WorkflowError> {
        let result = self.inner.cleanup(retention).await?;
        
        // Clean cache as well
        self.cleanup_cache().await;
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryStateStore::new();
        
        let state = WorkflowState {
            instance_id: WorkflowId::generate(),
            workflow_id: "test_workflow".to_string(),
            version: Version { major: 1, minor: 0, patch: 0 },
            status: WorkflowStatus::Running { current_stage: StageId("stage1".to_string()) },
            current_stage: StageId("stage1".to_string()),
            input: HashMap::new(),
            state: HashMap::new(),
            metrics: WorkflowMetrics::default(),
            retry_attempts: HashMap::new(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            checkpoint_version: 1,
        };
        
        // Save state
        store.save(&state).await.unwrap();
        
        // Load state
        let loaded = store.load(&state.instance_id).await.unwrap();
        assert_eq!(loaded.instance_id, state.instance_id);
        assert_eq!(loaded.workflow_id, state.workflow_id);
        
        // List workflows
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], state.instance_id);
        
        // Delete state
        store.delete(&state.instance_id).await.unwrap();
        
        // Verify deleted
        assert!(store.load(&state.instance_id).await.is_err());
    }
    
    #[tokio::test]
    async fn test_file_store() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp_dir.path().to_path_buf()).unwrap();
        
        // Create an old completed workflow
        let old_state = WorkflowState {
            instance_id: WorkflowId::generate(),
            workflow_id: "old_workflow".to_string(),
            version: Version { major: 1, minor: 0, patch: 0 },
            status: WorkflowStatus::Completed { 
                result: crate::workflow::WorkflowResult {
                    output: HashMap::new(),
                    duration: Duration::from_secs(5),
                    metrics: WorkflowMetrics::default(),
                }
            },
            current_stage: StageId("final".to_string()),
            input: HashMap::new(),
            state: HashMap::new(),
            metrics: WorkflowMetrics::default(),
            retry_attempts: HashMap::new(),
            created_at: SystemTime::now() - Duration::from_secs(200),
            updated_at: SystemTime::now() - Duration::from_secs(200),
            checkpoint_version: 1,
        };
        
        // Save the old workflow using the store's save method first,
        // then manually update the file to have old timestamps
        store.save(&old_state).await.unwrap();
        
        // Now manually update the file's content to have old timestamps
        let path = store.get_file_path(&old_state.instance_id);
        let mut old_state_with_old_times = old_state.clone();
        old_state_with_old_times.updated_at = SystemTime::now() - Duration::from_secs(200);
        let json = serde_json::to_string_pretty(&old_state_with_old_times).unwrap();
        tokio::fs::write(&path, json).await.unwrap();
        
        // Create a new workflow to verify it's not deleted
        let new_state = WorkflowState {
            instance_id: WorkflowId::generate(),
            workflow_id: "new_workflow".to_string(),
            version: Version { major: 1, minor: 0, patch: 0 },
            status: WorkflowStatus::Completed { 
                result: crate::workflow::WorkflowResult {
                    output: HashMap::new(),
                    duration: Duration::from_secs(5),
                    metrics: WorkflowMetrics::default(),
                }
            },
            current_stage: StageId("final".to_string()),
            input: HashMap::new(),
            state: HashMap::new(),
            metrics: WorkflowMetrics::default(),
            retry_attempts: HashMap::new(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            checkpoint_version: 1,
        };
        
        // Save the new workflow normally
        store.save(&new_state).await.unwrap();
        
        // Verify both exist
        assert_eq!(store.list().await.unwrap().len(), 2);
        
        // Cleanup old workflows (older than 100 seconds)
        let removed = store.cleanup(Duration::from_secs(100)).await.unwrap();
        assert_eq!(removed, 1);
        
        // Verify only the new workflow remains
        let remaining = store.list().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], new_state.instance_id);
    }
}