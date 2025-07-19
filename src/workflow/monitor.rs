//! Workflow Monitoring and Visualization
//!
//! This module provides real-time monitoring, metrics collection, and
//! visualization capabilities for workflow execution.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use crate::{SystemTime};

use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, RwLock, Mutex},
    time::interval,
};
use tracing::{debug, info, warn};

use crate::workflow::{
    StageId, WorkflowId, WorkflowStatus, WorkflowError, WorkflowMetrics,
};

/// Monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Metrics collection interval
    pub collection_interval: Duration,
    /// History retention period
    pub retention_period: Duration,
    /// Maximum events to store per workflow
    pub max_events_per_workflow: usize,
    /// Enable detailed tracing
    pub enable_tracing: bool,
    /// Alert thresholds
    pub alert_config: AlertConfig,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(5),
            retention_period: Duration::from_secs(24 * 3600),
            max_events_per_workflow: 1000,
            enable_tracing: true,
            alert_config: AlertConfig::default(),
        }
    }
}

/// Alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Maximum workflow duration before alert
    pub max_workflow_duration: Duration,
    /// Maximum stage duration before alert
    pub max_stage_duration: Duration,
    /// Error rate threshold (errors per minute)
    pub error_rate_threshold: f32,
    /// Memory usage threshold in MB
    pub memory_threshold_mb: u64,
    /// CPU usage threshold percentage
    pub cpu_threshold_percent: f32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            max_workflow_duration: Duration::from_secs(3600),
            max_stage_duration: Duration::from_secs(600),
            error_rate_threshold: 10.0,
            memory_threshold_mb: 1024,
            cpu_threshold_percent: 80.0,
        }
    }
}

/// Monitoring event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringEvent {
    /// Workflow started
    WorkflowStarted {
        workflow_id: WorkflowId,
        definition_id: String,
        timestamp: SystemTime,
    },
    /// Workflow completed
    WorkflowCompleted {
        workflow_id: WorkflowId,
        duration: Duration,
        success: bool,
        timestamp: SystemTime,
    },
    /// Stage started
    StageStarted {
        workflow_id: WorkflowId,
        stage_id: StageId,
        timestamp: SystemTime,
    },
    /// Stage completed
    StageCompleted {
        workflow_id: WorkflowId,
        stage_id: StageId,
        duration: Duration,
        timestamp: SystemTime,
    },
    /// Error occurred
    ErrorOccurred {
        workflow_id: WorkflowId,
        stage_id: Option<StageId>,
        error: String,
        timestamp: SystemTime,
    },
    /// Metric recorded
    MetricRecorded {
        workflow_id: WorkflowId,
        metric_name: String,
        value: f64,
        timestamp: SystemTime,
    },
    /// Alert triggered
    AlertTriggered {
        workflow_id: Option<WorkflowId>,
        alert_type: AlertType,
        message: String,
        timestamp: SystemTime,
    },
}

/// Types of alerts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    WorkflowTimeout,
    StageTimeout,
    HighErrorRate,
    HighMemoryUsage,
    HighCpuUsage,
    SystemError,
}

/// Workflow monitor for real-time monitoring
pub struct WorkflowMonitor {
    /// Monitoring configuration
    config: MonitoringConfig,
    /// Event history
    event_history: Arc<RwLock<VecDeque<MonitoringEvent>>>,
    /// Workflow metrics
    workflow_metrics: Arc<RwLock<HashMap<WorkflowId, WorkflowMonitoringData>>>,
    /// System metrics
    system_metrics: Arc<RwLock<SystemMetrics>>,
    /// Alert handlers
    alert_handlers: Arc<RwLock<Vec<Box<dyn AlertHandler>>>>,
    /// Event channel
    event_tx: mpsc::Sender<MonitoringEvent>,
    event_rx: Arc<Mutex<mpsc::Receiver<MonitoringEvent>>>,
}

impl WorkflowMonitor {
    /// Create a new workflow monitor
    pub fn new(config: MonitoringConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);
        
        Self {
            config,
            event_history: Arc::new(RwLock::new(VecDeque::new())),
            workflow_metrics: Arc::new(RwLock::new(HashMap::new())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            alert_handlers: Arc::new(RwLock::new(Vec::new())),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
        }
    }

    /// Start the monitor
    pub async fn start(&self) -> Result<(), WorkflowError> {
        info!("Starting workflow monitor");
        
        // Start event processing
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.event_processing_loop().await;
        });
        
        // Start metrics collection
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.metrics_collection_loop().await;
        });
        
        // Start cleanup task
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.cleanup_loop().await;
        });
        
        Ok(())
    }

    /// Register an alert handler
    pub async fn register_alert_handler(&self, handler: Box<dyn AlertHandler>) {
        let mut handlers = self.alert_handlers.write().await;
        handlers.push(handler);
    }

    /// Record a monitoring event
    pub async fn record_event(&self, event: MonitoringEvent) -> Result<(), WorkflowError> {
        self.event_tx.send(event).await
            .map_err(|_| WorkflowError {
                code: "MONITORING_ERROR".to_string(),
                message: "Failed to record monitoring event".to_string(),
                stage: None,
                trace: None,
                recovery_hints: vec![],
            })
    }

    /// Get workflow metrics
    pub async fn get_workflow_metrics(&self, workflow_id: &WorkflowId) -> Option<WorkflowMonitoringData> {
        let metrics = self.workflow_metrics.read().await;
        metrics.get(workflow_id).cloned()
    }

    /// Get system metrics
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    /// Get recent events
    pub async fn get_recent_events(&self, count: usize) -> Vec<MonitoringEvent> {
        let history = self.event_history.read().await;
        history.iter().rev().take(count).cloned().collect()
    }

    /// Get workflow summary
    pub async fn get_workflow_summary(&self) -> WorkflowSummary {
        let metrics = self.workflow_metrics.read().await;
        let system = self.system_metrics.read().await;
        
        let active_workflows = metrics.iter()
            .filter(|(_, data)| matches!(data.status, WorkflowStatus::Running { .. }))
            .count();
        
        let completed_workflows = metrics.iter()
            .filter(|(_, data)| matches!(data.status, WorkflowStatus::Completed { .. }))
            .count();
        
        let failed_workflows = metrics.iter()
            .filter(|(_, data)| matches!(data.status, WorkflowStatus::Failed { .. }))
            .count();
        
        let total_duration: Duration = metrics.values()
            .filter_map(|data| data.end_time.map(|end| end.duration_since(data.start_time).unwrap_or_default()))
            .sum();
        
        let avg_duration = if completed_workflows > 0 {
            total_duration / completed_workflows as u32
        } else {
            Duration::default()
        };
        
        WorkflowSummary {
            active_workflows,
            completed_workflows,
            failed_workflows,
            total_workflows: metrics.len(),
            average_duration: avg_duration,
            system_metrics: system.clone(),
        }
    }

    /// Event processing loop
    async fn event_processing_loop(&self) {
        let mut receiver = self.event_rx.lock().await;
        
        while let Some(event) = receiver.recv().await {
            if let Err(e) = self.process_event(event.clone()).await {
                warn!("Error processing monitoring event: {:?}", e);
            }
        }
    }

    /// Process a monitoring event
    async fn process_event(&self, event: MonitoringEvent) -> Result<(), WorkflowError> {
        // Add to history
        {
            let mut history = self.event_history.write().await;
            history.push_back(event.clone());
            
            // Trim old events
            while history.len() > 10000 {
                history.pop_front();
            }
        }
        
        // Update metrics
        match &event {
            MonitoringEvent::WorkflowStarted { workflow_id, definition_id, timestamp } => {
                let mut metrics = self.workflow_metrics.write().await;
                metrics.insert(*workflow_id, WorkflowMonitoringData {
                    workflow_id: *workflow_id,
                    definition_id: definition_id.clone(),
                    status: WorkflowStatus::Running { current_stage: StageId("init".to_string()) },
                    start_time: *timestamp,
                    end_time: None,
                    stages_completed: 0,
                    errors: Vec::new(),
                    metrics: WorkflowMetrics::default(),
                });
            }
            MonitoringEvent::WorkflowCompleted { workflow_id, duration, success, timestamp } => {
                let mut metrics = self.workflow_metrics.write().await;
                if let Some(data) = metrics.get_mut(workflow_id) {
                    data.status = if *success {
                        WorkflowStatus::Completed { 
                            result: crate::workflow::WorkflowResult {
                                output: HashMap::new(),
                                duration: *duration,
                                metrics: data.metrics.clone(),
                            }
                        }
                    } else {
                        WorkflowStatus::Failed { 
                            error: WorkflowError {
                                code: "WORKFLOW_FAILED".to_string(),
                                message: "Workflow failed".to_string(),
                                stage: None,
                                trace: None,
                                recovery_hints: vec![],
                            }
                        }
                    };
                    data.end_time = Some(*timestamp);
                }
                
                // Update system metrics
                let mut system = self.system_metrics.write().await;
                system.total_workflows_completed += 1;
                if *success {
                    system.successful_workflows += 1;
                } else {
                    system.failed_workflows += 1;
                }
            }
            MonitoringEvent::StageCompleted { workflow_id, stage_id: _, duration, timestamp: _ } => {
                let mut metrics = self.workflow_metrics.write().await;
                if let Some(data) = metrics.get_mut(workflow_id) {
                    data.stages_completed += 1;
                    data.metrics.stages_executed += 1;
                }
                
                // Check for stage timeout alert
                if *duration > self.config.alert_config.max_stage_duration {
                    self.trigger_alert(AlertType::StageTimeout, 
                        format!("Stage took {:?}, exceeding threshold", duration),
                        Some(*workflow_id),
                    ).await;
                }
            }
            MonitoringEvent::ErrorOccurred { workflow_id, stage_id: _, error, timestamp: _ } => {
                let mut metrics = self.workflow_metrics.write().await;
                if let Some(data) = metrics.get_mut(workflow_id) {
                    data.errors.push(error.clone());
                    data.metrics.error_count += 1;
                }
                
                // Update system error rate
                let mut system = self.system_metrics.write().await;
                system.error_count += 1;
                
                // Check error rate
                let error_rate = system.calculate_error_rate();
                if error_rate > self.config.alert_config.error_rate_threshold {
                    self.trigger_alert(AlertType::HighErrorRate,
                        format!("Error rate {:.1}/min exceeds threshold", error_rate),
                        None,
                    ).await;
                }
            }
            MonitoringEvent::AlertTriggered { .. } => {
                // Alerts are already handled
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Metrics collection loop
    async fn metrics_collection_loop(&self) {
        let mut interval = interval(self.config.collection_interval);
        
        loop {
            interval.tick().await;
            
            // Collect system metrics
            if let Err(e) = self.collect_system_metrics().await {
                warn!("Failed to collect system metrics: {:?}", e);
            }
            
            // Check for alerts
            self.check_alerts().await;
        }
    }

    /// Collect system metrics
    async fn collect_system_metrics(&self) -> Result<(), WorkflowError> {
        let mut system = self.system_metrics.write().await;
        
        // Update timestamp
        system.last_updated = SystemTime::now();
        
        // In a real implementation, we would collect actual system metrics
        // For now, we'll use placeholder values
        system.cpu_usage = 45.0;
        system.memory_usage_mb = 512;
        
        Ok(())
    }

    /// Check for alert conditions
    async fn check_alerts(&self) {
        let metrics = self.workflow_metrics.read().await;
        let system = self.system_metrics.read().await;
        
        // Check CPU usage
        if system.cpu_usage > self.config.alert_config.cpu_threshold_percent {
            self.trigger_alert(AlertType::HighCpuUsage,
                format!("CPU usage {:.1}% exceeds threshold", system.cpu_usage),
                None,
            ).await;
        }
        
        // Check memory usage
        if system.memory_usage_mb > self.config.alert_config.memory_threshold_mb {
            self.trigger_alert(AlertType::HighMemoryUsage,
                format!("Memory usage {}MB exceeds threshold", system.memory_usage_mb),
                None,
            ).await;
        }
        
        // Check workflow timeouts
        let now = SystemTime::now();
        for (workflow_id, data) in metrics.iter() {
            if matches!(data.status, WorkflowStatus::Running { .. }) {
                if let Ok(duration) = now.duration_since(data.start_time) {
                    if duration > self.config.alert_config.max_workflow_duration {
                        self.trigger_alert(AlertType::WorkflowTimeout,
                            format!("Workflow running for {:?}, exceeding threshold", duration),
                            Some(*workflow_id),
                        ).await;
                    }
                }
            }
        }
    }

    /// Trigger an alert
    async fn trigger_alert(&self, alert_type: AlertType, message: String, workflow_id: Option<WorkflowId>) {
        let event = MonitoringEvent::AlertTriggered {
            workflow_id,
            alert_type: alert_type.clone(),
            message: message.clone(),
            timestamp: SystemTime::now(),
        };
        
        // Record the alert event
        let _ = self.record_event(event).await;
        
        // Notify all handlers
        let handlers = self.alert_handlers.read().await;
        for handler in handlers.iter() {
            handler.handle_alert(alert_type.clone(), message.clone(), workflow_id).await;
        }
    }

    /// Cleanup loop for old data
    async fn cleanup_loop(&self) {
        let mut interval = interval(Duration::from_secs(3600)); // 1 hour
        
        loop {
            interval.tick().await;
            
            let now = SystemTime::now();
            let retention_cutoff = now - self.config.retention_period;
            
            // Clean up old workflow metrics
            let mut metrics = self.workflow_metrics.write().await;
            metrics.retain(|_, data| {
                if let Some(end_time) = data.end_time {
                    end_time > retention_cutoff
                } else {
                    true // Keep running workflows
                }
            });
            
            // Clean up old events
            let mut history = self.event_history.write().await;
            history.retain(|event| {
                match event {
                    MonitoringEvent::WorkflowStarted { timestamp, .. } |
                    MonitoringEvent::WorkflowCompleted { timestamp, .. } |
                    MonitoringEvent::StageStarted { timestamp, .. } |
                    MonitoringEvent::StageCompleted { timestamp, .. } |
                    MonitoringEvent::ErrorOccurred { timestamp, .. } |
                    MonitoringEvent::MetricRecorded { timestamp, .. } |
                    MonitoringEvent::AlertTriggered { timestamp, .. } => {
                        *timestamp > retention_cutoff
                    }
                }
            });
            
            debug!("Cleaned up old monitoring data");
        }
    }
}

impl Clone for WorkflowMonitor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_history: self.event_history.clone(),
            workflow_metrics: self.workflow_metrics.clone(),
            system_metrics: self.system_metrics.clone(),
            alert_handlers: self.alert_handlers.clone(),
            event_tx: self.event_tx.clone(),
            event_rx: self.event_rx.clone(),
        }
    }
}

/// Monitoring data for a workflow
#[derive(Debug, Clone)]
pub struct WorkflowMonitoringData {
    /// Workflow ID
    pub workflow_id: WorkflowId,
    /// Workflow definition ID
    pub definition_id: String,
    /// Current status
    pub status: WorkflowStatus,
    /// Start time
    pub start_time: SystemTime,
    /// End time
    pub end_time: Option<SystemTime>,
    /// Number of stages completed
    pub stages_completed: u32,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Workflow metrics
    pub metrics: WorkflowMetrics,
}

/// System-wide metrics
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    /// Total workflows completed
    pub total_workflows_completed: u64,
    /// Successful workflows
    pub successful_workflows: u64,
    /// Failed workflows
    pub failed_workflows: u64,
    /// Total error count
    pub error_count: u64,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// Last update timestamp
    pub last_updated: SystemTime,
    /// Start time for rate calculations
    pub start_time: SystemTime,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            total_workflows_completed: 0,
            successful_workflows: 0,
            failed_workflows: 0,
            error_count: 0,
            cpu_usage: 0.0,
            memory_usage_mb: 0,
            last_updated: now,
            start_time: now,
        }
    }
}

impl SystemMetrics {
    /// Calculate error rate per minute
    pub fn calculate_error_rate(&self) -> f32 {
        if let Ok(duration) = self.last_updated.duration_since(self.start_time) {
            let minutes = duration.as_secs_f32() / 60.0;
            if minutes > 0.0 {
                return self.error_count as f32 / minutes;
            }
        }
        0.0
    }
}

/// Summary of workflow system state
#[derive(Debug, Clone)]
pub struct WorkflowSummary {
    /// Number of active workflows
    pub active_workflows: usize,
    /// Number of completed workflows
    pub completed_workflows: usize,
    /// Number of failed workflows
    pub failed_workflows: usize,
    /// Total workflows
    pub total_workflows: usize,
    /// Average workflow duration
    pub average_duration: Duration,
    /// System metrics
    pub system_metrics: SystemMetrics,
}

/// Alert handler trait
#[async_trait::async_trait]
pub trait AlertHandler: Send + Sync {
    /// Handle an alert
    async fn handle_alert(&self, alert_type: AlertType, message: String, workflow_id: Option<WorkflowId>);
}

/// Simple logging alert handler
pub struct LoggingAlertHandler;

#[async_trait::async_trait]
impl AlertHandler for LoggingAlertHandler {
    async fn handle_alert(&self, alert_type: AlertType, message: String, workflow_id: Option<WorkflowId>) {
        warn!("ALERT [{:?}] {}: {:?}", alert_type, message, workflow_id);
    }
}

// Helper trait for Duration operations
trait DurationExt {
    fn from_hours(hours: u64) -> Duration;
    fn from_mins(mins: u64) -> Duration;
}

impl DurationExt for Duration {
    fn from_hours(hours: u64) -> Duration {
        Duration::from_secs(hours * 3600)
    }
    
    fn from_mins(mins: u64) -> Duration {
        Duration::from_secs(mins * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_workflow_monitor() {
        let monitor = WorkflowMonitor::new(MonitoringConfig::default());
        monitor.start().await.unwrap();
        
        // Register alert handler
        monitor.register_alert_handler(Box::new(LoggingAlertHandler)).await;
        
        // Record some events
        let workflow_id = WorkflowId::generate();
        
        monitor.record_event(MonitoringEvent::WorkflowStarted {
            workflow_id,
            definition_id: "test_workflow".to_string(),
            timestamp: SystemTime::now(),
        }).await.unwrap();
        
        monitor.record_event(MonitoringEvent::StageCompleted {
            workflow_id,
            stage_id: StageId("stage1".to_string()),
            duration: Duration::from_secs(5),
            timestamp: SystemTime::now(),
        }).await.unwrap();
        
        monitor.record_event(MonitoringEvent::WorkflowCompleted {
            workflow_id,
            duration: Duration::from_secs(10),
            success: true,
            timestamp: SystemTime::now(),
        }).await.unwrap();
        
        // Give background tasks time to process events
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check metrics
        let summary = monitor.get_workflow_summary().await;
        assert_eq!(summary.completed_workflows, 1);
        assert_eq!(summary.total_workflows, 1);
        
        let events = monitor.get_recent_events(10).await;
        assert_eq!(events.len(), 3);
    }
}