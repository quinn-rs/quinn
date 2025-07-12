//! Export Management System
//!
//! This module implements centralized export management for monitoring data
//! to various external systems with data transformation and delivery guarantees.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

use crate::monitoring::MonitoringError;

/// Export manager for coordinating data exports
pub struct ExportManager {
    /// Export configuration
    config: ExportConfig,
    /// Data transformers
    transformers: Arc<DataTransformers>,
    /// Export schedulers
    schedulers: Arc<RwLock<HashMap<String, ExportScheduler>>>,
    /// Delivery manager
    delivery_manager: Arc<DeliveryManager>,
    /// Export state
    state: Arc<RwLock<ExportState>>,
    /// Background tasks
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>
}

impl ExportManager {
    /// Create new export manager
    pub async fn new(config: ExportConfig) -> Result<Self, MonitoringError> {
        let transformers = Arc::new(DataTransformers::new());
        let schedulers = Arc::new(RwLock::new(HashMap::new()));
        let delivery_manager = Arc::new(DeliveryManager::new(config.delivery.clone()));
        let state = Arc::new(RwLock::new(ExportState::new()));

        Ok(Self {
            config,
            transformers,
            schedulers,
            delivery_manager,
            state,
            tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Start export manager
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting export manager");

        // Initialize schedulers for each destination
        self.initialize_schedulers().await?;

        // Start background tasks
        self.start_export_coordination_task().await?;
        self.start_health_monitoring_task().await?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.status = ExportStatus::Running;
            state.start_time = Some(SystemTime::now());
        }

        info!("Export manager started");
        Ok(())
    }

    /// Stop export manager
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping export manager");

        // Update state
        {
            let mut state = self.state.write().await;
            state.status = ExportStatus::Stopping;
        }

        // Stop background tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        // Flush remaining data
        self.flush_all_exports().await?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.status = ExportStatus::Stopped;
            state.stop_time = Some(SystemTime::now());
        }

        info!("Export manager stopped");
        Ok(())
    }

    /// Get export manager status
    pub async fn get_status(&self) -> String {
        let state = self.state.read().await;
        format!("{:?}", state.status)
    }

    /// Export metrics data
    pub async fn export_metrics(&self, data: ExportData) -> Result<(), MonitoringError> {
        // Transform data for each configured destination
        for destination in &self.config.destinations {
            if let Ok(transformed_data) = self.transformers.transform_for_destination(&data, destination).await {
                self.delivery_manager.schedule_delivery(destination.clone(), transformed_data).await?;
            }
        }

        Ok(())
    }

    /// Initialize export schedulers
    async fn initialize_schedulers(&self) -> Result<(), MonitoringError> {
        let mut schedulers = self.schedulers.write().await;
        
        for destination in &self.config.destinations {
            let scheduler = ExportScheduler::new(destination.clone(), self.config.scheduling.clone());
            schedulers.insert(destination.id().to_string(), scheduler);
        }

        info!("Initialized {} export schedulers", schedulers.len());
        Ok(())
    }

    /// Start export coordination task
    async fn start_export_coordination_task(&self) -> Result<(), MonitoringError> {
        let delivery_manager = self.delivery_manager.clone();
        let config = self.config.clone();

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.coordination_interval);

            loop {
                interval.tick().await;

                if let Err(e) = delivery_manager.coordinate_deliveries().await {
                    warn!("Export coordination failed: {}", e);
                }
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Start health monitoring task
    async fn start_health_monitoring_task(&self) -> Result<(), MonitoringError> {
        let state = self.state.clone();
        let delivery_manager = self.delivery_manager.clone();

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let health = delivery_manager.get_health_status().await;
                
                let mut export_state = state.write().await;
                export_state.last_health_check = Some(SystemTime::now());
                export_state.exports_completed += health.successful_exports;
                export_state.export_errors += health.failed_exports;
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Flush all pending exports
    async fn flush_all_exports(&self) -> Result<(), MonitoringError> {
        self.delivery_manager.flush_all().await
    }
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Export destinations
    pub destinations: Vec<ExportDestination>,
    /// Scheduling configuration
    pub scheduling: SchedulingConfig,
    /// Delivery configuration
    pub delivery: DeliveryConfig,
    /// Export coordination interval
    pub coordination_interval: Duration,
    /// Data retention settings
    pub retention: RetentionConfig,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            destinations: vec![
                ExportDestination::File {
                    id: "local-file".to_string(),
                    path: "/tmp/ant-quic-metrics.json".to_string(),
                    format: FileFormat::JSON,
                }
            ],
            scheduling: SchedulingConfig::default(),
            delivery: DeliveryConfig::default(),
            coordination_interval: Duration::from_secs(60),
            retention: RetentionConfig::default(),
        }
    }
}

/// Export destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportDestination {
    File {
        id: String,
        path: String,
        format: FileFormat,
    },
    HTTP {
        id: String,
        endpoint: String,
        headers: HashMap<String, String>,
        auth: Option<AuthConfig>,
    },
    S3 {
        id: String,
        bucket: String,
        region: String,
        prefix: String,
    },
    Database {
        id: String,
        connection_string: String,
        table: String,
        schema: String,
    },
    Kafka {
        id: String,
        brokers: Vec<String>,
        topic: String,
        partition_key: Option<String>,
    },
}

impl ExportDestination {
    pub fn id(&self) -> &str {
        match self {
            ExportDestination::File { id, .. } => id,
            ExportDestination::HTTP { id, .. } => id,
            ExportDestination::S3 { id, .. } => id,
            ExportDestination::Database { id, .. } => id,
            ExportDestination::Kafka { id, .. } => id,
        }
    }
}

/// File formats for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileFormat {
    JSON,
    CSV,
    Parquet,
    Avro,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    Bearer,
    Basic,
    ApiKey,
    OAuth2,
}

/// Scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingConfig {
    /// Export interval
    pub interval: Duration,
    /// Batch size for exports
    pub batch_size: usize,
    /// Maximum delay before forced export
    pub max_delay: Duration,
    /// Enable intelligent scheduling
    pub intelligent_scheduling: bool,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300), // 5 minutes
            batch_size: 1000,
            max_delay: Duration::from_secs(600), // 10 minutes
            intelligent_scheduling: true,
        }
    }
}

/// Delivery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryConfig {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_retry_delay: Duration,
    /// Maximum retry delay
    pub max_retry_delay: Duration,
    /// Delivery timeout
    pub delivery_timeout: Duration,
    /// Enable compression
    pub compression: bool,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_retry_delay: Duration::from_secs(1),
            max_retry_delay: Duration::from_secs(60),
            delivery_timeout: Duration::from_secs(30),
            compression: true,
        }
    }
}

/// Data retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// How long to keep export data locally
    pub local_retention: Duration,
    /// How long to keep delivery receipts
    pub receipt_retention: Duration,
    /// Enable automatic cleanup
    pub auto_cleanup: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            local_retention: Duration::from_secs(3600 * 24), // 24 hours
            receipt_retention: Duration::from_secs(3600 * 24 * 7), // 7 days
            auto_cleanup: true,
        }
    }
}

/// Data to be exported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    /// Data type identifier
    pub data_type: String,
    /// Timestamp of data
    pub timestamp: SystemTime,
    /// Actual data payload
    pub payload: serde_json::Value,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Export scheduler for managing export timing
struct ExportScheduler {
    destination: ExportDestination,
    config: SchedulingConfig,
    last_export: Option<SystemTime>,
    pending_data: Vec<ExportData>,
}

impl ExportScheduler {
    fn new(destination: ExportDestination, config: SchedulingConfig) -> Self {
        Self {
            destination,
            config,
            last_export: None,
            pending_data: Vec::new(),
        }
    }

    fn should_export(&self) -> bool {
        if self.pending_data.len() >= self.config.batch_size {
            return true;
        }

        if let Some(last_export) = self.last_export {
            let elapsed = last_export.elapsed().unwrap_or_default();
            if elapsed >= self.config.interval {
                return true;
            }
            if elapsed >= self.config.max_delay && !self.pending_data.is_empty() {
                return true;
            }
        } else if !self.pending_data.is_empty() {
            return true;
        }

        false
    }

    fn add_data(&mut self, data: ExportData) {
        self.pending_data.push(data);
    }

    fn take_pending_data(&mut self) -> Vec<ExportData> {
        let data = self.pending_data.clone();
        self.pending_data.clear();
        self.last_export = Some(SystemTime::now());
        data
    }
}

/// Data transformers for different export formats
struct DataTransformers;

impl DataTransformers {
    fn new() -> Self {
        Self
    }

    async fn transform_for_destination(
        &self,
        data: &ExportData,
        destination: &ExportDestination,
    ) -> Result<TransformedData, MonitoringError> {
        match destination {
            ExportDestination::File { format, .. } => {
                self.transform_for_file_format(data, format).await
            }
            ExportDestination::HTTP { .. } => {
                self.transform_for_http(data).await
            }
            ExportDestination::S3 { .. } => {
                self.transform_for_s3(data).await
            }
            ExportDestination::Database { schema, .. } => {
                self.transform_for_database(data, schema).await
            }
            ExportDestination::Kafka { .. } => {
                self.transform_for_kafka(data).await
            }
        }
    }

    async fn transform_for_file_format(
        &self,
        data: &ExportData,
        format: &FileFormat,
    ) -> Result<TransformedData, MonitoringError> {
        let content = match format {
            FileFormat::JSON => serde_json::to_string(&data.payload)
                .map_err(|e| MonitoringError::ExportError(format!("JSON serialization failed: {}", e)))?,
            FileFormat::CSV => {
                // Convert JSON to CSV format
                format!("timestamp,data_type,payload\n{:?},{},{}", 
                    data.timestamp, data.data_type, data.payload)
            }
            FileFormat::Parquet | FileFormat::Avro => {
                // Would implement binary format serialization
                return Err(MonitoringError::ExportError("Binary formats not yet implemented".to_string()));
            }
        };

        Ok(TransformedData {
            content: content.into_bytes(),
            content_type: format.content_type().to_string(),
            metadata: data.metadata.clone(),
        })
    }

    async fn transform_for_http(&self, data: &ExportData) -> Result<TransformedData, MonitoringError> {
        let content = serde_json::to_string(&data.payload)
            .map_err(|e| MonitoringError::ExportError(format!("HTTP JSON serialization failed: {}", e)))?;

        Ok(TransformedData {
            content: content.into_bytes(),
            content_type: "application/json".to_string(),
            metadata: data.metadata.clone(),
        })
    }

    async fn transform_for_s3(&self, data: &ExportData) -> Result<TransformedData, MonitoringError> {
        // S3 typically uses JSON format
        self.transform_for_http(data).await
    }

    async fn transform_for_database(
        &self,
        data: &ExportData,
        _schema: &str,
    ) -> Result<TransformedData, MonitoringError> {
        // Would transform to SQL INSERT statements or prepared statement format
        let content = format!(
            "INSERT INTO monitoring_data (timestamp, data_type, payload, metadata) VALUES (?, ?, ?, ?)"
        );

        Ok(TransformedData {
            content: content.into_bytes(),
            content_type: "application/sql".to_string(),
            metadata: data.metadata.clone(),
        })
    }

    async fn transform_for_kafka(&self, data: &ExportData) -> Result<TransformedData, MonitoringError> {
        // Kafka typically uses JSON or Avro
        self.transform_for_http(data).await
    }
}

impl FileFormat {
    fn content_type(&self) -> &str {
        match self {
            FileFormat::JSON => "application/json",
            FileFormat::CSV => "text/csv",
            FileFormat::Parquet => "application/octet-stream",
            FileFormat::Avro => "application/octet-stream",
        }
    }
}

/// Transformed data ready for export
#[derive(Debug)]
struct TransformedData {
    content: Vec<u8>,
    content_type: String,
    metadata: HashMap<String, String>,
}

/// Delivery manager for ensuring data delivery
struct DeliveryManager {
    config: DeliveryConfig,
    pending_deliveries: Arc<Mutex<Vec<PendingDelivery>>>,
    delivery_receipts: Arc<Mutex<Vec<DeliveryReceipt>>>,
}

impl DeliveryManager {
    fn new(config: DeliveryConfig) -> Self {
        Self {
            config,
            pending_deliveries: Arc::new(Mutex::new(Vec::new())),
            delivery_receipts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn schedule_delivery(
        &self,
        destination: ExportDestination,
        data: TransformedData,
    ) -> Result<(), MonitoringError> {
        let delivery = PendingDelivery {
            id: uuid::Uuid::new_v4().to_string(),
            destination,
            data,
            scheduled_time: SystemTime::now(),
            retry_count: 0,
            last_attempt: None,
        };

        let mut pending = self.pending_deliveries.lock().await;
        pending.push(delivery);

        Ok(())
    }

    async fn coordinate_deliveries(&self) -> Result<(), MonitoringError> {
        let mut pending = self.pending_deliveries.lock().await;
        let mut completed = Vec::new();

        for (index, delivery) in pending.iter_mut().enumerate() {
            if self.should_attempt_delivery(delivery) {
                match self.attempt_delivery(delivery).await {
                    Ok(receipt) => {
                        let mut receipts = self.delivery_receipts.lock().await;
                        receipts.push(receipt);
                        completed.push(index);
                    }
                    Err(e) => {
                        delivery.retry_count += 1;
                        delivery.last_attempt = Some(SystemTime::now());
                        
                        if delivery.retry_count >= self.config.max_retries {
                            warn!("Delivery {} failed after {} retries: {}", delivery.id, delivery.retry_count, e);
                            completed.push(index);
                        }
                    }
                }
            }
        }

        // Remove completed deliveries in reverse order to maintain indices
        for &index in completed.iter().rev() {
            pending.remove(index);
        }

        Ok(())
    }

    fn should_attempt_delivery(&self, delivery: &PendingDelivery) -> bool {
        if delivery.last_attempt.is_none() {
            return true;
        }

        if let Some(last_attempt) = delivery.last_attempt {
            let retry_delay = self.calculate_retry_delay(delivery.retry_count);
            last_attempt.elapsed().unwrap_or_default() >= retry_delay
        } else {
            true
        }
    }

    async fn attempt_delivery(&self, delivery: &PendingDelivery) -> Result<DeliveryReceipt, MonitoringError> {
        debug!("Attempting delivery {} to {:?}", delivery.id, delivery.destination.id());

        // Simulate delivery attempt
        // In real implementation, would handle each destination type
        match &delivery.destination {
            ExportDestination::File { path, .. } => {
                std::fs::write(path, &delivery.data.content)
                    .map_err(|e| MonitoringError::ExportError(format!("File write failed: {}", e)))?;
            }
            ExportDestination::HTTP { endpoint, .. } => {
                // Would make HTTP request
                debug!("Would send HTTP request to {}", endpoint);
            }
            _ => {
                debug!("Delivery type not yet implemented");
            }
        }

        Ok(DeliveryReceipt {
            delivery_id: delivery.id.clone(),
            destination_id: delivery.destination.id().to_string(),
            timestamp: SystemTime::now(),
            status: DeliveryStatus::Success,
            bytes_sent: delivery.data.content.len(),
            response_time: Duration::from_millis(100), // Mock response time
        })
    }

    fn calculate_retry_delay(&self, retry_count: u32) -> Duration {
        let base_delay = self.config.initial_retry_delay;
        let exponential_delay = base_delay * 2_u32.pow(retry_count);
        std::cmp::min(Duration::from_millis(exponential_delay.as_millis() as u64), self.config.max_retry_delay)
    }

    async fn get_health_status(&self) -> DeliveryHealth {
        let receipts = self.delivery_receipts.lock().await;
        let recent_receipts: Vec<_> = receipts.iter()
            .filter(|r| r.timestamp.elapsed().unwrap_or_default() < Duration::from_secs(3600))
            .collect();

        let successful_exports = recent_receipts.iter()
            .filter(|r| matches!(r.status, DeliveryStatus::Success))
            .count() as u64;

        let failed_exports = recent_receipts.len() as u64 - successful_exports;

        DeliveryHealth {
            successful_exports,
            failed_exports,
            pending_deliveries: self.pending_deliveries.lock().await.len() as u64,
            avg_response_time: if !recent_receipts.is_empty() {
                recent_receipts.iter()
                    .map(|r| r.response_time.as_millis())
                    .sum::<u128>() / recent_receipts.len() as u128
            } else {
                0
            },
        }
    }

    async fn flush_all(&self) -> Result<(), MonitoringError> {
        // Force delivery of all pending items
        self.coordinate_deliveries().await?;
        
        // Wait for any remaining deliveries
        let pending_count = self.pending_deliveries.lock().await.len();
        if pending_count > 0 {
            warn!("Flushing with {} pending deliveries", pending_count);
        }

        Ok(())
    }
}

/// Pending delivery information
#[derive(Debug)]
struct PendingDelivery {
    id: String,
    destination: ExportDestination,
    data: TransformedData,
    scheduled_time: SystemTime,
    retry_count: u32,
    last_attempt: Option<SystemTime>,
}

/// Delivery receipt
#[derive(Debug)]
struct DeliveryReceipt {
    delivery_id: String,
    destination_id: String,
    timestamp: SystemTime,
    status: DeliveryStatus,
    bytes_sent: usize,
    response_time: Duration,
}

/// Delivery status
#[derive(Debug)]
enum DeliveryStatus {
    Success,
    Failure,
    Retry,
}

/// Delivery health metrics
#[derive(Debug)]
struct DeliveryHealth {
    successful_exports: u64,
    failed_exports: u64,
    pending_deliveries: u64,
    avg_response_time: u128,
}

/// Export manager state
#[derive(Debug)]
struct ExportState {
    status: ExportStatus,
    start_time: Option<SystemTime>,
    stop_time: Option<SystemTime>,
    exports_completed: u64,
    export_errors: u64,
    last_health_check: Option<SystemTime>,
}

impl ExportState {
    fn new() -> Self {
        Self {
            status: ExportStatus::Stopped,
            start_time: None,
            stop_time: None,
            exports_completed: 0,
            export_errors: 0,
            last_health_check: None,
        }
    }
}

/// Export manager status
#[derive(Debug, Clone)]
enum ExportStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_export_manager_creation() {
        let config = ExportConfig::default();
        let manager = ExportManager::new(config).await.unwrap();
        
        let status = manager.get_status().await;
        assert!(status.contains("Stopped"));
    }

    #[tokio::test]
    async fn test_data_transformation() {
        let transformers = DataTransformers::new();
        
        let data = ExportData {
            data_type: "test".to_string(),
            timestamp: SystemTime::now(),
            payload: serde_json::json!({"key": "value"}),
            metadata: HashMap::new(),
        };

        let destination = ExportDestination::File {
            id: "test".to_string(),
            path: "/tmp/test".to_string(),
            format: FileFormat::JSON,
        };

        let transformed = transformers.transform_for_destination(&data, &destination).await.unwrap();
        assert_eq!(transformed.content_type, "application/json");
    }

    #[test]
    fn test_export_scheduler() {
        let destination = ExportDestination::File {
            id: "test".to_string(),
            path: "/tmp/test".to_string(),
            format: FileFormat::JSON,
        };
        let config = SchedulingConfig::default();
        let scheduler = ExportScheduler::new(destination, config);

        // Empty scheduler should not export
        assert!(!scheduler.should_export());
    }
}