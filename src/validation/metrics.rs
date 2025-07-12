//! Metrics Collection and Analysis
//!
//! This module provides comprehensive metrics collection, aggregation,
//! and analysis capabilities for validation testing.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::validation::{
    ValidationError, MetricType, MetricsExportConfig, ExportFormat,
};

/// Metrics collection and analysis system
pub struct ValidationMetricsCollector {
    /// Collected metrics data
    metrics: Arc<RwLock<MetricsStorage>>,
    /// Collection configuration
    config: MetricsCollectionConfig,
    /// Export configuration
    export_config: Option<MetricsExportConfig>,
    /// Active collection tasks
    collection_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ValidationMetricsCollector {
    /// Create new metrics collector
    pub fn new(config: MetricsCollectionConfig, export_config: Option<MetricsExportConfig>) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(MetricsStorage::new())),
            config,
            export_config,
            collection_handles: Vec::new(),
        }
    }
    
    /// Start metrics collection
    pub async fn start_collection(&mut self) -> Result<(), ValidationError> {
        info!("Starting metrics collection with {} enabled metrics", self.config.enabled_metrics.len());
        
        // Start collection tasks for each metric type
        for metric_type in &self.config.enabled_metrics {
            let handle = self.start_metric_collection(metric_type.clone()).await?;
            self.collection_handles.push(handle);
        }
        
        // Start export task if configured
        if let Some(export_config) = &self.export_config {
            let export_handle = self.start_export_task(export_config.clone()).await?;
            self.collection_handles.push(export_handle);
        }
        
        Ok(())
    }
    
    /// Start collection for specific metric type
    async fn start_metric_collection(&self, metric_type: MetricType) -> Result<tokio::task::JoinHandle<()>, ValidationError> {
        let metrics = self.metrics.clone();
        let interval = self.config.collection_interval;
        
        let handle = tokio::spawn(async move {
            let mut collection_interval = tokio::time::interval(interval);
            
            loop {
                collection_interval.tick().await;
                
                let metric_value = match Self::collect_metric_value(&metric_type).await {
                    Ok(value) => value,
                    Err(e) => {
                        warn!("Failed to collect metric {:?}: {}", metric_type, e);
                        continue;
                    }
                };
                
                let mut storage = metrics.write().await;
                storage.record_metric(metric_type.clone(), metric_value).await;
            }
        });
        
        Ok(handle)
    }
    
    /// Collect value for specific metric type
    async fn collect_metric_value(metric_type: &MetricType) -> Result<MetricValue, ValidationError> {
        match metric_type {
            MetricType::ConnectionSuccess => {
                // In real implementation, would query connection tracking
                Ok(MetricValue::Counter(rand::random::<u64>() % 100))
            }
            MetricType::ConnectionLatency => {
                // In real implementation, would measure actual latency
                Ok(MetricValue::Gauge(rand::random::<f64>() * 100.0))
            }
            MetricType::Throughput => {
                // In real implementation, would measure actual throughput
                Ok(MetricValue::Gauge(rand::random::<f64>() * 1000.0))
            }
            MetricType::PacketLoss => {
                // In real implementation, would calculate packet loss
                Ok(MetricValue::Gauge(rand::random::<f64>() * 0.05))
            }
            MetricType::ResourceUsage => {
                // In real implementation, would query system resources
                Ok(MetricValue::Histogram(vec![
                    rand::random::<f64>() * 100.0,
                    rand::random::<f64>() * 100.0,
                    rand::random::<f64>() * 100.0,
                ]))
            }
            MetricType::ErrorRates => {
                // In real implementation, would track error rates
                Ok(MetricValue::Counter(rand::random::<u64>() % 10))
            }
            MetricType::NatTraversalStats => {
                // In real implementation, would query NAT traversal statistics
                Ok(MetricValue::Gauge(rand::random::<f64>() * 1.0))
            }
        }
    }
    
    /// Start export task
    async fn start_export_task(&self, export_config: MetricsExportConfig) -> Result<tokio::task::JoinHandle<()>, ValidationError> {
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut export_interval = tokio::time::interval(export_config.interval);
            
            loop {
                export_interval.tick().await;
                
                let storage = metrics.read().await;
                if let Err(e) = Self::export_metrics(&storage, &export_config).await {
                    warn!("Failed to export metrics: {}", e);
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Export metrics to configured destination
    async fn export_metrics(storage: &MetricsStorage, config: &MetricsExportConfig) -> Result<(), ValidationError> {
        let exported_data = match config.format {
            ExportFormat::Json => storage.export_json().await?,
            ExportFormat::Csv => storage.export_csv().await?,
            ExportFormat::Prometheus => storage.export_prometheus().await?,
            ExportFormat::InfluxDb => storage.export_influxdb().await?,
        };
        
        info!("Exported {} bytes of metrics data to {}", exported_data.len(), config.destination);
        
        // In real implementation, would write to actual destination
        debug!("Exported metrics: {}", String::from_utf8_lossy(&exported_data[..100.min(exported_data.len())]));
        
        Ok(())
    }
    
    /// Record a custom metric
    pub async fn record_metric(&self, metric_type: MetricType, value: MetricValue) {
        let mut storage = self.metrics.write().await;
        storage.record_metric(metric_type, value).await;
    }
    
    /// Get aggregated metrics for time period
    pub async fn get_aggregated_metrics(&self, period: Duration) -> HashMap<MetricType, AggregatedMetric> {
        let storage = self.metrics.read().await;
        storage.get_aggregated_metrics(period).await
    }
    
    /// Generate metrics summary report
    pub async fn generate_summary_report(&self, period: Duration) -> MetricsSummaryReport {
        let storage = self.metrics.read().await;
        storage.generate_summary_report(period).await
    }
    
    /// Cleanup old metrics data
    pub async fn cleanup_old_data(&self) {
        let mut storage = self.metrics.write().await;
        storage.cleanup_old_data(self.config.retention_period).await;
    }
    
    /// Stop all collection tasks
    pub async fn stop_collection(&mut self) {
        info!("Stopping metrics collection");
        
        for handle in self.collection_handles.drain(..) {
            handle.abort();
        }
    }
}

/// Metrics collection configuration
#[derive(Debug, Clone)]
pub struct MetricsCollectionConfig {
    /// Collection interval
    pub collection_interval: Duration,
    /// Enabled metric types
    pub enabled_metrics: Vec<MetricType>,
    /// Data retention period
    pub retention_period: Duration,
    /// Maximum data points per metric
    pub max_data_points: usize,
}

/// Metrics storage backend
struct MetricsStorage {
    /// Time series data for each metric
    time_series: HashMap<MetricType, TimeSeries>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl MetricsStorage {
    /// Create new metrics storage
    fn new() -> Self {
        Self {
            time_series: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
    
    /// Record a metric value
    async fn record_metric(&mut self, metric_type: MetricType, value: MetricValue) {
        let time_series = self.time_series.entry(metric_type).or_insert_with(TimeSeries::new);
        time_series.add_point(DataPoint {
            timestamp: SystemTime::now(),
            value,
        });
    }
    
    /// Get aggregated metrics for time period
    async fn get_aggregated_metrics(&self, period: Duration) -> HashMap<MetricType, AggregatedMetric> {
        let mut result = HashMap::new();
        let cutoff = SystemTime::now() - period;
        
        for (metric_type, time_series) in &self.time_series {
            let aggregated = time_series.aggregate_since(cutoff);
            result.insert(metric_type.clone(), aggregated);
        }
        
        result
    }
    
    /// Generate summary report
    async fn generate_summary_report(&self, period: Duration) -> MetricsSummaryReport {
        let aggregated = self.get_aggregated_metrics(period).await;
        
        MetricsSummaryReport {
            period,
            total_metrics: self.time_series.len(),
            total_data_points: self.time_series.values().map(|ts| ts.data_points.len()).sum(),
            metrics: aggregated,
            generated_at: SystemTime::now(),
        }
    }
    
    /// Export metrics as JSON
    async fn export_json(&self) -> Result<Vec<u8>, ValidationError> {
        let export_data = ExportData {
            timestamp: SystemTime::now(),
            metrics: self.time_series.clone(),
        };
        
        serde_json::to_vec_pretty(&export_data)
            .map_err(|e| ValidationError::MetricError(format!("JSON export failed: {}", e)))
    }
    
    /// Export metrics as CSV
    async fn export_csv(&self) -> Result<Vec<u8>, ValidationError> {
        let mut csv_data = String::new();
        csv_data.push_str("timestamp,metric_type,value\n");
        
        for (metric_type, time_series) in &self.time_series {
            for point in &time_series.data_points {
                let timestamp = point.timestamp.duration_since(UNIX_EPOCH)
                    .unwrap_or_default().as_secs();
                csv_data.push_str(&format!("{},{:?},{}\n", timestamp, metric_type, point.value));
            }
        }
        
        Ok(csv_data.into_bytes())
    }
    
    /// Export metrics in Prometheus format
    async fn export_prometheus(&self) -> Result<Vec<u8>, ValidationError> {
        let mut prom_data = String::new();
        
        for (metric_type, time_series) in &self.time_series {
            if let Some(latest) = time_series.data_points.back() {
                prom_data.push_str(&format!("# HELP {:?} Latest metric value\n", metric_type));
                prom_data.push_str(&format!("# TYPE {:?} gauge\n", metric_type));
                prom_data.push_str(&format!("{:?} {}\n", metric_type, latest.value));
            }
        }
        
        Ok(prom_data.into_bytes())
    }
    
    /// Export metrics in InfluxDB line protocol
    async fn export_influxdb(&self) -> Result<Vec<u8>, ValidationError> {
        let mut influx_data = String::new();
        
        for (metric_type, time_series) in &self.time_series {
            for point in &time_series.data_points {
                let timestamp = point.timestamp.duration_since(UNIX_EPOCH)
                    .unwrap_or_default().as_nanos();
                influx_data.push_str(&format!("validation_metric,type={:?} value={} {}\n", 
                    metric_type, point.value, timestamp));
            }
        }
        
        Ok(influx_data.into_bytes())
    }
    
    /// Cleanup old data points
    async fn cleanup_old_data(&mut self, retention_period: Duration) {
        let cutoff = SystemTime::now() - retention_period;
        
        for time_series in self.time_series.values_mut() {
            time_series.remove_before(cutoff);
        }
        
        self.last_cleanup = Instant::now();
    }
}

/// Time series data for a metric
#[derive(Debug, Clone, serde::Serialize)]
struct TimeSeries {
    /// Data points
    data_points: VecDeque<DataPoint>,
    /// Maximum number of points to keep
    max_points: usize,
}

impl TimeSeries {
    /// Create new time series
    fn new() -> Self {
        Self {
            data_points: VecDeque::new(),
            max_points: 10000,
        }
    }
    
    /// Add a data point
    fn add_point(&mut self, point: DataPoint) {
        self.data_points.push_back(point);
        
        // Enforce maximum points limit
        while self.data_points.len() > self.max_points {
            self.data_points.pop_front();
        }
    }
    
    /// Remove points before cutoff time
    fn remove_before(&mut self, cutoff: SystemTime) {
        while let Some(front) = self.data_points.front() {
            if front.timestamp < cutoff {
                self.data_points.pop_front();
            } else {
                break;
            }
        }
    }
    
    /// Aggregate data since cutoff time
    fn aggregate_since(&self, cutoff: SystemTime) -> AggregatedMetric {
        let relevant_points: Vec<_> = self.data_points.iter()
            .filter(|p| p.timestamp >= cutoff)
            .collect();
        
        if relevant_points.is_empty() {
            return AggregatedMetric::default();
        }
        
        let count = relevant_points.len() as f64;
        let sum = relevant_points.iter().map(|p| p.value.as_f64()).sum::<f64>();
        let mean = sum / count;
        
        let mut values: Vec<f64> = relevant_points.iter().map(|p| p.value.as_f64()).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let min = values[0];
        let max = values[values.len() - 1];
        let median = if values.len() % 2 == 0 {
            (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
        } else {
            values[values.len() / 2]
        };
        
        let p95_index = ((values.len() as f64) * 0.95) as usize;
        let p95 = values[p95_index.min(values.len() - 1)];
        
        AggregatedMetric {
            count: count as u64,
            sum,
            mean,
            min,
            max,
            median,
            p95,
            std_dev: Self::calculate_std_dev(&values, mean),
        }
    }
    
    /// Calculate standard deviation
    fn calculate_std_dev(values: &[f64], mean: f64) -> f64 {
        if values.len() <= 1 {
            return 0.0;
        }
        
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / (values.len() - 1) as f64;
        
        variance.sqrt()
    }
}

/// Individual metric data point
#[derive(Debug, Clone, serde::Serialize)]
struct DataPoint {
    /// Timestamp when metric was recorded
    timestamp: SystemTime,
    /// Metric value
    value: MetricValue,
}

/// Metric value types
#[derive(Debug, Clone, serde::Serialize)]
pub enum MetricValue {
    /// Counter value (monotonically increasing)
    Counter(u64),
    /// Gauge value (can increase or decrease)
    Gauge(f64),
    /// Histogram values
    Histogram(Vec<f64>),
}

impl MetricValue {
    /// Convert to f64 for aggregation
    fn as_f64(&self) -> f64 {
        match self {
            MetricValue::Counter(v) => *v as f64,
            MetricValue::Gauge(v) => *v,
            MetricValue::Histogram(values) => {
                values.iter().sum::<f64>() / values.len() as f64
            }
        }
    }
}

impl std::fmt::Display for MetricValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricValue::Counter(v) => write!(f, "{}", v),
            MetricValue::Gauge(v) => write!(f, "{:.2}", v),
            MetricValue::Histogram(values) => {
                write!(f, "[{}]", values.iter()
                    .map(|v| format!("{:.2}", v))
                    .collect::<Vec<_>>()
                    .join(", "))
            }
        }
    }
}

/// Aggregated metric statistics
#[derive(Debug, Clone, Default)]
pub struct AggregatedMetric {
    /// Number of data points
    pub count: u64,
    /// Sum of all values
    pub sum: f64,
    /// Mean value
    pub mean: f64,
    /// Minimum value
    pub min: f64,
    /// Maximum value
    pub max: f64,
    /// Median value
    pub median: f64,
    /// 95th percentile
    pub p95: f64,
    /// Standard deviation
    pub std_dev: f64,
}

/// Export data structure
#[derive(serde::Serialize)]
struct ExportData {
    timestamp: SystemTime,
    metrics: HashMap<MetricType, TimeSeries>,
}

/// Metrics summary report
#[derive(Debug)]
pub struct MetricsSummaryReport {
    /// Report period
    pub period: Duration,
    /// Total number of metric types
    pub total_metrics: usize,
    /// Total data points
    pub total_data_points: usize,
    /// Aggregated metrics
    pub metrics: HashMap<MetricType, AggregatedMetric>,
    /// Report generation time
    pub generated_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let config = MetricsCollectionConfig {
            collection_interval: Duration::from_millis(100),
            enabled_metrics: vec![MetricType::ConnectionSuccess],
            retention_period: Duration::from_secs(3600),
            max_data_points: 1000,
        };
        
        let mut collector = ValidationMetricsCollector::new(config, None);
        
        // Test metric recording
        collector.record_metric(MetricType::ConnectionSuccess, MetricValue::Counter(100)).await;
        
        let aggregated = collector.get_aggregated_metrics(Duration::from_secs(60)).await;
        assert!(aggregated.contains_key(&MetricType::ConnectionSuccess));
    }
    
    #[test]
    fn test_metric_value_conversion() {
        let counter = MetricValue::Counter(42);
        assert_eq!(counter.as_f64(), 42.0);
        
        let gauge = MetricValue::Gauge(3.14);
        assert_eq!(gauge.as_f64(), 3.14);
        
        let histogram = MetricValue::Histogram(vec![1.0, 2.0, 3.0]);
        assert_eq!(histogram.as_f64(), 2.0);
    }
    
    #[test]
    fn test_time_series_aggregation() {
        let mut ts = TimeSeries::new();
        let now = SystemTime::now();
        
        ts.add_point(DataPoint {
            timestamp: now,
            value: MetricValue::Gauge(10.0),
        });
        ts.add_point(DataPoint {
            timestamp: now,
            value: MetricValue::Gauge(20.0),
        });
        ts.add_point(DataPoint {
            timestamp: now,
            value: MetricValue::Gauge(30.0),
        });
        
        let aggregated = ts.aggregate_since(now - Duration::from_secs(60));
        assert_eq!(aggregated.count, 3);
        assert_eq!(aggregated.mean, 20.0);
        assert_eq!(aggregated.min, 10.0);
        assert_eq!(aggregated.max, 30.0);
    }
}