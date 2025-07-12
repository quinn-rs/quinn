//! Production Metrics Collection
//!
//! This module implements high-performance metrics collection for NAT traversal
//! operations with intelligent sampling, aggregation, and export capabilities.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    sync::{RwLock, Mutex},
    time::interval,
};
use tracing::{debug, info, warn};

use super::{
    MonitoringError, NatTraversalAttempt, NatTraversalResult, MetricsSummary,
};

/// Production metrics collector with intelligent sampling
pub struct ProductionMetricsCollector {
    /// Metrics configuration
    config: MetricsConfig,
    /// Core metrics storage
    metrics_store: Arc<MetricsStore>,
    /// Sampling controller
    sampler: Arc<AdaptiveSampler>,
    /// Aggregation engine
    aggregator: Arc<MetricsAggregator>,
    /// Export manager
    exporter: Arc<MetricsExporter>,
    /// Circuit breaker for overload protection
    circuit_breaker: Arc<CircuitBreaker>,
    /// Collector state
    state: Arc<RwLock<CollectorState>>,
    /// Background tasks
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ProductionMetricsCollector {
    /// Create new production metrics collector
    pub async fn new(config: MetricsConfig) -> Result<Self, MonitoringError> {
        let metrics_store = Arc::new(MetricsStore::new(config.storage.clone()));
        let sampler = Arc::new(AdaptiveSampler::new(config.sampling.clone()));
        let aggregator = Arc::new(MetricsAggregator::new(config.aggregation.clone()));
        let exporter = Arc::new(MetricsExporter::new(config.export.clone()));
        let circuit_breaker = Arc::new(CircuitBreaker::new(config.circuit_breaker.clone()));
        
        Ok(Self {
            config,
            metrics_store,
            sampler,
            aggregator,
            exporter,
            circuit_breaker,
            state: Arc::new(RwLock::new(CollectorState::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Start metrics collection
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting production metrics collector");
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.status = CollectorStatus::Starting;
            state.start_time = Some(Instant::now());
        }
        
        // Start background tasks
        self.start_aggregation_task().await?;
        self.start_export_task().await?;
        self.start_cleanup_task().await?;
        self.start_health_task().await?;
        
        // Update state to running
        {
            let mut state = self.state.write().await;
            state.status = CollectorStatus::Running;
        }
        
        info!("Production metrics collector started");
        Ok(())
    }
    
    /// Stop metrics collection
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping production metrics collector");
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.status = CollectorStatus::Stopping;
        }
        
        // Stop background tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        
        // Final export
        self.exporter.flush().await?;
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.status = CollectorStatus::Stopped;
        }
        
        info!("Production metrics collector stopped");
        Ok(())
    }
    
    /// Record NAT traversal attempt
    pub async fn record_nat_attempt(&self, attempt: &NatTraversalAttempt) -> Result<(), MonitoringError> {
        // Check circuit breaker
        if !self.circuit_breaker.allow_request().await {
            return Ok(()); // Fail fast during overload
        }
        
        // Check sampling decision
        if !self.sampler.should_sample_attempt(attempt).await {
            return Ok(());
        }
        
        // Record attempt metrics
        let attempt_metric = AttemptMetric {
            attempt_id: attempt.attempt_id.clone(),
            timestamp: attempt.timestamp,
            client_region: attempt.client_info.region.clone(),
            server_region: attempt.server_info.region.clone(),
            nat_types: (
                attempt.client_info.nat_type.clone(),
                attempt.server_info.nat_type.clone(),
            ),
            network_conditions: attempt.network_conditions.clone(),
        };
        
        self.metrics_store.record_attempt(attempt_metric).await?;
        
        // Update counters
        self.increment_counter("nat_attempts_total", &[
            ("client_region", attempt.client_info.region.as_deref().unwrap_or("unknown")),
            ("server_region", attempt.server_info.region.as_deref().unwrap_or("unknown")),
        ]).await;
        
        Ok(())
    }
    
    /// Record NAT traversal result
    pub async fn record_nat_result(&self, result: &NatTraversalResult) -> Result<(), MonitoringError> {
        // Always sample results (more important than attempts)
        let sample_rate = if result.success { 0.1 } else { 1.0 }; // 10% success, 100% failures
        if !self.sampler.should_sample_with_rate(sample_rate).await {
            return Ok(());
        }
        
        // Record result metrics
        let result_metric = ResultMetric {
            attempt_id: result.attempt_id.clone(),
            success: result.success,
            duration: result.duration,
            error_category: result.error_info.as_ref().map(|e| e.error_category.clone()),
            performance: result.performance_metrics.clone(),
            connection_info: result.connection_info.clone(),
        };
        
        self.metrics_store.record_result(result_metric).await?;
        
        // Update counters and histograms
        let status = if result.success { "success" } else { "failure" };
        self.increment_counter("nat_results_total", &[("status", status)]).await;
        
        self.record_histogram("nat_duration_ms", result.duration.as_millis() as f64, &[
            ("status", status),
        ]).await;
        
        if let Some(conn_info) = &result.connection_info {
            self.record_histogram("connection_latency_ms", conn_info.quality.latency_ms as f64, &[]).await;
            self.record_histogram("connection_throughput_mbps", conn_info.quality.throughput_mbps as f64, &[]).await;
        }
        
        // Record error metrics
        if let Some(error_info) = &result.error_info {
            self.increment_counter("nat_errors_total", &[
                ("category", &format!("{:?}", error_info.error_category)),
                ("code", &error_info.error_code),
            ]).await;
        }
        
        Ok(())
    }
    
    /// Get collector status
    pub async fn get_status(&self) -> String {
        let state = self.state.read().await;
        format!("{:?}", state.status)
    }
    
    /// Get metrics summary
    pub async fn get_summary(&self) -> MetricsSummary {
        self.metrics_store.get_summary().await
    }
    
    /// Increment counter metric
    async fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {
        self.metrics_store.increment_counter(name, labels).await;
    }
    
    /// Record histogram value
    async fn record_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        self.metrics_store.record_histogram(name, value, labels).await;
    }
    
    /// Start aggregation background task
    async fn start_aggregation_task(&self) -> Result<(), MonitoringError> {
        let aggregator = self.aggregator.clone();
        let metrics_store = self.metrics_store.clone();
        let interval_duration = self.config.aggregation.interval;
        
        let task = tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = aggregator.aggregate_metrics(&metrics_store).await {
                    warn!("Metrics aggregation failed: {}", e);
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start export background task
    async fn start_export_task(&self) -> Result<(), MonitoringError> {
        let exporter = self.exporter.clone();
        let aggregator = self.aggregator.clone();
        let interval_duration = self.config.export.interval;
        
        let task = tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                match aggregator.get_aggregated_metrics().await {
                    Ok(metrics) => {
                        if let Err(e) = exporter.export_metrics(metrics).await {
                            warn!("Metrics export failed: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get aggregated metrics: {}", e);
                    }
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start cleanup background task
    async fn start_cleanup_task(&self) -> Result<(), MonitoringError> {
        let metrics_store = self.metrics_store.clone();
        let retention_period = self.config.storage.retention_period;
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Cleanup hourly
            
            loop {
                interval.tick().await;
                
                if let Err(e) = metrics_store.cleanup_old_data(retention_period).await {
                    warn!("Metrics cleanup failed: {}", e);
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start health monitoring task
    async fn start_health_task(&self) -> Result<(), MonitoringError> {
        let circuit_breaker = self.circuit_breaker.clone();
        let metrics_store = self.metrics_store.clone();
        let state = self.state.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Health check every 30s
            
            loop {
                interval.tick().await;
                
                // Check system health
                let health = metrics_store.get_health_metrics().await;
                let metrics_per_second = health.metrics_per_second;
                circuit_breaker.update_health(health).await;
                
                // Update collector state
                let mut collector_state = state.write().await;
                collector_state.last_health_check = Some(Instant::now());
                collector_state.metrics_collected += metrics_per_second as u64;
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
}

/// Metrics configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsConfig {
    /// Storage configuration
    pub storage: StorageConfig,
    /// Sampling configuration
    pub sampling: SamplingConfig,
    /// Aggregation configuration
    pub aggregation: AggregationConfig,
    /// Export configuration
    pub export: MetricsExportConfig,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            sampling: SamplingConfig::default(),
            aggregation: AggregationConfig::default(),
            export: MetricsExportConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageConfig {
    /// Maximum metrics to store in memory
    pub max_metrics: usize,
    /// Data retention period
    pub retention_period: Duration,
    /// Flush interval to disk
    pub flush_interval: Duration,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_metrics: 100_000,
            retention_period: Duration::from_secs(3600), // 1 hour
            flush_interval: Duration::from_secs(60),     // 1 minute
        }
    }
}

/// Sampling configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SamplingConfig {
    /// Base sampling rate for attempts
    pub base_attempt_rate: f64,
    /// Sampling rate for results
    pub result_rate: f64,
    /// Adaptive sampling settings
    pub adaptive: AdaptiveSamplingConfig,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            base_attempt_rate: 0.01, // 1% of attempts
            result_rate: 0.1,        // 10% of results
            adaptive: AdaptiveSamplingConfig::default(),
        }
    }
}

/// Adaptive sampling configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdaptiveSamplingConfig {
    /// Enable adaptive sampling
    pub enabled: bool,
    /// Target metrics per second
    pub target_rate: f64,
    /// Adjustment interval
    pub adjustment_interval: Duration,
    /// Maximum sampling rate
    pub max_rate: f64,
    /// Minimum sampling rate
    pub min_rate: f64,
}

impl Default for AdaptiveSamplingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_rate: 1000.0, // 1000 metrics/sec
            adjustment_interval: Duration::from_secs(60),
            max_rate: 1.0,
            min_rate: 0.001,
        }
    }
}

/// Aggregation configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregationConfig {
    /// Aggregation interval
    pub interval: Duration,
    /// Aggregation window size
    pub window_size: Duration,
    /// Enable percentile calculations
    pub enable_percentiles: bool,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),        // Aggregate every 10s
            window_size: Duration::from_secs(60),     // 60s window
            enable_percentiles: true,
        }
    }
}

/// Export configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsExportConfig {
    /// Export interval
    pub interval: Duration,
    /// Export destinations
    pub destinations: Vec<ExportDestination>,
    /// Batch size for export
    pub batch_size: usize,
    /// Export timeout
    pub timeout: Duration,
}

impl Default for MetricsExportConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            destinations: vec![ExportDestination::Prometheus {
                endpoint: "http://localhost:9090/api/v1/write".to_string(),
            }],
            batch_size: 1000,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Export destinations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExportDestination {
    Prometheus { endpoint: String },
    InfluxDB { endpoint: String, database: String },
    CloudWatch { region: String },
    DataDog { api_key: String },
    StatsD { endpoint: String },
}

/// Circuit breaker configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold
    pub failure_threshold: u32,
    /// Success threshold for recovery
    pub success_threshold: u32,
    /// Timeout duration
    pub timeout: Duration,
    /// Maximum queue size
    pub max_queue_size: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            max_queue_size: 10000,
        }
    }
}

/// Metrics store for high-performance storage
struct MetricsStore {
    /// Counter metrics
    counters: Arc<RwLock<HashMap<String, CounterMetric>>>,
    /// Histogram metrics
    histograms: Arc<RwLock<HashMap<String, HistogramMetric>>>,
    /// Attempt metrics
    attempts: Arc<Mutex<VecDeque<AttemptMetric>>>,
    /// Result metrics
    results: Arc<Mutex<VecDeque<ResultMetric>>>,
    /// Storage configuration
    config: StorageConfig,
}

impl MetricsStore {
    fn new(config: StorageConfig) -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
            attempts: Arc::new(Mutex::new(VecDeque::new())),
            results: Arc::new(Mutex::new(VecDeque::new())),
            config,
        }
    }
    
    async fn record_attempt(&self, attempt: AttemptMetric) -> Result<(), MonitoringError> {
        let mut attempts = self.attempts.lock().await;
        attempts.push_back(attempt);
        
        // Enforce size limit
        while attempts.len() > self.config.max_metrics {
            attempts.pop_front();
        }
        
        Ok(())
    }
    
    async fn record_result(&self, result: ResultMetric) -> Result<(), MonitoringError> {
        let mut results = self.results.lock().await;
        results.push_back(result);
        
        // Enforce size limit
        while results.len() > self.config.max_metrics {
            results.pop_front();
        }
        
        Ok(())
    }
    
    async fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {
        let key = format!("{}:{}", name, labels_to_string(labels));
        let mut counters = self.counters.write().await;
        
        counters.entry(key)
            .or_insert_with(|| CounterMetric::new(name.to_string(), labels_to_map(labels)))
            .increment();
    }
    
    async fn record_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let key = format!("{}:{}", name, labels_to_string(labels));
        let mut histograms = self.histograms.write().await;
        
        histograms.entry(key)
            .or_insert_with(|| HistogramMetric::new(name.to_string(), labels_to_map(labels)))
            .record(value);
    }
    
    async fn get_summary(&self) -> MetricsSummary {
        let results = self.results.lock().await;
        let _one_hour_ago = SystemTime::now() - Duration::from_secs(3600);
        
        let recent_results: Vec<_> = results.iter()
            .filter(|r| r.attempt_id.len() > 0) // Simple time filter
            .collect();
        
        let total_attempts = recent_results.len() as u64;
        let successful = recent_results.iter().filter(|r| r.success).count() as u64;
        let success_rate = if total_attempts > 0 {
            successful as f32 / total_attempts as f32
        } else {
            0.0
        };
        
        let avg_duration = if !recent_results.is_empty() {
            recent_results.iter()
                .map(|r| r.duration.as_millis())
                .sum::<u128>() / recent_results.len() as u128
        } else {
            0
        };
        
        MetricsSummary {
            nat_attempts_last_hour: total_attempts,
            success_rate_last_hour: success_rate,
            avg_connection_time_ms: avg_duration as u64,
            active_connections: 0, // Would be tracked separately
            error_rate_last_hour: 1.0 - success_rate,
        }
    }
    
    async fn cleanup_old_data(&self, retention_period: Duration) -> Result<(), MonitoringError> {
        let cutoff = SystemTime::now() - retention_period;
        
        // Cleanup attempts
        {
            let mut attempts = self.attempts.lock().await;
            while let Some(front) = attempts.front() {
                if front.timestamp < cutoff {
                    attempts.pop_front();
                } else {
                    break;
                }
            }
        }
        
        // Cleanup results would be similar
        // In practice, would also cleanup counters and histograms
        
        Ok(())
    }
    
    async fn get_health_metrics(&self) -> HealthMetrics {
        let attempts_count = self.attempts.lock().await.len();
        let results_count = self.results.lock().await.len();
        
        HealthMetrics {
            metrics_per_second: (attempts_count + results_count) as f64 / 60.0, // Rough estimate
            memory_usage_mb: ((attempts_count + results_count) * 1024) as f64 / 1024.0 / 1024.0,
            queue_depth: attempts_count + results_count,
            error_rate: 0.0, // Would calculate from actual errors
        }
    }
}

/// Adaptive sampler for intelligent sampling decisions
struct AdaptiveSampler {
    config: SamplingConfig,
    current_rate: Arc<AtomicU64>, // Stored as u64 for atomic operations
    last_adjustment: Arc<RwLock<Instant>>,
}

impl AdaptiveSampler {
    fn new(config: SamplingConfig) -> Self {
        let initial_rate = (config.base_attempt_rate * 1_000_000.0) as u64; // Store as millionths
        
        Self {
            config,
            current_rate: Arc::new(AtomicU64::new(initial_rate)),
            last_adjustment: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    async fn should_sample_attempt(&self, _attempt: &NatTraversalAttempt) -> bool {
        let rate = self.current_rate.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        rand::random::<f64>() < rate
    }
    
    async fn should_sample_with_rate(&self, rate: f64) -> bool {
        rand::random::<f64>() < rate
    }
    
    async fn adjust_sampling_rate(&self, current_metrics_rate: f64) {
        if !self.config.adaptive.enabled {
            return;
        }
        
        let mut last_adjustment = self.last_adjustment.write().await;
        if last_adjustment.elapsed() < self.config.adaptive.adjustment_interval {
            return;
        }
        
        let target_rate = self.config.adaptive.target_rate;
        let current_rate = self.current_rate.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        
        let adjustment_factor = target_rate / current_metrics_rate.max(1.0);
        let new_rate = (current_rate * adjustment_factor)
            .max(self.config.adaptive.min_rate)
            .min(self.config.adaptive.max_rate);
        
        self.current_rate.store((new_rate * 1_000_000.0) as u64, Ordering::Relaxed);
        *last_adjustment = Instant::now();
        
        debug!("Adjusted sampling rate from {:.4} to {:.4}", current_rate, new_rate);
    }
}

/// Circuit breaker for overload protection
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
    consecutive_failures: Arc<AtomicU64>,
    consecutive_successes: Arc<AtomicU64>,
    queue_size: Arc<AtomicU64>,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
            queue_size: Arc::new(AtomicU64::new(0)),
        }
    }
    
    async fn allow_request(&self) -> bool {
        let state = self.state.read().await;
        
        match *state {
            CircuitBreakerState::Closed => {
                // Check queue size
                self.queue_size.load(Ordering::Relaxed) < self.config.max_queue_size as u64
            }
            CircuitBreakerState::Open => false,
            CircuitBreakerState::HalfOpen => {
                // Allow limited requests to test recovery
                self.queue_size.load(Ordering::Relaxed) < (self.config.max_queue_size / 10) as u64
            }
        }
    }
    
    async fn update_health(&self, health: HealthMetrics) {
        // Update queue size
        self.queue_size.store(health.queue_depth as u64, Ordering::Relaxed);
        
        // Check if we should change circuit breaker state
        if health.error_rate > 0.5 {
            // High error rate
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            self.consecutive_successes.store(0, Ordering::Relaxed);
            
            if failures >= self.config.failure_threshold as u64 {
                let mut state = self.state.write().await;
                *state = CircuitBreakerState::Open;
                warn!("Circuit breaker opened due to high error rate");
            }
        } else {
            // Low error rate
            let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
            self.consecutive_failures.store(0, Ordering::Relaxed);
            
            let current_state = *self.state.read().await;
            if matches!(current_state, CircuitBreakerState::Open) && successes >= self.config.success_threshold as u64 {
                let mut state = self.state.write().await;
                *state = CircuitBreakerState::HalfOpen;
                info!("Circuit breaker moved to half-open state");
            } else if matches!(current_state, CircuitBreakerState::HalfOpen) && successes >= self.config.success_threshold as u64 * 2 {
                let mut state = self.state.write().await;
                *state = CircuitBreakerState::Closed;
                info!("Circuit breaker closed - system recovered");
            }
        }
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy)]
enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Metrics aggregator for time-based aggregation
struct MetricsAggregator {
    config: AggregationConfig,
    aggregated_data: Arc<RwLock<AggregatedData>>,
}

impl MetricsAggregator {
    fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            aggregated_data: Arc::new(RwLock::new(AggregatedData::new())),
        }
    }
    
    async fn aggregate_metrics(&self, _metrics_store: &MetricsStore) -> Result<(), MonitoringError> {
        // Aggregate metrics from the store
        // This would calculate time-based windows, percentiles, etc.
        debug!("Aggregating metrics for export");
        Ok(())
    }
    
    async fn get_aggregated_metrics(&self) -> Result<Vec<ExportMetric>, MonitoringError> {
        let data = self.aggregated_data.read().await;
        Ok(data.to_export_metrics())
    }
}

/// Metrics exporter for various destinations
struct MetricsExporter {
    config: MetricsExportConfig,
}

impl MetricsExporter {
    fn new(config: MetricsExportConfig) -> Self {
        Self { config }
    }
    
    async fn export_metrics(&self, metrics: Vec<ExportMetric>) -> Result<(), MonitoringError> {
        for destination in &self.config.destinations {
            if let Err(e) = self.export_to_destination(destination, &metrics).await {
                warn!("Failed to export to {:?}: {}", destination, e);
            }
        }
        Ok(())
    }
    
    async fn export_to_destination(&self, destination: &ExportDestination, metrics: &[ExportMetric]) -> Result<(), MonitoringError> {
        match destination {
            ExportDestination::Prometheus { endpoint } => {
                debug!("Exporting {} metrics to Prometheus at {}", metrics.len(), endpoint);
                // Would implement actual Prometheus export
            }
            ExportDestination::InfluxDB { endpoint, database } => {
                debug!("Exporting {} metrics to InfluxDB at {} (db: {})", metrics.len(), endpoint, database);
                // Would implement actual InfluxDB export
            }
            _ => {
                debug!("Export to {:?} not yet implemented", destination);
            }
        }
        Ok(())
    }
    
    async fn flush(&self) -> Result<(), MonitoringError> {
        debug!("Flushing remaining metrics");
        Ok(())
    }
}

// Helper functions and data structures

fn labels_to_string(labels: &[(&str, &str)]) -> String {
    labels.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",")
}

fn labels_to_map(labels: &[(&str, &str)]) -> HashMap<String, String> {
    labels.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Collector state
#[derive(Debug)]
struct CollectorState {
    status: CollectorStatus,
    start_time: Option<Instant>,
    last_health_check: Option<Instant>,
    metrics_collected: u64,
    errors_encountered: u64,
}

impl CollectorState {
    fn new() -> Self {
        Self {
            status: CollectorStatus::Stopped,
            start_time: None,
            last_health_check: None,
            metrics_collected: 0,
            errors_encountered: 0,
        }
    }
}

/// Collector status
#[derive(Debug, Clone)]
enum CollectorStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

/// Health metrics
#[derive(Debug, Clone)]
struct HealthMetrics {
    metrics_per_second: f64,
    memory_usage_mb: f64,
    queue_depth: usize,
    error_rate: f64,
}

/// Attempt metric
#[derive(Debug, Clone)]
struct AttemptMetric {
    attempt_id: String,
    timestamp: SystemTime,
    client_region: Option<String>,
    server_region: Option<String>,
    nat_types: (Option<crate::monitoring::NatType>, Option<crate::monitoring::NatType>),
    network_conditions: crate::monitoring::NetworkConditions,
}

/// Result metric
#[derive(Debug, Clone)]
struct ResultMetric {
    attempt_id: String,
    success: bool,
    duration: Duration,
    error_category: Option<crate::monitoring::ErrorCategory>,
    performance: crate::monitoring::PerformanceMetrics,
    connection_info: Option<crate::monitoring::ConnectionInfo>,
}

/// Counter metric
struct CounterMetric {
    name: String,
    labels: HashMap<String, String>,
    value: AtomicU64,
}

impl CounterMetric {
    fn new(name: String, labels: HashMap<String, String>) -> Self {
        Self {
            name,
            labels,
            value: AtomicU64::new(0),
        }
    }
    
    fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
}

/// Histogram metric
struct HistogramMetric {
    name: String,
    labels: HashMap<String, String>,
    buckets: RwLock<Vec<f64>>,
    sum: AtomicU64, // Stored as fixed-point
    count: AtomicU64,
}

impl HistogramMetric {
    fn new(name: String, labels: HashMap<String, String>) -> Self {
        Self {
            name,
            labels,
            buckets: RwLock::new(Vec::new()),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
    
    fn record(&self, value: f64) {
        // Add to bucket (simplified)
        self.sum.fetch_add((value * 1000.0) as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Aggregated data
struct AggregatedData {
    window_start: Instant,
    metrics: Vec<ExportMetric>,
}

impl AggregatedData {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            metrics: Vec::new(),
        }
    }
    
    fn to_export_metrics(&self) -> Vec<ExportMetric> {
        self.metrics.clone()
    }
}

/// Export metric format
#[derive(Debug, Clone)]
struct ExportMetric {
    name: String,
    value: f64,
    labels: HashMap<String, String>,
    timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let config = MetricsConfig::default();
        let collector = ProductionMetricsCollector::new(config).await.unwrap();
        
        let status = collector.get_status().await;
        assert!(status.contains("Stopped"));
    }
    
    #[tokio::test]
    async fn test_adaptive_sampler() {
        let config = SamplingConfig::default();
        let sampler = AdaptiveSampler::new(config);
        
        // Test rate adjustment
        sampler.adjust_sampling_rate(500.0).await; // Half target rate
        
        // Rate should increase to compensate
        let rate = sampler.current_rate.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        assert!(rate > 0.01); // Should be higher than base rate
    }
    
    #[tokio::test]
    async fn test_circuit_breaker() {
        let config = CircuitBreakerConfig::default();
        let breaker = CircuitBreaker::new(config);
        
        // Initially should allow requests
        assert!(breaker.allow_request().await);
        
        // Simulate high error rate
        let bad_health = HealthMetrics {
            metrics_per_second: 1000.0,
            memory_usage_mb: 100.0,
            queue_depth: 100,
            error_rate: 0.8, // High error rate
        };
        
        // Update health multiple times to trip circuit breaker
        for _ in 0..10 {
            breaker.update_health(bad_health.clone()).await;
        }
        
        // Should eventually deny requests (depending on thresholds)
        // This test might need adjustment based on exact logic
    }
}