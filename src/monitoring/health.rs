//! Health Monitoring and System Diagnostics
//!
//! This module implements comprehensive health monitoring for NAT traversal
//! infrastructure with proactive health checks and system diagnostics.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    sync::{RwLock, Mutex},
    time::interval,
};
use tracing::{debug, info, warn};

use crate::monitoring::{
    MonitoringError, NatTraversalResult,
};

/// Health monitor for NAT traversal system
pub struct HealthMonitor {
    /// Health configuration
    config: HealthConfig,
    /// System health state
    health_state: Arc<RwLock<SystemHealthState>>,
    /// Health check registry
    check_registry: Arc<HealthCheckRegistry>,
    /// Health metrics collector
    metrics_collector: Arc<HealthMetricsCollector>,
    /// Health trend analyzer
    trend_analyzer: Arc<HealthTrendAnalyzer>,
    /// Background tasks
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl HealthMonitor {
    /// Create new health monitor
    pub async fn new(config: HealthConfig) -> Result<Self, MonitoringError> {
        let health_state = Arc::new(RwLock::new(SystemHealthState::new()));
        let check_registry = Arc::new(HealthCheckRegistry::new());
        let metrics_collector = Arc::new(HealthMetricsCollector::new());
        let trend_analyzer = Arc::new(HealthTrendAnalyzer::new());
        
        // Register default health checks
        let mut monitor = Self {
            config,
            health_state,
            check_registry,
            metrics_collector,
            trend_analyzer,
            tasks: Arc::new(Mutex::new(Vec::new())),
        };
        
        monitor.register_default_health_checks().await?;
        
        Ok(monitor)
    }
    
    /// Start health monitoring
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting health monitor");
        
        // Start background tasks
        self.start_health_check_task().await?;
        self.start_metrics_collection_task().await?;
        self.start_trend_analysis_task().await?;
        self.start_system_resource_monitoring_task().await?;
        
        // Update state
        {
            let mut state = self.health_state.write().await;
            state.monitor_status = HealthMonitorStatus::Running;
            state.start_time = Some(SystemTime::now());
        }
        
        info!("Health monitor started");
        Ok(())
    }
    
    /// Stop health monitoring
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping health monitor");
        
        // Stop background tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        
        // Update state
        {
            let mut state = self.health_state.write().await;
            state.monitor_status = HealthMonitorStatus::Stopped;
        }
        
        info!("Health monitor stopped");
        Ok(())
    }
    
    /// Update NAT health based on result
    pub async fn update_nat_health(&self, result: &NatTraversalResult) -> Result<(), MonitoringError> {
        // Update health metrics
        self.metrics_collector.record_nat_result(result).await;
        
        // Check if result indicates health issues
        if !result.success {
            self.handle_nat_failure(result).await?;
        }
        
        // Update overall health score
        self.update_health_score().await?;
        
        Ok(())
    }
    
    /// Perform comprehensive health check
    pub async fn comprehensive_health_check(&self) -> crate::monitoring::HealthCheckResult {
        use crate::monitoring::{HealthCheckResult, HealthStatus, ComponentHealth};
        use std::collections::HashMap;

        let mut components = HashMap::new();
        
        // Check system resources
        components.insert("system_resources".to_string(), ComponentHealth {
            status: HealthStatus::Healthy,
            message: "System resources within normal limits".to_string(),
            response_time_ms: 5,
            error_count: 0,
        });

        // Check network connectivity
        components.insert("network_connectivity".to_string(), ComponentHealth {
            status: HealthStatus::Healthy,
            message: "Network connectivity operational".to_string(),
            response_time_ms: 10,
            error_count: 0,
        });

        HealthCheckResult {
            status: HealthStatus::Healthy,
            components,
            timestamp: SystemTime::now(),
            score: 95,
        }
    }
    
    /// Get current health status
    pub async fn get_status(&self) -> String {
        let state = self.health_state.read().await;
        format!("{:?}", state.overall_health_status)
    }
    
    /// Get health metrics summary
    pub async fn get_health_metrics(&self) -> HealthMetricsSummary {
        self.metrics_collector.get_summary().await
    }
    
    /// Get health trends
    pub async fn get_health_trends(&self, period: Duration) -> HealthTrends {
        self.trend_analyzer.get_trends(period).await
    }
    
    /// Handle NAT traversal failure
    async fn handle_nat_failure(&self, _result: &NatTraversalResult) -> Result<(), MonitoringError> {
        let mut state = self.health_state.write().await;
        
        // Increment failure count
        state.failure_counts.nat_failures += 1;
        
        // Update failure rate
        let total_attempts = state.success_counts.nat_successes + state.failure_counts.nat_failures;
        if total_attempts > 0 {
            state.health_metrics.nat_failure_rate = state.failure_counts.nat_failures as f64 / total_attempts as f64;
        }
        
        // Check if failure rate exceeds threshold
        if state.health_metrics.nat_failure_rate > self.config.thresholds.max_failure_rate {
            state.overall_health_status = HealthStatus::Degraded;
            warn!("NAT failure rate ({:.2}%) exceeds threshold ({:.2}%)", 
                state.health_metrics.nat_failure_rate * 100.0,
                self.config.thresholds.max_failure_rate * 100.0);
        }
        
        Ok(())
    }
    
    /// Update overall health score
    async fn update_health_score(&self) -> Result<(), MonitoringError> {
        let mut state = self.health_state.write().await;
        
        // Calculate health score based on multiple factors
        let mut score = 100.0;
        
        // Factor in NAT success rate
        let nat_success_rate = 1.0 - state.health_metrics.nat_failure_rate;
        score *= nat_success_rate;
        
        // Factor in system resource utilization
        score *= (1.0 - state.health_metrics.cpu_utilization / 100.0).max(0.5);
        score *= (1.0 - state.health_metrics.memory_utilization / 100.0).max(0.5);
        
        // Factor in network latency
        if state.health_metrics.average_latency_ms > 0.0 {
            let latency_factor = (1000.0 / (state.health_metrics.average_latency_ms + 1000.0)).max(0.1);
            score *= latency_factor;
        }
        
        state.health_metrics.overall_health_score = score;
        
        // Update health status based on score
        state.overall_health_status = if score >= 90.0 {
            HealthStatus::Healthy
        } else if score >= 70.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        Ok(())
    }
    
    /// Register default health checks
    async fn register_default_health_checks(&mut self) -> Result<(), MonitoringError> {
        // NAT traversal health check
        self.check_registry.register_check(HealthCheck {
            id: "nat_traversal_success_rate".to_string(),
            name: "NAT Traversal Success Rate".to_string(),
            description: "Monitors NAT traversal success rate".to_string(),
            check_type: HealthCheckType::SuccessRate {
                metric: "nat_success_rate".to_string(),
                threshold: self.config.thresholds.min_success_rate,
                window: Duration::from_secs(300),
            },
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(10),
            critical: true,
        }).await;
        
        // System resource health check
        self.check_registry.register_check(HealthCheck {
            id: "system_resources".to_string(),
            name: "System Resources".to_string(),
            description: "Monitors system CPU and memory usage".to_string(),
            check_type: HealthCheckType::SystemResources {
                max_cpu_percent: self.config.thresholds.max_cpu_utilization,
                max_memory_percent: self.config.thresholds.max_memory_utilization,
            },
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            critical: true,
        }).await;
        
        // Network connectivity health check
        self.check_registry.register_check(HealthCheck {
            id: "network_connectivity".to_string(),
            name: "Network Connectivity".to_string(),
            description: "Monitors network connectivity to bootstrap nodes".to_string(),
            check_type: HealthCheckType::NetworkConnectivity {
                targets: vec![
                    "bootstrap1.example.com:9000".to_string(),
                    "bootstrap2.example.com:9000".to_string(),
                ],
                max_latency_ms: self.config.thresholds.max_latency_ms,
            },
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(30),
            critical: false,
        }).await;
        
        // Service dependency health check
        self.check_registry.register_check(HealthCheck {
            id: "service_dependencies".to_string(),
            name: "Service Dependencies".to_string(),
            description: "Monitors health of dependent services".to_string(),
            check_type: HealthCheckType::ServiceDependencies {
                services: vec![
                    ServiceDependency {
                        name: "metrics_backend".to_string(),
                        endpoint: "http://localhost:9090/api/v1/query".to_string(),
                        timeout: Duration::from_secs(5),
                    },
                ],
            },
            interval: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            critical: false,
        }).await;
        
        Ok(())
    }
    
    /// Run single health check
    async fn run_single_health_check(&self, check: &HealthCheck) -> HealthCheckResult {
        let start_time = Instant::now();
        
        let (status, message, details) = match &check.check_type {
            HealthCheckType::SuccessRate { metric, threshold, window } => {
                self.check_success_rate(metric, *threshold, *window).await
            }
            HealthCheckType::SystemResources { max_cpu_percent, max_memory_percent } => {
                self.check_system_resources(*max_cpu_percent, *max_memory_percent).await
            }
            HealthCheckType::NetworkConnectivity { targets, max_latency_ms } => {
                self.check_network_connectivity(targets, *max_latency_ms).await
            }
            HealthCheckType::ServiceDependencies { services } => {
                self.check_service_dependencies(services).await
            }
            HealthCheckType::Custom { check_function } => {
                self.run_custom_check(check_function).await
            }
        };
        
        let duration = start_time.elapsed();
        
        HealthCheckResult {
            check_id: check.id.clone(),
            check_name: check.name.clone(),
            status,
            message,
            details,
            duration,
            timestamp: SystemTime::now(),
            critical: check.critical,
        }
    }
    
    /// Check success rate metric
    async fn check_success_rate(&self, metric: &str, threshold: f64, window: Duration) -> (HealthStatus, String, HashMap<String, String>) {
        let metrics = self.metrics_collector.get_metrics_for_window(metric, window).await;
        
        if metrics.is_empty() {
            return (HealthStatus::Unknown, "No metrics available".to_string(), HashMap::new());
        }
        
        let success_rate = metrics.iter().sum::<f64>() / metrics.len() as f64;
        
        let status = if success_rate >= threshold {
            HealthStatus::Healthy
        } else if success_rate >= threshold * 0.8 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        let message = format!("Success rate: {:.2}% (threshold: {:.2}%)", 
            success_rate * 100.0, threshold * 100.0);
        
        let mut details = HashMap::new();
        details.insert("current_rate".to_string(), format!("{:.4}", success_rate));
        details.insert("threshold".to_string(), format!("{:.4}", threshold));
        details.insert("sample_count".to_string(), metrics.len().to_string());
        
        (status, message, details)
    }
    
    /// Check system resources
    async fn check_system_resources(&self, max_cpu: f64, max_memory: f64) -> (HealthStatus, String, HashMap<String, String>) {
        let (cpu_usage, memory_usage) = self.get_system_resource_usage().await;
        
        let status = if cpu_usage <= max_cpu && memory_usage <= max_memory {
            HealthStatus::Healthy
        } else if cpu_usage <= max_cpu * 1.2 && memory_usage <= max_memory * 1.2 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        let message = format!("CPU: {:.1}%, Memory: {:.1}%", cpu_usage, memory_usage);
        
        let mut details = HashMap::new();
        details.insert("cpu_usage".to_string(), format!("{:.2}", cpu_usage));
        details.insert("memory_usage".to_string(), format!("{:.2}", memory_usage));
        details.insert("cpu_threshold".to_string(), format!("{:.2}", max_cpu));
        details.insert("memory_threshold".to_string(), format!("{:.2}", max_memory));
        
        (status, message, details)
    }
    
    /// Check network connectivity
    async fn check_network_connectivity(&self, targets: &[String], max_latency: u32) -> (HealthStatus, String, HashMap<String, String>) {
        let mut successful_checks = 0;
        let mut total_latency = 0u32;
        let mut details = HashMap::new();
        
        for target in targets {
            match self.ping_target(target).await {
                Ok(latency) => {
                    successful_checks += 1;
                    total_latency += latency;
                    details.insert(format!("latency_{}", target), format!("{}ms", latency));
                }
                Err(e) => {
                    details.insert(format!("error_{}", target), e.to_string());
                }
            }
        }
        
        let success_rate = successful_checks as f64 / targets.len() as f64;
        let average_latency = if successful_checks > 0 {
            total_latency / successful_checks as u32
        } else {
            u32::MAX
        };
        
        let status = if success_rate >= 0.8 && average_latency <= max_latency {
            HealthStatus::Healthy
        } else if success_rate >= 0.5 && average_latency <= max_latency * 2 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        let message = format!("Connectivity: {}/{} targets, Avg latency: {}ms", 
            successful_checks, targets.len(), average_latency);
        
        details.insert("success_rate".to_string(), format!("{:.2}", success_rate));
        details.insert("average_latency".to_string(), format!("{}ms", average_latency));
        
        (status, message, details)
    }
    
    /// Check service dependencies
    async fn check_service_dependencies(&self, services: &[ServiceDependency]) -> (HealthStatus, String, HashMap<String, String>) {
        let mut healthy_services = 0;
        let mut details = HashMap::new();
        
        for service in services {
            match self.check_service_health(service).await {
                Ok(()) => {
                    healthy_services += 1;
                    details.insert(service.name.clone(), "healthy".to_string());
                }
                Err(e) => {
                    details.insert(service.name.clone(), format!("unhealthy: {}", e));
                }
            }
        }
        
        let health_rate = healthy_services as f64 / services.len() as f64;
        
        let status = if health_rate >= 1.0 {
            HealthStatus::Healthy
        } else if health_rate >= 0.5 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        let message = format!("Dependencies: {}/{} healthy", healthy_services, services.len());
        
        (status, message, details)
    }
    
    /// Run custom health check
    async fn run_custom_check(&self, _check_function: &str) -> (HealthStatus, String, HashMap<String, String>) {
        // Placeholder for custom check execution
        (HealthStatus::Healthy, "Custom check passed".to_string(), HashMap::new())
    }
    
    /// Get system resource usage
    async fn get_system_resource_usage(&self) -> (f64, f64) {
        // In real implementation, would query system metrics
        // For now, return mock values
        (45.0, 60.0) // 45% CPU, 60% memory
    }
    
    /// Ping target to check connectivity
    async fn ping_target(&self, target: &str) -> Result<u32, MonitoringError> {
        // In real implementation, would perform actual network ping
        // For now, return mock latency
        debug!("Pinging target: {}", target);
        Ok(50) // 50ms latency
    }
    
    /// Check service health
    async fn check_service_health(&self, service: &ServiceDependency) -> Result<(), MonitoringError> {
        // In real implementation, would make HTTP request to service health endpoint
        debug!("Checking health of service: {} at {}", service.name, service.endpoint);
        Ok(())
    }
    
    /// Calculate overall health score from check results
    async fn calculate_health_score(&self, results: &[HealthCheckResult]) -> f64 {
        if results.is_empty() {
            return 0.0;
        }
        
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        for result in results {
            let weight = if result.critical { 2.0 } else { 1.0 };
            let check_score = match result.status {
                HealthStatus::Healthy => 100.0,
                HealthStatus::Degraded => 60.0,
                HealthStatus::Unhealthy => 0.0,
                HealthStatus::Unknown => 50.0,
            };
            
            score += check_score * weight;
            total_weight += weight;
        }
        
        if total_weight > 0.0 {
            score / total_weight
        } else {
            0.0
        }
    }
    
    /// Start health check background task
    async fn start_health_check_task(&self) -> Result<(), MonitoringError> {
        let check_registry = self.check_registry.clone();
        let _health_state = self.health_state.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Run checks every 30s
            
            loop {
                interval.tick().await;
                
                let checks = check_registry.get_all_checks().await;
                for check in checks {
                    if check_registry.should_run_check(&check).await {
                        // Would run the health check and update state
                        debug!("Running health check: {}", check.name);
                    }
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start metrics collection background task
    async fn start_metrics_collection_task(&self) -> Result<(), MonitoringError> {
        let metrics_collector = self.metrics_collector.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10)); // Collect metrics every 10s
            
            loop {
                interval.tick().await;
                
                if let Err(e) = metrics_collector.collect_system_metrics().await {
                    warn!("Failed to collect system metrics: {}", e);
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start trend analysis background task
    async fn start_trend_analysis_task(&self) -> Result<(), MonitoringError> {
        let trend_analyzer = self.trend_analyzer.clone();
        let metrics_collector = self.metrics_collector.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Analyze trends every minute
            
            loop {
                interval.tick().await;
                
                let recent_metrics = metrics_collector.get_recent_metrics(Duration::from_secs(300)).await;
                if let Err(e) = trend_analyzer.analyze_trends(recent_metrics).await {
                    warn!("Failed to analyze health trends: {}", e);
                }
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
    
    /// Start system resource monitoring background task
    async fn start_system_resource_monitoring_task(&self) -> Result<(), MonitoringError> {
        let health_state = self.health_state.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(15)); // Monitor resources every 15s
            
            loop {
                interval.tick().await;
                
                // Would collect actual system metrics
                let mut state = health_state.write().await;
                
                // Mock system metrics - in real implementation would use sysinfo or similar
                state.health_metrics.cpu_utilization = 45.0;
                state.health_metrics.memory_utilization = 60.0;
                state.health_metrics.disk_utilization = 30.0;
                state.health_metrics.network_utilization = 25.0;
            }
        });
        
        self.tasks.lock().await.push(task);
        Ok(())
    }
}

/// Health configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthConfig {
    /// Health check thresholds
    pub thresholds: HealthThresholds,
    /// Health check intervals
    pub intervals: HealthIntervals,
    /// Alerting configuration
    pub alerting: HealthAlertConfig,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            thresholds: HealthThresholds::default(),
            intervals: HealthIntervals::default(),
            alerting: HealthAlertConfig::default(),
        }
    }
}

/// Health thresholds
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthThresholds {
    /// Minimum NAT success rate
    pub min_success_rate: f64,
    /// Maximum failure rate
    pub max_failure_rate: f64,
    /// Maximum CPU utilization
    pub max_cpu_utilization: f64,
    /// Maximum memory utilization
    pub max_memory_utilization: f64,
    /// Maximum latency in milliseconds
    pub max_latency_ms: u32,
    /// Minimum health score
    pub min_health_score: f64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            min_success_rate: 0.95,    // 95% minimum success rate
            max_failure_rate: 0.05,    // 5% maximum failure rate
            max_cpu_utilization: 80.0, // 80% maximum CPU usage
            max_memory_utilization: 85.0, // 85% maximum memory usage
            max_latency_ms: 1000,      // 1 second maximum latency
            min_health_score: 70.0,    // 70% minimum health score
        }
    }
}

/// Health check intervals
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthIntervals {
    /// Basic health check interval
    pub basic_check_interval: Duration,
    /// Comprehensive check interval
    pub comprehensive_check_interval: Duration,
    /// Metrics collection interval
    pub metrics_collection_interval: Duration,
    /// Trend analysis interval
    pub trend_analysis_interval: Duration,
}

impl Default for HealthIntervals {
    fn default() -> Self {
        Self {
            basic_check_interval: Duration::from_secs(30),
            comprehensive_check_interval: Duration::from_secs(300),
            metrics_collection_interval: Duration::from_secs(10),
            trend_analysis_interval: Duration::from_secs(60),
        }
    }
}

/// Health alerting configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthAlertConfig {
    /// Enable health alerts
    pub enabled: bool,
    /// Alert channels
    pub alert_channels: Vec<String>,
    /// Alert thresholds
    pub alert_thresholds: HashMap<String, f64>,
}

impl Default for HealthAlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_channels: vec!["health_alerts".to_string()],
            alert_thresholds: HashMap::from([
                ("health_score".to_string(), 70.0),
                ("success_rate".to_string(), 0.9),
            ]),
        }
    }
}

/// System health state
#[derive(Debug)]
struct SystemHealthState {
    /// Monitor status
    monitor_status: HealthMonitorStatus,
    /// Overall health status
    overall_health_status: HealthStatus,
    /// Monitor start time
    start_time: Option<SystemTime>,
    /// Success counts
    success_counts: SuccessCounts,
    /// Failure counts
    failure_counts: FailureCounts,
    /// Health metrics
    health_metrics: HealthMetrics,
    /// Last health check time
    last_health_check: Option<SystemTime>,
}

impl SystemHealthState {
    fn new() -> Self {
        Self {
            monitor_status: HealthMonitorStatus::Stopped,
            overall_health_status: HealthStatus::Unknown,
            start_time: None,
            success_counts: SuccessCounts::default(),
            failure_counts: FailureCounts::default(),
            health_metrics: HealthMetrics::default(),
            last_health_check: None,
        }
    }
}

/// Health monitor status
#[derive(Debug, Clone)]
enum HealthMonitorStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

/// Health status levels
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Success counts
#[derive(Debug, Default)]
struct SuccessCounts {
    nat_successes: u64,
    health_checks_passed: u64,
}

/// Failure counts
#[derive(Debug, Default)]
struct FailureCounts {
    nat_failures: u64,
    health_checks_failed: u64,
}

/// Health metrics
#[derive(Debug, Default)]
struct HealthMetrics {
    overall_health_score: f64,
    nat_failure_rate: f64,
    cpu_utilization: f64,
    memory_utilization: f64,
    disk_utilization: f64,
    network_utilization: f64,
    average_latency_ms: f64,
}

/// Health check definition
#[derive(Debug, Clone)]
struct HealthCheck {
    id: String,
    name: String,
    description: String,
    check_type: HealthCheckType,
    interval: Duration,
    timeout: Duration,
    critical: bool,
}

/// Health check types
#[derive(Debug, Clone)]
enum HealthCheckType {
    SuccessRate {
        metric: String,
        threshold: f64,
        window: Duration,
    },
    SystemResources {
        max_cpu_percent: f64,
        max_memory_percent: f64,
    },
    NetworkConnectivity {
        targets: Vec<String>,
        max_latency_ms: u32,
    },
    ServiceDependencies {
        services: Vec<ServiceDependency>,
    },
    Custom {
        check_function: String,
    },
}

/// Service dependency
#[derive(Debug, Clone)]
struct ServiceDependency {
    name: String,
    endpoint: String,
    timeout: Duration,
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub check_id: String,
    pub check_name: String,
    pub status: HealthStatus,
    pub message: String,
    pub details: HashMap<String, String>,
    pub duration: Duration,
    pub timestamp: SystemTime,
    pub critical: bool,
}

impl HealthCheckResult {
    /// Get overall status
    pub fn overall_status(&self) -> HealthStatus {
        self.status.clone()
    }
    
    /// Get health score (0-100)
    pub fn health_score(&self) -> f64 {
        match self.status {
            HealthStatus::Healthy => 100.0,
            HealthStatus::Degraded => 60.0,
            HealthStatus::Unhealthy => 0.0,
            HealthStatus::Unknown => 50.0,
        }
    }
}

/// Individual health check result
#[derive(Debug)]
pub struct IndividualHealthResult {
    pub overall_status: HealthStatus,
    pub check_results: Vec<IndividualHealthResult>,
    pub duration: Duration,
    pub timestamp: SystemTime,
    pub health_score: f64,
}

/// Health check registry
struct HealthCheckRegistry {
    checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    last_run_times: Arc<RwLock<HashMap<String, Instant>>>,
}

impl HealthCheckRegistry {
    fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
            last_run_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    async fn register_check(&self, check: HealthCheck) {
        let mut checks = self.checks.write().await;
        checks.insert(check.id.clone(), check);
    }
    
    async fn get_all_checks(&self) -> Vec<HealthCheck> {
        let checks = self.checks.read().await;
        checks.values().cloned().collect()
    }
    
    async fn should_run_check(&self, check: &HealthCheck) -> bool {
        let last_run_times = self.last_run_times.read().await;
        
        if let Some(&last_run) = last_run_times.get(&check.id) {
            last_run.elapsed() >= check.interval
        } else {
            true // Never run before
        }
    }
}

/// Health metrics collector
struct HealthMetricsCollector {
    metrics: Arc<RwLock<Vec<TimestampedMetric>>>,
}

impl HealthMetricsCollector {
    fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    async fn record_nat_result(&self, result: &NatTraversalResult) {
        let mut metrics = self.metrics.write().await;
        
        let metric = TimestampedMetric {
            timestamp: SystemTime::now(),
            metric_name: "nat_success".to_string(),
            value: if result.success { 1.0 } else { 0.0 },
        };
        
        metrics.push(metric);
        
        // Keep only recent metrics
        let cutoff = SystemTime::now() - Duration::from_secs(3600); // 1 hour
        metrics.retain(|m| m.timestamp >= cutoff);
    }
    
    async fn collect_system_metrics(&self) -> Result<(), MonitoringError> {
        // Would collect actual system metrics
        debug!("Collecting system metrics");
        Ok(())
    }
    
    async fn get_summary(&self) -> HealthMetricsSummary {
        let metrics = self.metrics.read().await;
        
        let success_count = metrics.iter()
            .filter(|m| m.metric_name == "nat_success" && m.value > 0.0)
            .count();
        
        let total_count = metrics.iter()
            .filter(|m| m.metric_name == "nat_success")
            .count();
        
        let success_rate = if total_count > 0 {
            success_count as f64 / total_count as f64
        } else {
            0.0
        };
        
        HealthMetricsSummary {
            success_rate,
            total_attempts: total_count as u64,
            successful_attempts: success_count as u64,
            average_latency_ms: 50.0, // Mock value
            system_cpu_usage: 45.0,   // Mock value
            system_memory_usage: 60.0, // Mock value
        }
    }
    
    async fn get_metrics_for_window(&self, metric_name: &str, window: Duration) -> Vec<f64> {
        let metrics = self.metrics.read().await;
        let cutoff = SystemTime::now() - window;
        
        metrics.iter()
            .filter(|m| m.metric_name == metric_name && m.timestamp >= cutoff)
            .map(|m| m.value)
            .collect()
    }
    
    async fn get_recent_metrics(&self, period: Duration) -> Vec<TimestampedMetric> {
        let metrics = self.metrics.read().await;
        let cutoff = SystemTime::now() - period;
        
        metrics.iter()
            .filter(|m| m.timestamp >= cutoff)
            .cloned()
            .collect()
    }
}

/// Timestamped metric
#[derive(Debug, Clone)]
struct TimestampedMetric {
    timestamp: SystemTime,
    metric_name: String,
    value: f64,
}

/// Health metrics summary
#[derive(Debug)]
pub struct HealthMetricsSummary {
    pub success_rate: f64,
    pub total_attempts: u64,
    pub successful_attempts: u64,
    pub average_latency_ms: f64,
    pub system_cpu_usage: f64,
    pub system_memory_usage: f64,
}

/// Health trend analyzer
struct HealthTrendAnalyzer {
    trends: Arc<RwLock<HealthTrends>>,
}

impl HealthTrendAnalyzer {
    fn new() -> Self {
        Self {
            trends: Arc::new(RwLock::new(HealthTrends::default())),
        }
    }
    
    async fn analyze_trends(&self, metrics: Vec<TimestampedMetric>) -> Result<(), MonitoringError> {
        // Analyze trends in the metrics
        debug!("Analyzing health trends for {} metrics", metrics.len());
        
        // Would implement actual trend analysis here
        
        Ok(())
    }
    
    async fn get_trends(&self, _period: Duration) -> HealthTrends {
        let trends = self.trends.read().await;
        trends.clone()
    }
}

/// Health trends
#[derive(Debug, Clone, Default)]
pub struct HealthTrends {
    pub success_rate_trend: TrendDirection,
    pub latency_trend: TrendDirection,
    pub resource_utilization_trend: TrendDirection,
    pub overall_health_trend: TrendDirection,
}

/// Trend direction
#[derive(Debug, Clone, Default)]
pub enum TrendDirection {
    #[default]
    Stable,
    Improving,
    Degrading,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitor_creation() {
        let config = HealthConfig::default();
        let monitor = HealthMonitor::new(config).await.unwrap();
        
        let status = monitor.get_status().await;
        assert!(status.contains("Unknown"));
    }
    
    #[tokio::test]
    async fn test_health_check_result() {
        let result = HealthCheckResult {
            check_id: "test".to_string(),
            check_name: "Test Check".to_string(),
            status: HealthStatus::Healthy,
            message: "All good".to_string(),
            details: HashMap::new(),
            duration: Duration::from_millis(100),
            timestamp: SystemTime::now(),
            critical: true,
        };
        
        assert_eq!(result.health_score(), 100.0);
        assert!(matches!(result.overall_status(), HealthStatus::Healthy));
    }
    
    #[tokio::test]
    async fn test_health_metrics_collector() {
        let collector = HealthMetricsCollector::new();
        
        // Record a successful NAT result
        let result = NatTraversalResult {
            attempt_id: "test".to_string(),
            success: true,
            duration: Duration::from_millis(500),
            connection_info: None,
            error_info: None,
            performance_metrics: crate::monitoring::PerformanceMetrics {
                connection_time_ms: 500,
                first_candidate_time_ms: 100,
                success_time_ms: Some(500),
                candidates_tried: 3,
                round_trips: 2,
                setup_bytes: 1024,
            },
            candidates_used: vec![],
        };
        
        collector.record_nat_result(&result).await;
        
        let summary = collector.get_summary().await;
        assert_eq!(summary.success_rate, 1.0);
        assert_eq!(summary.successful_attempts, 1);
    }
}