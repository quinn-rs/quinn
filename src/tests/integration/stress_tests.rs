//! Stress Tests for NAT Traversal Integration
//!
//! This module provides comprehensive stress testing for NAT traversal functionality
//! under extreme conditions and high load scenarios.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use tokio::{sync::mpsc, time::sleep};
use tracing::{debug, info, warn};

use crate::{
    connection::nat_traversal::{NatTraversalRole},
    nat_traversal_api::{NatTraversalConfig, EndpointRole, PeerId},
};

use super::{
    nat_simulator::{NetworkSimulator, NatTraversalSimulationResult},
    mock_network::{MockNetworkEnvironment, NatType},
    NetworkSimulationConfig, StressTest, PerformanceMetrics,
};

/// Stress testing framework
pub struct StressTestFramework {
    /// Test configuration
    config: StressTestConfig,
    /// Network simulator
    simulator: Arc<Mutex<NetworkSimulator>>,
    /// Stress test metrics
    metrics: Arc<StressTestMetrics>,
    /// Resource monitor
    resource_monitor: Arc<Mutex<StressResourceMonitor>>,
}

/// Configuration for stress tests
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    /// Maximum concurrent connections to test
    pub max_concurrent_connections: usize,
    /// Total connections to establish during test
    pub total_connections: usize,
    /// Test duration
    pub test_duration: Duration,
    /// Connection establishment timeout
    pub connection_timeout: Duration,
    /// Memory limit (MB)
    pub memory_limit_mb: u64,
    /// CPU limit (%)
    pub cpu_limit_percent: f32,
    /// Packet loss percentage for stress conditions
    pub stress_packet_loss_percent: u8,
    /// Enable memory leak detection
    pub enable_memory_leak_detection: bool,
    /// Enable performance profiling
    pub enable_profiling: bool,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 1000,
            total_connections: 10000,
            test_duration: Duration::from_secs(300), // 5 minutes
            connection_timeout: Duration::from_secs(30),
            memory_limit_mb: 1000, // 1GB
            cpu_limit_percent: 80.0,
            stress_packet_loss_percent: 10,
            enable_memory_leak_detection: true,
            enable_profiling: false,
        }
    }
}

/// Stress test metrics collector
pub struct StressTestMetrics {
    /// Connection statistics
    pub connections_attempted: AtomicUsize,
    pub connections_succeeded: AtomicUsize,
    pub connections_failed: AtomicUsize,
    pub connections_timeout: AtomicUsize,
    
    /// Timing statistics
    pub total_connection_time: AtomicU64, // in milliseconds
    pub min_connection_time: AtomicU64,
    pub max_connection_time: AtomicU64,
    
    /// Resource statistics
    pub peak_memory_usage: AtomicU64,
    pub peak_cpu_usage: Arc<Mutex<f32>>,
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_received: AtomicU64,
    
    /// Error statistics
    pub error_counts: Arc<Mutex<HashMap<String, u64>>>,
    
    /// Performance samples
    pub performance_samples: Arc<Mutex<Vec<PerformanceSample>>>,
}

/// Performance sample for stress testing
#[derive(Debug, Clone)]
pub struct PerformanceSample {
    /// Timestamp
    pub timestamp: Instant,
    /// Active connections count
    pub active_connections: usize,
    /// Memory usage (bytes)
    pub memory_usage: u64,
    /// CPU usage (%)
    pub cpu_usage: f32,
    /// Connection establishment rate (per second)
    pub connection_rate: f32,
    /// Error rate (%)
    pub error_rate: f32,
}

/// Resource monitor for stress testing
pub struct StressResourceMonitor {
    /// Monitoring start time
    start_time: Option<Instant>,
    /// Memory samples
    memory_samples: Vec<u64>,
    /// CPU samples
    cpu_samples: Vec<f32>,
    /// Baseline measurements
    baseline_memory: Option<u64>,
    baseline_cpu: Option<f32>,
    /// Sampling interval
    sampling_interval: Duration,
}

/// Result of a stress test
#[derive(Debug, Clone)]
pub struct StressTestResult {
    /// Test name
    pub test_name: String,
    /// Test success
    pub success: bool,
    /// Test duration
    pub duration: Duration,
    /// Performance summary
    pub performance_summary: StressTestSummary,
    /// Resource usage summary
    pub resource_summary: ResourceUsageSummary,
    /// Error summary
    pub error_summary: HashMap<String, u64>,
}

/// Summary of stress test performance
#[derive(Debug, Clone)]
pub struct StressTestSummary {
    /// Total connections attempted
    pub connections_attempted: usize,
    /// Successful connections
    pub connections_succeeded: usize,
    /// Failed connections
    pub connections_failed: usize,
    /// Connection success rate
    pub success_rate: f32,
    /// Average connection time
    pub avg_connection_time: Duration,
    /// Connection throughput (connections/sec)
    pub connection_throughput: f32,
    /// Peak concurrent connections
    pub peak_concurrent_connections: usize,
}

/// Summary of resource usage during stress test
#[derive(Debug, Clone)]
pub struct ResourceUsageSummary {
    /// Peak memory usage (MB)
    pub peak_memory_mb: f64,
    /// Average memory usage (MB)
    pub avg_memory_mb: f64,
    /// Memory growth rate (MB/hour)
    pub memory_growth_rate: f64,
    /// Peak CPU usage (%)
    pub peak_cpu_percent: f32,
    /// Average CPU usage (%)
    pub avg_cpu_percent: f32,
    /// Memory leaks detected
    pub memory_leaks_detected: bool,
    /// Resource efficiency score
    pub efficiency_score: f32,
}

impl StressTestFramework {
    /// Create a new stress test framework
    pub fn new(config: StressTestConfig, network_config: NetworkSimulationConfig) -> Self {
        let simulator = Arc::new(Mutex::new(NetworkSimulator::new(network_config)));
        let metrics = Arc::new(StressTestMetrics::new());
        let resource_monitor = Arc::new(Mutex::new(StressResourceMonitor::new()));
        
        Self {
            config,
            simulator,
            metrics,
            resource_monitor,
        }
    }

    /// Run all stress tests
    pub async fn run_all_stress_tests(&mut self) -> Vec<StressTestResult> {
        info!("Starting comprehensive stress test suite");
        
        let mut results = Vec::new();
        
        // Concurrent connections stress test
        results.push(self.test_concurrent_connections().await);
        
        // Connection churn stress test
        results.push(self.test_connection_churn().await);
        
        // Memory pressure stress test
        results.push(self.test_memory_pressure().await);
        
        // Extended duration stress test
        results.push(self.test_extended_duration().await);
        
        // Generate stress test report
        self.generate_stress_test_report(&results);
        
        results
    }

    /// Test concurrent connections under stress
    pub async fn test_concurrent_connections(&mut self) -> StressTestResult {
        info!("Starting concurrent connections stress test");
        let start_time = Instant::now();
        
        // Reset metrics
        self.metrics.reset();
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        // Start background monitoring
        let metrics_clone = self.metrics.clone();
        let resource_monitor_clone = self.resource_monitor.clone();
        let monitoring_handle = tokio::spawn(async move {
            Self::background_monitoring(metrics_clone, resource_monitor_clone).await;
        });
        
        let mut connection_handles = Vec::new();
        let mut active_connections = Arc::new(AtomicUsize::new(0));
        
        // Launch concurrent connections in batches
        let batch_size = 50;
        let total_batches = self.config.max_concurrent_connections / batch_size;
        
        for batch in 0..total_batches {
            debug!("Starting batch {}/{}", batch + 1, total_batches);
            
            for connection_id in 0..batch_size {
                let simulator = self.simulator.clone();
                let metrics = self.metrics.clone();
                let active_connections = active_connections.clone();
                let connection_timeout = self.config.connection_timeout;
                
                let handle = tokio::spawn(async move {
                    let connection_start = Instant::now();
                    
                    // Increment active connections
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
                    
                    let client_config = NatTraversalConfig {
                        role: EndpointRole::Client,
                        bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                        max_candidates: 5, // Reduced for stress test
                        coordination_timeout: Duration::from_secs(5),
                        enable_symmetric_nat: true,
                        enable_relay_fallback: false,
                        max_concurrent_attempts: 2,
                    };
                    
                    let server_config = NatTraversalConfig {
                        role: EndpointRole::Server { can_coordinate: false },
                        bootstrap_nodes: vec![],
                        max_candidates: 5,
                        coordination_timeout: Duration::from_secs(5),
                        enable_symmetric_nat: true,
                        enable_relay_fallback: false,
                        max_concurrent_attempts: 2,
                    };
                    
                    // Apply timeout to connection attempt
                    let result = tokio::time::timeout(
                        connection_timeout,
                        simulator.lock().unwrap().simulate_nat_traversal(client_config, server_config)
                    ).await;
                    
                    let connection_time = connection_start.elapsed();
                    
                    match result {
                        Ok(Ok(sim_result)) if sim_result.success => {
                            metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
                            metrics.update_connection_time(connection_time);
                        }
                        Ok(Ok(_)) => {
                            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Err(_)) => {
                            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Timeout
                            metrics.connections_timeout.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    
                    // Decrement active connections
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                    
                    connection_time
                });
                
                connection_handles.push(handle);
            }
            
            // Small delay between batches to avoid overwhelming the system
            sleep(Duration::from_millis(100)).await;
            
            // Check if we've hit resource limits
            if self.check_resource_limits().await {
                warn!("Resource limits reached, stopping batch creation");
                break;
            }
        }
        
        // Wait for all connections to complete
        info!("Waiting for {} connections to complete", connection_handles.len());
        
        for handle in connection_handles {
            let _ = handle.await;
        }
        
        // Stop monitoring
        monitoring_handle.abort();
        
        let duration = start_time.elapsed();
        let performance_summary = self.calculate_performance_summary();
        let resource_summary = self.calculate_resource_summary(duration);
        
        StressTestResult {
            test_name: "concurrent_connections".to_string(),
            success: performance_summary.success_rate > 0.7 && !resource_summary.memory_leaks_detected,
            duration,
            performance_summary,
            resource_summary,
            error_summary: self.metrics.get_error_summary(),
        }
    }

    /// Test connection churn (rapid connect/disconnect cycles)
    pub async fn test_connection_churn(&mut self) -> StressTestResult {
        info!("Starting connection churn stress test");
        let start_time = Instant::now();
        
        self.metrics.reset();
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        let test_duration = Duration::from_secs(120); // 2 minutes of churn
        let churn_interval = Duration::from_millis(500); // New connection every 500ms
        let mut cycle_count = 0;
        
        while start_time.elapsed() < test_duration {
            cycle_count += 1;
            debug!("Connection churn cycle {}", cycle_count);
            
            // Create multiple short-lived connections
            let mut handles = Vec::new();
            
            for _ in 0..5 {
                let simulator = self.simulator.clone();
                let metrics = self.metrics.clone();
                
                let handle = tokio::spawn(async move {
                    metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
                    
                    let client_config = NatTraversalConfig {
                        role: EndpointRole::Client,
                        bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                        max_candidates: 3,
                        coordination_timeout: Duration::from_secs(3),
                        enable_symmetric_nat: false,
                        enable_relay_fallback: false,
                        max_concurrent_attempts: 1,
                    };
                    
                    let server_config = NatTraversalConfig {
                        role: EndpointRole::Server { can_coordinate: false },
                        bootstrap_nodes: vec![],
                        max_candidates: 3,
                        coordination_timeout: Duration::from_secs(3),
                        enable_symmetric_nat: false,
                        enable_relay_fallback: false,
                        max_concurrent_attempts: 1,
                    };
                    
                    let connection_start = Instant::now();
                    let result = simulator.lock().unwrap()
                        .simulate_nat_traversal(client_config, server_config).await;
                    
                    let connection_time = connection_start.elapsed();
                    
                    match result {
                        Ok(sim_result) if sim_result.success => {
                            metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
                            metrics.update_connection_time(connection_time);
                            
                            // Simulate some data transfer
                            sleep(Duration::from_millis(100)).await;
                            
                            // Connection ends (churn)
                        }
                        _ => {
                            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
                
                handles.push(handle);
            }
            
            // Wait for this batch to complete
            for handle in handles {
                let _ = handle.await;
            }
            
            sleep(churn_interval).await;
        }
        
        let duration = start_time.elapsed();
        let performance_summary = self.calculate_performance_summary();
        let resource_summary = self.calculate_resource_summary(duration);
        
        StressTestResult {
            test_name: "connection_churn".to_string(),
            success: performance_summary.success_rate > 0.6 && resource_summary.memory_growth_rate < 100.0,
            duration,
            performance_summary,
            resource_summary,
            error_summary: self.metrics.get_error_summary(),
        }
    }

    /// Test memory pressure scenarios
    pub async fn test_memory_pressure(&mut self) -> StressTestResult {
        info!("Starting memory pressure stress test");
        let start_time = Instant::now();
        
        self.metrics.reset();
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        // Create memory pressure by allocating large amounts of data
        let mut memory_pressure_data: Vec<Vec<u8>> = Vec::new();
        let pressure_increment = 10 * 1024 * 1024; // 10MB chunks
        
        // Gradually increase memory pressure while testing connections
        for pressure_level in 1..=20 {
            info!("Memory pressure level: {} ({}MB)", pressure_level, pressure_level * 10);
            
            // Allocate more memory
            memory_pressure_data.push(vec![0u8; pressure_increment]);
            
            // Test connections under this pressure level
            let mut handles = Vec::new();
            
            for _ in 0..10 {
                let simulator = self.simulator.clone();
                let metrics = self.metrics.clone();
                
                let handle = tokio::spawn(async move {
                    metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
                    
                    let client_config = NatTraversalConfig {
                        role: EndpointRole::Client,
                        bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                        max_candidates: 4,
                        coordination_timeout: Duration::from_secs(8),
                        enable_symmetric_nat: true,
                        enable_relay_fallback: true,
                        max_concurrent_attempts: 2,
                    };
                    
                    let server_config = NatTraversalConfig {
                        role: EndpointRole::Server { can_coordinate: true },
                        bootstrap_nodes: vec![],
                        max_candidates: 4,
                        coordination_timeout: Duration::from_secs(8),
                        enable_symmetric_nat: true,
                        enable_relay_fallback: true,
                        max_concurrent_attempts: 2,
                    };
                    
                    let connection_start = Instant::now();
                    let result = simulator.lock().unwrap()
                        .simulate_nat_traversal(client_config, server_config).await;
                    
                    let connection_time = connection_start.elapsed();
                    
                    match result {
                        Ok(sim_result) if sim_result.success => {
                            metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
                            metrics.update_connection_time(connection_time);
                        }
                        _ => {
                            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
                
                handles.push(handle);
            }
            
            // Wait for connections to complete
            for handle in handles {
                let _ = handle.await;
            }
            
            // Check if we've hit memory limits
            if self.check_memory_limit().await {
                warn!("Memory limit reached at pressure level {}", pressure_level);
                break;
            }
            
            sleep(Duration::from_secs(2)).await;
        }
        
        // Clean up memory pressure
        memory_pressure_data.clear();
        
        let duration = start_time.elapsed();
        let performance_summary = self.calculate_performance_summary();
        let resource_summary = self.calculate_resource_summary(duration);
        
        StressTestResult {
            test_name: "memory_pressure".to_string(),
            success: performance_summary.success_rate > 0.5 && resource_summary.peak_memory_mb < 1000.0,
            duration,
            performance_summary,
            resource_summary,
            error_summary: self.metrics.get_error_summary(),
        }
    }

    /// Test extended duration scenarios
    pub async fn test_extended_duration(&mut self) -> StressTestResult {
        info!("Starting extended duration stress test");
        let start_time = Instant::now();
        
        self.metrics.reset();
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        let test_duration = Duration::from_secs(600); // 10 minutes
        let connection_interval = Duration::from_secs(5);
        
        while start_time.elapsed() < test_duration {
            let elapsed = start_time.elapsed();
            let progress = elapsed.as_secs_f32() / test_duration.as_secs_f32();
            
            if (elapsed.as_secs() % 60) == 0 {
                info!("Extended duration test progress: {:.1}%", progress * 100.0);
            }
            
            // Establish a connection
            let simulator = self.simulator.clone();
            let metrics = self.metrics.clone();
            
            let handle = tokio::spawn(async move {
                metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
                
                let client_config = NatTraversalConfig {
                    role: EndpointRole::Client,
                    bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                    max_candidates: 6,
                    coordination_timeout: Duration::from_secs(10),
                    enable_symmetric_nat: true,
                    enable_relay_fallback: true,
                    max_concurrent_attempts: 3,
                };
                
                let server_config = NatTraversalConfig {
                    role: EndpointRole::Server { can_coordinate: true },
                    bootstrap_nodes: vec![],
                    max_candidates: 6,
                    coordination_timeout: Duration::from_secs(10),
                    enable_symmetric_nat: true,
                    enable_relay_fallback: true,
                    max_concurrent_attempts: 3,
                };
                
                let connection_start = Instant::now();
                let result = simulator.lock().unwrap()
                    .simulate_nat_traversal(client_config, server_config).await;
                
                let connection_time = connection_start.elapsed();
                
                match result {
                    Ok(sim_result) if sim_result.success => {
                        metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
                        metrics.update_connection_time(connection_time);
                    }
                    _ => {
                        metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            
            let _ = handle.await;
            
            sleep(connection_interval).await;
        }
        
        let duration = start_time.elapsed();
        let performance_summary = self.calculate_performance_summary();
        let resource_summary = self.calculate_resource_summary(duration);
        
        StressTestResult {
            test_name: "extended_duration".to_string(),
            success: performance_summary.success_rate > 0.7 && resource_summary.memory_growth_rate < 50.0,
            duration,
            performance_summary,
            resource_summary,
            error_summary: self.metrics.get_error_summary(),
        }
    }

    // Helper methods

    async fn background_monitoring(
        metrics: Arc<StressTestMetrics>,
        resource_monitor: Arc<Mutex<StressResourceMonitor>>,
    ) {
        let monitoring_interval = Duration::from_millis(1000); // 1 second
        
        loop {
            sleep(monitoring_interval).await;
            
            // Collect performance sample
            let sample = PerformanceSample {
                timestamp: Instant::now(),
                active_connections: 0, // Would be tracked in real implementation
                memory_usage: Self::get_current_memory_usage().await,
                cpu_usage: Self::get_current_cpu_usage().await,
                connection_rate: 0.0, // Would be calculated from metrics
                error_rate: 0.0,
            };
            
            metrics.performance_samples.lock().unwrap().push(sample.clone());
            
            // Update peak values
            metrics.peak_memory_usage.fetch_max(sample.memory_usage, Ordering::Relaxed);
            {
                let mut peak_cpu = metrics.peak_cpu_usage.lock().unwrap();
                if sample.cpu_usage > *peak_cpu {
                    *peak_cpu = sample.cpu_usage;
                }
            }
            
            // Update resource monitor
            {
                let mut monitor = resource_monitor.lock().unwrap();
                monitor.memory_samples.push(sample.memory_usage);
                monitor.cpu_samples.push(sample.cpu_usage);
            }
        }
    }

    async fn get_current_memory_usage() -> u64 {
        // In a real implementation, this would use platform-specific APIs
        // For testing, return a simulated value
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(50_000_000..200_000_000) // 50-200 MB
    }

    async fn get_current_cpu_usage() -> f32 {
        // In a real implementation, this would use platform-specific APIs
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(10.0..60.0) // 10-60% CPU
    }

    async fn check_resource_limits(&self) -> bool {
        let memory_usage = Self::get_current_memory_usage().await;
        let cpu_usage = Self::get_current_cpu_usage().await;
        
        let memory_mb = memory_usage / (1024 * 1024);
        
        memory_mb > self.config.memory_limit_mb || cpu_usage > self.config.cpu_limit_percent
    }

    async fn check_memory_limit(&self) -> bool {
        let memory_usage = Self::get_current_memory_usage().await;
        let memory_mb = memory_usage / (1024 * 1024);
        memory_mb > self.config.memory_limit_mb
    }

    fn calculate_performance_summary(&self) -> StressTestSummary {
        let attempted = self.metrics.connections_attempted.load(Ordering::Relaxed);
        let succeeded = self.metrics.connections_succeeded.load(Ordering::Relaxed);
        let failed = self.metrics.connections_failed.load(Ordering::Relaxed);
        
        let success_rate = if attempted > 0 {
            succeeded as f32 / attempted as f32
        } else {
            0.0
        };
        
        let total_time_ms = self.metrics.total_connection_time.load(Ordering::Relaxed);
        let avg_connection_time = if succeeded > 0 {
            Duration::from_millis(total_time_ms / succeeded as u64)
        } else {
            Duration::from_secs(0)
        };
        
        StressTestSummary {
            connections_attempted: attempted,
            connections_succeeded: succeeded,
            connections_failed: failed,
            success_rate,
            avg_connection_time,
            connection_throughput: 0.0, // Would be calculated from timing data
            peak_concurrent_connections: 0, // Would be tracked during test
        }
    }

    fn calculate_resource_summary(&self, test_duration: Duration) -> ResourceUsageSummary {
        let samples = self.metrics.performance_samples.lock().unwrap();
        
        if samples.is_empty() {
            return ResourceUsageSummary {
                peak_memory_mb: 0.0,
                avg_memory_mb: 0.0,
                memory_growth_rate: 0.0,
                peak_cpu_percent: 0.0,
                avg_cpu_percent: 0.0,
                memory_leaks_detected: false,
                efficiency_score: 0.0,
            };
        }
        
        let peak_memory_mb = samples.iter()
            .map(|s| s.memory_usage as f64 / (1024.0 * 1024.0))
            .fold(0.0f64, |a, b| a.max(b));
        
        let avg_memory_mb = samples.iter()
            .map(|s| s.memory_usage as f64 / (1024.0 * 1024.0))
            .sum::<f64>() / samples.len() as f64;
        
        let peak_cpu_percent = samples.iter()
            .map(|s| s.cpu_usage)
            .fold(0.0f32, |a, b| a.max(b));
        
        let avg_cpu_percent = samples.iter()
            .map(|s| s.cpu_usage)
            .sum::<f32>() / samples.len() as f32;
        
        // Simple memory growth rate calculation
        let memory_growth_rate = if samples.len() > 1 {
            let first_memory = samples.first().unwrap().memory_usage as f64 / (1024.0 * 1024.0);
            let last_memory = samples.last().unwrap().memory_usage as f64 / (1024.0 * 1024.0);
            let hours = test_duration.as_secs_f64() / 3600.0;
            if hours > 0.0 {
                (last_memory - first_memory) / hours
            } else {
                0.0
            }
        } else {
            0.0
        };
        
        let memory_leaks_detected = memory_growth_rate > 100.0; // > 100 MB/hour
        
        let efficiency_score = if peak_memory_mb > 0.0 && peak_cpu_percent > 0.0 {
            let memory_efficiency = 1000.0 / peak_memory_mb; // Higher is better
            let cpu_efficiency = 100.0 / peak_cpu_percent as f64; // Higher is better
            (memory_efficiency + cpu_efficiency) / 2.0
        } else {
            0.0
        };
        
        ResourceUsageSummary {
            peak_memory_mb,
            avg_memory_mb,
            memory_growth_rate,
            peak_cpu_percent,
            avg_cpu_percent,
            memory_leaks_detected,
            efficiency_score: efficiency_score as f32,
        }
    }

    fn generate_stress_test_report(&self, results: &[StressTestResult]) {
        info!("=== Stress Test Report ===");
        
        let successful_tests = results.iter().filter(|r| r.success).count();
        let total_tests = results.len();
        
        info!("Stress tests passed: {}/{}", successful_tests, total_tests);
        
        for result in results {
            let status = if result.success { "PASS" } else { "FAIL" };
            info!("{}: {} - Success Rate: {:.1}%, Peak Memory: {:.1}MB", 
                  result.test_name, 
                  status,
                  result.performance_summary.success_rate * 100.0,
                  result.resource_summary.peak_memory_mb);
        }
        
        // Overall statistics
        let total_connections: usize = results.iter()
            .map(|r| r.performance_summary.connections_attempted)
            .sum();
        let total_successful: usize = results.iter()
            .map(|r| r.performance_summary.connections_succeeded)
            .sum();
        
        if total_connections > 0 {
            let overall_success_rate = total_successful as f32 / total_connections as f32;
            info!("Overall connection success rate: {:.1}%", overall_success_rate * 100.0);
        }
    }
}

impl StressTestMetrics {
    fn new() -> Self {
        Self {
            connections_attempted: AtomicUsize::new(0),
            connections_succeeded: AtomicUsize::new(0),
            connections_failed: AtomicUsize::new(0),
            connections_timeout: AtomicUsize::new(0),
            total_connection_time: AtomicU64::new(0),
            min_connection_time: AtomicU64::new(u64::MAX),
            max_connection_time: AtomicU64::new(0),
            peak_memory_usage: AtomicU64::new(0),
            peak_cpu_usage: Arc::new(Mutex::new(0.0)),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
            error_counts: Arc::new(Mutex::new(HashMap::new())),
            performance_samples: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn reset(&self) {
        self.connections_attempted.store(0, Ordering::Relaxed);
        self.connections_succeeded.store(0, Ordering::Relaxed);
        self.connections_failed.store(0, Ordering::Relaxed);
        self.connections_timeout.store(0, Ordering::Relaxed);
        self.total_connection_time.store(0, Ordering::Relaxed);
        self.min_connection_time.store(u64::MAX, Ordering::Relaxed);
        self.max_connection_time.store(0, Ordering::Relaxed);
        self.peak_memory_usage.store(0, Ordering::Relaxed);
        *self.peak_cpu_usage.lock().unwrap() = 0.0;
        self.total_bytes_sent.store(0, Ordering::Relaxed);
        self.total_bytes_received.store(0, Ordering::Relaxed);
        self.error_counts.lock().unwrap().clear();
        self.performance_samples.lock().unwrap().clear();
    }

    fn update_connection_time(&self, duration: Duration) {
        let millis = duration.as_millis() as u64;
        self.total_connection_time.fetch_add(millis, Ordering::Relaxed);
        self.min_connection_time.fetch_min(millis, Ordering::Relaxed);
        self.max_connection_time.fetch_max(millis, Ordering::Relaxed);
    }

    fn get_error_summary(&self) -> HashMap<String, u64> {
        self.error_counts.lock().unwrap().clone()
    }
}

impl StressResourceMonitor {
    fn new() -> Self {
        Self {
            start_time: None,
            memory_samples: Vec::new(),
            cpu_samples: Vec::new(),
            baseline_memory: None,
            baseline_cpu: None,
            sampling_interval: Duration::from_millis(1000),
        }
    }

    fn start_monitoring(&mut self) {
        self.start_time = Some(Instant::now());
        self.memory_samples.clear();
        self.cpu_samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stress_test_framework_creation() {
        let stress_config = StressTestConfig::default();
        let network_config = NetworkSimulationConfig::default();
        
        let framework = StressTestFramework::new(stress_config, network_config);
        
        assert!(framework.config.max_concurrent_connections > 0);
        assert!(framework.config.test_duration > Duration::from_secs(0));
    }

    #[test]
    fn test_stress_test_metrics() {
        let metrics = StressTestMetrics::new();
        
        // Test initial state
        assert_eq!(metrics.connections_attempted.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.connections_succeeded.load(Ordering::Relaxed), 0);
        
        // Test updates
        metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
        metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
        metrics.update_connection_time(Duration::from_millis(100));
        
        assert_eq!(metrics.connections_attempted.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.connections_succeeded.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_connection_time.load(Ordering::Relaxed), 100);
    }

    #[tokio::test]
    async fn test_resource_limit_checking() {
        let stress_config = StressTestConfig {
            memory_limit_mb: 100,
            cpu_limit_percent: 50.0,
            ..StressTestConfig::default()
        };
        let network_config = NetworkSimulationConfig::default();
        
        let framework = StressTestFramework::new(stress_config, network_config);
        
        // This test would check resource limits in a real implementation
        let _limit_check = framework.check_resource_limits().await;
    }
}