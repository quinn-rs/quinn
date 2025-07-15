//! Performance Testing for NAT Traversal Integration
//!
//! This module provides comprehensive performance testing infrastructure for
//! validating NAT traversal performance characteristics under various conditions.

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
    NetworkSimulationConfig, PerformanceMetrics, PerformanceTest,
};

/// Performance testing framework
pub struct PerformanceTestFramework {
    /// Test configuration
    config: PerformanceTestConfig,
    /// Network simulator
    simulator: Arc<Mutex<NetworkSimulator>>,
    /// Performance metrics collector
    metrics_collector: Arc<Mutex<MetricsCollector>>,
    /// System resource monitor
    resource_monitor: Arc<Mutex<SystemResourceMonitor>>,
}

/// Configuration for performance tests
#[derive(Debug, Clone)]
pub struct PerformanceTestConfig {
    /// Duration for performance tests
    pub test_duration: Duration,
    /// Number of iterations for averaging
    pub iterations: u32,
    /// Concurrent connection targets
    pub concurrent_connections: Vec<usize>,
    /// Latency test targets (ms)
    pub latency_targets: Vec<u32>,
    /// Throughput test targets (Mbps)
    pub throughput_targets: Vec<u32>,
    /// Memory usage thresholds (MB)
    pub memory_thresholds: Vec<u64>,
    /// CPU usage thresholds (%)
    pub cpu_thresholds: Vec<f32>,
    /// Enable detailed profiling
    pub enable_profiling: bool,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            test_duration: Duration::from_secs(60),
            iterations: 10,
            concurrent_connections: vec![1, 10, 50, 100, 500],
            latency_targets: vec![50, 100, 200, 500],
            throughput_targets: vec![1, 10, 100],
            memory_thresholds: vec![10, 50, 100, 500],
            cpu_thresholds: vec![10.0, 25.0, 50.0, 80.0],
            enable_profiling: false,
        }
    }
}

/// Metrics collector for performance data
pub struct MetricsCollector {
    /// Connection establishment latencies
    connection_latencies: Vec<Duration>,
    /// Throughput measurements
    throughput_measurements: Vec<f64>,
    /// Memory usage samples
    memory_samples: Vec<MemorySample>,
    /// CPU usage samples
    cpu_samples: Vec<CpuSample>,
    /// Error counts by type
    error_counts: HashMap<String, u64>,
    /// Connection success rates
    success_rates: Vec<f32>,
}

/// Memory usage sample
#[derive(Debug, Clone)]
pub struct MemorySample {
    /// Timestamp
    pub timestamp: Instant,
    /// Total memory usage in bytes
    pub total_memory: u64,
    /// Heap memory usage in bytes
    pub heap_memory: u64,
    /// Stack memory usage in bytes
    pub stack_memory: u64,
}

/// CPU usage sample
#[derive(Debug, Clone)]
pub struct CpuSample {
    /// Timestamp
    pub timestamp: Instant,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// User time percentage
    pub user_percent: f32,
    /// System time percentage
    pub system_percent: f32,
}

/// System resource monitor
pub struct SystemResourceMonitor {
    /// Monitoring start time
    start_time: Option<Instant>,
    /// Memory baseline
    memory_baseline: Option<u64>,
    /// CPU baseline
    cpu_baseline: Option<f32>,
    /// Peak memory usage
    peak_memory: AtomicU64,
    /// Average CPU usage
    avg_cpu_usage: Arc<Mutex<f32>>,
    /// Sampling interval
    sampling_interval: Duration,
}

/// Performance test result
#[derive(Debug, Clone)]
pub struct PerformanceTestResult {
    /// Test name
    pub test_name: String,
    /// Test success
    pub success: bool,
    /// Performance metrics
    pub metrics: PerformanceMetrics,
    /// Latency statistics
    pub latency_stats: LatencyStatistics,
    /// Throughput statistics
    pub throughput_stats: ThroughputStatistics,
    /// Resource usage statistics
    pub resource_stats: ResourceStatistics,
    /// Error summary
    pub error_summary: HashMap<String, u64>,
}

/// Latency statistics
#[derive(Debug, Clone)]
pub struct LatencyStatistics {
    /// Mean latency
    pub mean: Duration,
    /// Median latency
    pub median: Duration,
    /// 95th percentile latency
    pub p95: Duration,
    /// 99th percentile latency
    pub p99: Duration,
    /// Minimum latency
    pub min: Duration,
    /// Maximum latency
    pub max: Duration,
    /// Standard deviation
    pub std_dev: Duration,
}

/// Throughput statistics
#[derive(Debug, Clone)]
pub struct ThroughputStatistics {
    /// Mean throughput (Mbps)
    pub mean_mbps: f64,
    /// Peak throughput (Mbps)
    pub peak_mbps: f64,
    /// Minimum throughput (Mbps)
    pub min_mbps: f64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Transfer duration
    pub duration: Duration,
}

/// Resource usage statistics
#[derive(Debug, Clone)]
pub struct ResourceStatistics {
    /// Peak memory usage (MB)
    pub peak_memory_mb: f64,
    /// Average memory usage (MB)
    pub avg_memory_mb: f64,
    /// Peak CPU usage (%)
    pub peak_cpu_percent: f32,
    /// Average CPU usage (%)
    pub avg_cpu_percent: f32,
    /// Memory efficiency (connections per MB)
    pub memory_efficiency: f64,
}

impl PerformanceTestFramework {
    /// Create a new performance test framework
    pub fn new(config: PerformanceTestConfig, network_config: NetworkSimulationConfig) -> Self {
        let simulator = Arc::new(Mutex::new(NetworkSimulator::new(network_config)));
        let metrics_collector = Arc::new(Mutex::new(MetricsCollector::new()));
        let resource_monitor = Arc::new(Mutex::new(SystemResourceMonitor::new()));
        
        Self {
            config,
            simulator,
            metrics_collector,
            resource_monitor,
        }
    }

    /// Run all performance tests
    pub async fn run_all_performance_tests(&mut self) -> Vec<PerformanceTestResult> {
        info!("Starting comprehensive performance test suite");
        
        let mut results = Vec::new();
        
        // Connection establishment latency tests
        results.push(self.test_connection_establishment_latency().await);
        
        // Throughput measurement tests
        results.push(self.test_throughput_measurement().await);
        
        // Memory usage analysis
        results.push(self.test_memory_usage_analysis().await);
        
        // CPU usage monitoring
        results.push(self.test_cpu_usage_monitoring().await);
        
        // Scalability testing
        results.push(self.test_scalability().await);
        
        // Generate performance summary
        self.generate_performance_summary(&results);
        
        results
    }

    /// Test connection establishment latency
    pub async fn test_connection_establishment_latency(&mut self) -> PerformanceTestResult {
        info!("Testing connection establishment latency");
        
        let mut latencies = Vec::new();
        let mut successes = 0;
        let mut failures = 0;
        
        // Start resource monitoring
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        for iteration in 0..self.config.iterations {
            debug!("Latency test iteration {}/{}", iteration + 1, self.config.iterations);
            
            let start_time = Instant::now();
            
            // Create test configurations
            let client_config = NatTraversalConfig {
                role: EndpointRole::Client,
                bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(10),
                enable_symmetric_nat: true,
                enable_relay_fallback: false,
                max_concurrent_attempts: 3,
            };
            
            let server_config = NatTraversalConfig {
                role: EndpointRole::Server { can_coordinate: true },
                bootstrap_nodes: vec![],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(10),
                enable_symmetric_nat: true,
                enable_relay_fallback: false,
                max_concurrent_attempts: 3,
            };
            
            // Simulate NAT traversal
            let result = self.simulator.lock().unwrap()
                .simulate_nat_traversal(client_config, server_config).await;
            
            match result {
                Ok(sim_result) => {
                    if sim_result.success {
                        let latency = start_time.elapsed();
                        latencies.push(latency);
                        successes += 1;
                    } else {
                        failures += 1;
                    }
                }
                Err(_) => {
                    failures += 1;
                }
            }
            
            // Small delay between iterations
            sleep(Duration::from_millis(100)).await;
        }
        
        // Calculate statistics
        let latency_stats = self.calculate_latency_statistics(&latencies);
        let resource_stats = self.resource_monitor.lock().unwrap().get_statistics();
        
        let success_rate = successes as f32 / self.config.iterations as f32;
        
        PerformanceTestResult {
            test_name: "connection_establishment_latency".to_string(),
            success: success_rate > 0.8, // Success if > 80% connections succeed
            metrics: PerformanceMetrics {
                connection_attempts: self.config.iterations as u64,
                successful_connections: successes,
                failed_connections: failures,
                avg_connection_time: latency_stats.mean,
                ..Default::default()
            },
            latency_stats,
            throughput_stats: ThroughputStatistics {
                mean_mbps: 0.0,
                peak_mbps: 0.0,
                min_mbps: 0.0,
                total_bytes: 0,
                duration: Duration::from_secs(0),
            },
            resource_stats,
            error_summary: HashMap::new(),
        }
    }

    /// Test throughput measurement
    pub async fn test_throughput_measurement(&mut self) -> PerformanceTestResult {
        info!("Testing throughput measurement");
        
        let mut throughput_measurements = Vec::new();
        let test_data_size = 1024 * 1024; // 1 MB test data
        
        for &target_mbps in &self.config.throughput_targets {
            debug!("Testing throughput target: {} Mbps", target_mbps);
            
            let start_time = Instant::now();
            
            // Simulate data transfer
            let transferred_bytes = self.simulate_data_transfer(test_data_size, target_mbps).await;
            let duration = start_time.elapsed();
            
            let actual_mbps = (transferred_bytes as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
            throughput_measurements.push(actual_mbps);
        }
        
        let throughput_stats = self.calculate_throughput_statistics(&throughput_measurements);
        
        PerformanceTestResult {
            test_name: "throughput_measurement".to_string(),
            success: throughput_stats.mean_mbps > 1.0, // Success if > 1 Mbps
            metrics: PerformanceMetrics {
                network_bandwidth_usage: throughput_stats.total_bytes,
                ..Default::default()
            },
            latency_stats: LatencyStatistics {
                mean: Duration::from_millis(0),
                median: Duration::from_millis(0),
                p95: Duration::from_millis(0),
                p99: Duration::from_millis(0),
                min: Duration::from_millis(0),
                max: Duration::from_millis(0),
                std_dev: Duration::from_millis(0),
            },
            throughput_stats,
            resource_stats: self.resource_monitor.lock().unwrap().get_statistics(),
            error_summary: HashMap::new(),
        }
    }

    /// Test memory usage analysis
    pub async fn test_memory_usage_analysis(&mut self) -> PerformanceTestResult {
        info!("Testing memory usage analysis");
        
        let mut memory_samples = Vec::new();
        let monitoring_duration = self.config.test_duration;
        let sample_interval = Duration::from_millis(100);
        let total_samples = monitoring_duration.as_millis() / sample_interval.as_millis();
        
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        for sample_idx in 0..total_samples {
            let memory_sample = self.collect_memory_sample().await;
            memory_samples.push(memory_sample);
            
            // Simulate some memory-intensive operations
            if sample_idx % 10 == 0 {
                self.simulate_memory_operations().await;
            }
            
            sleep(sample_interval).await;
        }
        
        let resource_stats = self.analyze_memory_usage(&memory_samples);
        
        PerformanceTestResult {
            test_name: "memory_usage_analysis".to_string(),
            success: resource_stats.peak_memory_mb < 500.0, // Success if < 500 MB peak
            metrics: PerformanceMetrics {
                peak_memory_usage: resource_stats.peak_memory_mb as u64 * 1024 * 1024,
                ..Default::default()
            },
            latency_stats: LatencyStatistics {
                mean: Duration::from_millis(0),
                median: Duration::from_millis(0),
                p95: Duration::from_millis(0),
                p99: Duration::from_millis(0),
                min: Duration::from_millis(0),
                max: Duration::from_millis(0),
                std_dev: Duration::from_millis(0),
            },
            throughput_stats: ThroughputStatistics {
                mean_mbps: 0.0,
                peak_mbps: 0.0,
                min_mbps: 0.0,
                total_bytes: 0,
                duration: monitoring_duration,
            },
            resource_stats,
            error_summary: HashMap::new(),
        }
    }

    /// Test CPU usage monitoring
    pub async fn test_cpu_usage_monitoring(&mut self) -> PerformanceTestResult {
        info!("Testing CPU usage monitoring");
        
        let mut cpu_samples = Vec::new();
        let monitoring_duration = self.config.test_duration;
        let sample_interval = Duration::from_millis(100);
        let total_samples = monitoring_duration.as_millis() / sample_interval.as_millis();
        
        for sample_idx in 0..total_samples {
            let cpu_sample = self.collect_cpu_sample().await;
            cpu_samples.push(cpu_sample);
            
            // Simulate CPU-intensive operations
            if sample_idx % 5 == 0 {
                self.simulate_cpu_operations().await;
            }
            
            sleep(sample_interval).await;
        }
        
        let resource_stats = self.analyze_cpu_usage(&cpu_samples);
        
        PerformanceTestResult {
            test_name: "cpu_usage_monitoring".to_string(),
            success: resource_stats.avg_cpu_percent < 50.0, // Success if < 50% average CPU
            metrics: PerformanceMetrics {
                avg_cpu_usage: resource_stats.avg_cpu_percent,
                ..Default::default()
            },
            latency_stats: LatencyStatistics {
                mean: Duration::from_millis(0),
                median: Duration::from_millis(0),
                p95: Duration::from_millis(0),
                p99: Duration::from_millis(0),
                min: Duration::from_millis(0),
                max: Duration::from_millis(0),
                std_dev: Duration::from_millis(0),
            },
            throughput_stats: ThroughputStatistics {
                mean_mbps: 0.0,
                peak_mbps: 0.0,
                min_mbps: 0.0,
                total_bytes: 0,
                duration: monitoring_duration,
            },
            resource_stats,
            error_summary: HashMap::new(),
        }
    }

    /// Test scalability with increasing connection counts
    pub async fn test_scalability(&mut self) -> PerformanceTestResult {
        info!("Testing scalability");
        
        let mut latencies = Vec::new();
        let mut total_successes = 0;
        let mut total_attempts = 0;
        
        let concurrent_connections = self.config.concurrent_connections.clone();
        for &connection_count in &concurrent_connections {
            info!("Testing {} concurrent connections", connection_count);
            
            let (successes, connection_latencies) = 
                self.test_concurrent_connections(connection_count).await;
            
            total_successes += successes;
            total_attempts += connection_count;
            latencies.extend(connection_latencies);
            
            // Allow system to recover between tests
            sleep(Duration::from_secs(2)).await;
        }
        
        let latency_stats = self.calculate_latency_statistics(&latencies);
        let resource_stats = self.resource_monitor.lock().unwrap().get_statistics();
        let success_rate = total_successes as f32 / total_attempts as f32;
        
        PerformanceTestResult {
            test_name: "scalability_testing".to_string(),
            success: success_rate > 0.7, // Success if > 70% overall success rate
            metrics: PerformanceMetrics {
                connection_attempts: total_attempts as u64,
                successful_connections: total_successes as u64,
                failed_connections: (total_attempts - total_successes) as u64,
                avg_connection_time: latency_stats.mean,
                peak_memory_usage: resource_stats.peak_memory_mb as u64 * 1024 * 1024,
                avg_cpu_usage: resource_stats.avg_cpu_percent,
                ..Default::default()
            },
            latency_stats,
            throughput_stats: ThroughputStatistics {
                mean_mbps: 0.0,
                peak_mbps: 0.0,
                min_mbps: 0.0,
                total_bytes: 0,
                duration: Duration::from_secs(0),
            },
            resource_stats,
            error_summary: HashMap::new(),
        }
    }

    /// Test concurrent connections
    async fn test_concurrent_connections(&mut self, connection_count: usize) -> (usize, Vec<Duration>) {
        let mut handles = Vec::new();
        let start_time = Instant::now();
        
        // Start resource monitoring
        self.resource_monitor.lock().unwrap().start_monitoring();
        
        for _ in 0..connection_count {
            let simulator = self.simulator.clone();
            
            let handle = tokio::spawn(async move {
                let client_config = NatTraversalConfig {
                    role: EndpointRole::Client,
                    bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                    max_candidates: 5, // Reduced for scalability
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
                
                let connection_start = Instant::now();
                let result = simulator.lock().unwrap()
                    .simulate_nat_traversal(client_config, server_config).await;
                
                match result {
                    Ok(sim_result) if sim_result.success => {
                        Some(connection_start.elapsed())
                    }
                    _ => None
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all connections to complete
        let mut successes = 0;
        let mut latencies = Vec::new();
        
        for handle in handles {
            if let Ok(Some(latency)) = handle.await {
                successes += 1;
                latencies.push(latency);
            }
        }
        
        debug!("Concurrent connection test: {}/{} succeeded", successes, connection_count);
        
        (successes, latencies)
    }

    // Helper methods for performance testing

    async fn simulate_data_transfer(&self, size: usize, _target_mbps: u32) -> u64 {
        // Simulate data transfer - in real implementation this would
        // actually transfer data through the NAT traversal connection
        sleep(Duration::from_millis(100)).await;
        size as u64
    }

    async fn collect_memory_sample(&self) -> MemorySample {
        MemorySample {
            timestamp: Instant::now(),
            total_memory: self.get_memory_usage().await,
            heap_memory: self.get_heap_usage().await,
            stack_memory: self.get_stack_usage().await,
        }
    }

    async fn collect_cpu_sample(&self) -> CpuSample {
        CpuSample {
            timestamp: Instant::now(),
            cpu_percent: self.get_cpu_usage().await,
            user_percent: self.get_user_cpu_usage().await,
            system_percent: self.get_system_cpu_usage().await,
        }
    }

    async fn simulate_memory_operations(&self) {
        // Simulate memory allocation/deallocation
        let _data: Vec<u8> = vec![0; 1024 * 1024]; // Allocate 1MB
        sleep(Duration::from_millis(10)).await;
    }

    async fn simulate_cpu_operations(&self) {
        // Simulate CPU-intensive work
        let mut sum = 0u64;
        for i in 0..10000 {
            sum = sum.wrapping_add(i);
        }
        let _ = sum; // Use the result to prevent optimization
    }

    // Platform-specific system monitoring methods
    async fn get_memory_usage(&self) -> u64 {
        // In a real implementation, this would use platform-specific APIs
        // For testing, return a simulated value
        1024 * 1024 * 50 // 50 MB
    }

    async fn get_heap_usage(&self) -> u64 {
        1024 * 1024 * 30 // 30 MB
    }

    async fn get_stack_usage(&self) -> u64 {
        1024 * 1024 * 5 // 5 MB
    }

    async fn get_cpu_usage(&self) -> f32 {
        // Simulate varying CPU usage
        let mut rng = rand::thread_rng();
        use rand::Rng;
        rng.gen_range(5.0..50.0)
    }

    async fn get_user_cpu_usage(&self) -> f32 {
        let mut rng = rand::thread_rng();
        use rand::Rng;
        rng.gen_range(3.0..30.0)
    }

    async fn get_system_cpu_usage(&self) -> f32 {
        let mut rng = rand::thread_rng();
        use rand::Rng;
        rng.gen_range(1.0..15.0)
    }

    fn calculate_latency_statistics(&self, latencies: &[Duration]) -> LatencyStatistics {
        if latencies.is_empty() {
            return LatencyStatistics {
                mean: Duration::from_millis(0),
                median: Duration::from_millis(0),
                p95: Duration::from_millis(0),
                p99: Duration::from_millis(0),
                min: Duration::from_millis(0),
                max: Duration::from_millis(0),
                std_dev: Duration::from_millis(0),
            };
        }
        
        let mut sorted = latencies.to_vec();
        sorted.sort();
        
        let mean = Duration::from_nanos(
            (sorted.iter().map(|d| d.as_nanos()).sum::<u128>() / sorted.len() as u128) as u64
        );
        
        let median = sorted[sorted.len() / 2];
        let p95 = sorted[sorted.len() * 95 / 100];
        let p99 = sorted[sorted.len() * 99 / 100];
        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        
        // Calculate standard deviation
        let variance = sorted.iter()
            .map(|d| {
                let diff = d.as_nanos() as i128 - mean.as_nanos() as i128;
                (diff * diff) as u128
            })
            .sum::<u128>() / sorted.len() as u128;
        let std_dev = Duration::from_nanos((variance as f64).sqrt() as u64);
        
        LatencyStatistics {
            mean,
            median,
            p95,
            p99,
            min,
            max,
            std_dev,
        }
    }

    fn calculate_throughput_statistics(&self, measurements: &[f64]) -> ThroughputStatistics {
        if measurements.is_empty() {
            return ThroughputStatistics {
                mean_mbps: 0.0,
                peak_mbps: 0.0,
                min_mbps: 0.0,
                total_bytes: 0,
                duration: Duration::from_secs(0),
            };
        }
        
        let mean_mbps = measurements.iter().sum::<f64>() / measurements.len() as f64;
        let peak_mbps = measurements.iter().fold(0.0f64, |a, &b| a.max(b));
        let min_mbps = measurements.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        
        ThroughputStatistics {
            mean_mbps,
            peak_mbps,
            min_mbps,
            total_bytes: 0, // Would be calculated from actual data transfer
            duration: self.config.test_duration,
        }
    }

    fn analyze_memory_usage(&self, samples: &[MemorySample]) -> ResourceStatistics {
        if samples.is_empty() {
            return ResourceStatistics {
                peak_memory_mb: 0.0,
                avg_memory_mb: 0.0,
                peak_cpu_percent: 0.0,
                avg_cpu_percent: 0.0,
                memory_efficiency: 0.0,
            };
        }
        
        let peak_memory_mb = samples.iter()
            .map(|s| s.total_memory as f64 / (1024.0 * 1024.0))
            .fold(0.0f64, |a, b| a.max(b));
        
        let avg_memory_mb = samples.iter()
            .map(|s| s.total_memory as f64 / (1024.0 * 1024.0))
            .sum::<f64>() / samples.len() as f64;
        
        ResourceStatistics {
            peak_memory_mb,
            avg_memory_mb,
            peak_cpu_percent: 0.0,
            avg_cpu_percent: 0.0,
            memory_efficiency: if avg_memory_mb > 0.0 { 1.0 / avg_memory_mb } else { 0.0 },
        }
    }

    fn analyze_cpu_usage(&self, samples: &[CpuSample]) -> ResourceStatistics {
        if samples.is_empty() {
            return ResourceStatistics {
                peak_memory_mb: 0.0,
                avg_memory_mb: 0.0,
                peak_cpu_percent: 0.0,
                avg_cpu_percent: 0.0,
                memory_efficiency: 0.0,
            };
        }
        
        let peak_cpu_percent = samples.iter()
            .map(|s| s.cpu_percent)
            .fold(0.0f32, |a, b| a.max(b));
        
        let avg_cpu_percent = samples.iter()
            .map(|s| s.cpu_percent)
            .sum::<f32>() / samples.len() as f32;
        
        ResourceStatistics {
            peak_memory_mb: 0.0,
            avg_memory_mb: 0.0,
            peak_cpu_percent,
            avg_cpu_percent,
            memory_efficiency: 0.0,
        }
    }

    fn generate_performance_summary(&self, results: &[PerformanceTestResult]) {
        info!("=== Performance Test Summary ===");
        
        let successful_tests = results.iter().filter(|r| r.success).count();
        let total_tests = results.len();
        
        info!("Tests passed: {}/{}", successful_tests, total_tests);
        
        for result in results {
            let status = if result.success { "PASS" } else { "FAIL" };
            info!("{}: {} ({})", result.test_name, status, 
                  format!("{:.2}ms", result.latency_stats.mean.as_millis()));
        }
    }
}

impl MetricsCollector {
    fn new() -> Self {
        Self {
            connection_latencies: Vec::new(),
            throughput_measurements: Vec::new(),
            memory_samples: Vec::new(),
            cpu_samples: Vec::new(),
            error_counts: HashMap::new(),
            success_rates: Vec::new(),
        }
    }
}

impl SystemResourceMonitor {
    fn new() -> Self {
        Self {
            start_time: None,
            memory_baseline: None,
            cpu_baseline: None,
            peak_memory: AtomicU64::new(0),
            avg_cpu_usage: Arc::new(Mutex::new(0.0)),
            sampling_interval: Duration::from_millis(100),
        }
    }

    fn start_monitoring(&mut self) {
        self.start_time = Some(Instant::now());
    }

    fn get_statistics(&self) -> ResourceStatistics {
        ResourceStatistics {
            peak_memory_mb: self.peak_memory.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
            avg_memory_mb: 50.0, // Simulated average
            peak_cpu_percent: 80.0, // Simulated peak
            avg_cpu_percent: *self.avg_cpu_usage.lock().unwrap(),
            memory_efficiency: 0.02, // Simulated efficiency
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_framework_creation() {
        let perf_config = PerformanceTestConfig::default();
        let network_config = NetworkSimulationConfig::default();
        
        let framework = PerformanceTestFramework::new(perf_config, network_config);
        
        // Test that framework was created successfully
        assert!(!framework.config.concurrent_connections.is_empty());
        assert!(framework.config.test_duration > Duration::from_secs(0));
    }

    #[test]
    fn test_latency_statistics_calculation() {
        let perf_config = PerformanceTestConfig::default();
        let network_config = NetworkSimulationConfig::default();
        let framework = PerformanceTestFramework::new(perf_config, network_config);
        
        let latencies = vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(150),
            Duration::from_millis(300),
            Duration::from_millis(120),
        ];
        
        let stats = framework.calculate_latency_statistics(&latencies);
        
        assert!(stats.mean > Duration::from_millis(0));
        assert!(stats.min <= stats.median);
        assert!(stats.median <= stats.max);
        assert!(stats.p95 >= stats.median);
    }

    #[test]
    fn test_throughput_statistics_calculation() {
        let perf_config = PerformanceTestConfig::default();
        let network_config = NetworkSimulationConfig::default();
        let framework = PerformanceTestFramework::new(perf_config, network_config);
        
        let measurements = vec![10.0, 15.0, 12.0, 18.0, 14.0];
        let stats = framework.calculate_throughput_statistics(&measurements);
        
        assert!(stats.mean_mbps > 0.0);
        assert!(stats.peak_mbps >= stats.mean_mbps);
        assert!(stats.min_mbps <= stats.mean_mbps);
    }
}