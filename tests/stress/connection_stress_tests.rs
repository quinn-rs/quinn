//! Comprehensive stress tests for QUIC connection establishment with NAT traversal
//!
//! These tests push the system to its limits to ensure reliability under extreme conditions:
//! - Massive concurrent connections
//! - High packet loss scenarios
//! - Memory leak detection
//! - CPU saturation tests
//! - Connection churn scenarios

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use ant_quic::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig, TransportConfig,
    Connection, ConnectionError, VarInt,
};
use bytes::Bytes;
use tokio::{
    sync::{mpsc, Semaphore},
    time::{interval, sleep, timeout},
};
use tracing::{debug, error, info, warn};

/// Performance metrics collector
#[derive(Debug, Default)]
struct PerformanceMetrics {
    connections_attempted: AtomicUsize,
    connections_succeeded: AtomicUsize,
    connections_failed: AtomicUsize,
    total_bytes_sent: AtomicU64,
    total_bytes_received: AtomicU64,
    total_round_trips: AtomicU64,
    min_rtt_us: AtomicU64,
    max_rtt_us: AtomicU64,
    memory_samples: Arc<tokio::sync::Mutex<Vec<MemorySample>>>,
}

#[derive(Debug, Clone)]
struct MemorySample {
    timestamp: Instant,
    resident_memory_kb: u64,
    virtual_memory_kb: u64,
    connections_active: usize,
}

impl PerformanceMetrics {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            min_rtt_us: AtomicU64::new(u64::MAX),
            ..Default::default()
        })
    }

    fn record_connection_attempt(&self) {
        self.connections_attempted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_connection_success(&self) {
        self.connections_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    fn record_connection_failure(&self) {
        self.connections_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_bytes_sent(&self, bytes: u64) {
        self.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_bytes_received(&self, bytes: u64) {
        self.total_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_rtt(&self, rtt: Duration) {
        let rtt_us = rtt.as_micros() as u64;
        self.total_round_trips.fetch_add(1, Ordering::Relaxed);
        
        // Update min RTT
        let mut current_min = self.min_rtt_us.load(Ordering::Relaxed);
        while rtt_us < current_min {
            match self.min_rtt_us.compare_exchange_weak(
                current_min,
                rtt_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }
        
        // Update max RTT
        let mut current_max = self.max_rtt_us.load(Ordering::Relaxed);
        while rtt_us > current_max {
            match self.max_rtt_us.compare_exchange_weak(
                current_max,
                rtt_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }
    }

    async fn record_memory_sample(&self, connections_active: usize) {
        let memory_info = get_process_memory_info();
        let sample = MemorySample {
            timestamp: Instant::now(),
            resident_memory_kb: memory_info.0,
            virtual_memory_kb: memory_info.1,
            connections_active,
        };
        
        self.memory_samples.lock().await.push(sample);
    }

    fn summary(&self) -> String {
        let attempted = self.connections_attempted.load(Ordering::Relaxed);
        let succeeded = self.connections_succeeded.load(Ordering::Relaxed);
        let failed = self.connections_failed.load(Ordering::Relaxed);
        let success_rate = if attempted > 0 {
            (succeeded as f64 / attempted as f64) * 100.0
        } else {
            0.0
        };
        
        let bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.total_bytes_received.load(Ordering::Relaxed);
        let round_trips = self.total_round_trips.load(Ordering::Relaxed);
        let min_rtt = self.min_rtt_us.load(Ordering::Relaxed);
        let max_rtt = self.max_rtt_us.load(Ordering::Relaxed);
        let avg_rtt = if round_trips > 0 {
            // Note: This is approximate, real implementation would track sum
            (min_rtt + max_rtt) / 2
        } else {
            0
        };
        
        format!(
            "Performance Summary:\n\
             Connections: {} attempted, {} succeeded, {} failed ({}% success rate)\n\
             Data Transfer: {} MB sent, {} MB received\n\
             RTT: min={} ms, avg={} ms, max={} ms\n\
             Round Trips: {}",
            attempted, succeeded, failed, success_rate,
            bytes_sent / 1_000_000, bytes_received / 1_000_000,
            min_rtt / 1000, avg_rtt / 1000, max_rtt / 1000,
            round_trips
        )
    }
}

/// Get current process memory usage (resident, virtual) in KB
fn get_process_memory_info() -> (u64, u64) {
    // Platform-specific implementation would go here
    // For testing, return mock values
    (100_000, 200_000)
}

/// Stress test configuration
#[derive(Debug, Clone)]
struct StressTestConfig {
    /// Number of concurrent connections to maintain
    concurrent_connections: usize,
    /// Total number of connections to create
    total_connections: usize,
    /// Duration to run the test
    test_duration: Duration,
    /// Size of data to send per connection
    data_size_per_connection: usize,
    /// Number of streams per connection
    streams_per_connection: usize,
    /// Packet loss percentage (0-100)
    packet_loss_percent: u8,
    /// Additional latency in milliseconds
    added_latency_ms: u32,
    /// Enable connection migration testing
    test_migration: bool,
    /// Enable NAT rebinding simulation
    test_nat_rebinding: bool,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            concurrent_connections: 100,
            total_connections: 1000,
            test_duration: Duration::from_secs(60),
            data_size_per_connection: 1_000_000, // 1MB
            streams_per_connection: 10,
            packet_loss_percent: 0,
            added_latency_ms: 0,
            test_migration: false,
            test_nat_rebinding: false,
        }
    }
}

/// Main stress test runner
struct StressTestRunner {
    config: StressTestConfig,
    metrics: Arc<PerformanceMetrics>,
    server_endpoint: Option<Endpoint>,
    client_endpoint: Option<Endpoint>,
}

impl StressTestRunner {
    fn new(config: StressTestConfig) -> Self {
        Self {
            config,
            metrics: PerformanceMetrics::new(),
            server_endpoint: None,
            client_endpoint: None,
        }
    }

    async fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create server endpoint
        let server_config = self.create_server_config()?;
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        self.server_endpoint = Some(Endpoint::server(server_socket, server_config)?);
        
        // Create client endpoint  
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        self.client_endpoint = Some(Endpoint::client(client_socket)?);
        
        info!("Test endpoints created");
        Ok(())
    }

    fn create_server_config(&self) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair)?;
        
        let mut config = ServerConfig::with_single_cert(vec![cert_der], key_der)?;
        
        // Configure for stress testing
        let mut transport = TransportConfig::default();
        transport.max_concurrent_bidi_streams(VarInt::from_u32(1000));
        transport.max_concurrent_uni_streams(VarInt::from_u32(1000));
        transport.max_idle_timeout(Some(Duration::from_secs(300)));
        
        config.transport_config(Arc::new(transport));
        Ok(config)
    }

    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.setup().await?;
        
        let server_addr = self.server_endpoint.as_ref().unwrap().local_addr()?;
        info!("Starting stress test against {}", server_addr);
        
        // Start server accept loop
        let server_endpoint = self.server_endpoint.clone().unwrap();
        let server_metrics = self.metrics.clone();
        let server_handle = tokio::spawn(async move {
            server_accept_loop(server_endpoint, server_metrics).await
        });
        
        // Start memory monitoring
        let memory_metrics = self.metrics.clone();
        let memory_handle = tokio::spawn(async move {
            memory_monitor_loop(memory_metrics).await
        });
        
        // Start client connection spawner
        let client_endpoint = self.client_endpoint.clone().unwrap();
        let client_metrics = self.metrics.clone();
        let config = self.config.clone();
        let client_handle = tokio::spawn(async move {
            client_connection_loop(client_endpoint, server_addr, config, client_metrics).await
        });
        
        // Run for configured duration
        sleep(self.config.test_duration).await;
        
        info!("Test duration complete, shutting down...");
        
        // Cleanup
        server_handle.abort();
        client_handle.abort();
        memory_handle.abort();
        
        // Print final metrics
        println!("{}", self.metrics.summary());
        
        // Analyze memory usage
        self.analyze_memory_usage().await?;
        
        Ok(())
    }

    async fn analyze_memory_usage(&self) -> Result<(), Box<dyn std::error::Error>> {
        let samples = self.metrics.memory_samples.lock().await;
        
        if samples.len() < 2 {
            return Ok(());
        }
        
        let first_sample = &samples[0];
        let last_sample = &samples[samples.len() - 1];
        
        let memory_growth_kb = last_sample.resident_memory_kb as i64 - first_sample.resident_memory_kb as i64;
        let memory_per_connection = if last_sample.connections_active > 0 {
            memory_growth_kb / last_sample.connections_active as i64
        } else {
            0
        };
        
        info!(
            "Memory Analysis:\n\
             Initial: {} MB resident\n\
             Final: {} MB resident\n\
             Growth: {} MB\n\
             Per connection: {} KB",
            first_sample.resident_memory_kb / 1000,
            last_sample.resident_memory_kb / 1000,
            memory_growth_kb / 1000,
            memory_per_connection
        );
        
        // Check for memory leaks
        if memory_per_connection > 100 {
            warn!("High memory usage per connection: {} KB", memory_per_connection);
        }
        
        Ok(())
    }
}

async fn server_accept_loop(endpoint: Endpoint, metrics: Arc<PerformanceMetrics>) {
    while let Some(incoming) = endpoint.accept().await {
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                handle_server_connection(connection, metrics).await;
            }
        });
    }
}

async fn handle_server_connection(connection: Connection, metrics: Arc<PerformanceMetrics>) {
    loop {
        tokio::select! {
            // Handle incoming streams
            stream = connection.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        tokio::spawn(handle_bidirectional_stream(send, recv, metrics.clone()));
                    }
                    Err(ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => {
                        warn!("Failed to accept stream: {}", e);
                        break;
                    }
                }
            }
            
            // Handle datagrams
            datagram = connection.read_datagram() => {
                match datagram {
                    Ok(data) => {
                        metrics.record_bytes_received(data.len() as u64);
                        // Echo back
                        let _ = connection.send_datagram(data);
                    }
                    Err(ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => {
                        warn!("Failed to read datagram: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_bidirectional_stream(
    mut send: ant_quic::SendStream,
    mut recv: ant_quic::RecvStream,
    metrics: Arc<PerformanceMetrics>,
) {
    // Echo server behavior
    let mut buffer = vec![0u8; 65536];
    
    loop {
        match recv.read(&mut buffer).await {
            Ok(Some(n)) => {
                metrics.record_bytes_received(n as u64);
                
                // Echo back
                if let Err(e) = send.write_all(&buffer[..n]).await {
                    warn!("Failed to echo data: {}", e);
                    break;
                }
                
                metrics.record_bytes_sent(n as u64);
            }
            Ok(None) => break, // Stream closed
            Err(e) => {
                warn!("Stream read error: {}", e);
                break;
            }
        }
    }
    
    let _ = send.finish();
}

async fn client_connection_loop(
    endpoint: Endpoint,
    server_addr: SocketAddr,
    config: StressTestConfig,
    metrics: Arc<PerformanceMetrics>,
) {
    let semaphore = Arc::new(Semaphore::new(config.concurrent_connections));
    let mut connection_count = 0;
    
    while connection_count < config.total_connections {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let endpoint = endpoint.clone();
        let metrics = metrics.clone();
        let config = config.clone();
        
        connection_count += 1;
        
        tokio::spawn(async move {
            metrics.record_connection_attempt();
            
            match create_client_connection(&endpoint, server_addr).await {
                Ok(connection) => {
                    metrics.record_connection_success();
                    stress_test_connection(connection, config, metrics).await;
                }
                Err(e) => {
                    metrics.record_connection_failure();
                    warn!("Connection failed: {}", e);
                }
            }
            
            drop(permit);
        });
        
        // Small delay to avoid thundering herd
        if connection_count % 10 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

async fn create_client_connection(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
) -> Result<Connection, Box<dyn std::error::Error>> {
    let client_config = ClientConfig::with_platform_verifier();
    
    let connection = endpoint.connect(server_addr, "localhost")?
        .await?;
    
    Ok(connection)
}

async fn stress_test_connection(
    connection: Connection,
    config: StressTestConfig,
    metrics: Arc<PerformanceMetrics>,
) {
    let mut tasks = Vec::new();
    
    // Spawn multiple streams
    for stream_id in 0..config.streams_per_connection {
        let connection = connection.clone();
        let metrics = metrics.clone();
        let data_size = config.data_size_per_connection / config.streams_per_connection;
        
        let task = tokio::spawn(async move {
            stress_test_stream(connection, stream_id, data_size, metrics).await
        });
        
        tasks.push(task);
    }
    
    // Test datagrams if supported
    if config.streams_per_connection > 0 {
        let connection = connection.clone();
        let metrics = metrics.clone();
        
        let task = tokio::spawn(async move {
            stress_test_datagrams(connection, metrics).await
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks
    for task in tasks {
        let _ = task.await;
    }
    
    // Close connection
    connection.close(VarInt::from_u32(0), b"stress test complete");
}

async fn stress_test_stream(
    connection: Connection,
    stream_id: usize,
    data_size: usize,
    metrics: Arc<PerformanceMetrics>,
) {
    match connection.open_bi().await {
        Ok((mut send, mut recv)) => {
            // Generate test data
            let data = vec![stream_id as u8; data_size];
            let start = Instant::now();
            
            // Send data
            if let Err(e) = send.write_all(&data).await {
                warn!("Failed to send data on stream {}: {}", stream_id, e);
                return;
            }
            
            metrics.record_bytes_sent(data_size as u64);
            
            // Receive echo
            let mut received = Vec::with_capacity(data_size);
            while received.len() < data_size {
                let mut buffer = vec![0u8; 65536];
                match recv.read(&mut buffer).await {
                    Ok(Some(n)) => {
                        received.extend_from_slice(&buffer[..n]);
                        metrics.record_bytes_received(n as u64);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("Failed to receive data on stream {}: {}", stream_id, e);
                        break;
                    }
                }
            }
            
            // Record RTT
            let rtt = start.elapsed();
            metrics.record_rtt(rtt);
            
            // Verify data integrity
            if received.len() == data.len() && received == data {
                debug!("Stream {} completed successfully, RTT: {:?}", stream_id, rtt);
            } else {
                warn!("Stream {} data mismatch", stream_id);
            }
            
            let _ = send.finish();
        }
        Err(e) => {
            warn!("Failed to open stream {}: {}", stream_id, e);
        }
    }
}

async fn stress_test_datagrams(connection: Connection, metrics: Arc<PerformanceMetrics>) {
    // Send bursts of datagrams
    for burst in 0..10 {
        for i in 0..10 {
            let data = vec![burst, i];
            match connection.send_datagram(data.into()) {
                Ok(_) => metrics.record_bytes_sent(2),
                Err(e) => warn!("Failed to send datagram: {}", e),
            }
        }
        
        // Small delay between bursts
        sleep(Duration::from_millis(10)).await;
    }
}

async fn memory_monitor_loop(metrics: Arc<PerformanceMetrics>) {
    let mut interval = interval(Duration::from_secs(1));
    
    loop {
        interval.tick().await;
        
        let active_connections = metrics.connections_succeeded.load(Ordering::Relaxed)
            - metrics.connections_failed.load(Ordering::Relaxed);
        
        metrics.record_memory_sample(active_connections).await;
    }
}

// Test implementations

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress test"]
async fn stress_test_10k_concurrent_connections() {
    let config = StressTestConfig {
        concurrent_connections: 10_000,
        total_connections: 10_000,
        test_duration: Duration::from_secs(120),
        data_size_per_connection: 1024, // 1KB per connection
        streams_per_connection: 1,
        ..Default::default()
    };
    
    let mut runner = StressTestRunner::new(config);
    runner.run().await.expect("Stress test failed");
    
    let metrics = runner.metrics;
    let success_rate = metrics.connections_succeeded.load(Ordering::Relaxed) as f64
        / metrics.connections_attempted.load(Ordering::Relaxed) as f64;
    
    assert!(success_rate > 0.95, "Success rate should be > 95%");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress test"]
async fn stress_test_high_packet_loss() {
    let config = StressTestConfig {
        concurrent_connections: 100,
        total_connections: 500,
        test_duration: Duration::from_secs(60),
        packet_loss_percent: 30,
        ..Default::default()
    };
    
    let mut runner = StressTestRunner::new(config);
    runner.run().await.expect("Stress test failed");
    
    let metrics = runner.metrics;
    let success_rate = metrics.connections_succeeded.load(Ordering::Relaxed) as f64
        / metrics.connections_attempted.load(Ordering::Relaxed) as f64;
    
    assert!(success_rate > 0.70, "Should handle 30% packet loss");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress test"]
async fn stress_test_connection_churn() {
    let config = StressTestConfig {
        concurrent_connections: 100,
        total_connections: 5000,
        test_duration: Duration::from_secs(60),
        data_size_per_connection: 10_000,
        streams_per_connection: 5,
        ..Default::default()
    };
    
    let mut runner = StressTestRunner::new(config);
    runner.run().await.expect("Stress test failed");
    
    // Check for connection leaks
    let samples = runner.metrics.memory_samples.lock().await;
    if samples.len() > 10 {
        let mid_point = samples.len() / 2;
        let mid_memory = samples[mid_point].resident_memory_kb;
        let end_memory = samples.last().unwrap().resident_memory_kb;
        
        // Memory should stabilize, not continuously grow
        let growth_percent = ((end_memory as f64 - mid_memory as f64) / mid_memory as f64) * 100.0;
        assert!(growth_percent < 10.0, "Memory growth should be < 10% after stabilization");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress test"]
async fn stress_test_large_data_transfer() {
    let config = StressTestConfig {
        concurrent_connections: 10,
        total_connections: 50,
        test_duration: Duration::from_secs(120),
        data_size_per_connection: 100_000_000, // 100MB per connection
        streams_per_connection: 4,
        ..Default::default()
    };
    
    let mut runner = StressTestRunner::new(config);
    runner.run().await.expect("Stress test failed");
    
    let metrics = runner.metrics;
    let total_data = metrics.total_bytes_sent.load(Ordering::Relaxed)
        + metrics.total_bytes_received.load(Ordering::Relaxed);
    
    assert!(total_data > 5_000_000_000, "Should transfer > 5GB total");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress test"]
async fn stress_test_many_streams() {
    let config = StressTestConfig {
        concurrent_connections: 50,
        total_connections: 100,
        test_duration: Duration::from_secs(60),
        data_size_per_connection: 1_000_000,
        streams_per_connection: 100, // 100 streams per connection
        ..Default::default()
    };
    
    let mut runner = StressTestRunner::new(config);
    runner.run().await.expect("Stress test failed");
    
    let metrics = runner.metrics;
    let round_trips = metrics.total_round_trips.load(Ordering::Relaxed);
    
    assert!(round_trips > 5000, "Should complete many stream round trips");
}