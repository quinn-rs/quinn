//! Connection storm stress test
//! 
//! This test validates system behavior under extreme connection load,
//! simulating scenarios where hundreds or thousands of clients attempt
//! to connect simultaneously.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    Endpoint, EndpointConfig, ServerConfig, ClientConfig,
    TransportConfig, VarInt,
};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// Configuration for stress test scenarios
#[derive(Clone)]
struct StressConfig {
    /// Number of concurrent connections to establish
    pub connections: usize,
    /// Duration to maintain connections
    pub duration: Duration,
    /// Rate limit for connection establishment (per second)
    pub rate_limit: Option<usize>,
    /// Enable detailed logging
    pub verbose: bool,
}

impl Default for StressConfig {
    fn default() -> Self {
        Self {
            connections: std::env::var("STRESS_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            duration: Duration::from_secs(
                std::env::var("STRESS_DURATION")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300)
            ),
            rate_limit: None,
            verbose: false,
        }
    }
}

/// Metrics collected during stress test
#[derive(Default)]
struct StressMetrics {
    connections_attempted: AtomicU64,
    connections_succeeded: AtomicU64,
    connections_failed: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    peak_memory_mb: AtomicU64,
}

impl StressMetrics {
    fn report(&self) {
        let attempted = self.connections_attempted.load(Ordering::Relaxed);
        let succeeded = self.connections_succeeded.load(Ordering::Relaxed);
        let failed = self.connections_failed.load(Ordering::Relaxed);
        
        println!("\n=== Stress Test Results ===");
        println!("Connections attempted: {}", attempted);
        println!("Connections succeeded: {} ({:.1}%)", 
            succeeded, 
            (succeeded as f64 / attempted as f64) * 100.0
        );
        println!("Connections failed: {}", failed);
        println!("Data sent: {} MB", self.bytes_sent.load(Ordering::Relaxed) / 1_000_000);
        println!("Data received: {} MB", self.bytes_received.load(Ordering::Relaxed) / 1_000_000);
        println!("Peak memory: {} MB", self.peak_memory_mb.load(Ordering::Relaxed));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Long-running test
async fn stress_test_connection_storm() {
    let config = StressConfig::default();
    stress_test_scenario(config, connection_storm_scenario).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Long-running test  
async fn stress_test_sustained_throughput() {
    let config = StressConfig {
        connections: 50,
        duration: Duration::from_secs(1800), // 30 minutes
        ..Default::default()
    };
    stress_test_scenario(config, sustained_throughput_scenario).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Long-running test
async fn stress_test_connection_churn() {
    let config = StressConfig {
        connections: 200,
        duration: Duration::from_secs(600), // 10 minutes
        ..Default::default()
    };
    stress_test_scenario(config, connection_churn_scenario).await;
}

/// Main stress test runner
async fn stress_test_scenario<F, Fut>(
    config: StressConfig,
    scenario: F,
) where
    F: Fn(Arc<Endpoint>, SocketAddr, Arc<StressConfig>, Arc<StressMetrics>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let _ = tracing_subscriber::fmt::try_init();
    
    println!("Starting stress test:");
    println!("  Connections: {}", config.connections);
    println!("  Duration: {:?}", config.duration);
    println!("  Rate limit: {:?}", config.rate_limit);
    
    // Setup server
    let server_addr = "127.0.0.1:0".parse().unwrap();
    let (server_endpoint, server_addr) = create_server_endpoint(server_addr).await;
    
    // Setup metrics
    let metrics = Arc::new(StressMetrics::default());
    let metrics_clone = metrics.clone();
    
    // Start memory monitoring
    let stop_monitoring = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_monitoring.clone();
    let monitor_handle = tokio::spawn(async move {
        monitor_memory_usage(metrics_clone, stop_clone).await;
    });
    
    // Setup client endpoint
    let client_endpoint = create_client_endpoint().await;
    
    // Rate limiter
    let rate_limiter = config.rate_limit.map(|rate| {
        Arc::new(Semaphore::new(rate))
    });
    
    // Run scenario
    let start = Instant::now();
    let config = Arc::new(config);
    let tasks = Vec::new();
    
    // Spawn client connections
    for i in 0..config.connections {
        let client = client_endpoint.clone();
        let config = config.clone();
        let metrics = metrics.clone();
        let rate_limiter = rate_limiter.clone();
        
        let task = tokio::spawn(async move {
            // Rate limiting
            if let Some(limiter) = rate_limiter {
                let _permit = limiter.acquire().await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            
            metrics.connections_attempted.fetch_add(1, Ordering::Relaxed);
            
            scenario(client, server_addr, config, metrics).await;
        });
        
        tasks.push(task);
        
        // Avoid thundering herd
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    
    // Wait for duration or completion
    tokio::select! {
        _ = tokio::time::sleep(config.duration) => {
            println!("Test duration reached");
        }
        _ = futures::future::join_all(tasks) => {
            println!("All connections completed");
        }
    }
    
    let elapsed = start.elapsed();
    println!("Test completed in {:?}", elapsed);
    
    // Stop monitoring
    stop_monitoring.store(true, Ordering::Relaxed);
    monitor_handle.await.unwrap();
    
    // Report results
    metrics.report();
    
    // Verify thresholds
    let success_rate = metrics.connections_succeeded.load(Ordering::Relaxed) as f64
        / metrics.connections_attempted.load(Ordering::Relaxed) as f64;
    
    assert!(success_rate > 0.8, "Success rate too low: {:.1}%", success_rate * 100.0);
}

/// Connection storm scenario - many connections, minimal data
async fn connection_storm_scenario(
    endpoint: Arc<Endpoint>,
    server_addr: SocketAddr,
    _config: Arc<StressConfig>,
    metrics: Arc<StressMetrics>,
) {
    match endpoint.connect(server_addr, "localhost").unwrap().await {
        Ok(connection) => {
            metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
            
            // Send minimal data
            match connection.open_uni().await {
                Ok(mut stream) => {
                    let data = b"stress test ping";
                    if stream.write_all(data).await.is_ok() {
                        metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    let _ = stream.finish();
                }
                Err(_) => {}
            }
            
            // Keep connection alive briefly
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(_) => {
            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Sustained throughput scenario - fewer connections, more data
async fn sustained_throughput_scenario(
    endpoint: Arc<Endpoint>,
    server_addr: SocketAddr,
    config: Arc<StressConfig>,
    metrics: Arc<StressMetrics>,
) {
    match endpoint.connect(server_addr, "localhost").unwrap().await {
        Ok(connection) => {
            metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
            
            // Send data continuously
            let start = Instant::now();
            let mut total_sent = 0u64;
            let chunk = vec![0u8; 65536]; // 64KB chunks
            
            while start.elapsed() < config.duration {
                match connection.open_uni().await {
                    Ok(mut stream) => {
                        for _ in 0..10 {
                            if stream.write_all(&chunk).await.is_ok() {
                                total_sent += chunk.len() as u64;
                            }
                        }
                        let _ = stream.finish();
                    }
                    Err(_) => break,
                }
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            
            metrics.bytes_sent.fetch_add(total_sent, Ordering::Relaxed);
        }
        Err(_) => {
            metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Connection churn scenario - rapid connect/disconnect cycles
async fn connection_churn_scenario(
    endpoint: Arc<Endpoint>,
    server_addr: SocketAddr,
    config: Arc<StressConfig>,
    metrics: Arc<StressMetrics>,
) {
    let start = Instant::now();
    let mut cycles = 0;
    
    while start.elapsed() < config.duration {
        match endpoint.connect(server_addr, "localhost").unwrap().await {
            Ok(connection) => {
                metrics.connections_succeeded.fetch_add(1, Ordering::Relaxed);
                
                // Quick data exchange
                if let Ok(mut stream) = connection.open_uni().await {
                    let data = format!("churn test {}", cycles).into_bytes();
                    if stream.write_all(&data).await.is_ok() {
                        metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
                
                // Quick disconnect
                connection.close(0u32.into(), b"churn");
                cycles += 1;
            }
            Err(_) => {
                metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Brief pause between cycles
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Monitor memory usage during test
async fn monitor_memory_usage(
    metrics: Arc<StressMetrics>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                let mb = kb / 1024;
                                let current = metrics.peak_memory_mb.load(Ordering::Relaxed);
                                if mb > current {
                                    metrics.peak_memory_mb.store(mb, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Create a test server endpoint
async fn create_server_endpoint(bind_addr: SocketAddr) -> (Arc<Endpoint>, SocketAddr) {
    let (cert, key) = generate_self_signed_cert();
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key.into()).unwrap();
    
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(VarInt::from_u32(1000));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1000));
    server_config.transport_config(Arc::new(transport));
    
    let endpoint = Endpoint::server(
        EndpointConfig::default(),
        bind_addr,
    ).unwrap();
    
    let addr = endpoint.local_addr().unwrap();
    (Arc::new(endpoint), addr)
}

/// Create a test client endpoint
async fn create_client_endpoint() -> Arc<Endpoint> {
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    
    let mut client_config = ClientConfig::new(Arc::new(rustls::RootCertStore::empty()));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(VarInt::from_u32(1000));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1000));
    client_config.transport_config(Arc::new(transport));
    
    endpoint.set_default_client_config(client_config);
    Arc::new(endpoint)
}

/// Generate self-signed certificate for testing
fn generate_self_signed_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (cert_der, key_der)
}