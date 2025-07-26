use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
/// NAT Test Harness
///
/// Comprehensive test harness for NAT traversal scenarios
/// Integrates with Docker environment and real ant-quic binaries
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// NAT test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTestConfig {
    pub bootstrap_addr: String,
    pub test_duration: Duration,
    pub connection_timeout: Duration,
    pub enable_metrics: bool,
    pub log_level: String,
}

impl Default for NatTestConfig {
    fn default() -> Self {
        Self {
            bootstrap_addr: "bootstrap:9000".to_string(),
            test_duration: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(30),
            enable_metrics: true,
            log_level: "debug".to_string(),
        }
    }
}

/// Result of a NAT traversal attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalResult {
    pub success: bool,
    pub connection_time_ms: Option<u64>,
    pub nat_type_client1: String,
    pub nat_type_client2: String,
    pub hole_punching_used: bool,
    pub relay_used: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub error_message: Option<String>,
}

/// Test harness for NAT scenarios
pub struct NatTestHarness {
    config: NatTestConfig,
    results: Vec<NatTraversalResult>,
}

impl NatTestHarness {
    pub fn new(config: NatTestConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }

    /// Run a NAT traversal test between two containers
    pub async fn run_nat_test(
        &mut self,
        client1_container: &str,
        client2_container: &str,
        nat_type1: &str,
        nat_type2: &str,
    ) -> Result<NatTraversalResult> {
        println!(
            "Testing NAT traversal: {} ({}) <-> {} ({})",
            client1_container, nat_type1, client2_container, nat_type2
        );

        let start_time = Instant::now();

        // Start listener on client2
        let listener_handle = self.start_listener(client2_container).await?;

        // Get peer ID from listener
        let peer_id = self.get_peer_id_from_logs(&listener_handle).await?;

        // Connect from client1
        let connection_result = self.connect_to_peer(client1_container, &peer_id).await;

        let elapsed = start_time.elapsed();

        // Analyze results
        let result = match connection_result {
            Ok(metrics) => NatTraversalResult {
                success: true,
                connection_time_ms: Some(elapsed.as_millis() as u64),
                nat_type_client1: nat_type1.to_string(),
                nat_type_client2: nat_type2.to_string(),
                hole_punching_used: metrics.hole_punching_used,
                relay_used: metrics.relay_used,
                packets_sent: metrics.packets_sent,
                packets_received: metrics.packets_received,
                error_message: None,
            },
            Err(e) => NatTraversalResult {
                success: false,
                connection_time_ms: None,
                nat_type_client1: nat_type1.to_string(),
                nat_type_client2: nat_type2.to_string(),
                hole_punching_used: false,
                relay_used: false,
                packets_sent: 0,
                packets_received: 0,
                error_message: Some(e.to_string()),
            },
        };

        self.results.push(result.clone());
        Ok(result)
    }

    /// Start ant-quic listener in a container
    async fn start_listener(&self, container: &str) -> Result<ListenerHandle> {
        let cmd = format!(
            "docker exec -e RUST_LOG={} {} ant-quic --listen 0.0.0.0:9000 --dashboard",
            self.config.log_level, container
        );

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start listener")?;

        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let (tx, rx) = mpsc::channel(100);

        // Spawn log reader
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let _ = tx.send(line).await;
                }
            }
        });

        // Wait for listener to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(ListenerHandle {
            process: child,
            log_rx: rx,
        })
    }

    /// Extract peer ID from listener logs
    async fn get_peer_id_from_logs(&self, handle: &ListenerHandle) -> Result<String> {
        // In real implementation, parse logs to find peer ID
        // For now, return a placeholder
        Ok("test_peer_id".to_string())
    }

    /// Connect to a peer from a container
    async fn connect_to_peer(&self, container: &str, peer_id: &str) -> Result<ConnectionMetrics> {
        let cmd = format!(
            "docker exec -e RUST_LOG={} {} ant-quic --connect {} --bootstrap {}",
            self.config.log_level, container, peer_id, self.config.bootstrap_addr
        );

        let output = timeout(
            self.config.connection_timeout,
            tokio::task::spawn_blocking(move || Command::new("sh").arg("-c").arg(&cmd).output()),
        )
        .await??
        .context("Failed to execute connection command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(anyhow::anyhow!("Connection failed: {}", stderr));
        }

        // Parse metrics from output
        Ok(self.parse_connection_metrics(&stdout))
    }

    /// Parse connection metrics from ant-quic output
    fn parse_connection_metrics(&self, output: &str) -> ConnectionMetrics {
        // Parse real metrics from output
        // For now, return dummy metrics
        ConnectionMetrics {
            hole_punching_used: output.contains("Hole punching successful"),
            relay_used: output.contains("Using relay"),
            packets_sent: 100,
            packets_received: 95,
        }
    }

    /// Generate comprehensive test report
    pub fn generate_report(&self) -> TestReport {
        let total = self.results.len();
        let successful = self.results.iter().filter(|r| r.success).count();
        let hole_punching_used = self.results.iter().filter(|r| r.hole_punching_used).count();
        let relay_used = self.results.iter().filter(|r| r.relay_used).count();

        let avg_connection_time = self
            .results
            .iter()
            .filter_map(|r| r.connection_time_ms)
            .sum::<u64>() as f64
            / successful as f64;

        TestReport {
            total_tests: total,
            successful_connections: successful,
            success_rate: (successful as f64 / total as f64) * 100.0,
            hole_punching_connections: hole_punching_used,
            relay_connections: relay_used,
            average_connection_time_ms: avg_connection_time,
            nat_type_matrix: self.build_nat_matrix(),
            detailed_results: self.results.clone(),
        }
    }

    /// Build NAT type success matrix
    fn build_nat_matrix(&self) -> NatTypeMatrix {
        let mut matrix = NatTypeMatrix::new();

        for result in &self.results {
            matrix.record_result(
                &result.nat_type_client1,
                &result.nat_type_client2,
                result.success,
            );
        }

        matrix
    }
}

/// Handle for a running listener process
struct ListenerHandle {
    process: std::process::Child,
    log_rx: mpsc::Receiver<String>,
}

/// Connection metrics
#[derive(Debug)]
struct ConnectionMetrics {
    hole_punching_used: bool,
    relay_used: bool,
    packets_sent: u64,
    packets_received: u64,
}

/// Comprehensive test report
#[derive(Debug, Serialize)]
pub struct TestReport {
    pub total_tests: usize,
    pub successful_connections: usize,
    pub success_rate: f64,
    pub hole_punching_connections: usize,
    pub relay_connections: usize,
    pub average_connection_time_ms: f64,
    pub nat_type_matrix: NatTypeMatrix,
    pub detailed_results: Vec<NatTraversalResult>,
}

/// NAT type success matrix
#[derive(Debug, Default, Serialize)]
pub struct NatTypeMatrix {
    pub entries: Vec<MatrixEntry>,
}

#[derive(Debug, Serialize)]
pub struct MatrixEntry {
    pub nat_type1: String,
    pub nat_type2: String,
    pub attempts: u32,
    pub successes: u32,
    pub success_rate: f64,
}

impl NatTypeMatrix {
    fn new() -> Self {
        Self::default()
    }

    fn record_result(&mut self, nat1: &str, nat2: &str, success: bool) {
        let key = if nat1 < nat2 {
            (nat1.to_string(), nat2.to_string())
        } else {
            (nat2.to_string(), nat1.to_string())
        };

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.nat_type1 == key.0 && e.nat_type2 == key.1)
        {
            entry.attempts += 1;
            if success {
                entry.successes += 1;
            }
            entry.success_rate = (entry.successes as f64 / entry.attempts as f64) * 100.0;
        } else {
            self.entries.push(MatrixEntry {
                nat_type1: key.0,
                nat_type2: key.1,
                attempts: 1,
                successes: if success { 1 } else { 0 },
                success_rate: if success { 100.0 } else { 0.0 },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_harness_creation() {
        let config = NatTestConfig::default();
        let harness = NatTestHarness::new(config);

        assert!(harness.results.is_empty());
    }

    #[test]
    fn test_nat_matrix() {
        let mut matrix = NatTypeMatrix::new();

        matrix.record_result("full_cone", "symmetric", true);
        matrix.record_result("full_cone", "symmetric", false);
        matrix.record_result("full_cone", "symmetric", true);

        assert_eq!(matrix.entries.len(), 1);
        assert_eq!(matrix.entries[0].attempts, 3);
        assert_eq!(matrix.entries[0].successes, 2);
        assert_eq!(matrix.entries[0].success_rate, 66.66666666666667);
    }
}
