#\![edition = "2024"]
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// NAT Docker Integration Tests
///
/// Integration tests that use the Docker NAT testing environment
/// to validate NAT traversal under realistic network conditions
use std::process::Command;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Docker-based NAT test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerNatTest {
    pub name: String,
    pub description: String,
    pub client1_nat: String,
    pub client2_nat: String,
    pub network_profile: String,
    pub expected_result: ExpectedResult,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExpectedResult {
    Success,
    FailWithRelay,
    FailCompletely,
}

/// Test execution result
#[derive(Debug)]
pub struct TestExecutionResult {
    pub test_name: String,
    pub success: bool,
    pub connection_time_ms: Option<u64>,
    pub relay_used: bool,
    pub error_message: Option<String>,
    pub logs: Vec<String>,
}

/// Docker NAT test orchestrator
pub struct DockerNatTestRunner {
    docker_compose_path: String,
    test_results: Vec<TestExecutionResult>,
    #[allow(dead_code)]
    container_logs: HashMap<String, Vec<String>>,
}

impl Default for DockerNatTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerNatTestRunner {
    pub fn new() -> Self {
        Self {
            docker_compose_path: "docker/docker-compose.yml".to_string(),
            test_results: Vec::new(),
            container_logs: HashMap::new(),
        }
    }

    /// Run all Docker-based NAT tests
    pub async fn run_all_tests(&mut self) -> Result<()> {
        println!("Starting Docker NAT integration tests...");

        // Start Docker environment
        self.start_docker_environment().await?;

        // Wait for containers to be ready
        sleep(Duration::from_secs(5)).await;

        // Run test scenarios
        let test_scenarios = self.create_test_scenarios();

        for scenario in test_scenarios {
            println!("\n=== Running: {} ===", scenario.name);
            println!("Description: {}", scenario.description);

            let result = self.run_test_scenario(&scenario).await;
            self.test_results.push(result);
        }

        // Generate report
        self.generate_test_report();

        // Cleanup
        self.cleanup_docker_environment().await?;

        Ok(())
    }

    /// Create comprehensive test scenarios
    fn create_test_scenarios(&self) -> Vec<DockerNatTest> {
        vec![
            // Basic NAT type combinations
            DockerNatTest {
                name: "full_cone_connectivity".to_string(),
                description: "Test connectivity between two full cone NATs".to_string(),
                client1_nat: "nat1".to_string(), // Full Cone
                client2_nat: "nat1".to_string(),
                network_profile: "normal".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 30,
            },
            DockerNatTest {
                name: "symmetric_challenge".to_string(),
                description: "Test hardest case: symmetric to symmetric NAT".to_string(),
                client1_nat: "nat2".to_string(), // Symmetric
                client2_nat: "nat2".to_string(),
                network_profile: "normal".to_string(),
                expected_result: ExpectedResult::FailWithRelay,
                timeout_seconds: 60,
            },
            DockerNatTest {
                name: "port_restricted_mixed".to_string(),
                description: "Test port restricted NAT with full cone".to_string(),
                client1_nat: "nat3".to_string(), // Port Restricted
                client2_nat: "nat1".to_string(), // Full Cone
                network_profile: "normal".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 45,
            },
            DockerNatTest {
                name: "cgnat_challenge".to_string(),
                description: "Test CGNAT (carrier grade) connectivity".to_string(),
                client1_nat: "nat4".to_string(), // CGNAT
                client2_nat: "nat1".to_string(), // Full Cone
                network_profile: "normal".to_string(),
                expected_result: ExpectedResult::FailWithRelay,
                timeout_seconds: 60,
            },
            // Network condition tests
            DockerNatTest {
                name: "high_latency_nat".to_string(),
                description: "Test NAT traversal with high latency (satellite)".to_string(),
                client1_nat: "nat1".to_string(),
                client2_nat: "nat3".to_string(),
                network_profile: "satellite".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 120,
            },
            DockerNatTest {
                name: "lossy_network_nat".to_string(),
                description: "Test NAT traversal with 5% packet loss".to_string(),
                client1_nat: "nat2".to_string(),
                client2_nat: "nat1".to_string(),
                network_profile: "lossy_wifi".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 90,
            },
            DockerNatTest {
                name: "congested_network_nat".to_string(),
                description: "Test NAT traversal on congested network".to_string(),
                client1_nat: "nat3".to_string(),
                client2_nat: "nat3".to_string(),
                network_profile: "congested".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 120,
            },
            // Mobile network scenarios
            DockerNatTest {
                name: "mobile_3g_nat".to_string(),
                description: "Test NAT traversal on 3G mobile network".to_string(),
                client1_nat: "nat2".to_string(),
                client2_nat: "nat1".to_string(),
                network_profile: "3g".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 90,
            },
            DockerNatTest {
                name: "mobile_4g_nat".to_string(),
                description: "Test NAT traversal on 4G LTE network".to_string(),
                client1_nat: "nat3".to_string(),
                client2_nat: "nat1".to_string(),
                network_profile: "4g".to_string(),
                expected_result: ExpectedResult::Success,
                timeout_seconds: 60,
            },
        ]
    }

    /// Run a single test scenario
    async fn run_test_scenario(&mut self, scenario: &DockerNatTest) -> TestExecutionResult {
        let start_time = std::time::Instant::now();

        // Apply network profile
        if let Err(e) = self.apply_network_profile(&scenario.network_profile).await {
            return TestExecutionResult {
                test_name: scenario.name.clone(),
                success: false,
                connection_time_ms: None,
                relay_used: false,
                error_message: Some(format!("Failed to apply network profile: {e}")),
                logs: vec![],
            };
        }

        // Get container names
        let client1_container = format!(
            "ant-quic-client{}",
            scenario.client1_nat.chars().last().unwrap_or('1')
        );
        let client2_container = format!(
            "ant-quic-client{}",
            scenario.client2_nat.chars().last().unwrap_or('2')
        );

        // Execute test in containers
        match timeout(
            Duration::from_secs(scenario.timeout_seconds),
            self.execute_nat_test(&client1_container, &client2_container),
        )
        .await
        {
            Ok(Ok((success, relay_used))) => {
                let elapsed = start_time.elapsed();
                let logs = self
                    .collect_container_logs(&[&client1_container, &client2_container])
                    .await;

                TestExecutionResult {
                    test_name: scenario.name.clone(),
                    success,
                    connection_time_ms: Some(elapsed.as_millis() as u64),
                    relay_used,
                    error_message: None,
                    logs,
                }
            }
            Ok(Err(e)) => {
                let logs = self
                    .collect_container_logs(&[&client1_container, &client2_container])
                    .await;

                TestExecutionResult {
                    test_name: scenario.name.clone(),
                    success: false,
                    connection_time_ms: None,
                    relay_used: false,
                    error_message: Some(e.to_string()),
                    logs,
                }
            }
            Err(_) => {
                let logs = self
                    .collect_container_logs(&[&client1_container, &client2_container])
                    .await;

                TestExecutionResult {
                    test_name: scenario.name.clone(),
                    success: false,
                    connection_time_ms: None,
                    relay_used: false,
                    error_message: Some("Test timeout".to_string()),
                    logs,
                }
            }
        }
    }

    /// Execute NAT traversal test between two containers
    async fn execute_nat_test(&self, client1: &str, client2: &str) -> Result<(bool, bool)> {
        // Start ant-quic in listening mode on client2
        let listen_cmd = format!("docker exec -d {client2} ant-quic --listen 0.0.0.0:9000");

        Command::new("sh")
            .arg("-c")
            .arg(&listen_cmd)
            .output()
            .context("Failed to start listener")?;

        // Give listener time to start
        sleep(Duration::from_secs(2)).await;

        // Get client2's peer ID (would be from actual implementation)
        let peer_id = "test_peer_id"; // Placeholder

        // Connect from client1 to client2
        let connect_cmd = format!(
            "docker exec {client1} ant-quic --connect {peer_id} --bootstrap bootstrap:9000"
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(&connect_cmd)
            .output()
            .context("Failed to execute connection test")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check if connection succeeded
        let success = output.status.success()
            && (stdout.contains("Connection established")
                || stdout.contains("Connected successfully"));

        // Check if relay was used
        let relay_used =
            stdout.contains("Using relay") || stdout.contains("Relay connection established");

        if !success {
            println!("Connection failed. Stdout: {stdout}");
            println!("Stderr: {stderr}");
        }

        Ok((success, relay_used))
    }

    /// Apply network profile to containers
    async fn apply_network_profile(&self, profile: &str) -> Result<()> {
        let script_path = "docker/scripts/network-conditions.sh";

        let cmd = format!("bash {script_path} apply {profile}");

        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .context("Failed to apply network profile")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to apply network profile: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Collect logs from containers
    async fn collect_container_logs(&self, containers: &[&str]) -> Vec<String> {
        let mut logs = Vec::new();

        for container in containers {
            let cmd = format!("docker logs {container} --tail 100");

            if let Ok(output) = Command::new("sh").arg("-c").arg(&cmd).output() {
                let container_logs = String::from_utf8_lossy(&output.stdout);
                logs.push(format!("=== {container} logs ===\n{container_logs}"));
            }
        }

        logs
    }

    /// Start Docker test environment
    async fn start_docker_environment(&self) -> Result<()> {
        println!("Starting Docker NAT test environment...");

        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.docker_compose_path)
            .arg("up")
            .arg("-d")
            .output()
            .context("Failed to start Docker environment")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to start Docker environment: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Cleanup Docker environment
    async fn cleanup_docker_environment(&self) -> Result<()> {
        println!("Cleaning up Docker environment...");

        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.docker_compose_path)
            .arg("down")
            .output()
            .context("Failed to stop Docker environment")?;

        if !output.status.success() {
            eprintln!(
                "Warning: Failed to cleanup Docker environment: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Generate test report
    fn generate_test_report(&self) {
        println!("\n\n=== NAT Docker Integration Test Report ===\n");

        let total = self.test_results.len();
        let passed = self.test_results.iter().filter(|r| r.success).count();
        let failed = total - passed;

        println!("Total Tests: {total}");
        println!(
            "Passed: {} ({:.1}%)",
            passed,
            (passed as f64 / total as f64) * 100.0
        );
        println!("Failed: {failed}");
        println!();

        println!("Detailed Results:");
        println!("{:-<80}", "");
        println!(
            "{:<30} {:<15} {:<15} {:<20}",
            "Test Name", "Result", "Time (ms)", "Relay Used"
        );
        println!("{:-<80}", "");

        for result in &self.test_results {
            let status = if result.success {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let time = result
                .connection_time_ms
                .map(|t| t.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let relay = if result.relay_used { "Yes" } else { "No" };

            println!(
                "{:<30} {:<15} {:<15} {:<20}",
                result.test_name, status, time, relay
            );

            if let Some(ref error) = result.error_message {
                println!("  Error: {error}");
            }
        }

        println!("{:-<80}", "");

        // Summary by NAT type
        println!("\nNAT Type Success Rates:");
        let mut nat_stats: HashMap<String, (usize, usize)> = HashMap::new();

        for result in &self.test_results {
            let nat_types = result.test_name.split('_').collect::<Vec<_>>();
            if nat_types.len() >= 2 {
                let entry = nat_stats.entry(nat_types[0].to_string()).or_insert((0, 0));
                entry.1 += 1;
                if result.success {
                    entry.0 += 1;
                }
            }
        }

        for (nat_type, (passed, total)) in nat_stats {
            let rate = (passed as f64 / total as f64) * 100.0;
            println!("  {nat_type}: {passed}/{total} ({rate:.1}%)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Docker environment
    async fn test_docker_nat_integration() {
        let mut runner = DockerNatTestRunner::new();
        runner
            .run_all_tests()
            .await
            .expect("Docker NAT tests failed");
    }

    #[test]
    fn test_scenario_creation() {
        let runner = DockerNatTestRunner::new();
        let scenarios = runner.create_test_scenarios();

        assert!(!scenarios.is_empty());
        assert!(scenarios.iter().any(|s| s.name.contains("symmetric")));
        assert!(scenarios.iter().any(|s| s.name.contains("cgnat")));
        assert!(scenarios.iter().any(|s| s.network_profile != "normal"));
    }
}
