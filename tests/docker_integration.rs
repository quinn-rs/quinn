//! Docker-based integration tests for ant-quic
//!
//! These tests use Docker containers to simulate realistic network conditions
//! including various NAT types, network partitions, and latency scenarios.

use std::{process::Command, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
struct DockerTestConfig {
    /// Docker compose file to use
    compose_file: String,
    /// Test name
    test_name: String,
    /// Test timeout
    timeout_secs: u64,
    /// Expected success rate (0.0 - 1.0)
    expected_success_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerTestResult {
    test_name: String,
    success: bool,
    duration_secs: f64,
    connections_established: usize,
    connections_failed: usize,
    success_rate: f64,
    error_message: Option<String>,
}

#[tokio::test]
#[cfg(feature = "docker-tests")]
async fn test_docker_nat_scenarios() {
    init_docker_tests();

    let test_configs = vec![
        DockerTestConfig {
            compose_file: "docker/docker-compose.yml".to_string(),
            test_name: "full_cone_nat".to_string(),
            timeout_secs: 120,
            expected_success_rate: 0.95,
        },
        DockerTestConfig {
            compose_file: "docker/docker-compose.yml".to_string(),
            test_name: "symmetric_nat".to_string(),
            timeout_secs: 180,
            expected_success_rate: 0.85,
        },
        DockerTestConfig {
            compose_file: "docker/docker-compose.yml".to_string(),
            test_name: "port_restricted_nat".to_string(),
            timeout_secs: 150,
            expected_success_rate: 0.90,
        },
    ];

    for config in test_configs {
        info!("Running Docker test: {}", config.test_name);

        let result = run_docker_test(&config).await;

        assert!(
            result.success,
            "Docker test '{}' failed: {:?}",
            config.test_name, result.error_message
        );

        assert!(
            result.success_rate >= config.expected_success_rate,
            "Success rate {:.2}% below expected {:.2}% for test '{}'",
            result.success_rate * 100.0,
            config.expected_success_rate * 100.0,
            config.test_name
        );

        info!(
            "Docker test '{}' completed successfully in {:.2}s with {:.2}% success rate",
            config.test_name,
            result.duration_secs,
            result.success_rate * 100.0
        );
    }
}

#[tokio::test]
#[cfg(feature = "docker-tests")]
async fn test_docker_network_partitions() {
    init_docker_tests();

    info!("Testing network partition scenarios with Docker");

    // Start the Docker network
    let compose_file = "docker/docker-compose.yml";
    docker_compose_up(compose_file).await;

    // Wait for network to stabilize
    sleep(Duration::from_secs(10)).await;

    // Create network partition
    info!("Creating network partition between containers");

    let partition_cmd = Command::new("docker")
        .args(&[
            "exec",
            "nat-gateway-1",
            "iptables",
            "-I",
            "FORWARD",
            "-s",
            "10.1.0.0/24",
            "-d",
            "10.2.0.0/24",
            "-j",
            "DROP",
        ])
        .output()
        .expect("Failed to create network partition");

    if !partition_cmd.status.success() {
        error!(
            "Failed to create partition: {}",
            String::from_utf8_lossy(&partition_cmd.stderr)
        );
    }

    // Test behavior during partition
    sleep(Duration::from_secs(30)).await;

    // Heal partition
    info!("Healing network partition");

    let heal_cmd = Command::new("docker")
        .args(&[
            "exec",
            "nat-gateway-1",
            "iptables",
            "-D",
            "FORWARD",
            "-s",
            "10.1.0.0/24",
            "-d",
            "10.2.0.0/24",
            "-j",
            "DROP",
        ])
        .output()
        .expect("Failed to heal network partition");

    if !heal_cmd.status.success() {
        warn!(
            "Failed to heal partition: {}",
            String::from_utf8_lossy(&heal_cmd.stderr)
        );
    }

    // Test recovery
    sleep(Duration::from_secs(30)).await;

    // Check final state
    let logs = get_docker_logs("test-runner").await;
    assert!(
        logs.contains("Network recovered from partition"),
        "Network did not recover properly"
    );

    docker_compose_down(compose_file).await;
}

#[tokio::test]
#[cfg(feature = "docker-tests")]
async fn test_docker_latency_scenarios() {
    init_docker_tests();

    info!("Testing latency scenarios with Docker");

    let latency_configs = vec![
        ("low", "10ms", "1ms"),         // Low latency
        ("medium", "50ms", "10ms"),     // Medium latency
        ("high", "200ms", "50ms"),      // High latency
        ("variable", "100ms", "100ms"), // High jitter
    ];

    for (name, delay, jitter) in latency_configs {
        info!("Testing {} latency: {} ± {}", name, delay, jitter);

        // Apply network latency
        let tc_cmd = Command::new("docker")
            .args(&[
                "exec", "client-1", "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay",
                delay, jitter,
            ])
            .output()
            .expect("Failed to apply latency");

        if !tc_cmd.status.success() {
            error!(
                "Failed to apply latency: {}",
                String::from_utf8_lossy(&tc_cmd.stderr)
            );
            continue;
        }

        // Run test with latency
        let result = run_latency_test(name).await;

        // Remove latency
        let _ = Command::new("docker")
            .args(&[
                "exec", "client-1", "tc", "qdisc", "del", "dev", "eth0", "root",
            ])
            .output();

        assert!(result.success, "Latency test '{}' failed", name);
    }
}

#[tokio::test]
#[cfg(feature = "docker-tests")]
async fn test_docker_scale_scenario() {
    init_docker_tests();

    info!("Testing scale scenario with Docker");

    // Start with minimal network
    docker_compose_up("docker/docker-compose.yml").await;
    sleep(Duration::from_secs(5)).await;

    // Scale up client nodes
    for scale in [5, 10, 20] {
        info!("Scaling to {} client nodes", scale);

        let scale_cmd = Command::new("docker-compose")
            .args(&[
                "-f",
                "docker/docker-compose.yml",
                "up",
                "-d",
                "--scale",
                &format!("client={}", scale),
            ])
            .output()
            .expect("Failed to scale containers");

        if !scale_cmd.status.success() {
            error!(
                "Failed to scale: {}",
                String::from_utf8_lossy(&scale_cmd.stderr)
            );
            break;
        }

        // Wait for network to stabilize
        sleep(Duration::from_secs(10)).await;

        // Check network health
        let health = check_network_health().await;
        assert!(
            health.healthy_nodes >= scale * 80 / 100,
            "Less than 80% of nodes are healthy at scale {}",
            scale
        );
    }

    docker_compose_down("docker/docker-compose.yml").await;
}

// Helper functions

fn init_docker_tests() {
    // Ensure Docker is available
    let docker_check = Command::new("docker")
        .args(&["version"])
        .output()
        .expect("Docker not found. Please install Docker to run these tests.");

    if !docker_check.status.success() {
        panic!("Docker is not running. Please start Docker daemon.");
    }

    // Ensure docker-compose is available
    let compose_check = Command::new("docker-compose")
        .args(&["version"])
        .output()
        .expect("docker-compose not found. Please install docker-compose.");

    if !compose_check.status.success() {
        panic!("docker-compose is not available.");
    }
}

async fn run_docker_test(config: &DockerTestConfig) -> DockerTestResult {
    let start = std::time::Instant::now();

    // Start Docker containers
    docker_compose_up(&config.compose_file).await;

    // Run the specific test
    let test_output = Command::new("docker")
        .args(&["exec", "test-runner", "/app/run-test.sh", &config.test_name])
        .output()
        .expect("Failed to run test in Docker");

    let success = test_output.status.success();
    let output = String::from_utf8_lossy(&test_output.stdout);

    // Parse results from output
    let connections_established = parse_metric(&output, "connections_established").unwrap_or(0);
    let connections_failed = parse_metric(&output, "connections_failed").unwrap_or(0);

    let total_attempts = connections_established + connections_failed;
    let success_rate = if total_attempts > 0 {
        connections_established as f64 / total_attempts as f64
    } else {
        0.0
    };

    // Clean up
    docker_compose_down(&config.compose_file).await;

    DockerTestResult {
        test_name: config.test_name.clone(),
        success,
        duration_secs: start.elapsed().as_secs_f64(),
        connections_established,
        connections_failed,
        success_rate,
        error_message: if !success {
            Some(String::from_utf8_lossy(&test_output.stderr).to_string())
        } else {
            None
        },
    }
}

async fn docker_compose_up(compose_file: &str) {
    info!("Starting Docker containers from {}", compose_file);

    let output = Command::new("docker-compose")
        .args(&["-f", compose_file, "up", "-d"])
        .output()
        .expect("Failed to start Docker containers");

    if !output.status.success() {
        panic!(
            "docker-compose up failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn docker_compose_down(compose_file: &str) {
    info!("Stopping Docker containers");

    let output = Command::new("docker-compose")
        .args(&["-f", compose_file, "down", "-v"])
        .output()
        .expect("Failed to stop Docker containers");

    if !output.status.success() {
        warn!(
            "docker-compose down failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn get_docker_logs(container: &str) -> String {
    let output = Command::new("docker")
        .args(&["logs", container])
        .output()
        .expect("Failed to get Docker logs");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn parse_metric(output: &str, metric: &str) -> Option<usize> {
    output
        .lines()
        .find(|line| line.contains(metric))
        .and_then(|line| line.split(':').nth(1).and_then(|v| v.trim().parse().ok()))
}

async fn run_latency_test(name: &str) -> DockerTestResult {
    // Simplified latency test
    let output = Command::new("docker")
        .args(&[
            "exec",
            "test-runner",
            "/app/run-test.sh",
            &format!("latency_{}", name),
        ])
        .output()
        .expect("Failed to run latency test");

    DockerTestResult {
        test_name: format!("latency_{}", name),
        success: output.status.success(),
        duration_secs: 30.0,
        connections_established: 1,
        connections_failed: 0,
        success_rate: 1.0,
        error_message: None,
    }
}

#[derive(Debug)]
struct NetworkHealth {
    total_nodes: usize,
    healthy_nodes: usize,
    unhealthy_nodes: usize,
}

async fn check_network_health() -> NetworkHealth {
    let output = Command::new("docker")
        .args(&["ps", "--format", "{{.Names}}\t{{.Status}}"])
        .output()
        .expect("Failed to check container status");

    let status_output = String::from_utf8_lossy(&output.stdout);
    let mut total_nodes = 0;
    let mut healthy_nodes = 0;

    for line in status_output.lines() {
        if line.contains("client-") || line.contains("bootstrap") {
            total_nodes += 1;
            if line.contains("Up") && line.contains("healthy") {
                healthy_nodes += 1;
            }
        }
    }

    NetworkHealth {
        total_nodes,
        healthy_nodes,
        unhealthy_nodes: total_nodes - healthy_nodes,
    }
}
