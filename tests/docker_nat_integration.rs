//! Docker NAT Integration Tests
//!
//! These tests verify NAT traversal functionality using Docker containers
//! to simulate various NAT configurations.

#[cfg(all(test, feature = "docker-tests", not(target_os = "windows")))]
mod docker_nat_tests {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    fn docker_compose_available() -> bool {
        Command::new("docker")
            .args(&["compose", "version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn run_docker_test(test_name: &str) -> Result<String, String> {
        if !docker_compose_available() {
            return Err("Docker Compose not available".to_string());
        }

        // Change to docker directory
        let output = Command::new("sh")
            .args(&[
                "-c",
                &format!(
                    "cd docker && ./scripts/run-nat-tests.sh --test {}",
                    test_name
                ),
            ])
            .output()
            .map_err(|e| format!("Failed to run test: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    #[test]
    #[ignore = "requires Docker"]
    fn test_full_cone_nat_connectivity() {
        let result = run_docker_test("fullcone_connectivity");
        assert!(result.is_ok(), "Full Cone NAT test failed: {:?}", result);
    }

    #[test]
    #[ignore = "requires Docker"]
    fn test_symmetric_nat_traversal() {
        let result = run_docker_test("symmetric_traversal");
        assert!(result.is_ok(), "Symmetric NAT test failed: {:?}", result);
    }

    #[test]
    #[ignore = "requires Docker"]
    fn test_cgnat_connectivity() {
        let result = run_docker_test("cgnat_connectivity");
        assert!(result.is_ok(), "CGNAT test failed: {:?}", result);
    }

    #[test]
    #[ignore = "requires Docker"]
    fn test_nat_stress() {
        // Run a shorter stress test
        let output = Command::new("sh")
            .args(&[
                "-c",
                "cd docker && TEST_DURATION=60 ./scripts/run-nat-stress-tests.sh",
            ])
            .output()
            .expect("Failed to run stress test");

        assert!(
            output.status.success(),
            "Stress test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(test)]
mod docker_sanity_checks {
    use super::*;

    #[test]
    fn test_docker_available() {
        let output = std::process::Command::new("docker")
            .arg("--version")
            .output();

        match output {
            Ok(o) if o.status.success() => {
                println!("Docker version: {}", String::from_utf8_lossy(&o.stdout));
            }
            _ => {
                println!("Docker not available - skipping Docker-based tests");
            }
        }
    }
}
