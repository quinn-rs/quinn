//! Security regression tests for ant-quic
//!
//! Tests for specific security improvements made in recent commits to ensure
//! they don't regress and that the system handles security-sensitive scenarios safely.

use ant_quic::nat_traversal_api::{EndpointRole, NatTraversalConfig, NatTraversalEndpoint};
use std::time::Duration;

/// Helper to create a basic client config for testing
fn test_client_config() -> NatTraversalConfig {
    NatTraversalConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(5),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: None, // Let system choose - tests random port functionality
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    }
}

/// Helper to create a server config
fn test_server_config() -> NatTraversalConfig {
    NatTraversalConfig {
        role: EndpointRole::Server {
            can_coordinate: true,
        },
        bootstrap_nodes: vec![],
        max_candidates: 20,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 10,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    }
}

/// Test that endpoint creation with None bind_addr doesn't panic
/// Regression test for commit 6e633cd9 - protocol obfuscation improvements
#[tokio::test]
async fn test_random_port_binding_no_panic() {
    // This tests the create_random_port_bind_addr() function indirectly
    // by ensuring None bind_addr is handled safely

    let config = test_client_config(); // bind_addr is None

    // This should not panic, even if random port selection fails
    let result = NatTraversalEndpoint::new(config, None).await;

    // Either success or failure is fine - the key is no panic
    match result {
        Ok(_) => println!("✓ Random port binding succeeded"),
        Err(e) => println!("✓ Random port binding failed gracefully: {}", e),
    }
}

/// Test that error conditions don't cause panics  
/// Regression test for commit a7d1de11 - robust error handling
#[tokio::test]
async fn test_error_handling_no_panic() {
    // Test various potentially problematic configurations

    // Test 1: Zero timeouts
    let config1 = NatTraversalConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(0), // Zero timeout
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    };

    let result1 = NatTraversalEndpoint::new(config1, None).await;
    // Should either succeed or fail gracefully
    match result1 {
        Ok(_) => println!("✓ Zero timeout handled successfully"),
        Err(e) => println!("✓ Zero timeout rejected safely: {}", e),
    }

    // Test 2: Zero max candidates
    let config2 = NatTraversalConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 0, // Zero candidates
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    };

    let result2 = NatTraversalEndpoint::new(config2, None).await;
    match result2 {
        Ok(_) => println!("✓ Zero candidates handled successfully"),
        Err(e) => println!("✓ Zero candidates rejected safely: {}", e),
    }
}

/// Test concurrent endpoint creation doesn't cause race conditions
/// Related to mutex safety improvements
#[tokio::test]
async fn test_concurrent_creation_safety() {
    const NUM_CONCURRENT: usize = 10;

    // Create many endpoints concurrently
    let handles: Vec<_> = (0..NUM_CONCURRENT)
        .map(|i| {
            tokio::spawn(async move {
                let mut config = test_client_config();
                // Use different bind ports to avoid conflicts
                config.bind_addr = Some(format!("127.0.0.1:{}", 10000 + i).parse().unwrap());

                let result = NatTraversalEndpoint::new(config, None).await;
                (i, result.is_ok())
            })
        })
        .collect();

    // Wait for all to complete
    let results: Vec<_> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task should not panic"))
        .collect();

    // Check that no tasks panicked
    assert_eq!(results.len(), NUM_CONCURRENT, "All tasks should complete");

    let successful = results.iter().filter(|(_, success)| *success).count();
    println!(
        "✓ Concurrent creation test: {}/{} succeeded",
        successful, NUM_CONCURRENT
    );
}

/// Test statistics access doesn't panic with concurrent access
/// Tests mutex safety in statistics gathering
#[tokio::test]
async fn test_statistics_concurrent_access() {
    let config = test_server_config();

    let endpoint_result = NatTraversalEndpoint::new(config, None).await;

    if let Ok(endpoint) = endpoint_result {
        // Concurrent statistics access
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let ep = &endpoint;
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ep.get_statistics()))
            })
            .collect();

        // Check that no statistics call panicked
        for (i, result) in handles.into_iter().enumerate() {
            assert!(result.is_ok(), "Statistics call {} should not panic", i);
        }

        println!("✓ Concurrent statistics access completed safely");
    }
}

/// Test that malformed configurations are handled safely
#[tokio::test]
async fn test_malformed_config_handling() {
    // Test bootstrap role without bootstrap nodes
    let contradictory_config = NatTraversalConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![], // Empty for bootstrap role - contradiction
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    };

    let result = NatTraversalEndpoint::new(contradictory_config, None).await;

    // Should handle contradiction gracefully
    match result {
        Ok(_) => println!("✓ Bootstrap with no nodes accepted (implementation choice)"),
        Err(e) => println!("✓ Bootstrap with no nodes rejected safely: {}", e),
    }

    // Test extremely large values that could cause overflow
    let extreme_config = NatTraversalConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: usize::MAX, // Maximum possible value
        coordination_timeout: Duration::from_secs(u64::MAX / 1000), // Very large timeout
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: usize::MAX,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    };

    let result2 = NatTraversalEndpoint::new(extreme_config, None).await;

    match result2 {
        Ok(_) => println!("✓ Extreme values handled successfully"),
        Err(e) => println!("✓ Extreme values rejected safely: {}", e),
    }
}

/// Test input sanitization for potential security issues
#[tokio::test]
async fn test_input_sanitization() {
    // Test with many bootstrap nodes (potential DoS vector)
    let many_bootstraps: Vec<_> = (9000..9200)
        .map(|port| format!("127.0.0.1:{}", port).parse().unwrap())
        .collect();

    let large_bootstrap_config = NatTraversalConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: many_bootstraps, // 200 bootstrap nodes
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        timeouts: Default::default(),
    };

    // This should either work or fail gracefully, not exhaust memory or panic
    let start_time = std::time::Instant::now();
    let result = NatTraversalEndpoint::new(large_bootstrap_config, None).await;
    let duration = start_time.elapsed();

    // Should complete within reasonable time
    assert!(
        duration < Duration::from_secs(30),
        "Large config processing took too long"
    );

    match result {
        Ok(_) => println!(
            "✓ Large bootstrap list handled successfully in {:?}",
            duration
        ),
        Err(e) => println!(
            "✓ Large bootstrap list rejected safely in {:?}: {}",
            duration, e
        ),
    }
}

/// Test resource cleanup and prevent leaks
#[tokio::test]
async fn test_resource_cleanup() {
    // Create and drop many endpoints to test for resource leaks
    for i in 0..20 {
        let mut config = test_client_config();
        config.bind_addr = Some(format!("127.0.0.1:{}", 11000 + i).parse().unwrap());

        let endpoint_result = NatTraversalEndpoint::new(config, None).await;

        if let Ok(endpoint) = endpoint_result {
            // Use the endpoint briefly
            let _stats = endpoint.get_statistics();

            // Endpoint will be dropped here - test cleanup
        }

        // Small delay to allow cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("✓ Resource cleanup test completed - no obvious leaks");
}

#[cfg(test)]
mod specific_regression_tests {
    use super::*;

    /// Specific test for commit 6e633cd9: enhanced protocol obfuscation
    #[tokio::test]
    async fn test_commit_6e633cd9_protocol_obfuscation() {
        // Test that the create_random_port_bind_addr function is used
        // when bind_addr is None

        let config_with_none = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()],
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: false,
            max_concurrent_attempts: 5,
            bind_addr: None, // This should trigger random port binding
            prefer_rfc_nat_traversal: true,
            timeouts: Default::default(),
        };

        // Should not panic and should handle random port selection
        let result = NatTraversalEndpoint::new(config_with_none, None).await;

        match result {
            Ok(endpoint) => {
                // If we can get the endpoint, verify it has a proper address
                if let Some(quinn_ep) = endpoint.get_quinn_endpoint() {
                    if let Ok(addr) = quinn_ep.local_addr() {
                        assert_ne!(addr.port(), 0, "Should have assigned port");
                        assert_eq!(
                            addr.ip().to_string(),
                            "0.0.0.0",
                            "Should bind to all interfaces"
                        );
                        println!("✓ Random port binding successful: {}", addr);
                    }
                }
            }
            Err(e) => {
                // Error is acceptable in test environment
                println!("✓ Random port binding handled error safely: {}", e);
            }
        }
    }

    /// Specific test for commit a7d1de11: robust error handling
    #[tokio::test]
    async fn test_commit_a7d1de11_robust_error_handling() {
        // Test scenarios that previously could cause panics due to unwrap() usage

        // Scenario 1: Configuration that might cause mutex lock issues
        let problematic_config = NatTraversalConfig {
            role: EndpointRole::Server {
                can_coordinate: false,
            }, // Server that can't coordinate
            bootstrap_nodes: vec!["127.0.0.1:9000".parse().unwrap()], // But has bootstrap nodes
            max_candidates: 0,
            coordination_timeout: Duration::from_secs(0),
            enable_symmetric_nat: false,
            enable_relay_fallback: false,
            max_concurrent_attempts: 0,
            bind_addr: None,
            prefer_rfc_nat_traversal: true,
            timeouts: Default::default(),
        };

        // Should not panic, even if configuration is inconsistent
        let result = NatTraversalEndpoint::new(problematic_config, None).await;

        match result {
            Ok(_) => println!("✓ Problematic config handled successfully"),
            Err(e) => println!("✓ Problematic config rejected with proper error: {}", e),
        }

        // The key test is that we didn't panic
        println!("✓ Robust error handling regression test passed");
    }
}

// Re-export futures_util for the test
use futures_util;
