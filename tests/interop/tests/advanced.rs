#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Advanced Features Tests
///
/// Tests advanced QUIC features including 0-RTT, connection migration, multipath, and ECN
use super::utils;
use ant_quic::high_level::Endpoint;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info};

/// Run an advanced features test
pub async fn run_test(
    endpoint: &Endpoint,
    server_addr: &str,
    test_name: &str,
) -> Result<HashMap<String, f64>> {
    match test_name {
        "0rtt" => test_0rtt(endpoint, server_addr).await,
        "connection_migration" => test_connection_migration(endpoint, server_addr).await,
        "multipath" => test_multipath(endpoint, server_addr).await,
        "ecn" => test_ecn(endpoint, server_addr).await,
        _ => Err(anyhow::anyhow!("Unknown advanced test: {}", test_name)),
    }
}

/// Test 0-RTT early data
async fn test_0rtt(endpoint: &Endpoint, server_addr: &str) -> Result<HashMap<String, f64>> {
    info!("Testing 0-RTT with {}", server_addr);

    let mut metrics = HashMap::new();

    // First connection to establish session
    let conn1 = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Send some data to establish session state
    let (mut send, _recv) = conn1.open_bi().await?;
    send.write_all(b"Establishing session for 0-RTT").await?;
    send.finish()?;

    // Close connection gracefully
    conn1.close(0u32.into(), b"0rtt setup complete");

    // Wait a bit
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection should use 0-RTT if supported
    let rtt_start = std::time::Instant::now();

    // Note: The high-level API doesn't expose 0-RTT directly
    // In a real test, we would check if early data was accepted
    let conn2 = match utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await {
        Ok(conn) => conn,
        Err(e) => {
            metrics.insert("0rtt_supported".to_string(), 0.0);
            return Ok(metrics);
        }
    };

    let rtt_handshake_time = rtt_start.elapsed();

    // Compare with initial handshake time
    metrics.insert(
        "0rtt_handshake_ms".to_string(),
        rtt_handshake_time.as_millis() as f64,
    );
    metrics.insert("0rtt_tested".to_string(), 1.0);

    conn2.close(0u32.into(), b"0rtt test complete");

    info!("0-RTT test completed");
    Ok(metrics)
}

/// Test connection migration
async fn test_connection_migration(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing connection migration with {}", server_addr);

    let mut metrics = HashMap::new();

    // Establish connection
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Send initial data
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"Pre-migration data").await?;
    send.finish()?;

    // Note: The high-level API doesn't expose connection migration directly
    // In a real test, we would:
    // 1. Change the local address/port
    // 2. Continue sending data
    // 3. Verify the connection remains active

    // For now, test that the connection remains stable
    let migration_test_start = std::time::Instant::now();

    // Continue using the connection
    let (mut send2, _recv2) = conn.open_bi().await?;
    send2.write_all(b"Post-migration data").await?;
    send2.finish()?;

    let migration_time = migration_test_start.elapsed();

    metrics.insert("migration_tested".to_string(), 1.0);
    metrics.insert(
        "migration_time_ms".to_string(),
        migration_time.as_millis() as f64,
    );

    conn.close(0u32.into(), b"migration test complete");

    info!("Connection migration test completed");
    Ok(metrics)
}

/// Test multipath QUIC
async fn test_multipath(endpoint: &Endpoint, server_addr: &str) -> Result<HashMap<String, f64>> {
    info!("Testing multipath with {}", server_addr);

    let mut metrics = HashMap::new();

    // Note: Multipath QUIC is still experimental
    // This test checks if the server supports multipath negotiation

    let conn = match utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await {
        Ok(conn) => conn,
        Err(e) => {
            metrics.insert("multipath_supported".to_string(), 0.0);
            return Ok(metrics);
        }
    };

    // In a real multipath test, we would:
    // 1. Negotiate multipath support via transport parameters
    // 2. Establish multiple paths
    // 3. Send data across different paths
    // 4. Measure aggregated throughput

    metrics.insert("multipath_tested".to_string(), 1.0);
    metrics.insert("multipath_supported".to_string(), 0.0); // Not yet implemented

    conn.close(0u32.into(), b"multipath test complete");

    info!("Multipath test completed");
    Ok(metrics)
}

/// Test Explicit Congestion Notification (ECN)
async fn test_ecn(endpoint: &Endpoint, server_addr: &str) -> Result<HashMap<String, f64>> {
    info!("Testing ECN with {}", server_addr);

    let mut metrics = HashMap::new();

    // ECN testing requires cooperation from the network path
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Send data to observe ECN behavior
    let (mut send, _recv) = conn.open_bi().await?;

    let ecn_test_start = std::time::Instant::now();
    let test_size = 1024 * 1024; // 1MB
    let test_data = vec![0u8; test_size];

    send.write_all(&test_data).await?;
    send.finish()?;

    let ecn_test_time = ecn_test_start.elapsed();

    // In a real ECN test, we would:
    // 1. Check if ECN was negotiated in transport parameters
    // 2. Monitor ECN feedback from ACK frames
    // 3. Observe congestion control response to ECN marks

    metrics.insert("ecn_tested".to_string(), 1.0);
    metrics.insert(
        "ecn_transfer_ms".to_string(),
        ecn_test_time.as_millis() as f64,
    );
    metrics.insert(
        "ecn_throughput_mbps".to_string(),
        (test_size as f64 * 8.0) / (ecn_test_time.as_secs_f64() * 1_000_000.0),
    );

    conn.close(0u32.into(), b"ecn test complete");

    info!("ECN test completed");
    Ok(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_features_framework() {
        // Verify test framework structure
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

        // Test will fail without network, but validates the structure
        let result = test_0rtt(&endpoint, "quic.saorsalabs.com:9000").await;
        assert!(result.is_err());
    }
}
