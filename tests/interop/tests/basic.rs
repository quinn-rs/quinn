#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Basic Connectivity Tests
/// 
/// Tests fundamental QUIC connectivity including handshake, data transfer, and connection closure
use super::utils;
use ant_quic::high_level::Endpoint;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, debug};

/// Run a basic connectivity test
pub async fn run_test(
    endpoint: &Endpoint,
    server_addr: &str,
    test_name: &str,
) -> Result<HashMap<String, f64>> {
    match test_name {
        "handshake" => test_handshake(endpoint, server_addr).await,
        "data_transfer" => test_data_transfer(endpoint, server_addr).await,
        "connection_close" => test_connection_close(endpoint, server_addr).await,
        _ => Err(anyhow::anyhow!("Unknown basic test: {}", test_name)),
    }
}

/// Test basic handshake
async fn test_handshake(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing handshake with {}", server_addr);
    
    let mut metrics = HashMap::new();
    
    // Measure handshake time
    let handshake_duration = utils::measure_handshake_time(endpoint, server_addr).await?;
    
    metrics.insert("handshake_ms".to_string(), handshake_duration.as_millis() as f64);
    
    // Verify handshake succeeded by opening a stream
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;
    
    // Try to open a stream to verify connection is functional
    let (mut send, _recv) = conn.open_bi().await
        .map_err(|e| anyhow::anyhow!("Failed to open stream: {}", e))?;
    
    // Send minimal data
    send.write_all(b"QUIC handshake test").await?;
    send.finish()?;
    
    // Clean close
    conn.close(0u32.into(), b"handshake test complete");
    
    info!("Handshake test completed in {:?}", handshake_duration);
    
    Ok(metrics)
}

/// Test data transfer
async fn test_data_transfer(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing data transfer with {}", server_addr);
    
    let mut metrics = HashMap::new();
    
    // Establish connection
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;
    
    // Test small data transfer (1KB)
    let small_metrics = utils::test_data_transfer(&conn, 1024).await?;
    for (k, v) in small_metrics {
        metrics.insert(format!("small_{}", k), v);
    }
    
    // Test medium data transfer (1MB)
    let medium_metrics = utils::test_data_transfer(&conn, 1024 * 1024).await?;
    for (k, v) in medium_metrics {
        metrics.insert(format!("medium_{}", k), v);
    }
    
    // Test multiple streams
    let stream_start = std::time::Instant::now();
    let mut handles = vec![];
    
    for i in 0..5 {
        let conn_clone = conn.clone();
        let handle = tokio::spawn(async move {
            let (mut send, mut recv) = conn_clone.open_bi().await?;
            let data = format!("Stream {} test data", i).into_bytes();
            send.write_all(&data).await?;
            send.finish()?;
            
            let mut buf = vec![0u8; 1024];
            let _ = recv.read(&mut buf).await?;
            Ok::<_, anyhow::Error>(())
        });
        handles.push(handle);
    }
    
    // Wait for all streams
    for handle in handles {
        handle.await??;
    }
    
    let stream_duration = stream_start.elapsed();
    metrics.insert("multi_stream_ms".to_string(), stream_duration.as_millis() as f64);
    
    // Clean close
    conn.close(0u32.into(), b"data transfer test complete");
    
    info!("Data transfer test completed");
    
    Ok(metrics)
}

/// Test connection close
async fn test_connection_close(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing connection close with {}", server_addr);
    
    let mut metrics = HashMap::new();
    
    // Establish connection
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;
    
    // Open a stream
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"close test").await?;
    send.finish()?;
    
    // Test graceful close
    let close_start = std::time::Instant::now();
    conn.close(0u32.into(), b"graceful close test");
    
    // Wait for close to complete
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify connection is closed by trying to use the stream
    let read_result = recv.read(&mut [0u8; 10]).await;
    assert!(read_result.is_err() || read_result.unwrap() == 0);
    
    let close_duration = close_start.elapsed();
    metrics.insert("close_ms".to_string(), close_duration.as_millis() as f64);
    
    // Test immediate close with new connection
    let conn2 = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;
    
    let immediate_start = std::time::Instant::now();
    conn2.close(1u32.into(), b"immediate close test");
    let immediate_duration = immediate_start.elapsed();
    
    metrics.insert("immediate_close_ms".to_string(), immediate_duration.as_millis() as f64);
    
    info!("Connection close test completed");
    
    Ok(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_basic_connectivity() {
        // This is a unit test to verify the test framework itself
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        
        // Test against a known endpoint (will fail in unit tests, but validates structure)
        let result = test_handshake(&endpoint, "cloudflare.com:443").await;
        
        // In unit tests this will fail due to lack of network access
        // But we can verify the error handling
        assert!(result.is_err());
    }
}