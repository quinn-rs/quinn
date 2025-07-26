/// Transport Features Tests
///
/// Tests QUIC transport features including streams, flow control, congestion control, and loss recovery
use super::utils;
use ant_quic::high_level::{Connection, Endpoint};
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

/// Run a transport feature test
pub async fn run_test(
    endpoint: &Endpoint,
    server_addr: &str,
    test_name: &str,
) -> Result<HashMap<String, f64>> {
    match test_name {
        "stream_operations" => test_stream_operations(endpoint, server_addr).await,
        "flow_control" => test_flow_control(endpoint, server_addr).await,
        "congestion_control" => test_congestion_control(endpoint, server_addr).await,
        "loss_recovery" => test_loss_recovery(endpoint, server_addr).await,
        _ => Err(anyhow::anyhow!("Unknown transport test: {}", test_name)),
    }
}

/// Test stream operations
async fn test_stream_operations(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing stream operations with {}", server_addr);

    let mut metrics = HashMap::new();
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Test bidirectional streams
    let bidi_start = std::time::Instant::now();
    let mut bidi_count = 0;

    for i in 0..10 {
        match timeout(Duration::from_secs(2), conn.open_bi()).await {
            Ok(Ok((mut send, mut recv))) => {
                send.write_all(format!("Bidi stream {} test", i).as_bytes())
                    .await?;
                send.finish()?;

                let mut buf = vec![0u8; 100];
                let _ = recv.read(&mut buf).await?;
                bidi_count += 1;
            }
            Ok(Err(e)) => {
                debug!("Failed to open bidi stream {}: {}", i, e);
                break;
            }
            Err(_) => {
                debug!("Timeout opening bidi stream {}", i);
                break;
            }
        }
    }

    let bidi_duration = bidi_start.elapsed();
    metrics.insert("bidi_streams_opened".to_string(), bidi_count as f64);
    metrics.insert(
        "bidi_streams_ms".to_string(),
        bidi_duration.as_millis() as f64,
    );

    // Test unidirectional streams
    let uni_start = std::time::Instant::now();
    let mut uni_count = 0;

    for i in 0..10 {
        match timeout(Duration::from_secs(2), conn.open_uni()).await {
            Ok(Ok(mut send)) => {
                send.write_all(format!("Uni stream {} test", i).as_bytes())
                    .await?;
                send.finish()?;
                uni_count += 1;
            }
            Ok(Err(e)) => {
                debug!("Failed to open uni stream {}: {}", i, e);
                break;
            }
            Err(_) => {
                debug!("Timeout opening uni stream {}", i);
                break;
            }
        }
    }

    let uni_duration = uni_start.elapsed();
    metrics.insert("uni_streams_opened".to_string(), uni_count as f64);
    metrics.insert(
        "uni_streams_ms".to_string(),
        uni_duration.as_millis() as f64,
    );

    // Test concurrent streams
    let concurrent_start = std::time::Instant::now();
    let mut handles = vec![];

    for i in 0..5 {
        let conn_clone = conn.clone();
        let handle = tokio::spawn(async move {
            let (mut send, _recv) = conn_clone.open_bi().await?;
            send.write_all(format!("Concurrent stream {}", i).as_bytes())
                .await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        });
        handles.push(handle);
    }

    let mut concurrent_success = 0;
    for handle in handles {
        if handle.await?.is_ok() {
            concurrent_success += 1;
        }
    }

    let concurrent_duration = concurrent_start.elapsed();
    metrics.insert("concurrent_streams".to_string(), concurrent_success as f64);
    metrics.insert(
        "concurrent_ms".to_string(),
        concurrent_duration.as_millis() as f64,
    );

    conn.close(0u32.into(), b"stream test complete");

    info!("Stream operations test completed");
    Ok(metrics)
}

/// Test flow control
async fn test_flow_control(endpoint: &Endpoint, server_addr: &str) -> Result<HashMap<String, f64>> {
    info!("Testing flow control with {}", server_addr);

    let mut metrics = HashMap::new();
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Test stream flow control by sending data in chunks
    let (mut send, mut recv) = conn.open_bi().await?;

    // Send data in small chunks to test flow control windows
    let chunk_size = 16 * 1024; // 16KB chunks
    let total_size = 256 * 1024; // 256KB total
    let chunks = total_size / chunk_size;

    let flow_start = std::time::Instant::now();
    let mut bytes_sent = 0;

    for i in 0..chunks {
        let chunk = vec![i as u8; chunk_size];
        match timeout(Duration::from_secs(2), send.write_all(&chunk)).await {
            Ok(Ok(_)) => {
                bytes_sent += chunk_size;
            }
            Ok(Err(e)) => {
                debug!("Flow control limit hit at {} bytes: {}", bytes_sent, e);
                break;
            }
            Err(_) => {
                debug!("Timeout sending chunk at {} bytes", bytes_sent);
                break;
            }
        }

        // Small delay to allow flow control updates
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    send.finish()?;

    let flow_duration = flow_start.elapsed();
    metrics.insert("bytes_sent".to_string(), bytes_sent as f64);
    metrics.insert(
        "flow_control_ms".to_string(),
        flow_duration.as_millis() as f64,
    );
    metrics.insert(
        "throughput_mbps".to_string(),
        (bytes_sent as f64 * 8.0) / (flow_duration.as_secs_f64() * 1_000_000.0),
    );

    // Test connection flow control with multiple streams
    let conn_flow_start = std::time::Instant::now();
    let mut stream_handles = vec![];

    for i in 0..3 {
        let conn_clone = conn.clone();
        let handle = tokio::spawn(async move {
            let (mut send, _recv) = conn_clone.open_bi().await?;
            let data = vec![i as u8; 64 * 1024]; // 64KB per stream
            send.write_all(&data).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(data.len())
        });
        stream_handles.push(handle);
    }

    let mut total_conn_bytes = 0;
    for handle in stream_handles {
        if let Ok(Ok(bytes)) = handle.await {
            total_conn_bytes += bytes;
        }
    }

    let conn_flow_duration = conn_flow_start.elapsed();
    metrics.insert("conn_flow_bytes".to_string(), total_conn_bytes as f64);
    metrics.insert(
        "conn_flow_ms".to_string(),
        conn_flow_duration.as_millis() as f64,
    );

    conn.close(0u32.into(), b"flow control test complete");

    info!("Flow control test completed");
    Ok(metrics)
}

/// Test congestion control
async fn test_congestion_control(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing congestion control with {}", server_addr);

    let mut metrics = HashMap::new();
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Test congestion control by measuring throughput over time
    let (mut send, _recv) = conn.open_bi().await?;

    // Send data in bursts to observe congestion control behavior
    let burst_size = 128 * 1024; // 128KB bursts
    let num_bursts = 10;
    let mut throughputs = vec![];

    for i in 0..num_bursts {
        let burst_data = vec![i as u8; burst_size];
        let burst_start = std::time::Instant::now();

        match timeout(Duration::from_secs(5), send.write_all(&burst_data)).await {
            Ok(Ok(_)) => {
                let burst_duration = burst_start.elapsed();
                let throughput =
                    (burst_size as f64 * 8.0) / (burst_duration.as_secs_f64() * 1_000_000.0);
                throughputs.push(throughput);

                debug!("Burst {} throughput: {:.2} Mbps", i, throughput);
            }
            _ => break,
        }

        // Delay between bursts
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    send.finish()?;

    // Calculate congestion control metrics
    if !throughputs.is_empty() {
        let avg_throughput = throughputs.iter().sum::<f64>() / throughputs.len() as f64;
        let min_throughput = throughputs.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_throughput = throughputs.iter().fold(0.0, |a, &b| a.max(b));

        metrics.insert("avg_throughput_mbps".to_string(), avg_throughput);
        metrics.insert("min_throughput_mbps".to_string(), min_throughput);
        metrics.insert("max_throughput_mbps".to_string(), max_throughput);
        metrics.insert(
            "throughput_variance".to_string(),
            (max_throughput - min_throughput) / avg_throughput,
        );
        metrics.insert("bursts_completed".to_string(), throughputs.len() as f64);
    }

    conn.close(0u32.into(), b"congestion control test complete");

    info!("Congestion control test completed");
    Ok(metrics)
}

/// Test loss recovery
async fn test_loss_recovery(
    endpoint: &Endpoint,
    server_addr: &str,
) -> Result<HashMap<String, f64>> {
    info!("Testing loss recovery with {}", server_addr);

    let mut metrics = HashMap::new();
    let conn = utils::test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;

    // Test loss recovery by sending data and measuring retransmission behavior
    // Note: We can't directly simulate packet loss at this level,
    // but we can observe recovery behavior through timing

    let (mut send, mut recv) = conn.open_bi().await?;

    // Send test pattern
    let test_data = b"Loss recovery test pattern - expecting retransmissions";
    let send_start = std::time::Instant::now();

    send.write_all(test_data).await?;
    send.finish()?;

    // Try to receive echo (if server echoes)
    let mut received = vec![0u8; test_data.len()];
    match timeout(Duration::from_secs(5), recv.read_exact(&mut received)).await {
        Ok(Ok(_)) => {
            let recovery_time = send_start.elapsed();
            metrics.insert("recovery_ms".to_string(), recovery_time.as_millis() as f64);
            metrics.insert("recovery_success".to_string(), 1.0);
        }
        _ => {
            metrics.insert("recovery_success".to_string(), 0.0);
        }
    }

    // Test multiple small messages to observe ACK behavior
    let ack_test_start = std::time::Instant::now();
    let (mut send2, _recv2) = conn.open_bi().await?;

    for i in 0..20 {
        let msg = format!("ACK test message {}", i);
        send2.write_all(msg.as_bytes()).await?;

        // Small delay to spread out packets
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    send2.finish()?;
    let ack_test_duration = ack_test_start.elapsed();

    metrics.insert(
        "ack_test_ms".to_string(),
        ack_test_duration.as_millis() as f64,
    );
    metrics.insert("messages_sent".to_string(), 20.0);

    conn.close(0u32.into(), b"loss recovery test complete");

    info!("Loss recovery test completed");
    Ok(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_features_framework() {
        // Verify test framework structure
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

        // Test will fail without network, but validates the structure
        let result = test_stream_operations(&endpoint, "quic.saorsalabs.com:9000").await;
        assert!(result.is_err());
    }
}
