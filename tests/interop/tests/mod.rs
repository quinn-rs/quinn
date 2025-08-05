/// Interoperability Test Categories and Cases
use ant_quic::high_level::Endpoint;
use anyhow::Result;
use std::collections::HashMap;

pub mod basic;
pub mod version;
pub mod transport;
pub mod extensions;
pub mod http3;
pub mod advanced;
pub mod nat;

/// Test category
#[derive(Debug, Clone)]
pub struct TestCategory {
    pub name: String,
    pub description: String,
    pub tests: Vec<TestCase>,
}

/// Individual test case
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// Common test utilities
pub mod utils {
    use super::*;
    use ant_quic::{ClientConfig, TransportConfig, VarInt};
    use ant_quic::crypto::rustls::QuicClientConfig;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    
    /// Create a standard client configuration for testing
    pub fn create_test_client_config() -> Result<ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
            roots.add(cert).unwrap();
        }
        
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        
        // Configure ALPN for HTTP/3
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        
        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto)?
        ));
        
        // Set transport parameters for interop testing
        let mut transport_config = TransportConfig::default();
        transport_config.max_idle_timeout(Some(VarInt::from_u32(30000).into())); // 30 seconds
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
        config.transport_config(Arc::new(transport_config));
        
        Ok(config)
    }
    
    /// Test connection establishment with timeout
    pub async fn test_connection(
        endpoint: &Endpoint,
        server_addr: &str,
        timeout_duration: Duration,
    ) -> Result<ant_quic::high_level::Connection> {
        let addr = server_addr.parse()?;
        
        timeout(timeout_duration, async {
            endpoint.connect(addr, "h3")
                .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?
                .await
                .map_err(|e| anyhow::anyhow!("Connection error: {}", e))
        })
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout after {:?}", timeout_duration))?
    }
    
    /// Measure handshake time
    pub async fn measure_handshake_time(
        endpoint: &Endpoint,
        server_addr: &str,
    ) -> Result<Duration> {
        let start = std::time::Instant::now();
        let conn = test_connection(endpoint, server_addr, Duration::from_secs(10)).await?;
        let duration = start.elapsed();
        
        // Clean close
        conn.close(0u32.into(), b"test complete");
        
        Ok(duration)
    }
    
    /// Test data transfer
    pub async fn test_data_transfer(
        conn: &ant_quic::high_level::Connection,
        size: usize,
    ) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        
        // Open a bidirectional stream
        let (mut send, mut recv) = conn.open_bi().await?;
        
        // Generate test data
        let test_data = vec![0u8; size];
        let start = std::time::Instant::now();
        
        // Send data
        send.write_all(&test_data).await?;
        send.finish()?;
        
        // Receive echo (if server echoes)
        let mut received = Vec::new();
        recv.read_to_end(&mut received).await?;
        
        let duration = start.elapsed();
        
        // Calculate metrics
        metrics.insert("transfer_time_ms".to_string(), duration.as_millis() as f64);
        metrics.insert("throughput_mbps".to_string(), 
            (size as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0)
        );
        
        Ok(metrics)
    }
    
    /// Extract server name from address
    pub fn extract_server_name(addr: &str) -> String {
        addr.split(':')
            .next()
            .unwrap_or("unknown")
            .to_string()
    }
}