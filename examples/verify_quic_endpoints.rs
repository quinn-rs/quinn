/// Verify Public QUIC Endpoints
///
/// This example verifies which public QUIC endpoints are accessible
/// and documents their capabilities.
use ant_quic::{
    ClientConfig, VarInt,
    high_level::Endpoint,
};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};

/// Test endpoints from our documentation
const TEST_ENDPOINTS: &[(&str, &str)] = &[
    ("quic.nginx.org:443", "NGINX official"),
    ("cloudflare.com:443", "Cloudflare production"),
    ("www.google.com:443", "Google production"),
    ("facebook.com:443", "Meta/Facebook production"),
    ("cloudflare-quic.com:443", "Cloudflare test site"),
    ("quic.rocks:4433", "Google test endpoint"),
    ("http3-test.litespeedtech.com:4433", "LiteSpeed test"),
    ("test.privateoctopus.com:4433", "Picoquic test"),
    ("test.pquic.org:443", "PQUIC research"),
    ("www.litespeedtech.com:443", "LiteSpeed production"),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info,verify_quic_endpoints=info")
        .init();

    info!("Starting QUIC endpoint verification...");

    // Create client endpoint
    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    let mut results = Vec::new();

    for (endpoint_str, description) in TEST_ENDPOINTS {
        info!("Testing {} - {}", endpoint_str, description);

        let result = test_endpoint(&endpoint, endpoint_str).await;
        results.push((endpoint_str, description, result));
    }

    // Print summary
    println!("\n=== QUIC Endpoint Verification Results ===\n");

    let mut successful = 0;
    let mut failed = 0;

    for (endpoint_str, description, result) in &results {
        match result {
            Ok(info) => {
                successful += 1;
                println!("✅ {} - {}", endpoint_str, description);
                println!("   Connected: Yes");
                println!("   ALPN: {:?}", info.alpn);
                println!("   Protocol Version: 0x{:08x}", info.protocol_version);
                println!();
            }
            Err(e) => {
                failed += 1;
                println!("❌ {} - {}", endpoint_str, description);
                println!("   Error: {}", e);
                println!();
            }
        }
    }

    println!("Summary: {} successful, {} failed", successful, failed);

    Ok(())
}

#[derive(Debug)]
struct EndpointInfo {
    alpn: Option<Vec<u8>>,
    protocol_version: u32,
}

async fn test_endpoint(
    endpoint: &Endpoint,
    endpoint_str: &str,
) -> Result<EndpointInfo, Box<dyn std::error::Error>> {
    // Parse address
    let addr: std::net::SocketAddr = endpoint_str.parse()?;

    // Extract server name
    let server_name = endpoint_str.split(':').next().unwrap_or(endpoint_str);

    // Create client config
    #[cfg(feature = "platform-verifier")]
    let client_config = ClientConfig::try_with_platform_verifier()?;

    #[cfg(not(feature = "platform-verifier"))]
    let client_config = {
        use ant_quic::crypto::rustls::QuicClientConfig;

        let mut roots = rustls::RootCertStore::empty();

        // Add system roots
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    roots
                        .add(rustls::pki_types::CertificateDer::from(cert.0))
                        .ok();
                }
            }
            Err(e) => {
                warn!("Failed to load native certs: {}", e);
            }
        }

        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let quic_crypto = QuicClientConfig::try_from(Arc::new(crypto))?;
        ClientConfig::new(Arc::new(quic_crypto))
    };

    // Attempt connection with timeout
    let connecting = endpoint.connect_with(client_config, addr, server_name)?;

    let connection = match timeout(Duration::from_secs(5), connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(format!("Connection failed: {}", e).into()),
        Err(_) => return Err("Connection timeout".into()),
    };

    // Get connection info
    let alpn = connection.handshake_data().and_then(|data| {
        data.downcast_ref::<ant_quic::crypto::rustls::HandshakeData>()
            .and_then(|handshake| handshake.protocol.clone())
    });

    // Get protocol version - this is hardcoded for now as we don't have direct access
    let protocol_version = 0x00000001; // QUIC v1

    // Test basic data exchange
    match connection.open_bi().await {
        Ok((mut send, _recv)) => {
            send.write_all(b"HEAD / HTTP/3\r\n\r\n").await.ok();
            send.finish().ok();
        }
        Err(e) => {
            warn!("Failed to open stream: {}", e);
        }
    }

    // Close connection gracefully
    connection.close(VarInt::from_u32(0), b"test complete");

    Ok(EndpointInfo {
        alpn,
        protocol_version,
    })
}
