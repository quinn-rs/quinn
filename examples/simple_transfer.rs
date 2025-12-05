// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Simple data transfer example with clear metrics
//!
//! This example demonstrates basic QUIC data transfer with throughput measurement.
//! Run in two terminals:
//!
//! Terminal 1 (Server):
//! ```bash
//! cargo run --release --example simple_transfer
//! ```
//!
//! Terminal 2 (Client):
//! ```bash
//! cargo run --release --example simple_transfer -- --client
//! ```

use ant_quic::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    high_level::default_runtime,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::info;

/// Generate self-signed certificate for testing
fn generate_test_cert() -> anyhow::Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    Ok((cert_der, key_der))
}

/// Certificate verifier that accepts any certificate (testing only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

async fn run_server(addr: SocketAddr) -> anyhow::Result<()> {
    info!("🚀 Starting server on {}", addr);

    // Generate certificate
    let (cert, key) = generate_test_cert()?;

    // Create server
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![b"transfer".to_vec()];

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let server_socket = std::net::UdpSocket::bind(addr)?;
    let server_addr = server_socket.local_addr()?;

    let runtime = default_runtime().ok_or_else(|| anyhow::anyhow!("Failed to create runtime"))?;
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime,
    )?;

    info!("✅ Server listening on {}", server_addr);
    info!("💡 Now run the client: cargo run --release --example simple_transfer -- --client");
    info!("");

    // Accept connection
    let incoming = server
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("No incoming connection"))?;

    let connection = incoming.await?;
    info!("🔗 Client connected from {}", connection.remote_address());

    // Accept stream
    let (mut send, mut recv) = connection.accept_bi().await?;

    let mut total_received = 0u64;
    let start = Instant::now();
    let mut buf = vec![0u8; 16384];
    let mut last_report = Instant::now();

    info!("📥 Receiving data...");

    // Receive and echo data
    while let Some(n) = recv.read(&mut buf).await? {
        total_received += n as u64;

        // Echo back
        send.write_all(&buf[..n]).await?;

        // Progress report every 100ms
        if last_report.elapsed() > Duration::from_millis(100) {
            let elapsed = start.elapsed().as_secs_f64();
            let throughput_mbps = (total_received as f64 * 8.0) / elapsed / 1_000_000.0;
            info!(
                "   📊 Received: {} KB ({:.1} Mbps)",
                total_received / 1024,
                throughput_mbps
            );
            last_report = Instant::now();
        }
    }

    let elapsed = start.elapsed();
    let throughput_mbps = (total_received as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;

    info!("");
    info!("✅ Transfer complete!");
    info!("📊 Statistics:");
    info!(
        "   Total received: {} KB ({} MB)",
        total_received / 1024,
        total_received / (1024 * 1024)
    );
    info!("   Time: {:.2}s", elapsed.as_secs_f64());
    info!("   Throughput: {:.2} Mbps", throughput_mbps);

    // Get connection stats
    let stats = connection.stats();
    let efficiency = (total_received as f64 / stats.udp_rx.bytes as f64) * 100.0;

    info!("");
    info!("🔍 Efficiency Metrics:");
    info!("   Application data: {} bytes", total_received);
    info!("   UDP bytes received: {} bytes", stats.udp_rx.bytes);
    info!(
        "   Protocol overhead: {} bytes",
        stats.udp_rx.bytes.saturating_sub(total_received)
    );
    info!("   Efficiency: {:.2}%", efficiency);

    send.finish()?;

    // Wait a bit before closing
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}

async fn run_client(server_addr: SocketAddr) -> anyhow::Result<()> {
    info!("🚀 Starting client, connecting to {}", server_addr);

    // Create client
    let client_socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let runtime = default_runtime().ok_or_else(|| anyhow::anyhow!("Failed to create runtime"))?;

    let mut client = Endpoint::new(EndpointConfig::default(), None, client_socket, runtime)?;

    // Configure client crypto
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"transfer".to_vec()];

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));

    client.set_default_client_config(client_config);

    // Connect
    let connection = client.connect(server_addr, "localhost")?.await?;

    info!("✅ Connected to server");

    // Test parameters - small size for reliable transfer
    let chunk_size: usize = 4096; // 4 KB chunks
    let total_size: u64 = 1024 * 1024; // 1 MB total
    let num_chunks = (total_size / chunk_size as u64) as usize;

    info!(
        "📤 Transferring {} KB in {} chunks of {} bytes",
        total_size / 1024,
        num_chunks,
        chunk_size
    );
    info!("");

    // Open stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send data
    let send_start = Instant::now();
    let chunk = vec![0xAB; chunk_size];

    for i in 0..num_chunks {
        send.write_all(&chunk).await?;

        // Progress report every 50 chunks
        if i > 0 && i % 50 == 0 {
            let progress = (i as f64 / num_chunks as f64) * 100.0;
            info!("   📤 Sent: {:.1}%", progress);
        }

        // Small delay every 10 chunks for flow control
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }

    send.finish()?;
    let send_elapsed = send_start.elapsed();

    info!("✅ Send complete in {:.2}s", send_elapsed.as_secs_f64());
    info!("📥 Receiving echo...");

    // Receive echoed data
    let recv_start = Instant::now();
    let mut total_received = 0u64;
    let mut buf = vec![0u8; 16384];

    while let Some(n) = recv.read(&mut buf).await? {
        total_received += n as u64;
    }

    let recv_elapsed = recv_start.elapsed();

    // Calculate statistics
    let send_throughput = (total_size as f64 * 8.0) / send_elapsed.as_secs_f64() / 1_000_000.0;
    let recv_throughput = (total_received as f64 * 8.0) / recv_elapsed.as_secs_f64() / 1_000_000.0;
    let round_trip = send_elapsed + recv_elapsed;

    info!("");
    info!("✅ Transfer complete!");
    info!("📊 Results:");
    info!("   Sent: {} KB", total_size / 1024);
    info!("   Received: {} KB", total_received / 1024);
    info!(
        "   Send time: {:.2}s ({:.2} Mbps)",
        send_elapsed.as_secs_f64(),
        send_throughput
    );
    info!(
        "   Receive time: {:.2}s ({:.2} Mbps)",
        recv_elapsed.as_secs_f64(),
        recv_throughput
    );
    info!("   Round-trip: {:.2}s", round_trip.as_secs_f64());
    info!(
        "   Average: {:.2} Mbps",
        (send_throughput + recv_throughput) / 2.0
    );

    // Get connection stats
    let stats = connection.stats();
    let efficiency = (total_size as f64 / stats.udp_tx.bytes as f64) * 100.0;

    info!("");
    info!("🔍 Efficiency Metrics:");
    info!("   Application data: {} bytes", total_size);
    info!("   UDP bytes sent: {} bytes", stats.udp_tx.bytes);
    info!(
        "   Protocol overhead: {} bytes",
        stats.udp_tx.bytes.saturating_sub(total_size)
    );
    info!("   Efficiency: {:.2}%", efficiency);

    // Close connection
    connection.close(0u32.into(), b"complete");

    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("simple_transfer=info,ant_quic=warn")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let is_client = args.len() > 1 && args[1] == "--client";

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 5000));

    if is_client {
        run_client(server_addr).await
    } else {
        run_server(server_addr).await
    }
}
