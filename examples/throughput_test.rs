// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Throughput and efficiency testing example
//!
//! This example measures the throughput and efficiency of data transfer
//! between two ant-quic nodes with comprehensive statistics.

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
use tracing::{info, warn};

/// Generate self-signed certificate for testing
fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info,throughput_test=info")
        .init();

    info!("=== Ant-QUIC Throughput Test ===");

    // Generate certificate
    let (cert, key) = generate_test_cert();

    // Create server
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let server_socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let server_addr = server_socket.local_addr()?;

    let runtime = default_runtime().ok_or_else(|| anyhow::anyhow!("Failed to create runtime"))?;
    let server = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )?;

    info!("Server listening on {}", server_addr);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Connection failed: {}", e);
                    continue;
                }
            };

            info!(
                "Server: Connection established from {}",
                connection.remote_address()
            );

            tokio::spawn(async move {
                // Accept bidirectional stream
                match connection.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        let mut total_received = 0u64;
                        let start = Instant::now();
                        let mut buf = vec![0u8; 65536];

                        // Echo all data back
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(n)) => {
                                    total_received += n as u64;
                                    if let Err(e) = send.write_all(&buf[..n]).await {
                                        warn!("Server send error: {}", e);
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    // Stream finished
                                    info!("Server: Stream finished");
                                    break;
                                }
                                Err(e) => {
                                    warn!("Server read error: {}", e);
                                    break;
                                }
                            }
                        }

                        let elapsed = start.elapsed();
                        let throughput =
                            (total_received as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;

                        info!(
                            "Server: Received {} bytes in {:.2}s ({:.2} Mbps)",
                            total_received,
                            elapsed.as_secs_f64(),
                            throughput
                        );

                        // Finish send stream
                        if let Err(e) = send.finish() {
                            warn!("Server finish error: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Server accept_bi error: {}", e);
                    }
                }

                // Get connection stats
                let stats = connection.stats();
                info!("Server connection stats: {:?}", stats);
            });
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client
    let client_socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;

    let mut client = Endpoint::new(EndpointConfig::default(), None, client_socket, runtime)?;

    // Configure client crypto (skip verification for testing)
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));

    client.set_default_client_config(client_config);

    info!("Client connecting to {}", server_addr);

    // Connect
    let connection = client.connect(server_addr, "localhost")?.await?;

    info!("Client: Connection established");

    // Test parameters - using smaller total for more reliable test
    let chunk_size: usize = 8 * 1024; // 8 KB chunks
    let total_bytes: u64 = 10 * 1024 * 1024; // 10 MB total
    let num_chunks = (total_bytes as usize) / chunk_size;

    info!(
        "Starting data transfer: {} chunks of {} bytes ({} MB total)",
        num_chunks,
        chunk_size,
        total_bytes / (1024 * 1024)
    );

    // Open bidirectional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send data
    let send_start = Instant::now();
    let chunk = vec![0xAB; chunk_size];

    for i in 0..num_chunks {
        send.write_all(&chunk).await?;

        if i % 100 == 0 {
            info!(
                "Sent {} / {} chunks ({:.1}%)",
                i,
                num_chunks,
                (i as f64 / num_chunks as f64) * 100.0
            );
        }

        // Small delay to allow flow control
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    send.finish()?;
    let send_elapsed = send_start.elapsed();

    info!("Send completed in {:.2}s", send_elapsed.as_secs_f64());

    // Receive echoed data
    let recv_start = Instant::now();
    let mut total_received = 0u64;
    let mut buf = vec![0u8; 65536];

    loop {
        match recv.read(&mut buf).await? {
            Some(n) => {
                total_received += n as u64;

                if total_received % (10 * 1024 * 1024) == 0 {
                    info!(
                        "Received {} MB / {} MB ({:.1}%)",
                        total_received / (1024 * 1024),
                        total_bytes / (1024 * 1024),
                        (total_received as f64 / total_bytes as f64) * 100.0
                    );
                }
            }
            None => break,
        }
    }

    let recv_elapsed = recv_start.elapsed();

    // Calculate statistics
    let send_throughput = (total_bytes as f64 * 8.0) / send_elapsed.as_secs_f64() / 1_000_000.0;
    let recv_throughput = (total_received as f64 * 8.0) / recv_elapsed.as_secs_f64() / 1_000_000.0;
    let round_trip_time = send_elapsed + recv_elapsed;

    info!("\n=== Results ===");
    info!(
        "Total sent: {} bytes ({} MB)",
        total_bytes,
        total_bytes / (1024 * 1024)
    );
    info!(
        "Total received: {} bytes ({} MB)",
        total_received,
        total_received / (1024 * 1024)
    );
    info!("Send time: {:.2}s", send_elapsed.as_secs_f64());
    info!("Receive time: {:.2}s", recv_elapsed.as_secs_f64());
    info!("Round-trip time: {:.2}s", round_trip_time.as_secs_f64());
    info!("Send throughput: {:.2} Mbps", send_throughput);
    info!("Receive throughput: {:.2} Mbps", recv_throughput);
    info!(
        "Average throughput: {:.2} Mbps",
        (send_throughput + recv_throughput) / 2.0
    );

    // Get connection stats
    let stats = connection.stats();
    info!("\n=== Connection Statistics ===");
    info!("Path stats: {:?}", stats.path);
    info!("Frame stats (TX): {:?}", stats.frame_tx);
    info!("Frame stats (RX): {:?}", stats.frame_rx);
    info!("UDP stats (TX): {:?}", stats.udp_tx);
    info!("UDP stats (RX): {:?}", stats.udp_rx);

    // Calculate efficiency
    let udp_overhead = stats.udp_tx.bytes.saturating_sub(total_bytes);
    let efficiency = (total_bytes as f64 / stats.udp_tx.bytes as f64) * 100.0;

    info!("\n=== Efficiency ===");
    info!("Application data: {} bytes", total_bytes);
    info!("UDP bytes sent: {} bytes", stats.udp_tx.bytes);
    info!("Protocol overhead: {} bytes", udp_overhead);
    info!("Efficiency: {:.2}%", efficiency);

    // Close connection
    connection.close(0u32.into(), b"test complete");

    // Wait a bit for server to finish
    tokio::time::sleep(Duration::from_millis(500)).await;

    server_handle.abort();

    Ok(())
}
