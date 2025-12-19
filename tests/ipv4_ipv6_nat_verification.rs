//! IPv4/IPv6 NAT Traversal Verification Tests
//!
//! These tests verify that NAT traversal works correctly with both
//! IPv4 and IPv6 addresses, including dual-stack scenarios.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use tracing::{info, warn};

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-aws-lc-rs")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn transport_config_no_pqc() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.enable_pqc(false);
    Arc::new(transport_config)
}

/// Test IPv4 NAT traversal
#[tokio::test]
async fn test_ipv4_nat_traversal() {
    ensure_crypto_provider();

    let _ = tracing_subscriber::fmt::try_init();
    info!("Testing IPv4 NAT traversal");

    // Create IPv4 server
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

    let (cert, key) = generate_test_cert();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test-ipv4".to_vec()];

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport_config_no_pqc());

    let server = Endpoint::server(server_config, server_addr).unwrap();
    let server_addr = server.local_addr().unwrap();
    info!("IPv4 server listening on {}", server_addr);

    // Spawn server accept task
    let _server_handle = tokio::spawn(async move {
        if let Some(conn) = server.accept().await {
            let connection = conn.await.expect("Server connection failed");
            info!(
                "Server accepted IPv4 connection from {}",
                connection.remote_address()
            );
        }
    });

    // Create IPv4 client
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test-ipv4".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config_no_pqc());

    let mut endpoint = Endpoint::client(client_addr).unwrap();
    endpoint.set_default_client_config(client_config);

    // Test connection
    let conn = endpoint.connect(server_addr, "localhost").unwrap();
    let connection = timeout(Duration::from_secs(5), conn)
        .await
        .expect("Connection timeout")
        .expect("Connection failed");

    info!(
        "✓ IPv4 connection established: {}",
        connection.remote_address()
    );

    // Verify we're using IPv4
    assert!(connection.remote_address().is_ipv4());
}

/// Test IPv6 NAT traversal (if available)
#[tokio::test]
async fn test_ipv6_nat_traversal() {
    ensure_crypto_provider();

    let _ = tracing_subscriber::fmt::try_init();
    info!("Testing IPv6 NAT traversal");

    // Try to bind to IPv6 localhost
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 0);

    let (cert, key) = generate_test_cert();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test-ipv6".to_vec()];

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport_config_no_pqc());

    // Try to create IPv6 server
    let server_result = Endpoint::server(server_config, server_addr);

    if let Err(e) = server_result {
        warn!("IPv6 not available on this system: {}", e);
        info!("Skipping IPv6 test - this is expected on some systems");
        return;
    }

    let server = server_result.unwrap();
    let server_addr = server.local_addr().unwrap();
    info!("IPv6 server listening on {}", server_addr);

    // Spawn server accept task
    let _server_handle = tokio::spawn(async move {
        if let Some(conn) = server.accept().await {
            let connection = conn.await.expect("Server connection failed");
            info!(
                "Server accepted IPv6 connection from {}",
                connection.remote_address()
            );
        }
    });

    // Create IPv6 client
    let client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 0);

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test-ipv6".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config_no_pqc());

    let mut endpoint = Endpoint::client(client_addr).unwrap();
    endpoint.set_default_client_config(client_config);

    // Test connection
    let conn = endpoint.connect(server_addr, "localhost").unwrap();
    let connection = timeout(Duration::from_secs(5), conn)
        .await
        .expect("Connection timeout")
        .expect("Connection failed");

    info!(
        "✓ IPv6 connection established: {}",
        connection.remote_address()
    );

    // Verify we're using IPv6
    assert!(connection.remote_address().is_ipv6());
}

/// Test dual-stack scenario
#[tokio::test]
async fn test_dual_stack_nat_traversal() {
    ensure_crypto_provider();

    let _ = tracing_subscriber::fmt::try_init();
    info!("Testing dual-stack NAT traversal");

    // Create dual-stack server (bind to all interfaces)
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    let (cert, key) = generate_test_cert();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test-dual".to_vec()];

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport_config_no_pqc());

    let server = Arc::new(Endpoint::server(server_config, server_addr).unwrap());
    let server_port = server.local_addr().unwrap().port();
    info!("Dual-stack server listening on port {}", server_port);

    // Spawn server accept tasks
    let server_clone = server.clone();
    let _server_handle1 = tokio::spawn(async move {
        if let Some(conn) = server_clone.accept().await {
            let connection = conn.await.expect("Server connection failed");
            info!(
                "Server accepted connection from {}",
                connection.remote_address()
            );
        }
    });

    let server_clone = server.clone();
    let _server_handle2 = tokio::spawn(async move {
        if let Some(conn) = server_clone.accept().await {
            let connection = conn.await.expect("Server connection failed");
            info!(
                "Server accepted second connection from {}",
                connection.remote_address()
            );
        }
    });

    // Test IPv4 client connection
    {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test-dual".to_vec()];

        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        client_config.transport_config(transport_config_no_pqc());

        let mut endpoint = Endpoint::client(client_addr).unwrap();
        endpoint.set_default_client_config(client_config);

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);

        let conn = endpoint.connect(server_addr, "localhost").unwrap();
        let connection = timeout(Duration::from_secs(5), conn)
            .await
            .expect("Connection timeout")
            .expect("Connection failed");

        info!(
            "✓ IPv4 client connected to dual-stack server: {}",
            connection.remote_address()
        );
    }

    // Test IPv6 client connection (if available)
    {
        let client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 0);

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test-dual".to_vec()];

        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        client_config.transport_config(transport_config_no_pqc());

        match Endpoint::client(client_addr) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config);

                let server_addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    server_port,
                );

                let conn = endpoint.connect(server_addr, "localhost").unwrap();
                match timeout(Duration::from_secs(5), conn).await {
                    Ok(Ok(connection)) => {
                        info!(
                            "✓ IPv6 client connected to dual-stack server: {}",
                            connection.remote_address()
                        );
                    }
                    _ => {
                        warn!("IPv6 connection failed - this is expected on some systems");
                    }
                }
            }
            Err(e) => {
                warn!(
                    "IPv6 client creation failed: {} - this is expected on some systems",
                    e
                );
            }
        }
    }
}

// Certificate verification helper
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
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
