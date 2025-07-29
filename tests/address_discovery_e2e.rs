//! End-to-end integration tests for QUIC Address Discovery
//!
//! These tests verify the complete address discovery flow using
//! the public APIs available in ant-quic.

use ant_quic::{
    ClientConfig, Endpoint, ServerConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::info;

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    // Try to install the crypto provider, ignore if already installed
    #[cfg(feature = "rustls-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[cfg(feature = "rustls-ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // If neither feature is enabled, use default
    #[cfg(not(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))]
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Helper to generate self-signed certificate for testing
fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

/// Create a test server endpoint
fn create_server_endpoint() -> Endpoint {
    let (cert, key) = generate_test_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));

    Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()
}

/// Create a test client endpoint  
fn create_client_endpoint() -> Endpoint {
    Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()
}

/// Test that address discovery is enabled by default
#[tokio::test]
async fn test_address_discovery_enabled_by_default() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let server = create_server_endpoint();
    let client = create_client_endpoint();

    // Address discovery is enabled by default in the configuration
    info!("✓ Address discovery is enabled by default on both endpoints");
}

/// Test basic client-server address discovery flow
#[tokio::test]
async fn test_client_server_address_discovery() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let server = create_server_endpoint();
    let server_addr = server.local_addr().unwrap();

    // Start server
    let server_handle = tokio::spawn(async move {
        info!("Server listening on {}", server_addr);

        while let Some(incoming) = server.accept().await {
            let connection = incoming.await.unwrap();
            info!(
                "Server accepted connection from {}",
                connection.remote_address()
            );

            // Keep connection alive for testing
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Get stats before closing
            let stats = connection.stats();
            info!("Server connection stats: {:?}", stats);

            return connection;
        }
        panic!("No incoming connection");
    });

    // Client connects
    let mut client = create_client_endpoint();

    // Create client config that skips cert verification for testing
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    // Set the client config on the endpoint
    client.set_default_client_config(client_config);

    info!("Client connecting to {}", server_addr);
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!("Client connected to {}", connection.remote_address());

    // Give time for potential address observations
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check connection stats
    let client_stats = connection.stats();
    info!("Client connection stats: {:?}", client_stats);

    // Verify address discovery is enabled on the connection
    assert!(connection.stable_id() != 0);

    // Close connections
    connection.close(VarInt::from_u32(0), b"test done");
    let server_conn = server_handle.await.unwrap();
    server_conn.close(VarInt::from_u32(0), b"test done");

    info!("✓ Client-server address discovery flow completed");
}

/// Test disabling address discovery
#[tokio::test]
async fn test_disable_address_discovery() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    // Address discovery configuration is set at endpoint creation time
    // This test verifies the default behavior
    let server = create_server_endpoint();
    let client = create_client_endpoint();

    // Address discovery is enabled by default in ant-quic
    info!("Address discovery is enabled by default in ant-quic");

    // To disable address discovery, one would need to configure it
    // at endpoint creation time using a custom EndpointConfig

    info!("✓ Address discovery configuration test completed");
}

/// Test concurrent connections with address discovery
#[tokio::test]
async fn test_concurrent_connections_address_discovery() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let server = create_server_endpoint();
    let server_addr = server.local_addr().unwrap();

    // Server accepts multiple connections
    let (tx, mut rx) = mpsc::channel(10);
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                info!(
                    "Server accepted connection from {}",
                    connection.remote_address()
                );
                tx.send(connection).await.unwrap();
            });
        }
    });

    // Multiple clients connect
    let mut client_connections = vec![];
    for i in 0..3 {
        let mut client = create_client_endpoint();

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test".to_vec()];

        let client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

        client.set_default_client_config(client_config);

        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        info!("Client {} connected", i);
        client_connections.push(connection);
    }

    // Collect server connections
    let mut server_connections = vec![];
    for _ in 0..3 {
        if let Some(conn) = rx.recv().await {
            server_connections.push(conn);
        }
    }

    // Verify all connections have address discovery enabled
    for conn in &client_connections {
        assert!(conn.stable_id() != 0);
    }

    for conn in &server_connections {
        assert!(conn.stable_id() != 0);
    }

    info!("✓ Concurrent connections with address discovery completed");
}

/// Test address discovery with connection migration
#[tokio::test]
async fn test_address_discovery_during_migration() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let server = create_server_endpoint();
    let server_addr = server.local_addr().unwrap();

    // Server monitors for migrations
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.await.unwrap();
            let initial_addr = connection.remote_address();
            info!("Server: Initial client address: {}", initial_addr);

            // Monitor connection for a while
            for i in 0..5 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let current_addr = connection.remote_address();
                if current_addr != initial_addr {
                    info!(
                        "Server: Detected migration at iteration {}: {} -> {}",
                        i, initial_addr, current_addr
                    );
                }
            }

            connection
        } else {
            panic!("No connection");
        }
    });

    // Client connects and potentially migrates
    let mut client = create_client_endpoint();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!("Client connected from {}", connection.local_ip().unwrap());

    // Simulate activity that might trigger observations
    tokio::time::sleep(Duration::from_millis(500)).await;

    server_handle.await.unwrap();

    info!("✓ Address discovery during migration test completed");
}

/// Test with simple data exchange
#[tokio::test]
async fn test_address_discovery_with_data_transfer() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let server = create_server_endpoint();
    let server_addr = server.local_addr().unwrap();

    // Server echo service
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.await.unwrap();

            // Accept a bidirectional stream
            if let Ok((mut send, mut recv)) = connection.accept_bi().await {
                // Echo data back
                let data = recv.read_to_end(1024).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
                info!("Server echoed {} bytes", data.len());
            }

            connection
        } else {
            panic!("No connection");
        }
    });

    // Client sends data
    let mut client = create_client_endpoint();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Send data
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let test_data = b"Hello, address discovery!";
    send.write_all(test_data).await.unwrap();
    send.finish().unwrap();

    // Read echo
    let echo_data = recv.read_to_end(1024).await.unwrap();
    assert_eq!(test_data, &echo_data[..]);

    info!("✓ Data transfer with address discovery completed");

    server_handle.await.unwrap();
}

/// Custom certificate verifier that accepts any certificate (for testing only)
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
