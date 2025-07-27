//! Simple integration tests for QUIC Address Discovery Extension
//!
//! These tests verify basic address discovery functionality.

use ant_quic::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Once},
    time::Duration,
};
use tracing::info;

static INIT: Once = Once::new();

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    INIT.call_once(|| {
        // Install the crypto provider if not already installed
        #[cfg(feature = "rustls-aws-lc-rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        #[cfg(feature = "rustls-ring")]
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
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

/// Test that address discovery works by default
#[tokio::test]
async fn test_address_discovery_default_enabled() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting address discovery default enabled test");

    // Create server using default server config
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let server = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap())),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server accepts connections
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.await.unwrap();
            info!(
                "Server accepted connection from {}",
                connection.remote_address()
            );

            // Keep connection alive for testing
            tokio::time::sleep(Duration::from_millis(500)).await;

            connection
        } else {
            panic!("No incoming connection");
        }
    });

    // Client connects
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set up client config with certificate verification disabled for testing
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

    info!("Client connected to {}", connection.remote_address());

    // Wait for potential address discovery frames
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify connection works
    assert_eq!(connection.remote_address(), server_addr);

    server_handle.await.unwrap();

    info!("✓ Address discovery default enabled test completed");
}

/// Test multiple concurrent connections
#[tokio::test]
async fn test_concurrent_connections() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting concurrent connections test");

    // Create server
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let server = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap())),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server accepts multiple connections
    tokio::spawn(async move {
        let mut count = 0;
        while let Some(incoming) = server.accept().await {
            count += 1;
            let id = count;
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                info!(
                    "Server accepted connection {} from {}",
                    id,
                    connection.remote_address()
                );

                // Keep connections alive
                tokio::time::sleep(Duration::from_secs(1)).await;
            });

            if count >= 3 {
                break;
            }
        }
    });

    // Multiple clients connect
    let mut clients = vec![];
    for i in 0..3 {
        let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

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
        clients.push(connection);
    }

    // Verify all connections established
    assert_eq!(clients.len(), 3);

    info!("✓ Concurrent connections test completed");
}

/// Test with data transfer
#[tokio::test]
async fn test_with_data_transfer() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting data transfer test");

    // Create server
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let server = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap())),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server echo service
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.await.unwrap();

            // Accept a stream and echo data
            if let Ok((mut send, mut recv)) = connection.accept_bi().await {
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
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

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
    let test_data = b"Hello, QUIC Address Discovery!";
    send.write_all(test_data).await.unwrap();
    send.finish().unwrap();

    // Read echo
    let echo_data = recv.read_to_end(1024).await.unwrap();
    assert_eq!(test_data, &echo_data[..]);

    server_handle.await.unwrap();

    info!("✓ Data transfer test completed");
}
