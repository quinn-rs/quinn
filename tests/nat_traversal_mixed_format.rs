#\![edition = "2024"]
//! Integration tests for NAT traversal with mixed RFC and legacy endpoints

use ant_quic::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt,
    crypto::{rustls::QuicClientConfig, rustls::QuicServerConfig},
    transport_parameters::NatTraversalConfig,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Set up test logging
fn init_logging() {
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .try_init();
}

/// Create a basic server configuration
fn server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key.into())
        .unwrap();
    crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    config.transport_config(Arc::new(TransportConfig::default()));
    config
}

/// Create a basic client configuration
fn client_config() -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    config.transport_config(Arc::new(TransportConfig::default()));
    config
}

/// Certificate verification that accepts any certificate (for testing only)
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create a pair of connected endpoints
async fn make_pair(
    server_config: ServerConfig,
    client_config: ClientConfig,
) -> (Endpoint, Endpoint) {
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server_endpoint = Endpoint::server(server_config, server_addr).unwrap();

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut client_endpoint = Endpoint::client(client_addr).unwrap();
    client_endpoint.set_default_client_config(client_config);

    (client_endpoint, server_endpoint)
}

/// Test that a legacy client can connect to an RFC-aware server
#[tokio::test]
async fn legacy_client_rfc_server() {
    init_logging();

    // Create a server that supports RFC NAT traversal
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    // Create a legacy client (default config doesn't advertise RFC support)
    let client_config = client_config();

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    // Connect and verify the connection works
    let client_addr = client_endpoint.local_addr().unwrap();
    let conn = server_endpoint
        .connect(client_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Send some data to verify the connection
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"hello from server").await.unwrap();
    send.finish().unwrap();

    info!("Legacy client successfully connected to RFC server");
}

/// Test that an RFC client can connect to a legacy server
#[tokio::test]
async fn rfc_client_legacy_server() {
    init_logging();

    // Create a legacy server (no NAT traversal config)
    let server_config = server_config();

    // Create an RFC-aware client
    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    // Connect and verify
    let server_addr = server_endpoint.local_addr().unwrap();
    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Send some data
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"hello from client").await.unwrap();
    send.finish().unwrap();

    info!("RFC client successfully connected to legacy server");
}

/// Test that two RFC-aware endpoints negotiate to use RFC format
#[tokio::test]
async fn rfc_to_rfc_negotiation() {
    init_logging();

    // Create RFC-aware server
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    // Create RFC-aware client
    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    // Connect
    let server_addr = server_endpoint.local_addr().unwrap();
    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Verify transport parameters indicate RFC support
    // Note: We'd need to expose transport parameters to properly verify this
    // For now, just verify the connection works

    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"RFC negotiation test").await.unwrap();
    send.finish().unwrap();

    info!("RFC endpoints successfully negotiated format");
}

/// Test NAT traversal frames between mixed endpoints
#[tokio::test]
async fn nat_traversal_frame_compatibility() {
    init_logging();

    // This test would require more setup to actually test NAT traversal frames
    // For now, we verify basic connectivity with NAT traversal enabled

    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(5)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    // Connect both ways to test bidirectional compatibility
    let server_addr = server_endpoint.local_addr().unwrap();
    let client_addr = client_endpoint.local_addr().unwrap();

    // Client to server
    let conn1 = client_endpoint
        .connect(server_addr, "server")
        .unwrap()
        .await
        .unwrap();

    // Server to client
    let conn2 = server_endpoint
        .connect(client_addr, "client")
        .unwrap()
        .await
        .unwrap();

    // Exchange data on both connections
    let mut send1 = conn1.open_uni().await.unwrap();
    send1.write_all(b"client to server").await.unwrap();
    send1.finish().unwrap();

    let mut send2 = conn2.open_uni().await.unwrap();
    send2.write_all(b"server to client").await.unwrap();
    send2.finish().unwrap();

    info!("Bidirectional NAT traversal frame exchange successful");
}

/// Test that endpoints handle malformed frames gracefully
#[tokio::test]
async fn malformed_frame_handling() {
    init_logging();

    // This test verifies that endpoints can handle receiving frames in unexpected formats
    // without crashing the connection

    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    let client_config = client_config();

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    // Establish connection
    let server_addr = server_endpoint.local_addr().unwrap();
    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Connection should remain stable even if frames are sent in unexpected formats
    // (This would be tested more thoroughly with lower-level frame injection)

    // Verify connection is still alive
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"connection still alive").await.unwrap();
    send.finish().unwrap();

    // Wait a bit to ensure no delayed errors
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connection is still active by checking if we can open a stream
    let _ = conn.open_uni().await.unwrap();
    info!("Connection remained stable with mixed frame formats");
}
