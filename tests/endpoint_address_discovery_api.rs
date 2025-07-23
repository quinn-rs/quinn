//! Tests for the public address discovery API on Endpoint
//! 
//! This tests the high-level API that applications use to control
//! and monitor address discovery functionality.

use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use ant_quic::{Endpoint, EndpointConfig, ClientConfig, ServerConfig, TransportConfig};
use ant_quic::crypto::rustls::rustls;
use tracing::{info, debug};

/// Create a test endpoint with default configuration
fn create_test_endpoint() -> Endpoint {
    let server_config = ServerConfig::with_crypto(Arc::new(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()))
        .unwrap()));
    
    let config = EndpointConfig::default();
    Endpoint::new(Arc::new(config), Some(Arc::new(server_config)), false, None)
}

/// Test that address discovery is enabled by default
#[test]
fn test_address_discovery_enabled_by_default() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let endpoint = create_test_endpoint();
    
    // Address discovery should be enabled by default
    assert!(endpoint.address_discovery_enabled());
    info!("✓ Address discovery is enabled by default");
}

/// Test disabling address discovery
#[test]
fn test_disable_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut endpoint = create_test_endpoint();
    
    // Disable address discovery
    endpoint.enable_address_discovery(false);
    assert!(!endpoint.address_discovery_enabled());
    info!("✓ Address discovery can be disabled");
    
    // Re-enable address discovery
    endpoint.enable_address_discovery(true);
    assert!(endpoint.address_discovery_enabled());
    info!("✓ Address discovery can be re-enabled");
}

/// Test that new connections inherit address discovery setting
#[test]
fn test_new_connections_inherit_setting() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut endpoint = create_test_endpoint();
    let now = std::time::Instant::now();
    
    // Disable address discovery
    endpoint.enable_address_discovery(false);
    
    // Create a new connection
    let remote = SocketAddr::from((Ipv4Addr::new(93, 184, 215, 123), 443));
    let client_config = ClientConfig::new(Arc::new(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth()));
    
    match endpoint.connect(now, client_config, remote, "example.com") {
        Ok((handle, mut connection)) => {
            // The connection should have address discovery disabled
            assert!(!connection.address_discovery_enabled());
            info!("✓ New connections inherit address discovery setting");
        }
        Err(e) => panic!("Failed to create connection: {:?}", e),
    }
}

/// Test discovered addresses getter
#[test]
fn test_discovered_addresses_getter() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let endpoint = create_test_endpoint();
    
    // Initially, there should be no discovered addresses
    let addresses = endpoint.discovered_addresses();
    assert!(addresses.is_empty());
    info!("✓ Initially no discovered addresses");
    
    // TODO: After connections are established and addresses discovered,
    // this will return the discovered addresses
}

/// Test observed address on connection
#[test]
fn test_connection_observed_address() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut endpoint = create_test_endpoint();
    let now = std::time::Instant::now();
    
    // Create a connection
    let remote = SocketAddr::from((Ipv4Addr::new(93, 184, 215, 123), 443));
    let client_config = ClientConfig::new(Arc::new(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth()));
    
    match endpoint.connect(now, client_config, remote, "example.com") {
        Ok((handle, connection)) => {
            // Initially, there should be no observed address
            assert_eq!(connection.observed_address(), None);
            info!("✓ Initially no observed address on connection");
            
            // TODO: After receiving OBSERVED_ADDRESS frames,
            // this will return the observed address
        }
        Err(e) => panic!("Failed to create connection: {:?}", e),
    }
}

/// Test address change callbacks
#[test]
fn test_address_change_callbacks() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut endpoint = create_test_endpoint();
    let address_changes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let changes_clone = address_changes.clone();
    
    // Set up address change callback
    endpoint.set_address_change_callback(Box::new(move |old_addr, new_addr| {
        let mut changes = changes_clone.lock().unwrap();
        changes.push((old_addr, new_addr));
        info!("Address change detected: {:?} -> {:?}", old_addr, new_addr);
    }));
    
    // Initially no changes
    assert!(address_changes.lock().unwrap().is_empty());
    info!("✓ Address change callback can be set");
    
    // TODO: When addresses change, the callback will be invoked
}

/// Test clearing address change callback
#[test]
fn test_clear_address_change_callback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut endpoint = create_test_endpoint();
    
    // Set a callback
    endpoint.set_address_change_callback(Box::new(|_, _| {
        panic!("This callback should not be called after clearing");
    }));
    
    // Clear the callback
    endpoint.clear_address_change_callback();
    
    info!("✓ Address change callback can be cleared");
    
    // TODO: Verify no callbacks are invoked after clearing
}

/// Test address discovery statistics
#[test]
fn test_address_discovery_statistics() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let endpoint = create_test_endpoint();
    
    // Get address discovery statistics
    let stats = endpoint.address_discovery_stats();
    
    // Initially all stats should be zero
    assert_eq!(stats.frames_sent, 0);
    assert_eq!(stats.frames_received, 0);
    assert_eq!(stats.addresses_discovered, 0);
    assert_eq!(stats.address_changes_detected, 0);
    
    info!("✓ Address discovery statistics available");
}

// Helper for skipping certificate verification in tests
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
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Address discovery statistics
#[derive(Debug, Default, Clone)]
pub struct AddressDiscoveryStats {
    /// Number of OBSERVED_ADDRESS frames sent
    pub frames_sent: u64,
    /// Number of OBSERVED_ADDRESS frames received
    pub frames_received: u64,
    /// Number of unique addresses discovered
    pub addresses_discovered: u64,
    /// Number of address changes detected
    pub address_changes_detected: u64,
}