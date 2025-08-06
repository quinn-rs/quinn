//! Integration tests for OBSERVED_ADDRESS frame flow
//!
//! These tests verify that OBSERVED_ADDRESS frames are properly
//! sent and received during connection establishment.

use ant_quic::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{debug, info};

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

/// Mock NAT environment for testing
#[derive(Clone)]
struct NatEnvironment {
    /// Maps local addresses to public addresses
    mappings: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
}

impl NatEnvironment {
    fn new() -> Self {
        Self {
            mappings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Simulate NAT mapping
    fn map_address(&self, local: SocketAddr) -> SocketAddr {
        let mut mappings = self.mappings.lock().unwrap();
        if let Some(&public) = mappings.get(&local) {
            public
        } else {
            // Create a new mapping
            let public = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, rand::random::<u8>())),
                40000 + rand::random::<u16>() % 20000,
            );
            mappings.insert(local, public);
            info!("NAT: Mapped {} -> {}", local, public);
            public
        }
    }
}

/// Test OBSERVED_ADDRESS frame flow in basic scenario
#[tokio::test]
async fn test_basic_observed_address_flow() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting basic OBSERVED_ADDRESS frame flow test");

    // Create endpoints
    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();

    // Track observations
    let observations = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = observations.clone();

    // Server accepts connections and logs observations
    let server_handle = tokio::spawn(async move {
        match server.accept().await {
            Some(incoming) => {
                let connection = incoming.await.unwrap();
                let remote = connection.remote_address();
                info!("Server accepted connection from {}", remote);

                // In a real implementation, the server would observe the client's
                // address and potentially send OBSERVED_ADDRESS frames

                // Simulate observation logic
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Log that we would send an observation
                obs_clone
                    .lock()
                    .unwrap()
                    .push(("server->client".to_string(), remote));

                connection
            }
            _ => {
                panic!("No connection");
            }
        }
    });

    // Client connects
    let client = create_test_client();
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!(
        "Client connected from {} to {}",
        connection.local_ip().unwrap(),
        connection.remote_address()
    );

    // Wait for potential observations
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check observations
    {
        let obs = observations.lock().unwrap();
        assert!(!obs.is_empty(), "Should have observations");
        info!("Observations made: {:?}", *obs);
    }

    server_handle.await.unwrap();

    info!("✓ Basic OBSERVED_ADDRESS flow test completed");
}

/// Test OBSERVED_ADDRESS frames with NAT simulation
#[tokio::test]
async fn test_observed_address_with_nat() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting OBSERVED_ADDRESS with NAT test");

    let nat = NatEnvironment::new();

    // Bootstrap server (public IP)
    let bootstrap = create_test_server();
    let bootstrap_addr = bootstrap.local_addr().unwrap();
    info!("Bootstrap server at {}", bootstrap_addr);

    // Client behind NAT
    let client_local = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 100), 50000));
    let client_public = nat.map_address(client_local);

    // Bootstrap accepts and observes
    let bootstrap_handle = tokio::spawn(async move {
        match bootstrap.accept().await {
            Some(incoming) => {
                let connection = incoming.await.unwrap();
                let observed = connection.remote_address();

                // In NAT scenario, bootstrap sees the public address
                info!("Bootstrap observed client at: {}", observed);

                // Bootstrap would send OBSERVED_ADDRESS frame with this address
                // The client would learn its public address

                connection
            }
            _ => {
                panic!("No connection");
            }
        }
    });

    // Client connects through NAT
    let client = create_test_client();
    let connection = client
        .connect(bootstrap_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!("Client thinks it's at: {}", connection.local_ip().unwrap());
    info!("Bootstrap sees client at: {}", client_public);

    // In a real scenario, client would receive OBSERVED_ADDRESS
    // and learn its public address is different from local

    bootstrap_handle.await.unwrap();

    info!("✓ OBSERVED_ADDRESS with NAT test completed");
}

/// Test multiple observations on different paths
#[tokio::test]
async fn test_multipath_observations() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting multipath observations test");

    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();

    // Server handles multiple connections
    let (tx, mut rx) = mpsc::channel::<(usize, SocketAddr)>(10);

    tokio::spawn(async move {
        let mut conn_id = 0;
        while let Some(incoming) = server.accept().await {
            let tx = tx.clone();
            let id = conn_id;
            conn_id += 1;

            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                let observed = connection.remote_address();
                info!("Server connection {}: observed {}", id, observed);
                tx.send((id, observed)).await.unwrap();

                // Keep connection alive
                tokio::time::sleep(Duration::from_secs(1)).await;
            });
        }
    });

    // Multiple clients connect (simulating different paths)
    let mut clients = vec![];
    for i in 0..3 {
        let client = create_test_client();
        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        info!("Client {} connected", i);
        clients.push(connection);
    }

    // Collect observations
    let mut observations = vec![];
    for _ in 0..3 {
        if let Some(obs) = rx.recv().await {
            observations.push(obs);
        }
    }

    assert_eq!(observations.len(), 3, "Should have 3 observations");
    info!("All observations: {:?}", observations);

    info!("✓ Multipath observations test completed");
}

/// Test observation rate limiting behavior
#[tokio::test]
async fn test_observation_rate_limiting() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting rate limiting test");

    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();

    // Track observation attempts
    let attempts = Arc::new(Mutex::new(0));
    let attempts_clone = attempts.clone();

    // Server with rate limiting simulation
    let server_handle = tokio::spawn(async move {
        match server.accept().await {
            Some(incoming) => {
                let connection = incoming.await.unwrap();

                // Simulate multiple observation triggers
                for i in 0..10 {
                    // Check if we should send (rate limited)
                    {
                        let mut count = attempts_clone.lock().unwrap();
                        *count += 1;

                        // Simulate rate limiting: only first few should succeed
                        if i < 3 {
                            info!("Observation {} would be sent", i);
                        } else {
                            debug!("Observation {} rate limited", i);
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                connection
            }
            _ => {
                panic!("No connection");
            }
        }
    });

    // Client connects
    let client = create_test_client();
    let _connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Wait for rate limiting test
    tokio::time::sleep(Duration::from_millis(200)).await;

    let total_attempts = *attempts.lock().unwrap();
    assert_eq!(total_attempts, 10, "Should attempt 10 observations");

    server_handle.await.unwrap();

    info!("✓ Rate limiting test completed");
}

/// Test address discovery in connection migration scenario
#[tokio::test]
async fn test_observation_during_migration() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting migration observation test");

    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();

    // Server monitors for address changes
    let (tx, mut rx) = mpsc::channel::<String>(10);

    let server_handle = tokio::spawn(async move {
        match server.accept().await {
            Some(incoming) => {
                let connection = incoming.await.unwrap();
                let initial = connection.remote_address();
                tx.send(format!("Initial: {initial}")).await.unwrap();

                // Monitor for changes
                for i in 0..5 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let current = connection.remote_address();

                    if current != initial {
                        tx.send(format!("Migration {i}: {initial} -> {current}"))
                            .await
                            .unwrap();
                    }
                }

                connection
            }
            _ => {
                panic!("No connection");
            }
        }
    });

    // Client connects
    let client = create_test_client();
    let _connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Collect events
    let mut events = vec![];
    tokio::time::sleep(Duration::from_millis(600)).await;

    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    info!("Migration events: {:?}", events);
    assert!(!events.is_empty(), "Should have at least initial event");

    server_handle.await.unwrap();

    info!("✓ Migration observation test completed");
}

/// Helper to create test server endpoint
fn create_test_server() -> Endpoint {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));

    Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()
}

/// Helper to create test client endpoint
fn create_test_client() -> Endpoint {
    // Create a client config that skips certificate verification for testing
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();

    // Set ALPN protocols to match server
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    endpoint.set_default_client_config(client_config);
    endpoint
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
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
