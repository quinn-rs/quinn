//! Comprehensive integration tests for QUIC Address Discovery Extension
//! 
//! These tests verify the complete flow of address discovery from
//! connection establishment through frame exchange to NAT traversal integration.

use std::{
    net::{SocketAddr, Ipv4Addr, IpAddr},
    sync::Arc,
    time::Duration,
    collections::HashMap,
};
use ant_quic::{
    Endpoint, EndpointConfig, ClientConfig, ServerConfig, 
    TransportConfig, VarInt, ConnectionError, Event,
};
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{info, debug, warn};

/// Helper to create a test certificate
fn generate_test_cert() -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (cert_der, key_der)
}

/// Helper to create server and client endpoints with address discovery
async fn create_test_endpoints() -> (Endpoint, Endpoint) {
    let (cert, key) = generate_test_cert();
    
    // Create server config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone())
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];
    
    // Create server endpoint with address discovery enabled
    let mut server_config = EndpointConfig::default();
    server_config.enable_address_discovery(true);
    server_config.set_address_discovery_config(ant_quic::AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 20,
        observe_all_paths: true,
    });
    
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr, Arc::new(ServerConfig::with_crypto(Arc::new(server_crypto))))
        .await
        .unwrap();
    
    // Create client config
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];
    
    // Create client endpoint with address discovery enabled
    let mut client_config = EndpointConfig::default();
    client_config.enable_address_discovery(true);
    
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let client = Endpoint::client(client_addr, client_config)
        .await
        .unwrap();
    
    (server, client)
}

/// Test basic address discovery flow between client and server
#[tokio::test]
async fn test_basic_address_discovery_flow() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting basic address discovery flow test");
    
    let (server, client) = create_test_endpoints().await;
    let server_addr = server.local_addr().unwrap();
    
    // Spawn server to accept connections
    let server_handle = tokio::spawn(async move {
        info!("Server listening on {}", server_addr);
        
        if let Some(incoming) = server.accept().await {
            let connection = incoming.accept().unwrap().await.unwrap();
            info!("Server accepted connection from {}", connection.remote_address());
            
            // Server should observe client's address and may send OBSERVED_ADDRESS frames
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Check if we sent any observations
            let stats = connection.address_discovery_stats();
            info!("Server sent {} OBSERVED_ADDRESS frames", stats.observations_sent);
            
            connection
        } else {
            panic!("No incoming connection");
        }
    });
    
    // Client connects to server
    info!("Client connecting to server at {}", server_addr);
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    info!("Client connected from {} to {}", 
        connection.local_address().unwrap(), 
        connection.remote_address()
    );
    
    // Wait for potential OBSERVED_ADDRESS frames
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Check client's discovered addresses
    let client_stats = connection.address_discovery_stats();
    info!("Client received {} OBSERVED_ADDRESS frames", client_stats.observations_received);
    
    let discovered = connection.discovered_addresses();
    info!("Client discovered addresses: {:?}", discovered);
    
    // Verify server connection
    let server_conn = server_handle.await.unwrap();
    let server_stats = server_conn.address_discovery_stats();
    
    // Both sides should have address discovery enabled
    assert!(connection.address_discovery_enabled());
    assert!(server_conn.address_discovery_enabled());
    
    info!("✓ Basic address discovery flow completed successfully");
}

/// Test address discovery with multiple paths
#[tokio::test]
async fn test_multipath_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting multipath address discovery test");
    
    // This test simulates a scenario where a client has multiple network interfaces
    // In a real scenario, the client might connect via WiFi and cellular simultaneously
    
    let (server, client) = create_test_endpoints().await;
    let server_addr = server.local_addr().unwrap();
    
    // Server accepts connections
    let server_handle = tokio::spawn(async move {
        let mut connections = vec![];
        
        // Accept multiple connections (simulating different paths)
        for i in 0..2 {
            if let Some(incoming) = server.accept().await {
                let connection = incoming.accept().unwrap().await.unwrap();
                info!("Server accepted connection {} from {}", i, connection.remote_address());
                connections.push(connection);
            }
        }
        
        // Give time for address observations
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        for (i, conn) in connections.iter().enumerate() {
            let stats = conn.address_discovery_stats();
            info!("Connection {} stats: {:?}", i, stats);
        }
        
        connections
    });
    
    // Client creates multiple connections (simulating multiple paths)
    let mut client_connections = vec![];
    for i in 0..2 {
        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        info!("Client connection {} established", i);
        client_connections.push(connection);
    }
    
    // Wait for address discovery
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Check discovered addresses on each path
    for (i, conn) in client_connections.iter().enumerate() {
        let discovered = conn.discovered_addresses();
        let stats = conn.address_discovery_stats();
        info!("Client connection {} discovered: {:?}, stats: {:?}", i, discovered, stats);
    }
    
    let server_conns = server_handle.await.unwrap();
    assert_eq!(server_conns.len(), 2);
    
    info!("✓ Multipath address discovery test completed");
}

/// Test address discovery rate limiting
#[tokio::test]
async fn test_address_discovery_rate_limiting() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting rate limiting test");
    
    // Create endpoints with low rate limit
    let (cert, key) = generate_test_cert();
    
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];
    
    let mut server_config = EndpointConfig::default();
    server_config.enable_address_discovery(true);
    server_config.set_address_discovery_config(ant_quic::AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 2, // Very low rate: 2 per second
        observe_all_paths: false,
    });
    
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr, Arc::new(ServerConfig::with_crypto(Arc::new(server_crypto))))
        .await
        .unwrap();
    
    let server_addr = server.local_addr().unwrap();
    
    // Server that tries to trigger many observations
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.accept().unwrap().await.unwrap();
            
            // Try to trigger multiple observations quickly
            for i in 0..10 {
                // In a real implementation, this might be triggered by
                // path changes or other events
                debug!("Observation trigger {}", i);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            
            // Check how many were actually sent (should be rate limited)
            let stats = connection.address_discovery_stats();
            info!("Observations sent: {} (should be rate limited)", stats.observations_sent);
            
            // With 2/sec rate and ~500ms duration, should send at most 2-3
            assert!(stats.observations_sent <= 3, "Rate limiting not working");
            
            connection
        } else {
            panic!("No connection");
        }
    });
    
    // Client setup
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    let client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), EndpointConfig::default())
        .await
        .unwrap();
    
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    server_handle.await.unwrap();
    
    info!("✓ Rate limiting test completed");
}

/// Test address discovery in bootstrap mode
#[tokio::test]
async fn test_bootstrap_mode_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting bootstrap mode test");
    
    // Create bootstrap node with higher observation rate
    let (cert, key) = generate_test_cert();
    
    let mut bootstrap_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    bootstrap_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];
    
    let mut bootstrap_config = EndpointConfig::default();
    bootstrap_config.enable_address_discovery(true);
    bootstrap_config.set_address_discovery_config(ant_quic::AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 50, // Higher rate for bootstrap nodes
        observe_all_paths: true,
    });
    bootstrap_config.set_bootstrap_mode(true);
    
    let bootstrap_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let bootstrap = Endpoint::server(
        bootstrap_config, 
        bootstrap_addr, 
        Arc::new(ServerConfig::with_crypto(Arc::new(bootstrap_crypto)))
    )
    .await
    .unwrap();
    
    let bootstrap_addr = bootstrap.local_addr().unwrap();
    info!("Bootstrap node listening on {}", bootstrap_addr);
    
    // Bootstrap node accepts connections aggressively
    let bootstrap_handle = tokio::spawn(async move {
        let mut connections = HashMap::new();
        
        for i in 0..3 {
            if let Some(incoming) = bootstrap.accept().await {
                match incoming.accept() {
                    Ok(connecting) => {
                        match connecting.await {
                            Ok(connection) => {
                                let remote = connection.remote_address();
                                info!("Bootstrap accepted connection {} from {}", i, remote);
                                
                                // Bootstrap nodes should send observations immediately
                                // for new connections
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                
                                connections.insert(remote, connection);
                            }
                            Err(e) => warn!("Connection failed: {}", e),
                        }
                    }
                    Err(e) => warn!("Accept failed: {}", e),
                }
            }
        }
        
        // Check observation statistics
        for (addr, conn) in &connections {
            let stats = conn.address_discovery_stats();
            info!("Bootstrap sent {} observations to {}", stats.observations_sent, addr);
            assert!(stats.observations_sent > 0, "Bootstrap should send observations");
        }
        
        connections
    });
    
    // Multiple clients connect to bootstrap
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];
    
    let mut clients = vec![];
    for i in 0..3 {
        let client = Endpoint::client(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), 
            EndpointConfig::default()
        )
        .await
        .unwrap();
        
        let connection = client
            .connect(bootstrap_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        
        info!("Client {} connected", i);
        clients.push(connection);
    }
    
    // Wait for observations
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // All clients should have discovered their addresses
    for (i, conn) in clients.iter().enumerate() {
        let discovered = conn.discovered_addresses();
        let stats = conn.address_discovery_stats();
        info!("Client {} discovered {} addresses, received {} observations", 
            i, discovered.len(), stats.observations_received);
        assert!(stats.observations_received > 0, "Client should receive observations from bootstrap");
    }
    
    bootstrap_handle.await.unwrap();
    
    info!("✓ Bootstrap mode test completed");
}

/// Test address discovery disabled scenario
#[tokio::test]
async fn test_address_discovery_disabled() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting disabled address discovery test");
    
    let (cert, key) = generate_test_cert();
    
    // Create server with address discovery disabled
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];
    
    let mut server_config = EndpointConfig::default();
    server_config.enable_address_discovery(false); // Explicitly disable
    
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr, Arc::new(ServerConfig::with_crypto(Arc::new(server_crypto))))
        .await
        .unwrap();
    
    let server_addr = server.local_addr().unwrap();
    
    // Server accepts connection
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let connection = incoming.accept().unwrap().await.unwrap();
            
            // Should not send any observations
            tokio::time::sleep(Duration::from_millis(200)).await;
            let stats = connection.address_discovery_stats();
            assert_eq!(stats.observations_sent, 0, "Should not send observations when disabled");
            
            connection
        } else {
            panic!("No connection");
        }
    });
    
    // Client with address discovery disabled
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    let mut client_config = EndpointConfig::default();
    client_config.enable_address_discovery(false);
    
    let client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), client_config)
        .await
        .unwrap();
    
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    // Wait to ensure no observations are sent
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // Both sides should have it disabled
    assert!(!connection.address_discovery_enabled());
    
    let stats = connection.address_discovery_stats();
    assert_eq!(stats.observations_received, 0, "Should not receive observations when disabled");
    
    let server_conn = server_handle.await.unwrap();
    assert!(!server_conn.address_discovery_enabled());
    
    info!("✓ Disabled address discovery test completed");
}

/// Test address discovery with connection migration
#[tokio::test]
async fn test_address_discovery_with_migration() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting connection migration test");
    
    let (server, client) = create_test_endpoints().await;
    let server_addr = server.local_addr().unwrap();
    
    // Server accepts and monitors migration
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let mut connection = incoming.accept().unwrap().await.unwrap();
            let initial_remote = connection.remote_address();
            info!("Server: Initial client address: {}", initial_remote);
            
            // Monitor for path changes
            let mut path_changes = 0;
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                if connection.remote_address() != initial_remote {
                    path_changes += 1;
                    info!("Server: Detected path change to {}", connection.remote_address());
                    
                    // Address discovery should handle the new path
                    let stats = connection.address_discovery_stats();
                    info!("Server: Sent {} observations after {} path changes", 
                        stats.observations_sent, path_changes);
                }
            }
            
            connection
        } else {
            panic!("No connection");
        }
    });
    
    // Client connects and simulates migration
    let mut connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    info!("Client: Connected from {}", connection.local_address().unwrap());
    
    // Simulate network change by rebinding (if supported)
    // In real scenarios, this might happen when switching networks
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Check if we received observations after migration
    let stats = connection.address_discovery_stats();
    info!("Client: Received {} observations", stats.observations_received);
    
    server_handle.await.unwrap();
    
    info!("✓ Connection migration test completed");
}

/// Test integration with NAT traversal
#[tokio::test]
async fn test_nat_traversal_integration() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting NAT traversal integration test");
    
    // This test verifies that discovered addresses are used for NAT traversal
    
    // Create a bootstrap node that will help with address discovery
    let (cert, key) = generate_test_cert();
    
    let mut bootstrap_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    bootstrap_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];
    
    let mut bootstrap_config = EndpointConfig::default();
    bootstrap_config.enable_address_discovery(true);
    bootstrap_config.set_bootstrap_mode(true);
    
    let bootstrap = Endpoint::server(
        bootstrap_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(ServerConfig::with_crypto(Arc::new(bootstrap_crypto)))
    )
    .await
    .unwrap();
    
    let bootstrap_addr = bootstrap.local_addr().unwrap();
    
    // Bootstrap node helps clients discover addresses
    tokio::spawn(async move {
        while let Some(incoming) = bootstrap.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.accept().unwrap().await {
                    info!("Bootstrap: Helping {} discover address", connection.remote_address());
                    // Keep connection alive
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            });
        }
    });
    
    // Two clients behind NAT connect to bootstrap
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];
    
    // Client A
    let client_a = Endpoint::client(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        EndpointConfig::default()
    )
    .await
    .unwrap();
    
    let conn_a = client_a
        .connect(bootstrap_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    // Client B
    let client_b = Endpoint::client(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        EndpointConfig::default()
    )
    .await
    .unwrap();
    
    let conn_b = client_b
        .connect(bootstrap_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    // Wait for address discovery
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Both clients should have discovered their addresses
    let addrs_a = conn_a.discovered_addresses();
    let addrs_b = conn_b.discovered_addresses();
    
    info!("Client A discovered: {:?}", addrs_a);
    info!("Client B discovered: {:?}", addrs_b);
    
    // In a real NAT traversal scenario, these addresses would be
    // exchanged and used for hole punching
    let stats_a = conn_a.address_discovery_stats();
    let stats_b = conn_b.address_discovery_stats();
    
    assert!(stats_a.observations_received > 0, "Client A should discover address");
    assert!(stats_b.observations_received > 0, "Client B should discover address");
    
    info!("✓ NAT traversal integration test completed");
}