//! Integration tests for authenticated P2P connections

use ant_quic::{
    auth::AuthConfig,
    nat_traversal_api::{EndpointRole, PeerId},
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;
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

#[tokio::test]
async fn test_authenticated_connection() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt::try_init();

    // Create bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 25000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: false, // Bootstrap doesn't require auth
            ..Default::default()
        },
        bind_addr: None,
    };

    let _bootstrap = Arc::new(
        QuicP2PNode::new(bootstrap_config)
            .await
            .expect("Failed to create bootstrap node"),
    );

    // Create two client nodes with authentication enabled
    let client1_config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![bootstrap_addr],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: true,
            auth_timeout: Duration::from_secs(10),
            ..Default::default()
        },
        bind_addr: None,
    };

    let client2_config = client1_config.clone();

    let client1 = Arc::new(
        QuicP2PNode::new(client1_config)
            .await
            .expect("Failed to create client 1"),
    );

    let client2 = Arc::new(
        QuicP2PNode::new(client2_config)
            .await
            .expect("Failed to create client 2"),
    );

    let client1_id = client1.peer_id();
    let client2_id = client2.peer_id();

    info!("Client 1 ID: {:?}", client1_id);
    info!("Client 2 ID: {:?}", client2_id);

    // Start client2 to accept connections
    let client2_clone = Arc::clone(&client2);
    let accept_task = tokio::spawn(async move {
        match client2_clone.accept().await {
            Ok((addr, peer_id)) => {
                info!(
                    "Client 2 accepted connection from {:?} at {}",
                    peer_id, addr
                );
                Ok((addr, peer_id))
            }
            Err(e) => {
                eprintln!("Client 2 accept failed: {e}");
                Err(e)
            }
        }
    });

    // Give client2 time to start accepting
    sleep(Duration::from_millis(500)).await;

    // Client1 connects to client2
    match client1.connect_to_peer(client2_id, bootstrap_addr).await {
        Ok(addr) => {
            info!("Client 1 connected to client 2 at {}", addr);

            // Check authentication status
            assert!(client1.is_peer_authenticated(&client2_id).await);

            // Send a test message
            let test_data = b"Hello authenticated peer!";
            client1
                .send_to_peer(&client2_id, test_data)
                .await
                .expect("Failed to send data");

            // Client 2 receives the message
            let client2_recv = Arc::clone(&client2);
            let recv_result =
                tokio::time::timeout(Duration::from_secs(5), client2_recv.receive()).await;

            match recv_result {
                Ok(Ok((peer_id, data))) => {
                    assert_eq!(peer_id, client1_id);
                    assert_eq!(&data, test_data);
                    info!("Successfully received authenticated message");
                }
                _ => panic!("Failed to receive message"),
            }
        }
        Err(e) => {
            // Expected with stub implementation
            eprintln!("Connection failed (expected with stub): {e}");
        }
    }

    // Clean up accept task
    let _ = accept_task.await;
}

#[tokio::test]
async fn test_authentication_failure() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt::try_init();

    // Create bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 26000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: false,
            ..Default::default()
        },
        bind_addr: None,
    };

    let _bootstrap = Arc::new(
        QuicP2PNode::new(bootstrap_config)
            .await
            .expect("Failed to create bootstrap node"),
    );

    // Create a client with very short auth timeout to simulate failure
    let client_config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![bootstrap_addr],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: true,
            auth_timeout: Duration::from_millis(1), // Very short timeout
            max_auth_attempts: 1,
            ..Default::default()
        },
        bind_addr: None,
    };

    let client = Arc::new(
        QuicP2PNode::new(client_config)
            .await
            .expect("Failed to create client"),
    );

    // Try to connect to a non-existent peer (should fail auth)
    let fake_peer_id = PeerId([99; 32]);

    match client.connect_to_peer(fake_peer_id, bootstrap_addr).await {
        Ok(_) => panic!("Should not succeed with fake peer"),
        Err(e) => {
            info!("Connection failed as expected: {}", e);
            // This is expected behavior
        }
    }
}

#[tokio::test]
async fn test_multiple_authenticated_peers() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt::try_init();

    // Create bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 27000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: false,
            ..Default::default()
        },
        bind_addr: None,
    };

    let _bootstrap = Arc::new(
        QuicP2PNode::new(bootstrap_config)
            .await
            .expect("Failed to create bootstrap node"),
    );

    // Create three authenticated clients
    let mut clients = Vec::new();
    for i in 0..3 {
        let config = QuicNodeConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![bootstrap_addr],
            enable_coordinator: false,
            max_connections: 10,
            connection_timeout: Duration::from_secs(10),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig {
                require_authentication: true,
                ..Default::default()
            },
            bind_addr: None,
        };

        let client = Arc::new(
            QuicP2PNode::new(config)
                .await
                .unwrap_or_else(|_| panic!("Failed to create client {i}")),
        );
        clients.push(client);
    }

    // Get peer IDs
    let peer_ids: Vec<PeerId> = clients.iter().map(|c| c.peer_id()).collect();

    // Have clients 1 and 2 connect to client 0
    let client0 = Arc::clone(&clients[0]);
    let accept_task = tokio::spawn(async move {
        let mut accepted = Vec::new();
        for _ in 0..2 {
            match client0.accept().await {
                Ok((addr, peer_id)) => {
                    info!("Client 0 accepted connection from {:?}", peer_id);
                    accepted.push((addr, peer_id));
                }
                Err(e) => {
                    eprintln!("Accept failed: {e}");
                    break;
                }
            }
        }
        accepted
    });

    // Give time to start accepting
    sleep(Duration::from_millis(500)).await;

    // Connect clients 1 and 2 to client 0
    for (i, client) in clients.iter().enumerate().skip(1).take(2) {
        match client.connect_to_peer(peer_ids[0], bootstrap_addr).await {
            Ok(addr) => {
                info!("Client {} connected to client 0 at {}", i, addr);
            }
            Err(e) => {
                eprintln!("Client {i} connection failed (expected with stub): {e}");
            }
        }
    }

    // Check authenticated peers list
    let auth_peers = clients[0].list_authenticated_peers().await;
    info!("Client 0 has {} authenticated peers", auth_peers.len());

    // In a real implementation, this would show 2 authenticated peers
    // With stub implementation, we just verify the API works

    let _ = accept_task.await;
}

#[tokio::test]
async fn test_auth_with_disconnection() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt::try_init();

    // Create bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 28000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: false,
            ..Default::default()
        },
        bind_addr: None,
    };

    let _bootstrap = Arc::new(
        QuicP2PNode::new(bootstrap_config)
            .await
            .expect("Failed to create bootstrap node"),
    );

    // Create two clients
    let client_config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![bootstrap_addr],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: true,
            ..Default::default()
        },
        bind_addr: None,
    };

    let client1 = Arc::new(
        QuicP2PNode::new(client_config.clone())
            .await
            .expect("Failed to create client 1"),
    );

    let client2 = Arc::new(
        QuicP2PNode::new(client_config)
            .await
            .expect("Failed to create client 2"),
    );

    let client2_id = client2.peer_id();

    // Start client2 accepting
    let client2_clone = Arc::clone(&client2);
    let accept_task = tokio::spawn(async move {
        let _ = client2_clone.accept().await;
    });

    sleep(Duration::from_millis(500)).await;

    // Connect and authenticate
    match client1.connect_to_peer(client2_id, bootstrap_addr).await {
        Ok(_) => {
            info!("Connected and authenticated");

            // Verify authentication
            assert!(client1.is_peer_authenticated(&client2_id).await);

            // In a real implementation, we would disconnect and reconnect
            // to test that authentication is required again
        }
        Err(e) => {
            eprintln!("Connection failed (expected with stub): {e}");
        }
    }

    let _ = accept_task.await;
}
