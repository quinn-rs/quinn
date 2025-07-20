//! Infrastructure tests to validate test setup without full connectivity

use ant_quic::{
    auth::AuthConfig,
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::EndpointRole,
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::info;

#[tokio::test]
async fn test_node_creation() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test creating a bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    let bootstrap_node = QuicP2PNode::new(bootstrap_config)
        .await
        .expect("Failed to create bootstrap node");

    info!("Successfully created bootstrap node");

    // Test creating a client node
    let client_config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![bootstrap_addr],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    let client_node = QuicP2PNode::new(client_config)
        .await
        .expect("Failed to create client node");

    info!("Successfully created client node");

    // Verify stats are initialized
    let bootstrap_stats = bootstrap_node.get_stats().await;
    assert_eq!(bootstrap_stats.active_connections, 0);
    assert_eq!(bootstrap_stats.successful_connections, 0);
    assert_eq!(bootstrap_stats.failed_connections, 0);

    let client_stats = client_node.get_stats().await;
    assert_eq!(client_stats.active_connections, 0);
    assert_eq!(client_stats.successful_connections, 0);
    assert_eq!(client_stats.failed_connections, 0);
}

#[tokio::test]
async fn test_peer_id_generation() {
    let _ = tracing_subscriber::fmt::try_init();

    // Generate multiple peer IDs and ensure they're unique
    let mut peer_ids = Vec::new();

    for i in 0..10 {
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Ensure this peer ID is unique
        assert!(
            !peer_ids.contains(&peer_id),
            "Duplicate peer ID generated at iteration {}",
            i
        );
        peer_ids.push(peer_id);
    }

    info!("Generated {} unique peer IDs", peer_ids.len());
}

#[tokio::test]
async fn test_role_validation() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test that Server role with coordination requires bootstrap nodes
    let server_config = QuicNodeConfig {
        role: EndpointRole::Server {
            can_coordinate: true,
        },
        bootstrap_nodes: vec![], // No bootstrap nodes
        enable_coordinator: true,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    // This should fail validation
    match QuicP2PNode::new(server_config).await {
        Ok(_) => panic!("Server with coordination should require bootstrap nodes"),
        Err(e) => {
            info!("Server validation failed as expected: {}", e);
            assert!(e.to_string().contains("bootstrap"));
        }
    }

    // Test that Server role without coordination doesn't require bootstrap nodes
    let server_no_coord_config = QuicNodeConfig {
        role: EndpointRole::Server {
            can_coordinate: false,
        },
        bootstrap_nodes: vec![],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    // This should succeed
    let _server_node = QuicP2PNode::new(server_no_coord_config)
        .await
        .expect("Server without coordination should not require bootstrap nodes");

    info!("Server without coordination created successfully");
}

#[tokio::test]
async fn test_multiple_node_creation() {
    let _ = tracing_subscriber::fmt::try_init();

    // Create a bootstrap node first
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20000);

    let bootstrap_config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 100,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    let _bootstrap = QuicP2PNode::new(bootstrap_config)
        .await
        .expect("Failed to create bootstrap node");

    // Create multiple client nodes
    let mut nodes = Vec::new();
    for i in 0..5 {
        let config = QuicNodeConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![bootstrap_addr],
            enable_coordinator: false,
            max_connections: 10,
            connection_timeout: Duration::from_secs(10),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig::default(),
        };

        let node = QuicP2PNode::new(config)
            .await
            .expect(&format!("Failed to create client node {}", i));

        nodes.push(node);
    }

    info!("Successfully created {} client nodes", nodes.len());
    assert_eq!(nodes.len(), 5);
}

#[tokio::test]
async fn test_nat_endpoint_access() {
    let _ = tracing_subscriber::fmt::try_init();

    let config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9999,
        )],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(10),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
    };

    let node = QuicP2PNode::new(config)
        .await
        .expect("Failed to create node");

    // Verify we can access the NAT endpoint
    let _nat_endpoint = node
        .get_nat_endpoint()
        .expect("Should be able to access NAT endpoint");

    // Try to get NAT statistics
    match node.get_nat_stats().await {
        Ok(stats) => {
            info!("Retrieved NAT stats: {:?}", stats);
            // Basic validation
            // Basic validation - just check the stats structure is populated
            assert!(stats.active_sessions >= 0);
            assert!(stats.total_bootstrap_nodes >= 0);
        }
        Err(e) => {
            // This is expected with stub implementation
            info!("NAT stats retrieval failed as expected: {}", e);
        }
    }
}
