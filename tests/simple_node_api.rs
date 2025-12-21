//! Simple Node API Integration Tests
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.
//!
//! Tests for the zero-config `Node` API introduced in v0.14.0.
//!
//! This test suite validates:
//! - Zero-configuration node creation
//! - Various constructor methods (new, bind, with_peers, with_config)
//! - Status observability (NodeStatus)
//! - Event subscription (NodeEvent)
//! - Basic connectivity

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair;
use ant_quic::{NatType, Node, NodeConfig, NodeStatus};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

// ============================================================================
// Zero-Config Node Creation Tests
// ============================================================================

mod zero_config_tests {
    use super::*;

    #[tokio::test]
    async fn test_node_new_zero_config() {
        // The primary goal: create a node with ZERO configuration
        let node = Node::new().await.expect("Node::new() should succeed");

        // Verify it has a valid local address
        let local_addr = node.local_addr().expect("Should have local address");
        assert!(local_addr.port() > 0, "Node should bind to a valid port");
        println!("Zero-config node listening on: {}", local_addr);

        // Verify it has a peer ID
        let peer_id = node.peer_id();
        println!("Zero-config node peer ID: {:?}", peer_id);

        // Verify it has a public key (PeerId is 32-byte SHA256 hash of ML-DSA-65 public key)
        let public_key = node.public_key_bytes();
        assert_eq!(public_key.len(), 32, "PeerId should be 32 bytes");

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_bind_specific_addr() {
        let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0); // Random port on localhost

        let node = Node::bind(bind_addr)
            .await
            .expect("Node::bind() should succeed");

        let local_addr = node.local_addr().expect("Should have local address");
        assert_eq!(
            local_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "Should bind to localhost"
        );
        println!("Node bound to: {}", local_addr);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_peers() {
        // First create a node bound to localhost (so address is connectable)
        let node1 = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("First node should succeed");
        let node1_addr = node1.local_addr().expect("Should have address");
        println!("First node at: {}", node1_addr);

        // Create second node with known peer
        let node2 = Node::with_peers(vec![node1_addr])
            .await
            .expect("Node::with_peers() should succeed");

        let node2_addr = node2.local_addr().expect("Should have address");
        println!("Second node at: {}", node2_addr);
        println!("Second node peer ID: {:?}", node2.peer_id());

        // Peer IDs should be different
        assert_ne!(
            node1.peer_id(),
            node2.peer_id(),
            "Nodes should have different peer IDs"
        );

        node1.shutdown().await;
        node2.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_keypair_api() {
        // Test that the with_keypair API works with ML-DSA-65 keys
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Create node with the ML-DSA-65 keypair
        let node = Node::with_keypair(public_key, secret_key)
            .await
            .expect("Node::with_keypair() should succeed");

        // Node should have a valid address and key
        let local_addr = node.local_addr().expect("Should have address");
        let public_key_bytes = node.public_key_bytes();

        println!("Node with keypair at: {}", local_addr);
        println!("Public key (peer ID): {}", hex::encode(public_key_bytes));

        // PeerId is 32-byte SHA256 hash of ML-DSA-65 public key
        assert_eq!(public_key_bytes.len(), 32);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_config() {
        let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let config = NodeConfig::builder().bind_addr(bind_addr).build();

        let node = Node::with_config(config)
            .await
            .expect("Node::with_config() should succeed");

        let local_addr = node.local_addr().expect("Should have address");
        assert_eq!(
            local_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "Should use config bind address"
        );

        node.shutdown().await;
    }
}

// ============================================================================
// NodeStatus Observability Tests
// ============================================================================

mod status_tests {
    use super::*;

    #[tokio::test]
    async fn test_node_status_basic_fields() {
        let node = Node::new().await.expect("Node should create");
        let local_addr = node.local_addr().expect("Should have address");

        // Get status
        let status: NodeStatus = node.status().await;

        // Verify basic identity fields
        assert_eq!(
            status.peer_id,
            node.peer_id(),
            "Status peer_id should match"
        );
        assert_eq!(
            status.local_addr, local_addr,
            "Status local_addr should match"
        );

        // NAT type starts unknown
        assert_eq!(
            status.nat_type,
            NatType::Unknown,
            "NAT type should be unknown initially"
        );

        println!("NodeStatus:");
        println!("  peer_id: {:?}", status.peer_id);
        println!("  local_addr: {}", status.local_addr);
        println!("  nat_type: {:?}", status.nat_type);
        println!("  can_receive_direct: {}", status.can_receive_direct);
        println!("  connected_peers: {}", status.connected_peers);
        println!("  is_relaying: {}", status.is_relaying);
        println!("  is_coordinating: {}", status.is_coordinating);
        println!("  uptime: {:?}", status.uptime);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status_relay_fields() {
        let node = Node::new().await.expect("Node should create");
        let status = node.status().await;

        // Relay fields should be accessible
        println!("Relay status:");
        println!("  is_relaying: {}", status.is_relaying);
        println!("  relay_sessions: {}", status.relay_sessions);
        println!("  relay_bytes_forwarded: {}", status.relay_bytes_forwarded);

        // Initially, node shouldn't be relaying
        assert_eq!(status.relay_sessions, 0, "No relay sessions initially");

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status_coordinator_fields() {
        let node = Node::new().await.expect("Node should create");
        let status = node.status().await;

        // Coordinator fields should be accessible
        println!("Coordinator status:");
        println!("  is_coordinating: {}", status.is_coordinating);
        println!("  coordination_sessions: {}", status.coordination_sessions);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status_uptime() {
        let node = Node::new().await.expect("Node should create");

        // Get initial status
        let status1 = node.status().await;
        let uptime1 = status1.uptime;

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Get status again
        let status2 = node.status().await;
        let uptime2 = status2.uptime;

        // Uptime should have increased
        assert!(uptime2 > uptime1, "Uptime should increase over time");
        println!("Uptime increased: {:?} -> {:?}", uptime1, uptime2);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status_helper_methods() {
        let node = Node::new().await.expect("Node should create");
        let status = node.status().await;

        // Test helper methods
        let is_connected = status.is_connected();
        let can_help = status.can_help_traversal();
        let total_conns = status.total_connections();
        let direct_rate = status.direct_rate();

        println!("NodeStatus helpers:");
        println!("  is_connected(): {}", is_connected);
        println!("  can_help_traversal(): {}", can_help);
        println!("  total_connections(): {}", total_conns);
        println!("  direct_rate(): {}", direct_rate);

        // Initially not connected
        assert!(!is_connected, "No connections initially");
        assert_eq!(total_conns, 0, "No connections initially");

        node.shutdown().await;
    }
}

// ============================================================================
// NodeEvent Subscription Tests
// ============================================================================

mod event_tests {
    use super::*;

    #[tokio::test]
    async fn test_node_subscribe() {
        let node = Node::new().await.expect("Node should create");

        // Subscribe to events
        let mut events = node.subscribe();
        println!("Subscribed to events");

        // Events channel should be valid
        // (In real usage, events would arrive from connections)

        // Clean shutdown
        node.shutdown().await;

        // Channel should close after shutdown
        let recv_result = events.try_recv();
        println!("After shutdown, recv result: {:?}", recv_result);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let node = Node::new().await.expect("Node should create");

        // Multiple subscribers should work
        let _sub1 = node.subscribe();
        let _sub2 = node.subscribe();
        let _sub3 = node.subscribe();

        println!("Created 3 event subscribers");

        node.shutdown().await;
    }
}

// ============================================================================
// Connection Tests
// ============================================================================

mod connection_tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_addr_method_exists() {
        // This test validates the connect_addr API exists and can be called
        // Actual connectivity is tested in E2E tests with proper network setup
        let node = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("Node should create");

        let target_addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();

        // Try to connect with a very short timeout - will fail since no one is listening
        // but this validates the API works
        let result = timeout(Duration::from_millis(100), node.connect_addr(target_addr)).await;

        // Either timeout or connection error is expected (no listener at that address)
        match result {
            Ok(Ok(_)) => println!("Unexpectedly connected"),
            Ok(Err(e)) => println!("Connection error (expected): {}", e),
            Err(_) => println!("Timeout (expected)"),
        }

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_accept_method_exists() {
        // This test validates the accept API exists and can be called
        let node = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("Node should create");

        // Try to accept with a very short timeout
        let result = timeout(Duration::from_millis(50), node.accept()).await;

        // Timeout expected - no one is connecting
        assert!(
            result.is_err(),
            "Should timeout with no incoming connections"
        );
        println!("Accept correctly timed out with no connections");

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_add_peer_dynamically() {
        // Create two nodes on localhost
        let node1 = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("Node 1 should create");
        let node2 = Node::new().await.expect("Node 2 should create");

        let node1_addr = node1.local_addr().expect("Should have address");

        // Dynamically add node1 as peer of node2
        let _ = node2.add_peer(node1_addr).await;
        println!("Added {} as known peer", node1_addr);

        // Get connected peers (should be empty until actual connection)
        let peers = node2.connected_peers().await;
        println!("Connected peers: {:?}", peers);

        node1.shutdown().await;
        node2.shutdown().await;
    }
}

// ============================================================================
// Three-Node Network Tests
// ============================================================================

mod three_node_tests {
    use super::*;

    #[tokio::test]
    async fn test_three_node_creation() {
        println!("=== Three Node Simple API Test ===");

        // Create three nodes with zero configuration
        let node1 = Node::new().await.expect("Node 1 should create");
        let node2 = Node::new().await.expect("Node 2 should create");
        let node3 = Node::new().await.expect("Node 3 should create");

        let addr1 = node1.local_addr().expect("Should have address");
        let addr2 = node2.local_addr().expect("Should have address");
        let addr3 = node3.local_addr().expect("Should have address");

        println!("Node 1: {} -> {:?}", addr1, node1.peer_id());
        println!("Node 2: {} -> {:?}", addr2, node2.peer_id());
        println!("Node 3: {} -> {:?}", addr3, node3.peer_id());

        // Verify all peer IDs are unique
        let mut peer_ids = HashSet::new();
        peer_ids.insert(node1.peer_id());
        peer_ids.insert(node2.peer_id());
        peer_ids.insert(node3.peer_id());
        assert_eq!(peer_ids.len(), 3, "All nodes should have unique peer IDs");

        // Verify all addresses are unique
        let mut addrs = HashSet::new();
        addrs.insert(addr1);
        addrs.insert(addr2);
        addrs.insert(addr3);
        assert_eq!(addrs.len(), 3, "All nodes should have unique addresses");

        node1.shutdown().await;
        node2.shutdown().await;
        node3.shutdown().await;

        println!("=== Three Node Test Complete ===");
    }

    #[tokio::test]
    async fn test_three_node_status_comparison() {
        let node1 = Node::new().await.expect("Node 1 should create");
        let node2 = Node::new().await.expect("Node 2 should create");
        let node3 = Node::new().await.expect("Node 3 should create");

        let status1 = node1.status().await;
        let status2 = node2.status().await;
        let status3 = node3.status().await;

        println!("Status comparison:");
        println!(
            "  Node 1: nat={:?}, peers={}",
            status1.nat_type, status1.connected_peers
        );
        println!(
            "  Node 2: nat={:?}, peers={}",
            status2.nat_type, status2.connected_peers
        );
        println!(
            "  Node 3: nat={:?}, peers={}",
            status3.nat_type, status3.connected_peers
        );

        // All should start with unknown NAT
        assert_eq!(status1.nat_type, NatType::Unknown);
        assert_eq!(status2.nat_type, NatType::Unknown);
        assert_eq!(status3.nat_type, NatType::Unknown);

        node1.shutdown().await;
        node2.shutdown().await;
        node3.shutdown().await;
    }
}

// ============================================================================
// Config Builder Tests
// ============================================================================

mod config_tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = NodeConfig::default();
        assert!(config.bind_addr.is_none());
        assert!(config.known_peers.is_empty());
        assert!(config.keypair.is_none());
    }

    #[test]
    fn test_config_builder_bind_addr() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let config = NodeConfig::builder().bind_addr(addr).build();

        assert_eq!(config.bind_addr, Some(addr));
    }

    #[test]
    fn test_config_builder_known_peers() {
        let peer1: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let peer2: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let config = NodeConfig::builder()
            .known_peer(peer1)
            .known_peer(peer2)
            .build();

        assert_eq!(config.known_peers.len(), 2);
        assert!(config.known_peers.contains(&peer1));
        assert!(config.known_peers.contains(&peer2));
    }

    #[test]
    fn test_config_builder_full() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let peer: SocketAddr = "1.2.3.4:9000".parse().unwrap();
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

        let config = NodeConfig::builder()
            .bind_addr(addr)
            .known_peer(peer)
            .keypair(public_key, secret_key)
            .build();

        assert_eq!(config.bind_addr, Some(addr));
        assert_eq!(config.known_peers.len(), 1);
        assert!(config.keypair.is_some());
    }

    #[test]
    fn test_config_with_constructors() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let config1 = NodeConfig::with_bind_addr(addr);
        assert_eq!(config1.bind_addr, Some(addr));

        let peers = vec![
            "127.0.0.1:9000".parse().unwrap(),
            "127.0.0.1:9001".parse().unwrap(),
        ];
        let config2 = NodeConfig::with_known_peers(peers.clone());
        assert_eq!(config2.known_peers, peers);
    }
}

// ============================================================================
// NatType Tests
// ============================================================================

mod nat_type_tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(format!("{}", NatType::None), "None (Public IP)");
        assert_eq!(format!("{}", NatType::FullCone), "Full Cone");
        assert_eq!(
            format!("{}", NatType::AddressRestricted),
            "Address Restricted"
        );
        assert_eq!(format!("{}", NatType::PortRestricted), "Port Restricted");
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric");
        assert_eq!(format!("{}", NatType::Unknown), "Unknown");
    }

    #[test]
    fn test_nat_type_default() {
        assert_eq!(NatType::default(), NatType::Unknown);
    }

    #[test]
    fn test_nat_type_equality() {
        assert_eq!(NatType::FullCone, NatType::FullCone);
        assert_ne!(NatType::FullCone, NatType::Symmetric);
    }
}

// ============================================================================
// Integration Summary
// ============================================================================

#[tokio::test]
async fn test_simple_api_integration_summary() {
    println!("\n=== Simple Node API Integration Summary ===\n");

    // 1. Zero-config creation
    println!("1. Zero-config node creation...");
    let node = Node::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("Node::bind() failed");
    let local_addr = node.local_addr().expect("Should have address");
    println!("   Success: {} / {:?}", local_addr, node.peer_id());

    // 2. Status observability
    println!("\n2. Status observability...");
    let status = node.status().await;
    println!("   NAT type: {:?}", status.nat_type);
    println!("   Can receive direct: {}", status.can_receive_direct);
    println!("   Is relaying: {}", status.is_relaying);
    println!("   Uptime: {:?}", status.uptime);

    // 3. Event subscription
    println!("\n3. Event subscription...");
    let _events = node.subscribe();
    println!("   Subscribed to NodeEvent broadcast");

    // 4. Config builder
    println!("\n4. Config builder...");
    let config = NodeConfig::builder()
        .known_peer("127.0.0.1:9000".parse().unwrap())
        .build();
    println!(
        "   Built config with {} known peers",
        config.known_peers.len()
    );

    // 5. Second node with config
    println!("\n5. Node with known peer...");
    let config2 = NodeConfig::builder().known_peer(local_addr).build();
    let node2 = Node::with_config(config2)
        .await
        .expect("Node::with_config() failed");
    let node2_addr = node2.local_addr().expect("Should have address");
    println!("   Second node: {} / {:?}", node2_addr, node2.peer_id());

    // Cleanup
    node.shutdown().await;
    node2.shutdown().await;

    println!("\n=== Simple API Tests Complete ===\n");
}
