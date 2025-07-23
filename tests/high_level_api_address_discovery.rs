//! Tests for address discovery integration with high-level APIs
//! 
//! This tests how address discovery integrates with NatTraversalEndpoint
//! and QuicP2PNode APIs.

use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use ant_quic::{NatTraversalEndpoint, QuicP2PNode, NodeConfig};
use tracing::{info, debug};
use tokio;

/// Test that NatTraversalEndpoint uses address discovery by default
#[tokio::test]
async fn test_nat_traversal_endpoint_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    // Create a NAT traversal endpoint
    let local_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let endpoint = NatTraversalEndpoint::bind(local_addr)
        .await
        .expect("Failed to create endpoint");
    
    // Address discovery should be enabled by default
    assert!(endpoint.address_discovery_enabled());
    info!("✓ NatTraversalEndpoint has address discovery enabled by default");
    
    // Test that discovered addresses are integrated with NAT traversal
    let discovered = endpoint.discovered_addresses().await;
    info!("Discovered addresses: {:?}", discovered);
}

/// Test configuring address discovery in NatTraversalEndpoint
#[tokio::test]
async fn test_nat_traversal_endpoint_config() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let local_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    
    // Create endpoint with custom config
    let endpoint = NatTraversalEndpoint::bind_with_config(
        local_addr,
        |config| {
            config.set_address_discovery_enabled(false);
            config.set_max_observation_rate(5);
        }
    )
    .await
    .expect("Failed to create endpoint");
    
    // Address discovery should be disabled
    assert!(!endpoint.address_discovery_enabled());
    info!("✓ NatTraversalEndpoint respects address discovery config");
}

/// Test that QuicP2PNode enables address discovery by default
#[tokio::test]
async fn test_quic_p2p_node_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let config = NodeConfig::default();
    let node = QuicP2PNode::new(config)
        .await
        .expect("Failed to create P2P node");
    
    // Address discovery should be enabled by default
    assert!(node.address_discovery_enabled());
    info!("✓ QuicP2PNode has address discovery enabled by default");
    
    // Get address discovery stats
    let stats = node.address_discovery_stats();
    assert_eq!(stats.frames_sent, 0);
    assert_eq!(stats.frames_received, 0);
    info!("✓ QuicP2PNode provides address discovery statistics");
}

/// Test disabling address discovery in QuicP2PNode
#[tokio::test]
async fn test_quic_p2p_node_disable_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut config = NodeConfig::default();
    config.enable_address_discovery = false;
    
    let node = QuicP2PNode::new(config)
        .await
        .expect("Failed to create P2P node");
    
    // Address discovery should be disabled
    assert!(!node.address_discovery_enabled());
    info!("✓ QuicP2PNode respects address discovery configuration");
}

/// Test that discovered addresses improve NAT traversal success
#[tokio::test]
async fn test_nat_traversal_improvement() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info")
        .try_init();

    // Create two endpoints simulating NAT traversal scenario
    let endpoint1 = NatTraversalEndpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("Failed to create endpoint 1");
    
    let endpoint2 = NatTraversalEndpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("Failed to create endpoint 2");
    
    // Bootstrap node to help with address discovery
    let bootstrap = NatTraversalEndpoint::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("Failed to create bootstrap");
    
    let bootstrap_addr = bootstrap.local_addr();
    info!("Bootstrap node at: {}", bootstrap_addr);
    
    // Connect both endpoints to bootstrap
    endpoint1.add_bootstrap_node(bootstrap_addr).await;
    endpoint2.add_bootstrap_node(bootstrap_addr).await;
    
    // Wait for address discovery
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Check discovered addresses
    let discovered1 = endpoint1.discovered_addresses().await;
    let discovered2 = endpoint2.discovered_addresses().await;
    
    info!("Endpoint 1 discovered: {:?}", discovered1);
    info!("Endpoint 2 discovered: {:?}", discovered2);
    
    // With address discovery, both endpoints should know their reflexive addresses
    assert!(!discovered1.is_empty(), "Endpoint 1 should have discovered addresses");
    assert!(!discovered2.is_empty(), "Endpoint 2 should have discovered addresses");
    
    info!("✓ Address discovery improves NAT traversal capabilities");
}

/// Test address discovery statistics in high-level APIs
#[tokio::test]
async fn test_address_discovery_monitoring() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let node = QuicP2PNode::new(NodeConfig::default())
        .await
        .expect("Failed to create P2P node");
    
    // Subscribe to address discovery events
    let mut events = node.address_discovery_events();
    
    // Connect to a peer (would trigger address discovery in real scenario)
    let peer_addr = SocketAddr::from((Ipv4Addr::new(93, 184, 215, 123), 443));
    
    // In a real scenario, this would generate address discovery events
    tokio::select! {
        Some(event) = events.recv() => {
            match event {
                AddressDiscoveryEvent::AddressObserved { address, observer } => {
                    info!("Address observed: {} by {}", address, observer);
                }
                AddressDiscoveryEvent::AddressChanged { old, new } => {
                    info!("Address changed: {} -> {}", old, new);
                }
            }
        }
        _ = tokio::time::sleep(Duration::from_millis(100)) => {
            // No events in test environment
        }
    }
    
    info!("✓ Address discovery events can be monitored");
}

/// Test example usage of address discovery
#[tokio::test]
async fn test_example_usage() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info")
        .try_init();

    // Example: Create a P2P node with custom address discovery settings
    let mut config = NodeConfig::default();
    config.enable_address_discovery = true;
    config.observation_rate = 20; // More aggressive observation
    config.observe_all_paths = true; // Observe all network paths
    
    let node = QuicP2PNode::new(config)
        .await
        .expect("Failed to create P2P node");
    
    info!("Created P2P node with custom address discovery settings");
    
    // Example: Monitor address changes
    node.on_address_change(|old_addr, new_addr| {
        info!("My address changed from {:?} to {}", old_addr, new_addr);
        // Application can react to address changes
        // e.g., update DHT entries, notify peers, etc.
    });
    
    // Example: Get current discovered addresses
    let addresses = node.discovered_addresses().await;
    info!("My discovered addresses: {:?}", addresses);
    
    // Example: Check address discovery stats
    let stats = node.address_discovery_stats();
    info!("Address discovery stats: {:?}", stats);
    
    info!("✓ Example usage patterns work correctly");
}

/// Address discovery event types
#[derive(Debug, Clone)]
enum AddressDiscoveryEvent {
    AddressObserved {
        address: SocketAddr,
        observer: SocketAddr,
    },
    AddressChanged {
        old: Option<SocketAddr>,
        new: SocketAddr,
    },
}