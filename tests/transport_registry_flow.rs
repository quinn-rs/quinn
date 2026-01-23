//! Integration tests for transport registry flow
//!
//! Phase 1.1 TDD: These tests verify that transport providers configured via
//! NodeConfig flow through to P2pEndpoint and are accessible.
//!
//! These tests are designed to FAIL initially because:
//! - P2pConfig doesn't have transport_registry field yet
//! - P2pEndpoint doesn't store the registry yet
//! - P2pEndpoint doesn't have transport_registry() accessor yet
//! - Node::with_config() doesn't pass transport_providers through yet
//!
//! The tests define the acceptance criteria for Phase 1.1 implementation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

// TransportRegistry is used indirectly via build_transport_registry() return type
#[allow(unused_imports)]
use ant_quic::transport::{TransportProvider, TransportRegistry, TransportType, UdpTransport};
use ant_quic::{Node, NodeConfig};
use std::net::SocketAddr;
use std::sync::Arc;

/// Test that transport providers flow from NodeConfig to P2pEndpoint
///
/// This is the main acceptance criteria for Phase 1.1:
/// 1. Create UdpTransport as test provider
/// 2. Build NodeConfig with transport_provider()
/// 3. Create Node with that config
/// 4. Verify P2pEndpoint has access to the registered transport via transport_registry()
#[tokio::test]
async fn test_transport_registry_flows_from_node_config_to_p2p_endpoint() {
    // Step 1: Create a UdpTransport as test provider
    // Bind to a random port on localhost
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = UdpTransport::bind(addr)
        .await
        .expect("Failed to bind UdpTransport");
    let transport_provider: Arc<dyn TransportProvider> = Arc::new(transport);

    // Step 2: Build NodeConfig with transport_provider() method
    // The transport_provider() method already exists on NodeConfig
    let config = NodeConfig::builder()
        .transport_provider(transport_provider.clone())
        .build();

    // Verify the config has the provider
    assert_eq!(
        config.transport_providers.len(),
        1,
        "NodeConfig should have 1 transport provider"
    );

    // Step 3: Call Node::with_config()
    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Step 4: Assert that P2pEndpoint has access to the registered transport
    // This requires P2pEndpoint to have transport_registry() method
    // and the registry to contain our provider.
    //
    // NOTE: This test will FAIL until Phase 1.1 implementation is complete:
    // - Task 2: Add transport_registry to P2pConfig
    // - Task 4: Store TransportRegistry in P2pEndpoint
    // - Task 6: Wire Node::with_config to pass registry

    // Get transport registry from Node (requires transport_registry() method on Node/P2pEndpoint)
    let registry = node.transport_registry();
    assert!(
        !registry.is_empty(),
        "Registry should not be empty after wiring"
    );
    assert_eq!(registry.len(), 1, "Registry should have 1 provider");

    let udp_providers = registry.providers_by_type(TransportType::Udp);
    assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");

    // Cleanup
    node.shutdown().await;
}

/// Test that multiple transport providers can be registered
#[tokio::test]
async fn test_multiple_transport_providers_flow() {
    // Create two UDP transports (different ports)
    let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let transport1 = UdpTransport::bind(addr1)
        .await
        .expect("Failed to bind transport 1");
    let transport2 = UdpTransport::bind(addr2)
        .await
        .expect("Failed to bind transport 2");

    let provider1: Arc<dyn TransportProvider> = Arc::new(transport1);
    let provider2: Arc<dyn TransportProvider> = Arc::new(transport2);

    // Build config with multiple providers
    let config = NodeConfig::builder()
        .transport_provider(provider1.clone())
        .transport_provider(provider2.clone())
        .build();

    assert_eq!(
        config.transport_providers.len(),
        2,
        "NodeConfig should have 2 transport providers"
    );

    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Verify both providers are in the registry
    let registry = node.transport_registry();
    assert_eq!(registry.len(), 2, "Registry should have 2 providers");

    node.shutdown().await;
}

/// Test that NodeConfig::build_transport_registry() creates correct registry
#[tokio::test]
async fn test_build_transport_registry_helper() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = UdpTransport::bind(addr).await.expect("Failed to bind");
    let provider: Arc<dyn TransportProvider> = Arc::new(transport);

    let config = NodeConfig::builder()
        .transport_provider(provider.clone())
        .build();

    // The build_transport_registry method already exists
    let registry = config.build_transport_registry();

    assert_eq!(registry.len(), 1, "Registry should have 1 provider");

    let udp_providers = registry.providers_by_type(TransportType::Udp);
    assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
}

/// Test that default NodeConfig results in empty transport registry
#[tokio::test]
async fn test_default_config_empty_registry() {
    let config = NodeConfig::default();

    assert!(
        config.transport_providers.is_empty(),
        "Default config should have no transport providers"
    );

    let registry = config.build_transport_registry();
    assert!(registry.is_empty(), "Default registry should be empty");
}
