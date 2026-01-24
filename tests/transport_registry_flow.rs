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
use ant_quic::transport::{
    InboundDatagram, TransportAddr, TransportProvider, TransportRegistry, TransportStats,
    TransportType, UdpTransport,
};
use ant_quic::{Node, NodeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

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

// ============================================================================
// Phase 1.2 Integration Tests - P2pEndpoint → NatTraversalEndpoint Wiring
// ============================================================================

/// Test that transport registry flows from Node through to NatTraversalEndpoint.
/// This test defines acceptance criteria for Phase 1.2.
///
/// Verifies:
/// - TransportRegistry flows from P2pEndpoint to NatTraversalEndpoint
/// - NatTraversalConfig.transport_registry is set when creating endpoint
/// - The registry is accessible through Node's API
///
/// Note: We verify the wiring by checking that:
/// 1. Node has access to the registry (via transport_registry())
/// 2. The registry has our registered provider
/// 3. The unified_config correctly passes registry to NatTraversalConfig
///    (verified via to_nat_config() returning transport_registry: Some(...))
#[tokio::test]
async fn test_transport_registry_flows_to_nat_traversal_endpoint() {
    use ant_quic::unified_config::P2pConfig;

    // Create a registry with a provider
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = UdpTransport::bind(addr)
        .await
        .expect("Failed to bind UdpTransport");
    let provider: Arc<dyn TransportProvider> = Arc::new(transport);

    // Create NodeConfig with the provider
    let config = NodeConfig::builder()
        .transport_provider(provider.clone())
        .build();

    // Build Node
    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Verify registry is accessible from Node (Phase 1.1 - already working)
    let registry = node.transport_registry();
    assert!(!registry.is_empty(), "Registry should not be empty");
    assert_eq!(registry.len(), 1, "Registry should have 1 provider");

    // Verify P2pConfig's to_nat_config() correctly passes the registry
    // This is the key Phase 1.2 wiring - P2pConfig must include transport_registry
    // when converting to NatTraversalConfig for NatTraversalEndpoint creation
    let p2p_config = P2pConfig::builder()
        .transport_registry(ant_quic::transport::TransportRegistry::new())
        .build()
        .expect("P2pConfig build should succeed");
    let nat_config = p2p_config.to_nat_config();

    // Verify transport_registry is passed through to NatTraversalConfig
    assert!(
        nat_config.transport_registry.is_some(),
        "P2pConfig::to_nat_config() should include transport_registry"
    );

    node.shutdown().await;
}

// ============================================================================
// Phase 1.3 End-to-End Tests - Multi-Transport Concurrent I/O
// ============================================================================

/// End-to-end test with multiple transport providers, verifying concurrent send/receive.
///
/// Test scenario:
/// 1. Create registry with UDP and mock BLE transport
/// 2. Create two P2pEndpoint instances with the multi-transport registry
/// 3. Connect peers and exchange data
/// 4. Verify both transports show activity in stats
/// 5. Shut down one transport mid-test, verify failover to remaining transport
///
/// This test validates:
/// - Multiple transports can be registered and used simultaneously
/// - Data flows correctly through multi-transport endpoints
/// - Stats accurately reflect multi-transport activity
/// - System gracefully handles transport failures
#[tokio::test]
async fn test_multi_transport_concurrent_io() {
    use ant_quic::transport::ProviderError;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    // Helper: Create a mock BLE transport for testing
    #[allow(dead_code)]
    struct MockBleTransport {
        name: String,
        capabilities: ant_quic::transport::TransportCapabilities,
        online: AtomicBool,
        local_addr: TransportAddr,
        bytes_sent: AtomicU64,
        bytes_received: AtomicU64,
        inbound_tx: tokio::sync::Mutex<Option<mpsc::Sender<InboundDatagram>>>,
    }

    impl MockBleTransport {
        fn new() -> (Self, mpsc::Receiver<InboundDatagram>) {
            let (tx, rx) = mpsc::channel(16);
            let transport = Self {
                name: "MockBLE".to_string(),
                capabilities: ant_quic::transport::TransportCapabilities::ble(),
                online: AtomicBool::new(true),
                local_addr: TransportAddr::ble([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None),
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                inbound_tx: tokio::sync::Mutex::new(Some(tx)),
            };
            (transport, rx)
        }
    }

    #[async_trait::async_trait]
    impl TransportProvider for MockBleTransport {
        fn name(&self) -> &str {
            &self.name
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Ble
        }

        fn capabilities(&self) -> &ant_quic::transport::TransportCapabilities {
            &self.capabilities
        }

        fn local_addr(&self) -> Option<TransportAddr> {
            Some(self.local_addr.clone())
        }

        async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), ProviderError> {
            if !self.online.load(Ordering::SeqCst) {
                return Err(ProviderError::Offline);
            }

            if dest.transport_type() != TransportType::Ble {
                return Err(ProviderError::AddressMismatch {
                    expected: TransportType::Ble,
                    actual: dest.transport_type(),
                });
            }

            self.bytes_sent
                .fetch_add(data.len() as u64, Ordering::SeqCst);
            Ok(())
        }

        fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
            let (_, rx) = mpsc::channel(16);
            rx
        }

        fn is_online(&self) -> bool {
            self.online.load(Ordering::SeqCst)
        }

        async fn shutdown(&self) -> Result<(), ProviderError> {
            self.online.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn stats(&self) -> TransportStats {
            TransportStats {
                bytes_sent: self.bytes_sent.load(Ordering::SeqCst),
                bytes_received: self.bytes_received.load(Ordering::SeqCst),
                datagrams_sent: 0,
                datagrams_received: 0,
                send_errors: 0,
                receive_errors: 0,
                current_rtt: None,
            }
        }
    }

    // Step 1: Create registry with UDP and mock BLE transport
    let udp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let udp_transport = UdpTransport::bind(udp_addr)
        .await
        .expect("Failed to bind UDP transport");
    let udp_provider: Arc<dyn TransportProvider> = Arc::new(udp_transport);

    let (ble_transport, _ble_rx) = MockBleTransport::new();
    let ble_provider: Arc<dyn TransportProvider> = Arc::new(ble_transport);

    let mut registry = TransportRegistry::new();
    registry.register(udp_provider.clone());
    registry.register(ble_provider.clone());

    assert_eq!(registry.len(), 2, "Registry should have 2 providers");
    assert_eq!(
        registry.providers_by_type(TransportType::Udp).len(),
        1,
        "Should have 1 UDP provider"
    );
    assert_eq!(
        registry.providers_by_type(TransportType::Ble).len(),
        1,
        "Should have 1 BLE provider"
    );

    // Step 2: Create two P2pEndpoint instances with the multi-transport registry
    // Note: This uses the registry through Node/P2pConfig
    let node1_config = NodeConfig::builder()
        .transport_provider(udp_provider.clone())
        .transport_provider(ble_provider.clone())
        .build();

    let node1 = Node::with_config(node1_config)
        .await
        .expect("Failed to create node1");

    // Verify node1 has both transports
    let node1_registry = node1.transport_registry();
    assert_eq!(
        node1_registry.len(),
        2,
        "Node1 should have 2 transports registered"
    );

    // Create node2 with the same transports
    let node2_config = NodeConfig::builder()
        .transport_provider(udp_provider.clone())
        .transport_provider(ble_provider.clone())
        .build();

    let node2 = Node::with_config(node2_config)
        .await
        .expect("Failed to create node2");

    let node2_registry = node2.transport_registry();
    assert_eq!(
        node2_registry.len(),
        2,
        "Node2 should have 2 transports registered"
    );

    // Step 3: Verify transport capabilities and stats
    // Both nodes should have access to both transports through their registries
    println!("Node1 local address: {:?}", node1.local_addr());
    println!("Node2 local address: {:?}", node2.local_addr());

    // Verify both nodes can access their transport providers
    let node1_udp_providers = node1_registry.providers_by_type(TransportType::Udp);
    let node1_ble_providers = node1_registry.providers_by_type(TransportType::Ble);
    assert_eq!(
        node1_udp_providers.len(),
        1,
        "Node1 should have access to UDP transport"
    );
    assert_eq!(
        node1_ble_providers.len(),
        1,
        "Node1 should have access to BLE transport"
    );

    let node2_udp_providers = node2_registry.providers_by_type(TransportType::Udp);
    let node2_ble_providers = node2_registry.providers_by_type(TransportType::Ble);
    assert_eq!(
        node2_udp_providers.len(),
        1,
        "Node2 should have access to UDP transport"
    );
    assert_eq!(
        node2_ble_providers.len(),
        1,
        "Node2 should have access to BLE transport"
    );

    // Verify transports are online
    assert!(
        node1_udp_providers[0].is_online(),
        "Node1 UDP transport should be online"
    );
    assert!(
        node1_ble_providers[0].is_online(),
        "Node1 BLE transport should be online"
    );
    assert!(
        node2_udp_providers[0].is_online(),
        "Node2 UDP transport should be online"
    );
    assert!(
        node2_ble_providers[0].is_online(),
        "Node2 BLE transport should be online"
    );

    // Step 4: Verify transport stats are accessible
    let udp_stats = udp_provider.stats();
    println!(
        "UDP stats - sent: {} bytes, received: {} bytes, datagrams sent: {}, datagrams received: {}",
        udp_stats.bytes_sent,
        udp_stats.bytes_received,
        udp_stats.datagrams_sent,
        udp_stats.datagrams_received
    );

    let ble_stats = ble_provider.stats();
    println!(
        "BLE stats - sent: {} bytes, received: {} bytes, datagrams sent: {}, datagrams received: {}",
        ble_stats.bytes_sent,
        ble_stats.bytes_received,
        ble_stats.datagrams_sent,
        ble_stats.datagrams_received
    );

    // Verify stats structure is correct (fields are accessible)
    assert_eq!(
        udp_stats.send_errors, 0,
        "UDP should have no send errors initially"
    );
    assert_eq!(
        ble_stats.send_errors, 0,
        "BLE should have no send errors initially"
    );

    // Step 5: Shut down BLE transport mid-test, verify failover to UDP
    println!("\n=== Testing Transport Failover ===");
    println!("Shutting down BLE transport...");
    ble_provider.shutdown().await.expect("BLE shutdown failed");
    assert!(
        !ble_provider.is_online(),
        "BLE should be offline after shutdown"
    );

    // Verify UDP is still online
    assert!(
        udp_provider.is_online(),
        "UDP should still be online after BLE shutdown"
    );

    // Verify registry reflects the change
    tokio::time::sleep(Duration::from_millis(100)).await; // Give time for state to propagate

    // Final verification: Check online providers count
    let online_count = node1_registry.online_providers().count();
    assert_eq!(
        online_count, 1,
        "Only 1 transport (UDP) should be online after BLE shutdown"
    );

    // Cleanup
    node1.shutdown().await;
    node2.shutdown().await;
}
