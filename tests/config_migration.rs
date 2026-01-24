//! End-to-End Integration Test for Config Address Migration
//!
//! This test validates backward compatibility and correctness when migrating
//! from SocketAddr to TransportAddr in configuration types.
//!
//! # Test Scenarios
//!
//! 1. **P2pConfig with old SocketAddr approach** - Verify auto-conversion via Into trait
//! 2. **P2pConfig with new TransportAddr approach** - Verify explicit TransportAddr usage
//! 3. **NodeConfig with mixed transport types** - Verify heterogeneous transport support
//! 4. **Config interoperability** - Verify configs produce expected results when used together
//!
//! This ensures the migration maintains 100% backward compatibility while enabling
//! multi-transport functionality.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::transport::{TransportAddr, TransportType};
use ant_quic::{NodeConfig, P2pConfig};
use std::net::SocketAddr;

// ============================================================================
// P2pConfig Migration Tests
// ============================================================================

#[test]
fn test_p2p_config_old_socket_addr_approach() {
    // Scenario 1: Old code using SocketAddr directly
    // The Into trait should auto-convert to TransportAddr::Udp

    let bind_socket: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
    let peer1: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");
    let peer2: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");

    let config = P2pConfig::builder()
        .bind_addr(bind_socket) // Auto-converts via Into<TransportAddr>
        .known_peer(peer1) // Auto-converts via Into<TransportAddr>
        .known_peer(peer2) // Auto-converts via Into<TransportAddr>
        .build()
        .expect("Failed to build P2pConfig");

    // Verify bind_addr was auto-converted
    assert!(config.bind_addr.is_some());
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(bind_socket),
        "bind_addr should preserve SocketAddr via TransportAddr::Udp"
    );
    assert_eq!(
        config.bind_addr.as_ref().unwrap().transport_type(),
        TransportType::Udp
    );

    // Verify known_peers were auto-converted
    assert_eq!(config.known_peers.len(), 2);
    assert_eq!(config.known_peers[0].as_socket_addr(), Some(peer1));
    assert_eq!(config.known_peers[1].as_socket_addr(), Some(peer2));
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
    assert_eq!(config.known_peers[1].transport_type(), TransportType::Udp);
}

#[test]
fn test_p2p_config_new_transport_addr_approach() {
    // Scenario 2: New code using TransportAddr explicitly
    // This enables multi-transport functionality

    let bind_addr = TransportAddr::Udp("0.0.0.0:9000".parse().expect("valid addr"));
    let udp_peer = TransportAddr::Udp("192.168.1.1:9000".parse().expect("valid addr"));
    let ble_peer = TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None);

    let config = P2pConfig::builder()
        .bind_addr(bind_addr.clone())
        .known_peer(udp_peer.clone())
        .known_peer(ble_peer.clone())
        .build()
        .expect("Failed to build P2pConfig");

    // Verify bind_addr preserved
    assert_eq!(config.bind_addr, Some(bind_addr));

    // Verify heterogeneous known_peers list
    assert_eq!(config.known_peers.len(), 2);
    assert_eq!(config.known_peers[0], udp_peer);
    assert_eq!(config.known_peers[1], ble_peer);

    // Verify transport types
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
    assert_eq!(config.known_peers[1].transport_type(), TransportType::Ble);

    // Verify BLE peer has no socket addr
    assert!(config.known_peers[1].as_socket_addr().is_none());
}

#[test]
fn test_p2p_config_ipv6_addresses() {
    // Verify IPv6 addresses work correctly in both approaches

    let ipv6_bind: SocketAddr = "[::]:9000".parse().expect("valid IPv6 addr");
    let ipv6_peer: SocketAddr = "[::1]:9001".parse().expect("valid IPv6 addr");

    // Old approach (auto-convert)
    let config_old = P2pConfig::builder()
        .bind_addr(ipv6_bind)
        .known_peer(ipv6_peer)
        .build()
        .expect("Failed to build config");

    // New approach (explicit)
    let config_new = P2pConfig::builder()
        .bind_addr(TransportAddr::Udp(ipv6_bind))
        .known_peer(TransportAddr::Udp(ipv6_peer))
        .build()
        .expect("Failed to build config");

    // Both approaches should produce identical results
    assert_eq!(config_old.bind_addr, config_new.bind_addr);
    assert_eq!(config_old.known_peers, config_new.known_peers);

    // Verify IPv6 addresses preserved
    assert_eq!(
        config_new.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv6_bind)
    );
    assert_eq!(config_new.known_peers[0].as_socket_addr(), Some(ipv6_peer));
}

#[test]
fn test_p2p_config_known_peers_iterator() {
    // Test known_peers() with iterator of SocketAddr

    let peers: Vec<SocketAddr> = vec![
        "192.168.1.1:9000".parse().expect("valid addr"),
        "192.168.1.2:9000".parse().expect("valid addr"),
        "192.168.1.3:9000".parse().expect("valid addr"),
    ];

    let config = P2pConfig::builder()
        .known_peers(peers.clone())
        .build()
        .expect("Failed to build config");

    // Verify all peers were added and converted
    assert_eq!(config.known_peers.len(), 3);
    for (i, expected_peer) in peers.iter().enumerate() {
        assert_eq!(
            config.known_peers[i].as_socket_addr(),
            Some(*expected_peer),
            "Peer {} should match",
            i
        );
        assert_eq!(config.known_peers[i].transport_type(), TransportType::Udp);
    }
}

// ============================================================================
// NodeConfig Migration Tests
// ============================================================================

#[test]
fn test_node_config_old_socket_addr_approach() {
    // Verify NodeConfig also supports SocketAddr via Into trait

    let bind_socket: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");
    let peer1: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");
    let peer2: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");

    let config = NodeConfig::builder()
        .bind_addr(bind_socket)
        .known_peer(peer1)
        .known_peer(peer2)
        .build();

    // Verify auto-conversion worked
    assert_eq!(
        config.bind_addr,
        Some(TransportAddr::from(bind_socket)),
        "bind_addr should auto-convert"
    );
    assert_eq!(config.known_peers.len(), 2);
    assert_eq!(config.known_peers[0], TransportAddr::from(peer1));
    assert_eq!(config.known_peers[1], TransportAddr::from(peer2));
}

#[test]
fn test_node_config_new_transport_addr_approach() {
    // Verify NodeConfig supports explicit TransportAddr

    let bind_addr = TransportAddr::Udp("0.0.0.0:0".parse().expect("valid addr"));
    let udp_peer = TransportAddr::Udp("192.168.1.100:9000".parse().expect("valid addr"));
    let ble_peer = TransportAddr::ble([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], None);

    let config = NodeConfig::builder()
        .bind_addr(bind_addr.clone())
        .known_peer(udp_peer.clone())
        .known_peer(ble_peer.clone())
        .build();

    // Verify fields preserved
    assert_eq!(config.bind_addr, Some(bind_addr));
    assert_eq!(config.known_peers.len(), 2);
    assert_eq!(config.known_peers[0], udp_peer);
    assert_eq!(config.known_peers[1], ble_peer);

    // Verify transport types
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
    assert_eq!(config.known_peers[1].transport_type(), TransportType::Ble);
}

#[test]
fn test_node_config_mixed_transport_types() {
    // Scenario 3: NodeConfig with heterogeneous transport addresses
    // This validates the core multi-transport capability

    let udp_ipv4 = TransportAddr::Udp("192.168.1.1:9000".parse().expect("valid addr"));
    let udp_ipv6 = TransportAddr::Udp("[::1]:9001".parse().expect("valid addr"));
    let ble_device = TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None);
    let serial_port = TransportAddr::serial("/dev/ttyUSB0");

    let config = NodeConfig::builder()
        .known_peer(udp_ipv4.clone())
        .known_peer(udp_ipv6.clone())
        .known_peer(ble_device.clone())
        .known_peer(serial_port.clone())
        .build();

    // Verify all transport types preserved
    assert_eq!(config.known_peers.len(), 4);
    assert_eq!(config.known_peers[0], udp_ipv4);
    assert_eq!(config.known_peers[1], udp_ipv6);
    assert_eq!(config.known_peers[2], ble_device);
    assert_eq!(config.known_peers[3], serial_port);

    // Verify transport types
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
    assert_eq!(config.known_peers[1].transport_type(), TransportType::Udp);
    assert_eq!(config.known_peers[2].transport_type(), TransportType::Ble);
    assert_eq!(
        config.known_peers[3].transport_type(),
        TransportType::Serial
    );

    // Verify UDP addresses have socket addrs, others don't
    assert!(config.known_peers[0].as_socket_addr().is_some());
    assert!(config.known_peers[1].as_socket_addr().is_some());
    assert!(config.known_peers[2].as_socket_addr().is_none());
    assert!(config.known_peers[3].as_socket_addr().is_none());
}

// ============================================================================
// Cross-Config Interoperability Tests
// ============================================================================

#[test]
fn test_p2p_and_node_config_equivalence() {
    // Verify P2pConfig and NodeConfig produce equivalent results for the same inputs

    let bind_socket: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");
    let peer1: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");
    let peer2: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(bind_socket)
        .known_peer(peer1)
        .known_peer(peer2)
        .build()
        .expect("Failed to build P2pConfig");

    let node_config = NodeConfig::builder()
        .bind_addr(bind_socket)
        .known_peer(peer1)
        .known_peer(peer2)
        .build();

    // Both configs should have equivalent addresses
    assert_eq!(p2p_config.bind_addr, node_config.bind_addr);
    assert_eq!(p2p_config.known_peers, node_config.known_peers);
}

#[test]
fn test_to_nat_config_preserves_transport_addrs() {
    // Verify P2pConfig::to_nat_config() correctly handles TransportAddr fields

    let bind_addr: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");
    let peer1: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");
    let peer2: SocketAddr = "192.168.1.2:9000".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(bind_addr)
        .known_peer(peer1)
        .known_peer(peer2)
        .build()
        .expect("Failed to build config");

    let nat_config = p2p_config.to_nat_config();

    // NatTraversalConfig should extract SocketAddr from TransportAddr::Udp
    assert_eq!(nat_config.bind_addr, Some(bind_addr));
    assert_eq!(nat_config.known_peers.len(), 2);
    assert!(nat_config.known_peers.contains(&peer1));
    assert!(nat_config.known_peers.contains(&peer2));
}

#[test]
fn test_mixed_config_to_nat_config_filtering() {
    // Verify to_nat_config() filters out non-UDP addresses (BLE, Serial, etc.)
    // since NatTraversalConfig only works with SocketAddr

    let udp_peer: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");
    let ble_peer = TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None);

    let p2p_config = P2pConfig::builder()
        .known_peer(udp_peer)
        .known_peer(ble_peer) // This should be filtered out
        .build()
        .expect("Failed to build config");

    let nat_config = p2p_config.to_nat_config();

    // NatTraversalConfig should only contain UDP addresses
    assert_eq!(
        nat_config.known_peers.len(),
        1,
        "to_nat_config() should filter out non-UDP addresses"
    );
    assert_eq!(nat_config.known_peers[0], udp_peer);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_ipv4_mapped_ipv6_address() {
    // Test IPv4-mapped IPv6 addresses (::ffff:192.0.2.1)
    // These should be handled correctly without confusion

    use std::net::{IpAddr, Ipv6Addr};

    // Create IPv4-mapped IPv6 address
    let ipv4_mapped = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)),
        8080,
    );

    let config = P2pConfig::builder()
        .bind_addr(ipv4_mapped)
        .known_peer(ipv4_mapped)
        .build()
        .expect("Failed to build config");

    // Verify IPv4-mapped IPv6 addresses are preserved correctly
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv4_mapped),
        "IPv4-mapped IPv6 should be preserved"
    );
    assert_eq!(config.known_peers[0].as_socket_addr(), Some(ipv4_mapped));
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
}

#[test]
fn test_duplicate_peer_addresses() {
    // Test that duplicate peer addresses are handled correctly
    // Current behavior: duplicates are preserved (de-duplication may be added later)

    let peer1: SocketAddr = "192.168.1.1:9000".parse().expect("valid addr");
    let peer2: SocketAddr = "192.168.1.2:9000".parse().expect("valid addr");

    let config = P2pConfig::builder()
        .known_peer(peer1)
        .known_peer(peer2)
        .known_peer(peer1) // Intentional duplicate
        .known_peer(peer2) // Intentional duplicate
        .build()
        .expect("Failed to build config");

    // Current implementation preserves duplicates
    // This test documents the behavior - de-duplication could be added in future
    assert_eq!(
        config.known_peers.len(),
        4,
        "Duplicates are currently preserved (de-duplication not implemented)"
    );

    // Verify all addresses are correct
    assert_eq!(config.known_peers[0].as_socket_addr(), Some(peer1));
    assert_eq!(config.known_peers[1].as_socket_addr(), Some(peer2));
    assert_eq!(config.known_peers[2].as_socket_addr(), Some(peer1));
    assert_eq!(config.known_peers[3].as_socket_addr(), Some(peer2));
}

#[test]
fn test_empty_known_peers() {
    // Test that configs can be created with no known peers
    // This is valid - node can still accept incoming connections

    let config1 = P2pConfig::builder()
        .bind_addr("0.0.0.0:9000".parse::<SocketAddr>().unwrap())
        .build()
        .expect("Failed to build config with no known peers");

    assert!(
        config1.known_peers.is_empty(),
        "Config should allow empty known_peers"
    );

    let config2 = NodeConfig::builder()
        .bind_addr("0.0.0.0:9000".parse::<SocketAddr>().unwrap())
        .build();

    assert!(
        config2.known_peers.is_empty(),
        "NodeConfig should allow empty known_peers"
    );
}

#[test]
fn test_port_zero_dynamic_allocation() {
    // Verify port 0 (dynamic allocation) works correctly

    let dynamic_port: SocketAddr = "0.0.0.0:0".parse().expect("valid addr");

    let p2p_config = P2pConfig::builder()
        .bind_addr(dynamic_port)
        .build()
        .expect("Failed to build config");

    let node_config = NodeConfig::builder().bind_addr(dynamic_port).build();

    // Verify port 0 is preserved (OS will assign actual port at bind time)
    assert_eq!(
        p2p_config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(dynamic_port)
    );
    assert_eq!(
        node_config.bind_addr.unwrap().as_socket_addr(),
        Some(dynamic_port)
    );
}

#[test]
fn test_ipv6_with_scope_id() {
    // Test IPv6 addresses with scope IDs (zone indices)
    // e.g., fe80::1%eth0 or fe80::1%1

    use std::net::{Ipv6Addr, SocketAddrV6};

    // Link-local IPv6 with scope ID
    let ipv6_scoped = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        8080,
        0, // flowinfo
        1, // scope_id (interface index)
    ));

    let config = P2pConfig::builder()
        .bind_addr(ipv6_scoped)
        .known_peer(ipv6_scoped)
        .build()
        .expect("Failed to build config");

    // Verify scope ID is preserved
    assert_eq!(
        config.bind_addr.as_ref().unwrap().as_socket_addr(),
        Some(ipv6_scoped)
    );
    assert_eq!(config.known_peers[0].as_socket_addr(), Some(ipv6_scoped));

    // Verify it's recognized as UDP transport
    assert_eq!(config.known_peers[0].transport_type(), TransportType::Udp);
}

// ============================================================================
// Backward Compatibility Regression Tests
// ============================================================================

#[test]
fn test_old_code_still_compiles() {
    // This test represents typical old user code to ensure zero breakage

    let addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid");

    // Old pattern 1: Direct SocketAddr to bind_addr
    let _config1 = P2pConfig::builder().bind_addr(addr).build().unwrap();

    // Old pattern 2: Multiple known_peer calls with SocketAddr
    let _config2 = P2pConfig::builder()
        .known_peer("127.0.0.1:9001".parse::<SocketAddr>().unwrap())
        .known_peer("127.0.0.1:9002".parse::<SocketAddr>().unwrap())
        .build()
        .unwrap();

    // Old pattern 3: known_peers() with Vec<SocketAddr>
    let peers: Vec<SocketAddr> = vec![
        "127.0.0.1:9003".parse().unwrap(),
        "127.0.0.1:9004".parse().unwrap(),
    ];
    let _config3 = P2pConfig::builder().known_peers(peers).build().unwrap();

    // Old pattern 4: NodeConfig with SocketAddr
    let _node_config = NodeConfig::builder()
        .bind_addr(addr)
        .known_peer("127.0.0.1:9005".parse::<SocketAddr>().unwrap())
        .build();
}

#[test]
fn test_new_code_multi_transport() {
    // This test represents new user code using multi-transport features

    // Pattern 1: Explicit TransportAddr for clarity
    let _config1 = P2pConfig::builder()
        .bind_addr(TransportAddr::Udp(
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
        ))
        .build()
        .unwrap();

    // Pattern 2: Mixed transport types in known_peers
    let _config2 = NodeConfig::builder()
        .known_peer(TransportAddr::Udp(
            "192.168.1.1:9000".parse::<SocketAddr>().unwrap(),
        ))
        .known_peer(TransportAddr::ble(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            None,
        ))
        .known_peer(TransportAddr::serial("/dev/ttyUSB0"))
        .build();

    // Pattern 3: LoRa and other constrained transports
    let _config3 = NodeConfig::builder()
        .known_peer(TransportAddr::lora([0x01, 0x02, 0x03, 0x04]))
        .build();
}
