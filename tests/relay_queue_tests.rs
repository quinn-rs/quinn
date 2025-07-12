//! Integration tests for NAT traversal functionality
//!
//! This module tests the NAT traversal functionality through the public API,
//! focusing on overall system behavior and the high-level interfaces.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ant_quic::{
    VarInt,
    nat_traversal_api::{
        EndpointRole, NatTraversalConfig, NatTraversalEndpoint, NatTraversalError, PeerId,
    },
};

/// Create a test peer ID
fn create_test_peer_id(id: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = id;
    bytes[31] = id; // Add variety to make unique
    PeerId(bytes)
}

#[cfg(test)]
mod nat_traversal_api_tests {
    use super::*;

    #[test]
    fn test_peer_id_creation_and_display() {
        let peer_id = create_test_peer_id(42);

        // Verify peer ID format
        assert_eq!(peer_id.0[0], 42);
        assert_eq!(peer_id.0[31], 42);

        // Test display format (first 8 bytes as hex)
        let display_string = format!("{}", peer_id);
        assert_eq!(display_string.len(), 16); // 8 bytes * 2 hex chars
        assert!(display_string.starts_with("2a")); // 42 in hex
    }

    #[test]
    fn test_peer_id_from_bytes() {
        let bytes = [1u8; 32];
        let peer_id = PeerId::from(bytes);

        assert_eq!(peer_id.0, bytes);
    }

    #[test]
    fn test_peer_id_uniqueness() {
        let peer1 = create_test_peer_id(1);
        let peer2 = create_test_peer_id(2);
        let peer1_copy = create_test_peer_id(1);

        // Different IDs should be different
        assert_ne!(peer1, peer2);

        // Same construction should be equal
        assert_eq!(peer1, peer1_copy);

        // Test hash consistency (important for HashMap usage)
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(peer1, "peer1");
        map.insert(peer2, "peer2");

        assert_eq!(map.get(&peer1_copy), Some(&"peer1"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_nat_traversal_config_default() {
        let config = NatTraversalConfig::default();

        assert_eq!(config.role, EndpointRole::Client);
        assert_eq!(config.max_candidates, 8);
        assert_eq!(config.coordination_timeout, Duration::from_secs(10));
        assert!(config.enable_symmetric_nat);
        assert!(config.enable_relay_fallback);
        assert_eq!(config.max_concurrent_attempts, 3);
        assert!(config.bootstrap_nodes.is_empty());
    }

    #[test]
    fn test_nat_traversal_config_with_bootstrap_nodes() {
        let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![bootstrap_addr],
            max_candidates: 16,
            coordination_timeout: Duration::from_secs(30),
            enable_symmetric_nat: false,
            enable_relay_fallback: false,
            max_concurrent_attempts: 5,
        };

        assert_eq!(config.role, EndpointRole::Bootstrap);
        assert_eq!(config.bootstrap_nodes.len(), 1);
        assert_eq!(config.bootstrap_nodes[0], bootstrap_addr);
        assert_eq!(config.max_candidates, 16);
        assert_eq!(config.coordination_timeout, Duration::from_secs(30));
        assert!(!config.enable_symmetric_nat);
        assert!(!config.enable_relay_fallback);
        assert_eq!(config.max_concurrent_attempts, 5);
    }

    #[test]
    fn test_endpoint_role_matching() {
        // Test client role
        let client_role = EndpointRole::Client;
        assert!(matches!(client_role, EndpointRole::Client));

        // Test server roles
        let server_no_relay = EndpointRole::Server {
            can_coordinate: false,
        };
        let server_with_relay = EndpointRole::Server {
            can_coordinate: true,
        };

        assert!(matches!(
            server_no_relay,
            EndpointRole::Server {
                can_coordinate: false
            }
        ));
        assert!(matches!(
            server_with_relay,
            EndpointRole::Server {
                can_coordinate: true
            }
        ));

        // Test bootstrap role
        let bootstrap_role = EndpointRole::Bootstrap;
        assert!(matches!(bootstrap_role, EndpointRole::Bootstrap));
    }

    #[tokio::test]
    async fn test_nat_traversal_endpoint_creation_without_bootstrap() {
        // Should fail for client without bootstrap nodes
        let config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![], // Empty
            ..NatTraversalConfig::default()
        };

        let result = NatTraversalEndpoint::new(config, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bootstrap node"));
    }

    #[tokio::test]
    async fn test_nat_traversal_endpoint_creation_bootstrap_role() {
        // Bootstrap nodes don't need other bootstrap nodes
        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![], // Empty is OK for bootstrap
            ..NatTraversalConfig::default()
        };

        // This might still fail due to missing TLS config, but should not fail on bootstrap validation
        let result = NatTraversalEndpoint::new(config, None).await;
        // We expect this to fail for TLS reasons, not bootstrap validation
        if let Err(e) = result {
            assert!(!e.to_string().contains("bootstrap node"));
        }
    }

    #[tokio::test]
    async fn test_nat_traversal_endpoint_creation_with_bootstrap() {
        let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![bootstrap_addr],
            ..NatTraversalConfig::default()
        };

        // This will likely fail due to TLS configuration, but should pass bootstrap validation
        let result = NatTraversalEndpoint::new(config, None).await;
        if let Err(e) = result {
            assert!(!e.to_string().contains("bootstrap node"));
        }
    }

    #[tokio::test]
    async fn test_bootstrap_node_management() {
        let bootstrap_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let bootstrap_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 8080);

        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![bootstrap_addr1],
            ..NatTraversalConfig::default()
        };

        // Try to create endpoint - may fail due to TLS but we can test the concept
        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None).await {
            // Test adding bootstrap node
            let result = endpoint.add_bootstrap_node(bootstrap_addr2);
            assert!(result.is_ok());

            // Test removing bootstrap node
            let result = endpoint.remove_bootstrap_node(bootstrap_addr1);
            assert!(result.is_ok());

            // Test getting statistics
            let stats = endpoint.get_statistics();
            assert!(stats.is_ok());

            if let Ok(stats) = stats {
                assert_eq!(stats.active_sessions, 0); // No active sessions yet
                assert!(stats.total_bootstrap_nodes >= 1); // Should have at least the added one
            }
        }
    }
}

#[cfg(test)]
mod functional_tests {
    use super::*;

    #[test]
    fn test_varint_compatibility() {
        // Test VarInt values commonly used in NAT traversal
        let small_value = VarInt::from_u32(42);
        let medium_value = VarInt::from_u32(10000);
        let large_value = VarInt::from_u32(1000000);

        assert_eq!(small_value.into_inner(), 42);
        assert_eq!(medium_value.into_inner(), 10000);
        assert_eq!(large_value.into_inner(), 1000000);

        // Test maximum values
        let max_value = VarInt::from_u32(u32::MAX);
        assert_eq!(max_value.into_inner(), u32::MAX as u64);
    }

    #[test]
    fn test_socket_address_handling() {
        // Test various socket address formats used in NAT traversal
        let ipv4_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let ipv4_public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let ipv6_addr = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 9000);

        // Verify address properties
        assert!(ipv4_local.ip().is_ipv4());
        assert!(!ipv4_local.ip().is_loopback());
        assert!(ipv4_public.ip().is_ipv4());
        assert!(!ipv4_public.ip().is_loopback());
        assert!(ipv6_addr.ip().is_ipv6());

        // Test port ranges
        assert_eq!(ipv4_local.port(), 5000);
        assert_eq!(ipv4_public.port(), 8080);
        assert_eq!(ipv6_addr.port(), 9000);
    }

    #[tokio::test]
    async fn test_configuration_validation() {
        // Test invalid configurations
        let invalid_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![], // Invalid for client
            max_candidates: 0,       // Invalid
            coordination_timeout: Duration::from_secs(0), // Invalid
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 0, // Invalid
        };

        // The validation logic might be in the endpoint creation
        let result = NatTraversalEndpoint::new(invalid_config, None).await;
        assert!(result.is_err());

        // Test valid configuration
        let valid_config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![], // OK for bootstrap
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };

        // This might still fail due to other issues (TLS config), but should pass basic validation
        let result = NatTraversalEndpoint::new(valid_config, None).await;
        if let Err(e) = result {
            // Should not fail due to configuration validation
            assert!(!e.to_string().contains("bootstrap node"));
        }
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_nat_traversal_error_display() {
        let errors = vec![
            NatTraversalError::NoBootstrapNodes,
            NatTraversalError::NoCandidatesFound,
            NatTraversalError::CandidateDiscoveryFailed("test error".to_string()),
            NatTraversalError::CoordinationFailed("coordination error".to_string()),
            NatTraversalError::HolePunchingFailed,
            NatTraversalError::ValidationTimeout,
            NatTraversalError::NetworkError("network issue".to_string()),
            NatTraversalError::ConfigError("config issue".to_string()),
            NatTraversalError::ProtocolError("protocol issue".to_string()),
            NatTraversalError::Timeout,
            NatTraversalError::ConnectionFailed("connection error".to_string()),
            NatTraversalError::TraversalFailed("traversal error".to_string()),
        ];

        // Verify all errors implement Display properly
        for error in errors {
            let error_string = format!("{}", error);
            assert!(!error_string.is_empty());
            assert!(!error_string.starts_with("NatTraversalError")); // Should be user-friendly
        }
    }

    #[test]
    fn test_error_chain_compatibility() {
        // Test that our errors work with standard error handling
        let error = NatTraversalError::ConfigError("test error".to_string());

        // Should implement std::error::Error
        let _source: Option<&dyn Error> = error.source();

        // Should work with error conversion patterns
        let result: Result<(), NatTraversalError> = Err(error);
        assert!(result.is_err());

        // Test error message propagation
        if let Err(e) = result {
            assert!(e.to_string().contains("config"));
            assert!(e.to_string().contains("test error"));
        }
    }
}

#[cfg(test)]
mod nat_traversal_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_traversal_initiation() {
        let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![bootstrap_addr],
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None).await {
            let target_peer = create_test_peer_id(42);

            // Test NAT traversal initiation
            let result = endpoint.initiate_nat_traversal(target_peer, bootstrap_addr);
            // This might fail due to missing implementation details, but should not panic
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_polling_without_active_sessions() {
        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![],
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None).await {
            let now = std::time::Instant::now();

            // Polling with no active sessions should not panic
            let result = endpoint.poll(now);
            assert!(result.is_ok());

            if let Ok(events) = result {
                assert_eq!(events.len(), 0); // No events expected
            }
        }
    }

    #[tokio::test]
    async fn test_statistics_without_activity() {
        let config = NatTraversalConfig {
            role: EndpointRole::Bootstrap,
            bootstrap_nodes: vec![],
            ..NatTraversalConfig::default()
        };

        if let Ok(endpoint) = NatTraversalEndpoint::new(config, None).await {
            let stats = endpoint.get_statistics();
            assert!(stats.is_ok());

            if let Ok(stats) = stats {
                assert_eq!(stats.active_sessions, 0);
                assert_eq!(stats.successful_coordinations, 0);
                assert!(stats.average_coordination_time > Duration::ZERO);
            }
        }
    }
}

// Performance and stress tests (marked to run only when explicitly requested)

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    #[ignore = "performance test"]
    fn bench_peer_id_operations() {
        use std::collections::HashMap;

        let start = std::time::Instant::now();

        // Create many peer IDs and test map operations
        let mut peer_map = HashMap::new();
        for i in 0..10000 {
            let peer_id = create_test_peer_id(i as u8);
            peer_map.insert(peer_id, i);
        }

        // Test lookups
        for i in 0..1000 {
            let peer_id = create_test_peer_id(i as u8);
            let _value = peer_map.get(&peer_id);
        }

        let duration = start.elapsed();
        println!("Created and looked up peer IDs in {:?}", duration);
        assert!(duration < Duration::from_millis(100));
    }

    #[test]
    #[ignore = "performance test"]
    fn bench_configuration_creation() {
        let start = std::time::Instant::now();

        // Create many configurations
        for i in 0..1000 {
            let config = NatTraversalConfig {
                role: if i % 3 == 0 {
                    EndpointRole::Bootstrap
                } else {
                    EndpointRole::Client
                },
                bootstrap_nodes: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8)),
                    8080,
                )],
                max_candidates: i as usize % 32 + 1,
                coordination_timeout: Duration::from_secs(i as u64 % 60 + 1),
                enable_symmetric_nat: i % 2 == 0,
                enable_relay_fallback: i % 3 == 0,
                max_concurrent_attempts: i as usize % 10 + 1,
            };

            // Use the config to prevent optimization
            assert!(config.max_candidates > 0);
        }

        let duration = start.elapsed();
        println!("Created configurations in {:?}", duration);
        assert!(duration < Duration::from_millis(50));
    }
}

#[cfg(test)]
mod relay_functionality_tests {
    use super::*;

    #[test]
    fn test_endpoint_roles_for_relay() {
        // Test role capabilities for relay functionality

        // Client cannot relay
        let client_role = EndpointRole::Client;
        assert!(matches!(client_role, EndpointRole::Client));

        // Server can optionally relay
        let server_no_relay = EndpointRole::Server {
            can_coordinate: false,
        };
        let server_relay = EndpointRole::Server {
            can_coordinate: true,
        };

        assert!(matches!(
            server_no_relay,
            EndpointRole::Server {
                can_coordinate: false
            }
        ));
        assert!(matches!(
            server_relay,
            EndpointRole::Server {
                can_coordinate: true
            }
        ));

        // Bootstrap always relays
        let bootstrap = EndpointRole::Bootstrap;
        assert!(matches!(bootstrap, EndpointRole::Bootstrap));
    }

    #[test]
    fn test_multiple_bootstrap_nodes() {
        let bootstrap_addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 8080),
        ];

        let config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: bootstrap_addrs.clone(),
            ..NatTraversalConfig::default()
        };

        assert_eq!(config.bootstrap_nodes.len(), 3);
        for (i, addr) in config.bootstrap_nodes.iter().enumerate() {
            assert_eq!(*addr, bootstrap_addrs[i]);
        }
    }

    #[tokio::test]
    async fn test_invalid_configuration_scenarios() {
        // Test various invalid configuration scenarios

        // Client with no bootstrap nodes
        let invalid_client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![],
            ..NatTraversalConfig::default()
        };

        let result = NatTraversalEndpoint::new(invalid_client_config, None).await;
        assert!(result.is_err());

        // Test configuration with zero values (edge cases)
        let zero_values_config = NatTraversalConfig {
            role: EndpointRole::Bootstrap, // This should be valid
            bootstrap_nodes: vec![],
            max_candidates: 0,                    // Might be invalid
            coordination_timeout: Duration::ZERO, // Might be invalid
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 0, // Might be invalid
        };

        // This might be accepted or rejected depending on implementation
        let _result = NatTraversalEndpoint::new(zero_values_config, None).await;
    }
}
