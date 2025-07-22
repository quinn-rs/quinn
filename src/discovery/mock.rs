//! Mock Network Discovery Implementation
//!
//! This module provides a mock implementation of network interface discovery
//! for testing purposes. It allows simulating different network configurations
//! without requiring actual network interfaces.

use std::net::{IpAddr, SocketAddr};

use super::{DiscoveryError, NetworkDiscovery, NetworkInterface};

/// Mock network discovery implementation for testing
pub struct MockDiscovery {
    // Mock interfaces to return
    interfaces: Vec<NetworkInterface>,
    // Mock default route
    default_route: Option<SocketAddr>,
}

impl MockDiscovery {
    /// Create a new mock discovery instance with the specified interfaces
    pub fn new(interfaces: Vec<NetworkInterface>, default_route: Option<SocketAddr>) -> Self {
        Self {
            interfaces,
            default_route,
        }
    }

    /// Create a mock discovery instance with a simple network configuration
    pub fn with_simple_config() -> Self {
        // Create a simple network configuration with loopback and one external interface
        let interfaces = vec![
            NetworkInterface {
                name: "lo".into(),
                addresses: vec![
                    SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 0),
                    SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 0),
                ],
                is_up: true,
                is_wireless: false,
                mtu: Some(65535),
            },
            NetworkInterface {
                name: "eth0".into(),
                addresses: vec![
                    SocketAddr::new(IpAddr::V4("192.168.1.2".parse().unwrap()), 0),
                    SocketAddr::new(IpAddr::V6("fe80::1234:5678:9abc:def0".parse().unwrap()), 0),
                ],
                is_up: true,
                is_wireless: false,
                mtu: Some(1500),
            },
        ];

        let default_route = Some(SocketAddr::new(
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            0,
        ));

        Self {
            interfaces,
            default_route,
        }
    }
}

impl NetworkDiscovery for MockDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, DiscoveryError> {
        // Return the mock interfaces
        Ok(self.interfaces.clone())
    }

    fn get_default_route(&self) -> Result<Option<SocketAddr>, DiscoveryError> {
        // Return the mock default route
        Ok(self.default_route)
    }
}
