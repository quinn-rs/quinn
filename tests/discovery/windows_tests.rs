//! Windows Network Discovery Tests
//!
//! This module contains tests for the Windows network interface discovery implementation.
//! It tests the IP Helper API integration with various network configurations.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[cfg(windows)]
mod windows_tests {
    use super::*;
    use ant_quic::discovery::{NetworkDiscovery, NetworkInterface, DiscoveryError};
    use ant_quic::discovery::windows::WindowsDiscovery;

    #[test]
    fn test_windows_discovery_creation() {
        let discovery = WindowsDiscovery::new(Duration::from_secs(60));
        assert!(discovery.cache.is_none(), "Cache should be initially empty");
        assert_eq!(discovery.cache_refresh_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_windows_discover_interfaces() {
        let discovery = WindowsDiscovery::new(Duration::from_secs(60));
        let interfaces = discovery.discover_interfaces();
        
        // The test should not panic, even if no interfaces are found
        assert!(interfaces.is_ok(), "Interface discovery should not fail");
        
        // We should have at least one interface (loopback)
        let interfaces = interfaces.unwrap();
        assert!(!interfaces.is_empty(), "At least one interface should be found");
        
        // Verify we have a loopback interface
        let has_loopback = interfaces.iter().any(|iface| iface.is_loopback);
        assert!(has_loopback, "Loopback interface should be present");
        
        // Check that interfaces have valid properties
        for iface in interfaces {
            assert!(!iface.name.is_empty(), "Interface should have a name");
            assert!(iface.index > 0, "Interface should have a valid index");
            assert!(!iface.addresses.is_empty(), "Interface should have at least one address");
        }
    }

    #[test]
    fn test_windows_get_default_route() {
        let discovery = WindowsDiscovery::new(Duration::from_secs(60));
        let default_route = discovery.get_default_route();
        
        // The function should not panic
        assert!(default_route.is_ok(), "Default route discovery should not fail");
        
        // We may or may not have a default route depending on network connectivity
        // So we don't assert on the result, just that it doesn't error
    }

    #[test]
    fn test_windows_cache_refresh() {
        let mut discovery = WindowsDiscovery::new(Duration::from_millis(1));
        
        // First call should populate the cache
        let interfaces1 = discovery.discover_interfaces().unwrap();
        assert!(!interfaces1.is_empty(), "Should find interfaces");
        
        // Wait for cache to expire
        std::thread::sleep(Duration::from_millis(10));
        
        // Second call should refresh the cache
        let interfaces2 = discovery.discover_interfaces().unwrap();
        assert!(!interfaces2.is_empty(), "Should find interfaces after refresh");
        
        // The interfaces should be the same (or at least similar)
        assert_eq!(interfaces1.len(), interfaces2.len(), "Interface count should be consistent");
    }

    #[test]
    fn test_windows_interface_properties() {
        let discovery = WindowsDiscovery::new(Duration::from_secs(60));
        let interfaces = discovery.discover_interfaces().unwrap();
        
        for iface in interfaces {
            // Validate interface properties
            assert!(iface.index > 0, "Interface index should be positive");
            assert!(!iface.name.is_empty(), "Interface name should not be empty");
            
            // Check addresses
            for addr in &iface.addresses {
                match addr {
                    IpAddr::V4(v4) => {
                        assert!(!v4.is_unspecified(), "IPv4 address should not be 0.0.0.0");
                    },
                    IpAddr::V6(v6) => {
                        // Link-local addresses are fine for IPv6
                        assert!(!v6.is_unspecified(), "IPv6 address should not be ::");
                    }
                }
            }
            
            // MTU should be reasonable
            assert!(iface.mtu > 0, "MTU should be positive");
            assert!(iface.mtu <= 65536, "MTU should be <= 65536");
        }
    }
}

// Always compile this test, even on non-Windows platforms
#[test]
fn test_windows_discovery_mock() {
    // This test ensures we have a way to test Windows discovery on non-Windows platforms
    // It uses the mock implementation which should be available on all platforms
    
    // On Windows, this is just an extra test
    // On non-Windows, this is the only test that runs
    
    use ant_quic::discovery::mock::MockDiscovery;
    use ant_quic::discovery::NetworkDiscovery;
    
    let mock = MockDiscovery::with_simple_config();
    let interfaces = mock.discover_interfaces().unwrap();
    
    assert_eq!(interfaces.len(), 2, "Mock should have 2 interfaces");
    
    // Check loopback interface
    let loopback = interfaces.iter().find(|i| i.is_loopback).unwrap();
    assert_eq!(loopback.name, "lo");
    assert_eq!(loopback.addresses.len(), 2);
    
    // Check external interface
    let external = interfaces.iter().find(|i| !i.is_loopback).unwrap();
    assert_eq!(external.name, "eth0");
    assert_eq!(external.addresses.len(), 2);
    
    // Check default route
    let default_route = mock.get_default_route().unwrap();
    assert!(default_route.is_some());
    assert_eq!(default_route.unwrap().ip().to_string(), "192.168.1.1");
}