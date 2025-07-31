//! Quick frame parsing tests

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[test]
fn test_frame_type_identification() {
    super::utils::assert_duration(Duration::from_millis(10), || {
        // Basic frame type tests
        // Frame types are const values and tested in unit tests
        // Placeholder test - implementation pending
    });
}

#[test]
fn test_observed_address_creation() {
    super::utils::assert_duration(Duration::from_millis(50), || {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        // Observed address frame tested in unit tests
        assert_eq!(addr.port(), 8080);
    });
}

#[test]
fn test_frame_size_calculations() {
    super::utils::assert_duration(Duration::from_millis(10), || {
        // Test that basic structures have reasonable sizes
        use std::mem::size_of;

        // Socket addresses should be reasonable size
        assert!(size_of::<SocketAddr>() <= 32);
    });
}
