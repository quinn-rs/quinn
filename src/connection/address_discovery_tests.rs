// Comprehensive unit tests for address discovery in connections

use super::*;
use crate::frame::{Frame, ObservedAddress};
use crate::transport_parameters::AddressDiscoveryConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

#[test]
fn test_address_discovery_state_initialization() {
    let config = AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 20,
        observe_all_paths: false,
    };
    
    let now = Instant::now();
    let state = AddressDiscoveryState::new(&config, now);
    
    assert!(state.enabled);
    assert_eq!(state.max_observation_rate, 20);
    assert!(!state.observe_all_paths);
    assert!(state.observed_addresses.is_empty());
    assert!(!state.bootstrap_mode);
}

#[test]
fn test_handle_observed_address() {
    let config = AddressDiscoveryConfig::default();
    let now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    
    // Handle an observed address
    let observed_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 123)), 443);
    state.handle_observed_address(observed_addr, 0, now);
    
    // Check that address was recorded
    assert_eq!(state.observed_addresses.len(), 1);
    assert_eq!(state.observed_addresses[0].address, observed_addr);
    assert_eq!(state.observed_addresses[0].path_id, 0);
}

#[test]
fn test_multiple_observations() {
    let config = AddressDiscoveryConfig::default();
    let now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    
    // Add multiple addresses
    let addresses = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8081),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8082),
    ];
    
    for (i, addr) in addresses.iter().enumerate() {
        state.handle_observed_address(*addr, i as u64, now);
    }
    
    // Should have all addresses
    assert_eq!(state.observed_addresses.len(), 3);
    for (i, addr) in addresses.iter().enumerate() {
        assert_eq!(state.observed_addresses[i].address, *addr);
    }
}

#[test]
fn test_rate_limiting() {
    let config = AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 10, // 10 per second
        observe_all_paths: false,
    };
    
    let mut now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    let path_id = 0;
    
    // First observation should be allowed
    assert!(state.should_send_observation(path_id, now));
    state.record_observation_sent(path_id);
    
    // Immediate retry should be rate limited (no path info yet)
    assert!(!state.should_send_observation(path_id, now));
    
    // After sufficient time, should be allowed again
    now += Duration::from_millis(200);
    state.rate_limiter.last_update = now; // Update the rate limiter
    assert!(state.should_send_observation(path_id, now));
}

#[test]
fn test_bootstrap_mode() {
    let config = AddressDiscoveryConfig::default();
    let now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    
    // Enable bootstrap mode
    state.set_bootstrap_mode(true);
    assert!(state.bootstrap_mode);
    
    // Bootstrap mode affects path observation logic
    assert!(state.should_observe_path(0));
}

#[test]
fn test_disabled_state() {
    let config = AddressDiscoveryConfig {
        enabled: false,
        max_observation_rate: 10,
        observe_all_paths: false,
    };
    
    let now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    
    // When disabled, observations are not stored
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);
    state.handle_observed_address(addr, 0, now);
    
    // Address is not stored when disabled
    assert!(state.observed_addresses.is_empty());
}

#[test]
fn test_observe_all_paths_configuration() {
    let config = AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 10,
        observe_all_paths: true,
    };
    
    let now = Instant::now();
    let state = AddressDiscoveryState::new(&config, now);
    
    // Should be able to observe multiple paths
    assert!(state.should_observe_path(0));
    assert!(state.should_observe_path(1));
    assert!(state.should_observe_path(2));
}

#[test]
fn test_ipv6_address_handling() {
    let config = AddressDiscoveryConfig::default();
    let now = Instant::now();
    let mut state = AddressDiscoveryState::new(&config, now);
    
    // Test with IPv6 addresses
    let ipv6_addresses = vec![
        SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 443),
        SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 8080),
        SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 22),
    ];
    
    for (i, addr) in ipv6_addresses.iter().enumerate() {
        state.handle_observed_address(*addr, i as u64, now);
    }
    
    assert_eq!(state.observed_addresses.len(), 3);
    for (i, addr) in ipv6_addresses.iter().enumerate() {
        assert_eq!(state.observed_addresses[i].address, *addr);
    }
}

#[test]
fn test_rate_limiter_token_bucket() {
    let rate = 10; // 10 tokens per second
    let now = Instant::now();
    let mut limiter = AddressObservationRateLimiter::new(rate, now);
    
    // Should start with full bucket
    assert!(limiter.try_consume(1.0, now));
    assert!(limiter.try_consume(1.0, now));
    
    // Consume all tokens
    for _ in 0..8 {
        limiter.try_consume(1.0, now);
    }
    
    // Should be empty now
    assert!(!limiter.try_consume(1.0, now));
    
    // Wait for tokens to replenish
    let later = now + Duration::from_millis(100); // 0.1 seconds = 1 token
    assert!(limiter.try_consume(1.0, later));
}