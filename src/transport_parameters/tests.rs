// Comprehensive unit tests for QUIC Address Discovery transport parameters

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_address_discovery_config_default() {
    let config = AddressDiscoveryConfig::default();
    assert!(config.enabled); // Default is enabled
    assert_eq!(config.max_observation_rate, 10);
    assert_eq!(config.observe_all_paths, false);
}

#[test]
fn test_address_discovery_config_new() {
    // Test normal configuration
    let config = AddressDiscoveryConfig::new(true, 20, false);
    assert!(config.enabled);
    assert_eq!(config.max_observation_rate, 20);
    assert!(!config.observe_all_paths);
    
    // Test that rate is capped at 63 (6 bits)
    let config = AddressDiscoveryConfig::new(true, 100, true);
    assert!(config.enabled);
    assert_eq!(config.max_observation_rate, 63); // Capped
    assert!(config.observe_all_paths);
}

#[test]
fn test_bootstrap_configuration() {
    let mut config = AddressDiscoveryConfig::default();
    config.apply_bootstrap_settings();
    
    assert!(config.enabled);
    assert_eq!(config.max_observation_rate, 63); // Maximum rate
    assert!(config.observe_all_paths);
}

#[test]
fn test_address_discovery_edge_cases() {
    // Test edge case values
    let test_cases = vec![
        (0, 0),     // Zero gets stored as-is
        (1, 1),     // Minimum positive value
        (63, 63),   // Maximum 6-bit value
        (64, 63),   // Above max gets capped
        (255, 63),  // Way above max gets capped
    ];
    
    for (input, expected) in test_cases {
        let config = AddressDiscoveryConfig::new(true, input, false);
        assert_eq!(
            config.max_observation_rate, 
            expected,
            "Rate {} should become {}", 
            input, 
            expected
        );
    }
}

#[test]
fn test_transport_parameters_with_address_discovery() {
    let mut params = TransportParameters::default();
    params.address_discovery = Some(AddressDiscoveryConfig {
        enabled: true,
        max_observation_rate: 15,
        observe_all_paths: false,
    });
    
    // Test that the field is properly set
    assert!(params.address_discovery.is_some());
    
    let config = params.address_discovery.unwrap();
    assert!(config.enabled);
    assert_eq!(config.max_observation_rate, 15);
    assert!(!config.observe_all_paths);
}

#[test]
fn test_transport_parameters_without_address_discovery() {
    let params = TransportParameters::default();
    assert!(params.address_discovery.is_none());
}