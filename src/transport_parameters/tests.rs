// Comprehensive unit tests for QUIC Address Discovery transport parameters

use super::*;

#[test]
fn test_address_discovery_config_default() {
    let config = AddressDiscoveryConfig::default();
    // Default is SendAndReceive
    assert_eq!(config, AddressDiscoveryConfig::SendAndReceive);
}

#[test]
fn test_address_discovery_config_variants() {
    // Test all variants and their values
    assert_eq!(AddressDiscoveryConfig::SendOnly.to_value(), VarInt::from_u32(0));
    assert_eq!(AddressDiscoveryConfig::ReceiveOnly.to_value(), VarInt::from_u32(1));
    assert_eq!(AddressDiscoveryConfig::SendAndReceive.to_value(), VarInt::from_u32(2));
    
    // Test from_value conversions
    assert_eq!(AddressDiscoveryConfig::from_value(VarInt::from_u32(0)).unwrap(), AddressDiscoveryConfig::SendOnly);
    assert_eq!(AddressDiscoveryConfig::from_value(VarInt::from_u32(1)).unwrap(), AddressDiscoveryConfig::ReceiveOnly);
    assert_eq!(AddressDiscoveryConfig::from_value(VarInt::from_u32(2)).unwrap(), AddressDiscoveryConfig::SendAndReceive);
    assert!(AddressDiscoveryConfig::from_value(VarInt::from_u32(3)).is_err());
}

#[test]
fn test_address_discovery_roundtrip() {
    // Test that all variants can be encoded and decoded correctly
    for variant in [AddressDiscoveryConfig::SendOnly, AddressDiscoveryConfig::ReceiveOnly, AddressDiscoveryConfig::SendAndReceive] {
        let value = variant.to_value();
        let decoded = AddressDiscoveryConfig::from_value(value).unwrap();
        assert_eq!(decoded, variant);
    }
}

#[test]
fn test_address_discovery_invalid_values() {
    // Test that invalid values are rejected
    let invalid_values = vec![
        3,     // Invalid enum value
        10,    // Random invalid value
        100,   // Large invalid value
        VarInt::MAX.into_inner(), // Maximum VarInt value
    ];
    
    for value in invalid_values {
        let result = AddressDiscoveryConfig::from_value(VarInt::from_u64(value).unwrap());
        assert!(
            result.is_err(),
            "Value {value} should be rejected"
        );
    }
}

#[test]
fn test_transport_parameters_with_address_discovery() {
    let mut params = TransportParameters::default();
    params.address_discovery = Some(AddressDiscoveryConfig::SendAndReceive);
    
    // Test that the field is properly set
    assert!(params.address_discovery.is_some());
    assert_eq!(params.address_discovery.unwrap(), AddressDiscoveryConfig::SendAndReceive);
}

#[test]
fn test_transport_parameters_without_address_discovery() {
    let params = TransportParameters::default();
    assert!(params.address_discovery.is_none());
}