//! Tests for address discovery configuration in EndpointConfig
//! 
//! This tests the configuration options for address discovery,
//! including feature flags and environment variable overrides.

use std::sync::Arc;
use ant_quic::{EndpointConfig, Endpoint, ServerConfig};
use ant_quic::crypto::rustls::rustls;
use tracing::{info, debug};

/// Test default address discovery configuration
#[test]
fn test_default_address_discovery_config() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let config = EndpointConfig::default();
    
    // Address discovery should be enabled by default
    assert!(config.address_discovery_enabled());
    
    // Default observation rate should be reasonable (e.g., 10 per second)
    assert_eq!(config.max_observation_rate(), 10);
    
    // Default should observe only active paths
    assert!(!config.observe_all_paths());
    
    info!("✓ Default address discovery configuration is sensible");
}

/// Test configuring address discovery in EndpointConfig
#[test]
fn test_configure_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut config = EndpointConfig::default();
    
    // Disable address discovery
    config.set_address_discovery_enabled(false);
    assert!(!config.address_discovery_enabled());
    
    // Set custom observation rate
    config.set_max_observation_rate(20);
    assert_eq!(config.max_observation_rate(), 20);
    
    // Enable observing all paths
    config.set_observe_all_paths(true);
    assert!(config.observe_all_paths());
    
    info!("✓ Address discovery can be configured in EndpointConfig");
}

/// Test that endpoints inherit config settings
#[test]
fn test_endpoint_inherits_config() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut config = EndpointConfig::default();
    config.set_address_discovery_enabled(false);
    config.set_max_observation_rate(30);
    
    let server_config = ServerConfig::with_crypto(Arc::new(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()))
        .unwrap()));
    
    let endpoint = Endpoint::new(Arc::new(config), Some(Arc::new(server_config)), false, None);
    
    // Endpoint should inherit the disabled state
    assert!(!endpoint.address_discovery_enabled());
    
    info!("✓ Endpoints inherit address discovery config");
}

/// Test environment variable override for address discovery
#[test]
fn test_env_var_override() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    // Set environment variable to disable address discovery
    std::env::set_var("ANT_QUIC_ADDRESS_DISCOVERY_ENABLED", "false");
    
    let config = EndpointConfig::default();
    
    // Environment variable should override default
    assert!(!config.address_discovery_enabled());
    
    // Clean up
    std::env::remove_var("ANT_QUIC_ADDRESS_DISCOVERY_ENABLED");
    
    info!("✓ Environment variables can override address discovery config");
}

/// Test environment variable for observation rate
#[test]
fn test_env_var_observation_rate() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    // Set environment variable for observation rate
    std::env::set_var("ANT_QUIC_MAX_OBSERVATION_RATE", "50");
    
    let config = EndpointConfig::default();
    
    // Environment variable should override default
    assert_eq!(config.max_observation_rate(), 50);
    
    // Clean up
    std::env::remove_var("ANT_QUIC_MAX_OBSERVATION_RATE");
    
    info!("✓ Environment variables can override observation rate");
}

/// Test invalid environment variable values
#[test]
fn test_invalid_env_var_values() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    // Set invalid values
    std::env::set_var("ANT_QUIC_ADDRESS_DISCOVERY_ENABLED", "invalid");
    std::env::set_var("ANT_QUIC_MAX_OBSERVATION_RATE", "not_a_number");
    
    let config = EndpointConfig::default();
    
    // Should fall back to defaults on invalid values
    assert!(config.address_discovery_enabled()); // default true
    assert_eq!(config.max_observation_rate(), 10); // default rate
    
    // Clean up
    std::env::remove_var("ANT_QUIC_ADDRESS_DISCOVERY_ENABLED");
    std::env::remove_var("ANT_QUIC_MAX_OBSERVATION_RATE");
    
    info!("✓ Invalid environment variables fall back to defaults");
}

/// Test feature flag for address discovery
#[cfg(feature = "address-discovery")]
#[test]
fn test_address_discovery_feature_enabled() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let config = EndpointConfig::default();
    
    // With feature enabled, address discovery should be available
    assert!(config.address_discovery_available());
    
    info!("✓ Address discovery feature flag works");
}

/// Test feature flag disabled
#[cfg(not(feature = "address-discovery"))]
#[test]
fn test_address_discovery_feature_disabled() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let config = EndpointConfig::default();
    
    // Without feature, address discovery should not be available
    assert!(!config.address_discovery_available());
    
    // Even if enabled in config, it should have no effect
    let mut config = EndpointConfig::default();
    config.set_address_discovery_enabled(true);
    
    let endpoint = create_endpoint_with_config(config);
    assert!(!endpoint.address_discovery_enabled());
    
    info!("✓ Address discovery can be disabled via feature flag");
}

/// Test builder pattern for address discovery config
#[test]
fn test_builder_pattern() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let config = EndpointConfig::default()
        .address_discovery(true)
        .observation_rate(25)
        .observe_all_paths(true);
    
    assert!(config.address_discovery_enabled());
    assert_eq!(config.max_observation_rate(), 25);
    assert!(config.observe_all_paths());
    
    info!("✓ Builder pattern works for address discovery config");
}

/// Test configuration validation
#[test]
fn test_config_validation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    let mut config = EndpointConfig::default();
    
    // Test rate limit bounds (0-63 as per spec)
    config.set_max_observation_rate(0);
    assert_eq!(config.max_observation_rate(), 0);
    
    config.set_max_observation_rate(63);
    assert_eq!(config.max_observation_rate(), 63);
    
    // Values above 63 should be clamped
    config.set_max_observation_rate(100);
    assert_eq!(config.max_observation_rate(), 63);
    
    info!("✓ Configuration values are validated");
}

// Helper function
fn create_endpoint_with_config(config: EndpointConfig) -> Endpoint {
    let server_config = ServerConfig::with_crypto(Arc::new(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()))
        .unwrap()));
    
    Endpoint::new(Arc::new(config), Some(Arc::new(server_config)), false, None)
}