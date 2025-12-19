//! Basic integration tests for PQC implementation
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! This test suite performs basic validation of PQC functionality.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::pqc::{
    PqcConfigBuilder,
    types::{PqcError, PqcResult},
};

#[test]
fn test_pqc_config_builder() {
    // v0.13.0+: PQC is always on
    let config = PqcConfigBuilder::default()
        .build()
        .expect("Failed to build default config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
}

#[test]
fn test_pqc_config_with_algorithms() {
    // Test ML-KEM only
    let ml_kem_config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(false)
        .build()
        .expect("Failed to build ML-KEM only config");

    assert!(ml_kem_config.ml_kem_enabled);
    assert!(!ml_kem_config.ml_dsa_enabled);

    // Test ML-DSA only
    let ml_dsa_config = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(true)
        .build()
        .expect("Failed to build ML-DSA only config");

    assert!(!ml_dsa_config.ml_kem_enabled);
    assert!(ml_dsa_config.ml_dsa_enabled);
}

#[test]
fn test_pqc_requires_at_least_one_algorithm() {
    // v0.13.0+: Must have at least one PQC algorithm
    let result = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(false)
        .build();

    assert!(result.is_err(), "Config without algorithms should fail");
}

#[test]
fn test_memory_pool_configuration() {
    // Test valid memory pool sizes
    let config = PqcConfigBuilder::default()
        .memory_pool_size(50)
        .build()
        .expect("Failed to build config with memory pool");

    assert_eq!(config.memory_pool_size, 50);

    // Test invalid memory pool size
    let result = PqcConfigBuilder::default().memory_pool_size(0).build();

    assert!(result.is_err());
}

#[test]
fn test_algorithm_selection() {
    // Test disabling ML-KEM
    let config = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(true)
        .build()
        .expect("Failed to build config");

    assert!(!config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Test disabling ML-DSA
    let config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(false)
        .build()
        .expect("Failed to build config");

    assert!(config.ml_kem_enabled);
    assert!(!config.ml_dsa_enabled);
}

#[test]
fn test_timeout_multiplier() {
    // Test valid timeout multiplier
    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(1.5)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 1.5);

    // Test boundary values
    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(1.0)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 1.0);

    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(10.0)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 10.0);

    // Test invalid timeout multipliers
    let result = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(0.5)
        .build();

    assert!(result.is_err());

    let result = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(11.0)
        .build();

    assert!(result.is_err());
}

#[test]
fn test_config_validation() {
    // v0.13.0+: PQC is always on, verify comprehensive config
    let config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .handshake_timeout_multiplier(1.2)
        .build()
        .expect("Failed to build comprehensive config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.memory_pool_size, 20);
    assert_eq!(config.handshake_timeout_multiplier, 1.2);
}

#[test]
fn test_pqc_error_types() {
    // Verify error types exist and are usable
    let _err: PqcResult<()> = Err(PqcError::FeatureNotAvailable);
    let _err: PqcResult<()> = Err(PqcError::InvalidKeySize {
        expected: 1568,
        actual: 1000,
    });
    let _err: PqcResult<()> = Err(PqcError::CryptoError("test".to_string()));
}

/// Test that verifies release readiness for v0.13.0+
#[test]
fn test_release_criteria() {
    println!("\n=== PQC Basic Integration Test (v0.13.0+) ===\n");

    // Verify configuration system works
    let config = PqcConfigBuilder::default().build().unwrap();
    println!("Configuration system operational");
    println!("  - ML-KEM enabled: {}", config.ml_kem_enabled);
    println!("  - ML-DSA enabled: {}", config.ml_dsa_enabled);
    println!("  - Memory pool: {}", config.memory_pool_size);
    println!("  - Timeout multiplier: {}", config.handshake_timeout_multiplier);

    // Verify algorithm selection
    let ml_kem_only = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(false)
        .build()
        .unwrap();
    assert!(ml_kem_only.ml_kem_enabled);
    assert!(!ml_kem_only.ml_dsa_enabled);

    let ml_dsa_only = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(true)
        .build()
        .unwrap();
    assert!(!ml_dsa_only.ml_kem_enabled);
    assert!(ml_dsa_only.ml_dsa_enabled);
    println!("\nAlgorithm selection validated");

    // Verify performance tuning
    let perf_config = PqcConfigBuilder::default()
        .memory_pool_size(100)
        .handshake_timeout_multiplier(3.0)
        .build()
        .unwrap();
    assert_eq!(perf_config.memory_pool_size, 100);
    assert_eq!(perf_config.handshake_timeout_multiplier, 3.0);
    println!("Performance tuning options working");

    println!("\n=== v0.13.0+ Basic PQC Integration Complete ===");
    println!("  - Configuration validated");
    println!("  - Error types available");
    println!("  - PQC always enabled");

    println!("\n=== Tests Passed ===\n");
}
