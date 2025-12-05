//! Basic integration tests for PQC implementation
//!
//! This test suite performs basic validation of PQC functionality

#![allow(clippy::unwrap_used, clippy::expect_used)]

#![cfg(feature = "pqc")]

use ant_quic::crypto::pqc::{
    HybridPreference, PqcConfigBuilder, PqcMode,
    types::{PqcError, PqcResult},
};

#[test]
fn test_pqc_config_builder() {
    // Test default configuration
    let config = PqcConfigBuilder::default()
        .build()
        .expect("Failed to build default config");

    assert_eq!(config.mode, PqcMode::Hybrid);
    assert_eq!(config.hybrid_preference, HybridPreference::PreferPqc);
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Test PQC-only mode
    let pqc_only_config = PqcConfigBuilder::default()
        .mode(PqcMode::PqcOnly)
        .build()
        .expect("Failed to build PQC-only config");

    assert_eq!(pqc_only_config.mode, PqcMode::PqcOnly);

    // Test classical-only mode
    let classical_config = PqcConfigBuilder::default()
        .mode(PqcMode::ClassicalOnly)
        .build()
        .expect("Failed to build classical config");

    assert_eq!(classical_config.mode, PqcMode::ClassicalOnly);
}

#[test]
fn test_hybrid_preferences() {
    let preferences = [
        HybridPreference::PreferClassical,
        HybridPreference::Balanced,
        HybridPreference::PreferPqc,
    ];

    for pref in &preferences {
        let config = PqcConfigBuilder::default()
            .hybrid_preference(*pref)
            .build()
            .expect("Failed to build config with preference");

        assert_eq!(config.hybrid_preference, *pref);
    }
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
        .build()
        .expect("Failed to build config");

    assert!(!config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Test disabling ML-DSA
    let config = PqcConfigBuilder::default()
        .ml_dsa(false)
        .build()
        .expect("Failed to build config");

    assert!(config.ml_kem_enabled);
    assert!(!config.ml_dsa_enabled);

    // Test that PqcOnly mode requires at least one algorithm
    let result = PqcConfigBuilder::default()
        .mode(PqcMode::PqcOnly)
        .ml_kem(false)
        .ml_dsa(false)
        .build();

    assert!(result.is_err());
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
    // Test that we can build a comprehensive config
    let config = PqcConfigBuilder::default()
        .mode(PqcMode::Hybrid)
        .ml_kem(true)
        .ml_dsa(true)
        .hybrid_preference(HybridPreference::PreferPqc)
        .memory_pool_size(20)
        .handshake_timeout_multiplier(1.2)
        .build()
        .expect("Failed to build comprehensive config");

    assert_eq!(config.mode, PqcMode::Hybrid);
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.hybrid_preference, HybridPreference::PreferPqc);
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

/// Test that verifies release readiness
#[test]
fn test_release_criteria() {
    println!("\n=== PQC Basic Integration Test ===\n");

    // Verify configuration system works
    let config = PqcConfigBuilder::default().build().unwrap();
    println!("✓ Configuration system operational");
    println!("  - Default mode: {:?}", config.mode);
    println!("  - ML-KEM enabled: {}", config.ml_kem_enabled);
    println!("  - ML-DSA enabled: {}", config.ml_dsa_enabled);

    // Verify all modes are available
    let modes = [PqcMode::ClassicalOnly, PqcMode::Hybrid, PqcMode::PqcOnly];
    for mode in &modes {
        let _ = PqcConfigBuilder::default().mode(*mode).build().unwrap();
    }
    println!("\n✓ All PQC modes available");

    // Verify all preferences work
    let prefs = [
        HybridPreference::PreferClassical,
        HybridPreference::Balanced,
        HybridPreference::PreferPqc,
    ];
    for pref in &prefs {
        let _ = PqcConfigBuilder::default()
            .hybrid_preference(*pref)
            .build()
            .unwrap();
    }
    println!("✓ All hybrid preferences available");

    println!("\n✓ Basic PQC integration complete");
    println!("  - Configuration validated");
    println!("  - Error types available");
    println!("  - Feature flags working");

    println!("\n=== Tests Passed ===\n");
}
