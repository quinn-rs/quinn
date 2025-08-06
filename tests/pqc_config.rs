//! Tests for Post-Quantum Cryptography configuration API

use ant_quic::crypto::pqc::{HybridPreference, PqcConfig, PqcMode};
use ant_quic::{
    EndpointConfig,
    crypto::{CryptoError, HmacKey},
};
use std::sync::Arc;

/// Dummy HMAC key for testing
struct TestHmacKey;

impl HmacKey for TestHmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        // Dummy implementation for testing
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        // Dummy verification for testing
        if signature.len() >= self.signature_len() {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

#[test]
fn test_pqc_config_integration_with_endpoint() {
    // Create a PQC config
    let pqc_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::PreferPqc)
        .memory_pool_size(20)
        .build()
        .unwrap();

    // Create an endpoint config
    let reset_key: Arc<dyn HmacKey> = Arc::new(TestHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);

    // Set PQC config
    endpoint_config.pqc_config(pqc_config.clone());

    // Verify it was set (we can't directly access it due to pub(crate), but this tests compilation)
    // In a real scenario, the endpoint would use this config during connection establishment
}

#[test]
fn test_pqc_config_default_is_safe() {
    let config = PqcConfig::default();

    // Default should be Hybrid mode for compatibility
    assert_eq!(config.mode, PqcMode::Hybrid);

    // Both algorithms should be enabled by default
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Balanced preference is the safest default
    assert_eq!(config.hybrid_preference, HybridPreference::Balanced);

    // Reasonable defaults for performance
    assert_eq!(config.memory_pool_size, 10);
    assert_eq!(config.handshake_timeout_multiplier, 2.0);
}

#[test]
fn test_pqc_config_builder_chaining() {
    let config = PqcConfig::builder()
        .mode(PqcMode::PqcOnly)
        .ml_kem(true)
        .ml_dsa(true)
        .hybrid_preference(HybridPreference::PreferPqc)
        .memory_pool_size(50)
        .handshake_timeout_multiplier(3.0)
        .build()
        .unwrap();

    assert_eq!(config.mode, PqcMode::PqcOnly);
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.hybrid_preference, HybridPreference::PreferPqc);
    assert_eq!(config.memory_pool_size, 50);
    assert_eq!(config.handshake_timeout_multiplier, 3.0);
}

#[test]
fn test_classical_only_configuration() {
    // For environments that don't want PQC yet
    let config = PqcConfig::builder()
        .mode(PqcMode::ClassicalOnly)
        .ml_kem(false)
        .ml_dsa(false)
        .build()
        .unwrap();

    assert_eq!(config.mode, PqcMode::ClassicalOnly);
    assert!(!config.ml_kem_enabled);
    assert!(!config.ml_dsa_enabled);
}

#[test]
fn test_pqc_only_with_selective_algorithms() {
    // Enable only ML-KEM for key exchange, use classical signatures
    let config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .ml_kem(true)
        .ml_dsa(false)
        .build()
        .unwrap();

    assert!(config.ml_kem_enabled);
    assert!(!config.ml_dsa_enabled);
}

#[test]
fn test_performance_tuning_options() {
    // Configure for high-performance environment
    let config = PqcConfig::builder()
        .memory_pool_size(100) // Larger pool for many concurrent connections
        .handshake_timeout_multiplier(1.5) // Less conservative timeout
        .build()
        .unwrap();

    assert_eq!(config.memory_pool_size, 100);
    assert_eq!(config.handshake_timeout_multiplier, 1.5);
}

#[test]
fn test_example_usage_patterns() {
    // Example 1: Conservative migration to PQC
    let conservative_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::PreferClassical)
        .build()
        .unwrap();

    assert_eq!(
        conservative_config.hybrid_preference,
        HybridPreference::PreferClassical
    );

    // Example 2: Aggressive PQC adoption
    let aggressive_config = PqcConfig::builder()
        .mode(PqcMode::Hybrid)
        .hybrid_preference(HybridPreference::PreferPqc)
        .handshake_timeout_multiplier(4.0) // Allow more time for larger handshakes
        .build()
        .unwrap();

    assert_eq!(
        aggressive_config.hybrid_preference,
        HybridPreference::PreferPqc
    );

    // Example 3: Testing PQC-only environment
    let test_config = PqcConfig::builder()
        .mode(PqcMode::PqcOnly)
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(5) // Smaller pool for testing
        .build()
        .unwrap();

    assert_eq!(test_config.mode, PqcMode::PqcOnly);
}
