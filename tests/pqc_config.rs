//! Tests for Post-Quantum Cryptography configuration API
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! These tests verify the simplified PqcConfig API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::pqc::PqcConfig;
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
    // v0.13.0+: PQC is always on, config just tunes parameters
    let pqc_config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
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
fn test_pqc_config_default_values() {
    let config = PqcConfig::default();

    // v0.13.0+: Both algorithms enabled by default
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Reasonable defaults for performance
    assert_eq!(config.memory_pool_size, 10);
    assert_eq!(config.handshake_timeout_multiplier, 2.0);
}

#[test]
fn test_pqc_config_builder_chaining() {
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(50)
        .handshake_timeout_multiplier(3.0)
        .build()
        .unwrap();

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.memory_pool_size, 50);
    assert_eq!(config.handshake_timeout_multiplier, 3.0);
}

#[test]
fn test_pqc_config_requires_at_least_one_algorithm() {
    // v0.13.0+: Must have at least one PQC algorithm enabled
    let result = PqcConfig::builder()
        .ml_kem(false)
        .ml_dsa(false)
        .build();

    assert!(result.is_err(), "Config without algorithms should fail");
}

#[test]
fn test_ml_kem_only_configuration() {
    // Enable only ML-KEM for key exchange
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(false)
        .build()
        .unwrap();

    assert!(config.ml_kem_enabled);
    assert!(!config.ml_dsa_enabled);
}

#[test]
fn test_ml_dsa_only_configuration() {
    // Enable only ML-DSA for signatures
    let config = PqcConfig::builder()
        .ml_kem(false)
        .ml_dsa(true)
        .build()
        .unwrap();

    assert!(!config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
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
fn test_high_latency_network_configuration() {
    // Configure for slow/high-latency networks
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .handshake_timeout_multiplier(4.0) // Allow more time for larger PQC handshakes
        .build()
        .unwrap();

    assert_eq!(config.handshake_timeout_multiplier, 4.0);
}

#[test]
fn test_high_concurrency_configuration() {
    // Configure for servers with many connections
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(200) // Large pool for concurrent PQC operations
        .build()
        .unwrap();

    assert_eq!(config.memory_pool_size, 200);
}

#[test]
fn test_minimal_configuration() {
    // Minimal configuration for testing environments
    let config = PqcConfig::builder()
        .ml_kem(true)
        .memory_pool_size(5) // Smaller pool for testing
        .build()
        .unwrap();

    assert!(config.ml_kem_enabled);
    assert_eq!(config.memory_pool_size, 5);
}
