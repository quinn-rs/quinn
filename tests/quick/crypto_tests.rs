//! Quick cryptography tests
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

#[test]
fn test_basic_crypto_operations() {
    super::utils::assert_duration(Duration::from_millis(100), || {
        // Basic crypto operations are tested in unit tests
        // This is a placeholder for quick crypto tests
        // Placeholder test - implementation pending
    });
}

#[test]
fn test_key_generation_speed() {
    // ML-DSA-65 key generation is slower than Ed25519 - allow more time
    super::utils::assert_duration(Duration::from_millis(500), || {
        // Test that ML-DSA-65 key generation completes in reasonable time
        use ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair;
        let (_public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");
        // Test completed - ML-DSA-65 keypair generated successfully
    });
}
