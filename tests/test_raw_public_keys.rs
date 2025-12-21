//! Focused tests for Raw Public Key implementation
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.
//! This test file validates the Pure PQC Raw Public Key functionality.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "rustls-aws-lc-rs")]

use ant_quic::crypto::{
    certificate_negotiation::{CertificateNegotiationManager, NegotiationConfig},
    raw_public_keys::{RawPublicKeyConfigBuilder, pqc::generate_ml_dsa_keypair},
    tls_extensions::{CertificateType, CertificateTypeList, CertificateTypePreferences},
};

use std::time::Duration;

// ML-DSA-65 key sizes (FIPS 204)
const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;

#[test]
fn test_raw_public_key_generation() {
    // Test ML-DSA-65 key pair generation
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

    // Verify key sizes match ML-DSA-65 specification
    assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
    assert_eq!(secret_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
}

#[test]
fn test_certificate_type_negotiation() {
    // Create negotiation manager
    let config = NegotiationConfig {
        timeout: Duration::from_secs(10),
        enable_caching: true,
        max_cache_size: 100,
        allow_fallback: true,
        default_preferences: CertificateTypePreferences::prefer_raw_public_key(),
    };

    let manager = CertificateNegotiationManager::new(config);

    // Start a negotiation
    let preferences = CertificateTypePreferences::raw_public_key_only();
    let id = manager.start_negotiation(preferences).unwrap();

    // Simulate remote preferences
    let remote_client_types = Some(
        CertificateTypeList::new(vec![CertificateType::RawPublicKey, CertificateType::X509])
            .unwrap(),
    );

    let remote_server_types =
        Some(CertificateTypeList::new(vec![CertificateType::RawPublicKey]).unwrap());

    // Complete negotiation
    let result = manager.complete_negotiation(id, remote_client_types, remote_server_types);
    assert!(result.is_ok());

    let negotiation_result = result.unwrap();
    assert_eq!(
        negotiation_result.client_cert_type,
        CertificateType::RawPublicKey
    );
    assert_eq!(
        negotiation_result.server_cert_type,
        CertificateType::RawPublicKey
    );
}

#[test]
fn test_certificate_type_preferences() {
    // Test Raw Public Key only preferences
    let rpk_only = CertificateTypePreferences::raw_public_key_only();
    assert!(rpk_only.client_types.supports_raw_public_key());
    assert!(!rpk_only.client_types.supports_x509());

    // Test prefer Raw Public Key (but support X.509)
    let prefer_rpk = CertificateTypePreferences::prefer_raw_public_key();
    assert!(prefer_rpk.client_types.supports_raw_public_key());
    assert!(prefer_rpk.client_types.supports_x509());
    assert_eq!(
        prefer_rpk.client_types.most_preferred(),
        CertificateType::RawPublicKey
    );
}

#[test]
fn test_negotiation_caching() {
    let config = NegotiationConfig::default();
    let manager = CertificateNegotiationManager::new(config);

    // Perform first negotiation
    let preferences = CertificateTypePreferences::prefer_raw_public_key();
    let id1 = manager.start_negotiation(preferences.clone()).unwrap();

    let remote_types = Some(CertificateTypeList::raw_public_key_only());
    let result1 = manager.complete_negotiation(id1, remote_types.clone(), remote_types.clone());
    assert!(result1.is_ok());

    // Check cache stats before second negotiation
    let stats = manager.get_stats();
    let initial_cache_misses = stats.cache_misses;

    // Perform second negotiation with same parameters
    let id2 = manager.start_negotiation(preferences).unwrap();
    let result2 = manager.complete_negotiation(id2, remote_types.clone(), remote_types);
    assert!(result2.is_ok());

    // Verify cache was used
    let final_stats = manager.get_stats();
    assert_eq!(final_stats.cache_hits, 1);
    assert_eq!(final_stats.cache_misses, initial_cache_misses); // Second negotiation should hit cache, not miss
}

#[test]
fn test_raw_public_key_config_builder() {
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

    // Build client config
    let client_builder = RawPublicKeyConfigBuilder::new()
        .allow_any_key()
        .enable_certificate_type_extensions();

    let client_result = client_builder.build_client_config();
    assert!(client_result.is_ok());

    // Build server config with separate builder - use with_client_key for ML-DSA
    let server_builder = RawPublicKeyConfigBuilder::new()
        .with_client_key(public_key, secret_key)
        .enable_certificate_type_extensions();

    let server_result = server_builder.build_server_config();
    assert!(server_result.is_ok());
}

#[test]
fn test_certificate_type_list() {
    // Test creating a valid list
    let list = CertificateTypeList::new(vec![CertificateType::RawPublicKey, CertificateType::X509]);
    assert!(list.is_ok());

    let list = list.unwrap();
    assert_eq!(list.types.len(), 2);
    assert!(list.supports_raw_public_key());
    assert!(list.supports_x509());

    // Test empty list is invalid
    let empty = CertificateTypeList::new(vec![]);
    assert!(empty.is_err());

    // Test factory methods
    let rpk_only = CertificateTypeList::raw_public_key_only();
    assert_eq!(rpk_only.types.len(), 1);
    assert_eq!(rpk_only.types[0], CertificateType::RawPublicKey);
}
