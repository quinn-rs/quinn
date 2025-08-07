//! Focused tests for Raw Public Key implementation
//!
//! This test file validates the Phase 1-3 Raw Public Key functionality
//! without depending on the full codebase compilation.

#![cfg(feature = "rustls-ring")]

use ant_quic::crypto::{
    certificate_negotiation::{CertificateNegotiationManager, NegotiationConfig},
    raw_public_keys::{RawPublicKeyConfigBuilder, key_utils},
    tls_extensions::{CertificateType, CertificateTypeList, CertificateTypePreferences},
};

use std::time::Duration;

#[test]
fn test_raw_public_key_generation() {
    // Test Ed25519 key pair generation
    let (private_key, public_key) = key_utils::generate_ed25519_keypair();

    // Verify key sizes
    assert_eq!(private_key.as_bytes().len(), 32);
    assert_eq!(public_key.as_bytes().len(), 32);

    // Test public key extraction
    let key_bytes = key_utils::public_key_to_bytes(&public_key);
    assert_eq!(key_bytes.len(), 32);
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
    let (private_key, _public_key) = key_utils::generate_ed25519_keypair();

    // Build client config
    let client_builder = RawPublicKeyConfigBuilder::new()
        .allow_any_key()
        .enable_certificate_type_extensions();

    let client_result = client_builder.build_client_config();
    assert!(client_result.is_ok());

    // Build server config with separate builder
    let server_builder = RawPublicKeyConfigBuilder::new()
        .with_server_key(private_key)
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
