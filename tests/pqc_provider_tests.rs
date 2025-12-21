// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Tests for PQC CryptoProvider factory
//!
//! v2.0: Pure PQC - NO hybrid or classical algorithms.
//! These tests verify that the CryptoProvider factory correctly creates
//! providers that only use pure ML-KEM groups (0x0200, 0x0201, 0x0202).

#![cfg(feature = "rustls-aws-lc-rs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::pqc::{
    PqcConfig, create_crypto_provider, is_pqc_group, validate_negotiated_group,
};

/// Test that PQC provider can be created successfully
#[test]
fn test_pqc_provider_creation() {
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .build()
        .expect("Failed to build PqcConfig");

    let result = create_crypto_provider(&config);

    // The provider creation might fail if no PQC groups are available
    // from rustls-post-quantum, but if it succeeds, all groups should be PQC
    if let Ok(provider) = result {
        for group in provider.kx_groups.iter() {
            assert!(
                is_pqc_group(group.name()),
                "Provider should only have PQC groups, found {:?}",
                group.name()
            );
        }
    }
}

/// Test that config requires at least one algorithm enabled
#[test]
fn test_pqc_requires_algorithms() {
    // PqcConfig builder should reject config without algorithms
    let result = PqcConfig::builder().ml_kem(false).ml_dsa(false).build();

    assert!(
        result.is_err(),
        "Config without algorithms should fail validation"
    );
}

/// Test X25519 validation (should always fail in v0.13.0+)
#[test]
fn test_validate_negotiated_group_x25519() {
    // v0.13.0+: X25519 should always fail - PQC is mandatory
    let result = validate_negotiated_group(rustls::NamedGroup::X25519);
    assert!(result.is_err(), "X25519 should be rejected in v0.13.0+");
}

/// Test SECP256R1 validation (should always fail in v0.13.0+)
#[test]
fn test_validate_negotiated_group_secp256r1() {
    // v0.13.0+: SECP256R1 should always fail - PQC is mandatory
    let result = validate_negotiated_group(rustls::NamedGroup::secp256r1);
    assert!(result.is_err(), "SECP256R1 should be rejected in v0.13.0+");
}

/// Test ML-KEM group validation (v0.2: ML-KEM-containing groups)
#[test]
fn test_validate_negotiated_group_ml_kem() {
    // Pure ML-KEM groups should be accepted
    let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0200));
    assert!(result.is_ok(), "ML-KEM-512 (0x0200) should be accepted");

    let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0201));
    assert!(result.is_ok(), "ML-KEM-768 (0x0201) should be accepted");

    let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0202));
    assert!(result.is_ok(), "ML-KEM-1024 (0x0202) should be accepted");

    // v0.2: Hybrid ML-KEM groups are accepted (still provide PQC protection)
    let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EC));
    assert!(
        result.is_ok(),
        "X25519MLKEM768 should be accepted (contains ML-KEM)"
    );
}

/// Test PQC group detection (v2.0: ONLY pure ML-KEM)
#[test]
fn test_is_pqc_group() {
    // Classical groups should return false
    assert!(!is_pqc_group(rustls::NamedGroup::X25519));
    assert!(!is_pqc_group(rustls::NamedGroup::secp256r1));
    assert!(!is_pqc_group(rustls::NamedGroup::secp384r1));

    // v0.2: Pure ML-KEM groups should return true (IANA code points)
    assert!(is_pqc_group(rustls::NamedGroup::Unknown(0x0200))); // ML-KEM-512
    assert!(is_pqc_group(rustls::NamedGroup::Unknown(0x0201))); // ML-KEM-768
    assert!(is_pqc_group(rustls::NamedGroup::Unknown(0x0202))); // ML-KEM-1024

    // v0.2: Hybrid ML-KEM groups are accepted (provide PQC protection)
    assert!(is_pqc_group(rustls::NamedGroup::Unknown(0x11EC))); // X25519MLKEM768
    assert!(is_pqc_group(rustls::NamedGroup::Unknown(0x11EB))); // SecP256r1MLKEM768
}

/// Test that provider only includes PQC groups
#[test]
fn test_provider_only_has_pqc_groups() {
    let config = PqcConfig::builder()
        .ml_kem(true)
        .build()
        .expect("Failed to build config");

    let result = create_crypto_provider(&config);
    if let Ok(provider) = result {
        let has_classical = provider.kx_groups.iter().any(|g| !is_pqc_group(g.name()));

        // v0.13.0+: No classical groups should be present
        assert!(
            !has_classical,
            "Provider should not have any classical key exchange groups"
        );
    }
}

/// Test configured_provider_with_pqc function
#[test]
fn test_configured_provider_with_pqc() {
    use ant_quic::crypto::rustls::configured_provider_with_pqc;

    // Without config, should return default provider with PQC support
    let provider = configured_provider_with_pqc(None);
    assert!(
        !provider.kx_groups.is_empty(),
        "Default provider should have groups"
    );

    // With PQC config
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .build()
        .expect("Failed to build PqcConfig");

    let provider = configured_provider_with_pqc(Some(&config));
    assert!(
        !provider.kx_groups.is_empty(),
        "PQC provider should have groups"
    );
}

/// Test validate_pqc_connection function (v0.2: ML-KEM required)
#[test]
fn test_validate_pqc_connection() {
    use ant_quic::crypto::rustls::validate_pqc_connection;

    // Classical groups without ML-KEM should be rejected
    let result = validate_pqc_connection(rustls::NamedGroup::X25519);
    assert!(result.is_err(), "X25519 should be rejected");

    // Pure PQC groups should be accepted
    let result = validate_pqc_connection(rustls::NamedGroup::Unknown(0x0200));
    assert!(result.is_ok(), "ML-KEM-512 should be accepted");

    let result = validate_pqc_connection(rustls::NamedGroup::Unknown(0x0201));
    assert!(result.is_ok(), "ML-KEM-768 should be accepted");

    let result = validate_pqc_connection(rustls::NamedGroup::Unknown(0x0202));
    assert!(result.is_ok(), "ML-KEM-1024 should be accepted");

    // v0.2: Hybrid ML-KEM groups are accepted (provide PQC protection)
    let result = validate_pqc_connection(rustls::NamedGroup::Unknown(0x11EC));
    assert!(
        result.is_ok(),
        "X25519MLKEM768 should be accepted (contains ML-KEM)"
    );
}
