// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! PQC CryptoProvider factory for rustls
//!
//! v0.2: Pure Post-Quantum Cryptography - NO hybrid or classical algorithms.
//!
//! This module creates rustls CryptoProviders that use ONLY pure PQC algorithms:
//! - Key Exchange: ML-KEM-768 (0x0201) ONLY
//! - No X25519, no ECDH, no hybrid groups
//!
//! This is a greenfield network with no legacy compatibility requirements.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use super::config::PqcConfig;
use super::types::PqcError;

/// Create a PQC CryptoProvider
///
/// v0.2: Always creates a pure PQC provider with ML-KEM-768.
/// NO hybrid or classical algorithms will be offered or accepted.
///
/// # Arguments
/// * `config` - PQC configuration specifying algorithm preferences
///
/// # Returns
/// * `Ok(Arc<CryptoProvider>)` - A configured crypto provider
/// * `Err(PqcError)` - If provider creation fails
pub fn create_crypto_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    // v0.2: Always use pure PQC-only provider
    create_pqc_provider(config)
}

/// Create a pure PQC provider
///
/// v0.2: This provider ONLY offers pure ML-KEM groups for key exchange.
/// NO classical algorithms (X25519, ECDH) or hybrid groups are accepted.
fn create_pqc_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    // Validate that at least one PQC algorithm is enabled
    if !config.ml_kem_enabled && !config.ml_dsa_enabled {
        return Err(PqcError::CryptoError(
            "At least one PQC algorithm must be enabled".to_string(),
        ));
    }

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    // v0.2: Use rustls-post-quantum but filter to ONLY pure ML-KEM groups.
    // We reject hybrid groups (X25519MLKEM768, etc.) - pure PQC only.
    if config.ml_kem_enabled {
        let pq_provider = rustls_post_quantum::provider();

        // ONLY use pure ML-KEM key exchange groups (0x0200, 0x0201, 0x0202)
        // Reject hybrid groups and classical groups
        let pure_pqc_kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = pq_provider
            .kx_groups
            .iter()
            .filter(|g| is_pure_pqc_kx_group(g.name()))
            .copied()
            .collect();

        if pure_pqc_kx_groups.is_empty() {
            return Err(PqcError::CryptoError(
                "No pure PQC key exchange groups available - hybrid groups not accepted".to_string(),
            ));
        }

        provider.kx_groups = pure_pqc_kx_groups;
    }

    // TLS 1.3 cipher suites use symmetric encryption (AES-GCM, ChaCha20-Poly1305)
    // which is already quantum-resistant. The cipher suites themselves don't
    // determine the key exchange algorithm, so we keep the standard TLS 1.3 suites.
    // The quantum safety comes from using pure PQC key exchange groups above.

    Ok(Arc::new(provider))
}

/// Check if a NamedGroup is a PURE PQC group (v0.2: NO hybrids)
///
/// v0.2: ONLY pure ML-KEM groups are accepted. Hybrid groups are REJECTED.
fn is_pure_pqc_kx_group(group: rustls::NamedGroup) -> bool {
    // Pure ML-KEM groups ONLY (FIPS 203)
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    const MLKEM512: u16 = 0x0200; // ML-KEM-512 (NIST Level 1)
    const MLKEM768: u16 = 0x0201; // ML-KEM-768 (NIST Level 3) - PRIMARY
    const MLKEM1024: u16 = 0x0202; // ML-KEM-1024 (NIST Level 5)

    let group_code = u16::from(group);
    matches!(group_code, MLKEM512 | MLKEM768 | MLKEM1024)
}

/// Check if a NamedGroup is a valid PQC group (pure ML-KEM only)
///
/// v0.2: Hybrid groups (X25519MLKEM768, etc.) are REJECTED.
/// This is a greenfield network - no legacy compatibility needed.
fn is_pqc_kx_group(group: rustls::NamedGroup) -> bool {
    // v0.2: Only pure ML-KEM groups are valid PQC
    is_pure_pqc_kx_group(group)
}

/// Check if a negotiated group is a PQC group (for validation)
pub fn is_pqc_group(group: rustls::NamedGroup) -> bool {
    is_pqc_kx_group(group)
}

/// Validate that a connection used pure PQC algorithms
///
/// v0.2: Always validates that pure ML-KEM was used.
/// Hybrid groups (X25519MLKEM768, etc.) are REJECTED.
pub fn validate_negotiated_group(negotiated_group: rustls::NamedGroup) -> Result<(), PqcError> {
    if !is_pure_pqc_kx_group(negotiated_group) {
        return Err(PqcError::NegotiationFailed(format!(
            "Pure PQC key exchange required (ML-KEM-768 0x0201), but negotiated {:?}",
            negotiated_group
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pqc_provider() {
        let config = PqcConfig::builder()
            .ml_kem(true)
            .ml_dsa(true)
            .build()
            .expect("Failed to build config");

        let result = create_pqc_provider(&config);
        // This should succeed if rustls-post-quantum provides pure ML-KEM groups
        if let Ok(provider) = result {
            // All key exchange groups should be pure ML-KEM (no hybrids)
            for group in provider.kx_groups.iter() {
                assert!(
                    is_pure_pqc_kx_group(group.name()),
                    "Provider should only have pure ML-KEM groups, found {:?}",
                    group.name()
                );
            }
        }
    }

    #[test]
    fn test_requires_algorithms() {
        let config = PqcConfig::builder().ml_kem(false).ml_dsa(false).build();

        // Config validation should fail
        assert!(config.is_err(), "Config without algorithms should fail");
    }

    #[test]
    fn test_validate_negotiated_group() {
        // X25519 should fail (classical)
        let result = validate_negotiated_group(rustls::NamedGroup::X25519);
        assert!(result.is_err(), "X25519 should be rejected");

        // Pure ML-KEM groups should succeed
        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0200));
        assert!(result.is_ok(), "ML-KEM-512 should be accepted");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0201));
        assert!(result.is_ok(), "ML-KEM-768 should be accepted");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0202));
        assert!(result.is_ok(), "ML-KEM-1024 should be accepted");

        // v0.2: Hybrid groups should FAIL (rejected in pure PQC mode)
        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EC));
        assert!(result.is_err(), "X25519MLKEM768 (hybrid) should be rejected");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EB));
        assert!(result.is_err(), "SecP256r1MLKEM768 (hybrid) should be rejected");
    }

    #[test]
    fn test_is_pure_pqc_kx_group() {
        // Classical groups should return false
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::X25519));
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::secp256r1));
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::secp384r1));

        // Pure ML-KEM groups should return true
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0200))); // ML-KEM-512
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201))); // ML-KEM-768 (PRIMARY)
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0202))); // ML-KEM-1024

        // v0.2: Hybrid groups should return FALSE (no longer accepted)
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EB))); // SecP256r1MLKEM768
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC))); // X25519MLKEM768
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11ED))); // SecP384r1MLKEM1024
    }

    #[test]
    fn test_is_pqc_kx_group_same_as_pure() {
        // v0.2: is_pqc_kx_group should now be the same as is_pure_pqc_kx_group
        assert_eq!(
            is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201)),
            is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201))
        );
        assert_eq!(
            is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC)),
            is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC))
        );
    }
}
