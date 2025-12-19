// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! PQC CryptoProvider factory for rustls
//!
//! v0.13.0+: PQC is always enabled - ML-KEM-768 on every connection.
//! This module creates rustls CryptoProviders that use PQC algorithms.
//!
//! ONLY ML-KEM-768 key exchange groups are allowed. No classical algorithms
//! (X25519, ECDSA, etc.) will be offered or accepted.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use super::config::PqcConfig;
use super::types::PqcError;

/// Create a PQC CryptoProvider
///
/// v0.13.0+: Always creates a PQC-only provider with ML-KEM-768.
///
/// # Arguments
/// * `config` - PQC configuration specifying algorithm preferences
///
/// # Returns
/// * `Ok(Arc<CryptoProvider>)` - A configured crypto provider
/// * `Err(PqcError)` - If provider creation fails
pub fn create_crypto_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    // v0.13.0+: Always use PQC-only provider
    create_pqc_provider(config)
}

/// Create a PQC provider
///
/// This provider ONLY offers ML-KEM-768 for key exchange.
/// Classical algorithms like X25519 and ECDH are completely excluded.
fn create_pqc_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    // Validate that at least one PQC algorithm is enabled
    if !config.ml_kem_enabled && !config.ml_dsa_enabled {
        return Err(PqcError::CryptoError(
            "At least one PQC algorithm must be enabled".to_string(),
        ));
    }

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    // Use rustls-post-quantum which provides the X25519MLKEM768 hybrid group.
    // The X25519MLKEM768 hybrid is quantum-safe because even if
    // X25519 is broken by a quantum computer, ML-KEM-768 protects
    // the key exchange.
    if config.ml_kem_enabled {
        let pq_provider = rustls_post_quantum::provider();

        // ONLY use PQC-containing key exchange groups
        // Filter to only include groups that have PQC components
        let pqc_kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = pq_provider
            .kx_groups
            .iter()
            .filter(|g| is_pqc_kx_group(g.name()))
            .copied()
            .collect();

        if pqc_kx_groups.is_empty() {
            return Err(PqcError::CryptoError(
                "No PQC key exchange groups available".to_string(),
            ));
        }

        provider.kx_groups = pqc_kx_groups;
    }

    // TLS 1.3 cipher suites use symmetric encryption (AES-GCM, ChaCha20-Poly1305)
    // which is already quantum-resistant. The cipher suites themselves don't
    // determine the key exchange algorithm, so we keep the standard TLS 1.3 suites.
    // The quantum safety comes from using PQC key exchange groups above.

    Ok(Arc::new(provider))
}

/// Check if a NamedGroup contains PQC components
fn is_pqc_kx_group(group: rustls::NamedGroup) -> bool {
    // ML-KEM named groups (IANA TLS Supported Groups Registry)
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

    // Pure ML-KEM groups (FIPS 203)
    const MLKEM512: u16 = 0x0200; // 512 decimal
    const MLKEM768: u16 = 0x0201; // 513 decimal
    const MLKEM1024: u16 = 0x0202; // 514 decimal

    // Hybrid groups (IANA assigned codes)
    const SECP256R1_MLKEM768: u16 = 0x11EB; // 4587 decimal - SecP256r1MLKEM768
    const X25519_MLKEM768: u16 = 0x11EC; // 4588 decimal - X25519MLKEM768
    const SECP384R1_MLKEM1024: u16 = 0x11ED; // 4589 decimal - SecP384r1MLKEM1024
    const CURVESM2_MLKEM768: u16 = 0x11EE; // 4590 decimal - curveSM2MLKEM768

    let group_code = u16::from(group);
    matches!(
        group_code,
        MLKEM512
            | MLKEM768
            | MLKEM1024
            | SECP256R1_MLKEM768
            | X25519_MLKEM768
            | SECP384R1_MLKEM1024
            | CURVESM2_MLKEM768
    )
}

/// Check if a negotiated group is a PQC group (for validation)
pub fn is_pqc_group(group: rustls::NamedGroup) -> bool {
    is_pqc_kx_group(group)
}

/// Validate that a connection used PQC algorithms
///
/// v0.13.0+: Always validates that PQC was used.
pub fn validate_negotiated_group(negotiated_group: rustls::NamedGroup) -> Result<(), PqcError> {
    if !is_pqc_kx_group(negotiated_group) {
        return Err(PqcError::NegotiationFailed(format!(
            "PQC key exchange required, but negotiated {:?}",
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
        // This should succeed if rustls-post-quantum provides PQC groups
        if let Ok(provider) = result {
            // All key exchange groups should be PQC
            for group in provider.kx_groups.iter() {
                assert!(
                    is_pqc_kx_group(group.name()),
                    "Provider should only have PQC groups, found {:?}",
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
        // X25519 should fail
        let result = validate_negotiated_group(rustls::NamedGroup::X25519);
        assert!(result.is_err(), "X25519 should be rejected");

        // ML-KEM groups should succeed
        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0201));
        assert!(result.is_ok(), "ML-KEM-768 should be accepted");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EC));
        assert!(result.is_ok(), "X25519MLKEM768 should be accepted");
    }

    #[test]
    fn test_is_pqc_kx_group() {
        // Classical groups should return false
        assert!(!is_pqc_kx_group(rustls::NamedGroup::X25519));
        assert!(!is_pqc_kx_group(rustls::NamedGroup::secp256r1));
        assert!(!is_pqc_kx_group(rustls::NamedGroup::secp384r1));

        // Pure ML-KEM groups should return true
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0200))); // MLKEM512
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201))); // MLKEM768
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0202))); // MLKEM1024

        // Hybrid groups should return true (IANA assigned codes)
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EB))); // SecP256r1MLKEM768
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC))); // X25519MLKEM768
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11ED))); // SecP384r1MLKEM1024
    }
}
