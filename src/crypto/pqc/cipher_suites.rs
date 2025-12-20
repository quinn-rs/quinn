// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Pure PQC cipher suites for post-quantum TLS
//!
//! v0.2: Pure Post-Quantum Cryptography - NO hybrid or classical algorithms.
//!
//! This module defines cipher suites with pure PQC key exchange:
//! - Key Exchange: ML-KEM-768 (0x0201) ONLY
//! - Signatures: ML-DSA-65 (0x0901) ONLY
//!
//! This is a greenfield network with no legacy compatibility requirements.

use rustls::{
    CipherSuite, NamedGroup, SignatureScheme, SupportedCipherSuite,
    crypto::{ActiveKeyExchange, SupportedKxGroup},
};

/// Pure PQC named groups for key exchange
///
/// v0.2: ONLY pure ML-KEM groups with correct IANA code points.
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
pub mod named_groups {
    use rustls::NamedGroup;

    /// ML-KEM-512 (NIST Level 1)
    pub const MLKEM512: NamedGroup = NamedGroup::Unknown(0x0200);

    /// ML-KEM-768 (NIST Level 3) - PRIMARY
    pub const MLKEM768: NamedGroup = NamedGroup::Unknown(0x0201);

    /// ML-KEM-1024 (NIST Level 5)
    pub const MLKEM1024: NamedGroup = NamedGroup::Unknown(0x0202);
}

/// Pure PQC signature schemes
///
/// v0.2: ONLY pure ML-DSA schemes with correct IANA code points.
pub mod signature_schemes {
    use rustls::SignatureScheme;

    /// ML-DSA-44 (NIST Level 2)
    pub const MLDSA44: SignatureScheme = SignatureScheme::Unknown(0x0900);

    /// ML-DSA-65 (NIST Level 3) - PRIMARY
    pub const MLDSA65: SignatureScheme = SignatureScheme::Unknown(0x0901);

    /// ML-DSA-87 (NIST Level 5)
    pub const MLDSA87: SignatureScheme = SignatureScheme::Unknown(0x0902);
}

/// Placeholder cipher suite structures
/// These would need full implementation when rustls provides extension points
///
/// v0.2: TLS 1.3 AES-128-GCM with SHA-256 and pure ML-KEM-768
pub struct Tls13Aes128GcmSha256MlKem768;

impl Tls13Aes128GcmSha256MlKem768 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_AES_128_GCM_SHA256
    }

    /// Get supported key exchange groups (v0.2: pure ML-KEM only)
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::MLKEM768, named_groups::MLKEM1024]
    }
}

/// v0.2: TLS 1.3 AES-256-GCM with SHA-384 and pure ML-KEM-1024
pub struct Tls13Aes256GcmSha384MlKem1024;

impl Tls13Aes256GcmSha384MlKem1024 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_AES_256_GCM_SHA384
    }

    /// Get supported key exchange groups (v0.2: pure ML-KEM only)
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::MLKEM1024]
    }
}

/// v0.2: TLS 1.3 ChaCha20-Poly1305 with SHA-256 and pure ML-KEM-768
pub struct Tls13ChaCha20Poly1305Sha256MlKem768;

impl Tls13ChaCha20Poly1305Sha256MlKem768 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    }

    /// Get supported key exchange groups (v0.2: pure ML-KEM only)
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::MLKEM768, named_groups::MLKEM1024]
    }
}

// Static instances for use in tests
pub static TLS13_AES_128_GCM_SHA256_MLKEM768: Tls13Aes128GcmSha256MlKem768 =
    Tls13Aes128GcmSha256MlKem768;

pub static TLS13_AES_256_GCM_SHA384_MLKEM1024: Tls13Aes256GcmSha384MlKem1024 =
    Tls13Aes256GcmSha384MlKem1024;

pub static TLS13_CHACHA20_POLY1305_SHA256_MLKEM768: Tls13ChaCha20Poly1305Sha256MlKem768 =
    Tls13ChaCha20Poly1305Sha256MlKem768;

/// Check if a named group is a pure PQC group (v0.2: NO hybrids)
pub fn is_pqc_group(group: NamedGroup) -> bool {
    matches!(
        group,
        named_groups::MLKEM512 | named_groups::MLKEM768 | named_groups::MLKEM1024
    )
}

/// Check if a signature scheme is pure PQC (v0.2: NO hybrids)
pub fn is_pqc_signature(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        signature_schemes::MLDSA44 | signature_schemes::MLDSA65 | signature_schemes::MLDSA87
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_group_detection() {
        // v0.2: Pure ML-KEM groups
        assert!(is_pqc_group(named_groups::MLKEM512));
        assert!(is_pqc_group(named_groups::MLKEM768));
        assert!(is_pqc_group(named_groups::MLKEM1024));

        // Classical groups should not be detected as PQC
        assert!(!is_pqc_group(NamedGroup::X25519));
        assert!(!is_pqc_group(NamedGroup::Unknown(0x0017))); // P256 value
    }

    #[test]
    fn test_pqc_signature_detection() {
        // v0.2: Pure ML-DSA schemes
        assert!(is_pqc_signature(signature_schemes::MLDSA44));
        assert!(is_pqc_signature(signature_schemes::MLDSA65));
        assert!(is_pqc_signature(signature_schemes::MLDSA87));

        // Classical schemes should not be detected as PQC
        assert!(!is_pqc_signature(SignatureScheme::ED25519));
        assert!(!is_pqc_signature(SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn test_cipher_suite_properties() {
        let suite = &TLS13_AES_128_GCM_SHA256_MLKEM768;
        assert_eq!(suite.suite(), CipherSuite::TLS13_AES_128_GCM_SHA256);

        let groups = suite.key_exchange_groups();
        assert!(!groups.is_empty());
        // v0.2: All groups should be pure PQC
        assert!(groups.iter().all(|&g| is_pqc_group(g)));
    }

    #[test]
    fn test_named_group_codes() {
        // v0.2: Verify correct IANA code points
        assert_eq!(u16::from(named_groups::MLKEM512), 0x0200);
        assert_eq!(u16::from(named_groups::MLKEM768), 0x0201);
        assert_eq!(u16::from(named_groups::MLKEM1024), 0x0202);
    }

    #[test]
    fn test_signature_scheme_codes() {
        // v0.2: Verify correct IANA code points
        assert_eq!(u16::from(signature_schemes::MLDSA44), 0x0900);
        assert_eq!(u16::from(signature_schemes::MLDSA65), 0x0901);
        assert_eq!(u16::from(signature_schemes::MLDSA87), 0x0902);
    }
}
