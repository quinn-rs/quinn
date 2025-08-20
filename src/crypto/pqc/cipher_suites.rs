// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Hybrid cipher suites for post-quantum TLS
//!
//! This module defines cipher suites that combine classical and post-quantum
//! algorithms for key exchange while using standard AEAD for encryption.

use rustls::{
    CipherSuite, NamedGroup, SignatureScheme, SupportedCipherSuite,
    crypto::{ActiveKeyExchange, SupportedKxGroup},
};

/// Hybrid named groups for key exchange
pub mod named_groups {
    use rustls::NamedGroup;

    /// X25519 + ML-KEM-768 hybrid
    pub const X25519_MLKEM768: NamedGroup = NamedGroup::Unknown(0x01FD);

    /// P256 + ML-KEM-768 hybrid
    pub const P256_MLKEM768: NamedGroup = NamedGroup::Unknown(0x01FE);

    /// X25519 + ML-KEM-1024 hybrid
    pub const X25519_MLKEM1024: NamedGroup = NamedGroup::Unknown(0x01FF);
}

/// Hybrid signature schemes
pub mod signature_schemes {
    use rustls::SignatureScheme;

    /// Ed25519 + ML-DSA-65 hybrid
    pub const ED25519_MLDSA65: SignatureScheme = SignatureScheme::Unknown(0xFE3D);

    /// P256 + ML-DSA-65 hybrid
    pub const P256_MLDSA65: SignatureScheme = SignatureScheme::Unknown(0xFE3E);

    /// RSA-PSS + ML-DSA-65 hybrid
    pub const RSA_PSS_MLDSA65: SignatureScheme = SignatureScheme::Unknown(0xFE3F);
}

/// Placeholder cipher suite structures
/// These would need full implementation when rustls provides extension points
///
/// TLS 1.3 AES-128-GCM with SHA-256 and ML-KEM-768
pub struct Tls13Aes128GcmSha256MlKem768;

impl Tls13Aes128GcmSha256MlKem768 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_AES_128_GCM_SHA256
    }

    /// Get supported key exchange groups
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::X25519_MLKEM768, named_groups::P256_MLKEM768]
    }
}

/// TLS 1.3 AES-256-GCM with SHA-384 and ML-KEM-1024
pub struct Tls13Aes256GcmSha384MlKem1024;

impl Tls13Aes256GcmSha384MlKem1024 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_AES_256_GCM_SHA384
    }

    /// Get supported key exchange groups
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::X25519_MLKEM1024]
    }
}

/// TLS 1.3 ChaCha20-Poly1305 with SHA-256 and ML-KEM-768
pub struct Tls13ChaCha20Poly1305Sha256MlKem768;

impl Tls13ChaCha20Poly1305Sha256MlKem768 {
    /// Get the base cipher suite
    pub fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    }

    /// Get supported key exchange groups
    pub fn key_exchange_groups(&self) -> Vec<NamedGroup> {
        vec![named_groups::X25519_MLKEM768, named_groups::P256_MLKEM768]
    }
}

// Static instances for use in tests
pub static TLS13_AES_128_GCM_SHA256_MLKEM768: Tls13Aes128GcmSha256MlKem768 =
    Tls13Aes128GcmSha256MlKem768;

pub static TLS13_AES_256_GCM_SHA384_MLKEM1024: Tls13Aes256GcmSha384MlKem1024 =
    Tls13Aes256GcmSha384MlKem1024;

pub static TLS13_CHACHA20_POLY1305_SHA256_MLKEM768: Tls13ChaCha20Poly1305Sha256MlKem768 =
    Tls13ChaCha20Poly1305Sha256MlKem768;

/// Check if a named group is a hybrid PQC group
pub fn is_hybrid_group(group: NamedGroup) -> bool {
    matches!(
        group,
        named_groups::X25519_MLKEM768
            | named_groups::P256_MLKEM768
            | named_groups::X25519_MLKEM1024
    )
}

/// Check if a signature scheme is hybrid PQC
pub fn is_hybrid_signature(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        signature_schemes::ED25519_MLDSA65
            | signature_schemes::P256_MLDSA65
            | signature_schemes::RSA_PSS_MLDSA65
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_group_detection() {
        assert!(is_hybrid_group(named_groups::X25519_MLKEM768));
        assert!(is_hybrid_group(named_groups::P256_MLKEM768));
        assert!(!is_hybrid_group(NamedGroup::X25519));
        // P256 is not available in rustls NamedGroup enum
        assert!(!is_hybrid_group(NamedGroup::Unknown(0x0017))); // P256 value
    }

    #[test]
    fn test_hybrid_signature_detection() {
        assert!(is_hybrid_signature(signature_schemes::ED25519_MLDSA65));
        assert!(is_hybrid_signature(signature_schemes::P256_MLDSA65));
        assert!(!is_hybrid_signature(SignatureScheme::ED25519));
        assert!(!is_hybrid_signature(SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn test_cipher_suite_properties() {
        let suite = &TLS13_AES_128_GCM_SHA256_MLKEM768;
        assert_eq!(suite.suite(), CipherSuite::TLS13_AES_128_GCM_SHA256);

        let groups = suite.key_exchange_groups();
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|&g| is_hybrid_group(g)));
    }
}
