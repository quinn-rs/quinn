// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! TLS extensions for Post-Quantum Cryptography
//!
//! This module provides TLS named groups and signature schemes for PQC algorithms,
//! following draft-ietf-tls-hybrid-design-14 and related specifications.

use crate::crypto::pqc::types::PqcError;
use std::fmt;

/// TLS Named Groups including hybrid PQC groups
///
/// Based on:
/// - draft-ietf-tls-hybrid-design-14
/// - draft-ietf-tls-ecdhe-mlkem-00
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NamedGroup {
    // Classical groups (from TLS 1.3)
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    // Pure PQC groups
    MlKem512 = 0x0200,  // ML-KEM-512 (NIST Level 1)
    MlKem768 = 0x0201,  // ML-KEM-768 (NIST Level 3)
    MlKem1024 = 0x0202, // ML-KEM-1024 (NIST Level 5)

    // Hybrid groups (Classical + PQC)
    X25519MlKem768 = 0x4F2A, // X25519 + ML-KEM-768
    P256MlKem768 = 0x4F2B,   // P-256 + ML-KEM-768
    P384MlKem1024 = 0x4F2C,  // P-384 + ML-KEM-1024
}

impl NamedGroup {
    /// Check if this is a hybrid group
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::X25519MlKem768 | Self::P256MlKem768 | Self::P384MlKem1024
        )
    }

    /// Check if this is a pure PQC group
    pub fn is_pqc(&self) -> bool {
        matches!(self, Self::MlKem512 | Self::MlKem768 | Self::MlKem1024)
    }

    /// Check if this is a classical group
    pub fn is_classical(&self) -> bool {
        !self.is_pqc() && !self.is_hybrid()
    }

    /// Get the classical component of a hybrid group
    pub fn classical_component(&self) -> Option<Self> {
        match self {
            Self::X25519MlKem768 => Some(Self::X25519),
            Self::P256MlKem768 => Some(Self::Secp256r1),
            Self::P384MlKem1024 => Some(Self::Secp384r1),
            _ => None,
        }
    }

    /// Get the PQC component of a hybrid group
    pub fn pqc_component(&self) -> Option<Self> {
        match self {
            Self::X25519MlKem768 | Self::P256MlKem768 => Some(Self::MlKem768),
            Self::P384MlKem1024 => Some(Self::MlKem1024),
            _ => None,
        }
    }

    /// Convert from u16 wire format
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x0019 => Some(Self::Secp521r1),
            0x001D => Some(Self::X25519),
            0x001E => Some(Self::X448),
            0x0200 => Some(Self::MlKem512),
            0x0201 => Some(Self::MlKem768),
            0x0202 => Some(Self::MlKem1024),
            0x4F2A => Some(Self::X25519MlKem768),
            0x4F2B => Some(Self::P256MlKem768),
            0x4F2C => Some(Self::P384MlKem1024),
            _ => None,
        }
    }

    /// Convert to u16 wire format
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Secp256r1 => "secp256r1",
            Self::Secp384r1 => "secp384r1",
            Self::Secp521r1 => "secp521r1",
            Self::X25519 => "x25519",
            Self::X448 => "x448",
            Self::MlKem512 => "ml_kem_512",
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::X25519MlKem768 => "x25519_ml_kem_768",
            Self::P256MlKem768 => "p256_ml_kem_768",
            Self::P384MlKem1024 => "p384_ml_kem_1024",
        }
    }
}

impl fmt::Display for NamedGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// TLS Signature Schemes including hybrid PQC schemes
///
/// Based on:
/// - draft-ietf-tls-hybrid-design-14
/// - draft-ietf-lamps-dilithium-certificates-11
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SignatureScheme {
    // Classical schemes (from TLS 1.3)
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    // Pure PQC schemes
    MlDsa44 = 0x0900, // ML-DSA-44 (NIST Level 2)
    MlDsa65 = 0x0901, // ML-DSA-65 (NIST Level 3)
    MlDsa87 = 0x0902, // ML-DSA-87 (NIST Level 5)

    // Hybrid schemes (Classical + PQC)
    Ed25519MlDsa65 = 0x0920,   // Ed25519 + ML-DSA-65
    EcdsaP256MlDsa65 = 0x0921, // ECDSA-P256 + ML-DSA-65
    EcdsaP384MlDsa87 = 0x0922, // ECDSA-P384 + ML-DSA-87
}

impl SignatureScheme {
    /// Check if this is a hybrid scheme
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::Ed25519MlDsa65 | Self::EcdsaP256MlDsa65 | Self::EcdsaP384MlDsa87
        )
    }

    /// Check if this is a pure PQC scheme
    pub fn is_pqc(&self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    /// Check if this is a classical scheme
    pub fn is_classical(&self) -> bool {
        !self.is_pqc() && !self.is_hybrid()
    }

    /// Get the classical component of a hybrid scheme
    pub fn classical_component(&self) -> Option<Self> {
        match self {
            Self::Ed25519MlDsa65 => Some(Self::Ed25519),
            Self::EcdsaP256MlDsa65 => Some(Self::EcdsaSecp256r1Sha256),
            Self::EcdsaP384MlDsa87 => Some(Self::EcdsaSecp384r1Sha384),
            _ => None,
        }
    }

    /// Get the PQC component of a hybrid scheme
    pub fn pqc_component(&self) -> Option<Self> {
        match self {
            Self::Ed25519MlDsa65 | Self::EcdsaP256MlDsa65 => Some(Self::MlDsa65),
            Self::EcdsaP384MlDsa87 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Convert from u16 wire format
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0401 => Some(Self::RsaPkcs1Sha256),
            0x0501 => Some(Self::RsaPkcs1Sha384),
            0x0601 => Some(Self::RsaPkcs1Sha512),
            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0603 => Some(Self::EcdsaSecp521r1Sha512),
            0x0804 => Some(Self::RsaPssRsaeSha256),
            0x0805 => Some(Self::RsaPssRsaeSha384),
            0x0806 => Some(Self::RsaPssRsaeSha512),
            0x0807 => Some(Self::Ed25519),
            0x0808 => Some(Self::Ed448),
            0x0900 => Some(Self::MlDsa44),
            0x0901 => Some(Self::MlDsa65),
            0x0902 => Some(Self::MlDsa87),
            0x0920 => Some(Self::Ed25519MlDsa65),
            0x0921 => Some(Self::EcdsaP256MlDsa65),
            0x0922 => Some(Self::EcdsaP384MlDsa87),
            _ => None,
        }
    }

    /// Convert to u16 wire format
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            Self::EcdsaSecp256r1Sha256 => "ecdsa_secp256r1_sha256",
            Self::EcdsaSecp384r1Sha384 => "ecdsa_secp384r1_sha384",
            Self::EcdsaSecp521r1Sha512 => "ecdsa_secp521r1_sha512",
            Self::RsaPssRsaeSha256 => "rsa_pss_rsae_sha256",
            Self::RsaPssRsaeSha384 => "rsa_pss_rsae_sha384",
            Self::RsaPssRsaeSha512 => "rsa_pss_rsae_sha512",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
            Self::MlDsa44 => "ml_dsa_44",
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::Ed25519MlDsa65 => "ed25519_ml_dsa_65",
            Self::EcdsaP256MlDsa65 => "ecdsa_p256_ml_dsa_65",
            Self::EcdsaP384MlDsa87 => "ecdsa_p384_ml_dsa_87",
        }
    }
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Serialization for wire format
impl NamedGroup {
    /// Serialize to bytes for TLS wire format
    pub fn to_bytes(&self) -> [u8; 2] {
        let value = self.to_u16();
        [((value >> 8) & 0xFF) as u8, (value & 0xFF) as u8]
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 2 {
            return Err(PqcError::CryptoError(
                "Invalid named group bytes".to_string(),
            ));
        }
        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::from_u16(value)
            .ok_or_else(|| PqcError::CryptoError(format!("Unknown named group: 0x{:04X}", value)))
    }
}

impl SignatureScheme {
    /// Serialize to bytes for TLS wire format
    pub fn to_bytes(&self) -> [u8; 2] {
        let value = self.to_u16();
        [((value >> 8) & 0xFF) as u8, (value & 0xFF) as u8]
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 2 {
            return Err(PqcError::CryptoError(
                "Invalid signature scheme bytes".to_string(),
            ));
        }
        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::from_u16(value).ok_or_else(|| {
            PqcError::CryptoError(format!("Unknown signature scheme: 0x{:04X}", value))
        })
    }
}

/// Extension trait for rustls integration
pub trait RustlsIntegration {
    /// Convert to rustls NamedGroup if supported
    fn to_rustls_named_group(&self) -> Option<rustls::NamedGroup>;

    /// Convert to rustls SignatureScheme if supported
    fn to_rustls_signature_scheme(&self) -> Option<rustls::SignatureScheme>;
}

impl RustlsIntegration for NamedGroup {
    fn to_rustls_named_group(&self) -> Option<rustls::NamedGroup> {
        // Map classical groups to rustls equivalents
        // PQC groups will be handled by custom implementation
        match self {
            Self::Secp256r1 => Some(rustls::NamedGroup::secp256r1),
            Self::Secp384r1 => Some(rustls::NamedGroup::secp384r1),
            Self::Secp521r1 => Some(rustls::NamedGroup::secp521r1),
            Self::X25519 => Some(rustls::NamedGroup::X25519),
            _ => None, // PQC and hybrid groups not directly supported
        }
    }

    fn to_rustls_signature_scheme(&self) -> Option<rustls::SignatureScheme> {
        None // Named groups don't map to signature schemes
    }
}

impl RustlsIntegration for SignatureScheme {
    fn to_rustls_named_group(&self) -> Option<rustls::NamedGroup> {
        None // Signature schemes don't map to named groups
    }

    fn to_rustls_signature_scheme(&self) -> Option<rustls::SignatureScheme> {
        // Map classical schemes to rustls equivalents
        match self {
            Self::RsaPkcs1Sha256 => Some(rustls::SignatureScheme::RSA_PKCS1_SHA256),
            Self::RsaPkcs1Sha384 => Some(rustls::SignatureScheme::RSA_PKCS1_SHA384),
            Self::RsaPkcs1Sha512 => Some(rustls::SignatureScheme::RSA_PKCS1_SHA512),
            Self::EcdsaSecp256r1Sha256 => Some(rustls::SignatureScheme::ECDSA_NISTP256_SHA256),
            Self::EcdsaSecp384r1Sha384 => Some(rustls::SignatureScheme::ECDSA_NISTP384_SHA384),
            Self::EcdsaSecp521r1Sha512 => Some(rustls::SignatureScheme::ECDSA_NISTP521_SHA512),
            Self::RsaPssRsaeSha256 => Some(rustls::SignatureScheme::RSA_PSS_SHA256),
            Self::RsaPssRsaeSha384 => Some(rustls::SignatureScheme::RSA_PSS_SHA384),
            Self::RsaPssRsaeSha512 => Some(rustls::SignatureScheme::RSA_PSS_SHA512),
            Self::Ed25519 => Some(rustls::SignatureScheme::ED25519),
            _ => None, // PQC and hybrid schemes not directly supported
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_group_conversions() {
        // Test classical groups
        assert_eq!(NamedGroup::X25519.to_u16(), 0x001D);
        assert_eq!(NamedGroup::from_u16(0x001D), Some(NamedGroup::X25519));

        // Test PQC groups
        assert_eq!(NamedGroup::MlKem768.to_u16(), 0x0201);
        assert_eq!(NamedGroup::from_u16(0x0201), Some(NamedGroup::MlKem768));

        // Test hybrid groups
        assert_eq!(NamedGroup::X25519MlKem768.to_u16(), 0x4F2A);
        assert_eq!(
            NamedGroup::from_u16(0x4F2A),
            Some(NamedGroup::X25519MlKem768)
        );
    }

    #[test]
    fn test_named_group_classification() {
        // Classical
        assert!(NamedGroup::X25519.is_classical());
        assert!(!NamedGroup::X25519.is_pqc());
        assert!(!NamedGroup::X25519.is_hybrid());

        // PQC
        assert!(!NamedGroup::MlKem768.is_classical());
        assert!(NamedGroup::MlKem768.is_pqc());
        assert!(!NamedGroup::MlKem768.is_hybrid());

        // Hybrid
        assert!(!NamedGroup::X25519MlKem768.is_classical());
        assert!(!NamedGroup::X25519MlKem768.is_pqc());
        assert!(NamedGroup::X25519MlKem768.is_hybrid());
    }

    #[test]
    fn test_hybrid_components() {
        let hybrid = NamedGroup::X25519MlKem768;
        assert_eq!(hybrid.classical_component(), Some(NamedGroup::X25519));
        assert_eq!(hybrid.pqc_component(), Some(NamedGroup::MlKem768));

        let classical = NamedGroup::X25519;
        assert_eq!(classical.classical_component(), None);
        assert_eq!(classical.pqc_component(), None);
    }

    #[test]
    fn test_signature_scheme_conversions() {
        // Test classical schemes
        assert_eq!(SignatureScheme::Ed25519.to_u16(), 0x0807);
        assert_eq!(
            SignatureScheme::from_u16(0x0807),
            Some(SignatureScheme::Ed25519)
        );

        // Test PQC schemes
        assert_eq!(SignatureScheme::MlDsa65.to_u16(), 0x0901);
        assert_eq!(
            SignatureScheme::from_u16(0x0901),
            Some(SignatureScheme::MlDsa65)
        );

        // Test hybrid schemes
        assert_eq!(SignatureScheme::Ed25519MlDsa65.to_u16(), 0x0920);
        assert_eq!(
            SignatureScheme::from_u16(0x0920),
            Some(SignatureScheme::Ed25519MlDsa65)
        );
    }

    #[test]
    fn test_wire_format_serialization() {
        // Test NamedGroup
        let group = NamedGroup::X25519MlKem768;
        let bytes = group.to_bytes();
        assert_eq!(bytes, [0x4F, 0x2A]);
        assert_eq!(NamedGroup::from_bytes(&bytes).unwrap(), group);

        // Test SignatureScheme
        let scheme = SignatureScheme::Ed25519MlDsa65;
        let bytes = scheme.to_bytes();
        assert_eq!(bytes, [0x09, 0x20]);
        assert_eq!(SignatureScheme::from_bytes(&bytes).unwrap(), scheme);
    }

    #[test]
    fn test_rustls_integration() {
        // Test classical mapping
        let group = NamedGroup::X25519;
        assert!(group.to_rustls_named_group().is_some());

        // Test PQC mapping (should be None)
        let pqc_group = NamedGroup::MlKem768;
        assert!(pqc_group.to_rustls_named_group().is_none());

        // Test signature scheme mapping
        let scheme = SignatureScheme::Ed25519;
        assert!(scheme.to_rustls_signature_scheme().is_some());

        let pqc_scheme = SignatureScheme::MlDsa65;
        assert!(pqc_scheme.to_rustls_signature_scheme().is_none());
    }
}
