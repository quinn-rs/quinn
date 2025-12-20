// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! TLS extensions for Pure Post-Quantum Cryptography
//!
//! v0.2: Pure PQC - NO hybrid or classical algorithms.
//!
//! This module provides TLS named groups and signature schemes for pure PQC:
//! - Key exchange: ML-KEM-768 (0x0201) ONLY
//! - Signatures: ML-DSA-65 (0x0901) ONLY
//!
//! NO classical fallback. NO hybrid algorithms. This is a greenfield network.

use crate::crypto::pqc::types::PqcError;
use std::fmt;

/// TLS Named Groups for Pure PQC Key Exchange
///
/// ONLY ML-KEM groups are supported. Classical and hybrid groups are rejected.
///
/// Based on:
/// - FIPS 203 (ML-KEM)
/// - draft-ietf-tls-mlkem-04
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NamedGroup {
    // Pure PQC groups - ONLY THESE ARE ACCEPTED
    MlKem512 = 0x0200,  // ML-KEM-512 (NIST Level 1)
    MlKem768 = 0x0201,  // ML-KEM-768 (NIST Level 3) - PRIMARY
    MlKem1024 = 0x0202, // ML-KEM-1024 (NIST Level 5)
}

impl NamedGroup {
    /// The primary/default group for ant-quic
    pub const PRIMARY: Self = Self::MlKem768;

    /// Check if this is a pure PQC group (always true for this enum)
    pub fn is_pqc(&self) -> bool {
        true
    }

    /// Check if this group is supported (always true for this enum)
    pub fn is_supported(&self) -> bool {
        true
    }

    /// Convert from u16 wire format
    /// Returns None for unsupported groups (classical, hybrid)
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0200 => Some(Self::MlKem512),
            0x0201 => Some(Self::MlKem768),
            0x0202 => Some(Self::MlKem1024),
            _ => None, // Classical and hybrid groups rejected
        }
    }

    /// Convert to u16 wire format
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Serialize to bytes for TLS wire format
    pub fn to_bytes(&self) -> [u8; 2] {
        self.to_u16().to_be_bytes()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 2 {
            return Err(PqcError::CryptoError(
                "Invalid named group bytes".to_string(),
            ));
        }
        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::from_u16(value).ok_or_else(|| {
            PqcError::NegotiationFailed(format!(
                "Named group 0x{:04X} not supported - use ML-KEM-768 (0x0201)",
                value
            ))
        })
    }
}

impl fmt::Display for NamedGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// TLS Signature Schemes for Pure PQC Authentication
///
/// ONLY ML-DSA schemes are supported. Classical and hybrid schemes are rejected.
///
/// Based on:
/// - FIPS 204 (ML-DSA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SignatureScheme {
    // Pure PQC schemes - ONLY THESE ARE ACCEPTED
    MlDsa44 = 0x0900, // ML-DSA-44 (NIST Level 2)
    MlDsa65 = 0x0901, // ML-DSA-65 (NIST Level 3) - PRIMARY
    MlDsa87 = 0x0902, // ML-DSA-87 (NIST Level 5)
}

impl SignatureScheme {
    /// The primary/default signature scheme for ant-quic
    pub const PRIMARY: Self = Self::MlDsa65;

    /// Check if this is a pure PQC scheme (always true for this enum)
    pub fn is_pqc(&self) -> bool {
        true
    }

    /// Check if this scheme is supported (always true for this enum)
    pub fn is_supported(&self) -> bool {
        true
    }

    /// Convert from u16 wire format
    /// Returns None for unsupported schemes (classical, hybrid)
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0900 => Some(Self::MlDsa44),
            0x0901 => Some(Self::MlDsa65),
            0x0902 => Some(Self::MlDsa87),
            _ => None, // Classical and hybrid schemes rejected
        }
    }

    /// Convert to u16 wire format
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Serialize to bytes for TLS wire format
    pub fn to_bytes(&self) -> [u8; 2] {
        self.to_u16().to_be_bytes()
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
            PqcError::NegotiationFailed(format!(
                "Signature scheme 0x{:04X} not supported - use ML-DSA-65 (0x0901)",
                value
            ))
        })
    }
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_group_primary() {
        assert_eq!(NamedGroup::PRIMARY, NamedGroup::MlKem768);
        assert_eq!(NamedGroup::PRIMARY.to_u16(), 0x0201);
    }

    #[test]
    fn test_named_group_conversions() {
        // ML-KEM groups should work
        assert_eq!(NamedGroup::MlKem768.to_u16(), 0x0201);
        assert_eq!(NamedGroup::from_u16(0x0201), Some(NamedGroup::MlKem768));
        assert_eq!(NamedGroup::from_u16(0x0200), Some(NamedGroup::MlKem512));
        assert_eq!(NamedGroup::from_u16(0x0202), Some(NamedGroup::MlKem1024));

        // Classical groups should be rejected
        assert_eq!(NamedGroup::from_u16(0x001D), None); // X25519
        assert_eq!(NamedGroup::from_u16(0x0017), None); // secp256r1

        // Hybrid groups should be rejected
        assert_eq!(NamedGroup::from_u16(0x11EC), None); // X25519MLKEM768
        assert_eq!(NamedGroup::from_u16(0x11EB), None); // P256MLKEM768
    }

    #[test]
    fn test_signature_scheme_primary() {
        assert_eq!(SignatureScheme::PRIMARY, SignatureScheme::MlDsa65);
        assert_eq!(SignatureScheme::PRIMARY.to_u16(), 0x0901);
    }

    #[test]
    fn test_signature_scheme_conversions() {
        // ML-DSA schemes should work
        assert_eq!(SignatureScheme::MlDsa65.to_u16(), 0x0901);
        assert_eq!(
            SignatureScheme::from_u16(0x0901),
            Some(SignatureScheme::MlDsa65)
        );
        assert_eq!(
            SignatureScheme::from_u16(0x0900),
            Some(SignatureScheme::MlDsa44)
        );
        assert_eq!(
            SignatureScheme::from_u16(0x0902),
            Some(SignatureScheme::MlDsa87)
        );

        // Classical schemes should be rejected
        assert_eq!(SignatureScheme::from_u16(0x0807), None); // Ed25519
        assert_eq!(SignatureScheme::from_u16(0x0403), None); // ECDSA P256

        // Hybrid schemes should be rejected
        assert_eq!(SignatureScheme::from_u16(0x0920), None); // Ed25519+ML-DSA-65
        assert_eq!(SignatureScheme::from_u16(0x0921), None); // ECDSA P256+ML-DSA-65
    }

    #[test]
    fn test_wire_format_serialization() {
        // Test ML-KEM-768
        let group = NamedGroup::MlKem768;
        let bytes = group.to_bytes();
        assert_eq!(bytes, [0x02, 0x01]);
        assert_eq!(NamedGroup::from_bytes(&bytes).unwrap(), group);

        // Test ML-DSA-65
        let scheme = SignatureScheme::MlDsa65;
        let bytes = scheme.to_bytes();
        assert_eq!(bytes, [0x09, 0x01]);
        assert_eq!(SignatureScheme::from_bytes(&bytes).unwrap(), scheme);
    }

    #[test]
    fn test_rejected_groups_error() {
        // Classical X25519 should give helpful error
        let result = NamedGroup::from_bytes(&[0x00, 0x1D]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("0x001D"));
        assert!(err.to_string().contains("ML-KEM-768"));

        // Hybrid X25519MLKEM768 should give helpful error
        let result = NamedGroup::from_bytes(&[0x11, 0xEC]);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_pqc() {
        assert!(NamedGroup::MlKem768.is_pqc());
        assert!(NamedGroup::MlKem512.is_pqc());
        assert!(NamedGroup::MlKem1024.is_pqc());

        assert!(SignatureScheme::MlDsa65.is_pqc());
        assert!(SignatureScheme::MlDsa44.is_pqc());
        assert!(SignatureScheme::MlDsa87.is_pqc());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", NamedGroup::MlKem768), "ML-KEM-768");
        assert_eq!(format!("{}", SignatureScheme::MlDsa65), "ML-DSA-65");
    }
}
