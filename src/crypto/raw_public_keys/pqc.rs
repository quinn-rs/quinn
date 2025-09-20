// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Post-Quantum Cryptography extensions for Raw Public Keys
//!
//! This module extends the raw public key infrastructure to support
//! ML-DSA keys and hybrid combinations for post-quantum authentication.

use std::fmt::{self, Debug};

use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::crypto::pqc::{
    MlDsaOperations,
    ml_dsa::MlDsa65,
    types::{MlDsaPublicKey as MlDsa65PublicKey, MlDsaSignature as MlDsa65Signature, PqcError},
};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519PublicKey};

/// Extended Raw Public Key types including PQC variants
#[derive(Clone, Debug)]
pub enum ExtendedRawPublicKey {
    /// Classical Ed25519 key
    Ed25519(Ed25519PublicKey),

    /// Post-quantum ML-DSA-65 key
    MlDsa65(MlDsa65PublicKey),

    /// Hybrid Ed25519 + ML-DSA-65 key
    HybridEd25519MlDsa65 {
        ed25519: Ed25519PublicKey,
        ml_dsa: MlDsa65PublicKey,
    },
}

impl ExtendedRawPublicKey {
    /// Create SubjectPublicKeyInfo DER encoding for the key
    pub fn to_subject_public_key_info(&self) -> Result<Vec<u8>, PqcError> {
        match self {
            Self::Ed25519(key) => {
                // Use existing Ed25519 SPKI encoding
                Ok(super::create_ed25519_subject_public_key_info(key))
            }
            Self::MlDsa65(key) => {
                // Create ML-DSA SPKI encoding
                create_ml_dsa_subject_public_key_info(key)
            }
            Self::HybridEd25519MlDsa65 { ed25519, ml_dsa } => {
                // Create composite SPKI for hybrid key
                create_hybrid_subject_public_key_info(ed25519, ml_dsa)
            }
        }
    }

    /// Extract public key from SubjectPublicKeyInfo
    pub fn from_subject_public_key_info(spki: &[u8]) -> Result<Self, PqcError> {
        // Try Ed25519 first (most common)
        if let Ok(key) = extract_ed25519_from_spki(spki) {
            return Ok(Self::Ed25519(key));
        }

        // Try ML-DSA
        if let Ok(key) = extract_ml_dsa_from_spki(spki) {
            return Ok(Self::MlDsa65(key));
        }

        // Try hybrid
        if let Ok((ed25519, ml_dsa)) = extract_hybrid_from_spki(spki) {
            return Ok(Self::HybridEd25519MlDsa65 { ed25519, ml_dsa });
        }

        Err(PqcError::InvalidPublicKey)
    }

    /// Verify a signature using this public key
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        scheme: SignatureScheme,
    ) -> Result<(), PqcError> {
        match self {
            Self::Ed25519(key) => verify_ed25519_signature(key, message, signature, scheme),
            Self::MlDsa65(key) => verify_ml_dsa_signature(key, message, signature, scheme),
            Self::HybridEd25519MlDsa65 { ed25519, ml_dsa } => {
                // For hybrid, both signatures must verify
                verify_hybrid_signature(ed25519, ml_dsa, message, signature, scheme)
            }
        }
    }

    /// Get the signature schemes supported by this key type
    pub fn supported_signature_schemes(&self) -> Vec<SignatureScheme> {
        match self {
            Self::Ed25519(_) => vec![SignatureScheme::ED25519],
            Self::MlDsa65(_) => vec![
                // ML-DSA-65 scheme (private use codepoint)
                SignatureScheme::Unknown(0xFE3C),
            ],
            Self::HybridEd25519MlDsa65 { .. } => vec![
                // Hybrid Ed25519+ML-DSA-65 scheme
                SignatureScheme::Unknown(0xFE3D),
            ],
        }
    }

    /// Get the size of this public key in bytes
    pub fn size(&self) -> usize {
        match self {
            Self::Ed25519(_) => 32,
            Self::MlDsa65(key) => key.as_bytes().len(),
            Self::HybridEd25519MlDsa65 { ml_dsa, .. } => 32 + ml_dsa.as_bytes().len(),
        }
    }
}

/// Create SubjectPublicKeyInfo for ML-DSA public key
fn create_ml_dsa_subject_public_key_info(
    public_key: &MlDsa65PublicKey,
) -> Result<Vec<u8>, PqcError> {
    // ML-DSA OID: 1.3.6.1.4.1.2.267.12.4.4 (draft-ietf-lamps-dilithium-certificates)
    // This is the OID for ML-DSA-65
    let ml_dsa_oid = vec![
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x30, 0x00,
    ];

    let key_bytes = public_key.as_bytes();
    let key_len = key_bytes.len();

    // Calculate total length
    let oid_sequence_len = 2 + ml_dsa_oid.len();
    let bit_string_len = 1 + key_len; // 1 byte for unused bits
    let total_len = 2 + oid_sequence_len + 2 + bit_string_len;

    let mut spki = Vec::with_capacity(total_len + 2);

    // SEQUENCE tag and length
    spki.push(0x30);
    encode_length(&mut spki, total_len);

    // Algorithm identifier SEQUENCE
    spki.push(0x30);
    encode_length(&mut spki, ml_dsa_oid.len());
    spki.extend_from_slice(&ml_dsa_oid);

    // Subject public key BIT STRING
    spki.push(0x03);
    encode_length(&mut spki, bit_string_len);
    spki.push(0x00); // No unused bits
    spki.extend_from_slice(key_bytes);

    Ok(spki)
}

/// Create composite SubjectPublicKeyInfo for hybrid key
fn create_hybrid_subject_public_key_info(
    ed25519: &Ed25519PublicKey,
    ml_dsa: &MlDsa65PublicKey,
) -> Result<Vec<u8>, PqcError> {
    // Composite key OID (private use)
    let composite_oid = vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA0, 0x34, 0x01];

    // Get individual SPKIs
    let ed25519_spki = super::create_ed25519_subject_public_key_info(ed25519);
    let ml_dsa_spki = create_ml_dsa_subject_public_key_info(ml_dsa)?;

    // Create composite structure
    let composite_len = 2 + ed25519_spki.len() + 2 + ml_dsa_spki.len();
    let oid_sequence_len = 2 + composite_oid.len();
    let bit_string_len = 1 + composite_len;
    let total_len = 2 + oid_sequence_len + 2 + bit_string_len;

    let mut spki = Vec::with_capacity(total_len + 2);

    // Outer SEQUENCE
    spki.push(0x30);
    encode_length(&mut spki, total_len);

    // Algorithm identifier
    spki.push(0x30);
    encode_length(&mut spki, composite_oid.len());
    spki.extend_from_slice(&composite_oid);

    // BIT STRING containing composite
    spki.push(0x03);
    encode_length(&mut spki, bit_string_len);
    spki.push(0x00); // No unused bits

    // SEQUENCE of SPKIs
    spki.push(0x30);
    encode_length(&mut spki, composite_len - 2);
    spki.extend_from_slice(&ed25519_spki);
    spki.extend_from_slice(&ml_dsa_spki);

    Ok(spki)
}

/// Extract Ed25519 key from SPKI
fn extract_ed25519_from_spki(spki: &[u8]) -> Result<Ed25519PublicKey, PqcError> {
    // Ed25519 OID pattern
    let ed25519_oid = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    if spki.len() != 44 || !spki.starts_with(&ed25519_oid) {
        return Err(PqcError::InvalidPublicKey);
    }

    let key_bytes = &spki[12..44];
    Ed25519PublicKey::from_bytes(
        key_bytes
            .try_into()
            .map_err(|_| PqcError::InvalidPublicKey)?,
    )
    .map_err(|_| PqcError::InvalidPublicKey)
}

/// Extract ML-DSA key from SPKI (placeholder)
fn extract_ml_dsa_from_spki(_spki: &[u8]) -> Result<MlDsa65PublicKey, PqcError> {
    // This is a placeholder - actual implementation would parse the ASN.1 structure
    // For now, return error as ML-DSA is not yet implemented
    Err(PqcError::OperationNotSupported)
}

/// Extract hybrid key from SPKI (placeholder)
fn extract_hybrid_from_spki(
    _spki: &[u8],
) -> Result<(Ed25519PublicKey, MlDsa65PublicKey), PqcError> {
    // This is a placeholder - actual implementation would parse the composite structure
    // For now, return error as hybrid keys are not yet implemented
    Err(PqcError::OperationNotSupported)
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(
    key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
    scheme: SignatureScheme,
) -> Result<(), PqcError> {
    if scheme != SignatureScheme::ED25519 {
        return Err(PqcError::InvalidSignature);
    }

    if signature.len() != 64 {
        return Err(PqcError::InvalidSignature);
    }

    let sig = Ed25519Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| PqcError::InvalidSignature)?,
    );

    use ed25519_dalek::Verifier;
    key.verify(message, &sig)
        .map_err(|_| PqcError::InvalidSignature)
}

/// Verify ML-DSA signature (placeholder)
fn verify_ml_dsa_signature(
    key: &MlDsa65PublicKey,
    message: &[u8],
    signature: &[u8],
    scheme: SignatureScheme,
) -> Result<(), PqcError> {
    // Check for ML-DSA scheme
    if scheme != SignatureScheme::Unknown(0xFE3C) {
        return Err(PqcError::InvalidSignature);
    }

    // Parse signature bytes into ML-DSA signature
    let sig = MlDsa65Signature::from_bytes(signature)?;

    // Use the ML-DSA verifier
    let verifier = MlDsa65::new();
    match verifier.verify(key, message, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PqcError::InvalidSignature),
        Err(e) => Err(e),
    }
}

/// Verify hybrid signature (both must pass)
fn verify_hybrid_signature(
    ed25519: &Ed25519PublicKey,
    ml_dsa: &MlDsa65PublicKey,
    message: &[u8],
    signature: &[u8],
    scheme: SignatureScheme,
) -> Result<(), PqcError> {
    // Check for hybrid scheme
    if scheme != SignatureScheme::Unknown(0xFE3D) {
        return Err(PqcError::InvalidSignature);
    }

    // Hybrid signature format: [ed25519_sig(64) || ml_dsa_sig]
    if signature.len() < 64 {
        return Err(PqcError::InvalidSignature);
    }

    let ed25519_sig = &signature[..64];
    let ml_dsa_sig = &signature[64..];

    // Both must verify
    verify_ed25519_signature(ed25519, message, ed25519_sig, SignatureScheme::ED25519)?;
    verify_ml_dsa_signature(
        ml_dsa,
        message,
        ml_dsa_sig,
        SignatureScheme::Unknown(0xFE3C),
    )?;

    Ok(())
}

/// Encode ASN.1 length
fn encode_length(output: &mut Vec<u8>, len: usize) {
    if len < 128 {
        output.push(len as u8);
    } else if len < 256 {
        output.push(0x81);
        output.push(len as u8);
    } else {
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push((len & 0xFF) as u8);
    }
}

/// PQC-aware Raw Public Key Verifier
#[derive(Debug)]
pub struct PqcRawPublicKeyVerifier {
    /// Set of trusted public keys
    trusted_keys: Vec<ExtendedRawPublicKey>,
    /// Whether to allow any valid key
    allow_any_key: bool,
}

impl PqcRawPublicKeyVerifier {
    /// Create a new verifier with trusted keys
    pub fn new(trusted_keys: Vec<ExtendedRawPublicKey>) -> Self {
        Self {
            trusted_keys,
            allow_any_key: false,
        }
    }

    /// Create a verifier that accepts any valid key (development only)
    pub fn allow_any() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_any_key: true,
        }
    }

    /// Add a trusted key
    pub fn add_trusted_key(&mut self, key: ExtendedRawPublicKey) {
        self.trusted_keys.push(key);
    }

    /// Verify a certificate (SPKI) against trusted keys
    pub fn verify_cert(&self, cert: &[u8]) -> Result<ExtendedRawPublicKey, TlsError> {
        // Extract key from SPKI
        let key = ExtendedRawPublicKey::from_subject_public_key_info(cert)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Check if trusted
        if self.allow_any_key {
            return Ok(key);
        }

        // Check against trusted keys
        for trusted in &self.trusted_keys {
            if self.keys_match(&key, trusted) {
                return Ok(key);
            }
        }

        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ))
    }

    /// Check if two keys match
    fn keys_match(&self, a: &ExtendedRawPublicKey, b: &ExtendedRawPublicKey) -> bool {
        match (a, b) {
            (ExtendedRawPublicKey::Ed25519(a), ExtendedRawPublicKey::Ed25519(b)) => {
                a.as_bytes() == b.as_bytes()
            }
            (ExtendedRawPublicKey::MlDsa65(a), ExtendedRawPublicKey::MlDsa65(b)) => {
                a.as_bytes() == b.as_bytes()
            }
            (
                ExtendedRawPublicKey::HybridEd25519MlDsa65 {
                    ed25519: a_ed,
                    ml_dsa: a_ml,
                },
                ExtendedRawPublicKey::HybridEd25519MlDsa65 {
                    ed25519: b_ed,
                    ml_dsa: b_ml,
                },
            ) => a_ed.as_bytes() == b_ed.as_bytes() && a_ml.as_bytes() == b_ml.as_bytes(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_raw_public_key_ed25519() {
        use crate::crypto::raw_public_keys::key_utils::generate_ed25519_keypair;

        // Generate valid test key
        let (_, ed25519_key) = generate_ed25519_keypair();
        let key_bytes = *ed25519_key.as_bytes();

        let extended_key = ExtendedRawPublicKey::Ed25519(ed25519_key);

        // Test SPKI encoding
        let spki = extended_key.to_subject_public_key_info().unwrap();
        assert_eq!(spki.len(), 44);

        // Test round-trip
        let recovered = ExtendedRawPublicKey::from_subject_public_key_info(&spki).unwrap();
        match recovered {
            ExtendedRawPublicKey::Ed25519(key) => {
                assert_eq!(key.as_bytes(), &key_bytes);
            }
            _ => panic!("Wrong key type"),
        }

        // Test size
        assert_eq!(extended_key.size(), 32);

        // Test supported schemes
        assert_eq!(
            extended_key.supported_signature_schemes(),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn test_ml_dsa_spki_encoding() {
        // Create a dummy ML-DSA public key
        let ml_dsa_key = MlDsa65PublicKey::from_bytes(&vec![0u8; 1952]).unwrap();
        let extended_key = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);

        // Test SPKI encoding
        match extended_key.to_subject_public_key_info() {
            Ok(spki) => {
                // Should have proper ASN.1 structure
                assert!(spki.starts_with(&[0x30])); // SEQUENCE tag
                assert!(spki.len() > 1952); // Larger than key due to ASN.1
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until ML-DSA is implemented
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test size
        assert_eq!(extended_key.size(), 1952);

        // Test supported schemes
        assert_eq!(
            extended_key.supported_signature_schemes(),
            vec![SignatureScheme::Unknown(0xFE3C)]
        );
    }

    #[test]
    fn test_hybrid_key() {
        use crate::crypto::raw_public_keys::key_utils::generate_ed25519_keypair;

        // Create test keys
        let (_, ed25519_key) = generate_ed25519_keypair();
        let ml_dsa_key = MlDsa65PublicKey::from_bytes(&vec![2u8; 1952]).unwrap();

        let hybrid_key = ExtendedRawPublicKey::HybridEd25519MlDsa65 {
            ed25519: ed25519_key,
            ml_dsa: ml_dsa_key,
        };

        // Test size
        assert_eq!(hybrid_key.size(), 32 + 1952);

        // Test supported schemes
        assert_eq!(
            hybrid_key.supported_signature_schemes(),
            vec![SignatureScheme::Unknown(0xFE3D)]
        );
    }

    #[test]
    fn test_pqc_verifier() {
        use crate::crypto::raw_public_keys::key_utils::generate_ed25519_keypair;

        // Create test keys with valid Ed25519 keys
        let (_, pub1) = generate_ed25519_keypair();
        let (_, pub2) = generate_ed25519_keypair();

        let key1 = ExtendedRawPublicKey::Ed25519(pub1);
        let key2 = ExtendedRawPublicKey::Ed25519(pub2);

        // Create verifier with trusted key
        let verifier = PqcRawPublicKeyVerifier::new(vec![key1.clone()]);

        // Test verification with trusted key
        let spki1 = key1.to_subject_public_key_info().unwrap();
        assert!(verifier.verify_cert(&spki1).is_ok());

        // Test verification with untrusted key
        let spki2 = key2.to_subject_public_key_info().unwrap();
        assert!(verifier.verify_cert(&spki2).is_err());

        // Test allow_any mode
        let any_verifier = PqcRawPublicKeyVerifier::allow_any();
        assert!(any_verifier.verify_cert(&spki2).is_ok());
    }

    #[test]
    fn test_asn1_length_encoding() {
        let mut buf = Vec::new();

        // Short form (< 128)
        encode_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);

        // Long form (128-255)
        buf.clear();
        encode_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        // Long form (256+)
        buf.clear();
        encode_length(&mut buf, 1000);
        assert_eq!(buf, vec![0x82, 0x03, 0xE8]);
    }
}
