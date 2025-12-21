// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Pure Post-Quantum Cryptography for Raw Public Keys
//!
//! v0.2: Pure PQC - NO classical algorithms.
//!
//! This module provides:
//! - ML-DSA-65 key generation for Pure PQC identity
//! - PeerId derivation from ML-DSA-65 public keys
//! - SPKI (SubjectPublicKeyInfo) ASN.1 encoding/decoding for ML-DSA-65
//! - Signature verification for TLS 1.3 authentication
//!
//! This is a greenfield network - Pure PQC from day one.

use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::crypto::pqc::{
    MlDsaOperations,
    ml_dsa::MlDsa65,
    types::{
        MlDsaPublicKey as MlDsa65PublicKey, MlDsaSecretKey as MlDsa65SecretKey,
        MlDsaSignature as MlDsa65Signature, PqcError,
    },
};

// Re-export types for external use
pub use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

// =============================================================================
// Constants
// =============================================================================

/// ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18 (NIST CSOR)
/// Per draft-ietf-lamps-dilithium-certificates
const ML_DSA_65_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

/// ML-DSA-65 public key size in bytes (per FIPS 204)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 secret key size in bytes (per FIPS 204)
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;

/// ML-DSA-65 signature size in bytes (per FIPS 204)
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

// =============================================================================
// Pure PQC Identity Functions
// =============================================================================

/// Generate a new ML-DSA-65 keypair for Pure PQC identity
///
/// This is the PRIMARY and ONLY identity generation function.
/// Returns (public_key, secret_key) for use in TLS authentication and PeerId derivation.
pub fn generate_ml_dsa_keypair() -> Result<(MlDsa65PublicKey, MlDsa65SecretKey), PqcError> {
    let ml_dsa = MlDsa65::new();
    ml_dsa.generate_keypair()
}

/// Derive a PeerId from an ML-DSA-65 public key using SHA-256 hash
///
/// Pure PQC peer identification using ML-DSA-65 public keys.
///
/// The SHA-256 hash ensures:
/// - Uniform 32-byte distribution
/// - Collision resistance
/// - No direct key exposure in the peer ID
pub fn derive_peer_id_from_public_key(
    public_key: &MlDsa65PublicKey,
) -> crate::nat_traversal_api::PeerId {
    use aws_lc_rs::digest;

    let key_bytes = public_key.as_bytes();

    // Create the input data with domain separator
    let mut input = Vec::with_capacity(20 + key_bytes.len());
    input.extend_from_slice(b"AUTONOMI_PEER_ID_V2:");
    input.extend_from_slice(key_bytes);

    // Hash the input using SHA-256
    let hash = digest::digest(&digest::SHA256, &input);
    let hash_bytes = hash.as_ref();

    let mut peer_id_bytes = [0u8; 32];
    peer_id_bytes.copy_from_slice(hash_bytes);

    crate::nat_traversal_api::PeerId(peer_id_bytes)
}

/// Derive a PeerId from raw ML-DSA-65 public key bytes (1952 bytes)
pub fn derive_peer_id_from_key_bytes(
    key_bytes: &[u8],
) -> Result<crate::nat_traversal_api::PeerId, PqcError> {
    let public_key = MlDsa65PublicKey::from_bytes(key_bytes)?;
    Ok(derive_peer_id_from_public_key(&public_key))
}

/// Verify that a peer ID was correctly derived from an ML-DSA-65 public key
pub fn verify_peer_id(
    peer_id: &crate::nat_traversal_api::PeerId,
    public_key: &MlDsa65PublicKey,
) -> bool {
    let derived_id = derive_peer_id_from_public_key(public_key);
    *peer_id == derived_id
}

// =============================================================================
// SPKI (SubjectPublicKeyInfo) Encoding/Decoding
// =============================================================================

/// Create SubjectPublicKeyInfo for ML-DSA-65 public key
///
/// Encodes per draft-ietf-lamps-dilithium-certificates:
/// ```asn1
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm OBJECT IDENTIFIER,
///     -- parameters MUST be absent for ML-DSA
/// }
/// ```
pub fn create_subject_public_key_info(public_key: &MlDsa65PublicKey) -> Result<Vec<u8>, PqcError> {
    let key_bytes = public_key.as_bytes();
    let key_len = key_bytes.len();

    // Validate key size
    if key_len != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(PqcError::InvalidPublicKey);
    }

    // Algorithm identifier: SEQUENCE { OID }
    let oid_with_tag_len = 2 + ML_DSA_65_OID.len(); // 11 bytes
    let algorithm_seq_content_len = oid_with_tag_len;

    // BIT STRING: tag (0x03) + length + 0x00 (unused bits) + key
    let bit_string_content_len = 1 + key_len; // 1953 bytes
    let bit_string_len_encoding = length_encoding_size(bit_string_content_len);
    let bit_string_total = 1 + bit_string_len_encoding + bit_string_content_len;

    // Algorithm SEQUENCE
    let algo_seq_len_encoding = length_encoding_size(algorithm_seq_content_len);
    let algo_seq_total = 1 + algo_seq_len_encoding + algorithm_seq_content_len;

    // Outer SEQUENCE content
    let outer_content_len = algo_seq_total + bit_string_total;

    let mut spki = Vec::with_capacity(4 + outer_content_len);

    // Outer SEQUENCE
    spki.push(0x30);
    encode_length(&mut spki, outer_content_len);

    // Algorithm identifier SEQUENCE
    spki.push(0x30);
    encode_length(&mut spki, algorithm_seq_content_len);

    // OID
    spki.push(0x06);
    spki.push(ML_DSA_65_OID.len() as u8);
    spki.extend_from_slice(&ML_DSA_65_OID);

    // Subject public key BIT STRING
    spki.push(0x03);
    encode_length(&mut spki, bit_string_content_len);
    spki.push(0x00); // No unused bits
    spki.extend_from_slice(key_bytes);

    Ok(spki)
}

/// Extract ML-DSA-65 key from SubjectPublicKeyInfo
pub fn extract_public_key_from_spki(spki: &[u8]) -> Result<MlDsa65PublicKey, PqcError> {
    let mut pos = 0;

    // Parse outer SEQUENCE
    if spki.get(pos) != Some(&0x30) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos += 1;

    let (outer_len, len_bytes) = parse_length(&spki[pos..])?;
    pos += len_bytes;

    // Verify we have enough data
    if spki.len() < pos + outer_len {
        return Err(PqcError::InvalidPublicKey);
    }

    // Parse algorithm identifier SEQUENCE
    if spki.get(pos) != Some(&0x30) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos += 1;

    let (algo_len, len_bytes) = parse_length(&spki[pos..])?;
    pos += len_bytes;
    let algo_end = pos + algo_len;

    // Parse OID
    if spki.get(pos) != Some(&0x06) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos += 1;

    let (oid_len, len_bytes) = parse_length(&spki[pos..])?;
    pos += len_bytes;

    if oid_len != ML_DSA_65_OID.len() {
        return Err(PqcError::InvalidPublicKey);
    }

    // Verify ML-DSA-65 OID
    if spki.get(pos..pos + oid_len) != Some(&ML_DSA_65_OID[..]) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos = algo_end;

    // Parse BIT STRING
    if spki.get(pos) != Some(&0x03) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos += 1;

    let (bit_string_len, len_bytes) = parse_length(&spki[pos..])?;
    pos += len_bytes;

    // First byte of BIT STRING is unused bits count (must be 0)
    if spki.get(pos) != Some(&0x00) {
        return Err(PqcError::InvalidPublicKey);
    }
    pos += 1;

    // Extract public key bytes
    let key_len = bit_string_len - 1;
    if key_len != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(PqcError::InvalidPublicKey);
    }

    let key_bytes = spki
        .get(pos..pos + key_len)
        .ok_or(PqcError::InvalidPublicKey)?;

    MlDsa65PublicKey::from_bytes(key_bytes)
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verify ML-DSA-65 signature
pub fn verify_signature(
    key: &MlDsa65PublicKey,
    message: &[u8],
    signature: &[u8],
    scheme: SignatureScheme,
) -> Result<(), PqcError> {
    // Check for ML-DSA-65 scheme - uses rustls native enum (IANA 0x0905)
    if scheme != SignatureScheme::ML_DSA_65 {
        return Err(PqcError::InvalidSignature);
    }

    let sig = MlDsa65Signature::from_bytes(signature)?;

    let verifier = MlDsa65::new();
    match verifier.verify(key, message, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PqcError::InvalidSignature),
        Err(e) => Err(e),
    }
}

/// Get the supported signature schemes for ML-DSA-65
/// Uses rustls native enum (IANA 0x0905)
pub fn supported_signature_schemes() -> Vec<SignatureScheme> {
    vec![SignatureScheme::ML_DSA_65]
}

/// Sign data with an ML-DSA-65 secret key
///
/// Returns the signature as an MlDsaSignature on success.
pub fn sign_with_ml_dsa(
    secret_key: &MlDsa65SecretKey,
    data: &[u8],
) -> Result<MlDsa65Signature, PqcError> {
    let signer = MlDsa65::new();
    signer.sign(secret_key, data)
}

/// Verify a signature with an ML-DSA-65 public key
///
/// Returns Ok(()) if the signature is valid, Err otherwise.
pub fn verify_with_ml_dsa(
    public_key: &MlDsa65PublicKey,
    data: &[u8],
    signature: &MlDsa65Signature,
) -> Result<(), PqcError> {
    let verifier = MlDsa65::new();
    match verifier.verify(public_key, data, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PqcError::InvalidSignature),
        Err(e) => Err(e),
    }
}

// =============================================================================
// PQC Raw Public Key Verifier
// =============================================================================

/// Pure PQC Raw Public Key Verifier for TLS
#[derive(Debug)]
pub struct PqcRawPublicKeyVerifier {
    trusted_keys: Vec<MlDsa65PublicKey>,
    allow_any_key: bool,
}

impl PqcRawPublicKeyVerifier {
    /// Create a new verifier with trusted keys
    pub fn new(trusted_keys: Vec<MlDsa65PublicKey>) -> Self {
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
    pub fn add_trusted_key(&mut self, key: MlDsa65PublicKey) {
        self.trusted_keys.push(key);
    }

    /// Verify a certificate (SPKI) against trusted keys
    pub fn verify_cert(&self, cert: &[u8]) -> Result<MlDsa65PublicKey, TlsError> {
        let key = extract_public_key_from_spki(cert)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        if self.allow_any_key {
            return Ok(key);
        }

        for trusted in &self.trusted_keys {
            if key.as_bytes() == trusted.as_bytes() {
                return Ok(key);
            }
        }

        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ))
    }
}

// =============================================================================
// ASN.1 Helpers
// =============================================================================

fn length_encoding_size(len: usize) -> usize {
    if len < 128 {
        1
    } else if len < 256 {
        2
    } else {
        3
    }
}

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

fn parse_length(data: &[u8]) -> Result<(usize, usize), PqcError> {
    if data.is_empty() {
        return Err(PqcError::InvalidPublicKey);
    }

    let first = data[0];
    if first < 128 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(PqcError::InvalidPublicKey);
        }
        Ok((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(PqcError::InvalidPublicKey);
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else {
        Err(PqcError::InvalidPublicKey)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ml_dsa_keypair() {
        let result = generate_ml_dsa_keypair();
        assert!(result.is_ok());

        let (public_key, secret_key) = result.unwrap();

        assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(secret_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);

        // Different keypairs should be different
        let (public_key2, _) = generate_ml_dsa_keypair().unwrap();
        assert_ne!(public_key.as_bytes(), public_key2.as_bytes());
    }

    #[test]
    fn test_derive_peer_id() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();

        // Deterministic
        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_public_key(&public_key);
        assert_eq!(peer_id1, peer_id2);

        // Different keys produce different peer IDs
        let (public_key2, _) = generate_ml_dsa_keypair().unwrap();
        let peer_id3 = derive_peer_id_from_public_key(&public_key2);
        assert_ne!(peer_id1, peer_id3);
    }

    #[test]
    fn test_derive_peer_id_from_key_bytes() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();
        let key_bytes = public_key.as_bytes();

        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_key_bytes(key_bytes).unwrap();
        assert_eq!(peer_id1, peer_id2);

        // Invalid key bytes should fail
        assert!(derive_peer_id_from_key_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_verify_peer_id() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        assert!(verify_peer_id(&peer_id, &public_key));

        let (other_key, _) = generate_ml_dsa_keypair().unwrap();
        assert!(!verify_peer_id(&peer_id, &other_key));
    }

    #[test]
    fn test_spki_round_trip() {
        let (public_key, _) = generate_ml_dsa_keypair().unwrap();

        let spki = create_subject_public_key_info(&public_key).unwrap();
        assert!(spki.starts_with(&[0x30]));
        assert!(spki.len() > ML_DSA_65_PUBLIC_KEY_SIZE);

        let recovered = extract_public_key_from_spki(&spki).unwrap();
        assert_eq!(recovered.as_bytes(), public_key.as_bytes());
    }

    #[test]
    fn test_spki_with_synthetic_key() {
        let key_bytes: Vec<u8> = (0..1952).map(|i| (i % 256) as u8).collect();
        let public_key = MlDsa65PublicKey::from_bytes(&key_bytes).unwrap();

        let spki = create_subject_public_key_info(&public_key).unwrap();
        let recovered = extract_public_key_from_spki(&spki).unwrap();
        assert_eq!(recovered.as_bytes(), &key_bytes[..]);
    }

    #[test]
    fn test_pqc_verifier() {
        let (pub1, _) = generate_ml_dsa_keypair().unwrap();
        let (pub2, _) = generate_ml_dsa_keypair().unwrap();

        let verifier = PqcRawPublicKeyVerifier::new(vec![pub1.clone()]);

        let spki1 = create_subject_public_key_info(&pub1).unwrap();
        assert!(verifier.verify_cert(&spki1).is_ok());

        let spki2 = create_subject_public_key_info(&pub2).unwrap();
        assert!(verifier.verify_cert(&spki2).is_err());

        let any_verifier = PqcRawPublicKeyVerifier::allow_any();
        assert!(any_verifier.verify_cert(&spki2).is_ok());
    }

    #[test]
    fn test_supported_signature_schemes() {
        let schemes = supported_signature_schemes();
        // ML-DSA-65 IANA code is 0x0905 per draft-tls-westerbaan-mldsa
        assert_eq!(schemes, vec![SignatureScheme::ML_DSA_65]);
    }

    #[test]
    fn test_parse_length() {
        let (len, consumed) = parse_length(&[50]).unwrap();
        assert_eq!(len, 50);
        assert_eq!(consumed, 1);

        let (len, consumed) = parse_length(&[0x81, 200]).unwrap();
        assert_eq!(len, 200);
        assert_eq!(consumed, 2);

        let (len, consumed) = parse_length(&[0x82, 0x07, 0xA1]).unwrap();
        assert_eq!(len, 1953);
        assert_eq!(consumed, 3);

        assert!(parse_length(&[]).is_err());
    }

    #[test]
    fn test_asn1_length_encoding() {
        let mut buf = Vec::new();

        encode_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);

        buf.clear();
        encode_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        buf.clear();
        encode_length(&mut buf, 1000);
        assert_eq!(buf, vec![0x82, 0x03, 0xE8]);
    }
}
