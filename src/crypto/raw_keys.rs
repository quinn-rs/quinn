//! Raw Public Key Support
//!
//! This module implements support for Ed25519 keys in SubjectPublicKeyInfo format
//! as specified in RFC 7250. It provides functionality for key generation, encoding,
//! and verification with a focus on simplicity and performance.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

/// Errors that can occur during raw public key operations
#[derive(Debug, Error)]
pub enum RawKeyError {
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),
}

/// Ed25519 key pair for authentication
#[derive(Clone, Debug)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create a key pair from an existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key in SubjectPublicKeyInfo format
    pub fn public_key_spki(&self) -> Vec<u8> {
        create_ed25519_subject_public_key_info(&self.verifying_key)
    }

    /// Get the raw public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.verifying_key.as_bytes()
    }

    /// Get a reference to the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign data with the private key
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Verify a signature with the public key
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RawKeyError> {
        self.verifying_key
            .verify(data, signature)
            .map_err(|_| RawKeyError::VerificationFailed)
    }
}

/// Create a SubjectPublicKeyInfo DER encoding for an Ed25519 public key
///
/// This function creates a minimal DER encoding of the SubjectPublicKeyInfo
/// structure containing an Ed25519 public key as specified in RFC 5280 and RFC 8410.
pub fn create_ed25519_subject_public_key_info(public_key: &VerifyingKey) -> Vec<u8> {
    // Ed25519 SubjectPublicKeyInfo structure:
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
    //   }
    //   BIT STRING (32 bytes of public key)
    // }

    // Pre-allocate the exact size needed (44 bytes)
    let mut spki = Vec::with_capacity(44);

    // SEQUENCE tag and length (total length will be 44 bytes)
    spki.extend_from_slice(&[0x30, 0x2a]);

    // Algorithm identifier SEQUENCE
    spki.extend_from_slice(&[0x30, 0x05]);

    // Ed25519 OID: 1.3.101.112
    spki.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]);

    // Subject public key BIT STRING
    spki.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING, 33 bytes (32 + 1 unused bits byte)

    // The actual 32-byte Ed25519 public key
    spki.extend_from_slice(public_key.as_bytes());

    spki
}

/// Extract an Ed25519 public key from SubjectPublicKeyInfo format
///
/// This function extracts the raw 32-byte Ed25519 public key from a
/// SubjectPublicKeyInfo structure as specified in RFC 5280 and RFC 8410.
pub fn extract_ed25519_key_from_spki(spki_der: &[u8]) -> Result<[u8; 32], RawKeyError> {
    // Simple parsing for Ed25519 SubjectPublicKeyInfo
    if spki_der.len() != 44 {
        return Err(RawKeyError::InvalidFormat(format!(
            "Invalid SPKI length: expected 44 bytes, got {}",
            spki_der.len()
        )));
    }

    // Look for Ed25519 OID pattern in the DER encoding
    let ed25519_oid = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    if !spki_der.starts_with(&ed25519_oid) {
        return Err(RawKeyError::InvalidFormat(
            "Invalid SPKI format: Ed25519 OID not found".to_string(),
        ));
    }

    // The public key should be at offset 12 and be 32 bytes long
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&spki_der[12..44]);

    Ok(public_key)
}

/// Create a VerifyingKey from SubjectPublicKeyInfo format
pub fn verifying_key_from_spki(spki_der: &[u8]) -> Result<VerifyingKey, RawKeyError> {
    let key_bytes = extract_ed25519_key_from_spki(spki_der)?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| RawKeyError::InvalidFormat(format!("Invalid Ed25519 public key: {e}")))
}

/// Derive a peer ID from a public key
///
/// This function creates a deterministic peer ID from an Ed25519 public key
/// using a secure hash function to ensure uniform distribution and prevent
/// direct key exposure.
pub fn derive_peer_id_from_public_key(public_key: &VerifyingKey) -> [u8; 32] {
    let key_bytes = public_key.as_bytes();

    // Create the input data with domain separator
    let mut input = Vec::with_capacity(20 + 32); // "AUTONOMI_PEER_ID_V1:" + key_bytes
    input.extend_from_slice(b"AUTONOMI_PEER_ID_V1:");
    input.extend_from_slice(key_bytes);

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        // Use SHA-256 to hash the public key with a domain separator
        use ring::digest::{SHA256, digest};

        // Hash the input
        let hash = digest(&SHA256, &input);
        let hash_bytes = hash.as_ref();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(hash_bytes);
        peer_id_bytes
    }

    #[cfg(feature = "aws-lc-rs")]
    {
        use aws_lc_rs::digest;

        // Hash the input
        let hash = digest::digest(&digest::SHA256, &input);
        let hash_bytes = hash.as_ref();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(hash_bytes);
        peer_id_bytes
    }

    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    {
        // Use SHA2 crate as fallback
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&input);
        let result = hasher.finalize();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(&result);
        peer_id_bytes
    }
}

/// Verify that a peer ID was correctly derived from a public key
pub fn verify_peer_id(peer_id: &[u8; 32], public_key: &VerifyingKey) -> bool {
    let derived_id = derive_peer_id_from_public_key(public_key);
    peer_id == &derived_id
}

/// Generate a new Ed25519 key pair (convenience function)
pub fn generate_ed25519_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519KeyPair::generate();
        let signature = keypair.sign(b"test message");
        assert!(keypair.verify(b"test message", &signature).is_ok());
        assert!(keypair.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_spki_encoding_decoding() {
        let keypair = Ed25519KeyPair::generate();
        let spki = keypair.public_key_spki();

        // Verify SPKI format
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[0..2], &[0x30, 0x2a]); // SEQUENCE tag and length

        // Extract key from SPKI
        let extracted_key = extract_ed25519_key_from_spki(&spki).unwrap();
        assert_eq!(extracted_key, keypair.public_key_bytes());

        // Create VerifyingKey from SPKI
        let verifying_key = verifying_key_from_spki(&spki).unwrap();
        assert_eq!(verifying_key.as_bytes(), keypair.verifying_key().as_bytes());
    }

    #[test]
    fn test_peer_id_derivation() {
        let keypair1 = Ed25519KeyPair::generate();
        let keypair2 = Ed25519KeyPair::generate();

        let peer_id1 = derive_peer_id_from_public_key(keypair1.verifying_key());
        let peer_id2 = derive_peer_id_from_public_key(keypair1.verifying_key());
        let peer_id3 = derive_peer_id_from_public_key(keypair2.verifying_key());

        // Same key should produce same peer ID
        assert_eq!(peer_id1, peer_id2);

        // Different keys should produce different peer IDs
        assert_ne!(peer_id1, peer_id3);

        // Verify peer ID
        assert!(verify_peer_id(&peer_id1, keypair1.verifying_key()));
        assert!(!verify_peer_id(&peer_id1, keypair2.verifying_key()));
    }

    #[test]
    fn test_invalid_spki() {
        // Too short
        let result = extract_ed25519_key_from_spki(&[0; 43]);
        assert!(result.is_err());

        // Wrong OID
        let mut invalid_spki = vec![0; 44];
        invalid_spki[7] = 0xFF; // Corrupt the OID
        let result = extract_ed25519_key_from_spki(&invalid_spki);
        assert!(result.is_err());
    }
}
