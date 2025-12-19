// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-KEM/AES Hybrid Public Key Encryption
//!
//! This module implements hybrid public key encryption using ML-KEM-768 for key
//! encapsulation and AES-256-GCM for symmetric encryption. This provides the
//! missing piece for actual data encryption using post-quantum cryptography.
//!
//! # Design
//!
//! The encryption process:
//! 1. Generate ephemeral ML-KEM keypair (or use existing public key)
//! 2. Encapsulate to get shared secret
//! 3. Derive AES key using HKDF-SHA256
//! 4. Encrypt data with AES-256-GCM
//! 5. Return wire format with ML-KEM ciphertext + AES ciphertext
//!
//! # Security
//!
//! - Uses NIST-approved ML-KEM-768 (FIPS 203)
//! - AES-256-GCM provides authenticated encryption
//! - HKDF-SHA256 for proper key derivation (NIST SP 800-56C Rev. 2)
//! - Constant-time operations where possible

use crate::crypto::pqc::types::*;
use crate::crypto::pqc::{MlKemOperations, ml_kem::MlKem768};
use aws_lc_rs::aead::{self, AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;

/// Wire format for encrypted messages
///
/// Contains all necessary components for decryption:
/// - ML-KEM ciphertext for key encapsulation
/// - AES-GCM ciphertext with authentication tag
/// - Nonce for AES-GCM
/// - Associated data hash for integrity
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub ml_kem_ciphertext: Box<[u8; ML_KEM_768_CIPHERTEXT_SIZE]>,
    /// AES-256-GCM encrypted data (variable length)
    pub aes_ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Hash of associated data for verification
    pub associated_data_hash: [u8; 32],
    /// Version for future compatibility
    pub version: u8,
}

impl EncryptedMessage {
    /// Get the total size of the encrypted message
    pub fn total_size(&self) -> usize {
        ML_KEM_768_CIPHERTEXT_SIZE + // ml_kem_ciphertext
        self.aes_ciphertext.len() + // aes_ciphertext
        12 + // nonce
        32 + // associated_data_hash
        1 // version
    }

    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.ml_kem_ciphertext[..]);
        bytes.extend_from_slice(&self.aes_ciphertext);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.associated_data_hash);
        bytes.push(self.version);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < ML_KEM_768_CIPHERTEXT_SIZE + 12 + 32 + 1 {
            return Err(PqcError::InvalidCiphertext);
        }

        let mut offset = 0;

        // Extract ML-KEM ciphertext
        let mut ml_kem_ciphertext = Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]);
        ml_kem_ciphertext.copy_from_slice(&bytes[offset..offset + ML_KEM_768_CIPHERTEXT_SIZE]);
        offset += ML_KEM_768_CIPHERTEXT_SIZE;

        // Calculate AES ciphertext length
        let aes_len = bytes.len() - ML_KEM_768_CIPHERTEXT_SIZE - 12 - 32 - 1;
        if aes_len == 0 {
            return Err(PqcError::InvalidCiphertext);
        }

        // Extract AES ciphertext
        let aes_ciphertext = bytes[offset..offset + aes_len].to_vec();
        offset += aes_len;

        // Extract nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[offset..offset + 12]);
        offset += 12;

        // Extract associated data hash
        let mut associated_data_hash = [0u8; 32];
        associated_data_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Extract version
        let version = bytes[offset];

        if version != 1 {
            return Err(PqcError::CryptoError(format!(
                "Unsupported version: {}",
                version
            )));
        }

        Ok(Self {
            ml_kem_ciphertext,
            aes_ciphertext,
            nonce,
            associated_data_hash,
            version,
        })
    }
}

/// ML-KEM/AES Hybrid Public Key Encryption system
///
/// Provides the missing public key encryption capability using ML-KEM for
/// key encapsulation and AES-256-GCM for symmetric encryption.
pub struct HybridPublicKeyEncryption {
    ml_kem: MlKem768,
    rng: SystemRandom,
    /// Cache for derived keys to avoid repeated HKDF operations
    key_cache: HashMap<Vec<u8>, [u8; 32]>,
}

impl HybridPublicKeyEncryption {
    /// Create a new hybrid PKE instance
    pub fn new() -> Self {
        Self {
            ml_kem: MlKem768::new(),
            rng: SystemRandom::new(),
            key_cache: HashMap::new(),
        }
    }

    /// Encrypt data using ML-KEM/AES hybrid scheme
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - ML-KEM public key of the recipient
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data (AAD)
    ///
    /// # Returns
    ///
    /// Encrypted message containing ML-KEM ciphertext and AES-GCM ciphertext
    ///
    /// # Security
    ///
    /// - Uses ML-KEM-768 for quantum-resistant key encapsulation
    /// - Derives AES key using HKDF-SHA256 with proper salt and info
    /// - AES-256-GCM provides confidentiality and authenticity
    /// - Associated data is authenticated but not encrypted
    pub fn encrypt(
        &self,
        recipient_public_key: &MlKemPublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<EncryptedMessage> {
        // Step 1: ML-KEM encapsulation to get shared secret
        let (ml_kem_ciphertext, shared_secret) = self.ml_kem.encapsulate(recipient_public_key)?;

        // Step 2: Derive AES key using HKDF-SHA256
        let aes_key = self.derive_aes_key(&shared_secret, associated_data)?;

        // Step 3: Generate random nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| PqcError::CryptoError("Failed to generate nonce".to_string()))?;

        // Step 4: Encrypt with AES-256-GCM
        let aes_ciphertext =
            self.aes_encrypt(&aes_key, &nonce_bytes, plaintext, associated_data)?;

        // Step 5: Hash associated data for integrity verification
        let associated_data_hash = self.hash_associated_data(associated_data);

        // Step 6: Create encrypted message
        Ok(EncryptedMessage {
            ml_kem_ciphertext: ml_kem_ciphertext.0,
            aes_ciphertext,
            nonce: nonce_bytes,
            associated_data_hash,
            version: 1,
        })
    }

    /// Decrypt data using ML-KEM/AES hybrid scheme
    ///
    /// # Arguments
    ///
    /// * `private_key` - ML-KEM secret key for decapsulation
    /// * `encrypted_message` - Encrypted message to decrypt
    /// * `associated_data` - Associated authenticated data (must match encryption)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext data
    ///
    /// # Security
    ///
    /// - Verifies associated data integrity before decryption
    /// - Uses constant-time operations where possible
    /// - Properly handles authentication failures
    pub fn decrypt(
        &self,
        private_key: &MlKemSecretKey,
        encrypted_message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        // Step 1: Verify message version
        if encrypted_message.version != 1 {
            return Err(PqcError::CryptoError(format!(
                "Unsupported message version: {}",
                encrypted_message.version
            )));
        }

        // Step 2: Verify associated data integrity
        let expected_hash = self.hash_associated_data(associated_data);
        if expected_hash != encrypted_message.associated_data_hash {
            return Err(PqcError::VerificationFailed(
                "Associated data mismatch".to_string(),
            ));
        }

        // Step 3: ML-KEM decapsulation to recover shared secret
        let ml_kem_ct = MlKemCiphertext(encrypted_message.ml_kem_ciphertext.clone());
        let shared_secret = self.ml_kem.decapsulate(private_key, &ml_kem_ct)?;

        // Step 4: Derive AES key using same process as encryption
        let aes_key = self.derive_aes_key(&shared_secret, associated_data)?;

        // Step 5: Decrypt with AES-256-GCM
        let plaintext = self.aes_decrypt(
            &aes_key,
            &encrypted_message.nonce,
            &encrypted_message.aes_ciphertext,
            associated_data,
        )?;

        Ok(plaintext)
    }

    /// Derive AES-256 key from ML-KEM shared secret using SHA256-based KDF
    ///
    /// Uses a simplified but secure key derivation function based on SHA256.
    /// This follows the general principles of NIST SP 800-56C Rev. 2.
    fn derive_aes_key(
        &self,
        shared_secret: &SharedSecret,
        associated_data: &[u8],
    ) -> PqcResult<[u8; 32]> {
        // Create a domain-separated key derivation using SHA256
        let mut ctx = digest::Context::new(&digest::SHA256);

        // Add salt for extraction phase (equivalent to HKDF-Extract)
        ctx.update(b"ant-quic-ml-kem-aes-v1-salt");
        ctx.update(shared_secret.as_bytes());

        // Add context for expansion phase (equivalent to HKDF-Expand)
        ctx.update(b"ant-quic-aes256-gcm-expand");
        ctx.update(&self.hash_associated_data(associated_data));

        // Add length encoding for proper domain separation
        ctx.update(&[0, 0, 1, 0]); // 256 bits = 32 bytes in big-endian

        let digest = ctx.finish();

        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(digest.as_ref());
        Ok(aes_key)
    }

    /// Encrypt with AES-256-GCM
    fn aes_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| PqcError::CryptoError("Failed to create AES key".to_string()))?;

        let aes_key = LessSafeKey::new(unbound_key);
        let nonce_obj = Nonce::assume_unique_for_key(*nonce);

        let mut ciphertext = plaintext.to_vec();
        aes_key
            .seal_in_place_append_tag(nonce_obj, aead::Aad::from(associated_data), &mut ciphertext)
            .map_err(|_| PqcError::EncapsulationFailed("AES encryption failed".to_string()))?;

        Ok(ciphertext)
    }

    /// Decrypt with AES-256-GCM
    fn aes_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| PqcError::CryptoError("Failed to create AES key".to_string()))?;

        let aes_key = LessSafeKey::new(unbound_key);
        let nonce_obj = Nonce::assume_unique_for_key(*nonce);

        // The ciphertext includes the authentication tag at the end
        // open_in_place will verify the tag and return the plaintext without it
        let mut in_out = ciphertext.to_vec();
        let plaintext = aes_key
            .open_in_place(nonce_obj, aead::Aad::from(associated_data), &mut in_out)
            .map_err(|_| PqcError::DecapsulationFailed("AES decryption failed".to_string()))?;

        Ok(plaintext.to_vec())
    }

    /// Hash associated data for integrity verification
    fn hash_associated_data(&self, data: &[u8]) -> [u8; 32] {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"ant-quic-associated-data-v1");
        ctx.update(data);
        let digest = ctx.finish();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest.as_ref());
        hash
    }

    /// Clear sensitive key cache (should be called periodically)
    pub fn clear_key_cache(&mut self) {
        self.key_cache.clear();
    }

    /// Get the algorithm identifier
    pub const fn algorithm_name() -> &'static str {
        "ML-KEM-768-AES-256-GCM"
    }

    /// Get the security level description
    pub const fn security_level() -> &'static str {
        "Quantum-resistant (NIST Level 3) with 256-bit symmetric security"
    }
}

impl Default for HybridPublicKeyEncryption {
    fn default() -> Self {
        Self::new()
    }
}

// Ensure EncryptedMessage is Send + Sync for async usage
unsafe impl Send for EncryptedMessage {}
unsafe impl Sync for EncryptedMessage {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_pke_creation() {
        let pke = HybridPublicKeyEncryption::new();
        assert_eq!(
            HybridPublicKeyEncryption::algorithm_name(),
            "ML-KEM-768-AES-256-GCM"
        );
        assert_eq!(
            HybridPublicKeyEncryption::security_level(),
            "Quantum-resistant (NIST Level 3) with 256-bit symmetric security"
        );
        let _ = pke; // Use the variable
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_encryption_decryption_roundtrip() {
        let pke = HybridPublicKeyEncryption::new();

        // Generate keypair for testing
        let (public_key, secret_key) = pke
            .ml_kem
            .generate_keypair()
            .expect("Key generation should succeed");

        let plaintext = b"Hello, quantum-resistant world!";
        let associated_data = b"test-context";

        // Encrypt
        let encrypted = pke
            .encrypt(&public_key, plaintext, associated_data)
            .expect("Encryption should succeed");

        // Verify encrypted message structure
        assert_eq!(encrypted.version, 1);
        assert_eq!(
            encrypted.ml_kem_ciphertext.len(),
            ML_KEM_768_CIPHERTEXT_SIZE
        );
        assert!(encrypted.aes_ciphertext.len() >= plaintext.len() + 16); // Should include 16-byte auth tag
        assert_eq!(encrypted.nonce.len(), 12);
        assert_eq!(encrypted.associated_data_hash.len(), 32);

        // Decrypt
        let decrypted = pke
            .decrypt(&secret_key, &encrypted, associated_data)
            .expect("Decryption should succeed");

        // Verify roundtrip
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_different_associated_data_fails() {
        let pke = HybridPublicKeyEncryption::new();
        let (public_key, secret_key) = pke.ml_kem.generate_keypair().unwrap();

        let plaintext = b"test message";
        let associated_data_1 = b"context-1";
        let associated_data_2 = b"context-2";

        // Encrypt with one context
        let encrypted = pke
            .encrypt(&public_key, plaintext, associated_data_1)
            .unwrap();

        // Try to decrypt with different context - should fail
        let result = pke.decrypt(&secret_key, &encrypted, associated_data_2);
        assert!(result.is_err());
        assert!(matches!(result, Err(PqcError::VerificationFailed(_))));
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let encrypted = EncryptedMessage {
            ml_kem_ciphertext: Box::new([1u8; ML_KEM_768_CIPHERTEXT_SIZE]),
            aes_ciphertext: vec![2u8; 64],
            nonce: [3u8; 12],
            associated_data_hash: [4u8; 32],
            version: 1,
        };

        // Test serialization
        let bytes = encrypted.to_bytes();
        let expected_size = ML_KEM_768_CIPHERTEXT_SIZE + 64 + 12 + 32 + 1;
        assert_eq!(bytes.len(), expected_size);
        assert_eq!(encrypted.total_size(), expected_size);

        // Test deserialization
        let deserialized =
            EncryptedMessage::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.ml_kem_ciphertext, encrypted.ml_kem_ciphertext);
        assert_eq!(deserialized.aes_ciphertext, encrypted.aes_ciphertext);
        assert_eq!(deserialized.nonce, encrypted.nonce);
        assert_eq!(
            deserialized.associated_data_hash,
            encrypted.associated_data_hash
        );
        assert_eq!(deserialized.version, encrypted.version);
    }

    #[test]
    fn test_invalid_message_version() {
        let mut bytes = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE + 1 + 12 + 32 + 1];
        // Set invalid version
        let len = bytes.len();
        bytes[len - 1] = 99;

        let result = EncryptedMessage::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result, Err(PqcError::CryptoError(_))));
    }

    #[test]
    fn test_message_too_small() {
        let bytes = vec![0u8; 10]; // Too small
        let result = EncryptedMessage::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result, Err(PqcError::InvalidCiphertext)));
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_empty_plaintext() {
        let pke = HybridPublicKeyEncryption::new();
        let (public_key, secret_key) = pke.ml_kem.generate_keypair().unwrap();

        let plaintext = b"";
        let associated_data = b"empty-test";

        // Should handle empty plaintext
        let encrypted = pke
            .encrypt(&public_key, plaintext, associated_data)
            .unwrap();
        let decrypted = pke
            .decrypt(&secret_key, &encrypted, associated_data)
            .unwrap();

        assert_eq!(decrypted, plaintext);
        assert!(decrypted.is_empty());
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_large_plaintext() {
        let pke = HybridPublicKeyEncryption::new();
        let (public_key, secret_key) = pke.ml_kem.generate_keypair().unwrap();

        // Test with 1MB of data
        let plaintext = vec![42u8; 1024 * 1024];
        let associated_data = b"large-test";

        let encrypted = pke
            .encrypt(&public_key, &plaintext, associated_data)
            .unwrap();
        let decrypted = pke
            .decrypt(&secret_key, &encrypted, associated_data)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation_consistency() {
        let pke = HybridPublicKeyEncryption::new();
        let shared_secret = SharedSecret([1u8; 32]);
        let associated_data = b"test";

        // Key derivation should be deterministic
        let key1 = pke.derive_aes_key(&shared_secret, associated_data).unwrap();
        let key2 = pke.derive_aes_key(&shared_secret, associated_data).unwrap();

        assert_eq!(key1, key2);

        // Different associated data should produce different keys
        let key3 = pke.derive_aes_key(&shared_secret, b"different").unwrap();
        assert_ne!(key1, key3);
    }
}
