// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Hybrid cryptography combiners for classical and post-quantum algorithms
//!
//! This module implements hybrid modes that combine classical algorithms with
//! post-quantum algorithms to provide defense-in-depth security. Even if one
//! algorithm is broken, the hybrid construction remains secure as long as the
//! other algorithm remains secure.
//!
//! # Hybrid Modes
//!
//! - **Hybrid KEM**: Combines classical ECDH with ML-KEM-768
//! - **Hybrid Signatures**: Combines classical signatures with ML-DSA-65
//!
//! # Security
//!
//! The hybrid constructions follow the principles from draft-ietf-tls-hybrid-design:
//! - KEM: Uses KDF to combine shared secrets (not XOR)
//! - Signatures: Concatenates both signatures, both must verify

use crate::crypto::pqc::combiners::{ConcatenationCombiner, HybridCombiner};
use crate::crypto::pqc::types::*;
use crate::crypto::pqc::{MlDsaOperations, MlKemOperations, ml_dsa::MlDsa65, ml_kem::MlKem768};
use ring::rand::{self, SecureRandom};
use ring::signature::{self, Ed25519KeyPair, KeyPair as SignatureKeyPair};
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Hybrid KEM combiner for classical ECDH and ML-KEM-768
///
/// This combiner provides quantum-resistant key exchange by combining
/// classical elliptic curve Diffie-Hellman with post-quantum ML-KEM.
#[derive(Clone)]
pub struct HybridKem {
    ml_kem: MlKem768,
    combiner: Arc<dyn HybridCombiner>,
    rng: Arc<dyn SecureRandom>,
}

impl HybridKem {
    /// Create a new hybrid KEM combiner
    pub fn new() -> Self {
        Self {
            ml_kem: MlKem768::new(),
            combiner: Arc::new(ConcatenationCombiner),
            rng: Arc::new(rand::SystemRandom::new()),
        }
    }

    /// Create with a specific combiner
    pub fn with_combiner(combiner: Arc<dyn HybridCombiner>) -> Self {
        Self {
            ml_kem: MlKem768::new(),
            combiner,
            rng: Arc::new(rand::SystemRandom::new()),
        }
    }

    /// Generate a hybrid keypair (classical + PQC)
    ///
    /// Returns both classical ECDH and ML-KEM keypairs
    pub fn generate_keypair(&self) -> PqcResult<(HybridKemPublicKey, HybridKemSecretKey)> {
        // Generate ML-KEM keypair
        let (ml_kem_pub, ml_kem_sec) = self.ml_kem.generate_keypair()?;

        // Generate X25519 keypair using proper elliptic curve operations
        let mut rng_bytes = [0u8; 32];
        self.rng
            .fill(&mut rng_bytes)
            .map_err(|_| PqcError::KeyGenerationFailed("Random generation failed".to_string()))?;

        let secret = StaticSecret::from(rng_bytes);
        let public = X25519PublicKey::from(&secret);

        let classical_sec = secret.to_bytes().to_vec();
        let classical_pub = public.to_bytes().to_vec();

        Ok((
            HybridKemPublicKey {
                classical: classical_pub.into_boxed_slice(),
                ml_kem: ml_kem_pub,
            },
            HybridKemSecretKey {
                classical: classical_sec.into_boxed_slice(),
                ml_kem: ml_kem_sec,
            },
        ))
    }

    /// Encapsulate using hybrid mode
    ///
    /// Performs both classical ECDH and ML-KEM encapsulation
    pub fn encapsulate(
        &self,
        public_key: &HybridKemPublicKey,
    ) -> PqcResult<(HybridKemCiphertext, SharedSecret)> {
        // Perform ML-KEM encapsulation
        let (ml_kem_ct, ml_kem_ss) = self.ml_kem.encapsulate(&public_key.ml_kem)?;

        // Generate ephemeral X25519 keypair for encapsulation
        // We use StaticSecret for ephemeral key since x25519-dalek's EphemeralSecret
        // doesn't allow creation from bytes
        let mut rng_bytes = [0u8; 32];
        self.rng
            .fill(&mut rng_bytes)
            .map_err(|_| PqcError::KeyGenerationFailed("Random generation failed".to_string()))?;
        let ephemeral_secret = StaticSecret::from(rng_bytes);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // Parse peer's public key
        let peer_public_bytes: [u8; 32] =
            public_key
                .classical
                .as_ref()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: 32,
                    actual: public_key.classical.len(),
                })?;
        let peer_public = X25519PublicKey::from(peer_public_bytes);

        // Perform X25519 key agreement
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);
        let classical_ss = shared_secret.to_bytes().to_vec();

        // Combine the shared secrets
        let info = b"hybrid-kem-encapsulation";
        let combined_ss = self
            .combiner
            .combine(&classical_ss, ml_kem_ss.as_bytes(), info)?;

        Ok((
            HybridKemCiphertext {
                classical: ephemeral_public.to_bytes().to_vec().into_boxed_slice(),
                ml_kem: ml_kem_ct,
            },
            combined_ss,
        ))
    }

    /// Decapsulate using hybrid mode
    ///
    /// Recovers shared secret from both classical and PQC components
    pub fn decapsulate(
        &self,
        secret_key: &HybridKemSecretKey,
        ciphertext: &HybridKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        // Perform ML-KEM decapsulation
        let ml_kem_ss = self
            .ml_kem
            .decapsulate(&secret_key.ml_kem, &ciphertext.ml_kem)?;

        // Parse our secret key
        let secret_key_bytes: [u8; 32] =
            secret_key
                .classical
                .as_ref()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: 32,
                    actual: secret_key.classical.len(),
                })?;
        let static_secret = StaticSecret::from(secret_key_bytes);

        // Parse ephemeral public key from ciphertext
        let ephemeral_public_bytes: [u8; 32] =
            ciphertext
                .classical
                .as_ref()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: 32,
                    actual: ciphertext.classical.len(),
                })?;
        let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);

        // Perform X25519 key agreement
        let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
        let classical_ss = shared_secret.to_bytes().to_vec();

        // Combine the shared secrets
        let info = b"hybrid-kem-encapsulation";
        let combined_ss = self
            .combiner
            .combine(&classical_ss, ml_kem_ss.as_bytes(), info)?;

        Ok(combined_ss)
    }

    /// Get the algorithm name
    pub const fn algorithm_name() -> &'static str {
        "Hybrid-ECDH-ML-KEM-768"
    }

    /// Get the combined security level
    pub const fn security_level() -> &'static str {
        "Classical 128-bit + Quantum 192-bit (NIST Level 3)"
    }

    /// Check if hybrid KEM is available
    pub fn is_available() -> bool {
        // Check if both classical and PQC are available
        // For now, we consider it available if ML-KEM is available
        true // Since we're using temporary classical implementation
    }
}

impl Default for HybridKem {
    fn default() -> Self {
        Self::new()
    }
}

/// Hybrid signature combiner for classical signatures and ML-DSA-65
///
/// This combiner provides quantum-resistant signatures by combining
/// classical signature algorithms with post-quantum ML-DSA.
#[derive(Clone)]
pub struct HybridSignature {
    ml_dsa: MlDsa65,
    rng: Arc<dyn SecureRandom>,
}

impl HybridSignature {
    /// Create a new hybrid signature combiner
    pub fn new() -> Self {
        Self {
            ml_dsa: MlDsa65::new(),
            rng: Arc::new(rand::SystemRandom::new()),
        }
    }

    /// Generate a hybrid signature keypair
    ///
    /// Returns both classical and ML-DSA keypairs
    pub fn generate_keypair(
        &self,
    ) -> PqcResult<(HybridSignaturePublicKey, HybridSignatureSecretKey)> {
        // Generate ML-DSA keypair
        let (ml_dsa_pub, ml_dsa_sec) = self.ml_dsa.generate_keypair()?;

        // Generate Ed25519 keypair
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(self.rng.as_ref())
            .map_err(|_| PqcError::KeyGenerationFailed("Ed25519 generation failed".to_string()))?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| PqcError::KeyGenerationFailed("Ed25519 from PKCS8 failed".to_string()))?;

        let classical_pub = key_pair.public_key().as_ref().to_vec().into_boxed_slice();
        let classical_sec = pkcs8_bytes.as_ref().to_vec().into_boxed_slice();

        Ok((
            HybridSignaturePublicKey {
                classical: classical_pub,
                ml_dsa: ml_dsa_pub,
            },
            HybridSignatureSecretKey {
                classical: classical_sec,
                ml_dsa: ml_dsa_sec,
            },
        ))
    }

    /// Sign a message using both algorithms
    ///
    /// Creates a hybrid signature containing both classical and PQC signatures
    pub fn sign(
        &self,
        secret_key: &HybridSignatureSecretKey,
        message: &[u8],
    ) -> PqcResult<HybridSignatureValue> {
        // Sign with ML-DSA
        let ml_dsa_sig = self.ml_dsa.sign(&secret_key.ml_dsa, message)?;

        // Sign with Ed25519
        let key_pair = Ed25519KeyPair::from_pkcs8(&secret_key.classical)
            .map_err(|_| PqcError::SigningFailed("Ed25519 key parsing failed".to_string()))?;

        let classical_sig = key_pair.sign(message);

        Ok(HybridSignatureValue {
            classical: classical_sig.as_ref().to_vec().into_boxed_slice(),
            ml_dsa: ml_dsa_sig.as_bytes().to_vec().into_boxed_slice(),
        })
    }

    /// Verify a hybrid signature
    ///
    /// Both classical and PQC signatures must verify for success
    pub fn verify(
        &self,
        public_key: &HybridSignaturePublicKey,
        message: &[u8],
        signature: &HybridSignatureValue,
    ) -> PqcResult<bool> {
        // Verify Ed25519 signature
        let ed25519_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, &public_key.classical);
        let classical_valid = ed25519_public_key
            .verify(message, &signature.classical)
            .is_ok();

        if !classical_valid {
            return Ok(false);
        }

        // Verify ML-DSA signature
        let ml_dsa_sig = MlDsaSignature::from_bytes(&signature.ml_dsa)
            .map_err(|_| PqcError::InvalidSignature)?;

        let ml_dsa_valid = self
            .ml_dsa
            .verify(&public_key.ml_dsa, message, &ml_dsa_sig)?;

        // Both must verify
        Ok(classical_valid && ml_dsa_valid)
    }

    /// Get the algorithm name
    pub const fn algorithm_name() -> &'static str {
        "Hybrid-Ed25519-ML-DSA-65"
    }

    /// Get the combined security level
    pub const fn security_level() -> &'static str {
        "Classical 128-bit + Quantum 192-bit (NIST Level 3)"
    }

    /// Get the total signature size
    pub const fn signature_size() -> usize {
        64 + ML_DSA_65_SIGNATURE_SIZE // Ed25519 (64) + ML-DSA-65 (3309)
    }

    /// Check if hybrid signatures are available
    pub fn is_available() -> bool {
        // Check if both classical and PQC are available
        // For now, we consider it available since we have Ed25519 + ML-DSA
        true
    }
}

impl Default for HybridSignature {
    fn default() -> Self {
        Self::new()
    }
}

/// Combines two shared secrets using a key derivation function
///
/// This is more secure than simple XOR as it provides proper entropy mixing.
/// Following draft-ietf-tls-hybrid-design, we concatenate the secrets and
/// apply a KDF to derive the final shared secret.
///
/// # Arguments
///
/// * `classical` - The classical ECDH shared secret
/// * `pqc` - The post-quantum ML-KEM shared secret
/// * `info` - Context-specific information for the KDF
///
/// # Security
///
/// The combined secret is at least as strong as the stronger of the two inputs.
/// If either algorithm is secure, the combined output remains secure.
#[allow(dead_code)]
fn combine_shared_secrets(classical: &[u8], pqc: &[u8], info: &[u8]) -> SharedSecret {
    use ring::digest;

    // Following the hybrid design draft, concatenate classical || pqc
    let mut combined = Vec::with_capacity(classical.len() + pqc.len());
    combined.extend_from_slice(classical);
    combined.extend_from_slice(pqc);

    // Use HKDF-Extract with SHA-256 to derive the final secret
    // In a real implementation, we would use proper HKDF
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&combined);
    ctx.update(info);
    let digest = ctx.finish();

    // Take the first 32 bytes as our shared secret
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&digest.as_ref()[..32]);

    SharedSecret(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_creation() {
        let hybrid_kem = HybridKem::new();
        let _hybrid_kem2: HybridKem = Default::default();

        // Just verify creation works
        let _ = hybrid_kem;
    }

    #[test]
    fn test_hybrid_kem_key_generation() {
        let hybrid_kem = HybridKem::new();
        let result = hybrid_kem.generate_keypair();

        assert!(result.is_ok());
        let (pub_key, sec_key) = result.unwrap();
        assert_eq!(pub_key.classical.len(), 32); // X25519 public key
        assert_eq!(pub_key.ml_kem.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sec_key.classical.len(), 32); // X25519 secret key
        assert_eq!(sec_key.ml_kem.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_kem_encapsulation() {
        let hybrid_kem = HybridKem::new();

        // Generate a proper keypair first
        let (public_key, _) = hybrid_kem.generate_keypair().unwrap();

        let result = hybrid_kem.encapsulate(&public_key);
        assert!(result.is_ok());

        let (ciphertext, shared_secret) = result.unwrap();
        assert_eq!(ciphertext.classical.len(), 32); // X25519 ephemeral public key
        assert_eq!(
            ciphertext.ml_kem.as_bytes().len(),
            ML_KEM_768_CIPHERTEXT_SIZE
        );
        assert_eq!(shared_secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_hybrid_kem_decapsulation() {
        let hybrid_kem = HybridKem::new();

        // Generate keypair and encapsulate first
        let (public_key, secret_key) = hybrid_kem.generate_keypair().unwrap();
        let (ciphertext, _expected_ss) = hybrid_kem.encapsulate(&public_key).unwrap();

        let result = hybrid_kem.decapsulate(&secret_key, &ciphertext);
        assert!(result.is_ok());

        let shared_secret = result.unwrap();
        assert_eq!(shared_secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_hybrid_signature_creation() {
        let hybrid_sig = HybridSignature::new();
        let _hybrid_sig2: HybridSignature = Default::default();

        // Just verify creation works
        let _ = hybrid_sig;
    }

    #[test]
    fn test_hybrid_signature_key_generation() {
        let hybrid_sig = HybridSignature::new();
        let result = hybrid_sig.generate_keypair();

        assert!(result.is_ok());
        let (pub_key, sec_key) = result.unwrap();
        assert_eq!(pub_key.classical.len(), 32); // Ed25519 public key
        assert_eq!(pub_key.ml_dsa.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        // Secret key will be PKCS8 format, so size varies
        assert!(sec_key.classical.len() > 32);
        assert_eq!(sec_key.ml_dsa.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_signature_signing() {
        let hybrid_sig = HybridSignature::new();

        // Generate proper keypair first
        let (_, secret_key) = hybrid_sig.generate_keypair().unwrap();

        let message = b"Test message for hybrid signing";
        let result = hybrid_sig.sign(&secret_key, message);

        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.classical.len(), 64); // Ed25519 signature
        assert_eq!(signature.ml_dsa.len(), ML_DSA_65_SIGNATURE_SIZE);
    }

    #[test]
    fn test_hybrid_signature_verification() {
        let hybrid_sig = HybridSignature::new();

        // Generate keypair and sign first
        let (public_key, secret_key) = hybrid_sig.generate_keypair().unwrap();
        let message = b"Test message for verification";
        let signature = hybrid_sig.sign(&secret_key, message).unwrap();

        let result = hybrid_sig.verify(&public_key, message, &signature);
        assert!(result.is_ok(), "Verification returned error: {:?}", result);
        let is_valid = result.unwrap();
        assert!(is_valid, "Signature verification failed");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let result = hybrid_sig.verify(&public_key, wrong_message, &signature);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_combine_shared_secrets() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let combined = combine_shared_secrets(&classical, &pqc, info);

        // Verify the output has correct length
        assert_eq!(combined.as_bytes().len(), 32);

        // Verify it's deterministic
        let combined2 = combine_shared_secrets(&classical, &pqc, info);
        assert_eq!(combined.as_bytes(), combined2.as_bytes());

        // Verify different inputs produce different outputs
        let different_classical = [3u8; 32];
        let combined3 = combine_shared_secrets(&different_classical, &pqc, info);
        assert_ne!(combined.as_bytes(), combined3.as_bytes());
    }

    #[test]
    fn test_hybrid_kem_utility_methods() {
        assert_eq!(HybridKem::algorithm_name(), "Hybrid-ECDH-ML-KEM-768");
        assert_eq!(
            HybridKem::security_level(),
            "Classical 128-bit + Quantum 192-bit (NIST Level 3)"
        );

        assert!(HybridKem::is_available()); // Always available now
    }

    #[test]
    fn test_hybrid_signature_utility_methods() {
        assert_eq!(
            HybridSignature::algorithm_name(),
            "Hybrid-Ed25519-ML-DSA-65"
        );
        assert_eq!(
            HybridSignature::security_level(),
            "Classical 128-bit + Quantum 192-bit (NIST Level 3)"
        );
        assert_eq!(
            HybridSignature::signature_size(),
            64 + ML_DSA_65_SIGNATURE_SIZE
        );

        assert!(HybridSignature::is_available()); // Always available now
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let hybrid_kem = HybridKem::new();

        // Generate hybrid keypair
        let (public_key, secret_key) = hybrid_kem
            .generate_keypair()
            .expect("Hybrid key generation should succeed");

        // Encapsulate
        let (ciphertext, shared_secret1) = hybrid_kem
            .encapsulate(&public_key)
            .expect("Hybrid encapsulation should succeed");

        // Decapsulate
        let shared_secret2 = hybrid_kem
            .decapsulate(&secret_key, &ciphertext)
            .expect("Hybrid decapsulation should succeed");

        // Verify shared secrets match
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let hybrid_sig = HybridSignature::new();

        // Generate hybrid keypair
        let (public_key, secret_key) = hybrid_sig
            .generate_keypair()
            .expect("Hybrid key generation should succeed");

        // Sign message
        let message = b"Test message for hybrid signature";
        let signature = hybrid_sig
            .sign(&secret_key, message)
            .expect("Hybrid signing should succeed");

        // Verify signature
        let is_valid = hybrid_sig
            .verify(&public_key, message, &signature)
            .expect("Hybrid verification should succeed");
        assert!(is_valid);

        // Verify with wrong message fails
        let wrong_message = b"Different message";
        let is_valid = hybrid_sig
            .verify(&public_key, wrong_message, &signature)
            .expect("Hybrid verification should succeed");
        assert!(!is_valid);
    }

    #[test]
    #[ignore = "Placeholder for future security property tests"]
    fn test_hybrid_security_properties() {
        // Test that hybrid remains secure if one algorithm fails
        // This would involve simulating algorithm compromise
        // and verifying the hybrid construction still provides security
        // TODO: Implement when we have formal security property verification
    }
}
