// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-DSA-65 implementation using aws-lc-rs
//!
//! This module provides the implementation of Module Lattice-based Digital Signature
//! Algorithm (ML-DSA) as specified in FIPS 204, using aws-lc-rs.

use crate::crypto::pqc::MlDsaOperations;
use crate::crypto::pqc::types::*;

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::{
    encoding::AsDer,
    signature::{KeyPair, UnparsedPublicKey},
    unstable::signature::{
        ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, PqdsaSigningAlgorithm,
        PqdsaVerificationAlgorithm,
    },
};

#[cfg(feature = "aws-lc-rs")]
use std::collections::HashMap;
#[cfg(feature = "aws-lc-rs")]
use std::sync::{Arc, Mutex};

/// Cached key entry for ML-DSA
#[cfg(feature = "aws-lc-rs")]
struct CachedDsaKey {
    key_pair: Arc<PqdsaKeyPair>,
    public_key_der: Vec<u8>,
}

/// ML-DSA-65 implementation using aws-lc-rs
pub struct MlDsa65Impl {
    #[cfg(feature = "aws-lc-rs")]
    signing_alg: &'static PqdsaSigningAlgorithm,
    #[cfg(feature = "aws-lc-rs")]
    verification_alg: &'static PqdsaVerificationAlgorithm,
    /// Key cache - maps public key bytes to full key pair
    /// This is needed because aws-lc-rs doesn't expose private key serialization
    #[cfg(feature = "aws-lc-rs")]
    key_cache: Arc<Mutex<HashMap<Vec<u8>, CachedDsaKey>>>,
}

impl MlDsa65Impl {
    /// Create a new ML-DSA-65 implementation
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            signing_alg: &ML_DSA_65_SIGNING,
            #[cfg(feature = "aws-lc-rs")]
            verification_alg: &ML_DSA_65,
            #[cfg(feature = "aws-lc-rs")]
            key_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clear the key cache
    #[cfg(feature = "aws-lc-rs")]
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.key_cache.lock() {
            cache.clear();
        }
    }
}

impl Clone for MlDsa65Impl {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            signing_alg: self.signing_alg,
            #[cfg(feature = "aws-lc-rs")]
            verification_alg: self.verification_alg,
            #[cfg(feature = "aws-lc-rs")]
            key_cache: Arc::clone(&self.key_cache),
        }
    }
}

#[cfg(feature = "aws-lc-rs")]
impl MlDsaOperations for MlDsa65Impl {
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        // Generate a new key pair
        let key_pair = PqdsaKeyPair::generate(self.signing_alg)
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        // Extract public key bytes
        let public_key_der = key_pair
            .public_key()
            .as_der()
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        let public_key_bytes = public_key_der.as_ref().to_vec();

        // Store the key pair in cache
        {
            let mut cache = self.key_cache.lock().map_err(|_| {
                PqcError::KeyGenerationFailed("Failed to acquire key cache lock".to_string())
            })?;

            // Use first ML_DSA_65_PUBLIC_KEY_SIZE bytes as the key for consistency
            let key_id = if public_key_bytes.len() >= ML_DSA_65_PUBLIC_KEY_SIZE {
                public_key_bytes[..ML_DSA_65_PUBLIC_KEY_SIZE].to_vec()
            } else {
                let mut padded = vec![0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
                padded[..public_key_bytes.len()].copy_from_slice(&public_key_bytes);
                padded
            };

            cache.insert(
                key_id,
                CachedDsaKey {
                    key_pair: Arc::new(key_pair),
                    public_key_der: public_key_bytes.clone(),
                },
            );
        }

        // Create our key types
        let mut public_key = Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]);
        let mut secret_key = Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);

        // For public key, we'll store the actual DER-encoded public key
        let pub_copy_len = public_key_bytes.len().min(ML_DSA_65_PUBLIC_KEY_SIZE);
        public_key[..pub_copy_len].copy_from_slice(&public_key_bytes[..pub_copy_len]);

        // For secret key, we store the public key as an identifier (same as ML-KEM)
        secret_key[..pub_copy_len].copy_from_slice(&public_key_bytes[..pub_copy_len]);

        Ok((MlDsaPublicKey(public_key), MlDsaSecretKey(secret_key)))
    }

    fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        // Extract the public key identifier from the secret key
        let key_id = secret_key.0[..ML_DSA_65_PUBLIC_KEY_SIZE].to_vec();

        // Retrieve the key pair from cache
        let key_pair = {
            let cache = self.key_cache.lock().map_err(|_| {
                PqcError::SigningFailed("Failed to acquire key cache lock".to_string())
            })?;

            cache
                .get(&key_id)
                .map(|entry| entry.key_pair.clone())
                .ok_or(PqcError::InvalidSecretKey)?
        };

        // Sign the message
        let mut signature_bytes = vec![0u8; self.signing_alg.signature_len()];
        let sig_len = key_pair
            .sign(message, &mut signature_bytes)
            .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

        signature_bytes.truncate(sig_len);

        // Ensure correct size
        if signature_bytes.len() > ML_DSA_65_SIGNATURE_SIZE {
            return Err(PqcError::InvalidSignature);
        }

        // Create our signature type
        let mut sig = Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]);
        sig[..signature_bytes.len()].copy_from_slice(&signature_bytes);

        Ok(MlDsaSignature(sig))
    }

    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        // The public key identifier is stored in the public key
        let key_id = public_key.0[..ML_DSA_65_PUBLIC_KEY_SIZE].to_vec();

        // Find the cached entry to get the original DER-encoded public key
        let public_key_der = {
            let cache = self.key_cache.lock().map_err(|_| {
                PqcError::VerificationFailed("Failed to acquire key cache lock".to_string())
            })?;

            cache
                .get(&key_id)
                .map(|entry| entry.public_key_der.clone())
                .ok_or(PqcError::VerificationFailed(
                    "Public key not found in cache".to_string(),
                ))?
        };

        // Create unparsed public key for verification
        let unparsed_public_key = UnparsedPublicKey::new(self.verification_alg, &public_key_der);

        // Find the actual signature length (non-zero bytes from the end)
        let mut sig_len = ML_DSA_65_SIGNATURE_SIZE;
        for i in (0..ML_DSA_65_SIGNATURE_SIZE).rev() {
            if signature.0[i] != 0 {
                sig_len = i + 1;
                break;
            }
        }

        if sig_len == 0 {
            return Ok(false);
        }

        // Verify the signature
        match unparsed_public_key.verify(message, &signature.0[..sig_len]) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Fallback implementation when aws-lc-rs is not available
#[cfg(not(feature = "aws-lc-rs"))]
impl MlDsaOperations for MlDsa65Impl {
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        // Without aws-lc-rs, we can't provide real ML-DSA
        // This is just a placeholder that generates random bytes
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut pub_key = Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]);
        let mut sec_key = Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);

        rng.fill_bytes(&mut pub_key[..]);
        rng.fill_bytes(&mut sec_key[..]);

        Ok((MlDsaPublicKey(pub_key), MlDsaSecretKey(sec_key)))
    }

    fn sign(&self, _secret_key: &MlDsaSecretKey, _message: &[u8]) -> PqcResult<MlDsaSignature> {
        // Without aws-lc-rs, we can't provide real ML-DSA
        Err(PqcError::FeatureNotAvailable)
    }

    fn verify(
        &self,
        _public_key: &MlDsaPublicKey,
        _message: &[u8],
        _signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        // Without aws-lc-rs, we can't provide real ML-DSA
        Err(PqcError::FeatureNotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_dsa_65_key_generation() {
        let ml_dsa = MlDsa65Impl::new();
        let result = ml_dsa.generate_keypair();

        assert!(result.is_ok());
        let (pub_key, sec_key) = result.unwrap();

        assert_eq!(pub_key.0.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(sec_key.0.len(), ML_DSA_65_SECRET_KEY_SIZE);
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_dsa_65_sign_verify() {
        let ml_dsa = MlDsa65Impl::new();

        // Generate keypair
        let (pub_key, sec_key) = ml_dsa.generate_keypair().unwrap();

        // Sign message
        let message = b"Test message for ML-DSA-65";
        let signature = ml_dsa.sign(&sec_key, message).unwrap();

        assert_eq!(signature.0.len(), ML_DSA_65_SIGNATURE_SIZE);

        // Verify signature
        let valid = ml_dsa.verify(&pub_key, message, &signature).unwrap();
        assert!(valid, "Signature should be valid");

        // Verify with wrong message
        let wrong_message = b"Different message";
        let invalid = ml_dsa.verify(&pub_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_dsa_65_verify_with_different_key() {
        let ml_dsa = MlDsa65Impl::new();

        // Generate two different keypairs
        let (pub_key1, sec_key1) = ml_dsa.generate_keypair().unwrap();
        let (pub_key2, _sec_key2) = ml_dsa.generate_keypair().unwrap();

        // Sign with first key
        let message = b"Test message";
        let signature = ml_dsa.sign(&sec_key1, message).unwrap();

        // Verify with correct key
        let valid = ml_dsa.verify(&pub_key1, message, &signature).unwrap();
        assert!(valid);

        // Verify with wrong key should fail
        let invalid = ml_dsa.verify(&pub_key2, message, &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    #[cfg(not(feature = "aws-lc-rs"))]
    fn test_ml_dsa_without_feature() {
        let ml_dsa = MlDsa65Impl::new();

        // Key generation should work (returns random bytes)
        let keypair_result = ml_dsa.generate_keypair();
        assert!(keypair_result.is_ok());

        let (pub_key, sec_key) = keypair_result.unwrap();

        // Signing should fail without the feature
        let message = b"test";
        let sign_result = ml_dsa.sign(&sec_key, message);
        assert!(sign_result.is_err());
        assert!(matches!(sign_result, Err(PqcError::FeatureNotAvailable)));

        // Verification should also fail
        let sig = MlDsaSignature(Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]));
        let verify_result = ml_dsa.verify(&pub_key, message, &sig);
        assert!(verify_result.is_err());
        assert!(matches!(verify_result, Err(PqcError::FeatureNotAvailable)));
    }
}
