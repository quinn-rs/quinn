//! ML-KEM-768 implementation using aws-lc-rs
//!
//! This module provides the implementation of Module Lattice-based Key Encapsulation
//! Mechanism (ML-KEM) as specified in FIPS 203, using aws-lc-rs.
//!
//! Note: Since aws-lc-rs doesn't expose raw private key serialization for ML-KEM,
//! we store the entire DecapsulationKey object during key generation and use
//! a temporary in-memory cache for key operations. For production use, you would
//! need to implement proper key storage using PKCS#8 encoding or secure key storage.

use crate::crypto::pqc::MlKemOperations;
use crate::crypto::pqc::types::*;

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::kem::{
    Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768,
    SharedSecret as AwsSharedSecret,
};

#[cfg(feature = "aws-lc-rs")]
use std::collections::HashMap;
#[cfg(feature = "aws-lc-rs")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "aws-lc-rs")]
use std::time::{Duration, Instant};

/// Cached key entry with timestamp
#[cfg(feature = "aws-lc-rs")]
struct CachedKey {
    key: Arc<DecapsulationKey>,
    created_at: Instant,
}

/// ML-KEM-768 implementation using aws-lc-rs
pub struct MlKem768Impl {
    #[cfg(feature = "aws-lc-rs")]
    algorithm: &'static Algorithm,
    /// Temporary key storage - maps secret key bytes to DecapsulationKey
    /// In production, this should be replaced with proper key management
    #[cfg(feature = "aws-lc-rs")]
    key_cache: Arc<Mutex<HashMap<Vec<u8>, CachedKey>>>,
}

impl MlKem768Impl {
    /// Create a new ML-KEM-768 implementation
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            algorithm: &ML_KEM_768,
            #[cfg(feature = "aws-lc-rs")]
            key_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clean up old entries from key cache
    ///
    /// This should be called periodically to prevent memory leaks.
    /// Removes entries older than the specified duration.
    #[cfg(feature = "aws-lc-rs")]
    pub fn cleanup_cache(&self, max_age: Duration) {
        if let Ok(mut cache) = self.key_cache.lock() {
            let now = Instant::now();
            cache.retain(|_, entry| now.duration_since(entry.created_at) < max_age);
        }
    }

    /// Get the current size of the key cache
    #[cfg(feature = "aws-lc-rs")]
    pub fn cache_size(&self) -> usize {
        self.key_cache.lock().map(|cache| cache.len()).unwrap_or(0)
    }

    /// Clear all entries from the key cache
    #[cfg(feature = "aws-lc-rs")]
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.key_cache.lock() {
            cache.clear();
        }
    }
}

impl Clone for MlKem768Impl {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            algorithm: self.algorithm,
            #[cfg(feature = "aws-lc-rs")]
            key_cache: Arc::clone(&self.key_cache),
        }
    }
}

#[cfg(feature = "aws-lc-rs")]
impl MlKemOperations for MlKem768Impl {
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        // Generate a decapsulation (private) key
        let decapsulation_key = DecapsulationKey::generate(self.algorithm)
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        // Get the encapsulation (public) key
        let encapsulation_key = decapsulation_key
            .encapsulation_key()
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        // Extract public key bytes
        let public_key_bytes = encapsulation_key
            .key_bytes()
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        // For ML-KEM, we need to store the full DecapsulationKey since aws-lc-rs
        // doesn't expose raw private key serialization. We'll use a unique identifier
        // based on the public key bytes as a temporary solution.
        let key_id = public_key_bytes.as_ref().to_vec();

        // Store the decapsulation key in our cache with timestamp
        {
            let mut cache = self.key_cache.lock().map_err(|_| {
                PqcError::KeyGenerationFailed("Failed to acquire key cache lock".to_string())
            })?;
            cache.insert(
                key_id.clone(),
                CachedKey {
                    key: Arc::new(decapsulation_key),
                    created_at: Instant::now(),
                },
            );
        }

        // Ensure correct sizes
        if public_key_bytes.as_ref().len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidPublicKey);
        }

        // Create our key types
        let mut public_key = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
        let mut secret_key = Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]);

        public_key.copy_from_slice(public_key_bytes.as_ref());

        // For the secret key, we store the public key as an identifier
        // This is a temporary solution - in production, use proper key storage
        secret_key[..ML_KEM_768_PUBLIC_KEY_SIZE].copy_from_slice(public_key_bytes.as_ref());

        Ok((MlKemPublicKey(public_key), MlKemSecretKey(secret_key)))
    }

    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        if public_key.0.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidPublicKey);
        }

        // Reconstruct the encapsulation key from bytes
        let encapsulation_key = EncapsulationKey::new(self.algorithm, public_key.0.as_ref())
            .map_err(|_| PqcError::InvalidPublicKey)?;

        // Perform encapsulation
        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate()
            .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;

        // Extract bytes
        let ciphertext_bytes = ciphertext.as_ref();
        let shared_secret_bytes = shared_secret.as_ref();

        // Ensure correct sizes
        if ciphertext_bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidCiphertext);
        }
        if shared_secret_bytes.len() != ML_KEM_768_SHARED_SECRET_SIZE {
            return Err(PqcError::InvalidSharedSecret);
        }

        // Create our types
        let mut ct = Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]);
        let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];

        ct.copy_from_slice(ciphertext_bytes);
        ss.copy_from_slice(shared_secret_bytes);

        Ok((MlKemCiphertext(ct), SharedSecret(ss)))
    }

    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        if secret_key.0.len() != ML_KEM_768_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidSecretKey);
        }
        if ciphertext.0.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidCiphertext);
        }

        // Extract the key identifier (public key) from the secret key
        let key_id = secret_key.0[..ML_KEM_768_PUBLIC_KEY_SIZE].to_vec();

        // Retrieve the decapsulation key from cache
        let decapsulation_key = {
            let cache = self.key_cache.lock().map_err(|_| {
                PqcError::DecapsulationFailed("Failed to acquire key cache lock".to_string())
            })?;
            cache
                .get(&key_id)
                .map(|entry| entry.key.clone())
                .ok_or(PqcError::InvalidSecretKey)?
        };

        // Create ciphertext from bytes (convert array ref to slice)
        let ct = Ciphertext::from(&ciphertext.0[..]);

        // Perform decapsulation
        let shared_secret = decapsulation_key
            .decapsulate(ct)
            .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;

        // Extract bytes
        let shared_secret_bytes = shared_secret.as_ref();

        // Ensure correct size
        if shared_secret_bytes.len() != ML_KEM_768_SHARED_SECRET_SIZE {
            return Err(PqcError::InvalidSharedSecret);
        }

        // Create our type
        let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        ss.copy_from_slice(shared_secret_bytes);

        Ok(SharedSecret(ss))
    }
}

// Fallback implementation when aws-lc-rs is not available
#[cfg(not(feature = "aws-lc-rs"))]
impl MlKemOperations for MlKem768Impl {
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        // Without aws-lc-rs, we can't provide real ML-KEM
        // This is just a placeholder that generates random bytes
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut pub_key = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
        let mut sec_key = Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]);

        rng.fill_bytes(&mut pub_key[..]);
        rng.fill_bytes(&mut sec_key[..]);

        // Copy public key to beginning of secret key to match the aws-lc-rs implementation
        sec_key[..ML_KEM_768_PUBLIC_KEY_SIZE].copy_from_slice(&pub_key[..]);

        Ok((MlKemPublicKey(pub_key), MlKemSecretKey(sec_key)))
    }

    fn encapsulate(
        &self,
        _public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        // Without aws-lc-rs, we can't provide real ML-KEM
        Err(PqcError::FeatureNotAvailable)
    }

    fn decapsulate(
        &self,
        _secret_key: &MlKemSecretKey,
        _ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        // Without aws-lc-rs, we can't provide real ML-KEM
        Err(PqcError::FeatureNotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_kem_768_key_generation() {
        let ml_kem = MlKem768Impl::new();
        let result = ml_kem.generate_keypair();

        assert!(result.is_ok());
        let (pub_key, sec_key) = result.unwrap();

        assert_eq!(pub_key.0.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sec_key.0.len(), ML_KEM_768_SECRET_KEY_SIZE);
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_kem_768_roundtrip() {
        let ml_kem = MlKem768Impl::new();

        // Generate keypair
        let (pub_key, sec_key) = ml_kem.generate_keypair().unwrap();

        // Encapsulate
        let (ciphertext, ss1) = ml_kem.encapsulate(&pub_key).unwrap();

        // Decapsulate
        let ss2 = ml_kem.decapsulate(&sec_key, &ciphertext).unwrap();

        // The shared secrets should match
        assert_eq!(ss1.0, ss2.0);
        assert_eq!(ss1.0.len(), ML_KEM_768_SHARED_SECRET_SIZE);
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_ml_kem_768_sizes() {
        let ml_kem = MlKem768Impl::new();

        let (pub_key, sec_key) = ml_kem.generate_keypair().unwrap();
        let (ciphertext, shared_secret) = ml_kem.encapsulate(&pub_key).unwrap();

        assert_eq!(pub_key.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sec_key.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
        assert_eq!(ciphertext.as_bytes().len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(
            shared_secret.as_bytes().len(),
            ML_KEM_768_SHARED_SECRET_SIZE
        );
    }

    #[test]
    #[cfg(not(feature = "aws-lc-rs"))]
    fn test_ml_kem_without_feature() {
        let ml_kem = MlKem768Impl::new();

        // Key generation should work (returns random bytes)
        let keypair_result = ml_kem.generate_keypair();
        assert!(keypair_result.is_ok());

        let (pub_key, sec_key) = keypair_result.unwrap();

        // Encapsulation should fail without the feature
        let encap_result = ml_kem.encapsulate(&pub_key);
        assert!(encap_result.is_err());
        assert!(matches!(encap_result, Err(PqcError::FeatureNotAvailable)));

        // Decapsulation should also fail
        let ct = MlKemCiphertext(Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]));
        let decap_result = ml_kem.decapsulate(&sec_key, &ct);
        assert!(decap_result.is_err());
        assert!(matches!(decap_result, Err(PqcError::FeatureNotAvailable)));
    }
}
