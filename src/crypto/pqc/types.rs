// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Type definitions for Post-Quantum Cryptography

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for PQC operations
pub type PqcResult<T> = Result<T, PqcError>;

/// Errors that can occur during PQC operations
#[derive(Debug, Error, Clone)]
pub enum PqcError {
    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid ciphertext size
    #[error("Invalid ciphertext size: expected {expected}, got {actual}")]
    InvalidCiphertextSize { expected: usize, actual: usize },

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// Invalid signature size
    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize { expected: usize, actual: usize },

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Feature not available
    #[error("PQC feature not enabled")]
    FeatureNotAvailable,

    /// Generic cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Memory pool error
    #[error("Memory pool error: {0}")]
    PoolError(String),

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Invalid shared secret
    #[error("Invalid shared secret")]
    InvalidSharedSecret,

    /// Operation not supported
    #[error("Operation not supported")]
    OperationNotSupported,

    /// Negotiation failed
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Key exchange failed
    #[error("Key exchange failed")]
    KeyExchangeFailed,
}

// ML-KEM-768 constants
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

// ML-DSA-65 constants
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// ML-KEM-768 public key
#[derive(Clone)]
pub struct MlKemPublicKey(pub Box<[u8; ML_KEM_768_PUBLIC_KEY_SIZE]>);

impl MlKemPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

impl Serialize for MlKemPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlKemPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// ML-KEM-768 secret key
#[derive(ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub Box<[u8; ML_KEM_768_SECRET_KEY_SIZE]>);

impl Zeroize for MlKemSecretKey {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl MlKemSecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

impl Serialize for MlKemSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlKemSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// ML-KEM-768 ciphertext
#[derive(Clone)]
pub struct MlKemCiphertext(pub Box<[u8; ML_KEM_768_CIPHERTEXT_SIZE]>);

impl MlKemCiphertext {
    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidCiphertextSize {
                expected: ML_KEM_768_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut ct = Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]);
        ct.copy_from_slice(bytes);
        Ok(Self(ct))
    }
}

impl Serialize for MlKemCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlKemCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// ML-DSA-65 public key
#[derive(Clone)]
pub struct MlDsaPublicKey(pub Box<[u8; ML_DSA_65_PUBLIC_KEY_SIZE]>);

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPublicKey({} bytes)", self.0.len())
    }
}

impl MlDsaPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

impl Serialize for MlDsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlDsaPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// ML-DSA-65 secret key
#[derive(ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub Box<[u8; ML_DSA_65_SECRET_KEY_SIZE]>);

impl Zeroize for MlDsaSecretKey {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl MlDsaSecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_65_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

impl Serialize for MlDsaSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlDsaSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// ML-DSA-65 signature
#[derive(Clone)]
pub struct MlDsaSignature(pub Box<[u8; ML_DSA_65_SIGNATURE_SIZE]>);

impl MlDsaSignature {
    /// Get the signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(PqcError::InvalidSignatureSize {
                expected: ML_DSA_65_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut sig = Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]);
        sig.copy_from_slice(bytes);
        Ok(Self(sig))
    }
}

impl Serialize for MlDsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for MlDsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Shared secret from key encapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; ML_KEM_768_SHARED_SECRET_SIZE]);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([..{}])", self.0.len())
    }
}

impl SharedSecret {
    /// Get the shared secret as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_SHARED_SECRET_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_SHARED_SECRET_SIZE,
                actual: bytes.len(),
            });
        }
        let mut secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        secret.copy_from_slice(bytes);
        Ok(Self(secret))
    }
}

// Hybrid types for combining classical and PQC algorithms

/// Hybrid KEM public key (classical + ML-KEM)
#[derive(Clone)]
pub struct HybridKemPublicKey {
    /// Classical ECDH public key (e.g., P-256)
    pub classical: Box<[u8]>,
    /// ML-KEM-768 public key
    pub ml_kem: MlKemPublicKey,
}

/// Hybrid KEM secret key (classical + ML-KEM)
#[derive(ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    /// Classical ECDH private key
    pub classical: Box<[u8]>,
    /// ML-KEM-768 secret key
    pub ml_kem: MlKemSecretKey,
}

impl Zeroize for HybridKemSecretKey {
    fn zeroize(&mut self) {
        self.classical.as_mut().zeroize();
        self.ml_kem.zeroize();
    }
}

/// Hybrid KEM ciphertext (classical + ML-KEM)
#[derive(Clone)]
pub struct HybridKemCiphertext {
    /// Classical ECDH ephemeral public key
    pub classical: Box<[u8]>,
    /// ML-KEM-768 ciphertext
    pub ml_kem: MlKemCiphertext,
}

/// Hybrid signature public key (classical + ML-DSA)
#[derive(Clone)]
pub struct HybridSignaturePublicKey {
    /// Classical signature public key (e.g., Ed25519)
    pub classical: Box<[u8]>,
    /// ML-DSA-65 public key
    pub ml_dsa: MlDsaPublicKey,
}

/// Hybrid signature secret key (classical + ML-DSA)
#[derive(ZeroizeOnDrop)]
pub struct HybridSignatureSecretKey {
    /// Classical signature private key
    pub classical: Box<[u8]>,
    /// ML-DSA-65 secret key
    pub ml_dsa: MlDsaSecretKey,
}

impl Zeroize for HybridSignatureSecretKey {
    fn zeroize(&mut self) {
        self.classical.as_mut().zeroize();
        self.ml_dsa.zeroize();
    }
}

/// Hybrid signature value (classical + ML-DSA signatures)
#[derive(Clone)]
pub struct HybridSignatureValue {
    /// Classical signature (e.g., Ed25519 signature)
    pub classical: Box<[u8]>,
    /// ML-DSA-65 signature
    pub ml_dsa: Box<[u8]>,
}

#[cfg(all(test, feature = "pqc"))]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_error_conversions() {
        // Test error type conversions and display
        let err = PqcError::InvalidKeySize {
            expected: 1184,
            actual: 1000,
        };
        assert_eq!(err.to_string(), "Invalid key size: expected 1184, got 1000");

        let err = PqcError::KeyGenerationFailed("test failure".to_string());
        assert_eq!(err.to_string(), "Key generation failed: test failure");
    }

    #[test]
    fn test_constant_sizes() {
        // Verify constant sizes match NIST standards
        assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(ML_KEM_768_SECRET_KEY_SIZE, 2400);
        assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, 1088);
        assert_eq!(ML_KEM_768_SHARED_SECRET_SIZE, 32);

        assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(ML_DSA_65_SECRET_KEY_SIZE, 4032);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_ml_kem_public_key_serialization() {
        // Create a test public key
        let test_data = vec![42u8; ML_KEM_768_PUBLIC_KEY_SIZE];
        let key = MlKemPublicKey::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&key).unwrap();

        // Deserialize
        let deserialized: MlKemPublicKey = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ml_kem_secret_key_serialization() {
        // Create a test secret key
        let test_data = vec![43u8; ML_KEM_768_SECRET_KEY_SIZE];
        let key = MlKemSecretKey::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&key).unwrap();

        // Deserialize
        let deserialized: MlKemSecretKey = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ml_kem_ciphertext_serialization() {
        // Create a test ciphertext
        let test_data = vec![44u8; ML_KEM_768_CIPHERTEXT_SIZE];
        let ct = MlKemCiphertext::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&ct).unwrap();

        // Deserialize
        let deserialized: MlKemCiphertext = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(ct.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ml_dsa_public_key_serialization() {
        // Create a test public key
        let test_data = vec![45u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let key = MlDsaPublicKey::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&key).unwrap();

        // Deserialize
        let deserialized: MlDsaPublicKey = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ml_dsa_secret_key_serialization() {
        // Create a test secret key
        let test_data = vec![46u8; ML_DSA_65_SECRET_KEY_SIZE];
        let key = MlDsaSecretKey::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&key).unwrap();

        // Deserialize
        let deserialized: MlDsaSecretKey = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(key.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_ml_dsa_signature_serialization() {
        // Create a test signature
        let test_data = vec![47u8; ML_DSA_65_SIGNATURE_SIZE];
        let sig = MlDsaSignature::from_bytes(&test_data).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&sig).unwrap();

        // Deserialize
        let deserialized: MlDsaSignature = serde_json::from_str(&serialized).unwrap();

        // Verify
        assert_eq!(sig.as_bytes(), deserialized.as_bytes());
    }
}
