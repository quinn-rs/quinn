//! Type definitions for Post-Quantum Cryptography

use thiserror::Error;

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

    /// Operation not supported
    #[error("Operation not supported")]
    OperationNotSupported,

    /// Negotiation failed
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),
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

/// ML-KEM-768 secret key
pub struct MlKemSecretKey(pub Box<[u8; ML_KEM_768_SECRET_KEY_SIZE]>);

impl MlKemSecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
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

/// ML-DSA-65 secret key
pub struct MlDsaSecretKey(pub Box<[u8; ML_DSA_65_SECRET_KEY_SIZE]>);

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

/// Shared secret from key encapsulation
#[derive(Clone)]
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
pub struct HybridKemSecretKey {
    /// Classical ECDH private key
    pub classical: Box<[u8]>,
    /// ML-KEM-768 secret key
    pub ml_kem: MlKemSecretKey,
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
pub struct HybridSignatureSecretKey {
    /// Classical signature private key
    pub classical: Box<[u8]>,
    /// ML-DSA-65 secret key
    pub ml_dsa: MlDsaSecretKey,
}

/// Hybrid signature value (classical + ML-DSA signatures)
#[derive(Clone)]
pub struct HybridSignatureValue {
    /// Classical signature (e.g., Ed25519 signature)
    pub classical: Box<[u8]>,
    /// ML-DSA-65 signature
    pub ml_dsa: Box<[u8]>,
}

// Implement zeroization for secret keys
impl Drop for MlKemSecretKey {
    fn drop(&mut self) {
        // Zero out the secret key on drop
        self.0.as_mut().fill(0);
    }
}

impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        // Zero out the secret key on drop
        self.0.as_mut().fill(0);
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Zero out the shared secret on drop
        self.0.fill(0);
    }
}

impl Drop for HybridKemSecretKey {
    fn drop(&mut self) {
        // Zero out both classical and PQC secret keys
        self.classical.fill(0);
        // ml_kem will be zeroed by its own Drop impl
    }
}

impl Drop for HybridSignatureSecretKey {
    fn drop(&mut self) {
        // Zero out both classical and PQC secret keys
        self.classical.fill(0);
        // ml_dsa will be zeroed by its own Drop impl
    }
}

#[cfg(test)]
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
}
