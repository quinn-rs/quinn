//! Post-Quantum Cryptography module for ant-quic
//!
//! This module implements NIST-standardized post-quantum algorithms:
//! - ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism)
//! - ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)
//!
//! The implementation provides hybrid modes combining classical and PQC algorithms
//! for defense-in-depth against both classical and quantum attacks.

pub mod hybrid;
pub mod memory_pool;
pub mod ml_dsa;
pub mod ml_kem;
pub mod tls;
pub mod tls_extensions;
pub mod types;

/// rustls crypto provider for PQC
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub mod rustls_provider;

/// Hybrid cipher suites for PQC
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub mod cipher_suites;

pub use types::{PqcError, PqcResult};

#[cfg(feature = "pqc")]
pub use hybrid::{HybridKem, HybridSignature};
#[cfg(feature = "pqc")]
pub use memory_pool::{PoolConfig, PqcMemoryPool};
#[cfg(feature = "pqc")]
pub use ml_dsa::MlDsa65;
#[cfg(feature = "pqc")]
pub use ml_kem::MlKem768;
#[cfg(feature = "pqc")]
pub use tls::{PqcTlsExtension};
#[cfg(feature = "pqc")]
pub use tls_extensions::{NamedGroup, SignatureScheme};

/// Post-Quantum Cryptography provider trait
pub trait PqcProvider: Send + Sync + 'static {
    /// ML-KEM operations provider
    type MlKem: MlKemOperations;

    /// ML-DSA operations provider
    type MlDsa: MlDsaOperations;

    /// Get ML-KEM operations
    fn ml_kem(&self) -> &Self::MlKem;

    /// Get ML-DSA operations
    fn ml_dsa(&self) -> &Self::MlDsa;
}

/// ML-KEM operations trait
pub trait MlKemOperations: Send + Sync {
    /// Generate a new ML-KEM keypair
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)>;

    /// Encapsulate a shared secret
    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)>;

    /// Decapsulate a shared secret
    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret>;
}

/// ML-DSA operations trait
pub trait MlDsaOperations: Send + Sync {
    /// Generate a new ML-DSA keypair
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)>;

    /// Sign a message
    fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature>;

    /// Verify a signature
    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool>;
}

// Import types from the types module
use types::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlKemCiphertext, MlKemPublicKey,
    MlKemSecretKey, SharedSecret,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_module_imports() {
        // Verify all submodules are accessible
        use crate::crypto::pqc::{ml_dsa, ml_kem, types};

        // This test just verifies compilation
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn test_aws_lc_pqc_available() {
        // Verify aws-lc-rs PQC APIs can be imported when feature is enabled
        // Note: aws-lc-rs may not export these directly, we'll verify in implementation
    }
}
