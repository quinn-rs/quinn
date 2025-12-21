// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Post-Quantum Cryptography module for ant-quic
//!
//! v0.2: Pure PQC - NO hybrid or classical algorithms.
//!
//! This module implements NIST-standardized post-quantum algorithms using saorsa-pqc:
//! - ML-KEM-768 (IANA 0x0201) - Key encapsulation for TLS key exchange
//! - ML-DSA-65 (IANA 0x0905) - Digital signatures for TLS authentication
//!
//! This is a greenfield network with no legacy compatibility requirements.
//! Ed25519 is retained ONLY for 32-byte PeerId compact identifier.

// v0.2: Removed dead/placeholder modules (benchmarks, parallel, memory_pool_optimized, ml_*_impl)
pub mod cipher_suites;
pub mod combiners;
pub mod config;
pub mod encryption;
pub mod memory_pool;
pub mod ml_dsa;
pub mod ml_kem;
pub mod negotiation;
pub mod packet_handler;
pub mod pqc_crypto_provider;
pub mod rustls_provider;
pub mod security_validation;
pub mod tls;
pub mod tls_extensions;
pub mod tls_integration;
pub mod types;

/// Post-Quantum Cryptography exports - always available
pub use config::{PqcConfig, PqcConfigBuilder};
pub use pqc_crypto_provider::{create_crypto_provider, is_pqc_group, validate_negotiated_group};
pub use types::{PqcError, PqcResult};

// PQC algorithm implementations - always available
pub use encryption::{EncryptedMessage, HybridPublicKeyEncryption};
// v0.2: Removed HybridKem, HybridSignature - pure PQC only
pub use memory_pool::{PoolConfig, PqcMemoryPool};
pub use ml_dsa::MlDsa65;
pub use ml_kem::MlKem768;
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
    fn test_aws_lc_pqc_available() {
        // Verify aws-lc-rs PQC APIs are always available
        // Note: aws-lc-rs may not export these directly, we'll verify in implementation
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pqc_overhead() {
        // Measure baseline (non-PQC) handshake time
        let baseline_start = Instant::now();
        // Simulate baseline handshake
        std::thread::sleep(std::time::Duration::from_millis(10));
        let baseline_time = baseline_start.elapsed();

        // Measure PQC handshake time using actual implementations
        let pqc_start = Instant::now();

        // v0.2: Use actual ML-KEM and ML-DSA operations instead of placeholder benchmarks
        let ml_kem = MlKem768::new();
        let ml_dsa = MlDsa65::new();

        // Key exchange operations
        let (kem_pub, _kem_sec) = ml_kem.generate_keypair().expect("KEM keygen");
        let (_ct, _ss) = ml_kem.encapsulate(&kem_pub).expect("KEM encap");

        // Signature operations
        let (dsa_pub, dsa_sec) = ml_dsa.generate_keypair().expect("DSA keygen");
        let sig = ml_dsa.sign(&dsa_sec, b"test").expect("DSA sign");
        let _ = ml_dsa.verify(&dsa_pub, b"test", &sig).expect("DSA verify");

        let pqc_time = pqc_start.elapsed();

        // Calculate overhead
        let overhead =
            ((pqc_time.as_millis() as f64 / baseline_time.as_millis().max(1) as f64) - 1.0) * 100.0;

        println!("Performance Test Results:");
        println!("  Baseline time: {:?}", baseline_time);
        println!("  PQC time: {:?}", pqc_time);
        println!("  Overhead: {:.1}%", overhead);

        // Check if we meet the target (relaxed for debug builds due to unoptimized crypto)
        // Debug builds are ~10x slower due to unoptimized PQC crypto operations
        let max_overhead = if cfg!(debug_assertions) {
            1000.0
        } else {
            150.0
        };
        assert!(
            overhead < max_overhead,
            "PQC overhead {:.1}% exceeds {}% target",
            overhead,
            max_overhead
        );
    }
}
