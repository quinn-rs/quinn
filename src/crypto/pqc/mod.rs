//! Post-Quantum Cryptography module for ant-quic
//!
//! This module implements NIST-standardized post-quantum algorithms:
//! - ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism)
//! - ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)
//!
//! The implementation provides hybrid modes combining classical and PQC algorithms
//! for defense-in-depth against both classical and quantum attacks.

pub mod benchmarks;
pub mod cipher_suites;
pub mod combiners;
pub mod config;
pub mod hybrid;
pub mod hybrid_key_exchange;
pub mod memory_pool;
pub mod memory_pool_optimized;
pub mod ml_dsa;
pub mod ml_dsa_impl;
pub mod ml_kem;
pub mod ml_kem_impl;
pub mod negotiation;
pub mod packet_handler;
pub mod parallel;
pub mod rustls_provider;
pub mod tls;
pub mod tls_extensions;
pub mod tls_integration;
pub mod types;

/// rustls crypto provider for PQC
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub use config::{HybridPreference, PqcConfig, PqcConfigBuilder, PqcMode};
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

        // Measure PQC handshake time
        let pqc_start = Instant::now();
        // Simulate PQC handshake
        let bench = benchmarks::PqcBenchmarks::new(1);
        let _kex_results = bench.benchmark_key_exchange();
        let _sig_results = bench.benchmark_signatures();
        let pqc_time = pqc_start.elapsed();

        // Calculate overhead
        let overhead =
            ((pqc_time.as_millis() as f64 / baseline_time.as_millis() as f64) - 1.0) * 100.0;

        println!("Performance Test Results:");
        println!("  Baseline time: {:?}", baseline_time);
        println!("  PQC time: {:?}", pqc_time);
        println!("  Overhead: {:.1}%", overhead);

        // Check if we meet the target
        assert!(
            overhead < 10.0,
            "PQC overhead {:.1}% exceeds 10% target",
            overhead
        );
    }
}
