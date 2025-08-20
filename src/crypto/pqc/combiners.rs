// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! NIST SP 800-56C Rev. 2 compliant key combiners for hybrid cryptography
//!
//! This module implements secure key combination methods following NIST
//! standards for combining classical and post-quantum shared secrets.

use crate::crypto::pqc::types::*;
use ring::hkdf;
use ring::hmac;

/// NIST SP 800-56C Rev. 2 Option 1: Concatenation KDF
///
/// This implements the concatenation KDF as specified in NIST SP 800-56C Rev. 2,
/// Section 4.1. It concatenates the shared secrets and applies a KDF.
pub struct ConcatenationCombiner;

impl ConcatenationCombiner {
    /// Combine two shared secrets using concatenation and HKDF
    ///
    /// # Arguments
    /// * `classical_secret` - The classical shared secret (e.g., from ECDH)
    /// * `pqc_secret` - The post-quantum shared secret (e.g., from ML-KEM)
    /// * `info` - Context-specific information for domain separation
    ///
    /// # Returns
    /// A combined shared secret of 32 bytes
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // NIST SP 800-56C Rev. 2 specifies concatenation: classical || pqc
        let mut concatenated = Vec::with_capacity(classical_secret.len() + pqc_secret.len());
        concatenated.extend_from_slice(classical_secret);
        concatenated.extend_from_slice(pqc_secret);

        // Use HKDF-Extract and HKDF-Expand with SHA-256
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&concatenated);

        let mut output = [0u8; 32];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?
            .fill(&mut output)
            .map_err(|_| PqcError::CryptoError("HKDF fill failed".to_string()))?;

        Ok(SharedSecret(output))
    }

    /// Combine with additional salt parameter
    ///
    /// # Arguments
    /// * `classical_secret` - The classical shared secret
    /// * `pqc_secret` - The post-quantum shared secret
    /// * `salt` - Optional salt value for HKDF
    /// * `info` - Context-specific information
    pub fn combine_with_salt(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        let mut concatenated = Vec::with_capacity(classical_secret.len() + pqc_secret.len());
        concatenated.extend_from_slice(classical_secret);
        concatenated.extend_from_slice(pqc_secret);

        let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = hkdf_salt.extract(&concatenated);

        let mut output = [0u8; 32];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?
            .fill(&mut output)
            .map_err(|_| PqcError::CryptoError("HKDF fill failed".to_string()))?;

        Ok(SharedSecret(output))
    }
}

/// NIST SP 800-56C Rev. 2 Option 2: Two-Step KDF
///
/// This implements a two-step approach where each secret is processed
/// separately before combination.
pub struct TwoStepCombiner;

impl TwoStepCombiner {
    /// Combine two shared secrets using a two-step KDF process
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // Step 1: Extract from classical secret
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk_classical = salt.extract(classical_secret);

        // Step 2: Extract from PQC secret using classical PRK as salt
        let mut classical_prk_bytes = vec![0u8; 32];
        prk_classical
            .expand(&[], hkdf::HKDF_SHA256)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?
            .fill(&mut classical_prk_bytes)
            .map_err(|_| PqcError::CryptoError("HKDF fill failed".to_string()))?;

        let salt_pqc = hkdf::Salt::new(hkdf::HKDF_SHA256, &classical_prk_bytes);
        let prk_combined = salt_pqc.extract(pqc_secret);

        // Step 3: Expand to final key
        let mut output = [0u8; 32];
        prk_combined
            .expand(&[info], hkdf::HKDF_SHA256)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?
            .fill(&mut output)
            .map_err(|_| PqcError::CryptoError("HKDF fill failed".to_string()))?;

        Ok(SharedSecret(output))
    }
}

/// HMAC-based combiner for additional security
///
/// This provides an alternative combination method using HMAC for
/// scenarios requiring different security properties.
pub struct HmacCombiner;

impl HmacCombiner {
    /// Combine secrets using HMAC
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // Use classical secret as HMAC key, PQC secret as message
        let key = hmac::Key::new(hmac::HMAC_SHA256, classical_secret);

        // HMAC(classical_secret, pqc_secret || info)
        let mut message = Vec::with_capacity(pqc_secret.len() + info.len());
        message.extend_from_slice(pqc_secret);
        message.extend_from_slice(info);

        let tag = hmac::sign(&key, &message);

        let mut output = [0u8; 32];
        output.copy_from_slice(tag.as_ref());

        Ok(SharedSecret(output))
    }
}

/// Trait for hybrid key combiners
pub trait HybridCombiner: Send + Sync {
    /// Combine classical and post-quantum shared secrets
    fn combine(
        &self,
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret>;

    /// Get the name of the combiner algorithm
    fn algorithm_name(&self) -> &'static str;
}

impl HybridCombiner for ConcatenationCombiner {
    fn combine(
        &self,
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        Self::combine(classical_secret, pqc_secret, info)
    }

    fn algorithm_name(&self) -> &'static str {
        "NIST-SP-800-56C-Option1-Concatenation"
    }
}

impl HybridCombiner for TwoStepCombiner {
    fn combine(
        &self,
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        Self::combine(classical_secret, pqc_secret, info)
    }

    fn algorithm_name(&self) -> &'static str {
        "NIST-SP-800-56C-Option2-TwoStep"
    }
}

impl HybridCombiner for HmacCombiner {
    fn combine(
        &self,
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        Self::combine(classical_secret, pqc_secret, info)
    }

    fn algorithm_name(&self) -> &'static str {
        "HMAC-SHA256-Combiner"
    }
}

/// Default combiner following NIST recommendations
pub fn default_combiner() -> Box<dyn HybridCombiner> {
    Box::new(ConcatenationCombiner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concatenation_combiner() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let result = ConcatenationCombiner::combine(&classical, &pqc, info);
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert_eq!(secret.as_bytes().len(), 32);

        // Verify deterministic
        let result2 = ConcatenationCombiner::combine(&classical, &pqc, info);
        assert_eq!(secret.as_bytes(), result2.unwrap().as_bytes());

        // Verify different inputs produce different outputs
        let different_classical = [3u8; 32];
        let result3 = ConcatenationCombiner::combine(&different_classical, &pqc, info);
        assert_ne!(secret.as_bytes(), result3.unwrap().as_bytes());
    }

    #[test]
    fn test_concatenation_combiner_with_salt() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let salt = b"test salt";
        let info = b"test info";

        let result = ConcatenationCombiner::combine_with_salt(&classical, &pqc, salt, info);
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert_eq!(secret.as_bytes().len(), 32);

        // Different salt produces different output
        let different_salt = b"different salt";
        let result2 =
            ConcatenationCombiner::combine_with_salt(&classical, &pqc, different_salt, info);
        assert_ne!(secret.as_bytes(), result2.unwrap().as_bytes());
    }

    #[test]
    fn test_two_step_combiner() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let result = TwoStepCombiner::combine(&classical, &pqc, info);
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert_eq!(secret.as_bytes().len(), 32);

        // Verify deterministic
        let result2 = TwoStepCombiner::combine(&classical, &pqc, info);
        assert_eq!(secret.as_bytes(), result2.unwrap().as_bytes());
    }

    #[test]
    fn test_hmac_combiner() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let result = HmacCombiner::combine(&classical, &pqc, info);
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert_eq!(secret.as_bytes().len(), 32);

        // Verify deterministic
        let result2 = HmacCombiner::combine(&classical, &pqc, info);
        assert_eq!(secret.as_bytes(), result2.unwrap().as_bytes());
    }

    #[test]
    fn test_different_combiners_produce_different_outputs() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let concat_result = ConcatenationCombiner::combine(&classical, &pqc, info).unwrap();
        let twostep_result = TwoStepCombiner::combine(&classical, &pqc, info).unwrap();
        let hmac_result = HmacCombiner::combine(&classical, &pqc, info).unwrap();

        // All three should produce different outputs
        assert_ne!(concat_result.as_bytes(), twostep_result.as_bytes());
        assert_ne!(concat_result.as_bytes(), hmac_result.as_bytes());
        assert_ne!(twostep_result.as_bytes(), hmac_result.as_bytes());
    }

    #[test]
    fn test_hybrid_combiner_trait() {
        let combiner: Box<dyn HybridCombiner> = Box::new(ConcatenationCombiner);
        assert_eq!(
            combiner.algorithm_name(),
            "NIST-SP-800-56C-Option1-Concatenation"
        );

        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let info = b"test info";

        let result = combiner.combine(&classical, &pqc, info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_combiner() {
        let combiner = default_combiner();
        assert_eq!(
            combiner.algorithm_name(),
            "NIST-SP-800-56C-Option1-Concatenation"
        );
    }

    #[test]
    fn test_combiner_with_various_sizes() {
        // Test with different secret sizes
        let classical_p256 = [1u8; 32]; // P-256 produces 32-byte secrets
        let classical_p384 = [1u8; 48]; // P-384 produces 48-byte secrets
        let pqc = [2u8; 32]; // ML-KEM always produces 32-byte secrets
        let info = b"test info";

        // Should work with different classical secret sizes
        let result1 = ConcatenationCombiner::combine(&classical_p256, &pqc, info);
        assert!(result1.is_ok());

        let result2 = ConcatenationCombiner::combine(&classical_p384, &pqc, info);
        assert!(result2.is_ok());

        // Different input sizes should produce different outputs
        assert_ne!(result1.unwrap().as_bytes(), result2.unwrap().as_bytes());
    }

    #[test]
    fn test_empty_info() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let empty_info = b"";

        // Should work with empty info
        let result = ConcatenationCombiner::combine(&classical, &pqc, empty_info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_info() {
        let classical = [1u8; 32];
        let pqc = [2u8; 32];
        let large_info = vec![0u8; 1024]; // 1KB of info

        // Should work with large info
        let result = ConcatenationCombiner::combine(&classical, &pqc, &large_info);
        assert!(result.is_ok());
    }
}
