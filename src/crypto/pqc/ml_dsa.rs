//! ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) implementation
//!
//! This module provides ML-DSA-65 support as specified in FIPS 204.
//! ML-DSA-65 provides NIST security level 3 (192-bit quantum security).
//!
//! # Current Status
//!
//! This implementation is a placeholder awaiting ML-DSA support in aws-lc-rs.
//! All methods currently return appropriate error messages indicating that
//! the functionality is not yet available.
//!
//! # Example
//!
//! ```no_run
//! use ant_quic::crypto::pqc::ml_dsa::MlDsa65;
//!
//! let ml_dsa = MlDsa65::new();
//!
//! // Generate a keypair (will return error until implemented)
//! match ml_dsa.generate_keypair() {
//!     Ok((public_key, secret_key)) => {
//!         // Use keys for signing/verification
//!     }
//!     Err(e) => {
//!         eprintln!("ML-DSA not yet available: {}", e);
//!     }
//! }
//! ```

use crate::crypto::pqc::types::*;
use crate::crypto::pqc::MlDsaOperations;

#[path = "ml_dsa_impl.rs"]
mod ml_dsa_impl;
use ml_dsa_impl::MlDsa65Impl;

// Re-export key types for convenience
pub use crate::crypto::pqc::types::{
    MlDsaPublicKey as MlDsa65PublicKey, MlDsaSecretKey as MlDsa65SecretKey,
    MlDsaSignature as MlDsa65Signature,
};

/// ML-DSA-65 implementation
///
/// This struct provides methods for ML-DSA-65 digital signature algorithm
/// as specified in FIPS 204. ML-DSA-65 offers 192-bit quantum security
/// (NIST security level 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsa65;

impl Default for MlDsa65 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa65 {
    /// Create a new ML-DSA-65 instance
    ///
    /// # Example
    ///
    /// ```
    /// use ant_quic::crypto::pqc::ml_dsa::MlDsa65;
    ///
    /// let ml_dsa = MlDsa65::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Generate a new ML-DSA-65 keypair
    ///
    /// Generates a public/secret keypair for use with ML-DSA-65 digital signatures.
    ///
    /// # Returns
    ///
    /// - `Ok((public_key, secret_key))` - A tuple containing the public and secret keys
    /// - `Err(PqcError)` - If key generation fails or PQC feature is not enabled
    ///
    /// # Key Sizes
    ///
    /// - Public key: 1,952 bytes
    /// - Secret key: 4,032 bytes
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_dsa::MlDsa65;
    /// let ml_dsa = MlDsa65::new();
    /// match ml_dsa.generate_keypair() {
    ///     Ok((public_key, secret_key)) => {
    ///         println!("Generated ML-DSA-65 keypair");
    ///         // Store keys securely
    ///     }
    ///     Err(e) => eprintln!("Failed to generate keypair: {}", e),
    /// }
    /// ```
    pub fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlDsa65Impl::new();
            impl_.generate_keypair()
        }
        #[cfg(not(feature = "pqc"))]
        {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Sign a message using the secret key
    ///
    /// Creates a digital signature for the given message using ML-DSA-65.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The signer's ML-DSA-65 secret key
    /// * `message` - The message to sign (can be any length)
    ///
    /// # Returns
    ///
    /// - `Ok(signature)` - The ML-DSA-65 signature (3,309 bytes)
    /// - `Err(PqcError)` - If signing fails or PQC feature is not enabled
    ///
    /// # Security
    ///
    /// ML-DSA provides strong unforgeability under chosen message attacks (SUF-CMA).
    /// The signing operation is deterministic, producing the same signature for
    /// the same message and key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_dsa::MlDsa65;
    /// # use ant_quic::crypto::pqc::types::*;
    /// # let ml_dsa = MlDsa65::new();
    /// # let (_, secret_key) = ml_dsa.generate_keypair().unwrap();
    /// let message = b"Important message to sign";
    /// match ml_dsa.sign(&secret_key, message) {
    ///     Ok(signature) => {
    ///         println!("Message signed successfully");
    ///         // Transmit signature with message
    ///     }
    ///     Err(e) => eprintln!("Signing failed: {}", e),
    /// }
    /// ```
    pub fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlDsa65Impl::new();
            impl_.sign(secret_key, message)
        }
        #[cfg(not(feature = "pqc"))]
        {
            let _ = (secret_key, message);
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Verify a signature using the public key
    ///
    /// Verifies that the signature was created by the holder of the corresponding
    /// secret key for the given message.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's ML-DSA-65 public key
    /// * `message` - The message that was supposedly signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - If the signature is valid
    /// - `Ok(false)` - If the signature is invalid
    /// - `Err(PqcError)` - If verification fails or PQC feature is not enabled
    ///
    /// # Security
    ///
    /// Signature verification is deterministic and constant-time to prevent
    /// timing attacks. Invalid signatures will reliably return `false`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_dsa::MlDsa65;
    /// # use ant_quic::crypto::pqc::types::*;
    /// # let ml_dsa = MlDsa65::new();
    /// # let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    /// # let message = b"Important message";
    /// # let signature = ml_dsa.sign(&secret_key, message).unwrap();
    /// match ml_dsa.verify(&public_key, message, &signature) {
    ///     Ok(true) => println!("Signature is valid"),
    ///     Ok(false) => println!("Signature is invalid"),
    ///     Err(e) => eprintln!("Verification failed: {}", e),
    /// }
    /// ```
    pub fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlDsa65Impl::new();
            impl_.verify(public_key, message, signature)
        }
        #[cfg(not(feature = "pqc"))]
        {
            let _ = (public_key, message, signature);
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Get the algorithm name
    pub const fn algorithm_name() -> &'static str {
        "ML-DSA-65"
    }

    /// Get the NIST security level
    pub const fn security_level() -> u8 {
        3 // NIST Level 3 (192-bit quantum security)
    }

    /// Get the public key size in bytes
    pub const fn public_key_size() -> usize {
        ML_DSA_65_PUBLIC_KEY_SIZE
    }

    /// Get the secret key size in bytes
    pub const fn secret_key_size() -> usize {
        ML_DSA_65_SECRET_KEY_SIZE
    }

    /// Get the signature size in bytes
    pub const fn signature_size() -> usize {
        ML_DSA_65_SIGNATURE_SIZE
    }

    /// Check if ML-DSA support is available
    pub fn is_available() -> bool {
        #[cfg(feature = "pqc")]
        {
            // In the future, this could check if aws-lc-rs has ML-DSA support
            false
        }
        #[cfg(not(feature = "pqc"))]
        {
            false
        }
    }
}

#[cfg(feature = "pqc")]
#[cfg(feature = "aws-lc-rs")]
mod aws_lc_impl {
    use super::*;
    use crate::crypto::pqc::MlDsaOperations;
    use crate::crypto::pqc::types::*;

    /// AWS-LC implementation of ML-DSA operations
    pub struct AwsLcMlDsa;

    impl MlDsaOperations for AwsLcMlDsa {
        fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
            // TODO: Implement using aws-lc-rs ML-DSA API when available
            // For now, return a placeholder error
            Err(PqcError::KeyGenerationFailed(
                "ML-DSA support not yet implemented in aws-lc-rs".to_string(),
            ))
        }

        fn sign(&self, _secret_key: &MlDsaSecretKey, _message: &[u8]) -> PqcResult<MlDsaSignature> {
            // TODO: Implement using aws-lc-rs ML-DSA API when available
            Err(PqcError::SigningFailed(
                "ML-DSA support not yet implemented in aws-lc-rs".to_string(),
            ))
        }

        fn verify(
            &self,
            _public_key: &MlDsaPublicKey,
            _message: &[u8],
            _signature: &MlDsaSignature,
        ) -> PqcResult<bool> {
            // TODO: Implement using aws-lc-rs ML-DSA API when available
            Err(PqcError::VerificationFailed(
                "ML-DSA support not yet implemented in aws-lc-rs".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::types::*;

    #[test]
    fn test_ml_dsa_key_generation() {
        let ml_dsa = MlDsa65::new();
        let result = ml_dsa.generate_keypair();

        #[cfg(feature = "pqc")]
        {
            // Our temporary implementation should work
            assert!(result.is_ok());
            let (pub_key, sec_key) = result.unwrap();
            assert_eq!(pub_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
            assert_eq!(sec_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
        }

        #[cfg(not(feature = "pqc"))]
        {
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_dsa_signing() {
        let ml_dsa = MlDsa65::new();

        #[cfg(feature = "pqc")]
        {
            // Generate a proper keypair
            let (_, secret_key) = ml_dsa.generate_keypair().unwrap();
            let message = b"Test message for signing";
            let result = ml_dsa.sign(&secret_key, message);
            
            // Our temporary implementation should work
            assert!(result.is_ok());
            let signature = result.unwrap();
            assert_eq!(signature.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);
        }

        #[cfg(not(feature = "pqc"))]
        {
            let secret_key = MlDsaSecretKey(Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]));
            let message = b"Test message for signing";
            let result = ml_dsa.sign(&secret_key, message);
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_dsa_verification() {
        let ml_dsa = MlDsa65::new();

        #[cfg(feature = "pqc")]
        {
            // Generate proper keys and signature
            let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
            let message = b"Test message for verification";
            let signature = ml_dsa.sign(&secret_key, message).unwrap();
            let result = ml_dsa.verify(&public_key, message, &signature);
            
            // Our temporary implementation should work
            assert!(result.is_ok());
            assert!(result.unwrap());
            
            // Test with wrong message should fail
            let wrong_message = b"Wrong message";
            let result = ml_dsa.verify(&public_key, wrong_message, &signature);
            assert!(result.is_ok());
            assert!(!result.unwrap());
        }

        #[cfg(not(feature = "pqc"))]
        {
            let public_key = MlDsaPublicKey(Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]));
            let signature = MlDsaSignature(Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]));
            let message = b"Test message for verification";
            let result = ml_dsa.verify(&public_key, message, &signature);
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_dsa_key_sizes() {
        // Verify our constants match FIPS 204 specifications
        assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(ML_DSA_65_SECRET_KEY_SIZE, 4032);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_ml_dsa_error_messages() {
        // Test error types and messages
        let err = PqcError::SigningFailed("ML-DSA signing failed".to_string());
        assert!(err.to_string().contains("ML-DSA"));
        
        let err = PqcError::VerificationFailed("ML-DSA verification failed".to_string());
        assert!(err.to_string().contains("ML-DSA"));
        
        let err = PqcError::KeyGenerationFailed("ML-DSA key generation failed".to_string());
        assert!(err.to_string().contains("ML-DSA"));
    }

    #[test]
    fn test_ml_dsa_utility_methods() {
        assert_eq!(MlDsa65::algorithm_name(), "ML-DSA-65");
        assert_eq!(MlDsa65::security_level(), 3);
        assert_eq!(MlDsa65::public_key_size(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(MlDsa65::secret_key_size(), ML_DSA_65_SECRET_KEY_SIZE);
        assert_eq!(MlDsa65::signature_size(), ML_DSA_65_SIGNATURE_SIZE);
        assert!(!MlDsa65::is_available()); // Not available until aws-lc-rs support
    }

    #[test]
    fn test_ml_dsa_default_trait() {
        let ml_dsa1 = MlDsa65::new();
        let ml_dsa2: MlDsa65 = Default::default();
        assert_eq!(ml_dsa1, ml_dsa2);
    }

    #[test]
    fn test_ml_dsa_message_sizes() {
        let ml_dsa = MlDsa65::new();
        let _secret_key = MlDsaSecretKey(Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]));

        // Test with various message sizes
        let messages = [
            &b""[..],          // Empty message
            &b"x"[..],         // Single byte
            &[0u8; 64][..],    // 64 bytes
            &[0u8; 256][..],   // 256 bytes
            &[0u8; 1024][..],  // 1KB
            &[0u8; 65536][..], // 64KB
        ];

        for message in &messages {
            #[cfg(feature = "pqc")]
            {
                // Generate proper keypair
                let (_, sec_key) = ml_dsa.generate_keypair().unwrap();
                let result = ml_dsa.sign(&sec_key, message);
                // Our temporary implementation should work for all message sizes
                assert!(result.is_ok());
                let signature = result.unwrap();
                assert_eq!(signature.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);
            }
            
            #[cfg(not(feature = "pqc"))]
            {
                let result = ml_dsa.sign(&_secret_key, message);
                assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
            }
        }
    }

    // Future test placeholder for when we have actual implementation
    #[test]
    #[ignore] // Remove when ML-DSA is implemented
    fn test_ml_dsa_sign_verify_roundtrip() {
        let ml_dsa = MlDsa65::new();

        // Generate keypair
        let (public_key, secret_key) = ml_dsa
            .generate_keypair()
            .expect("Key generation should succeed");

        // Sign a message
        let message = b"Test message for ML-DSA signature";
        let signature = ml_dsa
            .sign(&secret_key, message)
            .expect("Signing should succeed");

        // Verify the signature
        let is_valid = ml_dsa
            .verify(&public_key, message, &signature)
            .expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");

        // Verify with wrong message fails
        let wrong_message = b"Different message";
        let is_valid = ml_dsa
            .verify(&public_key, wrong_message, &signature)
            .expect("Verification should succeed");
        assert!(!is_valid, "Signature should be invalid for wrong message");
    }

    #[test]
    #[ignore] // Remove when ML-DSA is implemented
    fn test_ml_dsa_deterministic_signatures() {
        let ml_dsa = MlDsa65::new();
        let (_, secret_key) = ml_dsa
            .generate_keypair()
            .expect("Key generation should succeed");

        let message = b"Deterministic signature test";

        // Sign the same message twice
        let sig1 = ml_dsa
            .sign(&secret_key, message)
            .expect("First signing should succeed");
        let sig2 = ml_dsa
            .sign(&secret_key, message)
            .expect("Second signing should succeed");

        // ML-DSA is deterministic, so signatures should be identical
        assert_eq!(
            sig1.0.as_ref(),
            sig2.0.as_ref(),
            "ML-DSA signatures should be deterministic"
        );
    }
}
