//! ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism) implementation
//!
//! This module provides ML-KEM-768 support as specified in FIPS 203.
//! ML-KEM-768 provides NIST security level 3 (192-bit quantum security).
//!
//! # Current Status
//!
//! This implementation is a placeholder awaiting ML-KEM support in aws-lc-rs.
//! All methods currently return appropriate error messages indicating that
//! the functionality is not yet available.
//!
//! # Example
//!
//! ```no_run
//! use ant_quic::crypto::pqc::ml_kem::MlKem768;
//!
//! let ml_kem = MlKem768::new();
//!
//! // Generate a keypair (will return error until implemented)
//! match ml_kem.generate_keypair() {
//!     Ok((public_key, secret_key)) => {
//!         // Use keys for encapsulation/decapsulation
//!     }
//!     Err(e) => {
//!         eprintln!("ML-KEM not yet available: {}", e);
//!     }
//! }
//! ```

use crate::crypto::pqc::types::*;
use crate::crypto::pqc::MlKemOperations;

#[path = "ml_kem_impl.rs"]
mod ml_kem_impl;
use ml_kem_impl::MlKem768Impl;

/// ML-KEM-768 implementation
///
/// This struct provides methods for ML-KEM-768 key encapsulation mechanism
/// as specified in FIPS 203. ML-KEM-768 offers 192-bit quantum security
/// (NIST security level 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKem768;

impl Default for MlKem768 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlKem768 {
    /// Create a new ML-KEM-768 instance
    ///
    /// # Example
    ///
    /// ```
    /// use ant_quic::crypto::pqc::ml_kem::MlKem768;
    ///
    /// let ml_kem = MlKem768::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Generate a new ML-KEM-768 keypair
    ///
    /// Generates a public/secret keypair for use with ML-KEM-768.
    ///
    /// # Returns
    ///
    /// - `Ok((public_key, secret_key))` - A tuple containing the public and secret keys
    /// - `Err(PqcError)` - If key generation fails or PQC feature is not enabled
    ///
    /// # Key Sizes
    ///
    /// - Public key: 1,184 bytes
    /// - Secret key: 2,400 bytes
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_kem::MlKem768;
    /// let ml_kem = MlKem768::new();
    /// match ml_kem.generate_keypair() {
    ///     Ok((public_key, secret_key)) => {
    ///         println!("Generated ML-KEM-768 keypair");
    ///     }
    ///     Err(e) => eprintln!("Failed to generate keypair: {}", e),
    /// }
    /// ```
    pub fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlKem768Impl::new();
            impl_.generate_keypair()
        }
        #[cfg(not(feature = "pqc"))]
        {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Encapsulate a shared secret using the recipient's public key
    ///
    /// Generates a shared secret and encapsulates it using the provided public key.
    /// This is used by the sender to create a shared secret that only the recipient
    /// (holder of the corresponding secret key) can recover.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The recipient's ML-KEM-768 public key
    ///
    /// # Returns
    ///
    /// - `Ok((ciphertext, shared_secret))` - The ciphertext to send and the shared secret
    /// - `Err(PqcError)` - If encapsulation fails or PQC feature is not enabled
    ///
    /// # Sizes
    ///
    /// - Ciphertext: 1,088 bytes
    /// - Shared secret: 32 bytes
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_kem::MlKem768;
    /// # use ant_quic::crypto::pqc::types::*;
    /// # let ml_kem = MlKem768::new();
    /// # let public_key = MlKemPublicKey(Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]));
    /// match ml_kem.encapsulate(&public_key) {
    ///     Ok((ciphertext, shared_secret)) => {
    ///         // Send ciphertext to recipient
    ///         // Use shared_secret for symmetric encryption
    ///     }
    ///     Err(e) => eprintln!("Encapsulation failed: {}", e),
    /// }
    /// ```
    pub fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlKem768Impl::new();
            impl_.encapsulate(public_key)
        }
        #[cfg(not(feature = "pqc"))]
        {
            let _ = public_key;
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Decapsulate a shared secret using the secret key
    ///
    /// Recovers the shared secret from the ciphertext using the recipient's secret key.
    /// This is used by the recipient to extract the shared secret that was encapsulated
    /// by the sender.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The recipient's ML-KEM-768 secret key
    /// * `ciphertext` - The ciphertext received from the sender
    ///
    /// # Returns
    ///
    /// - `Ok(shared_secret)` - The recovered shared secret (32 bytes)
    /// - `Err(PqcError)` - If decapsulation fails or PQC feature is not enabled
    ///
    /// # Security
    ///
    /// ML-KEM provides IND-CCA2 security, meaning the decapsulation will always
    /// produce a shared secret, even with invalid ciphertext. However, the resulting
    /// secret will be unpredictable if the ciphertext is invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ant_quic::crypto::pqc::ml_kem::MlKem768;
    /// # use ant_quic::crypto::pqc::types::*;
    /// # let ml_kem = MlKem768::new();
    /// # let secret_key = MlKemSecretKey(Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]));
    /// # let ciphertext = MlKemCiphertext(Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]));
    /// match ml_kem.decapsulate(&secret_key, &ciphertext) {
    ///     Ok(shared_secret) => {
    ///         // Use shared_secret for symmetric decryption
    ///     }
    ///     Err(e) => eprintln!("Decapsulation failed: {}", e),
    /// }
    /// ```
    pub fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        #[cfg(feature = "pqc")]
        {
            let impl_ = MlKem768Impl::new();
            impl_.decapsulate(secret_key, ciphertext)
        }
        #[cfg(not(feature = "pqc"))]
        {
            let _ = (secret_key, ciphertext);
            Err(PqcError::FeatureNotAvailable)
        }
    }

    /// Get the algorithm name
    pub const fn algorithm_name() -> &'static str {
        "ML-KEM-768"
    }

    /// Get the NIST security level
    pub const fn security_level() -> u8 {
        3 // NIST Level 3 (192-bit quantum security)
    }

    /// Get the public key size in bytes
    pub const fn public_key_size() -> usize {
        ML_KEM_768_PUBLIC_KEY_SIZE
    }

    /// Get the secret key size in bytes
    pub const fn secret_key_size() -> usize {
        ML_KEM_768_SECRET_KEY_SIZE
    }

    /// Get the ciphertext size in bytes
    pub const fn ciphertext_size() -> usize {
        ML_KEM_768_CIPHERTEXT_SIZE
    }

    /// Get the shared secret size in bytes
    pub const fn shared_secret_size() -> usize {
        ML_KEM_768_SHARED_SECRET_SIZE
    }

    /// Check if ML-KEM support is available
    pub fn is_available() -> bool {
        #[cfg(feature = "pqc")]
        {
            // In the future, this could check if aws-lc-rs has ML-KEM support
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
    use crate::crypto::pqc::MlKemOperations;
    use crate::crypto::pqc::types::*;

    /// AWS-LC implementation of ML-KEM operations
    pub struct AwsLcMlKem;

    impl MlKemOperations for AwsLcMlKem {
        fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
            // TODO: Implement using aws-lc-rs ML-KEM API when available
            // For now, return a placeholder error
            Err(PqcError::KeyGenerationFailed(
                "ML-KEM support not yet implemented in aws-lc-rs".to_string(),
            ))
        }

        fn encapsulate(
            &self,
            _public_key: &MlKemPublicKey,
        ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
            // TODO: Implement using aws-lc-rs ML-KEM API when available
            Err(PqcError::EncapsulationFailed(
                "ML-KEM support not yet implemented in aws-lc-rs".to_string(),
            ))
        }

        fn decapsulate(
            &self,
            _secret_key: &MlKemSecretKey,
            _ciphertext: &MlKemCiphertext,
        ) -> PqcResult<SharedSecret> {
            // TODO: Implement using aws-lc-rs ML-KEM API when available
            Err(PqcError::DecapsulationFailed(
                "ML-KEM support not yet implemented in aws-lc-rs".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::types::*;

    #[test]
    fn test_ml_kem_key_generation() {
        let ml_kem = MlKem768::new();
        let result = ml_kem.generate_keypair();

        #[cfg(feature = "pqc")]
        {
            // Our temporary implementation should work
            assert!(result.is_ok());
            let (pub_key, sec_key) = result.unwrap();
            assert_eq!(pub_key.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
            assert_eq!(sec_key.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
        }

        #[cfg(not(feature = "pqc"))]
        {
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_kem_encapsulation() {
        let ml_kem = MlKem768::new();

        #[cfg(feature = "pqc")]
        {
            // Generate a proper public key
            let (public_key, _) = ml_kem.generate_keypair().unwrap();
            let result = ml_kem.encapsulate(&public_key);
            
            // Our temporary implementation should work
            assert!(result.is_ok());
            let (ciphertext, shared_secret) = result.unwrap();
            assert_eq!(ciphertext.as_bytes().len(), ML_KEM_768_CIPHERTEXT_SIZE);
            assert_eq!(shared_secret.as_bytes().len(), ML_KEM_768_SHARED_SECRET_SIZE);
        }

        #[cfg(not(feature = "pqc"))]
        {
            let public_key = MlKemPublicKey(Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]));
            let result = ml_kem.encapsulate(&public_key);
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_kem_decapsulation() {
        let ml_kem = MlKem768::new();

        #[cfg(feature = "pqc")]
        {
            // Generate proper keys and encapsulate
            let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();
            let (ciphertext, _) = ml_kem.encapsulate(&public_key).unwrap();
            let result = ml_kem.decapsulate(&secret_key, &ciphertext);
            
            // Our temporary implementation should work
            assert!(result.is_ok());
            let shared_secret = result.unwrap();
            assert_eq!(shared_secret.as_bytes().len(), ML_KEM_768_SHARED_SECRET_SIZE);
        }

        #[cfg(not(feature = "pqc"))]
        {
            let secret_key = MlKemSecretKey(Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]));
            let ciphertext = MlKemCiphertext(Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]));
            let result = ml_kem.decapsulate(&secret_key, &ciphertext);
            assert!(matches!(result, Err(PqcError::FeatureNotAvailable)));
        }
    }

    #[test]
    fn test_ml_kem_key_sizes() {
        // Verify our constants match FIPS 203 specifications
        assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(ML_KEM_768_SECRET_KEY_SIZE, 2400);
        assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, 1088);
        assert_eq!(ML_KEM_768_SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_ml_kem_error_messages() {
        // Test error types and messages
        let err = PqcError::KeyGenerationFailed("ML-KEM key generation failed".to_string());
        assert!(err.to_string().contains("ML-KEM"));
        
        let err = PqcError::EncapsulationFailed("ML-KEM encapsulation failed".to_string());
        assert!(err.to_string().contains("ML-KEM"));
        
        let err = PqcError::DecapsulationFailed("ML-KEM decapsulation failed".to_string());
        assert!(err.to_string().contains("ML-KEM"));
    }

    #[test]
    fn test_ml_kem_utility_methods() {
        assert_eq!(MlKem768::algorithm_name(), "ML-KEM-768");
        assert_eq!(MlKem768::security_level(), 3);
        assert_eq!(MlKem768::public_key_size(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(MlKem768::secret_key_size(), ML_KEM_768_SECRET_KEY_SIZE);
        assert_eq!(MlKem768::ciphertext_size(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(
            MlKem768::shared_secret_size(),
            ML_KEM_768_SHARED_SECRET_SIZE
        );
        assert!(!MlKem768::is_available()); // Not available until aws-lc-rs support
    }

    #[test]
    fn test_ml_kem_default_trait() {
        let ml_kem1 = MlKem768::new();
        let ml_kem2: MlKem768 = Default::default();
        assert_eq!(ml_kem1, ml_kem2);
    }

    // Future test placeholder for when we have actual implementation
    #[test]
    #[ignore] // Remove when ML-KEM is implemented
    fn test_ml_kem_roundtrip() {
        let ml_kem = MlKem768::new();

        // Generate keypair
        let (public_key, secret_key) = ml_kem
            .generate_keypair()
            .expect("Key generation should succeed");

        // Encapsulate
        let (ciphertext, shared_secret1) = ml_kem
            .encapsulate(&public_key)
            .expect("Encapsulation should succeed");

        // Decapsulate
        let shared_secret2 = ml_kem
            .decapsulate(&secret_key, &ciphertext)
            .expect("Decapsulation should succeed");

        // Verify shared secrets match
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }
}
