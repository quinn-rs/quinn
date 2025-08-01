//! ML-KEM-768 implementation

use crate::crypto::pqc::{
    MlKemOperations,
    types::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcError, PqcResult, SharedSecret},
};

/// ML-KEM-768 implementation
pub struct MlKem768 {
    #[cfg(feature = "aws-lc-rs")]
    inner: crate::crypto::pqc::ml_kem_impl::MlKem768Impl,
}

impl MlKem768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            inner: crate::crypto::pqc::ml_kem_impl::MlKem768Impl::new(),
        }
    }
}

impl Clone for MlKem768 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl MlKemOperations for MlKem768 {
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.generate_keypair()
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.encapsulate(public_key)
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            let _ = public_key;
            Err(PqcError::FeatureNotAvailable)
        }
    }

    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.decapsulate(secret_key, ciphertext)
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            let _ = (secret_key, ciphertext);
            Err(PqcError::FeatureNotAvailable)
        }
    }
}
