//! ML-DSA-65 implementation

use crate::crypto::pqc::{
    MlDsaOperations,
    types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, PqcError, PqcResult},
};

/// ML-DSA-65 implementation
pub struct MlDsa65 {
    #[cfg(feature = "aws-lc-rs")]
    inner: crate::crypto::pqc::ml_dsa_impl::MlDsa65Impl,
}

impl MlDsa65 {
    /// Create a new ML-DSA-65 instance
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "aws-lc-rs")]
            inner: crate::crypto::pqc::ml_dsa_impl::MlDsa65Impl::new(),
        }
    }
}

impl Clone for MlDsa65 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl MlDsaOperations for MlDsa65 {
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.generate_keypair()
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            Err(PqcError::FeatureNotAvailable)
        }
    }

    fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.sign(secret_key, message)
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            let _ = (secret_key, message);
            Err(PqcError::FeatureNotAvailable)
        }
    }

    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.inner.verify(public_key, message, signature)
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            let _ = (public_key, message, signature);
            Err(PqcError::FeatureNotAvailable)
        }
    }
}
