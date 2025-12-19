// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-DSA-65 implementation using saorsa-pqc

use saorsa_pqc::{
    MlDsa65 as SaorsaMlDsa65, MlDsaOperations as SaorsaMlDsaOperations,
    MlDsaPublicKey as SaorsaMlDsaPublicKey, MlDsaSecretKey as SaorsaMlDsaSecretKey,
    MlDsaSignature as SaorsaMlDsaSignature,
};

use crate::crypto::pqc::{
    MlDsaOperations,
    types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, PqcError, PqcResult},
};

/// ML-DSA-65 implementation using saorsa-pqc
pub struct MlDsa65 {
    inner: SaorsaMlDsa65,
}

impl MlDsa65 {
    /// Create a new ML-DSA-65 instance
    pub fn new() -> Self {
        Self {
            inner: SaorsaMlDsa65::new(),
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
        let (pub_key, sec_key) = self
            .inner
            .generate_keypair()
            .map_err(|e| PqcError::KeyGenerationFailed(format!("Key generation failed: {}", e)))?;

        // Convert saorsa-pqc types to ant-quic types
        let ant_pub_key = MlDsaPublicKey::from_bytes(pub_key.as_bytes())
            .map_err(|_| PqcError::InvalidPublicKey)?;
        let ant_sec_key = MlDsaSecretKey::from_bytes(sec_key.as_bytes())
            .map_err(|_| PqcError::InvalidSecretKey)?;

        Ok((ant_pub_key, ant_sec_key))
    }

    fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        // Convert ant-quic types to saorsa-pqc types
        let saorsa_secret_key = SaorsaMlDsaSecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|_| PqcError::InvalidSecretKey)?;

        let signature = self
            .inner
            .sign(&saorsa_secret_key, message)
            .map_err(|e| PqcError::SigningFailed(format!("Signing failed: {}", e)))?;

        // Convert back to ant-quic types
        let ant_signature = MlDsaSignature::from_bytes(signature.as_bytes())
            .map_err(|_| PqcError::InvalidSignature)?;

        Ok(ant_signature)
    }

    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        // Convert ant-quic types to saorsa-pqc types
        let saorsa_public_key = SaorsaMlDsaPublicKey::from_bytes(public_key.as_bytes())
            .map_err(|_| PqcError::InvalidPublicKey)?;
        let saorsa_signature = SaorsaMlDsaSignature::from_bytes(signature.as_bytes())
            .map_err(|_| PqcError::InvalidSignature)?;

        let is_valid = self
            .inner
            .verify(&saorsa_public_key, message, &saorsa_signature)
            .map_err(|e| PqcError::VerificationFailed(format!("Verification failed: {}", e)))?;

        Ok(is_valid)
    }
}
