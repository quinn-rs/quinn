// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-KEM-768 implementation using saorsa-pqc

use saorsa_pqc::{
    MlKem768 as SaorsaMlKem768, MlKemCiphertext as SaorsaMlKemCiphertext,
    MlKemOperations as SaorsaMlKemOperations, MlKemPublicKey as SaorsaMlKemPublicKey,
    MlKemSecretKey as SaorsaMlKemSecretKey,
};

use crate::crypto::pqc::{
    MlKemOperations,
    types::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcError, PqcResult, SharedSecret},
};

/// ML-KEM-768 implementation using saorsa-pqc
pub struct MlKem768 {
    inner: SaorsaMlKem768,
}

impl MlKem768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Self {
        Self {
            inner: SaorsaMlKem768::new(),
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
        let (pub_key, sec_key) = self
            .inner
            .generate_keypair()
            .map_err(|e| PqcError::KeyGenerationFailed(format!("Key generation failed: {}", e)))?;

        // Convert saorsa-pqc types to ant-quic types
        let ant_pub_key = MlKemPublicKey::from_bytes(pub_key.as_bytes())
            .map_err(|_e| PqcError::InvalidPublicKey)?;
        let ant_sec_key = MlKemSecretKey::from_bytes(sec_key.as_bytes())
            .map_err(|_e| PqcError::InvalidSecretKey)?;

        Ok((ant_pub_key, ant_sec_key))
    }

    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        // Convert ant-quic types to saorsa-pqc types
        let saorsa_pub_key = SaorsaMlKemPublicKey::from_bytes(public_key.as_bytes())
            .map_err(|_| PqcError::InvalidPublicKey)?;

        let (ciphertext, shared_secret) = self
            .inner
            .encapsulate(&saorsa_pub_key)
            .map_err(|e| PqcError::EncapsulationFailed(format!("Encapsulation failed: {}", e)))?;

        // Convert back to ant-quic types
        let ant_ciphertext = MlKemCiphertext::from_bytes(ciphertext.as_bytes())
            .map_err(|_| PqcError::InvalidCiphertext)?;
        let ant_shared_secret = SharedSecret::from_bytes(shared_secret.as_bytes())
            .map_err(|_| PqcError::InvalidSharedSecret)?;

        Ok((ant_ciphertext, ant_shared_secret))
    }

    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        // Convert ant-quic types to saorsa-pqc types
        let saorsa_secret_key = SaorsaMlKemSecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|_| PqcError::InvalidSecretKey)?;
        let saorsa_ciphertext = SaorsaMlKemCiphertext::from_bytes(ciphertext.as_bytes())
            .map_err(|_| PqcError::InvalidCiphertext)?;

        let shared_secret = self
            .inner
            .decapsulate(&saorsa_secret_key, &saorsa_ciphertext)
            .map_err(|e| PqcError::DecapsulationFailed(format!("Decapsulation failed: {}", e)))?;

        // Convert back to ant-quic types
        let ant_shared_secret = SharedSecret::from_bytes(shared_secret.as_bytes())
            .map_err(|_| PqcError::InvalidSharedSecret)?;

        Ok(ant_shared_secret)
    }
}
