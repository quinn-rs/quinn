// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-DSA-65 based authentication for relay operations with anti-replay protection.

use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;
use crate::crypto::raw_public_keys::pqc::{
    ML_DSA_65_SIGNATURE_SIZE, sign_with_ml_dsa, verify_with_ml_dsa,
};
use crate::relay::{RelayError, RelayResult};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cryptographic authentication token for relay operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken {
    /// Unique nonce to prevent replay attacks
    pub nonce: u64,
    /// Timestamp when token was created (Unix timestamp)
    pub timestamp: u64,
    /// Requested bandwidth limit in bytes per second
    pub bandwidth_limit: u32,
    /// Session timeout in seconds
    pub timeout_seconds: u32,
    /// ML-DSA-65 signature over the token data (3309 bytes)
    pub signature: Vec<u8>,
}

/// ML-DSA-65 authenticator with anti-replay protection
#[derive(Debug)]
pub struct RelayAuthenticator {
    /// ML-DSA-65 public key for this node
    public_key: MlDsaPublicKey,
    /// ML-DSA-65 secret key for this node
    secret_key: MlDsaSecretKey,
    /// Set of used nonces for anti-replay protection
    used_nonces: Arc<Mutex<HashSet<u64>>>,
    /// Maximum age of tokens in seconds (default: 5 minutes)
    max_token_age: u64,
    /// Size of anti-replay window
    replay_window_size: u64,
}

impl AuthToken {
    /// Create a new authentication token
    pub fn new(
        bandwidth_limit: u32,
        timeout_seconds: u32,
        secret_key: &MlDsaSecretKey,
    ) -> RelayResult<Self> {
        let nonce = Self::generate_nonce();
        let timestamp = Self::current_timestamp()?;

        let mut token = Self {
            nonce,
            timestamp,
            bandwidth_limit,
            timeout_seconds,
            signature: vec![0; ML_DSA_65_SIGNATURE_SIZE],
        };

        // Sign the token
        let sig = sign_with_ml_dsa(secret_key, &token.signable_data()).map_err(|_| {
            RelayError::AuthenticationFailed {
                reason: "ML-DSA-65 signing failed".to_string(),
            }
        })?;
        token.signature = sig.as_bytes().to_vec();

        Ok(token)
    }

    /// Generate a cryptographically secure nonce
    fn generate_nonce() -> u64 {
        use rand::Rng;
        use rand::rngs::OsRng;
        OsRng.r#gen()
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> RelayResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| RelayError::AuthenticationFailed {
                reason: "System time before Unix epoch".to_string(),
            })
    }

    /// Get the data that should be signed
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.bandwidth_limit.to_le_bytes());
        data.extend_from_slice(&self.timeout_seconds.to_le_bytes());
        data
    }

    /// Verify the token signature
    pub fn verify(&self, public_key: &MlDsaPublicKey) -> RelayResult<()> {
        let signature = MlDsaSignature::from_bytes(&self.signature).map_err(|_| {
            RelayError::AuthenticationFailed {
                reason: "Invalid signature format".to_string(),
            }
        })?;

        verify_with_ml_dsa(public_key, &self.signable_data(), &signature).map_err(|_| {
            RelayError::AuthenticationFailed {
                reason: "Signature verification failed".to_string(),
            }
        })
    }

    /// Check if the token has expired
    pub fn is_expired(&self, max_age_seconds: u64) -> RelayResult<bool> {
        let current_time = Self::current_timestamp()?;
        Ok(current_time > self.timestamp + max_age_seconds)
    }
}

impl RelayAuthenticator {
    /// Create a new authenticator with a random key pair
    ///
    /// # Errors
    /// Returns an error if ML-DSA-65 key generation fails.
    pub fn new() -> RelayResult<Self> {
        let (public_key, secret_key) =
            generate_ml_dsa_keypair().map_err(|e| RelayError::AuthenticationFailed {
                reason: format!("ML-DSA-65 keypair generation failed: {}", e),
            })?;

        Ok(Self {
            public_key,
            secret_key,
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
            max_token_age: 300, // 5 minutes
            replay_window_size: 1000,
        })
    }

    /// Create an authenticator with a specific keypair
    pub fn with_keypair(public_key: MlDsaPublicKey, secret_key: MlDsaSecretKey) -> Self {
        Self {
            public_key,
            secret_key,
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
            max_token_age: 300,
            replay_window_size: 1000,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Create a new authentication token
    pub fn create_token(
        &self,
        bandwidth_limit: u32,
        timeout_seconds: u32,
    ) -> RelayResult<AuthToken> {
        AuthToken::new(bandwidth_limit, timeout_seconds, &self.secret_key)
    }

    /// Verify an authentication token with anti-replay protection
    #[allow(clippy::expect_used)]
    pub fn verify_token(
        &self,
        token: &AuthToken,
        peer_public_key: &MlDsaPublicKey,
    ) -> RelayResult<()> {
        // Check signature
        token.verify(peer_public_key)?;

        // Check if token has expired
        if token.is_expired(self.max_token_age)? {
            return Err(RelayError::AuthenticationFailed {
                reason: "Token expired".to_string(),
            });
        }

        // Check for replay attack
        let mut used_nonces = self
            .used_nonces
            .lock()
            .expect("Mutex poisoning is unexpected in normal operation");

        if used_nonces.contains(&token.nonce) {
            return Err(RelayError::AuthenticationFailed {
                reason: "Token replay detected".to_string(),
            });
        }

        // Add nonce to used set (with size limit)
        if used_nonces.len() >= self.replay_window_size as usize {
            // Remove oldest entries (simple approach - in production might use LRU)
            let to_remove: Vec<_> = used_nonces.iter().take(100).cloned().collect();
            for nonce in to_remove {
                used_nonces.remove(&nonce);
            }
        }

        used_nonces.insert(token.nonce);

        Ok(())
    }

    /// Set maximum token age
    pub fn set_max_token_age(&mut self, max_age_seconds: u64) {
        self.max_token_age = max_age_seconds;
    }

    /// Get maximum token age
    pub fn max_token_age(&self) -> u64 {
        self.max_token_age
    }

    /// Clear all used nonces (for testing)
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    pub fn clear_nonces(&self) {
        let mut used_nonces = self
            .used_nonces
            .lock()
            .expect("Mutex poisoning is unexpected in normal operation");
        used_nonces.clear();
    }

    /// Get number of used nonces (for testing)
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    pub fn nonce_count(&self) -> usize {
        let used_nonces = self
            .used_nonces
            .lock()
            .expect("Mutex poisoning is unexpected in normal operation");
        used_nonces.len()
    }
}

// Note: No Default impl - use new() which returns Result for proper error handling

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_auth_token_creation_and_verification() {
        let authenticator = RelayAuthenticator::new().unwrap();
        let token = authenticator.create_token(1024, 300).unwrap();

        assert!(token.bandwidth_limit == 1024);
        assert!(token.timeout_seconds == 300);
        assert!(token.nonce != 0);
        assert!(token.timestamp > 0);

        // Verify token
        assert!(token.verify(authenticator.public_key()).is_ok());
    }

    #[test]
    fn test_token_verification_with_wrong_key() {
        let authenticator1 = RelayAuthenticator::new().unwrap();
        let authenticator2 = RelayAuthenticator::new().unwrap();

        let token = authenticator1.create_token(1024, 300).unwrap();

        // Should fail with wrong key
        assert!(token.verify(authenticator2.public_key()).is_err());
    }

    #[test]
    fn test_token_expiration() {
        let mut authenticator = RelayAuthenticator::new().unwrap();
        authenticator.set_max_token_age(1); // 1 second

        let token = authenticator.create_token(1024, 300).unwrap();

        // Should not be expired immediately (using authenticator's max age)
        let max_age = authenticator.max_token_age();
        assert!(!token.is_expired(max_age).unwrap());

        // Wait for expiration - using longer delay to ensure expiration
        thread::sleep(Duration::from_secs(2)); // 2 full seconds to be sure

        // Should be expired now (using authenticator's max age)
        assert!(token.is_expired(max_age).unwrap());
    }

    #[test]
    fn test_anti_replay_protection() {
        let authenticator = RelayAuthenticator::new().unwrap();
        let token = authenticator.create_token(1024, 300).unwrap();

        // First verification should succeed
        assert!(
            authenticator
                .verify_token(&token, authenticator.public_key())
                .is_ok()
        );

        // Second verification should fail (replay)
        assert!(
            authenticator
                .verify_token(&token, authenticator.public_key())
                .is_err()
        );
    }

    #[test]
    fn test_nonce_uniqueness() {
        let authenticator = RelayAuthenticator::new().unwrap();
        let mut nonces = HashSet::new();

        // Generate many tokens and check nonce uniqueness
        for _ in 0..1000 {
            let token = authenticator.create_token(1024, 300).unwrap();
            assert!(!nonces.contains(&token.nonce), "Duplicate nonce detected");
            nonces.insert(token.nonce);
        }
    }

    #[test]
    fn test_token_signable_data() {
        let authenticator = RelayAuthenticator::new().unwrap();
        let token1 = authenticator.create_token(1024, 300).unwrap();
        let token2 = authenticator.create_token(1024, 300).unwrap();

        // Different tokens should have different signable data (due to nonce/timestamp)
        assert_ne!(token1.signable_data(), token2.signable_data());
    }

    #[test]
    fn test_nonce_window_management() {
        let authenticator = RelayAuthenticator::new().unwrap();

        // Fill up the nonce window
        for _ in 0..1000 {
            let token = authenticator.create_token(1024, 300).unwrap();
            let _ = authenticator.verify_token(&token, authenticator.public_key());
        }

        assert_eq!(authenticator.nonce_count(), 1000);

        // Add one more token (should trigger cleanup)
        let token = authenticator.create_token(1024, 300).unwrap();
        let _ = authenticator.verify_token(&token, authenticator.public_key());

        // Window should be maintained at reasonable size
        assert!(authenticator.nonce_count() <= 1000);
    }

    #[test]
    fn test_clear_nonces() {
        let authenticator = RelayAuthenticator::new().unwrap();
        let token = authenticator.create_token(1024, 300).unwrap();

        // Use token
        let _ = authenticator.verify_token(&token, authenticator.public_key());
        assert!(authenticator.nonce_count() > 0);

        // Clear nonces
        authenticator.clear_nonces();
        assert_eq!(authenticator.nonce_count(), 0);

        // Should be able to use the same token again
        assert!(
            authenticator
                .verify_token(&token, authenticator.public_key())
                .is_ok()
        );
    }

    #[test]
    fn test_with_specific_keypair() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let authenticator = RelayAuthenticator::with_keypair(public_key, secret_key);

        let token = authenticator.create_token(1024, 300).unwrap();
        assert!(token.verify(authenticator.public_key()).is_ok());
    }
}
