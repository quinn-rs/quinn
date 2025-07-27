//! Authentication module for P2P connections using Ed25519 keys
//!
//! This module provides authentication functionality for P2P connections,
//! including peer identity verification, challenge-response authentication,
//! and secure session establishment.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use ed25519_dalek::{
    Signature, Signer, SigningKey as Ed25519SecretKey, Verifier, VerifyingKey as Ed25519PublicKey,
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, public_key_from_bytes, public_key_to_bytes, verify_peer_id,
    },
    nat_traversal_api::PeerId,
};

/// Constant-time equality comparison for byte arrays
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // For constant-time execution, we must not return early based on length
    let len_equal = a.len() == b.len();

    // Process up to the shorter length to avoid bounds issues
    let min_len = a.len().min(b.len());
    let mut result = 0u8;

    // Compare bytes up to min length
    for i in 0..min_len {
        result |= a[i] ^ b[i];
    }

    // If lengths differ, ensure result is non-zero
    if !len_equal {
        result |= 1;
    }

    // Constant-time conversion to bool
    result == 0
}

/// Authentication error types
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Peer not found")]
    PeerNotFound,
    #[error("Authentication timeout")]
    Timeout,
    #[error("Invalid peer ID")]
    InvalidPeerId,
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Key error: {0}")]
    KeyError(String),
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Timeout for authentication handshake
    pub auth_timeout: Duration,
    /// Challenge validity duration
    pub challenge_validity: Duration,
    /// Whether to require authentication for all connections
    pub require_authentication: bool,
    /// Maximum number of authentication attempts
    pub max_auth_attempts: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(10),
            challenge_validity: Duration::from_secs(60),
            require_authentication: true,
            max_auth_attempts: 3,
        }
    }
}

/// Authentication message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMessage {
    /// Initial authentication request with public key
    AuthRequest {
        peer_id: PeerId,
        public_key: [u8; 32],
        timestamp: SystemTime,
    },
    /// Challenge to verify key ownership
    Challenge {
        nonce: [u8; 32],
        timestamp: SystemTime,
    },
    /// Response to challenge with signature
    ChallengeResponse {
        nonce: [u8; 32],
        signature: Vec<u8>,
        timestamp: SystemTime,
    },
    /// Authentication successful
    AuthSuccess {
        session_id: [u8; 32],
        timestamp: SystemTime,
    },
    /// Authentication failed
    AuthFailure { reason: String },
}

/// Authenticated peer information
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    /// Peer ID derived from public key
    pub peer_id: PeerId,
    /// Ed25519 public key
    pub public_key: Ed25519PublicKey,
    /// When authentication was completed
    pub authenticated_at: Instant,
    /// Session ID for this connection
    pub session_id: [u8; 32],
}

/// Authentication manager for handling peer authentication
pub struct AuthManager {
    /// Our Ed25519 secret key
    secret_key: Ed25519SecretKey,
    /// Our public key
    public_key: Ed25519PublicKey,
    /// Our peer ID
    peer_id: PeerId,
    /// Configuration
    config: AuthConfig,
    /// Authenticated peers
    authenticated_peers: Arc<RwLock<HashMap<PeerId, AuthenticatedPeer>>>,
    /// Pending challenges
    pending_challenges: Arc<RwLock<HashMap<PeerId, PendingChallenge>>>,
}

/// Pending authentication challenge
#[derive(Debug)]
struct PendingChallenge {
    nonce: [u8; 32],
    created_at: Instant,
    attempts: u32,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(secret_key: Ed25519SecretKey, config: AuthConfig) -> Self {
        let public_key = secret_key.verifying_key();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Initialized AuthManager with peer ID: {:?}", peer_id);

        Self {
            secret_key,
            public_key,
            peer_id,
            config,
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            pending_challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get our public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        public_key_to_bytes(&self.public_key)
    }

    /// Get authentication configuration
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Create an authentication request
    pub fn create_auth_request(&self) -> AuthMessage {
        AuthMessage::AuthRequest {
            peer_id: self.peer_id,
            public_key: self.public_key_bytes(),
            timestamp: SystemTime::now(),
        }
    }

    /// Handle incoming authentication request
    pub async fn handle_auth_request(
        &self,
        peer_id: PeerId,
        public_key_bytes: [u8; 32],
    ) -> Result<AuthMessage, AuthError> {
        // Verify that the peer ID matches the public key
        let public_key = public_key_from_bytes(&public_key_bytes)
            .map_err(|e| AuthError::KeyError(e.to_string()))?;

        if !verify_peer_id(&peer_id, &public_key) {
            return Err(AuthError::InvalidPeerId);
        }

        // Generate a challenge nonce
        let nonce = {
            use rand::Rng;
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill(&mut nonce);
            nonce
        };

        // Store the pending challenge
        let mut challenges = self.pending_challenges.write().await;
        challenges.insert(
            peer_id,
            PendingChallenge {
                nonce,
                created_at: Instant::now(),
                attempts: 0,
            },
        );

        debug!("Created challenge for peer {:?}", peer_id);

        Ok(AuthMessage::Challenge {
            nonce,
            timestamp: SystemTime::now(),
        })
    }

    /// Create a challenge response
    pub fn create_challenge_response(&self, nonce: [u8; 32]) -> Result<AuthMessage, AuthError> {
        // Sign the nonce with our private key
        let signature = self.secret_key.sign(&nonce);

        Ok(AuthMessage::ChallengeResponse {
            nonce,
            signature: signature.to_vec(),
            timestamp: SystemTime::now(),
        })
    }

    /// Verify a challenge response
    pub async fn verify_challenge_response(
        &self,
        peer_id: PeerId,
        public_key_bytes: [u8; 32],
        nonce: [u8; 32],
        signature_bytes: &[u8],
    ) -> Result<AuthMessage, AuthError> {
        // Perform all operations to ensure constant timing

        // Step 1: Gather all data and perform checks without early returns
        let mut challenges = self.pending_challenges.write().await;
        let challenge_exists = challenges.contains_key(&peer_id);
        let stored_nonce = challenges
            .get(&peer_id)
            .map(|c| c.nonce)
            .unwrap_or([0u8; 32]);
        let created_at = challenges
            .get(&peer_id)
            .map(|c| c.created_at)
            .unwrap_or(Instant::now());
        let attempts = challenges
            .get_mut(&peer_id)
            .map(|c| {
                c.attempts += 1;
                c.attempts
            })
            .unwrap_or(0);

        // Check conditions (but don't return early)
        let nonce_matches = constant_time_eq(&stored_nonce, &nonce);
        let not_expired = created_at.elapsed() <= self.config.challenge_validity;
        let attempts_ok = attempts < self.config.max_auth_attempts;

        // Step 2: Parse keys and signature (always do this)
        let public_key_result = public_key_from_bytes(&public_key_bytes);
        let signature_result = Signature::from_slice(signature_bytes);

        // Step 3: Verify signature (always attempt this)
        let verification_result = match (public_key_result, signature_result) {
            (Ok(pk), Ok(sig)) => pk.verify(&nonce, &sig).is_ok(),
            _ => false,
        };

        // Step 4: Generate session data (always do this to maintain constant timing)
        let session_id = {
            use rand::Rng;
            let mut id = [0u8; 32];
            rand::thread_rng().fill(&mut id);
            id
        };

        // Step 5: Determine final result based on all checks
        let all_valid =
            challenge_exists && nonce_matches && not_expired && attempts_ok && verification_result;

        debug!(
            "Verification results - exists: {}, nonce_matches: {}, not_expired: {}, attempts_ok: {}, verification: {}",
            challenge_exists, nonce_matches, not_expired, attempts_ok, verification_result
        );

        // Step 6: Clean up and store results based on validity
        if all_valid {
            // Remove the challenge
            challenges.remove(&peer_id);
            drop(challenges); // Release lock before acquiring peers lock

            // Store authenticated peer
            if let Ok(public_key) = public_key_from_bytes(&public_key_bytes) {
                let mut peers = self.authenticated_peers.write().await;
                peers.insert(
                    peer_id,
                    AuthenticatedPeer {
                        peer_id,
                        public_key,
                        authenticated_at: Instant::now(),
                        session_id,
                    },
                );

                info!("Successfully authenticated peer {:?}", peer_id);
            }

            Ok(AuthMessage::AuthSuccess {
                session_id,
                timestamp: SystemTime::now(),
            })
        } else {
            // Determine specific error (but after all operations complete)
            let error = if !challenge_exists {
                AuthError::PeerNotFound
            } else if !not_expired {
                challenges.remove(&peer_id);
                AuthError::ChallengeExpired
            } else if !attempts_ok {
                challenges.remove(&peer_id);
                AuthError::InvalidSignature
            } else if !nonce_matches {
                AuthError::InvalidSignature
            } else {
                AuthError::InvalidSignature
            };

            Err(error)
        }
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        let peers = self.authenticated_peers.read().await;
        peers.contains_key(peer_id)
    }

    /// Get authenticated peer information
    pub async fn get_authenticated_peer(&self, peer_id: &PeerId) -> Option<AuthenticatedPeer> {
        let peers = self.authenticated_peers.read().await;
        peers.get(peer_id).cloned()
    }

    /// Handle successful authentication from responder
    pub async fn handle_auth_success(
        &self,
        peer_id: PeerId,
        public_key_bytes: [u8; 32],
        session_id: [u8; 32],
    ) -> Result<(), AuthError> {
        // Parse the public key
        let public_key = public_key_from_bytes(&public_key_bytes)
            .map_err(|e| AuthError::KeyError(e.to_string()))?;

        // Store the authenticated peer
        let mut peers = self.authenticated_peers.write().await;
        peers.insert(
            peer_id,
            AuthenticatedPeer {
                peer_id,
                public_key,
                authenticated_at: Instant::now(),
                session_id,
            },
        );

        info!(
            "Marked peer {:?} as authenticated after receiving AuthSuccess",
            peer_id
        );
        Ok(())
    }

    /// Remove an authenticated peer
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        let mut peers = self.authenticated_peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!("Removed authenticated peer {:?}", peer_id);
        }
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) {
        let mut challenges = self.pending_challenges.write().await;
        let now = Instant::now();

        challenges.retain(|peer_id, challenge| {
            let expired =
                now.duration_since(challenge.created_at) <= self.config.challenge_validity;
            if !expired {
                debug!("Removing expired challenge for peer {:?}", peer_id);
            }
            expired
        });
    }

    /// Get list of authenticated peers
    pub async fn list_authenticated_peers(&self) -> Vec<PeerId> {
        let peers = self.authenticated_peers.read().await;
        peers.keys().cloned().collect()
    }

    /// Serialize an auth message
    pub fn serialize_message(msg: &AuthMessage) -> Result<Vec<u8>, AuthError> {
        serde_json::to_vec(msg).map_err(|e| AuthError::SerializationError(e.to_string()))
    }

    /// Deserialize an auth message
    pub fn deserialize_message(data: &[u8]) -> Result<AuthMessage, AuthError> {
        serde_json::from_slice(data).map_err(|e| AuthError::SerializationError(e.to_string()))
    }
}

/// Authentication protocol handler for integration with QuicP2PNode
pub struct AuthProtocol {
    auth_manager: Arc<AuthManager>,
    /// Temporary storage for public keys during authentication
    pending_auth: Arc<tokio::sync::RwLock<HashMap<PeerId, [u8; 32]>>>,
}

impl AuthProtocol {
    /// Create a new authentication protocol handler
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        Self {
            auth_manager,
            pending_auth: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Handle incoming authentication message
    pub async fn handle_message(
        &self,
        peer_id: PeerId,
        message: AuthMessage,
    ) -> Result<Option<AuthMessage>, AuthError> {
        match message {
            AuthMessage::AuthRequest {
                peer_id: req_peer_id,
                public_key,
                ..
            } => {
                if req_peer_id != peer_id {
                    return Err(AuthError::InvalidPeerId);
                }
                // Store the public key for later verification
                self.pending_auth.write().await.insert(peer_id, public_key);
                let response = self
                    .auth_manager
                    .handle_auth_request(peer_id, public_key)
                    .await?;
                Ok(Some(response))
            }
            AuthMessage::Challenge { nonce, .. } => {
                let response = self.auth_manager.create_challenge_response(nonce)?;
                Ok(Some(response))
            }
            AuthMessage::ChallengeResponse {
                nonce, signature, ..
            } => {
                // Get the public key from the initial auth request
                let public_key_bytes = match self.pending_auth.read().await.get(&peer_id) {
                    Some(key) => *key,
                    None => return Err(AuthError::PeerNotFound),
                };

                let response = self
                    .auth_manager
                    .verify_challenge_response(peer_id, public_key_bytes, nonce, &signature)
                    .await?;

                // Remove the pending auth entry on success
                if matches!(response, AuthMessage::AuthSuccess { .. }) {
                    self.pending_auth.write().await.remove(&peer_id);
                }

                Ok(Some(response))
            }
            AuthMessage::AuthSuccess { session_id, .. } => {
                info!(
                    "Authentication successful with peer {:?}, session: {:?}",
                    peer_id,
                    hex::encode(session_id)
                );
                Ok(None)
            }
            AuthMessage::AuthFailure { reason } => {
                warn!("Authentication failed with peer {:?}: {}", peer_id, reason);
                Err(AuthError::InvalidSignature)
            }
        }
    }

    /// Initiate authentication with a peer
    pub async fn initiate_auth(&self) -> AuthMessage {
        self.auth_manager.create_auth_request()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::raw_public_keys::key_utils::generate_ed25519_keypair;

    #[tokio::test]
    async fn test_auth_manager_creation() {
        let (secret_key, _) = generate_ed25519_keypair();
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(secret_key, config);

        // Verify peer ID is derived correctly
        let peer_id = auth_manager.peer_id();
        assert_eq!(peer_id.0.len(), 32);
    }

    #[tokio::test]
    async fn test_authentication_flow() {
        // Create two auth managers (simulating two peers)
        let (secret_key1, public_key1) = generate_ed25519_keypair();
        let (secret_key2, _) = generate_ed25519_keypair();

        let auth1 = AuthManager::new(secret_key1, AuthConfig::default());
        let auth2 = AuthManager::new(secret_key2, AuthConfig::default());

        // Peer 1 creates auth request
        let auth_request = auth1.create_auth_request();

        // Peer 2 handles the request and creates a challenge
        let challenge = match &auth_request {
            AuthMessage::AuthRequest {
                peer_id,
                public_key,
                ..
            } => auth2
                .handle_auth_request(*peer_id, *public_key)
                .await
                .unwrap(),
            _ => panic!("Expected AuthRequest"),
        };

        // Peer 1 responds to the challenge
        let response = match &challenge {
            AuthMessage::Challenge { nonce, .. } => {
                auth1.create_challenge_response(*nonce).unwrap()
            }
            _ => panic!("Expected Challenge"),
        };

        // Peer 2 verifies the response
        let result = match &response {
            AuthMessage::ChallengeResponse {
                nonce, signature, ..
            } => {
                auth2
                    .verify_challenge_response(
                        auth1.peer_id(),
                        public_key_to_bytes(&public_key1),
                        *nonce,
                        signature,
                    )
                    .await
            }
            _ => panic!("Expected ChallengeResponse"),
        };

        // Should be successful
        assert!(matches!(result, Ok(AuthMessage::AuthSuccess { .. })));

        // Peer 1 should now be authenticated by peer 2
        assert!(auth2.is_authenticated(&auth1.peer_id()).await);
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let (secret_key1, _) = generate_ed25519_keypair();
        let (secret_key2, public_key2) = generate_ed25519_keypair();

        let auth1 = AuthManager::new(secret_key1, AuthConfig::default());
        let _auth2 = AuthManager::new(secret_key2, AuthConfig::default());

        // Create a challenge
        let peer_id2 = derive_peer_id_from_public_key(&public_key2);
        let challenge = auth1
            .handle_auth_request(peer_id2, public_key_to_bytes(&public_key2))
            .await
            .unwrap();

        // Create an invalid response (wrong signature)
        let invalid_signature = vec![0u8; 64];
        let nonce = match &challenge {
            AuthMessage::Challenge { nonce, .. } => *nonce,
            _ => panic!("Expected Challenge"),
        };

        // Verification should fail
        let result = auth1
            .verify_challenge_response(
                peer_id2,
                public_key_to_bytes(&public_key2),
                nonce,
                &invalid_signature,
            )
            .await;

        assert!(matches!(result, Err(AuthError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_challenge_expiry() {
        let (secret_key, public_key) = generate_ed25519_keypair();
        let config = AuthConfig {
            challenge_validity: Duration::from_millis(100), // Very short for testing
            ..Default::default()
        };

        let auth = AuthManager::new(secret_key, config);
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Create a challenge
        let _challenge = auth
            .handle_auth_request(peer_id, public_key_to_bytes(&public_key))
            .await
            .unwrap();

        // Wait for it to expire
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Try to verify - should fail due to expiry
        let result = auth
            .verify_challenge_response(
                peer_id,
                public_key_to_bytes(&public_key),
                [0u8; 32],  // dummy nonce
                &[0u8; 64], // dummy signature
            )
            .await;

        assert!(matches!(result, Err(AuthError::ChallengeExpired)));
    }

    #[tokio::test]
    async fn test_message_serialization() {
        let (_, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        let msg = AuthMessage::AuthRequest {
            peer_id,
            public_key: public_key_to_bytes(&public_key),
            timestamp: SystemTime::now(),
        };

        // Serialize and deserialize
        let serialized = AuthManager::serialize_message(&msg).unwrap();
        let deserialized = AuthManager::deserialize_message(&serialized).unwrap();

        match (msg, deserialized) {
            (
                AuthMessage::AuthRequest {
                    peer_id: p1,
                    public_key: k1,
                    ..
                },
                AuthMessage::AuthRequest {
                    peer_id: p2,
                    public_key: k2,
                    ..
                },
            ) => {
                assert_eq!(p1, p2);
                assert_eq!(k1, k2);
            }
            _ => panic!("Message mismatch"),
        }
    }
}
