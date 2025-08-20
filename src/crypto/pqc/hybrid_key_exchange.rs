// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Hybrid key exchange implementation combining classical and PQC algorithms
//!
//! This module provides a complete key exchange flow using both classical
//! (ECDH) and post-quantum (ML-KEM) algorithms in parallel.

use crate::crypto::pqc::combiners::HybridCombiner;
use crate::crypto::pqc::hybrid::HybridKem;
use crate::crypto::pqc::types::*;
use std::sync::Arc;

/// Hybrid key exchange state machine
pub struct HybridKeyExchange {
    kem: HybridKem,
    role: KeyExchangeRole,
    state: KeyExchangeState,
}

/// Role in the key exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeRole {
    /// Initiator (client)
    Initiator,
    /// Responder (server)
    Responder,
}

/// State of the key exchange
pub enum KeyExchangeState {
    /// Initial state
    Initial,
    /// Waiting for peer's public key
    WaitingForPeerKey {
        our_keypair: (HybridKemPublicKey, HybridKemSecretKey),
    },
    /// Key exchange complete
    Complete { shared_secret: SharedSecret },
    /// Error state
    Failed(String),
}

/// Key share to be sent over the wire
#[derive(Clone)]
pub struct HybridKeyShare {
    /// Classical public key component
    pub classical_public: Vec<u8>,
    /// ML-KEM public key component
    pub ml_kem_public: Vec<u8>,
    /// For initiator: empty, For responder: ciphertext
    pub ciphertext: Option<HybridCiphertext>,
}

/// Hybrid ciphertext for responder
#[derive(Clone)]
pub struct HybridCiphertext {
    /// Classical ciphertext/ephemeral key
    pub classical: Vec<u8>,
    /// ML-KEM ciphertext
    pub ml_kem: Vec<u8>,
}

impl HybridKeyExchange {
    /// Create a new key exchange instance
    pub fn new(role: KeyExchangeRole) -> Self {
        Self {
            kem: HybridKem::new(),
            role,
            state: KeyExchangeState::Initial,
        }
    }

    /// Create with a specific combiner
    pub fn with_combiner(role: KeyExchangeRole, combiner: Arc<dyn HybridCombiner>) -> Self {
        Self {
            kem: HybridKem::with_combiner(combiner),
            role,
            state: KeyExchangeState::Initial,
        }
    }

    /// Start the key exchange
    ///
    /// For initiator: generates keypair and returns public key share
    /// For responder: returns error (must wait for initiator's key first)
    pub fn start(&mut self) -> PqcResult<HybridKeyShare> {
        match (&self.state, self.role) {
            (KeyExchangeState::Initial, KeyExchangeRole::Initiator) => {
                // Generate our keypair
                let (public_key, secret_key) = self.kem.generate_keypair()?;

                let key_share = HybridKeyShare {
                    classical_public: public_key.classical.to_vec(),
                    ml_kem_public: public_key.ml_kem.as_bytes().to_vec(),
                    ciphertext: None,
                };

                self.state = KeyExchangeState::WaitingForPeerKey {
                    our_keypair: (public_key, secret_key),
                };

                Ok(key_share)
            }
            (KeyExchangeState::Initial, KeyExchangeRole::Responder) => Err(PqcError::CryptoError(
                "Responder must wait for initiator's key share".to_string(),
            )),
            _ => Err(PqcError::CryptoError(
                "Invalid state for start operation".to_string(),
            )),
        }
    }

    /// Process peer's key share
    ///
    /// For initiator: processes responder's key share and derives shared secret
    /// For responder: processes initiator's key share, generates response
    pub fn process_peer_key_share(
        &mut self,
        peer_share: &HybridKeyShare,
    ) -> PqcResult<Option<HybridKeyShare>> {
        match (&self.state, self.role) {
            // Responder receiving initiator's public key
            (KeyExchangeState::Initial, KeyExchangeRole::Responder) => {
                // Parse peer's public key
                let peer_public = HybridKemPublicKey {
                    classical: peer_share.classical_public.clone().into_boxed_slice(),
                    ml_kem: MlKemPublicKey::from_bytes(&peer_share.ml_kem_public)?,
                };

                // Encapsulate to generate ciphertext and shared secret
                let (ciphertext, shared_secret) = self.kem.encapsulate(&peer_public)?;

                // Create response with ciphertext
                let response = HybridKeyShare {
                    classical_public: vec![], // Not needed for responder
                    ml_kem_public: vec![],    // Not needed for responder
                    ciphertext: Some(HybridCiphertext {
                        classical: ciphertext.classical.to_vec(),
                        ml_kem: ciphertext.ml_kem.as_bytes().to_vec(),
                    }),
                };

                self.state = KeyExchangeState::Complete { shared_secret };

                Ok(Some(response))
            }

            // Initiator receiving responder's ciphertext
            (KeyExchangeState::WaitingForPeerKey { our_keypair }, KeyExchangeRole::Initiator) => {
                let ciphertext = peer_share.ciphertext.as_ref().ok_or_else(|| {
                    PqcError::CryptoError("Expected ciphertext from responder".to_string())
                })?;

                // Parse ciphertext
                let hybrid_ct = HybridKemCiphertext {
                    classical: ciphertext.classical.clone().into_boxed_slice(),
                    ml_kem: MlKemCiphertext::from_bytes(&ciphertext.ml_kem)?,
                };

                // Decapsulate to derive shared secret
                let shared_secret = self.kem.decapsulate(&our_keypair.1, &hybrid_ct)?;

                self.state = KeyExchangeState::Complete { shared_secret };

                Ok(None) // Initiator doesn't send a response
            }

            _ => Err(PqcError::CryptoError(
                "Invalid state for processing peer key share".to_string(),
            )),
        }
    }

    /// Get the shared secret after successful key exchange
    pub fn get_shared_secret(&self) -> PqcResult<&SharedSecret> {
        match &self.state {
            KeyExchangeState::Complete { shared_secret } => Ok(shared_secret),
            _ => Err(PqcError::CryptoError(
                "Key exchange not complete".to_string(),
            )),
        }
    }

    /// Check if the key exchange is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, KeyExchangeState::Complete { .. })
    }

    /// Get the current role
    pub fn role(&self) -> KeyExchangeRole {
        self.role
    }

    /// Get the current state name for debugging
    pub fn state_name(&self) -> &'static str {
        match &self.state {
            KeyExchangeState::Initial => "Initial",
            KeyExchangeState::WaitingForPeerKey { .. } => "WaitingForPeerKey",
            KeyExchangeState::Complete { .. } => "Complete",
            KeyExchangeState::Failed(_) => "Failed",
        }
    }
}

/// Encode a hybrid key share for transmission
impl HybridKeyShare {
    /// Encode to bytes for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Encode classical public key length and data
        encoded.extend_from_slice(&(self.classical_public.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.classical_public);

        // Encode ML-KEM public key length and data
        encoded.extend_from_slice(&(self.ml_kem_public.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.ml_kem_public);

        // Encode ciphertext if present
        if let Some(ct) = &self.ciphertext {
            encoded.push(1); // Has ciphertext
            encoded.extend_from_slice(&(ct.classical.len() as u16).to_be_bytes());
            encoded.extend_from_slice(&ct.classical);
            encoded.extend_from_slice(&(ct.ml_kem.len() as u16).to_be_bytes());
            encoded.extend_from_slice(&ct.ml_kem);
        } else {
            encoded.push(0); // No ciphertext
        }

        encoded
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> PqcResult<Self> {
        let mut offset = 0;

        // Decode classical public key
        if data.len() < offset + 2 {
            return Err(PqcError::CryptoError(
                "Invalid key share encoding".to_string(),
            ));
        }
        let classical_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + classical_len {
            return Err(PqcError::CryptoError(
                "Invalid classical key length".to_string(),
            ));
        }
        let classical_public = data[offset..offset + classical_len].to_vec();
        offset += classical_len;

        // Decode ML-KEM public key
        if data.len() < offset + 2 {
            return Err(PqcError::CryptoError(
                "Invalid ML-KEM key encoding".to_string(),
            ));
        }
        let ml_kem_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + ml_kem_len {
            return Err(PqcError::CryptoError(
                "Invalid ML-KEM key length".to_string(),
            ));
        }
        let ml_kem_public = data[offset..offset + ml_kem_len].to_vec();
        offset += ml_kem_len;

        // Check for ciphertext
        if data.len() < offset + 1 {
            return Err(PqcError::CryptoError("Missing ciphertext flag".to_string()));
        }
        let has_ciphertext = data[offset] != 0;
        offset += 1;

        let ciphertext = if has_ciphertext {
            // Decode classical ciphertext
            if data.len() < offset + 2 {
                return Err(PqcError::CryptoError(
                    "Invalid classical ct encoding".to_string(),
                ));
            }
            let classical_ct_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if data.len() < offset + classical_ct_len {
                return Err(PqcError::CryptoError(
                    "Invalid classical ct length".to_string(),
                ));
            }
            let classical_ct = data[offset..offset + classical_ct_len].to_vec();
            offset += classical_ct_len;

            // Decode ML-KEM ciphertext
            if data.len() < offset + 2 {
                return Err(PqcError::CryptoError(
                    "Invalid ML-KEM ct encoding".to_string(),
                ));
            }
            let ml_kem_ct_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if data.len() < offset + ml_kem_ct_len {
                return Err(PqcError::CryptoError(
                    "Invalid ML-KEM ct length".to_string(),
                ));
            }
            let ml_kem_ct = data[offset..offset + ml_kem_ct_len].to_vec();

            Some(HybridCiphertext {
                classical: classical_ct,
                ml_kem: ml_kem_ct,
            })
        } else {
            None
        };

        Ok(Self {
            classical_public,
            ml_kem_public,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange_flow() {
        // Create initiator and responder
        let mut initiator = HybridKeyExchange::new(KeyExchangeRole::Initiator);
        let mut responder = HybridKeyExchange::new(KeyExchangeRole::Responder);

        // Initiator starts
        let initiator_share = initiator.start();

        assert!(initiator_share.is_ok());
        let initiator_share = initiator_share.unwrap();
        assert!(initiator_share.ciphertext.is_none());

        // Responder processes initiator's share
        let responder_response = responder.process_peer_key_share(&initiator_share);
        assert!(responder_response.is_ok());
        let responder_share = responder_response.unwrap();
        assert!(responder_share.is_some());
        let responder_share = responder_share.unwrap();
        assert!(responder_share.ciphertext.is_some());

        // Check responder is complete
        assert!(responder.is_complete());

        // Initiator processes responder's share
        let initiator_response = initiator.process_peer_key_share(&responder_share);
        assert!(initiator_response.is_ok());
        assert!(initiator_response.unwrap().is_none()); // No response from initiator

        // Check initiator is complete
        assert!(initiator.is_complete());

        // Both should have the same shared secret
        let initiator_secret = initiator.get_shared_secret().unwrap();
        let responder_secret = responder.get_shared_secret().unwrap();
        assert_eq!(initiator_secret.as_bytes(), responder_secret.as_bytes());
    }

    #[test]
    fn test_responder_cannot_start() {
        let mut responder = HybridKeyExchange::new(KeyExchangeRole::Responder);
        let result = responder.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_key_share_encoding() {
        let share = HybridKeyShare {
            classical_public: vec![1, 2, 3, 4],
            ml_kem_public: vec![5, 6, 7, 8, 9, 10],
            ciphertext: Some(HybridCiphertext {
                classical: vec![11, 12],
                ml_kem: vec![13, 14, 15],
            }),
        };

        let encoded = share.encode();
        let decoded = HybridKeyShare::decode(&encoded).unwrap();

        assert_eq!(share.classical_public, decoded.classical_public);
        assert_eq!(share.ml_kem_public, decoded.ml_kem_public);
        assert!(decoded.ciphertext.is_some());

        let orig_ct = share.ciphertext.as_ref().unwrap();
        let decoded_ct = decoded.ciphertext.as_ref().unwrap();
        assert_eq!(orig_ct.classical, decoded_ct.classical);
        assert_eq!(orig_ct.ml_kem, decoded_ct.ml_kem);
    }

    #[test]
    fn test_key_share_encoding_no_ciphertext() {
        let share = HybridKeyShare {
            classical_public: vec![1, 2, 3, 4],
            ml_kem_public: vec![5, 6, 7, 8, 9, 10],
            ciphertext: None,
        };

        let encoded = share.encode();
        let decoded = HybridKeyShare::decode(&encoded).unwrap();

        assert_eq!(share.classical_public, decoded.classical_public);
        assert_eq!(share.ml_kem_public, decoded.ml_kem_public);
        assert!(decoded.ciphertext.is_none());
    }

    #[test]
    fn test_state_transitions() {
        let mut kex = HybridKeyExchange::new(KeyExchangeRole::Initiator);
        assert_eq!(kex.state_name(), "Initial");

        let _ = kex.start().unwrap();
        assert_eq!(kex.state_name(), "WaitingForPeerKey");
    }
}
