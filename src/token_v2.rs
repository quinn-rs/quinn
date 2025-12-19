//! Token v2: bind address-validation tokens to (PeerId || CID || nonce).
//!
//! This module provides secure token encryption using AES-256-GCM with proper
//! authenticated encryption. Tokens are bound to specific peer IDs and connection
//! IDs to prevent token replay and spoofing attacks.
//!
//! Security features:
//! - AES-256-GCM authenticated encryption
//! - 12-byte nonces for uniqueness
//! - Authentication tags to prevent tampering
//! - Proper nonce handling to avoid reuse
//!
//! Not wired into transport yet; used by tests and for upcoming integration.
#![allow(missing_docs)]

// This module requires at least one crypto provider
// It will only be compiled when ring or aws-lc-rs features are enabled

use rand::RngCore;

use crate::{nat_traversal_api::PeerId, shared::ConnectionId};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

/// A 256-bit key used for encrypting and authenticating retry tokens.
/// Used with AES-256-GCM for authenticated encryption of token contents.
#[derive(Clone)]
pub struct TokenKey(pub [u8; 32]);

/// The decoded contents of a retry token after successful decryption and validation.
/// Contains the peer identity, connection ID, and nonce used for address validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTokenDecoded {
    /// The peer ID that the token was issued for.
    pub peer_id: PeerId,
    /// The connection ID associated with this token.
    pub cid: ConnectionId,
    /// A unique nonce to prevent replay attacks.
    pub nonce: u128,
}

/// Generate a random token key for testing purposes.
/// Fills a 32-byte array with random data from the provided RNG.
pub fn test_key_from_rng(rng: &mut dyn RngCore) -> TokenKey {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    TokenKey(k)
}

/// Encode a retry token containing peer ID, connection ID, and a fresh nonce.
/// Encrypts the token contents using AES-256-GCM with the provided key.
/// Returns the encrypted token as bytes, including authentication tag and nonce.
pub fn encode_retry_token_with_rng<R: RngCore>(
    key: &TokenKey,
    peer_id: &PeerId,
    cid: &ConnectionId,
    rng: &mut R,
) -> Vec<u8> {
    let mut nonce_bytes = [0u8; 12]; // AES-GCM standard nonce length is 12 bytes
    rng.fill_bytes(&mut nonce_bytes);

    let mut pt = Vec::with_capacity(32 + 1 + crate::MAX_CID_SIZE + 12);
    pt.extend_from_slice(&peer_id.0);
    pt.push(cid.len() as u8);
    pt.extend_from_slice(&cid[..]);
    pt.extend_from_slice(&nonce_bytes); // Include nonce in plaintext for binding
    seal(&key.0, &nonce_bytes, &pt)
}

pub fn encode_retry_token(key: &TokenKey, peer_id: &PeerId, cid: &ConnectionId) -> Vec<u8> {
    encode_retry_token_with_rng(key, peer_id, cid, &mut rand::thread_rng())
}

/// Decode and validate a retry token, returning the contained peer information.
/// Decrypts the token using the provided key and validates the contents.
/// Returns None if decryption fails or the token format is invalid.
pub fn decode_retry_token(key: &TokenKey, token: &[u8]) -> Option<RetryTokenDecoded> {
    // Use last 12 bytes (nonce suffix) for AEAD open
    let (ct, nonce_suffix) = token.split_at(token.len().checked_sub(12)?);
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(nonce_suffix);
    let plaintext = open(&key.0, &nonce12, ct).ok()?;
    if plaintext.len() < 32 + 1 + 12 {
        return None;
    } // Expect 12-byte nonce in plaintext
    let mut off = 0usize;
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&plaintext[off..off + 32]);
    off += 32;
    let cid_len = plaintext[off] as usize;
    off += 1;
    if plaintext.len() < off + cid_len + 12 {
        return None;
    }
    let mut cid_buf = [0u8; crate::MAX_CID_SIZE];
    cid_buf[..cid_len].copy_from_slice(&plaintext[off..off + cid_len]);
    let cid = ConnectionId::new(&cid_buf[..cid_len]);
    off += cid_len;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&plaintext[off..off + 12]);
    let mut nonce_bytes_16 = [0u8; 16];
    nonce_bytes_16[..12].copy_from_slice(&nonce_arr);
    let nonce = u128::from_le_bytes(nonce_bytes_16); // Convert 12 bytes to u128 (pad with zeros)
    Some(RetryTokenDecoded {
        peer_id: PeerId(pid),
        cid,
        nonce,
    })
}

/// Validate a retry/validation token against the expected peer and connection ID.
/// Returns `true` if the token decodes and matches both identifiers.
pub fn validate_token(
    key: &TokenKey,
    token: &[u8],
    expected_peer: &PeerId,
    expected_cid: &ConnectionId,
) -> bool {
    match decode_retry_token(key, token) {
        Some(dec) => dec.peer_id == *expected_peer && dec.cid == *expected_cid,
        None => false,
    }
}

/// Encrypt plaintext using AES-256-GCM with the provided key and nonce.
/// Returns the ciphertext with authentication tag and nonce suffix.
#[allow(clippy::expect_used, clippy::let_unit_value)]
fn seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).expect("invalid key length");
    let key = LessSafeKey::new(unbound_key);

    // Store nonce bytes for later use before creating Nonce object
    let nonce_bytes = *nonce;

    // Use 12-byte nonce for AES-GCM encryption
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).expect("invalid nonce length");

    let mut in_out = pt.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .expect("encryption failed");

    // Append the full 12-byte nonce as suffix (standard for QUIC tokens)
    in_out.extend_from_slice(&nonce_bytes);
    in_out
}

/// Decrypt ciphertext using AES-256-GCM with the provided key and nonce suffix.
/// Returns the decrypted plaintext on success, or error if decryption fails.
///
/// Security: Uses the same 12-byte nonce as encryption to maintain consistency.
/// The nonce is extracted from the token suffix and used directly for decryption.
/// Authentication failure (tampered ciphertext) will result in an error.
fn open(key: &[u8; 32], nonce12: &[u8; 12], ct_without_suffix: &[u8]) -> Result<Vec<u8>, ()> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| ())?;
    let key = LessSafeKey::new(unbound_key);

    // Use the 12-byte nonce directly (same as encryption)
    // This ensures nonce consistency between encrypt/decrypt operations
    let nonce = Nonce::try_assume_unique_for_key(nonce12).map_err(|_| ())?;

    let mut in_out = ct_without_suffix.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| ())?;

    // Remove the authentication tag (16 bytes) from the end
    in_out.truncate(in_out.len() - 16);
    Ok(in_out)
}
