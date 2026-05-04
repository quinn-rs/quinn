//! Implementations of Quinn's low-level crypto traits backed by the system OpenSSL library.
//!
//! This module provides [`HmacKey`], [`HkdfPrk`], and [`AeadKey`] using the `openssl` crate,
//! which links against the platform's installed libcrypto.  It mirrors the structure of
//! `ring_like.rs` so that `config/mod.rs` can select the right backend with `#[cfg]` blocks.

use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer, symm};

use crate::crypto::{self, CryptoError};

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/// An HMAC-SHA256 key backed by OpenSSL.
pub(crate) struct HmacKey(Vec<u8>);

impl HmacKey {
    /// Create a new HMAC-SHA256 key from raw bytes.
    pub(crate) fn new(key: &[u8]) -> Self {
        Self(key.to_vec())
    }
}

impl crypto::HmacKey for HmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let pkey = PKey::hmac(&self.0).expect("openssl: PKey::hmac failed");
        let mut signer =
            Signer::new(MessageDigest::sha256(), &pkey).expect("openssl: Signer::new failed");
        signer.update(data).expect("openssl: Signer::update failed");
        let sig = signer.sign_to_vec().expect("openssl: sign_to_vec failed");
        out.copy_from_slice(&sig);
    }

    fn signature_len(&self) -> usize {
        32 // SHA-256 output is always 32 bytes
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut actual = [0u8; 32];
        self.sign(data, &mut actual);
        // Use OpenSSL's constant-time comparison to avoid timing attacks
        if openssl::memcmp::eq(&actual, signature) {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

// ---------------------------------------------------------------------------
// HKDF PRK (HandshakeTokenKey)
// ---------------------------------------------------------------------------

/// An HKDF pseudo-random key backed by OpenSSL, usable as a [`crypto::HandshakeTokenKey`].
///
/// Created via HKDF-Extract(SHA-256, salt, IKM).  The `aead_from_hkdf` method performs
/// HKDF-Expand to derive a 32-byte AES-256-GCM key (RFC 5869, single-block variant).
pub(crate) struct HkdfPrk(Vec<u8>); // stores the raw 32-byte PRK

impl HkdfPrk {
    /// HKDF-Extract(salt, ikm) using SHA-256.
    ///
    /// Per RFC 5869 §2.2: if `salt` is empty a zero-filled HashLen (32) byte string is used.
    pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        // RFC 5869: if not provided, salt = zeroes of HashLen
        let zero_salt = [0u8; 32];
        let actual_salt: &[u8] = if salt.is_empty() { &zero_salt } else { salt };

        let pkey = PKey::hmac(actual_salt).expect("openssl: PKey::hmac failed");
        let mut signer =
            Signer::new(MessageDigest::sha256(), &pkey).expect("openssl: Signer::new failed");
        signer.update(ikm).expect("openssl: Signer::update failed");
        let prk = signer.sign_to_vec().expect("openssl: sign_to_vec failed");
        Self(prk)
    }
}

impl crypto::HandshakeTokenKey for HkdfPrk {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        // HKDF-Expand(PRK, info=random_bytes, L=32) — single 32-byte block:
        //   T(1) = HMAC-SHA256(PRK, info || 0x01)
        let pkey = PKey::hmac(&self.0).expect("openssl: PKey::hmac failed");
        let mut signer =
            Signer::new(MessageDigest::sha256(), &pkey).expect("openssl: Signer::new failed");
        signer
            .update(random_bytes)
            .expect("openssl: Signer::update failed");
        signer
            .update(&[0x01])
            .expect("openssl: Signer::update counter failed");
        let okm = signer.sign_to_vec().expect("openssl: sign_to_vec failed");

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&okm);
        Box::new(AeadKey(key_bytes))
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM AEAD key (AeadKey)
// ---------------------------------------------------------------------------

/// An AES-256-GCM key backed by OpenSSL, usable as a [`crypto::AeadKey`].
///
/// Follows the same zero-nonce / 16-byte tag convention as the ring/aws-lc-rs implementation.
pub(crate) struct AeadKey([u8; 32]);

impl crypto::AeadKey for AeadKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        let ciphertext = symm::encrypt_aead(
            symm::Cipher::aes_256_gcm(),
            &self.0,
            Some(&nonce),
            additional_data,
            data,
            &mut tag,
        )
        .map_err(|_| CryptoError)?;
        *data = ciphertext;
        data.extend_from_slice(&tag);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        if data.len() < 16 {
            return Err(CryptoError);
        }
        let tag_pos = data.len() - 16;
        let nonce = [0u8; 12];

        // decrypt_aead allocates a new buffer; we copy back into `data` afterwards
        let plaintext = symm::decrypt_aead(
            symm::Cipher::aes_256_gcm(),
            &self.0,
            Some(&nonce),
            additional_data,
            &data[..tag_pos],
            &data[tag_pos..],
        )
        .map_err(|_| CryptoError)?;

        let plain_len = plaintext.len();
        data[..plain_len].copy_from_slice(&plaintext);
        Ok(&mut data[..plain_len])
    }
}
