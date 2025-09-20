// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::{aead, error, hkdf, hmac};
#[cfg(feature = "ring")]
use ring::{aead, error, hkdf, hmac};

use crate::crypto::{self, CryptoError};

impl crypto::HmacKey for hmac::Key {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        out.copy_from_slice(hmac::sign(self, data).as_ref());
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        Ok(hmac::verify(self, data, signature)?)
    }
}

impl crypto::HandshakeTokenKey for hkdf::Prk {
    #[allow(clippy::panic)]
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let mut key_buffer = [0u8; 32];
        let info = [random_bytes];
        let okm = self
            .expand(&info, hkdf::HKDF_SHA256)
            .unwrap_or_else(|_| panic!("HKDF expand should succeed with valid parameters"));

        okm.fill(&mut key_buffer)
            .unwrap_or_else(|_| panic!("OKM fill should succeed"));

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_buffer)
            .unwrap_or_else(|_| panic!("AES key creation should succeed with valid key material"));
        Box::new(aead::LessSafeKey::new(key))
    }
}

impl crypto::AeadKey for aead::LessSafeKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let aad = aead::Aad::from(additional_data);
        let zero_nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
        Ok(self.seal_in_place_append_tag(zero_nonce, aad, data)?)
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let aad = aead::Aad::from(additional_data);
        let zero_nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
        Ok(self.open_in_place(zero_nonce, aad, data)?)
    }
}

impl From<error::Unspecified> for CryptoError {
    fn from(_: error::Unspecified) -> Self {
        Self
    }
}
