use ring::{aead, hmac};

use crate::{
    config::ConfigError,
    crypto,
    packet::{PacketNumber, LONG_HEADER_FORM},
};

impl crypto::HeaderKey for aead::quic::HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.new_mask(&sample[0..self.sample_size()]).unwrap();
        if header[0] & LONG_HEADER_FORM == LONG_HEADER_FORM {
            // Long header: 4 bits masked
            header[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: 5 bits masked
            header[0] ^= mask[0] & 0x1f;
        }
        let pn_length = PacketNumber::decode_len(header[0]);
        for (out, inp) in header[pn_offset..pn_offset + pn_length]
            .iter_mut()
            .zip(&mask[1..])
        {
            *out ^= inp;
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.new_mask(&sample[0..self.sample_size()]).unwrap();
        let pn_length = PacketNumber::decode_len(header[0]);
        if header[0] & LONG_HEADER_FORM == LONG_HEADER_FORM {
            // Long header: 4 bits masked
            header[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: 5 bits masked
            header[0] ^= mask[0] & 0x1f;
        }
        for (out, inp) in header[pn_offset..pn_offset + pn_length]
            .iter_mut()
            .zip(&mask[1..])
        {
            *out ^= inp;
        }
    }

    fn sample_size(&self) -> usize {
        self.algorithm().sample_len()
    }
}

impl crypto::HmacKey for hmac::Key {
    const KEY_LEN: usize = 64;
    type Signature = hmac::Tag;

    fn new(key: &[u8]) -> Result<Self, ConfigError> {
        if key.len() == Self::KEY_LEN {
            Ok(hmac::Key::new(hmac::HMAC_SHA256, key))
        } else {
            Err(ConfigError::OutOfBounds)
        }
    }

    fn sign(&self, data: &[u8]) -> Self::Signature {
        hmac::sign(self, data)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ()> {
        hmac::verify(self, data, signature).map_err(|_| ())
    }
}
