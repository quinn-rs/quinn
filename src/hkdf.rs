use bytes::{BigEndian, BufMut};

use ring::{
    aead::{self, AES_128_GCM},
    digest::SHA256,
    hkdf,
    hmac::SigningKey,
};

pub fn client_handshake_input(conn_id: u64) -> AeadInput {
    let shared_key = SigningKey::new(&SHA256, &client_handshake_secret(conn_id));
    let mut input = AeadInput::new(&AES_128_GCM);
    qhkdf_expand(&shared_key, b"key", input.key_mut());
    qhkdf_expand(&shared_key, b"iv", input.nonce_mut());
    input
}

fn client_handshake_secret(conn_id: u64) -> Vec<u8> {
    let prk = handshake_secret(conn_id);
    let mut out = vec![0u8; SHA256.output_len];
    qhkdf_expand(&prk, b"client hs", &mut out);
    out
}

pub fn qhkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(2 + 1 + 5 + out.len());
    info.put_u16::<BigEndian>(out.len() as u16);
    info.put_u8(5 + (label.len() as u8));
    info.extend_from_slice(b"QUIC ");
    info.extend_from_slice(&label);
    hkdf::expand(key, &info, out);
}

fn handshake_secret(conn_id: u64) -> SigningKey {
    let key = SigningKey::new(&SHA256, HANDSHAKE_SALT);
    let mut buf = Vec::with_capacity(8);
    buf.put_u64::<BigEndian>(conn_id);
    hkdf::extract(&key, &buf)
}

pub struct AeadInput {
    alg: &'static aead::Algorithm,
    input: Vec<u8>,
    split: usize,
}

impl AeadInput {
    pub fn new(alg: &'static aead::Algorithm) -> AeadInput {
        AeadInput {
            alg,
            input: vec![0; alg.key_len() + alg.nonce_len()],
            split: alg.key_len(),
        }
    }

    pub fn algorithm(&self) -> &aead::Algorithm {
        self.alg
    }

    pub fn key(&self) -> &[u8] {
        &self.input[..self.split]
    }

    pub fn key_mut(&mut self) -> &mut [u8] {
        &mut self.input[..self.split]
    }

    pub fn nonce(&self) -> &[u8] {
        &self.input[self.split..]
    }

    pub fn nonce_mut(&mut self) -> &mut [u8] {
        &mut self.input[self.split..]
    }
}

const HANDSHAKE_SALT: &[u8; 20] =
    b"\x9c\x10\x8f\x98\x52\x0a\x5c\x5c\x32\x96\x8e\x95\x0e\x8a\x2c\x5f\xe0\x6d\x6c\x38";

#[cfg(test)]
mod tests {
    #[test]
    fn test_handshake_client() {
        let conn_id = 0x8394c8f03e515708;
        let client_handshake_secret = super::client_handshake_secret(conn_id);
        let expected = b"\x83\x55\xf2\x1a\x3d\x8f\x83\xec\xb3\xd0\xf9\x71\x08\xd3\xf9\x5e\
                         \x0f\x65\xb4\xd8\xae\x88\xa0\x61\x1e\xe4\x9d\xb0\xb5\x23\x59\x1d";
        assert_eq!(&client_handshake_secret, expected);
        let input = super::client_handshake_input(conn_id);
        assert_eq!(input.key(), b"\x3a\xd0\x54\x2c\x4a\x85\x84\x74\x00\x63\x04\x9e\x3b\x3c\xaa\xb2");
        assert_eq!(input.nonce(), b"\xd1\xfd\x26\x05\x42\x75\x3a\xba\x38\x58\x9b\xad");
    }
}
