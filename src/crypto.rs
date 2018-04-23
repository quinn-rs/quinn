use bytes::{BigEndian, Buf, BufMut};

use std::io::Cursor;

use ring::{hkdf, aead::{self, AES_128_GCM, OpeningKey, SealingKey}, digest::SHA256,
           hmac::SigningKey};

pub struct PacketKey {
    alg: &'static aead::Algorithm,
    data: Vec<u8>,
    split: usize,
}

impl PacketKey {
    fn new(alg: &'static aead::Algorithm) -> Self {
        Self {
            alg,
            data: vec![0; alg.key_len() + alg.nonce_len()],
            split: alg.key_len(),
        }
    }

    pub fn for_client_handshake(conn_id: u64) -> Self {
        Self::build_handshake_key(conn_id, b"client hs")
    }

    pub fn for_server_handshake(conn_id: u64) -> Self {
        Self::build_handshake_key(conn_id, b"server hs")
    }

    fn build_handshake_key(conn_id: u64, label: &[u8]) -> Self {
        let shared_key = SigningKey::new(&SHA256, &expanded_handshake_secret(conn_id, label));
        let mut res = PacketKey::new(&AES_128_GCM);
        qhkdf_expand(&shared_key, b"key", &mut res.data[..res.split]);
        qhkdf_expand(&shared_key, b"iv", &mut res.data[res.split..]);
        res
    }

    pub fn algorithm(&self) -> &aead::Algorithm {
        self.alg
    }

    pub fn write_nonce(&self, number: u32, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.alg.nonce_len());
        let out = {
            let mut write = Cursor::new(out);
            write.put_u32::<BigEndian>(0);
            write.put_u64::<BigEndian>(number as u64);
            debug_assert_eq!(write.remaining(), 0);
            write.into_inner()
        };
        let iv = &self.data[self.split..];
        for i in 0..self.alg.nonce_len() {
            out[i] ^= iv[i];
        }
    }

    pub fn encrypt(
        &self,
        number: u32,
        ad: &[u8],
        in_out: &mut [u8],
        out_suffix_capacity: usize,
    ) -> usize {
        let key = SealingKey::new(self.alg, &self.data[..self.split]).unwrap();
        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..self.alg.nonce_len()];
        self.write_nonce(number, nonce);
        aead::seal_in_place(&key, &*nonce, ad, in_out, out_suffix_capacity).unwrap()
    }

    pub fn decrypt<'a>(&self, number: u32, ad: &[u8], input: &'a mut [u8]) -> &'a [u8] {
        let key = OpeningKey::new(self.alg, &self.data[..self.split]).unwrap();
        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..self.alg.nonce_len()];
        self.write_nonce(number, nonce);
        aead::open_in_place(&key, &*nonce, ad, 0, input).unwrap()
    }
}

fn expanded_handshake_secret(conn_id: u64, label: &[u8]) -> Vec<u8> {
    let prk = handshake_secret(conn_id);
    let mut out = vec![0u8; SHA256.output_len];
    qhkdf_expand(&prk, label, &mut out);
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

const HANDSHAKE_SALT: &[u8; 20] =
    b"\x9c\x10\x8f\x98\x52\x0a\x5c\x5c\x32\x96\x8e\x95\x0e\x8a\x2c\x5f\xe0\x6d\x6c\x38";

#[cfg(test)]
mod tests {
    #[test]
    fn test_handshake_client() {
        let conn_id = 0x8394c8f03e515708;
        let client_handshake_secret = super::expanded_handshake_secret(conn_id, b"client hs");
        let expected = b"\x83\x55\xf2\x1a\x3d\x8f\x83\xec\xb3\xd0\xf9\x71\x08\xd3\xf9\x5e\
                         \x0f\x65\xb4\xd8\xae\x88\xa0\x61\x1e\xe4\x9d\xb0\xb5\x23\x59\x1d";
        assert_eq!(&client_handshake_secret, expected);
        let input = super::PacketKey::for_client_handshake(conn_id);
        assert_eq!(
            &input.data[..input.split],
            b"\x3a\xd0\x54\x2c\x4a\x85\x84\x74\x00\x63\x04\x9e\x3b\x3c\xaa\xb2"
        );
        assert_eq!(
            &input.data[input.split..],
            b"\xd1\xfd\x26\x05\x42\x75\x3a\xba\x38\x58\x9b\xad"
        );
    }
}
