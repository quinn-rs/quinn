use bytes::{BigEndian, Buf, BufMut};

use std::fmt;
use std::io::Cursor;

use ring::{digest, hkdf, aead::{self, OpeningKey, SealingKey}};

pub use ring::aead::AES_128_GCM;
pub use ring::digest::SHA256;
pub use ring::hmac::SigningKey;

use super::{QuicError, QuicResult};
use types::{ConnectionId, Side};

pub enum Secret {
    Handshake(ConnectionId),
    For1Rtt(
        &'static aead::Algorithm,
        &'static digest::Algorithm,
        Vec<u8>,
        Vec<u8>,
    ),
}

impl Secret {
    pub fn tag_len(&self) -> usize {
        match *self {
            Secret::Handshake(_) => AES_128_GCM.tag_len(),
            Secret::For1Rtt(aead_alg, _, _, _) => aead_alg.tag_len(),
        }
    }

    pub fn build_key(&self, side: Side) -> PacketKey {
        match *self {
            Secret::Handshake(cid) => {
                let label = if side == Side::Client {
                    b"client hs"
                } else {
                    b"server hs"
                };
                PacketKey::new(
                    &AES_128_GCM,
                    &SHA256,
                    &expanded_handshake_secret(cid, label),
                )
            }
            Secret::For1Rtt(aead_alg, hash_alg, ref client_secret, ref server_secret) => {
                PacketKey::new(
                    aead_alg,
                    hash_alg,
                    match side {
                        Side::Client => client_secret,
                        Side::Server => server_secret,
                    },
                )
            }
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Secret::Handshake(cid) => write!(f, "Handshake({:?})", cid),
            Secret::For1Rtt(_, _, _, _) => write!(f, "For1Rtt(<secret>)"),
        }
    }
}

pub struct PacketKey {
    alg: &'static aead::Algorithm,
    data: Vec<u8>,
    split: usize,
}

impl PacketKey {
    pub fn new(
        aead_alg: &'static aead::Algorithm,
        hash_alg: &'static digest::Algorithm,
        secret: &[u8],
    ) -> Self {
        let mut res = Self {
            alg: aead_alg,
            data: vec![0; aead_alg.key_len() + aead_alg.nonce_len()],
            split: aead_alg.key_len(),
        };
        let secret_key = SigningKey::new(hash_alg, secret);
        qhkdf_expand(&secret_key, b"key", &mut res.data[..res.split]);
        qhkdf_expand(&secret_key, b"iv", &mut res.data[res.split..]);
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
    ) -> QuicResult<usize> {
        let key = SealingKey::new(self.alg, &self.data[..self.split])
            .map_err(|_| QuicError::EncryptError)?;
        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..self.alg.nonce_len()];
        self.write_nonce(number, nonce);
        aead::seal_in_place(&key, &*nonce, ad, in_out, out_suffix_capacity)
            .map_err(|_| QuicError::EncryptError)
    }

    pub fn decrypt<'a>(
        &self,
        number: u32,
        ad: &[u8],
        input: &'a mut [u8],
    ) -> QuicResult<&'a mut [u8]> {
        let key = OpeningKey::new(self.alg, &self.data[..self.split])
            .map_err(|_| QuicError::DecryptError)?;
        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..self.alg.nonce_len()];
        self.write_nonce(number, nonce);
        aead::open_in_place(&key, &*nonce, ad, 0, input).map_err(|_| QuicError::DecryptError)
    }
}

pub fn expanded_handshake_secret(conn_id: ConnectionId, label: &[u8]) -> Vec<u8> {
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

fn handshake_secret(conn_id: ConnectionId) -> SigningKey {
    let key = SigningKey::new(&SHA256, HANDSHAKE_SALT);
    let mut buf = Vec::with_capacity(8);
    buf.put_slice(&conn_id);
    hkdf::extract(&key, &buf)
}

const HANDSHAKE_SALT: &[u8; 20] =
    b"\x9c\x10\x8f\x98\x52\x0a\x5c\x5c\x32\x96\x8e\x95\x0e\x8a\x2c\x5f\xe0\x6d\x6c\x38";

#[cfg(test)]
mod tests {
    use types::ConnectionId;

    #[test]
    fn test_handshake_client() {
        let hs_cid = ConnectionId {
            len: 8,
            bytes: [
                0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
        };
        let client_handshake_secret = super::expanded_handshake_secret(hs_cid, b"client hs");
        let expected = b"\x83\x55\xf2\x1a\x3d\x8f\x83\xec\xb3\xd0\xf9\x71\x08\xd3\xf9\x5e\
                         \x0f\x65\xb4\xd8\xae\x88\xa0\x61\x1e\xe4\x9d\xb0\xb5\x23\x59\x1d";
        assert_eq!(&client_handshake_secret, expected);
        let input = super::PacketKey::new(
            &super::AES_128_GCM,
            &super::SHA256,
            &client_handshake_secret,
        );
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
