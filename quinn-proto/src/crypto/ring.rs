use bytes::{buf::ext::BufMutExt, BufMut, BytesMut};
use ring::{aead, hkdf, hmac};

use crate::{
    config::ConfigError,
    crypto,
    crypto::KeyPair,
    packet::{PacketNumber, LONG_HEADER_FORM},
    shared::ConnectionId,
    Side,
};

/// Keys for encrypting and decrypting packet payloads
pub struct PacketKey {
    iv: Iv,
    key: aead::LessSafeKey,
}

impl PacketKey {
    pub(crate) fn new(cipher: &'static aead::Algorithm, secret: &hkdf::Prk) -> Self {
        Self {
            key: aead::LessSafeKey::new(hkdf_expand(secret, b"quic key", cipher)),
            iv: hkdf_expand(secret, b"quic iv", IvLen),
        }
    }

    fn write_nonce(&self, iv: &Iv, number: u64, out: &mut [u8]) {
        let mut write = out.limit(out.len());
        write.put_u32(0);
        write.put_u64(number);
        debug_assert_eq!(write.remaining_mut(), 0);
        debug_assert_eq!(out.len(), iv.len());
        for (out, inp) in out.iter_mut().zip(iv.0.iter()) {
            *out ^= inp;
        }
    }
}

#[derive(Default)]
struct Iv([u8; aead::NONCE_LEN]);

impl Iv {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut iv = Iv::default();
        okm.fill(&mut iv.0[..]).unwrap();
        iv
    }
}

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let mut nonce_buf = [0u8; aead::NONCE_LEN];
        let nonce = &mut nonce_buf[..self.key.algorithm().nonce_len()];
        self.write_nonce(&self.iv, packet, nonce);

        let (header, payload) = buf.split_at_mut(header_len);
        let (payload, tag) = payload.split_at_mut(payload.len() - self.key.algorithm().tag_len());
        let header = aead::Aad::from(header);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).unwrap();
        let tagged = self
            .key
            .seal_in_place_separate_tag(nonce, header, payload)
            .unwrap();

        tag.copy_from_slice(tagged.as_ref());
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()> {
        if payload.len() < self.tag_len() {
            return Err(());
        }

        let mut nonce_buf = [0u8; aead::NONCE_LEN];
        let nonce = &mut nonce_buf[..self.key.algorithm().nonce_len()];
        self.write_nonce(&self.iv, packet, nonce);
        let payload_len = payload.len();

        let header = aead::Aad::from(header);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).unwrap();
        self.key
            .open_in_place(nonce, header, payload.as_mut())
            .map_err(|_| ())?;
        payload.truncate(payload_len - self.key.algorithm().tag_len());
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }
}

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
        if header[0] & 0x80 == 0x80 {
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

fn header_key_from_secret(
    aead: &aead::Algorithm,
    secret_key: &hkdf::Prk,
) -> aead::quic::HeaderProtectionKey {
    const LABEL: &[u8] = b"quic hp";
    if aead == &aead::AES_128_GCM {
        hkdf_expand(&secret_key, LABEL, &aead::quic::AES_128)
    } else if aead == &aead::AES_256_GCM {
        hkdf_expand(&secret_key, LABEL, &aead::quic::AES_256)
    } else if aead == &aead::CHACHA20_POLY1305 {
        hkdf_expand(&secret_key, LABEL, &aead::quic::CHACHA20)
    } else {
        unimplemented!()
    }
}

pub(crate) fn initial_keys(
    id: &ConnectionId,
    side: Side,
) -> (KeyPair<aead::quic::HeaderProtectionKey>, KeyPair<PacketKey>) {
    const CLIENT_LABEL: &[u8] = b"client in";
    const SERVER_LABEL: &[u8] = b"server in";
    let hs_secret = initial_secret(id);

    let client = expanded_initial_secret(&hs_secret, CLIENT_LABEL);
    let server = expanded_initial_secret(&hs_secret, SERVER_LABEL);
    let (local, remote) = match side {
        Side::Client => (client, server),
        Side::Server => (server, client),
    };
    generate_key_pairs(&aead::AES_128_GCM, &local, &remote)
}

fn expanded_initial_secret(prk: &hkdf::Prk, label: &[u8]) -> hkdf::Prk {
    hkdf_expand(prk, label, hkdf::HKDF_SHA256)
}

fn hkdf_expand<L, K>(key: &hkdf::Prk, label: &[u8], len: L) -> K
where
    L: hkdf::KeyType,
    K: for<'b> From<hkdf::Okm<'b, L>>,
{
    let out_len = (len.len() as u16).to_be_bytes();
    const BASE_LABEL: &[u8] = b"tls13 ";
    let label_len = (BASE_LABEL.len() + label.len()) as u8;
    let info = [&out_len, &[label_len][..], BASE_LABEL, label, &[0][..]];
    key.expand(&info, len).unwrap().into()
}

fn initial_secret(conn_id: &ConnectionId) -> hkdf::Prk {
    hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT).extract(conn_id)
}

const INITIAL_SALT: [u8; 20] = [
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02,
];

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

pub(crate) fn generate_key_pairs(
    aead: &'static aead::Algorithm,
    local_secret: &hkdf::Prk,
    remote_secret: &hkdf::Prk,
) -> (KeyPair<aead::quic::HeaderProtectionKey>, KeyPair<PacketKey>) {
    let (local_header, local_packet) = generate_keys(aead, local_secret);
    let (remote_header, remote_packet) = generate_keys(aead, remote_secret);
    (
        KeyPair {
            local: local_header,
            remote: remote_header,
        },
        KeyPair {
            local: local_packet,
            remote: remote_packet,
        },
    )
}

pub(crate) fn generate_keys(
    aead: &'static aead::Algorithm,
    secret: &hkdf::Prk,
) -> (aead::quic::HeaderProtectionKey, PacketKey) {
    (
        header_key_from_secret(aead, secret),
        PacketKey::new(aead, secret),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::{HeaderKey, PacketKey as _},
        MAX_CID_SIZE,
    };
    use hex_literal::hex;

    #[test]
    fn handshake_crypto_roundtrip() {
        let conn = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let (_, client) = initial_keys(&conn, Side::Client);
        let (_, server) = initial_keys(&conn, Side::Server);

        let mut buf = b"headerpayload".to_vec();
        buf.resize(buf.len() + client.local.tag_len(), 0);
        client.local.encrypt(0, &mut buf, 6);

        let mut header = BytesMut::from(buf.as_slice());
        let mut payload = header.split_off(6);
        server.remote.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&*payload, b"payload");
    }

    #[test]
    fn key_derivation() {
        let id = ConnectionId::new(&hex!("8394c8f03e515708"));
        let cipher = &aead::AES_128_GCM;
        let initial_secret = initial_secret(&id);
        println!();

        // Key secrets are opaque, so we cannot check them
        let client_secret = expanded_initial_secret(&initial_secret, b"client in");
        let key = PacketKey::new(cipher, &client_secret);
        assert_eq!(&key.iv.0[..], hex!("8681359410a70bb9c92f0420"));

        let server_secret = expanded_initial_secret(&initial_secret, b"server in");
        let key = PacketKey::new(cipher, &server_secret);
        assert_eq!(&key.iv.0[..], hex!("5e5ae651fd1e8495af13508b"));
    }

    #[test]
    fn packet_protection() {
        let id = ConnectionId::new(&hex!("8394c8f03e515708"));
        let (server_header, server) = initial_keys(&id, Side::Server);
        let (client_header, client) = initial_keys(&id, Side::Client);
        let plaintext = hex!(
            "c1ff00001205f067a5502a4262b50040740000
             0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988
             cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d
             89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002
             0304"
        );
        const HEADER_LEN: usize = 19;
        let protected = hex!(
            "caff00001205f067a5502a4262b50040749256
             8d33da8c3cae26ced25553d671d872ec 84c61c11b81ca2a29eecf7637a1aa920
             638e8bc0263f4554c831ee9ab2e19425 e08d1fa53f38581e420ba88f3667968a
             205573d4532422c8934a9bd8786209db 16515d8e2a3443b707c7e7e1f79b565b
             9a015c2b0ae33a485cfa0df39e8adcd8 2756"
        );
        let mut packet = plaintext.to_vec();
        packet.resize(packet.len() + server.local.tag_len(), 0);
        server.local.encrypt(0, &mut packet, HEADER_LEN);
        server_header.local.encrypt(17, &mut packet);
        assert_eq!(&packet[..], &protected[..]);
        client_header.remote.decrypt(17, &mut packet);
        let (header, payload) = packet.split_at(HEADER_LEN);
        assert_eq!(header, &plaintext[0..HEADER_LEN]);
        let mut payload = BytesMut::from(payload);
        client.remote.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&payload, &plaintext[HEADER_LEN..]);
    }

    #[test]
    fn key_derivation_1rtt() {
        // Pre-update test vectors generated by ngtcp2
        let client_secret = hkdf::Prk::new_less_safe(
            hkdf::HKDF_SHA256,
            &[
                0xb8, 0x76, 0x77, 0x08, 0xf8, 0x77, 0x23, 0x58, 0xa6, 0xea, 0x9f, 0xc4, 0x3e, 0x4a,
                0xdd, 0x2c, 0x96, 0x1b, 0x3f, 0x52, 0x87, 0xa6, 0xd1, 0x46, 0x7e, 0xe0, 0xae, 0xab,
                0x33, 0x72, 0x4d, 0xbf,
            ],
        );

        let server_secret = hkdf::Prk::new_less_safe(
            hkdf::HKDF_SHA256,
            &[
                0x42, 0xdc, 0x97, 0x21, 0x40, 0xe0, 0xf2, 0xe3, 0x98, 0x45, 0xb7, 0x67, 0x61, 0x34,
                0x39, 0xdc, 0x67, 0x58, 0xca, 0x43, 0x25, 0x9b, 0x87, 0x85, 0x06, 0x82, 0x4e, 0xb1,
                0xe4, 0x38, 0xd8, 0x55,
            ],
        );

        let cipher = &aead::AES_128_GCM;
        let onertt_client = PacketKey::new(cipher, &client_secret);
        let onertt_server = PacketKey::new(cipher, &server_secret);

        assert_eq!(
            &onertt_client.iv.0[..],
            [0xd5, 0x1b, 0x16, 0x6a, 0x3e, 0xc4, 0x6f, 0x7e, 0x5f, 0x93, 0x27, 0x15]
        );
        assert_eq!(
            &onertt_server.iv.0[..],
            [0x03, 0xda, 0x92, 0xa0, 0x91, 0x95, 0xe4, 0xbf, 0x87, 0x98, 0xd3, 0x78]
        );
    }
}
