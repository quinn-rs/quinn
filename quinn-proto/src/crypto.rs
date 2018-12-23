use std::net::SocketAddrV6;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, str};

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::Aes128Ctr;
use bytes::{BigEndian, Buf, BufMut, ByteOrder, BytesMut};
use orion::hazardous::stream::chacha20;
use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::hmac::{self, SigningKey};
use rustls::quic::{ClientQuicExt, ServerQuicExt};
use rustls::ProtocolVersion;
pub use rustls::{Certificate, NoClientAuth, PrivateKey, TLSError};
pub use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};
use webpki::DNSNameRef;

use crate::coding::{BufExt, BufMutExt};
use crate::packet::{ConnectionId, AEAD_TAG_SIZE};
use crate::transport_parameters::TransportParameters;
use crate::{Side, MAX_CID_SIZE, MIN_CID_SIZE, RESET_TOKEN_SIZE};

pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

impl TlsSession {
    pub fn new_client(
        config: &Arc<ClientConfig>,
        hostname: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, ConnectError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(hostname)
            .map_err(|_| ConnectError::InvalidDnsName(hostname.into()))?;
        Ok(TlsSession::Client(ClientSession::new_quic(
            &config,
            pki_server_name,
            to_vec(Side::Client, params),
        )))
    }

    pub fn new_server(config: &Arc<ServerConfig>, params: &TransportParameters) -> TlsSession {
        TlsSession::Server(ServerSession::new_quic(
            config,
            to_vec(Side::Server, params),
        ))
    }

    pub fn get_sni_hostname(&self) -> Option<&str> {
        match *self {
            TlsSession::Client(_) => None,
            TlsSession::Server(ref session) => session.get_sni_hostname(),
        }
    }
}

impl Deref for TlsSession {
    type Target = dyn Session;
    fn deref(&self) -> &Self::Target {
        match *self {
            TlsSession::Client(ref session) => session,
            TlsSession::Server(ref session) => session,
        }
    }
}

impl DerefMut for TlsSession {
    fn deref_mut(&mut self) -> &mut (dyn Session + 'static) {
        match *self {
            TlsSession::Client(ref mut session) => session,
            TlsSession::Server(ref mut session) => session,
        }
    }
}

pub fn build_server_config() -> ServerConfig {
    let mut cfg = ServerConfig::new(NoClientAuth::new());
    cfg.versions = vec![ProtocolVersion::TLSv1_3];
    cfg
}

fn to_vec(side: Side, params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(side, &mut bytes);
    bytes
}

/// Value used in ACKs we transmit
pub const ACK_DELAY_EXPONENT: u8 = 3;
/// Magic value used to indicate 0-RTT support in NewSessionTicket
//pub const TLS_MAX_EARLY_DATA: u32 = 0xffff_ffff;

pub fn reset_token_for(key: &SigningKey, id: &ConnectionId) -> [u8; RESET_TOKEN_SIZE] {
    let signature = hmac::sign(key, id);
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    result.copy_from_slice(&signature.as_ref()[..RESET_TOKEN_SIZE]);
    result
}

pub struct Crypto {
    local_secret: Vec<u8>,
    local_iv: Vec<u8>,
    local_header_key: HeaderKey,
    sealing_key: aead::SealingKey,
    remote_secret: Vec<u8>,
    remote_iv: Vec<u8>,
    remote_header_key: HeaderKey,
    opening_key: aead::OpeningKey,
    digest: &'static digest::Algorithm,
}

impl Crypto {
    pub fn new_initial(id: &ConnectionId, side: Side) -> Self {
        let (digest, cipher) = (&digest::SHA256, &aead::AES_128_GCM);
        let (local_label, remote_label) = if side.is_client() {
            (b"client in", b"server in")
        } else {
            (b"server in", b"client in")
        };
        let hs_secret = initial_secret(id);
        let (local_secret, remote_secret) = (
            expanded_initial_secret(&hs_secret, local_label),
            expanded_initial_secret(&hs_secret, remote_label),
        );
        let (local_key, local_iv, local_header_key) = Self::get_keys(digest, cipher, &local_secret);
        let (remote_key, remote_iv, remote_header_key) =
            Self::get_keys(digest, cipher, &remote_secret);

        Self {
            local_secret,
            sealing_key: aead::SealingKey::new(cipher, &local_key).unwrap(),
            local_header_key,
            local_iv,
            remote_secret,
            opening_key: aead::OpeningKey::new(cipher, &remote_key).unwrap(),
            remote_header_key,
            remote_iv,
            digest,
        }
    }

    pub fn new_1rtt(tls: &TlsSession, side: Side) -> Self {
        let suite = tls.get_negotiated_ciphersuite().unwrap();
        let (cipher, digest) = (suite.get_aead_alg(), suite.get_hash());

        const SERVER_LABEL: &[u8] = b"EXPORTER-QUIC server 1rtt";
        const CLIENT_LABEL: &[u8] = b"EXPORTER-QUIC client 1rtt";

        let (local_label, remote_label) = if side.is_client() {
            (CLIENT_LABEL, SERVER_LABEL)
        } else {
            (SERVER_LABEL, CLIENT_LABEL)
        };

        let mut local_secret = vec![0; digest.output_len];
        tls.export_keying_material(&mut local_secret, local_label, None)
            .unwrap();
        let mut remote_secret = vec![0; digest.output_len];
        tls.export_keying_material(&mut remote_secret, remote_label, None)
            .unwrap();

        Self::generate_1rtt(digest, cipher, local_secret, remote_secret)
    }

    pub fn write_nonce(&self, iv: &[u8], number: u64, out: &mut [u8]) {
        let out = {
            let mut write = io::Cursor::new(out);
            write.put_u32_be(0);
            write.put_u64_be(number);
            debug_assert_eq!(write.remaining(), 0);
            write.into_inner()
        };
        debug_assert_eq!(out.len(), iv.len());
        for (out, inp) in out.iter_mut().zip(iv.iter()) {
            *out ^= inp;
        }
    }

    pub fn header_decrypt_key(&self) -> &HeaderKey {
        &self.remote_header_key
    }

    pub fn header_encrypt_key(&self) -> &HeaderKey {
        &self.local_header_key
    }

    pub fn encrypt(&self, packet: u64, buf: &mut Vec<u8>, header_len: usize) {
        let (cipher, iv, key) = (
            self.sealing_key.algorithm(),
            &self.local_iv,
            &self.sealing_key,
        );

        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..cipher.nonce_len()];
        self.write_nonce(&iv, packet, nonce);
        let tag = vec![0; cipher.tag_len()];
        buf.extend(tag);

        let (header, payload) = buf.split_at_mut(header_len);
        aead::seal_in_place(&key, &*nonce, header, payload, cipher.tag_len()).unwrap();
    }

    pub fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()> {
        if payload.len() < AEAD_TAG_SIZE {
            return Err(());
        }

        let (cipher, iv, key) = (
            self.opening_key.algorithm(),
            &self.remote_iv,
            &self.opening_key,
        );

        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..cipher.nonce_len()];
        self.write_nonce(&iv, packet, nonce);
        let payload_len = payload.len();

        aead::open_in_place(&key, &*nonce, header, 0, payload.as_mut()).map_err(|_| ())?;
        payload.split_off(payload_len - cipher.tag_len());
        Ok(())
    }

    pub fn update(&self) -> Crypto {
        const UPDATE_LABEL: &[u8] = b"traffic upd";

        let local_secret_key = SigningKey::new(self.digest, &self.local_secret);
        let mut new_local_secret = vec![0; self.digest.output_len];
        hkdf_expand(&local_secret_key, UPDATE_LABEL, &mut new_local_secret);

        let remote_secret_key = SigningKey::new(self.digest, &self.remote_secret);
        let mut new_remote_secret = vec![0; self.digest.output_len];
        hkdf_expand(&remote_secret_key, UPDATE_LABEL, &mut new_remote_secret);

        Self::generate_1rtt(
            self.digest,
            self.opening_key.algorithm(),
            new_local_secret,
            new_remote_secret,
        )
    }

    fn generate_1rtt(
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        local_secret: Vec<u8>,
        remote_secret: Vec<u8>,
    ) -> Crypto {
        let (local_key, local_iv, local_header_key) = Self::get_keys(digest, cipher, &local_secret);
        let (remote_key, remote_iv, remote_header_key) =
            Self::get_keys(digest, cipher, &remote_secret);

        Crypto {
            local_secret,
            sealing_key: aead::SealingKey::new(cipher, &local_key).unwrap(),
            local_header_key,
            local_iv,
            remote_secret,
            opening_key: aead::OpeningKey::new(cipher, &remote_key).unwrap(),
            remote_header_key,
            remote_iv,
            digest,
        }
    }

    fn get_keys(
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        secret: &[u8],
    ) -> (Vec<u8>, Vec<u8>, HeaderKey) {
        let secret_key = SigningKey::new(digest, &secret);

        let mut key = vec![0; cipher.key_len()];
        hkdf_expand(&secret_key, b"quic key", &mut key);

        let mut iv = vec![0; cipher.nonce_len()];
        hkdf_expand(&secret_key, b"quic iv", &mut iv);

        (key, iv, HeaderKey::from_aead(cipher, &secret_key))
    }
}

#[derive(Clone)]
pub struct ConnectionInfo {
    pub(crate) id: ConnectionId,
    pub(crate) remote: SocketAddrV6,
}

#[derive(Debug, Fail)]
pub enum ConnectError {
    #[fail(display = "invalid DNS name: {}", _0)]
    InvalidDnsName(String),
    #[fail(display = "TLS error: {}", _0)]
    Tls(TLSError),
}

impl From<TLSError> for ConnectError {
    fn from(x: TLSError) -> Self {
        ConnectError::Tls(x)
    }
}

#[derive(Debug, PartialEq)]
pub enum HeaderKey {
    AesCtr128([u8; 16]),
    ChaCha20(chacha20::SecretKey),
}

impl HeaderKey {
    fn from_aead(alg: &aead::Algorithm, secret_key: &SigningKey) -> Self {
        use self::HeaderKey::*;
        const LABEL: &[u8] = b"quic hp";
        if alg == &aead::AES_128_GCM {
            let mut pn = [0; 16];
            hkdf_expand(&secret_key, LABEL, &mut pn);
            AesCtr128(pn)
        } else if alg == &aead::CHACHA20_POLY1305 {
            let mut pn = [0; 32];
            hkdf_expand(&secret_key, LABEL, &mut pn);
            ChaCha20(
                chacha20::SecretKey::from_slice(&pn)
                    .expect("packet number key construction failed"),
            )
        } else {
            unimplemented!()
        }
    }

    pub fn sample_size(&self) -> usize {
        use self::HeaderKey::*;
        match *self {
            AesCtr128(_) | ChaCha20(_) => 16,
        }
    }

    pub fn decrypt(&self, sample: &[u8], in_out: &mut [u8]) {
        use self::HeaderKey::*;
        match self {
            AesCtr128(key) => {
                let key = GenericArray::from_slice(key);
                let nonce = GenericArray::from_slice(sample);
                Aes128Ctr::new(key, nonce).apply_keystream(in_out)
            }
            ChaCha20(key) => {
                let counter = BigEndian::read_u32(&sample[..4]);
                let nonce =
                    chacha20::Nonce::from_slice(&sample[4..]).expect("failed to generate nonce");
                let mut input = [0; 4];
                (&mut input[..in_out.len()]).copy_from_slice(in_out);
                chacha20::decrypt(key, &nonce, counter, &input[..in_out.len()], in_out).unwrap();
            }
        }
    }

    pub fn encrypt(&self, sample: &[u8], in_out: &mut [u8]) {
        use self::HeaderKey::*;
        match self {
            AesCtr128(key) => {
                let key = GenericArray::from_slice(key);
                let nonce = GenericArray::from_slice(sample);
                Aes128Ctr::new(key, nonce).apply_keystream(in_out)
            }
            ChaCha20(key) => {
                let counter = BigEndian::read_u32(&sample[..4]);
                let nonce =
                    chacha20::Nonce::from_slice(&sample[4..]).expect("failed to generate nonce");
                let mut input = [0; 4];
                (&mut input[..in_out.len()]).copy_from_slice(in_out);
                chacha20::encrypt(key, &nonce, counter, &input[..in_out.len()], in_out).unwrap();
            }
        }
    }
}

pub fn expanded_initial_secret(prk: &SigningKey, label: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; digest::SHA256.output_len];
    hkdf_expand(prk, label, &mut out);
    out
}

pub fn hkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(2 + 1 + 5 + out.len());
    info.put_u16_be(out.len() as u16);
    const BASE_LABEL: &[u8] = b"tls13 ";
    info.put_u8((BASE_LABEL.len() + label.len()) as u8);
    info.extend_from_slice(BASE_LABEL);
    info.extend_from_slice(&label);
    info.put_u8(0);
    hkdf::expand(key, &info, out);
}

fn initial_secret(conn_id: &ConnectionId) -> SigningKey {
    let key = SigningKey::new(&digest::SHA256, &INITIAL_SALT);
    let mut buf = Vec::with_capacity(8);
    buf.put_slice(conn_id);
    hkdf::extract(&key, &buf)
}

const INITIAL_SALT: [u8; 20] = [
    0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae,
    0x48, 0x5e, 0x09, 0xa0,
];

pub struct TokenKey {
    // TODO: Use AEAD to hide token details from clients for better stability guarantees:
    // - ticket consists of (random, aead-encrypted-data)
    // - AEAD encryption key is HKDF(master-key, random)
    // - AEAD nonce is always set to 0
    // in other words, for each ticket, use different key derived from random using HKDF
    inner: SigningKey,
}

impl TokenKey {
    pub const SIZE: usize = 64;

    pub fn new(key: &[u8; Self::SIZE]) -> Self {
        let inner = SigningKey::new(&digest::SHA512_256, key);
        Self { inner }
    }

    pub(crate) fn generate(
        &self,
        address: &SocketAddrV6,
        dst_cid: &ConnectionId,
        issued: SystemTime,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write(dst_cid.len() as u8);
        buf.put_slice(dst_cid);
        buf.write::<u64>(
            issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );
        let signature_pos = buf.len();
        buf.put_slice(&address.ip().octets());
        buf.write(address.port());
        let signature = hmac::sign(&self.inner, &buf);
        // No reason to actually encode the IP in the token, since we always have the remote addr for an incoming packet.
        buf.truncate(signature_pos);
        buf.extend_from_slice(signature.as_ref());
        buf
    }

    pub(crate) fn check(
        &self,
        address: &SocketAddrV6,
        data: &[u8],
    ) -> Option<(ConnectionId, SystemTime)> {
        let mut reader = io::Cursor::new(data);
        let dst_cid_len = reader.get::<u8>().ok()? as usize;
        if dst_cid_len > reader.remaining()
            || dst_cid_len != 0 && (dst_cid_len < MIN_CID_SIZE || dst_cid_len > MAX_CID_SIZE)
        {
            return None;
        }
        let dst_cid = ConnectionId::new(&data[1..=dst_cid_len]);
        reader.advance(dst_cid_len);
        let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().ok()?, 0);
        let signature_start = reader.position() as usize;

        let mut buf = Vec::new();
        buf.put_slice(&data[0..signature_start]);
        buf.put_slice(&address.ip().octets());
        buf.write(address.port());

        hmac::verify_with_own_key(&self.inner, &buf, &data[signature_start..]).ok()?;
        Some((dst_cid, issued))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{self, RngCore};

    #[test]
    fn handshake_crypto_roundtrip() {
        let conn = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let client = Crypto::new_initial(&conn, Side::Client);
        let server = Crypto::new_initial(&conn, Side::Server);

        let mut buf = b"headerpayload".to_vec();
        client.encrypt(0, &mut buf, 6);

        let mut header = BytesMut::from(buf);
        let mut payload = header.split_off(6);
        server.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&*payload, b"payload");
    }

    #[test]
    fn key_derivation() {
        // Test vectors generated by ngtcp2
        let id = ConnectionId::new(&[0x7d, 0xdc, 0x42, 0x90, 0xc4, 0xe7, 0xd2, 0x04]);
        let digest = &digest::SHA256;
        let cipher = &aead::AES_128_GCM;
        let initial_secret = initial_secret(&id);
        let client_secret = expanded_initial_secret(&initial_secret, b"client in");
        assert_eq!(
            &client_secret[..],
            [
                0xf8, 0x86, 0x16, 0x78, 0x10, 0x56, 0xa6, 0xac, 0x00, 0x70, 0x87, 0xd1, 0x21, 0xce,
                0x15, 0x8e, 0xa8, 0xc7, 0x70, 0xa1, 0xe6, 0x28, 0x99, 0x61, 0x6c, 0xde, 0x50, 0x7b,
                0xb6, 0xd6, 0x0e, 0x08,
            ]
        );
        let (client_key, client_iv, client_header_key) =
            Crypto::get_keys(digest, cipher, &client_secret);
        assert_eq!(
            &client_key[..],
            [
                0x1b, 0x7e, 0x28, 0x58, 0x10, 0x18, 0x33, 0xce, 0x98, 0x9a, 0x77, 0x25, 0x4f, 0x3f,
                0xaa, 0x62
            ]
        );
        assert_eq!(
            &client_iv[..],
            [0x01, 0xa4, 0x1a, 0xa7, 0x3c, 0x43, 0x29, 0x8d, 0xcb, 0x38, 0xbc, 0xb6]
        );
        assert_eq!(
            client_header_key,
            HeaderKey::AesCtr128([
                0x9a, 0x85, 0x42, 0xef, 0x39, 0x90, 0x38, 0xab, 0xa6, 0x6e, 0xf1, 0x33, 0x38, 0x09,
                0xfc, 0x5b
            ])
        );

        let server_secret = expanded_initial_secret(&initial_secret, b"server in");
        assert_eq!(
            &server_secret[..],
            [
                0x5e, 0xac, 0x74, 0x74, 0x78, 0x72, 0xfe, 0x6d, 0x9e, 0xcb, 0xac, 0x75, 0xdf, 0x87,
                0xab, 0xc4, 0xbb, 0x43, 0x74, 0xc8, 0xe6, 0x63, 0x65, 0x49, 0xda, 0x71, 0x8b, 0x9f,
                0x72, 0x2f, 0x0d, 0x6a
            ]
        );
        let (server_key, server_iv, server_header_key) =
            Crypto::get_keys(digest, cipher, &server_secret);
        assert_eq!(
            &server_key[..],
            [
                0xf3, 0x67, 0xa4, 0xc1, 0x2f, 0x77, 0x26, 0xd9, 0x2c, 0xce, 0xa2, 0x1b, 0x93, 0x39,
                0xa8, 0x71
            ]
        );
        assert_eq!(
            &server_iv[..],
            [0x44, 0x82, 0x14, 0xc9, 0x66, 0x31, 0x4d, 0x8f, 0x54, 0x0b, 0x7b, 0x43]
        );
        assert_eq!(
            server_header_key,
            HeaderKey::AesCtr128([
                0x92, 0x2b, 0x11, 0x3f, 0x1b, 0x2a, 0x81, 0x5f, 0x08, 0x42, 0x54, 0xf9, 0x81, 0xa0,
                0xb0, 0x97
            ])
        );
    }

    #[test]
    fn token_sanity() {
        use std::net::Ipv6Addr;

        let mut key = [0; TokenKey::SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        let key = TokenKey::new(&key);
        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4433, 0, 0);
        let dst_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let issued = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost
        let token = key.generate(&addr, &dst_cid, issued);
        let (dst_cid2, issued2) = key.check(&addr, &token).expect("token didn't validate");
        assert_eq!(dst_cid, dst_cid2);
        assert_eq!(issued, issued2);
    }

    #[test]
    fn key_derivation_1rtt() {
        // Pre-update test vectors generated by ngtcp2
        let digest = &digest::SHA256;
        let cipher = &aead::AES_128_GCM;
        let onertt = Crypto::generate_1rtt(
            digest,
            cipher,
            [
                // Local
                0xb8, 0x76, 0x77, 0x08, 0xf8, 0x77, 0x23, 0x58, 0xa6, 0xea, 0x9f, 0xc4, 0x3e, 0x4a,
                0xdd, 0x2c, 0x96, 0x1b, 0x3f, 0x52, 0x87, 0xa6, 0xd1, 0x46, 0x7e, 0xe0, 0xae, 0xab,
                0x33, 0x72, 0x4d, 0xbf,
            ]
            .to_vec(),
            [
                // Remote
                0x42, 0xdc, 0x97, 0x21, 0x40, 0xe0, 0xf2, 0xe3, 0x98, 0x45, 0xb7, 0x67, 0x61, 0x34,
                0x39, 0xdc, 0x67, 0x58, 0xca, 0x43, 0x25, 0x9b, 0x87, 0x85, 0x06, 0x82, 0x4e, 0xb1,
                0xe4, 0x38, 0xd8, 0x55,
            ]
            .to_vec(),
        );

        assert_eq!(
            &onertt.local_iv[..],
            [0xd5, 0x1b, 0x16, 0x6a, 0x3e, 0xc4, 0x6f, 0x7e, 0x5f, 0x93, 0x27, 0x15]
        );
        assert_eq!(
            onertt.local_header_key,
            HeaderKey::AesCtr128([
                0x1b, 0xdc, 0x5b, 0xe9, 0x80, 0xd7, 0xb9, 0xb5, 0x0e, 0x78, 0x51, 0xcf, 0xb4, 0x71,
                0xa8, 0x4d,
            ])
        );

        assert_eq!(
            &onertt.remote_iv[..],
            [0x03, 0xda, 0x92, 0xa0, 0x91, 0x95, 0xe4, 0xbf, 0x87, 0x98, 0xd3, 0x78]
        );
        assert_eq!(
            onertt.remote_header_key,
            HeaderKey::AesCtr128([
                0x1a, 0x05, 0x0f, 0xc6, 0x78, 0xc6, 0xea, 0x30, 0x88, 0x17, 0x05, 0x90, 0x2d, 0x85,
                0x23, 0x23
            ])
        );

        let updated_onertt = onertt.update();

        assert_eq!(
            &updated_onertt.local_iv[..],
            [233, 47, 171, 44, 133, 77, 133, 109, 110, 95, 31, 254]
        );
        assert_eq!(
            updated_onertt.local_header_key,
            HeaderKey::AesCtr128([
                20, 96, 7, 204, 167, 174, 79, 250, 138, 213, 45, 234, 62, 176, 57, 139
            ])
        );

        assert_eq!(
            &updated_onertt.remote_iv[..],
            [182, 36, 161, 179, 178, 62, 80, 216, 255, 14, 228, 172]
        );
        assert_eq!(
            updated_onertt.remote_header_key,
            HeaderKey::AesCtr128([
                9, 9, 81, 40, 9, 32, 28, 118, 137, 189, 99, 193, 216, 85, 165, 228
            ])
        );
    }
}
