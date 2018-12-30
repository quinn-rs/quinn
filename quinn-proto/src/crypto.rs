use std::net::{IpAddr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, str};

use aes::{Aes128, Aes256};
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Ecb};
use bytes::{BigEndian, Buf, BufMut, ByteOrder, BytesMut};
use orion::hazardous::stream::chacha20;
use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::hmac::{self, SigningKey};
pub use rustls::quic::Secrets;
use rustls::quic::{ClientQuicExt, ServerQuicExt};
use rustls::ProtocolVersion;
pub use rustls::{Certificate, NoClientAuth, PrivateKey, TLSError};
pub use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};
use webpki::DNSNameRef;

use crate::coding::{BufExt, BufMutExt};
use crate::packet::{ConnectionId, PacketNumber, LONG_HEADER_FORM};
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
    sealing_key: aead::SealingKey,
    remote_secret: Vec<u8>,
    remote_iv: Vec<u8>,
    opening_key: aead::OpeningKey,
    digest: &'static digest::Algorithm,
}

impl Crypto {
    pub fn new_initial(id: &ConnectionId, side: Side) -> Self {
        let (digest, cipher) = (&digest::SHA256, &aead::AES_128_GCM);
        const CLIENT_LABEL: &[u8] = b"client in";
        const SERVER_LABEL: &[u8] = b"server in";
        let hs_secret = initial_secret(id);
        let secrets = Secrets {
            client: expanded_initial_secret(&hs_secret, CLIENT_LABEL),
            server: expanded_initial_secret(&hs_secret, SERVER_LABEL),
        };
        Self::new(side, digest, cipher, secrets)
    }

    pub fn new(
        side: Side,
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        secrets: Secrets,
    ) -> Self {
        let (local_secret, remote_secret) = if side.is_client() {
            (secrets.client, secrets.server)
        } else {
            (secrets.server, secrets.client)
        };
        let (local_key, local_iv) = Self::get_keys(digest, cipher, &local_secret);
        let (remote_key, remote_iv) = Self::get_keys(digest, cipher, &remote_secret);

        Crypto {
            local_secret,
            sealing_key: aead::SealingKey::new(cipher, &local_key).unwrap(),
            local_iv,
            remote_secret,
            opening_key: aead::OpeningKey::new(cipher, &remote_key).unwrap(),
            remote_iv,
            digest,
        }
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
        if payload.len() < self.tag_len() {
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

    fn get_keys(
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        secret: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let secret_key = SigningKey::new(digest, &secret);

        let mut key = vec![0; cipher.key_len()];
        hkdf_expand(&secret_key, b"quic key", &mut key);

        let mut iv = vec![0; cipher.nonce_len()];
        hkdf_expand(&secret_key, b"quic iv", &mut iv);

        (key, iv)
    }

    pub fn header_crypto(&self) -> HeaderCrypto {
        let local = SigningKey::new(self.digest, &self.local_secret);
        let remote = SigningKey::new(self.digest, &self.remote_secret);
        let cipher = self.sealing_key.algorithm();
        HeaderCrypto {
            local: HeaderKey::from_aead(cipher, &local),
            remote: HeaderKey::from_aead(cipher, &remote),
        }
    }

    pub fn update(&self, side: Side, tls: &TlsSession) -> Self {
        let (client_secret, server_secret) = match side {
            Side::Client => (&self.local_secret, &self.remote_secret),
            Side::Server => (&self.remote_secret, &self.local_secret),
        };
        let secrets = tls.update_secrets(client_secret, server_secret);
        let suite = tls.get_negotiated_ciphersuite().unwrap();
        Self::new(side, suite.get_hash(), suite.get_aead_alg(), secrets)
    }

    pub fn tag_len(&self) -> usize {
        self.sealing_key.algorithm().tag_len()
    }
}

pub struct HeaderCrypto {
    local: HeaderKey,
    remote: HeaderKey,
}

impl HeaderCrypto {
    pub fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.remote.mask(&sample[0..self.sample_size()]);
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

    pub fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.local.mask(&sample[0..self.sample_size()]);
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

    pub fn sample_size(&self) -> usize {
        self.local.sample_size()
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
enum HeaderKey {
    AesEcb128([u8; 16]),
    AesEcb256([u8; 32]),
    ChaCha20(chacha20::SecretKey),
}

impl HeaderKey {
    fn from_aead(alg: &aead::Algorithm, secret_key: &SigningKey) -> Self {
        use self::HeaderKey::*;
        const LABEL: &[u8] = b"quic hp";
        if alg == &aead::AES_128_GCM {
            let mut pn = [0; 16];
            hkdf_expand(&secret_key, LABEL, &mut pn);
            AesEcb128(pn)
        } else if alg == &aead::AES_256_GCM {
            let mut pn = [0; 32];
            hkdf_expand(&secret_key, LABEL, &mut pn);
            AesEcb256(pn)
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

    fn sample_size(&self) -> usize {
        use self::HeaderKey::*;
        match *self {
            AesEcb128(_) | AesEcb256(_) | ChaCha20(_) => 16,
        }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        use self::HeaderKey::*;
        match self {
            AesEcb128(key) => {
                let mut cipher = Ecb::<Aes128, ZeroPadding>::new_varkey(key).unwrap();
                let mut buf = [0; 16];
                buf.copy_from_slice(sample);
                cipher.encrypt_nopad(&mut buf).unwrap();
                [buf[0], buf[1], buf[2], buf[3], buf[4]]
            }
            AesEcb256(key) => {
                let mut cipher = Ecb::<Aes256, ZeroPadding>::new_varkey(key).unwrap();
                let mut buf = [0; 16];
                buf.copy_from_slice(sample);
                cipher.encrypt_nopad(&mut buf).unwrap();
                [buf[0], buf[1], buf[2], buf[3], buf[4]]
            }
            ChaCha20(key) => {
                let mut buf = [0; 5];
                let counter = BigEndian::read_u32(&sample[..4]);
                let nonce =
                    chacha20::Nonce::from_slice(&sample[4..]).expect("failed to generate nonce");
                chacha20::decrypt(key, &nonce, counter, &[0; 5], &mut buf).unwrap();
                buf
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
        address: &SocketAddr,
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
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());
        let signature = hmac::sign(&self.inner, &buf);
        // No reason to actually encode the IP in the token, since we always have the remote addr for an incoming packet.
        buf.truncate(signature_pos);
        buf.extend_from_slice(signature.as_ref());
        buf
    }

    pub(crate) fn check(
        &self,
        address: &SocketAddr,
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
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
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
        let (client_key, client_iv) = Crypto::get_keys(digest, cipher, &client_secret);
        let client_header_key =
            HeaderKey::from_aead(cipher, &SigningKey::new(digest, &client_secret));
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
            HeaderKey::AesEcb128([
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
        let (server_key, server_iv) = Crypto::get_keys(digest, cipher, &server_secret);
        let server_header_key =
            HeaderKey::from_aead(cipher, &SigningKey::new(digest, &server_secret));
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
            HeaderKey::AesEcb128([
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
        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
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
        let onertt = Crypto::new(
            Side::Client,
            digest,
            cipher,
            Secrets {
                client: vec![
                    0xb8, 0x76, 0x77, 0x08, 0xf8, 0x77, 0x23, 0x58, 0xa6, 0xea, 0x9f, 0xc4, 0x3e,
                    0x4a, 0xdd, 0x2c, 0x96, 0x1b, 0x3f, 0x52, 0x87, 0xa6, 0xd1, 0x46, 0x7e, 0xe0,
                    0xae, 0xab, 0x33, 0x72, 0x4d, 0xbf,
                ],
                server: vec![
                    0x42, 0xdc, 0x97, 0x21, 0x40, 0xe0, 0xf2, 0xe3, 0x98, 0x45, 0xb7, 0x67, 0x61,
                    0x34, 0x39, 0xdc, 0x67, 0x58, 0xca, 0x43, 0x25, 0x9b, 0x87, 0x85, 0x06, 0x82,
                    0x4e, 0xb1, 0xe4, 0x38, 0xd8, 0x55,
                ],
            },
        );

        let header = onertt.header_crypto();

        assert_eq!(
            &onertt.local_iv[..],
            [0xd5, 0x1b, 0x16, 0x6a, 0x3e, 0xc4, 0x6f, 0x7e, 0x5f, 0x93, 0x27, 0x15]
        );
        assert_eq!(
            header.local,
            HeaderKey::AesEcb128([
                0x1b, 0xdc, 0x5b, 0xe9, 0x80, 0xd7, 0xb9, 0xb5, 0x0e, 0x78, 0x51, 0xcf, 0xb4, 0x71,
                0xa8, 0x4d,
            ])
        );

        assert_eq!(
            &onertt.remote_iv[..],
            [0x03, 0xda, 0x92, 0xa0, 0x91, 0x95, 0xe4, 0xbf, 0x87, 0x98, 0xd3, 0x78]
        );
        assert_eq!(
            header.remote,
            HeaderKey::AesEcb128([
                0x1a, 0x05, 0x0f, 0xc6, 0x78, 0xc6, 0xea, 0x30, 0x88, 0x17, 0x05, 0x90, 0x2d, 0x85,
                0x23, 0x23
            ])
        );
    }
}
