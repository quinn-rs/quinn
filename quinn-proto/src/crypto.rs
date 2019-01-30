use std::net::{IpAddr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, str};

use bytes::{Buf, BufMut, BytesMut};
use ring::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};
use ring::aead::{self, Aad, Nonce};
use ring::digest;
use ring::hkdf;
use ring::hmac::{self, SigningKey};
use rustls::quic::{ClientQuicExt, Secrets, ServerQuicExt};
use rustls::ProtocolVersion;
pub use rustls::{Certificate, NoClientAuth, PrivateKey, TLSError};
pub use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};
use webpki::DNSNameRef;

use crate::coding::{BufExt, BufMutExt};
use crate::packet::{ConnectionId, PacketNumber, LONG_HEADER_FORM};
use crate::transport_parameters::TransportParameters;
use crate::{ConnectError, Side, TransportError, MAX_CID_SIZE, MIN_CID_SIZE, RESET_TOKEN_SIZE};

pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

impl TlsSession {
    fn side(&self) -> Side {
        match self {
            TlsSession::Client(_) => Side::Client,
            TlsSession::Server(_) => Side::Server,
        }
    }
}

impl CryptoSession for TlsSession {
    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    fn early_crypto(&self) -> Option<Crypto> {
        self.get_early_secret()
            .map(|secret| Crypto::new_0rtt(secret))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self {
            TlsSession::Client(session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(session) => session.is_handshaking(),
            TlsSession::Server(session) => session.is_handshaking(),
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.get_alert() {
                TransportError::crypto(alert.get_u8(), e.to_string())
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {}", e))
            }
        })
    }

    fn sni_hostname(&self) -> Option<&str> {
        match self {
            TlsSession::Client(_) => None,
            TlsSession::Server(session) => session.get_sni_hostname(),
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.get_quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Crypto> {
        let secrets = self.write_hs(buf)?;
        let suite = self
            .get_negotiated_ciphersuite()
            .expect("should not get secrets without cipher suite");
        Some(Crypto::new(
            self.side(),
            suite.get_hash(),
            suite.get_aead_alg(),
            secrets,
        ))
    }
}

pub trait CryptoSession {
    fn alpn_protocol(&self) -> Option<&[u8]>;
    fn early_crypto(&self) -> Option<Crypto>;
    fn early_data_accepted(&self) -> Option<bool>;
    fn is_handshaking(&self) -> bool;
    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError>;
    fn sni_hostname(&self) -> Option<&str>;
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Crypto>;
}

impl CryptoClientConfig for Arc<ClientConfig> {
    type Session = TlsSession;
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Self::Session, ConnectError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;
        Ok(TlsSession::Client(ClientSession::new_quic(
            self,
            pki_server_name,
            to_vec(Side::Client, params),
        )))
    }
}

pub trait CryptoClientConfig {
    type Session: CryptoSession;
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Self::Session, ConnectError>;
}

impl CryptoServerConfig for Arc<ServerConfig> {
    type Session = TlsSession;
    fn start_session(&self, params: &TransportParameters) -> Self::Session {
        TlsSession::Server(ServerSession::new_quic(self, to_vec(Side::Server, params)))
    }
}

pub trait CryptoServerConfig {
    type Session: CryptoSession;
    fn start_session(&self, params: &TransportParameters) -> Self::Session;
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

    fn new_0rtt(secret: &[u8]) -> Self {
        Self::new(
            Side::Client, // Meaningless when the secrets are equal
            &digest::SHA256,
            &aead::AES_128_GCM,
            Secrets {
                server: secret.into(),
                client: secret.into(),
            },
        )
    }

    fn new(
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

    fn write_nonce(&self, iv: &[u8], number: u64, out: &mut [u8]) {
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
        let header = Aad::from(header);
        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        aead::seal_in_place(&key, nonce, header, payload, cipher.tag_len()).unwrap();
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

        let header = Aad::from(header);
        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        aead::open_in_place(&key, nonce, header, 0, payload.as_mut()).map_err(|_| ())?;
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

    pub fn header_crypto(&self) -> RingHeaderCrypto {
        let local = SigningKey::new(self.digest, &self.local_secret);
        let remote = SigningKey::new(self.digest, &self.remote_secret);
        let cipher = self.sealing_key.algorithm();
        RingHeaderCrypto {
            local: header_key_from_secret(cipher, &local),
            remote: header_key_from_secret(cipher, &remote),
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

pub struct RingHeaderCrypto {
    local: HeaderProtectionKey,
    remote: HeaderProtectionKey,
}

impl HeaderCrypto for RingHeaderCrypto {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self
            .remote
            .new_mask(&sample[0..self.sample_size()])
            .unwrap();
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
        let mask = self.local.new_mask(&sample[0..self.sample_size()]).unwrap();
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
        self.local.algorithm().sample_len()
    }
}

pub trait HeaderCrypto {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    fn sample_size(&self) -> usize;
}

fn header_key_from_secret(aead: &aead::Algorithm, secret_key: &SigningKey) -> HeaderProtectionKey {
    const LABEL: &[u8] = b"quic hp";
    if aead == &aead::AES_128_GCM {
        let mut pn = [0; 16];
        hkdf_expand(&secret_key, LABEL, &mut pn);
        HeaderProtectionKey::new(&AES_128, &pn).unwrap()
    } else if aead == &aead::AES_256_GCM {
        let mut pn = [0; 32];
        hkdf_expand(&secret_key, LABEL, &mut pn);
        HeaderProtectionKey::new(&AES_256, &pn).unwrap()
    } else if aead == &aead::CHACHA20_POLY1305 {
        let mut pn = [0; 32];
        hkdf_expand(&secret_key, LABEL, &mut pn);
        HeaderProtectionKey::new(&CHACHA20, &pn).unwrap()
    } else {
        unimplemented!()
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
    hkdf::extract(&key, conn_id)
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
        let id = ConnectionId::new(&hex!("8394c8f03e515708"));
        let digest = &digest::SHA256;
        let cipher = &aead::AES_128_GCM;
        let initial_secret = initial_secret(&id);
        let client_secret = expanded_initial_secret(&initial_secret, b"client in");
        assert_eq!(
            &client_secret[..],
            hex!("8a3515a14ae3c31b9c2d6d5bc58538ca 5cd2baa119087143e60887428dcb52f6")
        );
        let (client_key, client_iv) = Crypto::get_keys(digest, cipher, &client_secret);
        assert_eq!(&client_key[..], hex!("98b0d7e5e7a402c67c33f350fa65ea54"));
        assert_eq!(&client_iv[..], hex!("19e94387805eb0b46c03a788"));

        let server_secret = expanded_initial_secret(&initial_secret, b"server in");
        assert_eq!(
            &server_secret[..],
            hex!("47b2eaea6c266e32c0697a9e2a898bdf 5c4fb3e5ac34f0e549bf2c58581a3811")
        );
        let (server_key, server_iv) = Crypto::get_keys(digest, cipher, &server_secret);
        assert_eq!(&server_key[..], hex!("9a8be902a9bdd91d16064ca118045fb4"));
        assert_eq!(&server_iv[..], hex!("0a82086d32205ba22241d8dc"));
    }

    #[test]
    fn packet_protection() {
        let id = ConnectionId::new(&hex!("8394c8f03e515708"));
        let server = Crypto::new_initial(&id, Side::Server);
        let server_header = server.header_crypto();
        let client = Crypto::new_initial(&id, Side::Client);
        let client_header = client.header_crypto();
        let plaintext = hex!(
            "c1ff00001205f067a5502a4262b50040740000
             0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988
             cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d
             89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002
             0304"
        );
        const HEADER_LEN: usize = 19;
        let protected = hex!(
            "c2ff00001205f067a5502a4262b50040 7428f63f2abf65a03e3e7ce041087cb1
             1fd7ba338b4fcd9e22bbdb5cff66218a 8ac48269098d73577222d3e02af7eb40
             1796a2d67c1c9e89d0dc5a5dfc6ceead f4ebd4eae0e3185dfe99a7f59288afaa
             75539cfad2bab440126a57213325f86d 3b8a5cb13b33f73a6317e34f73ac35ba
             3d7a1f0b5c"
        );
        let mut packet = plaintext.to_vec();
        server.encrypt(0, &mut packet, HEADER_LEN);
        server_header.encrypt(17, &mut packet);
        assert_eq!(&packet[..], &protected[..]);
        client_header.decrypt(17, &mut packet);
        let (header, payload) = packet.split_at(HEADER_LEN);
        assert_eq!(header, &plaintext[0..HEADER_LEN]);
        let mut payload = BytesMut::from(payload);
        client.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&payload, &plaintext[HEADER_LEN..]);
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

        assert_eq!(
            &onertt.local_iv[..],
            [0xd5, 0x1b, 0x16, 0x6a, 0x3e, 0xc4, 0x6f, 0x7e, 0x5f, 0x93, 0x27, 0x15]
        );
        assert_eq!(
            &onertt.remote_iv[..],
            [0x03, 0xda, 0x92, 0xa0, 0x91, 0x95, 0xe4, 0xbf, 0x87, 0x98, 0xd3, 0x78]
        );
    }
}
