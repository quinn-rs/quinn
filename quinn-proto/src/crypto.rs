use std::net::SocketAddrV6;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{io, str};

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::Aes128Ctr;
use blake2::{
    digest::{Input, VariableOutput},
    VarBlake2b,
};
use bytes::{Buf, BufMut, BytesMut};
use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::hmac::SigningKey;
use rustls::quic::{ClientQuicExt, ServerQuicExt};
pub use rustls::{Certificate, NoClientAuth, PrivateKey, TLSError};
pub use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Session};
use webpki::DNSNameRef;

use endpoint::EndpointError;
use packet::{ConnectionId, AEAD_TAG_SIZE};
use transport_parameters::TransportParameters;
use {Side, RESET_TOKEN_SIZE};

pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

impl TlsSession {
    pub fn new_client(
        config: &Arc<ClientConfig>,
        hostname: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, EndpointError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(hostname)
            .map_err(|_| EndpointError::InvalidDnsName(hostname.into()))?;
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
    ServerConfig::new(NoClientAuth::new())
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

pub fn reset_token_for(key: &[u8], id: &ConnectionId) -> [u8; RESET_TOKEN_SIZE] {
    let mut mac = VarBlake2b::new_keyed(key, RESET_TOKEN_SIZE);
    mac.input(id.as_ref());
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    mac.variable_result(|res| result.copy_from_slice(res));
    result
}

#[derive(Clone)]
pub enum Crypto {
    // ZeroRtt(ZeroRttCrypto),
    Handshake(CryptoContext),
    OneRtt(CryptoContext),
}

impl Crypto {
    /*
    pub fn new_0rtt(tls: &TlsSide) -> Self {
        let suite = tls.get_negotiated_ciphersuite().unwrap();
        let tls_cipher = tls.current_cipher().unwrap();
        let digest = tls_cipher.handshake_digest().unwrap();
        let cipher = Cipher::from_nid(tls_cipher.cipher_nid().unwrap()).unwrap();

        const LABEL: &str = "EXPORTER-QUIC 0rtt";

        let mut secret = vec![0; digest.size()];
        tls.export_keying_material_early(&mut secret, &LABEL, b"")
            .unwrap();
        Crypto::ZeroRtt(ZeroRttCrypto {
            state: CryptoState::new(digest, cipher, secret.into()),
            cipher,
        })
    }
    */

    pub fn new_handshake(id: &ConnectionId, side: Side) -> Self {
        let (digest, cipher) = (&digest::SHA256, &aead::AES_128_GCM);
        let (local_label, remote_label) = if side == Side::Client {
            (b"client hs", b"server hs")
        } else {
            (b"server hs", b"client hs")
        };
        let hs_secret = handshake_secret(id);
        let local = CryptoState::new(
            digest,
            cipher,
            expanded_handshake_secret(&hs_secret, local_label),
        );
        let remote = CryptoState::new(
            digest,
            cipher,
            expanded_handshake_secret(&hs_secret, remote_label),
        );
        Crypto::Handshake(CryptoContext {
            local,
            remote,
            digest,
            cipher,
        })
    }

    pub fn new_1rtt(tls: &TlsSession, side: Side) -> Self {
        let suite = tls.get_negotiated_ciphersuite().unwrap();
        let (cipher, digest) = (suite.get_aead_alg(), suite.get_hash());

        const SERVER_LABEL: &[u8] = b"EXPORTER-QUIC server 1rtt";
        const CLIENT_LABEL: &[u8] = b"EXPORTER-QUIC client 1rtt";

        let (local_label, remote_label) = if side == Side::Client {
            (CLIENT_LABEL, SERVER_LABEL)
        } else {
            (SERVER_LABEL, CLIENT_LABEL)
        };
        let mut local_secret = vec![0; digest.output_len];
        tls.export_keying_material(&mut local_secret, local_label, None)
            .unwrap();
        let local = CryptoState::new(digest, cipher, local_secret);

        let mut remote_secret = vec![0; digest.output_len];
        tls.export_keying_material(&mut remote_secret, remote_label, None)
            .unwrap();
        let remote = CryptoState::new(digest, cipher, remote_secret);
        Crypto::OneRtt(CryptoContext {
            local,
            remote,
            digest,
            cipher,
        })
    }

    /*
    pub fn is_0rtt(&self) -> bool {
        match *self {
            Crypto::ZeroRtt(_) => true,
            _ => false,
        }
    }
    */

    pub fn is_handshake(&self) -> bool {
        match *self {
            Crypto::Handshake(_) => true,
            _ => false,
        }
    }

    pub fn is_1rtt(&self) -> bool {
        match *self {
            Crypto::OneRtt(_) => true,
            _ => false,
        }
    }

    pub fn write_nonce(&self, state: &CryptoState, number: u64, out: &mut [u8]) {
        let out = {
            let mut write = io::Cursor::new(out);
            write.put_u32_be(0);
            write.put_u64_be(number);
            debug_assert_eq!(write.remaining(), 0);
            write.into_inner()
        };
        debug_assert_eq!(out.len(), state.iv.len());
        for (out, inp) in out.iter_mut().zip(state.iv.iter()) {
            *out ^= inp;
        }
    }

    pub fn encrypt(&self, packet: u64, buf: &mut Vec<u8>, header_len: usize) {
        // FIXME: retain crypter
        let (cipher, state) = match *self {
            //Crypto::ZeroRtt(ref crypto) => (crypto.cipher, &crypto.state),
            Crypto::Handshake(ref crypto) | Crypto::OneRtt(ref crypto) => {
                (crypto.cipher, &crypto.local)
            }
        };

        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..cipher.nonce_len()];
        self.write_nonce(&state, packet, nonce);
        let tag = vec![0; cipher.tag_len()];
        buf.extend(tag);

        let key = aead::SealingKey::new(cipher, &state.key).unwrap();
        let (header, payload) = buf.split_at_mut(header_len);
        aead::seal_in_place(&key, &*nonce, header, payload, cipher.tag_len()).unwrap();
    }

    pub fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()> {
        if payload.len() < AEAD_TAG_SIZE {
            return Err(());
        }

        let (cipher, state) = match *self {
            //Crypto::ZeroRtt(ref crypto) => (crypto.cipher, &crypto.state),
            Crypto::Handshake(ref crypto) | Crypto::OneRtt(ref crypto) => {
                (crypto.cipher, &crypto.remote)
            }
        };

        let mut nonce_buf = [0u8; aead::MAX_TAG_LEN];
        let nonce = &mut nonce_buf[..cipher.nonce_len()];
        self.write_nonce(&state, packet, nonce);
        let payload_len = payload.len();

        let key = aead::OpeningKey::new(cipher, &state.key).unwrap();
        aead::open_in_place(&key, &*nonce, header, 0, payload.as_mut()).map_err(|_| ())?;
        payload.split_off(payload_len - cipher.tag_len());
        Ok(())
    }

    pub fn update(&self, side: Side) -> Crypto {
        match *self {
            Crypto::OneRtt(ref crypto) => Crypto::OneRtt(CryptoContext {
                local: crypto.local.update(crypto.digest, crypto.cipher, side),
                remote: crypto.local.update(crypto.digest, crypto.cipher, !side),
                digest: crypto.digest,
                cipher: crypto.cipher,
            }),
            _ => unreachable!(),
        }
    }
}

/*
pub struct CookieFactory {
    mac_key: [u8; 64],
}

const COOKIE_MAC_BYTES: usize = 64;

impl CookieFactory {
    fn new(mac_key: [u8; 64]) -> Self {
        Self { mac_key }
    }

    fn generate(&self, conn: &ConnectionInfo, out: &mut [u8]) -> usize {
        let mac = self.generate_mac(conn);
        out[0..COOKIE_MAC_BYTES].copy_from_slice(&mac);
        COOKIE_MAC_BYTES
    }

    fn generate_mac(&self, conn: &ConnectionInfo) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);
        mac.process(&conn.remote.ip().octets());
        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }

    fn verify(&self, conn: &ConnectionInfo, cookie_data: &[u8]) -> bool {
        let expected = self.generate_mac(conn);
        if !constant_time_eq(cookie_data, &expected) {
            return false;
        }
        true
    }
}
*/

#[derive(Clone)]
pub struct ConnectionInfo {
    pub(crate) id: ConnectionId,
    pub(crate) remote: SocketAddrV6,
}

const HANDSHAKE_SALT: [u8; 20] = [
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
    0xe0, 0x6d, 0x6c, 0x38,
];

#[derive(Clone)]
pub struct CryptoState {
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    pn: Vec<u8>,
}

impl CryptoState {
    fn new(
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        secret: Vec<u8>,
    ) -> Self {
        let secret_key = SigningKey::new(digest, &secret);
        let mut key = vec![0; cipher.key_len()];
        qhkdf_expand(&secret_key, b"key", &mut key);
        let mut iv = vec![0; cipher.nonce_len()];
        qhkdf_expand(&secret_key, b"iv", &mut iv);
        let pne_alg = PacketNumberEncryptionAlgorithm::from_aead(cipher);
        let mut pn = vec![0; pne_alg.key_len()];
        qhkdf_expand(&secret_key, b"pn", &mut pn);
        Self {
            secret,
            key,
            iv,
            pn,
        }
    }

    fn update(
        &self,
        digest: &'static digest::Algorithm,
        cipher: &'static aead::Algorithm,
        side: Side,
    ) -> CryptoState {
        let secret_key = SigningKey::new(digest, &self.secret);
        let mut new_secret = vec![0; digest.output_len];
        qhkdf_expand(
            &secret_key,
            if side == Side::Client {
                b"client 1rtt"
            } else {
                b"server 1rtt"
            },
            &mut new_secret,
        );
        Self::new(digest, cipher, new_secret)
    }
}

#[derive(Clone)]
pub struct ZeroRttCrypto {
    state: CryptoState,
    cipher: &'static aead::Algorithm,
}

#[derive(Clone)]
pub struct CryptoContext {
    local: CryptoState,
    remote: CryptoState,
    digest: &'static digest::Algorithm,
    cipher: &'static aead::Algorithm,
}

#[derive(Debug, Fail)]
pub enum ConnectError {
    #[fail(display = "session ticket was malformed")]
    MalformedSession,
    #[fail(display = "TLS error: {}", _0)]
    Tls(TLSError),
}

impl From<TLSError> for ConnectError {
    fn from(x: TLSError) -> Self {
        ConnectError::Tls(x)
    }
}

pub fn expanded_handshake_secret(prk: &SigningKey, label: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; digest::SHA256.output_len];
    qhkdf_expand(prk, label, &mut out);
    out
}

pub fn qhkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(2 + 1 + 5 + out.len());
    info.put_u16_be(out.len() as u16);
    info.put_u8(5 + (label.len() as u8));
    info.extend_from_slice(b"QUIC ");
    info.extend_from_slice(&label);
    hkdf::expand(key, &info, out);
}

fn handshake_secret(conn_id: &ConnectionId) -> SigningKey {
    let key = SigningKey::new(&digest::SHA256, &HANDSHAKE_SALT);
    let mut buf = Vec::with_capacity(8);
    buf.put_slice(conn_id);
    hkdf::extract(&key, &buf)
}

enum PacketNumberEncryptionAlgorithm {
    AesCtr128,
}

impl PacketNumberEncryptionAlgorithm {
    fn from_aead(alg: &aead::Algorithm) -> Self {
        use self::PacketNumberEncryptionAlgorithm::*;
        if alg == &aead::AES_128_GCM {
            AesCtr128
        } else {
            unimplemented!()
        }
    }

    fn key_len(&self) -> usize {
        use self::PacketNumberEncryptionAlgorithm::*;
        match *self {
            AesCtr128 => 16,
        }
    }

    fn sample_size(&self) -> usize {
        use self::PacketNumberEncryptionAlgorithm::*;
        match *self {
            AesCtr128 => 16,
        }
    }

    fn decrypt(&self, key: &[u8], sample: &[u8], in_out: &mut [u8]) {
        use self::PacketNumberEncryptionAlgorithm::*;
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(sample);
        match *self {
            AesCtr128 => Aes128Ctr::new(key, nonce).apply_keystream(in_out),
        }
    }

    fn encrypt(&self, key: &[u8], sample: &[u8], in_out: &mut [u8]) {
        use self::PacketNumberEncryptionAlgorithm::*;
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(sample);
        match *self {
            AesCtr128 => Aes128Ctr::new(key, nonce).apply_keystream(in_out),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use packet::PacketNumber;
    use rand;
    use MAX_CID_SIZE;

    #[test]
    fn packet_number() {
        for prev in 0..1024 {
            for x in 0..256 {
                let found = PacketNumber::U8(x as u8).expand(prev);
                assert!(found as i64 - (prev + 1) as i64 <= 128 || prev < 128);
            }
        }
        // Order of operations regression test
        assert_eq!(PacketNumber::U32(0xa0bd197c).expand(0xa0bd197a), 0xa0bd197c);
    }

    #[test]
    fn handshake_crypto_roundtrip() {
        let conn = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE as u8);
        let client = Crypto::new_handshake(&conn, Side::Client);
        let server = Crypto::new_handshake(&conn, Side::Server);

        let mut buf = b"headerpayload".to_vec();
        client.encrypt(0, &mut buf, 6);

        let mut header = BytesMut::from(buf);
        let mut payload = header.split_off(6);
        server.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&*payload, b"payload");
    }

    #[test]
    fn key_derivation() {
        let id = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let digest = &digest::SHA256;
        let cipher = &aead::AES_128_GCM;
        let hs_secret = handshake_secret(&id);
        let client_secret = expanded_handshake_secret(&hs_secret, b"client hs");
        assert_eq!(
            &client_secret[..],
            [
                0x83, 0x55, 0xf2, 0x1a, 0x3d, 0x8f, 0x83, 0xec, 0xb3, 0xd0, 0xf9, 0x71, 0x08, 0xd3,
                0xf9, 0x5e, 0x0f, 0x65, 0xb4, 0xd8, 0xae, 0x88, 0xa0, 0x61, 0x1e, 0xe4, 0x9d, 0xb0,
                0xb5, 0x23, 0x59, 0x1d
            ]
        );
        let client_state = CryptoState::new(digest, cipher, client_secret);
        assert_eq!(
            &client_state.key[..],
            [
                0x3a, 0xd0, 0x54, 0x2c, 0x4a, 0x85, 0x84, 0x74, 0x00, 0x63, 0x04, 0x9e, 0x3b, 0x3c,
                0xaa, 0xb2
            ]
        );
        assert_eq!(
            &client_state.iv[..],
            [0xd1, 0xfd, 0x26, 0x05, 0x42, 0x75, 0x3a, 0xba, 0x38, 0x58, 0x9b, 0xad]
        );

        let server_secret = expanded_handshake_secret(&hs_secret, b"server hs");
        assert_eq!(
            &server_secret[..],
            [
                0xf8, 0x0e, 0x57, 0x71, 0x48, 0x4b, 0x21, 0xcd, 0xeb, 0xb5, 0xaf, 0xe0, 0xa2, 0x56,
                0xa3, 0x17, 0x41, 0xef, 0xe2, 0xb5, 0xc6, 0xb6, 0x17, 0xba, 0xe1, 0xb2, 0xf1, 0x5a,
                0x83, 0x04, 0x83, 0xd6
            ]
        );
        let server_state = CryptoState::new(digest, cipher, server_secret);
        assert_eq!(
            &server_state.key[..],
            [
                0xbe, 0xe4, 0xc2, 0x4d, 0x2a, 0xf1, 0x33, 0x80, 0xa9, 0xfa, 0x24, 0xa5, 0xe2, 0xba,
                0x2c, 0xff
            ]
        );
        assert_eq!(
            &server_state.iv[..],
            [0x25, 0xb5, 0x8e, 0x24, 0x6d, 0x9e, 0x7d, 0x5f, 0xfe, 0x43, 0x23, 0xfe]
        );
    }

    // https://github.com/quicwg/base-drafts/wiki/Test-vector-for-AES-packet-number-encryption
    #[test]
    fn pne_test_vectors() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let mut received = [
            0x30, 0x80, 0x6d, 0xbb, 0xb5, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9,
            0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc,
            0x5b, 0x88, 0x55,
        ];
        let alg = PacketNumberEncryptionAlgorithm::AesCtr128;
        // Cheating a little bit here...
        let sample_offset = 5;
        let (header, payload) = received.split_at_mut(sample_offset);
        let sample = &payload[..alg.sample_size()];
        alg.decrypt(&key, sample, &mut header[1..]);
        assert_eq!(&header[1..], [0xba, 0xba, 0xc0, 0x01]);
        alg.encrypt(&key, sample, &mut header[1..]);
        assert_eq!(&header[1..], [0x80, 0x6d, 0xbb, 0xb5]);
    }
}

//pub type SessionTicketBuffer = Arc<Mutex<Vec<Result<SslSession, ()>>>>;
