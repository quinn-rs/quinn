use std::net::SocketAddrV6;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{io, str};

use bytes::{Buf, BufMut, BytesMut};
use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::hmac::{self, SigningKey};
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

pub fn reset_token_for(key: &SigningKey, id: &ConnectionId) -> [u8; RESET_TOKEN_SIZE] {
    let signature = hmac::sign(key, id);
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    result.copy_from_slice(&signature.as_ref()[..RESET_TOKEN_SIZE]);
    result
}

#[derive(Clone)]
pub enum Crypto {
    // ZeroRtt(ZeroRttCrypto),
    Initial(CryptoContext),
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

    pub fn new_initial(id: &ConnectionId, side: Side) -> Self {
        let (digest, cipher) = (&digest::SHA256, &aead::AES_128_GCM);
        let (local_label, remote_label) = if side == Side::Client {
            (b"client in", b"server in")
        } else {
            (b"server in", b"client in")
        };
        let hs_secret = initial_secret(id);
        let local = CryptoState::new(
            digest,
            cipher,
            expanded_initial_secret(&hs_secret, local_label),
        );
        let remote = CryptoState::new(
            digest,
            cipher,
            expanded_initial_secret(&hs_secret, remote_label),
        );
        Crypto::Initial(CryptoContext {
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

    pub fn is_initial(&self) -> bool {
        match *self {
            Crypto::Initial(_) => true,
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
            Crypto::Initial(ref crypto) | Crypto::OneRtt(ref crypto) => {
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
            Crypto::Initial(ref crypto) | Crypto::OneRtt(ref crypto) => {
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

#[derive(Clone)]
pub struct CryptoState {
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
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
        Self { secret, key, iv }
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

pub fn expanded_initial_secret(prk: &SigningKey, label: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; digest::SHA256.output_len];
    qhkdf_expand(prk, label, &mut out);
    out
}

pub fn qhkdf_expand(key: &SigningKey, label: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(2 + 1 + 5 + out.len());
    info.put_u16_be(out.len() as u16);
    info.put_u8(5 + (label.len() as u8));
    info.extend_from_slice(b"quic ");
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
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
    0xe0, 0x6d, 0x6c, 0x38,
];

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
        let id = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let digest = &digest::SHA256;
        let cipher = &aead::AES_128_GCM;
        let initial_secret = initial_secret(&id);
        let client_secret = expanded_initial_secret(&initial_secret, b"client in");
        assert_eq!(
            &client_secret[..],
            [
                0x9f, 0x53, 0x64, 0x57, 0xf3, 0x2a, 0x1e, 0x0a, 0xe8, 0x64, 0xbc, 0xb3, 0xca, 0xf1,
                0x23, 0x51, 0x10, 0x63, 0x0e, 0x1d, 0x1f, 0xb3, 0x38, 0x35, 0xbd, 0x05, 0x41, 0x70,
                0xf9, 0x9b, 0xf7, 0xdc,
            ]
        );
        let client_state = CryptoState::new(digest, cipher, client_secret);
        assert_eq!(
            &client_state.key[..],
            [
                0xf2, 0x92, 0x8f, 0x26, 0x14, 0xad, 0x6c, 0x20, 0xb9, 0xbd, 0x00, 0x8e, 0x9c, 0x89,
                0x63, 0x1c,
            ]
        );
        assert_eq!(
            &client_state.iv[..],
            [0xab, 0x95, 0x0b, 0x01, 0x98, 0x63, 0x79, 0x78, 0xcf, 0x44, 0xaa, 0xb9,]
        );

        let server_secret = expanded_initial_secret(&initial_secret, b"server in");
        assert_eq!(
            &server_secret[..],
            [
                0xb0, 0x87, 0xdc, 0xd7, 0x47, 0x8d, 0xda, 0x8a, 0x85, 0x8f, 0xbf, 0x3d, 0x60, 0x5c,
                0x88, 0x85, 0x86, 0xc0, 0xa3, 0xa9, 0x87, 0x54, 0x23, 0xad, 0x4f, 0x11, 0x4f, 0x0b,
                0xa3, 0x8e, 0x5a, 0x2e,
            ]
        );
        let server_state = CryptoState::new(digest, cipher, server_secret);
        assert_eq!(
            &server_state.key[..],
            [
                0xf5, 0x68, 0x17, 0xd0, 0xfc, 0x59, 0x5c, 0xfc, 0x0a, 0x2b, 0x0b, 0xcf, 0xb1, 0x87,
                0x35, 0xec,
            ]
        );
        assert_eq!(
            &server_state.iv[..],
            [0x32, 0x05, 0x03, 0x5a, 0x3c, 0x93, 0x7c, 0x90, 0x2e, 0xe4, 0xf4, 0xd6,]
        );
    }
}

//pub type SessionTicketBuffer = Arc<Mutex<Vec<Result<SslSession, ()>>>>;
