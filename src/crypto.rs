use std::net::SocketAddrV6;
use std::str;
use std::sync::{Arc, Mutex};

use blake2::Blake2b;
use bytes::{BigEndian, ByteOrder, IntoBuf};
use constant_time_eq::constant_time_eq;
use digest::{Input, VariableOutput};
use openssl::ex_data;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{
    self, Ssl, SslAlert, SslContext, SslMethod, SslMode, SslOptions, SslRef, SslSession, SslVersion,
};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use openssl::x509::X509Ref;

use endpoint::{Config, ConnectionId, EndpointError, ListenKeys};
use transport_parameters::TransportParameters;
use {hkdf, Side, RESET_TOKEN_SIZE};

pub struct CertConfig<'a> {
    /// A TLS private key.
    pub private_key: &'a PKeyRef<Private>,
    /// A TLS certificate corresponding to `private_key`.
    pub cert: &'a X509Ref,
}

/// Value used in ACKs we transmit
pub const ACK_DELAY_EXPONENT: u8 = 3;
/// Magic value used to indicate 0-RTT support in NewSessionTicket
pub const TLS_MAX_EARLY_DATA: u32 = 0xffffffff;

pub fn reset_token_for(key: &[u8], id: &ConnectionId) -> [u8; RESET_TOKEN_SIZE] {
    let mut mac = Blake2b::new_keyed(key, RESET_TOKEN_SIZE);
    mac.process(id);
    // TODO: Server ID??
    let mut result = [0; RESET_TOKEN_SIZE];
    mac.variable_result(&mut result).unwrap();
    result
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Crypto {
    ZeroRtt,
    Handshake,
    OneRtt,
}

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

pub struct ConnectionInfo {
    pub(crate) id: ConnectionId,
    pub(crate) remote: SocketAddrV6,
}

lazy_static! {
    pub static ref CONNECTION_INFO_INDEX: ex_data::Index<Ssl, ConnectionInfo> =
        Ssl::new_ex_index().unwrap();
    pub static ref TRANSPORT_PARAMS_INDEX: ex_data::Index<Ssl, Result<TransportParameters, ::transport_parameters::Error>> =
        Ssl::new_ex_index().unwrap();
}

pub fn new_tls_ctx(
    config: Arc<Config>,
    cert: Option<CertConfig>,
    listen: Option<ListenKeys>,
) -> Result<(SslContext, SessionTicketBuffer), EndpointError> {
    let mut tls = SslContext::builder(SslMethod::tls())?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    tls.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_SSLV2
            | SslOptions::NO_SSLV3
            | SslOptions::NO_TLSV1
            | SslOptions::NO_TLSV1_1
            | SslOptions::NO_TLSV1_2
            | SslOptions::DONT_INSERT_EMPTY_FRAGMENTS,
    );
    tls.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);
    tls.set_mode(
        SslMode::ACCEPT_MOVING_WRITE_BUFFER
            | SslMode::ENABLE_PARTIAL_WRITE
            | SslMode::RELEASE_BUFFERS,
    );
    tls.set_default_verify_paths()?;
    if !config.use_stateless_retry {
        tls.set_max_early_data(TLS_MAX_EARLY_DATA)?;
    }
    if let Some(ref listen) = listen {
        let cookie_factory = Arc::new(CookieFactory::new(listen.cookie));
        {
            let cookie_factory = cookie_factory.clone();
            tls.set_stateless_cookie_generate_cb(move |tls, buf| {
                let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                Ok(cookie_factory.generate(conn, buf))
            });
        }
        tls.set_stateless_cookie_verify_cb(move |tls, cookie| {
            let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
            cookie_factory.verify(conn, cookie)
        });
    }
    let reset_key = listen.as_ref().map(|x| x.reset);
    tls.add_custom_ext(
        26,
        ssl::ExtensionContext::TLS1_3_ONLY
            | ssl::ExtensionContext::CLIENT_HELLO
            | ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS,
        {
            let config = config.clone();
            move |tls, ctx, _| {
                let conn = tls.ex_data(*CONNECTION_INFO_INDEX).unwrap();
                let mut buf = Vec::new();
                let mut params = TransportParameters {
                    initial_max_streams_bidi: config.max_remote_bi_streams,
                    initial_max_streams_uni: config.max_remote_uni_streams,
                    initial_max_data: config.receive_window,
                    initial_max_stream_data: config.stream_receive_window,
                    ack_delay_exponent: ACK_DELAY_EXPONENT,
                    ..TransportParameters::default()
                };
                let am_server = ctx == ssl::ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS;
                let side;
                if am_server {
                    params.stateless_reset_token =
                        Some(reset_token_for(reset_key.as_ref().unwrap(), &conn.id));
                    side = Side::Server;
                } else {
                    side = Side::Client;
                }
                params.write(side, &mut buf);
                Ok(Some(buf))
            }
        },
        |tls, ctx, data, _| {
            let side = if ctx == ssl::ExtensionContext::CLIENT_HELLO {
                Side::Server
            } else {
                Side::Client
            };
            match TransportParameters::read(side, &mut data.into_buf()) {
                Ok(params) => {
                    tls.set_ex_data(*TRANSPORT_PARAMS_INDEX, Ok(params));
                    Ok(())
                }
                Err(e) => {
                    use transport_parameters::Error::*;
                    tls.set_ex_data(*TRANSPORT_PARAMS_INDEX, Err(e));
                    Err(match e {
                        VersionNegotiation => SslAlert::ILLEGAL_PARAMETER,
                        IllegalValue => SslAlert::ILLEGAL_PARAMETER,
                        Malformed => SslAlert::DECODE_ERROR,
                    })
                }
            }
        },
    )?;

    if let Some(ref cert) = cert {
        tls.set_private_key(cert.private_key)?;
        tls.set_certificate(cert.cert)?;
        tls.check_private_key()?;
    }

    if !config.protocols.is_empty() {
        let mut buf = Vec::new();
        for protocol in &config.protocols {
            if protocol.len() > 255 {
                return Err(EndpointError::ProtocolTooLong(protocol.clone()));
            }
            buf.push(protocol.len() as u8);
            buf.extend_from_slice(protocol);
        }
        tls.set_alpn_protos(&buf)?;
        tls.set_alpn_select_callback(move |_ssl, protos| {
            if let Some(x) = ssl::select_next_proto(&buf, protos) {
                Ok(x)
            } else {
                Err(ssl::AlpnError::ALERT_FATAL)
            }
        });
    }

    if let Some(ref path) = config.keylog {
        let file = ::std::fs::File::create(path).map_err(EndpointError::Keylog)?;
        let file = Mutex::new(file);
        tls.set_keylog_callback(move |_, line| {
            use std::io::Write;
            let mut file = file.lock().unwrap();
            let _ = file.write_all(line.as_bytes());
            let _ = file.write_all(b"\n");
        });
    }

    let session_ticket_buffer = Arc::new(Mutex::new(Vec::new()));
    {
        let session_ticket_buffer = session_ticket_buffer.clone();
        tls.set_session_cache_mode(ssl::SslSessionCacheMode::BOTH);
        tls.set_new_session_callback(move |tls, session| {
            if tls.is_server() {
                return;
            }
            let mut buffer = session_ticket_buffer.lock().unwrap();
            match session.max_early_data() {
                0 | TLS_MAX_EARLY_DATA => {}
                _ => {
                    buffer.push(Err(()));
                }
            }
            buffer.push(Ok(session));
        });
    }

    let verify_flag = if config.require_client_certs {
        ssl::SslVerifyMode::PEER | ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT
    } else {
        ssl::SslVerifyMode::empty()
    };
    if config.client_cert_verifier.is_some() {
        let config = config.clone();
        tls.set_verify_callback(ssl::SslVerifyMode::PEER | verify_flag, move |x, y| {
            (config.client_cert_verifier.as_ref().unwrap())(x, y)
        });
    } else {
        tls.set_verify(verify_flag);
    }

    Ok((tls.build(), session_ticket_buffer))
}

const HANDSHAKE_SALT: [u8; 20] = [
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
    0xe0, 0x6d, 0x6c, 0x38,
];

#[derive(Clone)]
pub struct CryptoState {
    secret: Box<[u8]>,
    key: Box<[u8]>,
    iv: Box<[u8]>,
}

impl CryptoState {
    fn new(digest: MessageDigest, cipher: Cipher, secret: Box<[u8]>) -> Self {
        let key = hkdf::qexpand(digest, &secret, b"key", cipher.key_len() as u16);
        let iv = hkdf::qexpand(digest, &secret, b"iv", cipher.iv_len().unwrap() as u16);
        Self { secret, key, iv }
    }

    fn update(&self, digest: MessageDigest, cipher: Cipher, side: Side) -> CryptoState {
        let secret = hkdf::qexpand(
            digest,
            &self.secret,
            if side == Side::Client {
                b"client 1rtt"
            } else {
                b"server 1rtt"
            },
            digest.size() as u16,
        );
        Self::new(digest, cipher, secret)
    }
}

pub struct ZeroRttCrypto {
    state: CryptoState,
    cipher: Cipher,
}

impl ZeroRttCrypto {
    pub fn new(tls: &SslRef) -> Self {
        let tls_cipher = tls.current_cipher().unwrap();
        let digest = tls_cipher.handshake_digest().unwrap();
        let cipher = Cipher::from_nid(tls_cipher.cipher_nid().unwrap()).unwrap();

        const LABEL: &str = "EXPORTER-QUIC 0rtt";

        let mut secret = vec![0; digest.size()];
        tls.export_keying_material_early(&mut secret, &LABEL, b"")
            .unwrap();
        Self {
            state: CryptoState::new(digest, cipher, secret.into()),
            cipher,
        }
    }

    pub fn encrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut tag = [0; AEAD_TAG_SIZE];
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.state.iv[i];
        }
        let mut buf = encrypt_aead(
            self.cipher,
            &self.state.key,
            Some(&nonce),
            header,
            payload,
            &mut tag,
        ).unwrap();
        buf.extend_from_slice(&tag);
        buf
    }

    pub fn decrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.state.iv[i];
        }
        if payload.len() < AEAD_TAG_SIZE {
            return None;
        }
        let (payload, tag) = payload.split_at(payload.len() - AEAD_TAG_SIZE);
        decrypt_aead(
            self.cipher,
            &self.state.key,
            Some(&nonce),
            header,
            payload,
            tag,
        ).ok()
    }
}

#[derive(Clone)]
pub struct CryptoContext {
    local: CryptoState,
    remote: CryptoState,
    digest: MessageDigest,
    cipher: Cipher,
}

impl CryptoContext {
    pub fn handshake(id: &ConnectionId, side: Side) -> Self {
        let digest = MessageDigest::sha256();
        let cipher = Cipher::aes_128_gcm();
        let hs_secret = hkdf::extract(digest, &HANDSHAKE_SALT, &id.0);
        let (local_label, remote_label) = if side == Side::Client {
            (b"client hs", b"server hs")
        } else {
            (b"server hs", b"client hs")
        };
        let local = CryptoState::new(
            digest,
            cipher,
            hkdf::qexpand(digest, &hs_secret, &local_label[..], digest.size() as u16),
        );
        let remote = CryptoState::new(
            digest,
            cipher,
            hkdf::qexpand(digest, &hs_secret, &remote_label[..], digest.size() as u16),
        );
        CryptoContext {
            local,
            remote,
            digest,
            cipher,
        }
    }

    pub fn established(tls: &SslRef, side: Side) -> Self {
        let tls_cipher = tls.current_cipher().unwrap();
        let digest = tls_cipher.handshake_digest().unwrap();
        let cipher = Cipher::from_nid(tls_cipher.cipher_nid().unwrap()).unwrap();

        const SERVER_LABEL: &str = "EXPORTER-QUIC server 1rtt";
        const CLIENT_LABEL: &str = "EXPORTER-QUIC client 1rtt";

        let (local_label, remote_label) = if side == Side::Client {
            (CLIENT_LABEL, SERVER_LABEL)
        } else {
            (SERVER_LABEL, CLIENT_LABEL)
        };
        let mut local_secret = vec![0; digest.size()];
        tls.export_keying_material(&mut local_secret, local_label, Some(b""))
            .unwrap();
        let local = CryptoState::new(digest, cipher, local_secret.into());

        let mut remote_secret = vec![0; digest.size()];
        tls.export_keying_material(&mut remote_secret, remote_label, Some(b""))
            .unwrap();
        let remote = CryptoState::new(digest, cipher, remote_secret.into());
        CryptoContext {
            local,
            remote,
            digest,
            cipher,
        }
    }

    pub fn update(&self, side: Side) -> Self {
        CryptoContext {
            local: self.local.update(self.digest, self.cipher, side),
            remote: self.local.update(self.digest, self.cipher, !side),
            digest: self.digest,
            cipher: self.cipher,
        }
    }

    pub fn encrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        // FIXME: Output to caller-owned memory with preexisting header; retain crypter
        let mut tag = [0; AEAD_TAG_SIZE];
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.local.iv[i];
        }
        let mut buf = encrypt_aead(
            self.cipher,
            &self.local.key,
            Some(&nonce),
            header,
            payload,
            &mut tag,
        ).unwrap();
        buf.extend_from_slice(&tag);
        buf
    }

    pub fn decrypt(&self, packet: u64, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0; 12];
        BigEndian::write_u64(&mut nonce[4..12], packet);
        for i in 0..12 {
            nonce[i] ^= self.remote.iv[i];
        }
        if payload.len() < AEAD_TAG_SIZE {
            return None;
        }
        let (payload, tag) = payload.split_at(payload.len() - AEAD_TAG_SIZE);
        decrypt_aead(
            self.cipher,
            &self.remote.key,
            Some(&nonce),
            header,
            payload,
            tag,
        ).ok()
    }
}

pub const AEAD_TAG_SIZE: usize = 16;

#[cfg(test)]
mod test {
    use super::*;
    use endpoint::PacketNumber;
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
        let client = CryptoContext::handshake(&conn, Side::Client);
        let server = CryptoContext::handshake(&conn, Side::Server);
        let header = b"header";
        let payload = b"payload";
        let encrypted = client.encrypt(0, header, payload);
        let decrypted = server.decrypt(0, header, &encrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn key_derivation() {
        let id = ConnectionId(
            [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
                .iter()
                .cloned()
                .collect(),
        );
        let digest = MessageDigest::sha256();
        let cipher = Cipher::aes_128_gcm();
        let hs_secret = hkdf::extract(digest, &HANDSHAKE_SALT, &id.0);
        assert_eq!(
            &hs_secret[..],
            [
                0xa5, 0x72, 0xb0, 0x24, 0x5a, 0xf1, 0xed, 0xdf, 0x5c, 0x61, 0xc6, 0xe3, 0xf7, 0xf9,
                0x30, 0x4c, 0xa6, 0x6b, 0xfb, 0x4c, 0xaa, 0xf7, 0x65, 0x67, 0xd5, 0xcb, 0x8d, 0xd1,
                0xdc, 0x4e, 0x82, 0x0b
            ]
        );

        let client_secret = hkdf::qexpand(digest, &hs_secret, b"client hs", digest.size() as u16);
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

        let server_secret = hkdf::qexpand(digest, &hs_secret, b"server hs", digest.size() as u16);
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
}

pub type SessionTicketBuffer = Arc<Mutex<Vec<Result<SslSession, ()>>>>;
