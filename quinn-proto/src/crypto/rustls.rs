use std::{
    io,
    ops::{Deref, DerefMut},
    str,
    sync::Arc,
};

use bytes::BytesMut;
use ring::{aead, aead::quic::HeaderProtectionKey, hmac};
pub use rustls::TLSError;
use rustls::{
    self,
    quic::{ClientQuicExt, PacketKey, ServerQuicExt},
    Session,
};
use webpki::DNSNameRef;

use crate::{
    crypto,
    crypto::{KeyPair, Keys},
    transport_parameters::TransportParameters,
    CertificateChain, ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
};

/// A rustls TLS session
pub struct TlsSession {
    inner: SessionKind,
}

enum SessionKind {
    Client(rustls::ClientSession),
    Server(rustls::ServerSession),
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            SessionKind::Client(_) => Side::Client,
            SessionKind::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    type AuthenticationData = AuthenticationData;
    type ClientConfig = Arc<rustls::ClientConfig>;
    type HmacKey = hmac::Key;
    type PacketKey = PacketKey;
    type HeaderKey = HeaderProtectionKey;
    type ServerConfig = Arc<rustls::ServerConfig>;

    fn initial_keys(dst_cid: &ConnectionId, side: Side) -> Keys<Self> {
        const INITIAL_SALT: [u8; 20] = [
            0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4,
            0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
        ];

        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &INITIAL_SALT);
        let keys = rustls::quic::Keys::initial(&salt, dst_cid, side.is_client());
        Keys {
            header: KeyPair {
                local: keys.local.header,
                remote: keys.remote.header,
            },
            packet: KeyPair {
                local: keys.local.packet,
                remote: keys.remote.packet,
            },
        }
    }

    fn authentication_data(&self) -> AuthenticationData {
        AuthenticationData {
            peer_certificates: self.get_peer_certificates().map(|v| v.into()),
            protocol: self.get_alpn_protocol().map(|p| p.into()),
            server_name: match self.inner {
                SessionKind::Client(_) => None,
                SessionKind::Server(ref session) => session.get_sni_hostname().map(|s| s.into()),
            },
        }
    }

    fn early_crypto(&self) -> Option<(Self::HeaderKey, Self::PacketKey)> {
        let keys = self.get_0rtt_keys()?;
        Some((keys.header, keys.packet))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            SessionKind::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self.inner {
            SessionKind::Client(ref session) => session.is_handshaking(),
            SessionKind::Server(ref session) => session.is_handshaking(),
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.get_alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.get_u8()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {}", e))
            }
        })
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

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys<Self>> {
        let keys = self.write_hs(buf)?;
        Some(Keys {
            header: KeyPair {
                local: keys.local.header,
                remote: keys.remote.header,
            },
            packet: KeyPair {
                local: keys.local.packet,
                remote: keys.remote.packet,
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> KeyPair<Self::PacketKey> {
        let keys = (**self).next_1rtt_keys();
        KeyPair {
            local: keys.local,
            remote: keys.remote,
        }
    }

    fn retry_tag(orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }

    fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }
}

impl Deref for TlsSession {
    type Target = dyn rustls::Session;
    fn deref(&self) -> &Self::Target {
        match self.inner {
            SessionKind::Client(ref session) => session,
            SessionKind::Server(ref session) => session,
        }
    }
}

impl DerefMut for TlsSession {
    fn deref_mut(&mut self) -> &mut (dyn rustls::Session + 'static) {
        match self.inner {
            SessionKind::Client(ref mut session) => session,
            SessionKind::Server(ref mut session) => session,
        }
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75,
];

/// Authentication data for (rustls) TLS session
pub struct AuthenticationData {
    /// The certificate chain used by the peer to authenticate
    ///
    /// For clients, this is the certificate chain of the server. For servers, this is the
    /// certificate chain of the client, if client authentication was completed.
    ///
    /// `None` if this data was requested from the session before this value is available.
    ///
    /// If this is `None`, and `Connection::is_handshaking` returns `false`, the connection
    /// will have already been closed.
    pub peer_certificates: Option<CertificateChain>,
    /// The negotiated application protocol
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client
    ///
    /// `None` for outgoing connections.
    pub server_name: Option<String>,
}

impl crypto::ClientConfig<TlsSession> for Arc<rustls::ClientConfig> {
    fn new() -> Self {
        let mut cfg = rustls::ClientConfig::new();
        cfg.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        cfg.enable_early_data = true;
        #[cfg(feature = "native-certs")]
        match rustls_native_certs::load_native_certs() {
            Ok(x) => {
                cfg.root_store = x;
            }
            Err((Some(x), e)) => {
                cfg.root_store = x;
                tracing::warn!("couldn't load some default trust roots: {}", e);
            }
            Err((None, e)) => {
                tracing::warn!("couldn't load any default trust roots: {}", e);
            }
        }
        #[cfg(feature = "certificate-transparency")]
        {
            cfg.ct_logs = Some(&ct_logs::LOGS);
        }
        Arc::new(cfg)
    }

    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, ConnectError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;
        Ok(TlsSession {
            inner: SessionKind::Client(rustls::ClientSession::new_quic(
                self,
                pki_server_name,
                to_vec(params),
            )),
        })
    }
}

impl crypto::ServerConfig<TlsSession> for Arc<rustls::ServerConfig> {
    fn new() -> Self {
        let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        cfg.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        cfg.max_early_data_size = u32::max_value();
        Arc::new(cfg)
    }

    fn start_session(&self, params: &TransportParameters) -> TlsSession {
        TlsSession {
            inner: SessionKind::Server(rustls::ServerSession::new_quic(self, to_vec(params))),
        }
    }
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload) = buf.split_at_mut(header_len);
        let (payload, tag_storage) =
            payload.split_at_mut(payload.len() - self.key.algorithm().tag_len());
        let aad = aead::Aad::from(header);
        let nonce = self.iv.nonce_for(packet);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, payload)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()> {
        if payload.len() < self.key.algorithm().tag_len() {
            return Err(());
        }

        let payload_len = payload.len();
        let aad = aead::Aad::from(header);
        let nonce = self.iv.nonce_for(packet);
        self.key
            .open_in_place(nonce, aad, payload.as_mut())
            .map_err(|_| ())?;
        payload.truncate(payload_len - self.key.algorithm().tag_len());
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }
}
