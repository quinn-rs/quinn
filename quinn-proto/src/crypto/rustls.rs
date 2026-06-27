use std::{any::Any, io, str, sync::Arc};

use crate::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};
use bytes::BytesMut;
pub use rustls::Error;
#[cfg(feature = "__rustls-post-quantum-test")]
use rustls::crypto::kx::NamedGroup;
use rustls::{
    self,
    client::danger::ServerVerifier,
    crypto::{
        CipherSuite, Identity,
        cipher::{AeadKey, Iv},
    },
    error::AlertDescription,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    quic::{
        ClientConnection, Connection as _, DirectionalKeys, HeaderProtectionKey, KeyChange,
        PacketKey, Secrets, ServerConnection, Side as QuicSide, Suite, Version,
    },
};
#[cfg(feature = "platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;

impl From<Side> for QuicSide {
    fn from(s: Side) -> Self {
        match s {
            Side::Client => Self::Client,
            Side::Server => Self::Server,
        }
    }
}

/// A rustls TLS session
pub struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    exporter: Option<rustls::KeyingMaterialExporter>,
    inner: QuicConnection,
    suite: Suite,
}

impl TlsSession {
    fn side(&self) -> Side {
        self.inner.side()
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: self.inner.server_name().map(str::to_owned),
            protocol_version: match &self.inner {
                QuicConnection::Client(session) => session.protocol_version(),
                QuicConnection::Server(session) => session.protocol_version(),
            }
            .map(|x| -> Box<dyn Any> { Box::new(x) }),
            cipher_suite: match &self.inner {
                QuicConnection::Client(session) => session.negotiated_cipher_suite(),
                QuicConnection::Server(session) => session.negotiated_cipher_suite(),
            }
            .map(|suite| -> Box<dyn Any> { Box::new(suite.suite()) }),
            #[cfg(feature = "__rustls-post-quantum-test")]
            negotiated_key_exchange_group: self
                .inner
                .negotiated_key_exchange_group()
                .expect("key exchange group is negotiated"),
        }))
    }

    /// For the rustls `TlsSession`, the `Any` type is `rustls::crypto::Identity<'static>`
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner
            .peer_identity()
            .cloned()
            .map(|identity| -> Box<dyn Any> { Box::new(identity) })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.is_early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Ok(alert) = AlertDescription::try_from(&e) {
                TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string(),
                    crypto: Some(Arc::new(e)),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
            }
        })?;
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = self.inner.server_name().is_some();
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(&orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        retry_key_for_version(self.version, &self.suite)
            .decrypt_in_place(0, aad, tag, None)
            .is_ok()
    }

    fn export_keying_material(
        &mut self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        if self.exporter.is_none() {
            self.exporter = Some(
                self.inner
                    .exporter()
                    .map_err(|_| ExportKeyingMaterialError)?,
            );
        }

        self.exporter
            .as_ref()
            .expect("exporter is set")
            .derive(label, Some(context), output)
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

enum QuicConnection {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl QuicConnection {
    fn side(&self) -> Side {
        match self {
            Self::Client(_) => Side::Client,
            Self::Server(_) => Side::Server,
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Client(session) => session.alpn_protocol(),
            Self::Server(session) => session.alpn_protocol(),
        }
        .map(AsRef::as_ref)
    }

    fn peer_identity(&self) -> Option<&Identity<'static>> {
        match self {
            Self::Client(session) => session.peer_identity(),
            Self::Server(session) => session.peer_identity(),
        }
    }

    fn zero_rtt_keys(&self) -> Option<DirectionalKeys> {
        match self {
            Self::Client(session) => session.zero_rtt_keys(),
            Self::Server(session) => session.zero_rtt_keys(),
        }
    }

    fn is_early_data_accepted(&self) -> Option<bool> {
        match self {
            Self::Client(session) => Some(session.is_early_data_accepted()),
            Self::Server(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(session) => session.is_handshaking(),
            Self::Server(session) => session.is_handshaking(),
        }
    }

    fn read_hs(&mut self, buf: &[u8]) -> Result<(), Error> {
        match self {
            Self::Client(session) => session.read_hs(buf),
            Self::Server(session) => session.read_hs(buf),
        }
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            Self::Client(session) => session.write_hs(buf),
            Self::Server(session) => session.write_hs(buf),
        }
    }

    fn quic_transport_parameters(&self) -> Option<&[u8]> {
        match self {
            Self::Client(session) => session.quic_transport_parameters(),
            Self::Server(session) => session.quic_transport_parameters(),
        }
    }

    fn server_name(&self) -> Option<&str> {
        match self {
            Self::Client(_) => None,
            Self::Server(session) => session.server_name().map(AsRef::as_ref),
        }
    }

    #[cfg(feature = "__rustls-post-quantum-test")]
    fn negotiated_key_exchange_group(&self) -> Option<NamedGroup> {
        match self {
            Self::Client(session) => session.negotiated_key_exchange_group(),
            Self::Server(session) => session.negotiated_key_exchange_group(),
        }
        .map(|group| group.name())
    }

    fn exporter(&mut self) -> Result<rustls::KeyingMaterialExporter, Error> {
        match self {
            Self::Client(session) => session.exporter(),
            Self::Server(session) => session.exporter(),
        }
    }
}

fn retry_key_for_version(version: Version, initial_suite: &Suite) -> Box<dyn PacketKey> {
    let (nonce, key) = match version {
        Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
        _ => unreachable!(),
    };

    initial_suite
        .quic
        .packet_key(AeadKey::from(key), Iv::from(nonce))
}

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

impl HeaderKey for Box<dyn HeaderProtectionKey> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// Authentication data for (rustls) TLS session
#[non_exhaustive]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
    /// The protocol version negotiated with the peer, if any
    pub protocol_version: Option<Box<dyn Any>>,
    /// The cipher suite negotiated with the peer, if any
    pub cipher_suite: Option<Box<dyn Any>>,
    /// The key exchange group negotiated with the peer
    #[cfg(feature = "__rustls-post-quantum-test")]
    pub negotiated_key_exchange_group: NamedGroup,
}

/// A QUIC-compatible TLS client configuration
///
/// Quinn implicitly constructs a `QuicClientConfig` with reasonable defaults within
/// [`ClientConfig::with_root_certificates()`][root_certs] and
/// [`ClientConfig::try_with_platform_verifier()`][platform].
/// Alternatively, `QuicClientConfig`'s [`TryFrom`] implementation can be used to wrap around a
/// custom [`rustls::ClientConfig`], in which case care should be taken around certain points:
///
/// - If `enable_early_data` is not set to true, then sending 0-RTT data will not be possible on
///   outgoing connections.
/// - The [`rustls::ClientConfig`] must have TLS 1.3 support enabled for conversion to succeed.
///
/// The object in the `resumption` field of the inner [`rustls::ClientConfig`] determines whether
/// calling `into_0rtt` on outgoing connections returns `Ok` or `Err`. It typically allows
/// `into_0rtt` to proceed if it recognizes the server name, and defaults to an in-memory cache of
/// 256 server names.
///
/// [root_certs]: crate::config::ClientConfig::with_root_certificates()
/// [platform]: crate::config::ClientConfig::try_with_platform_verifier()
pub struct QuicClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    #[cfg(feature = "platform-verifier")]
    pub(crate) fn with_platform_verifier() -> Result<Self, Error> {
        let mut inner = rustls::ClientConfig::builder(configured_provider())
            .with_platform_verifier()?
            .with_no_client_auth()
            .expect("default providers are valid for QUIC");

        inner.enable_early_data = true;
        Ok(Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256.
            initial: initial_suite_from_provider(inner.provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a sane QUIC-compatible TLS client configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rustls::ClientConfig`] that
    /// satisfies this requirement.
    pub(crate) fn new(verifier: Arc<dyn ServerVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256.
            initial: initial_suite_from_provider(inner.provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        }
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ClientConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    pub(crate) fn inner(verifier: Arc<dyn ServerVerifier>) -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::builder(configured_provider())
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
            .expect("default providers are valid for QUIC");

        config.enable_early_data = true;
        config
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        Ok(Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            exporter: None,
            inner: QuicConnection::Client(
                ClientConnection::new(
                    self.inner.clone(),
                    version,
                    ServerName::try_from(server_name)
                        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
                        .to_owned(),
                    to_vec(params),
                )
                .unwrap(),
            ),
            suite: self.initial,
        }))
    }
}

impl TryFrom<rustls::ClientConfig> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ClientConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ClientConfig>> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ClientConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

/// The initial cipher suite (AES-128-GCM-SHA256) is not available
///
/// When the cipher suite is supplied `with_initial()`, it must be
/// [`CipherSuite::TLS13_AES_128_GCM_SHA256`]. When the cipher suite is derived from a config's
/// [`CryptoProvider`][provider], that provider must reference a cipher suite with the same ID.
///
/// [provider]: rustls::crypto::CryptoProvider
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    /// Whether the initial cipher suite was supplied by the caller
    specific: bool,
}

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.specific {
            true => "invalid cipher suite specified",
            false => "no initial cipher suite found",
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS server configuration
///
/// Quinn implicitly constructs a `QuicServerConfig` with reasonable defaults within
/// [`ServerConfig::with_single_cert()`][single]. Alternatively, `QuicServerConfig`'s [`TryFrom`]
/// implementation or `with_initial` method can be used to wrap around a custom
/// [`rustls::ServerConfig`], in which case care should be taken around certain points:
///
/// - If `max_early_data_size` is not set to `u32::MAX`, the server will not be able to accept
///   incoming 0-RTT data. QUIC prohibits `max_early_data_size` values other than 0 or `u32::MAX`.
/// - The `rustls::ServerConfig` must have TLS 1.3 support enabled for conversion to succeed.
///
/// [single]: crate::config::ServerConfig::with_single_cert()
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl QuicServerConfig {
    pub(crate) fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            // We're confident that the default providers contain TLS13_AES_128_GCM_SHA256.
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ServerConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self { inner, initial }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    /// Initialize a sane QUIC-compatible TLS server configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
    /// `u32::MAX`. Advanced users can use any [`rustls::ServerConfig`] that satisfies these
    /// requirements.
    pub(crate) fn inner(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<rustls::ServerConfig, Error> {
        let mut inner = rustls::ServerConfig::builder(configured_provider())
            .with_no_client_auth()
            .with_single_cert(Arc::new(Identity::from_cert_chain(cert_chain)?), key)?;

        inner.max_early_data_size = u32::MAX;
        Ok(inner)
    }
}

impl TryFrom<rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ServerConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            exporter: None,
            inner: QuicConnection::Server(
                ServerConnection::new(self.inner.clone(), version, to_vec(params)).unwrap(),
            ),
            suite: self.initial,
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(&orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let tag = retry_key_for_version(version, &self.initial)
            .encrypt_in_place(0, &pseudo_packet, &mut [], None)
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

pub(crate) fn initial_suite_from_provider(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Option<Suite> {
    provider
        .tls13_cipher_suites
        .iter()
        .find_map(|&suite| match suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => suite.quic_suite(),
            _ => None,
        })
}

pub(crate) fn configured_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(all(feature = "rustls-aws-lc-rs", not(feature = "rustls-ring")))]
    let provider = rustls_aws_lc_rs::DEFAULT_PROVIDER;
    #[cfg(feature = "rustls-ring")]
    let provider = rustls_ring::DEFAULT_PROVIDER;
    Arc::new(provider)
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

pub(crate) fn initial_keys(
    version: Version,
    dst_cid: ConnectionId,
    side: Side,
    suite: &Suite,
) -> Keys {
    let keys = suite.keys(&dst_cid, side.into(), version);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

impl crypto::PacketKey for Box<dyn PacketKey> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self
            .encrypt_in_place(packet, &*header, payload, None)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload.as_mut(), None)
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        (**self).confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        (**self).integrity_limit()
    }
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}
