use std::{any::Any, io, mem, str, sync::Arc};

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::aead;
use bytes::BytesMut;
#[cfg(feature = "ring")]
use ring::aead;
pub use rustls::Error;
#[cfg(feature = "__rustls-post-quantum-test")]
use rustls::NamedGroup;
use rustls::{
    self, CipherSuite,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, DnsName, PrivateKeyDer, ServerName},
    quic::{Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version},
};
#[cfg(feature = "platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;

use crate::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};

impl From<Side> for rustls::Side {
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
    inner: Connection,
    suite: Suite,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: match self.inner {
                Connection::Client(_) => None,
                Connection::Server(ref session) => session.server_name().map(|x| x.into()),
            },
            #[cfg(feature = "__rustls-post-quantum-test")]
            negotiated_key_exchange_group: self
                .inner
                .negotiated_key_exchange_group()
                .expect("key exchange group is negotiated")
                .name(),
        }))
    }

    /// For the rustls `TlsSession`, the `Any` type is `Vec<rustls::pki_types::CertificateDer>`
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().map(|v| -> Box<dyn Any> {
            Box::new(
                v.iter()
                    .map(|v| v.clone().into_owned())
                    .collect::<Vec<CertificateDer<'static>>>(),
            )
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
            }
        })?;
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
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

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        retry_tag_is_valid(self.version, *orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner
            .export_keying_material(output, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

impl crypto::HeaderKey for Box<dyn HeaderProtectionKey> {
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
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
    /// The key exchange group negotiated with the peer
    #[cfg(feature = "__rustls-post-quantum-test")]
    pub negotiated_key_exchange_group: NamedGroup,
}

/// ClientHello data available before a server TLS configuration has been selected
#[derive(Clone, Copy, Debug)]
pub struct ClientHello<'a> {
    server_name: Option<&'a str>,
    alpn_protocols: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> {
    /// The server name specified by the client, if any
    pub fn server_name(&self) -> Option<&'a str> {
        self.server_name
    }

    /// The ALPN protocol identifiers submitted by the client, if any
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn_protocols
            .map(|bytes| ClientHelloAlpnProtocols { bytes })
    }
}

/// ALPN protocol identifiers submitted in a [`ClientHello`]
#[derive(Clone, Debug)]
struct ClientHelloAlpnProtocols<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ClientHelloAlpnProtocols<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (&len, rest) = self.bytes.split_first()?;
        let len = usize::from(len);
        if rest.len() < len {
            self.bytes = &[];
            return None;
        }
        let (protocol, rest) = rest.split_at(len);
        self.bytes = rest;
        Some(protocol)
    }
}

/// Selects a rustls server configuration from ClientHello data
pub trait ServerConfigSelector: Send + Sync + 'static {
    /// Return `Some` to use a specific configuration, or `None` to use the default.
    fn select(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::ServerConfig>>;
}

impl<F> ServerConfigSelector for F
where
    F: for<'a> Fn(ClientHello<'a>) -> Option<Arc<rustls::ServerConfig>> + Send + Sync + 'static,
{
    fn select(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::ServerConfig>> {
        self(client_hello)
    }
}

/// A QUIC-compatible TLS client configuration
///
/// Quinn implicitly constructs a `QuicClientConfig` with reasonable defaults within
/// [`ClientConfig::with_root_certificates()`][root_certs] and [`ClientConfig::with_platform_verifier()`][platform].
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
/// [platform]: crate::config::ClientConfig::with_platform_verifier()
pub struct QuicClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    #[cfg(feature = "platform-verifier")]
    pub(crate) fn with_platform_verifier() -> Result<Self, Error> {
        // Keep in sync with `inner()` below
        let mut inner = rustls::ClientConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap() // The default providers support TLS 1.3
            .with_platform_verifier()?
            .with_no_client_auth();

        inner.enable_early_data = true;
        Ok(Self {
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a sane QUIC-compatible TLS client configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rustls::ClientConfig`] that
    /// satisfies this requirement.
    pub(crate) fn new(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
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

    pub(crate) fn inner(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
        // Keep in sync with `with_platform_verifier()` above
        let mut config = rustls::ClientConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap() // The default providers support TLS 1.3
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

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
            inner: rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
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
            initial: initial_suite_from_provider(inner.crypto_provider())
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
    ) -> Result<Self, rustls::Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
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
    ) -> Result<rustls::ServerConfig, rustls::Error> {
        let mut inner = rustls::ServerConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap() // The *ring* default provider supports TLS 1.3
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

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

/// A QUIC-compatible TLS server configuration selected using ClientHello data
///
/// This is useful when a server needs to select a complete [`rustls::ServerConfig`]
/// based on SNI or ALPN. The default configuration is used for QUIC Initial key
/// derivation and as a fallback when the selector returns `None`.
///
/// ClientHello data is buffered until the complete message is available. The
/// selected configurations must be valid for rustls QUIC server connections.
pub struct ClientHelloServerConfig {
    default: Arc<rustls::ServerConfig>,
    selector: Arc<dyn ServerConfigSelector>,
    initial: Suite,
}

impl ClientHelloServerConfig {
    /// Create a server configuration that selects the final rustls config per connection
    pub fn new<S>(
        default: Arc<rustls::ServerConfig>,
        selector: S,
    ) -> Result<Self, NoInitialCipherSuite>
    where
        S: ServerConfigSelector,
    {
        Ok(Self {
            initial: initial_suite_from_provider(default.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            default,
            selector: Arc::new(selector),
        })
    }
}

impl crypto::ServerConfig for ClientHelloServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        let mut encoded_params = Vec::new();
        params.write(&mut encoded_params);
        Box::new(ClientHelloSession {
            suite: self.initial,
            state: ClientHelloSessionState::Reading {
                version,
                params: encoded_params,
                default: self.default.clone(),
                selector: self.selector.clone(),
                buffered: Vec::new(),
            },
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        retry_tag(version, *orig_dst_cid, packet)
    }
}

struct ClientHelloSession {
    suite: Suite,
    state: ClientHelloSessionState,
}

enum ClientHelloSessionState {
    Reading {
        version: Version,
        params: Vec<u8>,
        default: Arc<rustls::ServerConfig>,
        selector: Arc<dyn ServerConfigSelector>,
        buffered: Vec<u8>,
    },
    Active(Box<TlsSession>),
}

impl ClientHelloSession {
    fn active(&self) -> Option<&TlsSession> {
        match &self.state {
            ClientHelloSessionState::Active(session) => Some(session),
            ClientHelloSessionState::Reading { .. } => None,
        }
    }

    fn active_mut(&mut self) -> Option<&mut TlsSession> {
        match &mut self.state {
            ClientHelloSessionState::Active(session) => Some(session),
            ClientHelloSessionState::Reading { .. } => None,
        }
    }
}

impl crypto::Session for ClientHelloSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version(), *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.active()?.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.active()?.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.active()?.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.active()?.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.active()
            .map(TlsSession::is_handshaking)
            .unwrap_or(true)
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if let Some(session) = self.active_mut() {
            return session.read_handshake(buf);
        }

        let ClientHelloSessionState::Reading {
            version,
            params,
            default,
            selector,
            buffered,
        } = &mut self.state
        else {
            unreachable!();
        };

        if buffered
            .len()
            .checked_add(buf.len())
            .is_none_or(|len| len > MAX_BUFFERED_CLIENT_HELLO)
        {
            return Err(ClientHelloParseError::Invalid.into());
        }
        buffered.extend_from_slice(buf);
        let Some(client_hello) = parse_client_hello(buffered)? else {
            return Ok(false);
        };

        let config = selector
            .select(client_hello)
            .unwrap_or_else(|| default.clone());
        let mut session = TlsSession {
            version: *version,
            got_handshake_data: false,
            next_secrets: None,
            inner: rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(config, *version, mem::take(params))
                    .map_err(config_error)?,
            ),
            suite: self.suite,
        };
        let buffered = mem::take(buffered);
        let result = session.read_handshake(&buffered)?;
        self.state = ClientHelloSessionState::Active(Box::new(session));
        Ok(result)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.active() {
            Some(session) => session.transport_parameters(),
            None => Ok(None),
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.active_mut()?.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        self.active_mut()?.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        match self.active() {
            Some(session) => session.is_valid_retry(orig_dst_cid, header, payload),
            None => retry_tag_is_valid(self.version(), *orig_dst_cid, header, payload),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        match self.active() {
            Some(session) => session.export_keying_material(output, label, context),
            None => Err(ExportKeyingMaterialError),
        }
    }
}

impl ClientHelloSession {
    fn version(&self) -> Version {
        match &self.state {
            ClientHelloSessionState::Reading { version, .. } => *version,
            ClientHelloSessionState::Active(session) => session.version,
        }
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
            inner: rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(self.inner.clone(), version, to_vec(params))
                    .unwrap(),
            ),
            suite: self.initial,
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let version = interpret_version(version).unwrap();
        retry_tag(version, *orig_dst_cid, packet)
    }
}

fn config_error(error: rustls::Error) -> TransportError {
    TransportError::INTERNAL_ERROR(format!("TLS config error: {error}"))
}

#[derive(Debug)]
enum ClientHelloParseError {
    Invalid,
}

impl From<ClientHelloParseError> for TransportError {
    fn from(_: ClientHelloParseError) -> Self {
        Self::PROTOCOL_VIOLATION("invalid TLS ClientHello")
    }
}

const CLIENT_HELLO_HEADER_LEN: usize = 4;
// Match rustls' maximum TLS handshake message size.
const MAX_CLIENT_HELLO_SIZE: usize = 0xffff;
const MAX_BUFFERED_CLIENT_HELLO: usize = CLIENT_HELLO_HEADER_LEN + MAX_CLIENT_HELLO_SIZE;

fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHello<'_>>, ClientHelloParseError> {
    const CLIENT_HELLO: u8 = 1;

    if buf.len() < CLIENT_HELLO_HEADER_LEN {
        return Ok(None);
    }
    if buf[0] != CLIENT_HELLO {
        return Err(ClientHelloParseError::Invalid);
    }

    let len = (usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]);
    if len > MAX_CLIENT_HELLO_SIZE {
        return Err(ClientHelloParseError::Invalid);
    }
    let Some(end) = CLIENT_HELLO_HEADER_LEN.checked_add(len) else {
        return Err(ClientHelloParseError::Invalid);
    };
    if buf.len() < end {
        return Ok(None);
    }

    let mut reader = ClientHelloReader::new(&buf[CLIENT_HELLO_HEADER_LEN..end]);
    reader.take(2)?; // legacy_version
    reader.take(32)?; // random
    let session_id_len = usize::from(reader.take_u8()?);
    reader.take(session_id_len)?;
    let cipher_suites_len = usize::from(reader.take_u16()?);
    if cipher_suites_len % 2 != 0 {
        return Err(ClientHelloParseError::Invalid);
    }
    reader.take(cipher_suites_len)?;
    let compression_methods_len = usize::from(reader.take_u8()?);
    reader.take(compression_methods_len)?;

    let mut server_name_seen = false;
    let mut server_name = None;
    let mut alpn_protocols = None;
    if !reader.is_empty() {
        let extensions_len = usize::from(reader.take_u16()?);
        let mut extensions = ClientHelloReader::new(reader.take(extensions_len)?);
        if !reader.is_empty() {
            return Err(ClientHelloParseError::Invalid);
        }

        while !extensions.is_empty() {
            let extension_type = extensions.take_u16()?;
            let extension_len = usize::from(extensions.take_u16()?);
            let extension = extensions.take(extension_len)?;
            match extension_type {
                0 => {
                    if server_name_seen {
                        return Err(ClientHelloParseError::Invalid);
                    }
                    server_name_seen = true;
                    server_name = parse_server_name(extension)?;
                }
                16 => {
                    if alpn_protocols.is_some() {
                        return Err(ClientHelloParseError::Invalid);
                    }
                    alpn_protocols = Some(parse_alpn_protocols(extension)?);
                }
                _ => {}
            }
        }
    }

    Ok(Some(ClientHello {
        server_name,
        alpn_protocols,
    }))
}

fn parse_server_name(buf: &[u8]) -> Result<Option<&str>, ClientHelloParseError> {
    let mut reader = ClientHelloReader::new(buf);
    let names_len = usize::from(reader.take_u16()?);
    let mut names = ClientHelloReader::new(reader.take(names_len)?);
    if !reader.is_empty() {
        return Err(ClientHelloParseError::Invalid);
    }

    let mut server_name = None;
    while !names.is_empty() {
        let name_type = names.take_u8()?;
        let name_len = usize::from(names.take_u16()?);
        let name = names.take(name_len)?;
        if name_type == 0 {
            if server_name.is_some() {
                return Err(ClientHelloParseError::Invalid);
            }
            DnsName::try_from(name).map_err(|_| ClientHelloParseError::Invalid)?;
            server_name = Some(str::from_utf8(name).map_err(|_| ClientHelloParseError::Invalid)?);
        }
    }

    Ok(server_name)
}

fn parse_alpn_protocols(buf: &[u8]) -> Result<&[u8], ClientHelloParseError> {
    let mut reader = ClientHelloReader::new(buf);
    let protocols_len = usize::from(reader.take_u16()?);
    let protocols = reader.take(protocols_len)?;
    if !reader.is_empty() {
        return Err(ClientHelloParseError::Invalid);
    }

    let mut reader = ClientHelloReader::new(protocols);
    while !reader.is_empty() {
        let protocol_len = usize::from(reader.take_u8()?);
        if protocol_len == 0 {
            return Err(ClientHelloParseError::Invalid);
        }
        reader.take(protocol_len)?;
    }

    Ok(protocols)
}

struct ClientHelloReader<'a> {
    bytes: &'a [u8],
}

impl<'a> ClientHelloReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ClientHelloParseError> {
        if self.bytes.len() < len {
            return Err(ClientHelloParseError::Invalid);
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn take_u8(&mut self) -> Result<u8, ClientHelloParseError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, ClientHelloParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

fn retry_tag(version: Version, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
    let (nonce, key) = match version {
        Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
        Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
        _ => unreachable!(),
    };

    let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(&orig_dst_cid);
    pseudo_packet.extend_from_slice(packet);

    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

    let tag = key
        .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
        .unwrap();
    let mut result = [0; 16];
    result.copy_from_slice(tag.as_ref());
    result
}

fn retry_tag_is_valid(
    version: Version,
    orig_dst_cid: ConnectionId,
    header: &[u8],
    payload: &[u8],
) -> bool {
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

    let (nonce, key) = match version {
        Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
        Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
        _ => unreachable!(),
    };

    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

    let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
    key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
}

pub(crate) fn initial_suite_from_provider(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
}

pub(crate) fn configured_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(all(feature = "rustls-aws-lc-rs", not(feature = "rustls-ring")))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "rustls-ring")]
    let provider = rustls::crypto::ring::default_provider();
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
        let tag = self.encrypt_in_place(packet, &*header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload.as_mut())
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
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}
