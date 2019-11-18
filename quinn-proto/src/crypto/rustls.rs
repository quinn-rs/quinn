use std::{
    fmt, io,
    ops::{Deref, DerefMut},
    str,
    sync::Arc,
};

use ring::{hkdf, hmac};
pub use rustls::TLSError;
use rustls::{
    self,
    internal::{msgs::enums::HashAlgorithm, pemfile},
    quic::{ClientQuicExt, Secrets, ServerQuicExt},
    KeyLogFile, NoClientAuth, ProtocolVersion, Session,
};
use webpki::DNSNameRef;

use super::ring::{hkdf_expand, Crypto};
use crate::{
    crypto, transport_parameters::TransportParameters, ConnectError, Side, TransportError,
    TransportErrorCode,
};

/// A rustls TLS session
pub enum TlsSession {
    #[doc(hidden)]
    Client(rustls::ClientSession),
    #[doc(hidden)]
    Server(rustls::ServerSession),
}

impl TlsSession {
    fn side(&self) -> Side {
        match self {
            TlsSession::Client(_) => Side::Client,
            TlsSession::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    type ClientConfig = ClientConfig;
    type HmacKey = hmac::Key;
    type Keys = Crypto;
    type ServerConfig = ServerConfig;

    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    fn early_crypto(&self) -> Option<Self::Keys> {
        let secret = self.get_early_secret()?;
        // If an early secret is known, TLS guarantees it's associated with a resumption
        // ciphersuite,
        let suite = self.get_negotiated_ciphersuite().unwrap();
        Some(Crypto::new(
            self.side(),
            suite.get_aead_alg(),
            secret.clone(),
            secret.clone(),
        ))
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

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Self::Keys> {
        let secrets = self.write_hs(buf)?;
        let suite = self
            .get_negotiated_ciphersuite()
            .expect("should not get secrets without cipher suite");
        Some(Crypto::new(
            self.side(),
            suite.get_aead_alg(),
            secrets.client,
            secrets.server,
        ))
    }

    fn update_keys(&self, keys: &Self::Keys) -> Self::Keys {
        let (client_secret, server_secret) = match self.side() {
            Side::Client => (&keys.local_secret, &keys.remote_secret),
            Side::Server => (&keys.remote_secret, &keys.local_secret),
        };

        let hash_alg = self
            .get_negotiated_ciphersuite()
            .expect("should not get secrets without cipher suite")
            .hash;
        let secrets = update_secrets(hash_alg, client_secret, server_secret);
        let suite = self.get_negotiated_ciphersuite().unwrap();
        Crypto::new(
            self.side(),
            suite.get_aead_alg(),
            secrets.client,
            secrets.server,
        )
    }
}

impl Deref for TlsSession {
    type Target = dyn rustls::Session;
    fn deref(&self) -> &Self::Target {
        match *self {
            TlsSession::Client(ref session) => session,
            TlsSession::Server(ref session) => session,
        }
    }
}

impl DerefMut for TlsSession {
    fn deref_mut(&mut self) -> &mut (dyn rustls::Session + 'static) {
        match *self {
            TlsSession::Client(ref mut session) => session,
            TlsSession::Server(ref mut session) => session,
        }
    }
}

/// rustls configuration for client sessions
#[derive(Clone)]
pub struct ClientConfig(Arc<rustls::ClientConfig>);

impl ClientConfig {
    /// Initialize new configuration with an existing rustls `ClientConfig`
    pub fn new(config: rustls::ClientConfig) -> Self {
        Self(Arc::new(config))
    }

    /// Add a trusted certificate authority.
    ///
    /// For more advanced/less secure certificate verification, construct a [`ClientConfig`]
    /// manually and use rustls's `dangerous_configuration` feature to override the certificate
    /// verifier.
    pub fn add_certificate_authority(&mut self, cert: Certificate) -> Result<(), webpki::Error> {
        let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(&cert.inner.0)?;
        Arc::make_mut(&mut self.0)
            .root_store
            .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&[anchor]));
        Ok(())
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) {
        Arc::make_mut(&mut self.0).key_log = Arc::new(KeyLogFile::new());
    }

    /// Set the application-layer protocols to accept, in order of descending preference
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn set_protocols(&mut self, protocols: &[&[u8]]) {
        Arc::make_mut(&mut self.0).alpn_protocols = protocols.iter().map(|x| x.to_vec()).collect();
    }
}

impl Default for ClientConfig {
    fn default() -> ClientConfig {
        let mut cfg = rustls::ClientConfig::new();
        cfg.versions = vec![ProtocolVersion::TLSv1_3];
        cfg.enable_early_data = true;
        Self(Arc::new(cfg))
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "ClientConfig(rustls::ClientConfig)")
    }
}

impl Deref for ClientConfig {
    type Target = Arc<rustls::ClientConfig>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClientConfig {
    fn deref_mut(&mut self) -> &mut Arc<rustls::ClientConfig> {
        &mut self.0
    }
}

impl crypto::ClientConfig<TlsSession> for ClientConfig {
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, ConnectError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;
        Ok(TlsSession::Client(rustls::ClientSession::new_quic(
            &self.0,
            pki_server_name,
            to_vec(params),
        )))
    }
}

/// rustls configuration for server sessions
#[derive(Clone)]
pub struct ServerConfig(Arc<rustls::ServerConfig>);

impl ServerConfig {
    /// Initialize new configuration with an existing rustls `ServerConfig`
    pub fn new(config: rustls::ServerConfig) -> Self {
        Self(Arc::new(config))
    }

    /// Set the certificate chain that will be presented to clients
    pub fn set_certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<(), TLSError> {
        Arc::make_mut(&mut self.0).set_single_cert(cert_chain.certs, key.inner)?;
        Ok(())
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) {
        Arc::make_mut(&mut self.0).key_log = Arc::new(KeyLogFile::new());
    }

    /// Set the application-layer protocols to accept, in order of descending preference
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn set_protocols(&mut self, protocols: &[&[u8]]) {
        Arc::make_mut(&mut self.0).alpn_protocols = protocols.iter().map(|x| x.to_vec()).collect();
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "ServerConfig(rustls::ServerConfig)")
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let mut cfg = rustls::ServerConfig::new(NoClientAuth::new());
        cfg.versions = vec![ProtocolVersion::TLSv1_3];
        cfg.max_early_data_size = u32::max_value();
        Self(Arc::new(cfg))
    }
}

impl crypto::ServerConfig<TlsSession> for ServerConfig {
    fn start_session(&self, params: &TransportParameters) -> TlsSession {
        TlsSession::Server(rustls::ServerSession::new_quic(&self.0, to_vec(params)))
    }
}

impl Deref for ServerConfig {
    type Target = Arc<rustls::ServerConfig>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ServerConfig {
    fn deref_mut(&mut self) -> &mut Arc<rustls::ServerConfig> {
        &mut self.0
    }
}

/// A single TLS certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    inner: rustls::Certificate,
}

impl Certificate {
    /// Parse a DER-formatted certificate
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {
            inner: rustls::Certificate(der.to_vec()),
        })
    }
}

/// A chain of signed TLS certificates ending the one to be used by a server
#[derive(Debug, Clone)]
pub struct CertificateChain {
    certs: Vec<rustls::Certificate>,
}

impl CertificateChain {
    /// Parse a PEM-formatted certificate chain
    ///
    /// ```no_run
    /// let pem = std::fs::read("fullchain.pem").expect("error reading certificates");
    /// let cert_chain = quinn_proto::crypto::rustls::PrivateKey::from_pem(&pem).expect("error parsing certificates");
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {
            certs: pemfile::certs(&mut &pem[..])
                .map_err(|()| ParseError("malformed certificate chain"))?,
        })
    }

    /// Construct a certificate chain from a list of certificates
    pub fn from_certs(certs: impl IntoIterator<Item = Certificate>) -> Self {
        certs.into_iter().collect()
    }
}

impl std::iter::FromIterator<Certificate> for CertificateChain {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Certificate>,
    {
        CertificateChain {
            certs: iter.into_iter().map(|x| x.inner).collect(),
        }
    }
}

/// The private key of a TLS certificate to be used by a server
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: rustls::PrivateKey,
}

impl PrivateKey {
    /// Parse a PEM-formatted private key
    ///
    /// ```no_run
    /// let pem = std::fs::read("key.pem").expect("error reading key");
    /// let key = quinn_proto::crypto::rustls::PrivateKey::from_pem(&pem).expect("error parsing key");
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self, ParseError> {
        let pkcs8 = pemfile::pkcs8_private_keys(&mut &pem[..])
            .map_err(|()| ParseError("malformed PKCS #8 private key"))?;
        if let Some(x) = pkcs8.into_iter().next() {
            return Ok(Self { inner: x });
        }
        let rsa = pemfile::rsa_private_keys(&mut &pem[..])
            .map_err(|()| ParseError("malformed PKCS #1 private key"))?;
        if let Some(x) = rsa.into_iter().next() {
            return Ok(Self { inner: x });
        }
        Err(ParseError("no private key found"))
    }

    /// Parse a DER-encoded (binary) private key
    pub fn from_der(der: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {
            inner: rustls::PrivateKey(der.to_vec()),
        })
    }
}

fn update_secrets(hash_alg: HashAlgorithm, client: &hkdf::Prk, server: &hkdf::Prk) -> Secrets {
    let hkdf_alg = match hash_alg {
        HashAlgorithm::SHA256 => hkdf::HKDF_SHA256,
        HashAlgorithm::SHA384 => hkdf::HKDF_SHA384,
        HashAlgorithm::SHA512 => hkdf::HKDF_SHA512,
        _ => panic!("unknown HKDF algorithm for hash algorithm {:?}", hash_alg),
    };

    Secrets {
        client: hkdf_expand(client, b"quic ku", hkdf_alg),
        server: hkdf_expand(server, b"quic ku", hkdf_alg),
    }
}

/// Errors encountered while parsing a TLS certificate or private key
#[derive(Debug, Clone)]
pub struct ParseError(&'static str);

impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad(self.0)
    }
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}
