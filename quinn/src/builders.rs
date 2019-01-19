use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::str;
use std::sync::Arc;
use std::time::Instant;

use err_derive::Error;
use fnv::FnvHashMap;
use futures::stream::futures_unordered::FuturesUnordered;
use quinn_proto as quinn;
use rustls::{KeyLogFile, ProtocolVersion, TLSError};
use slog::Logger;

use quinn_proto::{Config, ServerConfig};

use crate::tls::{Certificate, CertificateChain, PrivateKey};
use crate::udp::UdpSocket;
use crate::{Driver, Endpoint, EndpointInner, Incoming};

/// A helper for constructing an `Endpoint`.
pub struct EndpointBuilder<'a> {
    reactor: Option<&'a tokio_reactor::Handle>,
    logger: Logger,
    server_config: Option<ServerConfig>,
    config: Config,
    client_config: ClientConfig,
}

#[allow(missing_docs)]
impl<'a> EndpointBuilder<'a> {
    /// Start a builder with a specific initial low-level configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Build an endpoint bound to `addr`.
    pub fn bind<T: ToSocketAddrs>(
        self,
        addr: T,
    ) -> Result<(Endpoint, Driver, Incoming), EndpointError> {
        let socket = std::net::UdpSocket::bind(addr).map_err(EndpointError::Socket)?;
        self.from_socket(socket)
    }

    /// Build an endpoint around a pre-configured socket.
    pub fn from_socket(
        self,
        socket: std::net::UdpSocket,
    ) -> Result<(Endpoint, Driver, Incoming), EndpointError> {
        let reactor = if let Some(x) = self.reactor {
            Cow::Borrowed(x)
        } else {
            Cow::Owned(tokio_reactor::Handle::default())
        };
        let addr = socket.local_addr().map_err(EndpointError::Socket)?;
        let socket = UdpSocket::from_std(socket, &reactor).map_err(EndpointError::Socket)?;
        let (send, recv) = futures::sync::mpsc::channel(4);
        let rc = Rc::new(RefCell::new(EndpointInner {
            log: self.logger.clone(),
            socket,
            inner: quinn::Endpoint::new(self.logger, self.config, self.server_config)?,
            outgoing: None,
            epoch: Instant::now(),
            pending: FnvHashMap::default(),
            timers: FuturesUnordered::new(),
            buffered_incoming: VecDeque::new(),
            incoming: send,
            driver: None,
            ipv6: addr.is_ipv6(),
        }));
        Ok((
            Endpoint {
                inner: rc.clone(),
                default_client_config: self.client_config,
            },
            Driver(rc),
            recv,
        ))
    }

    /// Accept incoming connections.
    pub fn listen(&mut self, config: ServerConfig) -> &mut Self {
        self.server_config = Some(config);
        self
    }

    pub fn reactor(&mut self, handle: &'a tokio_reactor::Handle) -> &mut Self {
        self.reactor = Some(handle);
        self
    }
    pub fn logger(&mut self, logger: Logger) -> &mut Self {
        self.logger = logger;
        self
    }

    /// Set the default configuration used for outgoing connections.
    ///
    /// The default can be overriden by using `Endpoint::connect_with`.
    pub fn default_client_config(&mut self, config: ClientConfig) -> &mut Self {
        self.client_config = config;
        self
    }
}

impl<'a> Default for EndpointBuilder<'a> {
    fn default() -> Self {
        Self {
            reactor: None,
            logger: Logger::root(slog::Discard, o!()),
            server_config: None,
            config: Config::default(),
            client_config: ClientConfig::default(),
        }
    }
}

/// Errors that can occur during the construction of an `Endpoint`.
#[derive(Debug, Error)]
pub enum EndpointError {
    /// An error during setup of the underlying UDP socket.
    #[error(display = "failed to set up UDP socket: {}", _0)]
    Socket(io::Error),
    /// An error configuring TLS.
    #[error(display = "failed to set up TLS: {}", _0)]
    Tls(TLSError),
    /// Errors relating to web PKI infrastructure
    #[error(display = "webpki failed: {:?}", _0)]
    WebPki(webpki::Error),
}

impl From<quinn::EndpointError> for EndpointError {
    fn from(x: quinn::EndpointError) -> Self {
        use crate::quinn::EndpointError::*;
        match x {
            Tls(x) => EndpointError::Tls(x),
        }
    }
}

impl From<webpki::Error> for EndpointError {
    fn from(e: webpki::Error) -> Self {
        EndpointError::WebPki(e)
    }
}

/// Helper for constructing a `ServerConfig` to be passed to `EndpointBuilder::listen` to enable
/// incoming connections.
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    /// Construct a builder using `config` as the initial state.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Construct the complete `ServerConfig`.
    pub fn build(self) -> ServerConfig {
        self.config
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable.
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) -> &mut Self {
        {
            let tls_server_config = Arc::get_mut(&mut self.config.tls_config).unwrap();
            tls_server_config.key_log = Arc::new(KeyLogFile::new());
        }
        self
    }

    /// Set the certificate chain that will be presented to clients.
    pub fn set_certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<&mut Self, TLSError> {
        {
            let tls_server_config = Arc::get_mut(&mut self.config.tls_config).unwrap();
            tls_server_config.set_single_cert(cert_chain.certs, key.inner)?;
        }
        Ok(self)
    }

    /// Set the application-layer protocols to accept.
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    // TODO: Cite IANA registery for ALPN IDs
    pub fn set_protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        {
            let tls_server_config = Arc::get_mut(&mut self.config.tls_config).unwrap();
            let protocols_strings = protocols
                .iter()
                .map(|p| str::from_utf8(p).unwrap().into())
                .collect::<Vec<_>>();
            tls_server_config.set_protocols(&protocols_strings);
        }
        self
    }

    /// Whether to require clients to prove they can receive packets before accepting a connection
    pub fn use_stateless_retry(&mut self, enabled: bool) -> &mut Self {
        self.config.use_stateless_retry = enabled;
        self
    }
}

impl Default for ServerConfigBuilder {
    fn default() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }
}

/// Helper for creating new outgoing connections.
pub struct ClientConfigBuilder {
    config: quinn::ClientConfig,
}

impl ClientConfigBuilder {
    /// Create a new builder with default options set.
    pub fn new() -> Self {
        let mut config = quinn::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);
        config.versions = vec![ProtocolVersion::TLSv1_3];
        config.enable_early_data = true;
        Self { config }
    }

    /// Add a trusted certificate authority.
    ///
    /// For more advanced/less secure certificate verification, construct a [`ClientConfig`]
    /// manually and use rustls's `dangerous_configuration` feature to override the certificate
    /// verifier.
    pub fn add_certificate_authority(
        &mut self,
        cert: Certificate,
    ) -> Result<&mut Self, EndpointError> {
        {
            let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(
                untrusted::Input::from(&cert.inner.0),
            )?;
            self.config
                .root_store
                .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&[anchor]));
        }
        Ok(self)
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable.
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) -> &mut Self {
        self.config.key_log = Arc::new(KeyLogFile::new());
        self
    }

    /// Set application-layer protocols to declare support for.
    pub fn set_protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        self.config.alpn_protocols = protocols
            .iter()
            .map(|p| {
                str::from_utf8(p)
                    .expect("non-UTF8 protocols unsupported")
                    .into()
            })
            .collect();
        self
    }

    /// Begin connecting from `endpoint` to `addr`.
    pub fn build(self) -> ClientConfig {
        ClientConfig {
            tls_config: Arc::new(self.config),
        }
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for outgoing connections
#[derive(Clone)]
pub struct ClientConfig {
    /// TLS configuration to use.
    ///
    /// `versions` *must* be `vec![ProtocolVersion::TLSv1_3]`.
    pub tls_config: Arc<quinn::ClientConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfigBuilder::default().build()
    }
}
