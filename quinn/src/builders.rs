use std::{io, net::SocketAddr, str, sync::Arc};

use err_derive::Error;
use proto::{ClientConfig, EndpointConfig, ServerConfig};
use rustls::TLSError;

use crate::{
    endpoint::{Endpoint, EndpointDriver, EndpointRef, Incoming},
    udp::UdpSocket,
    Certificate, CertificateChain, PrivateKey,
};

/// A helper for constructing an `Endpoint`.
///
/// See `ClientConfigBuilder` for details on trust defaults.
#[derive(Clone, Debug)]
pub struct EndpointBuilder {
    server_config: Option<ServerConfig>,
    config: EndpointConfig,
    client_config: ClientConfig,
}

#[allow(missing_docs)]
impl EndpointBuilder {
    /// Start a builder with a specific initial low-level configuration.
    pub fn new(config: EndpointConfig) -> Self {
        Self {
            config,
            // Pull in this crate's defaults rather than proto's
            client_config: ClientConfigBuilder::default().build(),
            ..Self::default()
        }
    }

    /// Build an endpoint bound to `addr`.
    pub fn bind(
        self,
        addr: &SocketAddr,
    ) -> Result<(EndpointDriver, Endpoint, Incoming), EndpointError> {
        let socket = std::net::UdpSocket::bind(addr).map_err(EndpointError::Socket)?;
        self.with_socket(socket)
    }

    /// Build an endpoint around a pre-configured socket.
    pub fn with_socket(
        self,
        socket: std::net::UdpSocket,
    ) -> Result<(EndpointDriver, Endpoint, Incoming), EndpointError> {
        let addr = socket.local_addr().map_err(EndpointError::Socket)?;
        let socket = UdpSocket::from_std(socket).map_err(EndpointError::Socket)?;
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(Arc::new(self.config), self.server_config.map(Arc::new))?,
            addr.is_ipv6(),
        );
        Ok((
            EndpointDriver(rc.clone()),
            Endpoint {
                inner: rc.clone(),
                default_client_config: self.client_config,
            },
            Incoming::new(rc),
        ))
    }

    /// Accept incoming connections.
    pub fn listen(&mut self, config: ServerConfig) -> &mut Self {
        self.server_config = Some(config);
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

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            server_config: None,
            config: EndpointConfig::default(),
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
    /// An error in the Quinn transport configuration
    #[error(display = "configuration error: {:?}", _0)]
    Config(#[source] proto::ConfigError),
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
        Arc::make_mut(&mut self.config.crypto).key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    /// Set the certificate chain that will be presented to clients.
    pub fn certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<&mut Self, TLSError> {
        Arc::make_mut(&mut self.config.crypto).set_single_cert(cert_chain.certs, key.inner)?;
        Ok(self)
    }

    /// Set the application-layer protocols to accept, in order of descending preference.
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).alpn_protocols =
            protocols.iter().map(|x| x.to_vec()).collect();
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
///
/// If the `native-certs` and `ct-logs` features are enabled, `ClientConfigBuilder::default()` will
/// construct a configuration that trusts the host OS certificate store and uses built-in
/// certificate transparency logs respectively. These features are both enabled by default.
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Construct a builder using `config` as the initial state.
    ///
    /// If you want to trust the usual certificate authorities trusted by the system, use
    /// `ClientConfigBuilder::default()` with the `native-certs` and `ct-logs` features enabled
    /// instead.
    pub fn new(config: ClientConfig) -> Self {
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
    ) -> Result<&mut Self, webpki::Error> {
        let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(&cert.inner.0)?;
        Arc::make_mut(&mut self.config.crypto)
            .root_store
            .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&[anchor]));
        Ok(self)
    }

    /// Enable NSS-compatible cryptographic key logging to the `SSLKEYLOGFILE` environment variable.
    ///
    /// Useful for debugging encrypted communications with protocol analyzers such as Wireshark.
    pub fn enable_keylog(&mut self) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    /// Set the application-layer protocols to accept, in order of descending preference.
    ///
    /// When set, clients which don't declare support for at least one of the supplied protocols will be rejected.
    ///
    /// The IANA maintains a [registry] of standard protocol IDs, but custom IDs may be used as well.
    ///
    /// [registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    pub fn protocols(&mut self, protocols: &[&[u8]]) -> &mut Self {
        Arc::make_mut(&mut self.config.crypto).alpn_protocols =
            protocols.iter().map(|x| x.to_vec()).collect();
        self
    }

    /// Begin connecting from `endpoint` to `addr`.
    pub fn build(self) -> ClientConfig {
        self.config
    }
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        let mut x = ClientConfig::default();
        let crypto = Arc::make_mut(&mut x.crypto);
        #[cfg(feature = "native-certs")]
        match rustls_native_certs::load_native_certs() {
            Ok(x) => {
                crypto.root_store = x;
            }
            Err(e) => {
                tracing::warn!("couldn't load default trust roots: {}", e);
            }
        }
        #[cfg(feature = "ct-logs")]
        {
            crypto.ct_logs = Some(&ct_logs::LOGS);
        }
        Self::new(x)
    }
}
