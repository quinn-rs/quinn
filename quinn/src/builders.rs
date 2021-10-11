use std::{io, net::SocketAddr, sync::Arc};

use proto::{
    generic::{ClientConfig, ServerConfig},
    ConnectionIdGenerator, EndpointConfig,
};
use thiserror::Error;
use tracing::error;
use udp::UdpSocket;

use crate::endpoint::{Endpoint, EndpointDriver, EndpointRef, Incoming};

/// A helper for constructing an [`Endpoint`].
///
/// [`Endpoint`]: crate::generic::Endpoint
#[derive(Clone, Debug)]
pub struct EndpointBuilder<S>
where
    S: proto::crypto::Session,
{
    server_config: Option<ServerConfig<S>>,
    config: EndpointConfig,
    default_client_config: Option<ClientConfig<S>>,
}

#[allow(missing_docs)]
impl<S> EndpointBuilder<S>
where
    S: proto::crypto::Session + Send + 'static,
{
    /// Start a builder with a specific initial low-level configuration
    pub fn new(config: EndpointConfig, default_client_config: Option<ClientConfig<S>>) -> Self {
        Self {
            server_config: None,
            config,
            default_client_config,
        }
    }

    /// Build an endpoint bound to `addr`
    ///
    /// Must be called from within a tokio runtime context. To avoid consuming the
    /// `EndpointBuilder`, call `clone()` first.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    pub fn bind(self, addr: &SocketAddr) -> Result<(Endpoint<S>, Incoming<S>), EndpointError> {
        let socket = std::net::UdpSocket::bind(addr).map_err(EndpointError::Socket)?;
        self.with_socket(socket)
    }

    /// Build an endpoint around a pre-configured socket
    ///
    /// Must be called from within a tokio runtime context. To avoid consuming the
    /// `EndpointBuilder`, call `clone()` first.
    pub fn with_socket(
        self,
        socket: std::net::UdpSocket,
    ) -> Result<(Endpoint<S>, Incoming<S>), EndpointError> {
        let addr = socket.local_addr().map_err(EndpointError::Socket)?;
        let socket = UdpSocket::from_std(socket).map_err(EndpointError::Socket)?;
        let rc = EndpointRef::new(
            socket,
            proto::generic::Endpoint::new(Arc::new(self.config), self.server_config.map(Arc::new)),
            addr.is_ipv6(),
        );
        let driver = EndpointDriver(rc.clone());
        tokio::spawn(async {
            if let Err(e) = driver.await {
                error!("I/O error: {}", e);
            }
        });
        Ok((
            Endpoint {
                inner: rc.clone(),
                default_client_config: self.default_client_config,
            },
            Incoming::new(rc),
        ))
    }

    /// Accept incoming connections.
    pub fn listen(&mut self, config: ServerConfig<S>) -> &mut Self {
        self.server_config = Some(config);
        self
    }

    /// Set the default configuration used for outgoing connections.
    ///
    /// The default can be overriden by using [`Endpoint::connect_with()`].
    ///
    /// [`Endpoint::connect_with()`]: crate::generic::Endpoint::connect_with
    pub fn default_client_config(&mut self, config: ClientConfig<S>) -> &mut Self {
        self.default_client_config = Some(config);
        self
    }

    /// Use a customized cid generator factory in the endpoint
    pub fn connection_id_generator<
        F: Fn() -> Box<dyn ConnectionIdGenerator> + Send + Sync + 'static,
    >(
        &mut self,
        factory: F,
    ) -> &mut Self {
        self.config.cid_generator(factory);
        self
    }
}

#[cfg(feature = "tls-rustls")]
impl<S> Default for EndpointBuilder<S>
where
    S: proto::crypto::Session,
{
    fn default() -> Self {
        Self {
            server_config: None,
            config: EndpointConfig::default(),
            default_client_config: None,
        }
    }
}

/// Errors that can occur during the construction of an `Endpoint`.
#[derive(Debug, Error)]
pub enum EndpointError {
    /// An error during setup of the underlying UDP socket.
    #[error("failed to set up UDP socket: {0}")]
    Socket(io::Error),
}
