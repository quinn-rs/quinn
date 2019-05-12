use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use futures::{try_ready, Async, Future, Poll};
use quinn::{Endpoint, EndpointBuilder, EndpointDriver, EndpointError};
use slog::{self, o, Logger};

use crate::{
    connection::{ConnectionDriver, ConnectionRef},
    Error, Settings,
};

pub struct ClientBuilder<'a> {
    endpoint: EndpointBuilder<'a>,
    log: Option<Logger>,
    settings: Settings,
}

impl<'a> ClientBuilder<'a> {
    pub fn new(endpoint: EndpointBuilder<'a>) -> Self {
        Self {
            endpoint: endpoint,
            log: None,
            settings: Settings::default(),
        }
    }

    pub fn logger(&mut self, log: Logger) -> &mut Self {
        self.log = Some(log);
        self
    }

    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    pub fn bind<T: ToSocketAddrs>(
        self,
        addr: T,
    ) -> Result<(EndpointDriver, Client), EndpointError> {
        let (endpoint_driver, endpoint, _) = self.endpoint.bind(addr)?;
        Ok((
            endpoint_driver,
            Client {
                endpoint,
                settings: self.settings,
                log: self.log.unwrap_or(Logger::root(slog::Discard, o!())),
            },
        ))
    }
}

pub struct Client {
    endpoint: Endpoint,
    log: Logger,
    settings: Settings,
}

impl Client {
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            log: self.log.clone(),
            settings: self.settings.clone(),
            connecting: self.endpoint.connect(addr, server_name)?,
        })
    }
}

pub struct Connection(ConnectionRef);

pub struct Connecting {
    connecting: quinn::Connecting,
    log: Logger,
    settings: Settings,
}

impl Future for Connecting {
    type Item = (quinn::ConnectionDriver, ConnectionDriver, Connection);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (driver, conn, incoming) = try_ready!(self.connecting.poll());
        let conn_ref = ConnectionRef::new(conn.clone(), self.settings.clone())?;
        Ok(Async::Ready((
            driver,
            ConnectionDriver::new(conn_ref.clone(), incoming, self.log.clone()),
            Connection(conn_ref),
        )))
    }
}
