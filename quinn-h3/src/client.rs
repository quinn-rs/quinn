use quinn::{Endpoint, EndpointBuilder, EndpointDriver, EndpointError};
use slog::{self, o, Logger};
use std::net::ToSocketAddrs;

use crate::Settings;

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
