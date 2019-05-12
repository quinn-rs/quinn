#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use crate::{
    proto::connection::{Connection, Error as ProtoError},
    Settings,
};
use slog::Logger;

pub struct ConnectionDriver {
    conn: ConnectionRef,
    incoming: quinn::IncomingStreams,
    log: Logger,
}

impl ConnectionDriver {
    pub(crate) fn new(conn: ConnectionRef, incoming: quinn::IncomingStreams, log: Logger) -> Self {
        Self {
            conn,
            incoming,
            log,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionRef {
    pub inner: Arc<Mutex<Connection>>,
    pub quic: quinn::Connection,
}

impl ConnectionRef {
    pub fn new(quic: quinn::Connection, settings: Settings) -> Result<Self, ProtoError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(Connection::with_settings(settings)?)),
            quic,
        })
    }
}
