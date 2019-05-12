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

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    pub quic: quinn::Connection,
}

#[derive(Clone)]
pub(crate) struct ConnectionRef(pub Arc<Mutex<ConnectionInner>>);

impl ConnectionRef {
    pub fn new(quic: quinn::Connection, settings: Settings) -> Result<Self, ProtoError> {
        Ok(Self(Arc::new(Mutex::new(ConnectionInner {
            quic,
            inner: Connection::with_settings(settings)?,
        }))))
    }
}
