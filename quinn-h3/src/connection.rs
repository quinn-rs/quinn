use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use futures::task::Task;
use futures::{Async, Future, Poll, Stream};
use quinn::{NewStream, RecvStream, SendStream};
use slog::{info, Logger};

use crate::{
    proto::connection::{Connection, Error as ProtoError},
    Error, Settings,
};

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

impl Future for ConnectionDriver {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.incoming.poll()? {
            Async::Ready(None) => return Err(Error::peer("incoming requests closed")),
            Async::Ready(Some(NewStream::Uni(_recv))) => {
                info!(self.log, "incoming uni stream ignored");
            }
            Async::Ready(Some(NewStream::Bi(send, recv))) => {
                let mut conn = self.conn.h3.lock().unwrap();
                conn.requests.push_back((send, recv));
                if let Some(ref t) = conn.requests_task {
                    t.notify();
                }
            }
            _ => (),
        }

        Ok(Async::NotReady)
    }
}

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    pub requests: VecDeque<(SendStream, RecvStream)>,
    pub requests_task: Option<Task>,
}

#[derive(Clone)]
pub(crate) struct ConnectionRef {
    pub h3: Arc<Mutex<ConnectionInner>>,
    pub quic: quinn::Connection,
}

impl ConnectionRef {
    pub fn new(quic: quinn::Connection, settings: Settings) -> Result<Self, ProtoError> {
        Ok(Self {
            h3: Arc::new(Mutex::new(ConnectionInner {
                inner: Connection::with_settings(settings)?,
                requests: VecDeque::with_capacity(16),
                requests_task: None,
            })),
            quic,
        })
    }
}
