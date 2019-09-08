use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

use futures::{Future, Poll, Stream};
use quinn::{RecvStream, SendStream};

use crate::{
    proto::connection::{Connection, Error as ProtoError},
    Error, Settings,
};

pub struct ConnectionDriver {
    conn: ConnectionRef,
    incoming: quinn::IncomingBiStreams,
}

impl ConnectionDriver {
    pub(crate) fn new(conn: ConnectionRef, incoming: quinn::IncomingBiStreams) -> Self {
        Self { conn, incoming }
    }
}

impl Future for ConnectionDriver {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Pin::new(&mut self.incoming).poll_next(cx)? {
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Ready(Some((send, recv))) => {
                let mut conn = self.conn.h3.lock().unwrap();
                conn.requests.push_back((send, recv));
                if let Some(t) = conn.requests_task.take() {
                    t.wake();
                }
            }
            _ => (),
        }

        Poll::Pending
    }
}

pub(crate) struct ConnectionInner {
    pub inner: Connection,
    pub requests: VecDeque<(SendStream, RecvStream)>,
    pub requests_task: Option<Waker>,
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
