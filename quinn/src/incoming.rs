use std::{
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use proto::{ConnectionError, ServerConfig};
use thiserror::Error;

use crate::{
    connection::{Connecting, Connection},
    endpoint::EndpointRef,
};

/// An incoming connection for which the server has not yet begun its part of the handshake
#[derive(Debug)]
pub struct Incoming(Option<State>);

impl Incoming {
    pub(crate) fn new(inner: proto::Incoming, endpoint: EndpointRef) -> Self {
        Self(Some(State { inner, endpoint }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(mut self) -> Result<Connecting, ConnectionError> {
        let state = self.0.take().unwrap();
        state.endpoint.accept(state.inner, None)
    }

    /// Accept this incoming connection using a custom configuration.
    ///
    /// See [`accept()`] for more details.
    ///
    /// [`accept()`]: Incoming::accept
    pub fn accept_with(
        mut self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let state = self.0.take().unwrap();
        state.endpoint.accept(state.inner, Some(server_config))
    }

    /// Reject this incoming connection attempt
    pub fn refuse(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.refuse(state.inner);
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `remote_address_validated()` is true.
    pub fn retry(mut self) -> Result<(), RetryError> {
        let state = self.0.take().unwrap();
        state.endpoint.retry(state.inner).map_err(|e| {
            RetryError(Self(Some(State {
                inner: e.into_incoming(),
                endpoint: state.endpoint,
            })))
        })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.ignore(state.inner);
    }

    /// The local IP address which was used when the peer established
    /// the connection
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.0.as_ref().unwrap().inner.local_ip()
    }

    /// The peer's UDP address
    pub fn remote_address(&self) -> SocketAddr {
        self.0.as_ref().unwrap().inner.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.0.as_ref().unwrap().inner.remote_address_validated()
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // Implicit reject, similar to Connection's implicit close
        if let Some(state) = self.0.take() {
            state.endpoint.refuse(state.inner);
        }
    }
}

#[derive(Debug)]
struct State {
    inner: proto::Incoming,
    endpoint: EndpointRef,
}

/// Error for attempting to retry an [`Incoming`] which already bears an address
/// validation token from a previous retry
#[derive(Debug, Error)]
#[error("retry() with validated Incoming")]
pub struct RetryError(Incoming);

impl RetryError {
    /// Get the [`Incoming`]
    pub fn into_incoming(self) -> Incoming {
        self.0
    }
}

/// Basic adapter to let [`Incoming`] be `await`-ed like a [`Connecting`]
#[derive(Debug)]
pub struct IncomingFuture(Result<Connecting, ConnectionError>);

impl Future for IncomingFuture {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match &mut self.0 {
            Ok(ref mut connecting) => Pin::new(connecting).poll(cx),
            Err(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

impl IntoFuture for Incoming {
    type Output = Result<Connection, ConnectionError>;
    type IntoFuture = IncomingFuture;

    fn into_future(self) -> Self::IntoFuture {
        IncomingFuture(self.accept())
    }
}
