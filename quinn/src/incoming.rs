use std::{
    fmt,
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use proto::ConnectionError;
use thiserror::Error;

use crate::{
    connection::{Connecting, Connection},
    endpoint::EndpointRef,
};

/// An incoming connection for which the server has not yet begun its part of the handshake
pub struct Incoming(Option<State>);

impl Incoming {
    pub(crate) fn new(
        inner: proto::Incoming,
        endpoint: EndpointRef,
        response_buffer: BytesMut,
    ) -> Self {
        Self(Some(State {
            inner,
            endpoint,
            response_buffer,
        }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(mut self) -> Result<Connecting, ConnectionError> {
        let state = self.0.take().unwrap();
        state.endpoint.accept(state.inner, state.response_buffer)
    }

    /// Reject this incoming connection attempt
    pub fn reject(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.reject(state.inner, state.response_buffer);
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `remote_address_validated()` is true.
    pub fn retry(mut self) -> Result<(), RetryError> {
        let state = self.0.take().unwrap();
        state
            .endpoint
            .retry(state.inner, state.response_buffer)
            .map_err(|(e, response_buffer)| {
                RetryError(Self(Some(State {
                    inner: e.into_incoming(),
                    endpoint: state.endpoint,
                    response_buffer,
                })))
            })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(mut self) {
        self.0.take().unwrap();
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
            state.endpoint.reject(state.inner, state.response_buffer);
        }
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = self.0.as_ref().unwrap();
        f.debug_struct("Incoming")
            .field("inner", &state.inner)
            .field("endpoint", &state.endpoint)
            // response_buffer is too big and not meaningful enough
            .finish_non_exhaustive()
    }
}

struct State {
    inner: proto::Incoming,
    endpoint: EndpointRef,
    response_buffer: BytesMut,
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
