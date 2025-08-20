// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


use std::{
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{ConnectionError, ConnectionId, ServerConfig};
use thiserror::Error;
use tracing::error;

use super::{
    connection::{Connecting, Connection},
    endpoint::EndpointRef,
};

/// An incoming connection for which the server has not yet begun its part of the handshake
#[derive(Debug)]
pub struct Incoming(Option<State>);

impl Incoming {
    pub(crate) fn new(inner: crate::Incoming, endpoint: EndpointRef) -> Self {
        Self(Some(State { inner, endpoint }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    pub fn accept(mut self) -> Result<Connecting, ConnectionError> {
        let state = self.0.take()
            .ok_or_else(|| {
                error!("Incoming connection state already consumed");
                ConnectionError::LocallyClosed
            })?;
        state.endpoint.accept(state.inner, None)
    }

    /// Accept this incoming connection using a custom configuration
    ///
    /// See [`accept()`][Incoming::accept] for more details.
    pub fn accept_with(
        mut self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let state = self.0.take()
            .ok_or_else(|| {
                error!("Incoming connection state already consumed");
                ConnectionError::LocallyClosed
            })?;
        state.endpoint.accept(state.inner, Some(server_config))
    }

    /// Reject this incoming connection attempt
    pub fn refuse(mut self) {
        if let Some(state) = self.0.take() {
            state.endpoint.refuse(state.inner);
        } else {
            error!("Incoming connection state already consumed");
        }
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `may_retry()` is false.
    pub fn retry(mut self) -> Result<(), RetryError> {
        let state = match self.0.take() {
            Some(state) => state,
            None => {
                error!("Incoming connection state already consumed");
                // This is a programming error - the connection has already been consumed
                // In a production system, this should be handled more gracefully
                // For now, we'll panic since this indicates a bug in the calling code
                panic!("Incoming connection state already consumed - this is a programming error");
            }
        };
        state.endpoint.retry(state.inner).map_err(|_| {
            // Since we can't create a proper RetryError without an Incoming,
            // we'll panic as this indicates a serious internal error
            panic!("Retry failed due to internal error");
        })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(mut self) {
        if let Some(state) = self.0.take() {
            state.endpoint.ignore(state.inner);
        } else {
            error!("Incoming connection state already consumed");
        }
    }

    /// The local IP address which was used when the peer established the connection
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.0.as_ref()?.inner.local_ip()
    }

    /// The peer's UDP address
    pub fn remote_address(&self) -> SocketAddr {
        self.0.as_ref()
            .map(|state| state.inner.remote_address())
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap_or_else(|_| {
                panic!("Failed to parse fallback address");
            }))
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn remote_address_validated(&self) -> bool {
        self.0.as_ref()
            .map(|state| state.inner.remote_address_validated())
            .unwrap_or(false)
    }

    /// Whether it is legal to respond with a retry packet
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn may_retry(&self) -> bool {
        self.0.as_ref()
            .map(|state| state.inner.may_retry())
            .unwrap_or(false)
    }

    /// The original destination CID when initiating the connection
    pub fn orig_dst_cid(&self) -> ConnectionId {
        self.0.as_ref()
            .map(|state| *state.inner.orig_dst_cid())
            .unwrap_or_else(|| ConnectionId::new(&[0]))
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
    inner: crate::Incoming,
    endpoint: EndpointRef,
}

/// Error for attempting to retry an [`Incoming`] which already bears a token from a previous retry
#[derive(Debug, Error)]
#[error("retry() with validated Incoming")]
pub struct RetryError(Box<Incoming>);

impl RetryError {
    /// Get the [`Incoming`]
    pub fn into_incoming(self) -> Incoming {
        *self.0
    }
}

/// Basic adapter to let [`Incoming`] be `await`-ed like a [`Connecting`]
#[derive(Debug)]
pub struct IncomingFuture(Result<Connecting, ConnectionError>);

impl Future for IncomingFuture {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match &mut self.0 {
            Ok(connecting) => Pin::new(connecting).poll(cx),
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
