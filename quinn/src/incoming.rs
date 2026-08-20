use std::{
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use crate::runtime::AsyncTimer;
use proto::{ConnectionError, ConnectionId, ServerConfig};
use thiserror::Error;
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use tokio::sync::futures::OwnedNotified;

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

    /// Accept this incoming connection using a custom configuration
    ///
    /// See [`accept()`][Incoming::accept] for more details.
    pub fn accept_with(
        mut self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let state = self.0.take().unwrap();
        state.endpoint.accept(state.inner, Some(server_config))
    }

    /// Start reading this connection's rustls ClientHello before choosing a server config.
    ///
    /// The returned future buffers Initial and 0-RTT datagrams for this connection while it waits
    /// for enough ClientHello data. Once it resolves, inspect the ClientHello and continue with
    /// [`Accepted::accept_with`]. Dropping either the future or the resulting [`Accepted`] refuses
    /// the connection and releases its buffered protocol state. Resource limits applied before
    /// selection, including ClientHello and incoming-datagram buffering limits, come from the
    /// endpoint configuration captured when this method is called; selecting another configuration
    /// does not retroactively change them.
    #[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
    pub fn acceptor(mut self) -> Result<Acceptor, ConnectionError> {
        let state = self.0.take().unwrap();
        let endpoint = state.endpoint;
        let start = endpoint.start_rustls_acceptor(state.inner)?;
        let notify = Box::pin(start.notify.clone().notified_owned());
        Ok(Acceptor {
            state: Some(AcceptorState {
                accepting: start.accepting,
                endpoint,
                acceptor: start.acceptor,
                incoming_idx: start.incoming_idx,
                notify_source: start.notify,
                notify,
                deadline: start.deadline,
                timer: start.timer,
            }),
        })
    }

    /// Reject this incoming connection attempt
    pub fn refuse(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.refuse(state.inner);
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `may_retry()` is false.
    pub fn retry(mut self) -> Result<(), RetryError> {
        let state = self.0.take().unwrap();
        state.endpoint.retry(state.inner).map_err(|e| {
            RetryError(Box::new(Self(Some(State {
                inner: e.into_incoming(),
                endpoint: state.endpoint,
            }))))
        })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(mut self) {
        let state = self.0.take().unwrap();
        state.endpoint.ignore(state.inner);
    }

    /// The local IP address which was used when the peer established the connection
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
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn remote_address_validated(&self) -> bool {
        self.0.as_ref().unwrap().inner.remote_address_validated()
    }

    /// Whether it is legal to respond with a retry packet
    ///
    /// If `self.remote_address_validated()` is false, `self.may_retry()` is guaranteed to be true.
    /// The inverse is not guaranteed.
    pub fn may_retry(&self) -> bool {
        self.0.as_ref().unwrap().inner.may_retry()
    }

    /// The original destination CID when initiating the connection
    pub fn orig_dst_cid(&self) -> ConnectionId {
        self.0.as_ref().unwrap().inner.orig_dst_cid()
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

/// Future that resolves once rustls has read the incoming ClientHello.
///
/// Creating an `Acceptor` reserves one pending incoming-connection slot. Initial and 0-RTT
/// datagrams received while it is pending are buffered. The future observes the server's idle
/// timeout, and dropping it refuses the attempt and releases the reservation.
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub struct Acceptor {
    state: Option<AcceptorState>,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
struct AcceptorState {
    accepting: proto::Accepting,
    endpoint: EndpointRef,
    acceptor: proto::RustlsAcceptor,
    incoming_idx: usize,
    notify_source: Arc<tokio::sync::Notify>,
    notify: Pin<Box<OwnedNotified>>,
    deadline: Option<crate::Instant>,
    timer: Option<Pin<Box<dyn AsyncTimer>>>,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl Future for Acceptor {
    type Output = Result<Accepted, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let state = self.state.as_mut().expect("polled after completion");
            // Register before inspecting endpoint buffers so a datagram received between the
            // inspection and the pending return cannot be missed.
            state.notify.as_mut().enable();
            match state
                .endpoint
                .poll_rustls_acceptor(&mut state.accepting, &mut state.acceptor)
            {
                Ok(Some(accepted)) => {
                    if state
                        .accepting
                        .idle_timeout_deadline()
                        .is_some_and(|deadline| state.endpoint.runtime_now() >= deadline)
                    {
                        let state = self.state.take().unwrap();
                        state
                            .endpoint
                            .fail_rustls_accepting(state.accepting, ConnectionError::TimedOut);
                        return Poll::Ready(Err(ConnectionError::TimedOut));
                    }
                    let state = self.state.take().unwrap();
                    state
                        .endpoint
                        .shared
                        .unregister_acceptor(state.incoming_idx);
                    return Poll::Ready(Ok(Accepted {
                        state: Some(AcceptedState {
                            accepting: state.accepting,
                            endpoint: state.endpoint,
                            accepted,
                        }),
                    }));
                }
                Ok(None) => {
                    let deadline = state.accepting.idle_timeout_deadline();
                    if deadline != state.deadline {
                        if let (Some(timer), Some(deadline)) = (&mut state.timer, deadline) {
                            timer.as_mut().reset(deadline);
                        }
                        state.deadline = deadline;
                    }
                    let timed_out = state
                        .deadline
                        .is_some_and(|deadline| state.endpoint.runtime_now() >= deadline)
                        || state
                            .timer
                            .as_mut()
                            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready());
                    if timed_out {
                        let state = self.state.take().unwrap();
                        state
                            .endpoint
                            .fail_rustls_accepting(state.accepting, ConnectionError::TimedOut);
                        return Poll::Ready(Err(ConnectionError::TimedOut));
                    }
                    if state.notify.as_mut().poll(cx).is_ready() {
                        state.notify = Box::pin(state.notify_source.clone().notified_owned());
                        continue;
                    }
                    return Poll::Pending;
                }
                Err(error) => {
                    let state = self.state.take().unwrap();
                    state
                        .endpoint
                        .fail_rustls_accepting(state.accepting, error.clone());
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl Drop for Acceptor {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.endpoint.refuse_rustls_accepting(state.accepting);
        }
    }
}

/// An incoming connection whose ClientHello has been read.
///
/// Inspect [`client_hello()`](Self::client_hello), asynchronously choose a [`ServerConfig`], then
/// call [`accept_with()`](Self::accept_with) to continue the same TLS and QUIC handshake. Incoming
/// datagrams remain buffered during selection. Holding this value also keeps one pending incoming
/// slot reserved, so applications should bound slow configuration lookups and drop or refuse the
/// attempt if selection takes too long. Dropping this value refuses the connection and releases
/// all reserved state.
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub struct Accepted {
    state: Option<AcceptedState>,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
struct AcceptedState {
    accepting: proto::Accepting,
    endpoint: EndpointRef,
    accepted: proto::RustlsAccepted,
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl Accepted {
    /// Get the rustls ClientHello for this connection.
    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.state.as_ref().unwrap().accepted.client_hello()
    }

    /// Continue the QUIC handshake using the endpoint's configured server configuration.
    ///
    /// The configuration's cryptographic implementation must support continuing a staged rustls
    /// handshake, as Quinn's rustls-backed configurations do.
    pub fn accept(mut self) -> Result<Connecting, ConnectionError> {
        let state = self.state.take().unwrap();
        state
            .endpoint
            .accept_rustls(state.accepting, state.accepted, None)
    }

    /// Continue the QUIC handshake using a custom server configuration.
    ///
    /// This selects the complete Quinn configuration, including both TLS and transport policy.
    /// Its cryptographic implementation must support continuing a staged rustls handshake, as
    /// Quinn's rustls-backed configurations do.
    pub fn accept_with(
        mut self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let state = self.state.take().unwrap();
        state
            .endpoint
            .accept_rustls(state.accepting, state.accepted, Some(server_config))
    }

    /// Reject this incoming connection attempt.
    pub fn refuse(mut self) {
        let state = self.state.take().unwrap();
        state.endpoint.refuse_rustls_accepting(state.accepting);
    }
}

#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
impl Drop for Accepted {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.endpoint.refuse_rustls_accepting(state.accepting);
        }
    }
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

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
