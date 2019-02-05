//! QUIC transport protocol support for Tokio
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing
//! shortcomings of TCP, such as head-of-line blocking, poor security, slow handshakes, and
//! inefficient congestion control. This crate provides a portable userspace implementation.
//!
//! The entry point of this crate is the [`Endpoint`](struct.Endpoint.html).
//!
//! The futures and streams defined in this crate are not `Send` because they necessarily share
//! state with each other. As a result, they must be spawned on a single-threaded tokio runtime.
//!
//! ```
//! # extern crate tokio;
//! # extern crate quinn;
//! # extern crate futures;
//! # use futures::Future;
//! # fn main() {
//! let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
//! let mut builder = quinn::Endpoint::new();
//! // <configure builder>
//! let (endpoint, driver, _) = builder.bind("[::]:0").unwrap();
//! runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)));
//! // ...
//! # }
//! ```
//! # About QUIC
//!
//! A QUIC connection is an association between two endpoints. The endpoint which initiates the
//! connection is termed the client, and the endpoint which accepts it is termed the server. A
//! single endpoint may function as both client and server for different connections, for example
//! in a peer-to-peer application. To communicate application data, each endpoint may open streams
//! up to a limit dictated by its peer. Typically, that limit is increased as old streams are
//! finished.
//!
//! Streams may be unidirectional or bidirectional, and are cheap to create and disposable. For
//! example, a traditionally datagram-oriented application could use a new stream for every
//! message it wants to send, no longer needing to worry about MTUs. Bidirectional streams behave
//! much like a traditional TCP connection, and are useful for sending messages that have an
//! immediate response, such as an HTTP request. Stream data is delivered reliably, and there is no
//! ordering enforced between data on different streams.
//!
//! By avoiding head-of-line blocking and providing unified congestion control across all streams
//! of a connection, QUIC is able to provide higher throughput and lower latency than one or
//! multiple TCP connections between the same two hosts, while providing more useful behavior than
//! raw UDP sockets.
//!
//! QUIC uses encryption and identity verification built directly on TLS 1.3. Just as with a TLS
//! server, it is useful for a QUIC server to be identified by a certificate signed by a trusted
//! authority. If this is infeasible--for example, if servers are short-lived or not associated
//! with a domain name--then as with TLS, self-signed certificates can be used to provide
//! encryption alone.
#![warn(missing_docs)]

#[macro_use]
extern crate slog;

mod builders;
mod platform;
pub mod tls;
mod udp;

use std::cell::RefCell;
use std::collections::{hash_map, VecDeque};
use std::net::{SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::sync::Arc;
use std::time::Instant;
use std::{io, mem};

use bytes::Bytes;
use err_derive::Error;
use fnv::FnvHashMap;
use futures::stream::FuturesUnordered;
use futures::task::{self, Task};
use futures::unsync::oneshot;
use futures::Stream as FuturesStream;
use futures::{Async, Future, Poll, Sink};
use quinn_proto::{self as quinn, ConnectionHandle, Directionality, Side, StreamId, TimerUpdate};
use slog::Logger;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::Delay;

pub use crate::quinn::{
    ConnectError, ConnectionError, ConnectionId, ServerConfig, TransportConfig, ALPN_QUIC_H3,
    ALPN_QUIC_HTTP,
};
pub use crate::tls::{Certificate, CertificateChain, PrivateKey};

pub use crate::builders::{
    ClientConfig, ClientConfigBuilder, EndpointBuilder, EndpointError, ServerConfigBuilder,
};
use crate::udp::UdpSocket;

#[cfg(test)]
mod tests;

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Clone)]
pub struct Endpoint {
    inner: Rc<RefCell<EndpointInner>>,
    default_client_config: ClientConfig,
}

impl Endpoint {
    /// Begin constructing an `Endpoint`
    pub fn new<'a>() -> EndpointBuilder<'a> {
        EndpointBuilder::default()
    }

    /// Connect to a remote endpoint.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<impl Future<Item = NewClientConnection, Error = ConnectionError>, ConnectError>
    {
        self.connect_with(&self.default_client_config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect_with(
        &self,
        config: &ClientConfig,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<impl Future<Item = NewClientConnection, Error = ConnectionError>, ConnectError>
    {
        let (fut, conn) = self.connect_inner(
            addr,
            config.transport.clone(),
            config.tls_config.clone(),
            server_name,
        )?;
        Ok(fut.map_err(|_| unreachable!()).and_then(move |err| {
            if let Some(err) = err {
                Err(err)
            } else {
                Ok(NewClientConnection::new(Rc::new(conn)))
            }
        }))
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind(
        &self,
        socket: std::net::UdpSocket,
        reactor: &tokio_reactor::Handle,
    ) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let socket = UdpSocket::from_std(socket, &reactor)?;
        let mut inner = self.inner.borrow_mut();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();
        Ok(())
    }

    /*
    /// Connect to a remote endpoint, with support for transmitting data before the connection is
    /// established
    ///
    /// Returns a connection that may be used for sending immediately, and a future that will
    /// complete when the connection is established.
    ///
    /// Data transmitted this way may be replayed by an attacker until the session ticket expires.
    /// Never send non-idempotent commands as 0-RTT data.
    ///
    /// Servers may reject 0-RTT data, in which case anything sent will be retransmitted after the
    /// connection is established.
    ///
    /// # Panics
    /// - If `config.session_ticket` is `None`. A session ticket is necessary for 0-RTT to be
    /// possible.
    pub fn connect_zero_rtt(
        &self,
        addr: &SocketAddr,
        config: ClientConfig,
    ) -> Result<
        (
            NewClientConnection,
            impl Future<Item = (), Error = ConnectionError>,
        ),
        ConnectError,
    > {
        assert!(
            config.session_ticket.is_some(),
            "a session ticket must be supplied for zero-rtt transmits to be possible"
        );
        let (fut, conn) = self.connect_inner(addr, config)?;
        let conn = NewClientConnection::new(Rc::new(conn));
        Ok((
            conn,
            fut.map_err(|_| unreachable!())
                .and_then(move |err| err.map_or(Ok(()), Err)),
        ))
    }
    */

    fn connect_inner(
        &self,
        addr: &SocketAddr,
        transport_config: Arc<TransportConfig>,
        crypto_config: Arc<quinn::ClientConfig>,
        server_name: &str,
    ) -> Result<
        (
            impl Future<Item = Option<ConnectionError>, Error = futures::Canceled>,
            ConnectionInner,
        ),
        ConnectError,
    > {
        let (send, recv) = oneshot::channel();
        let handle = {
            let mut endpoint = self.inner.borrow_mut();
            let addr = if endpoint.ipv6 {
                SocketAddr::V6(ensure_ipv6(*addr))
            } else {
                *addr
            };
            let handle =
                endpoint
                    .inner
                    .connect(addr, transport_config, crypto_config, server_name)?;
            endpoint.pending.insert(handle, Pending::new(Some(send)));
            endpoint.notify();
            handle
        };
        let conn = ConnectionInner {
            endpoint: self.inner.clone(),
            handle,
            side: Side::Client,
        };
        Ok((recv, conn))
    }
}

/// A future that drives IO on an endpoint.
pub struct Driver(Rc<RefCell<EndpointInner>>);

impl Future for Driver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut buf = [0; 64 * 1024];
        let endpoint = &mut *self.0.borrow_mut();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(task::current());
        }
        let now = Instant::now();
        loop {
            loop {
                match endpoint.socket.poll_recv(&mut buf) {
                    Ok(Async::Ready((n, addr, ecn))) => {
                        endpoint.inner.handle(now, addr, ecn, (&buf[0..n]).into());
                    }
                    Ok(Async::NotReady) => {
                        break;
                    }
                    // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                    // attacker
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            while let Some((ch, event)) = endpoint.inner.poll() {
                use crate::quinn::Event::*;
                match event {
                    Connected { .. } => {
                        let _ = endpoint
                            .pending
                            .get_mut(&ch)
                            .unwrap()
                            .connecting
                            .take()
                            .map(|chan| chan.send(None));
                    }
                    ConnectionLost { reason } => {
                        if let Some(x) = endpoint.pending.get_mut(&ch) {
                            x.fail(reason);
                        }
                    }
                    StreamWritable { stream } => {
                        if let Some(writer) = endpoint
                            .pending
                            .get_mut(&ch)
                            .unwrap()
                            .blocked_writers
                            .remove(&stream)
                        {
                            writer.notify();
                        }
                    }
                    StreamOpened => {
                        let pending = endpoint.pending.get_mut(&ch).unwrap();
                        if let Some(x) = pending.incoming_streams_reader.take() {
                            x.notify();
                        }
                    }
                    StreamReadable { stream } => {
                        let pending = endpoint.pending.get_mut(&ch).unwrap();
                        if let Some(reader) = pending.blocked_readers.remove(&stream) {
                            reader.notify();
                        }
                    }
                    StreamAvailable { directionality } => {
                        let pending = endpoint.pending.get_mut(&ch).unwrap();
                        let queue = match directionality {
                            Directionality::Uni => &mut pending.uni_opening,
                            Directionality::Bi => &mut pending.bi_opening,
                        };
                        while let Some(connection) = queue.pop_front() {
                            if let Some(id) = endpoint.inner.open(ch, directionality) {
                                let _ = connection.send(Ok(id));
                            } else {
                                queue.push_front(connection);
                                break;
                            }
                        }
                    }
                    StreamFinished { stream } => {
                        let _ = endpoint
                            .pending
                            .get_mut(&ch)
                            .unwrap()
                            .finishing
                            .remove(&stream)
                            .unwrap()
                            .send(None);
                    }
                    Handshaking => {
                        endpoint.pending.insert(ch, Pending::new(None));
                        match endpoint.incoming.poll_ready() {
                            Ok(Async::Ready(())) => {
                                endpoint
                                    .incoming
                                    .start_send(NewConnection::new(self.0.clone(), ch))
                                    .unwrap();
                                endpoint.inner.accept();
                            }
                            _ => {
                                endpoint.buffered_incoming.push_back(ch);
                            }
                        }
                    }
                }
            }
            while let Ok(Async::Ready(())) = endpoint.incoming.poll_ready() {
                if let Some(ch) = endpoint.buffered_incoming.pop_front() {
                    endpoint
                        .incoming
                        .start_send(NewConnection::new(self.0.clone(), ch))
                        .unwrap();
                    endpoint.inner.accept();
                } else {
                    break;
                }
            }
            let _ = endpoint.incoming.poll_complete();
            let mut blocked = false;
            if let Some(ref x) = endpoint.outgoing {
                match endpoint.socket.poll_send(&x.destination, x.ecn, &x.packet) {
                    Ok(Async::Ready(_)) => {
                        endpoint.outgoing = None;
                    }
                    Ok(Async::NotReady) => {
                        blocked = true;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                        blocked = true;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            if !blocked {
                while let Some(x) = endpoint.inner.poll_transmit(now) {
                    match endpoint.socket.poll_send(&x.destination, x.ecn, &x.packet) {
                        Ok(Async::Ready(_)) => {}
                        Ok(Async::NotReady) => {
                            endpoint.outgoing = Some(x);
                            break;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                            endpoint.outgoing = Some(x);
                            break;
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }
            let mut timer_fired = false;
            loop {
                match endpoint.timers.poll() {
                    Ok(Async::Ready(Some(Some((ch, timer))))) => {
                        trace!(endpoint.log, "timeout"; "timer" => ?timer);
                        endpoint.inner.timeout(now, ch, timer);
                        if timer == quinn::Timer::Close {
                            // Connection drained
                            if let hash_map::Entry::Occupied(mut p) = endpoint.pending.entry(ch) {
                                if let Some(x) = p.get_mut().closing.take() {
                                    let _ = x.send(());
                                }
                                if p.get().dropped {
                                    p.remove();
                                } else {
                                    p.get_mut().drained = true;
                                }
                            }
                        }
                        timer_fired = true;
                    }
                    Ok(Async::Ready(Some(None))) => {}
                    Ok(Async::Ready(None)) | Ok(Async::NotReady) => {
                        break;
                    }
                    Err(()) => unreachable!(),
                }
            }
            while let Some((ch, x)) = endpoint.inner.poll_timers() {
                match x {
                    TimerUpdate {
                        timer: timer @ quinn::Timer::Close,
                        update: quinn::TimerSetting::Start(time),
                    } => {
                        endpoint.timers.push(Timer {
                            ch,
                            ty: timer,
                            delay: Delay::new(time),
                            cancel: None,
                        });
                    }
                    TimerUpdate {
                        timer,
                        update: quinn::TimerSetting::Start(time),
                    } => {
                        let pending = endpoint.pending.get_mut(&ch).unwrap();
                        let cancel = &mut pending.cancel_timers[timer as usize];
                        if let Some(cancel) = cancel.take() {
                            let _ = cancel.send(());
                        }
                        let (send, recv) = oneshot::channel();
                        *cancel = Some(send);
                        trace!(endpoint.log, "timer start"; "timer" => ?timer, "time" => ?time);
                        endpoint.timers.push(Timer {
                            ch,
                            ty: timer,
                            delay: Delay::new(time),
                            cancel: Some(recv),
                        });
                    }
                    TimerUpdate {
                        timer,
                        update: quinn::TimerSetting::Stop,
                    } => {
                        trace!(endpoint.log, "timer stop"; "timer" => ?timer);
                        // If a connection was lost, we already canceled its loss/idle timers.
                        if let Some(pending) = endpoint.pending.get_mut(&ch) {
                            if let Some(x) = pending.cancel_timers[timer as usize].take() {
                                let _ = x.send(());
                            }
                        }
                    }
                }
            }
            if !timer_fired {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let mut endpoint = self.0.borrow_mut();
        for ch in endpoint.pending.values_mut() {
            ch.fail(ConnectionError::TransportError(quinn::TransportError {
                code: quinn::TransportErrorCode::INTERNAL_ERROR,
                frame: None,
                reason: "driver future was dropped".to_string(),
            }));
        }
    }
}

struct EndpointInner {
    log: Logger,
    socket: UdpSocket,
    inner: quinn::Endpoint,
    outgoing: Option<quinn::Transmit>,
    pending: FnvHashMap<ConnectionHandle, Pending>,
    // TODO: Replace this with something custom that avoids using oneshots to cancel
    timers: FuturesUnordered<Timer>,
    buffered_incoming: VecDeque<ConnectionHandle>,
    incoming: futures::sync::mpsc::Sender<NewConnection>,
    driver: Option<Task>,
    ipv6: bool,
}

impl EndpointInner {
    /// Wake up a blocked `Driver` task to process I/O
    fn notify(&self) {
        if let Some(x) = self.driver.as_ref() {
            x.notify();
        }
    }
}

struct Pending {
    blocked_writers: FnvHashMap<StreamId, Task>,
    blocked_readers: FnvHashMap<StreamId, Task>,
    connecting: Option<oneshot::Sender<Option<ConnectionError>>>,
    uni_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    cancel_timers: [Option<oneshot::Sender<()>>; quinn::Timer::COUNT],
    incoming_streams_reader: Option<Task>,
    finishing: FnvHashMap<StreamId, oneshot::Sender<Option<ConnectionError>>>,
    error: Option<ConnectionError>,
    closing: Option<oneshot::Sender<()>>,
    dropped: bool,
    drained: bool,
}

impl Pending {
    fn new(connecting: Option<oneshot::Sender<Option<ConnectionError>>>) -> Self {
        Self {
            blocked_writers: FnvHashMap::default(),
            blocked_readers: FnvHashMap::default(),
            connecting,
            uni_opening: VecDeque::new(),
            bi_opening: VecDeque::new(),
            cancel_timers: [None, None, None, None, None, None],
            incoming_streams_reader: None,
            finishing: FnvHashMap::default(),
            error: None,
            closing: None,
            dropped: false,
            drained: false,
        }
    }

    fn fail(&mut self, reason: ConnectionError) {
        self.error = Some(reason.clone());
        for (_, writer) in self.blocked_writers.drain() {
            writer.notify()
        }
        for (_, reader) in self.blocked_readers.drain() {
            reader.notify()
        }
        if let Some(c) = self.connecting.take() {
            let _ = c.send(Some(reason.clone()));
        }
        for x in self.uni_opening.drain(..) {
            let _ = x.send(Err(reason.clone()));
        }
        for x in self.bi_opening.drain(..) {
            let _ = x.send(Err(reason.clone()));
        }
        if let Some(x) = self.incoming_streams_reader.take() {
            x.notify();
        }
        for (_, x) in self.finishing.drain() {
            let _ = x.send(Some(reason.clone()));
        }
    }
}

/// Stream of incoming connections.
pub type Incoming = futures::sync::mpsc::Receiver<NewConnection>;

/// A connection initiated by a remote client.
pub struct NewConnection {
    /// The connection itself.
    pub connection: Connection,
    /// The stream of QUIC streams initiated by the client.
    pub incoming: IncomingStreams,
}

impl NewConnection {
    fn new(endpoint: Rc<RefCell<EndpointInner>>, handle: quinn::ConnectionHandle) -> Self {
        let conn = Rc::new(ConnectionInner {
            endpoint,
            handle,
            side: Side::Server,
        });
        NewConnection {
            connection: Connection(conn.clone()),
            incoming: IncomingStreams(conn),
        }
    }
}

/// A connection initiated locally.
pub struct NewClientConnection {
    /// The connection itself.
    pub connection: Connection,
    /// The stream of QUIC streams initiated by the client.
    pub incoming: IncomingStreams,
}

impl NewClientConnection {
    fn new(conn: Rc<ConnectionInner>) -> Self {
        Self {
            connection: Connection(conn.clone()),
            incoming: IncomingStreams(conn.clone()),
        }
    }
}

/// A QUIC connection.
///
/// If a `Connection` is dropped without being explicitly closed, it will be automatically closed
/// with an `error_code` of 0 and an empty `reason`.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Clone)]
pub struct Connection(Rc<ConnectionInner>);

impl Connection {
    /// Initite a new outgoing unidirectional stream.
    pub fn open_uni(&self) -> impl Future<Item = SendStream, Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.handle, Directionality::Uni) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.handle).unwrap();
                pending.uni_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        let conn = self.0.clone();
        recv.map_err(|_| unreachable!())
            .and_then(|result| result)
            .map(move |stream| SendStream(BiStream::new(conn, stream)))
    }

    /// Initiate a new outgoing bidirectional stream.
    pub fn open_bi(&self) -> impl Future<Item = BiStream, Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.handle, Directionality::Bi) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.handle).unwrap();
                pending.bi_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        let conn = self.0.clone();
        recv.map_err(|_| unreachable!())
            .and_then(|result| result)
            .map(move |stream| BiStream::new(conn.clone(), stream))
    }

    /// Close the connection immediately.
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility
    /// to call this only when all important communications have been completed.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to be certain it is
    /// preserved in full, it should be kept under 1KiB.
    ///
    /// # Panics
    /// - If called more than once on handles to the same connection
    // FIXME: Infallible
    pub fn close(&self, error_code: u16, reason: &[u8]) -> impl Future<Item = (), Error = ()> {
        let (send, recv) = oneshot::channel();
        {
            let endpoint = &mut *self.0.endpoint.borrow_mut();

            let pending = endpoint.pending.get_mut(&self.0.handle).unwrap();
            assert!(
                pending.closing.is_none(),
                "a connection can only be closed once"
            );
            pending.closing = Some(send);

            endpoint
                .inner
                .close(Instant::now(), self.0.handle, error_code, reason.into());
        }
        let handle = self.clone();
        recv.then(move |_| {
            // Ensure the connection isn't dropped until it's fully drained.
            let _ = handle;
            Ok(())
        })
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.0
            .endpoint
            .borrow()
            .inner
            .connection(self.0.handle)
            .remote()
    }

    /// The `ConnectionId`s defined for `conn` locally.
    pub fn local_ids(&self) -> impl Iterator<Item = ConnectionId> {
        self.0
            .endpoint
            .borrow()
            .inner
            .connection(self.0.handle)
            .loc_cids()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }
    /// The `ConnectionId` defined for `conn` by the peer.
    pub fn remote_id(&self) -> ConnectionId {
        self.0
            .endpoint
            .borrow()
            .inner
            .connection(self.0.handle)
            .rem_cid()
    }

    /// The negotiated application protocol
    pub fn protocol(&self) -> Option<Box<[u8]>> {
        self.0
            .endpoint
            .borrow()
            .inner
            .connection(self.0.handle)
            .protocol()
            .map(|x| x.into())
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0
            .endpoint
            .borrow_mut()
            .inner
            .force_key_update(self.0.handle)
    }
}

struct ConnectionInner {
    endpoint: Rc<RefCell<EndpointInner>>,
    handle: ConnectionHandle,
    side: Side,
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        let endpoint = &mut *self.endpoint.borrow_mut();
        if let hash_map::Entry::Occupied(mut pending) = endpoint.pending.entry(self.handle) {
            if pending.get().drained {
                pending.remove();
                return;
            }
            pending.get_mut().dropped = true;
            if pending.get().closing.is_none() {
                endpoint
                    .inner
                    .close(Instant::now(), self.handle, 0, (&[][..]).into());
                if let Some(x) = endpoint.driver.as_ref() {
                    x.notify();
                }
            }
        }
    }
}

/// A stream of QUIC streams initiated by a remote peer.
pub struct IncomingStreams(Rc<ConnectionInner>);

impl FuturesStream for IncomingStreams {
    type Item = NewStream;
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut endpoint = self.0.endpoint.borrow_mut();
        if let Some(x) = endpoint.inner.accept_stream(self.0.handle) {
            let stream = BiStream::new(self.0.clone(), x);
            let stream = if x.directionality() == Directionality::Uni {
                NewStream::Uni(RecvStream(stream))
            } else {
                NewStream::Bi(stream)
            };
            return Ok(Async::Ready(Some(stream)));
        }
        let pending = endpoint.pending.get_mut(&self.0.handle).unwrap();
        if let Some(ref x) = pending.error {
            Err(x.clone())
        } else {
            pending.incoming_streams_reader = Some(task::current());
            Ok(Async::NotReady)
        }
    }
}

/// A stream initiated by a remote peer.
pub enum NewStream {
    /// A unidirectional stream.
    Uni(RecvStream),
    /// A bidirectional stream.
    Bi(BiStream),
}

/// A bidirectional stream, supporting both sending and receiving data.
///
/// Similar to a TCP connection. Each direction of data flow can be reset or finished by the
/// sending endpoint without interfering with activity in the other direction.
pub struct BiStream {
    conn: Rc<ConnectionInner>,
    stream: StreamId,

    // Send only
    finishing: Option<oneshot::Receiver<Option<ConnectionError>>>,
    finished: bool,

    // Recv only
    // Whether data reception is complete (due to receiving finish or reset or sending stop)
    recvd: bool,
}

impl BiStream {
    fn new(conn: Rc<ConnectionInner>, stream: StreamId) -> Self {
        Self {
            conn,
            stream,
            finishing: None,
            finished: false,
            recvd: false,
        }
    }
}

impl Write for BiStream {
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> {
        let mut endpoint = self.conn.endpoint.borrow_mut();
        use crate::quinn::WriteError::*;
        let n = match endpoint.inner.write(self.conn.handle, self.stream, buf) {
            Ok(n) => n,
            Err(Blocked) => {
                let pending = endpoint.pending.get_mut(&self.conn.handle).unwrap();
                if let Some(ref x) = pending.error {
                    return Err(WriteError::ConnectionClosed(x.clone()));
                }
                pending.blocked_writers.insert(self.stream, task::current());
                return Ok(Async::NotReady);
            }
            Err(Stopped { error_code }) => {
                return Err(WriteError::Stopped { error_code });
            }
        };
        endpoint.notify();
        Ok(Async::Ready(n))
    }

    fn poll_finish(&mut self) -> Poll<(), ConnectionError> {
        let mut endpoint = self.conn.endpoint.borrow_mut();
        if self.finishing.is_none() {
            endpoint.inner.finish(self.conn.handle, self.stream);
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            endpoint
                .pending
                .get_mut(&self.conn.handle)
                .unwrap()
                .finishing
                .insert(self.stream, send);
            endpoint.notify();
        }
        let r = self.finishing.as_mut().unwrap().poll().unwrap();
        match r {
            Async::Ready(None) => {
                self.finished = true;
                Ok(Async::Ready(()))
            }
            Async::Ready(Some(e)) => Err(e),
            Async::NotReady => Ok(Async::NotReady),
        }
    }

    fn reset(&mut self, error_code: u16) {
        let endpoint = &mut *self.conn.endpoint.borrow_mut();
        endpoint
            .inner
            .reset(self.conn.handle, self.stream, error_code);
        endpoint.notify();
    }
}

impl Read for BiStream {
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError> {
        let endpoint = &mut *self.conn.endpoint.borrow_mut();
        use crate::quinn::ReadError::*;
        let pending = endpoint.pending.get_mut(&self.conn.handle).unwrap();
        match endpoint.inner.read_unordered(self.conn.handle, self.stream) {
            Ok((bytes, offset)) => Ok(Async::Ready((bytes, offset))),
            Err(Blocked) => {
                if let Some(ref x) = pending.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                pending.blocked_readers.insert(self.stream, task::current());
                Ok(Async::NotReady)
            }
            Err(Reset { error_code }) => {
                self.recvd = true;
                Err(ReadError::Reset { error_code })
            }
            Err(Finished) => {
                self.recvd = true;
                Err(ReadError::Finished)
            }
        }
    }

    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError> {
        let endpoint = &mut *self.conn.endpoint.borrow_mut();
        use crate::quinn::ReadError::*;
        let pending = endpoint.pending.get_mut(&self.conn.handle).unwrap();
        match endpoint.inner.read(self.conn.handle, self.stream, buf) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(Blocked) => {
                if let Some(ref x) = pending.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                pending.blocked_readers.insert(self.stream, task::current());
                Ok(Async::NotReady)
            }
            Err(Reset { error_code }) => {
                self.recvd = true;
                Err(ReadError::Reset { error_code })
            }
            Err(Finished) => {
                self.recvd = true;
                Err(ReadError::Finished)
            }
        }
    }

    fn stop(&mut self, error_code: u16) {
        let endpoint = &mut *self.conn.endpoint.borrow_mut();
        endpoint
            .inner
            .stop_sending(self.conn.handle, self.stream, error_code);
        endpoint.notify();
        self.recvd = true;
    }
}

impl io::Write for BiStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Write::poll_write(self, buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(WriteError::Stopped { error_code }) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream stopped by peer: error {}", error_code),
            )),
            Err(WriteError::ConnectionClosed(e)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("connection closed: {}", e),
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for BiStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.poll_finish().map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("connection closed: {}", e),
            )
        })
    }
}

impl Drop for BiStream {
    fn drop(&mut self) {
        let endpoint = &mut *self.conn.endpoint.borrow_mut();
        let ours = self.stream.initiator() == self.conn.side;
        let (send, recv) = match self.stream.directionality() {
            Directionality::Bi => (true, true),
            Directionality::Uni => (ours, !ours),
        };
        if send && !self.finished {
            endpoint.inner.reset(self.conn.handle, self.stream, 0);
        }
        if recv && !self.recvd {
            endpoint
                .inner
                .stop_sending(self.conn.handle, self.stream, 0);
        }
        endpoint.notify();
    }
}

impl io::Read for BiStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use crate::ReadError::*;
        match Read::poll_read(self, buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Err(Finished) => Ok(0),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(Reset { error_code }) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("stream reset by peer: error {}", error_code),
            )),
            Err(ConnectionClosed(e)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("connection closed: {}", e),
            )),
        }
    }
}

impl AsyncRead for BiStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

/// A stream that can only be used to send data
pub struct SendStream(BiStream);

impl Write for SendStream {
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> {
        Write::poll_write(&mut self.0, buf)
    }
    fn poll_finish(&mut self) -> Poll<(), ConnectionError> {
        self.0.poll_finish()
    }
    fn reset(&mut self, error_code: u16) {
        self.0.reset(error_code);
    }
}

impl io::Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for SendStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.0.shutdown()
    }
}

/// A stream that can only be used to receive data
pub struct RecvStream(BiStream);

impl Read for RecvStream {
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError> {
        self.0.poll_read_unordered()
    }
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError> {
        Read::poll_read(&mut self.0, buf)
    }
    fn stop(&mut self, error_code: u16) {
        self.0.stop(error_code)
    }
}

impl io::Read for RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl AsyncRead for RecvStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

/// Uses unordered reads to be more efficient than using `AsyncRead` would allow
pub fn read_to_end<T: Read>(stream: T, size_limit: usize) -> ReadToEnd<T> {
    ReadToEnd {
        stream: Some(stream),
        size_limit,
        buffer: Vec::new(),
    }
}

struct Timer {
    ch: ConnectionHandle,
    ty: quinn::Timer,
    delay: Delay,
    cancel: Option<oneshot::Receiver<()>>,
}

impl Future for Timer {
    type Item = Option<(ConnectionHandle, quinn::Timer)>;
    type Error = (); // FIXME
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref mut cancel) = self.cancel {
            if let Ok(Async::NotReady) = cancel.poll() {
            } else {
                return Ok(Async::Ready(None));
            }
        }
        match self.delay.poll() {
            Err(e) => panic!("unexpected timer error: {}", e),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(())) => Ok(Async::Ready(Some((self.ch, self.ty)))),
        }
    }
}

/// Future produced by `read_to_end`
pub struct ReadToEnd<T> {
    stream: Option<T>,
    buffer: Vec<u8>,
    size_limit: usize,
}

impl<T: Read> Future for ReadToEnd<T> {
    type Item = (T, Box<[u8]>);
    type Error = ReadError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.stream.as_mut().unwrap().poll_read_unordered() {
                Ok(Async::Ready((data, offset))) => {
                    let len = self.buffer.len().max(offset as usize + data.len());
                    if len > self.size_limit {
                        return Err(ReadError::Finished);
                    }
                    self.buffer.resize(len, 0);
                    self.buffer[offset as usize..offset as usize + data.len()]
                        .copy_from_slice(&data);
                }
                Ok(Async::NotReady) => {
                    return Ok(Async::NotReady);
                }
                Err(ReadError::Finished) => {
                    return Ok(Async::Ready((
                        self.stream.take().unwrap(),
                        mem::replace(&mut self.buffer, Vec::new()).into(),
                    )));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

/// Trait of readable streams
pub trait Read {
    /// Read data contiguously from the stream.
    ///
    /// Returns the number of bytes read into `buf` on success.
    ///
    /// Applications involving bulk data transfer should consider using unordered reads for
    /// improved performance.
    ///
    /// # Panics
    /// - If called after `poll_read_unordered` was called on the same stream.
    ///   This is forbidden because an unordered read could consume a segment of data from a
    ///   location other than the start of the receive buffer, making it impossible for future
    ///   ordered reads to proceed.
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError>;

    /// Read a segment of data from any offset in the stream.
    ///
    /// Returns a segment of data and their offset in the stream. Segments may be received in any
    /// order and may overlap.
    ///
    /// Unordered reads have reduced overhead and higher throughput, and should therefore be
    /// preferred when applicable.
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError>;

    /// Close the receive stream immediately.
    ///
    /// The peer is notified and will cease transmitting on this stream, as if it had reset the
    /// stream itself. Further data may still be received on this stream if it was already in
    /// flight. Once called, a `ReadError::Reset` should be expected soon, although a peer might
    /// manage to finish the stream before it receives the reset, and a misbehaving peer might
    /// ignore the request entirely and continue sending until halted by flow control.
    ///
    /// Has no effect if the incoming stream already finished.
    fn stop(&mut self, error_code: u16);
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Error, Clone)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream.
    #[error(display = "stream reset by peer: error {}", error_code)]
    Reset {
        /// The error code supplied by the peer.
        error_code: u16,
    },
    /// The data on this stream has been fully delivered and no more will be transmitted.
    #[error(display = "the stream has been completely received")]
    Finished,
    /// The connection was closed.
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

/// Trait of writable streams
pub trait Write {
    /// Write bytes to the stream.
    ///
    /// Returns the number of bytes written on success. Congestion and flow control may cause this
    /// to be shorter than `buf.len()`, indicating that only a prefix of `buf` was written.
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError>;

    /// Shut down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    fn poll_finish(&mut self) -> Poll<(), ConnectionError>;

    /// Close the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped,
    /// and previously transmitted data will no longer be retransmitted if lost. If `poll_finish`
    /// was called previously and all data has already been transmitted at least once, the peer
    /// may still receive all written data.
    fn reset(&mut self, error_code: u16);
}

/// Errors that arise from writing to a stream
#[derive(Debug, Error, Clone)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream.
    #[error(display = "sending stopped by peer: error {}", error_code)]
    Stopped {
        /// The error code supplied by the peer.
        error_code: u16,
    },
    /// The connection was closed.
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}
