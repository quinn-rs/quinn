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
use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Instant;
use std::{io, mem};

use bytes::Bytes;
use err_derive::Error;
use fnv::FnvHashMap;
use futures::stream::FuturesUnordered;
use futures::sync::mpsc;
use futures::task::{self, Task};
use futures::unsync::oneshot;
use futures::Stream as FuturesStream;
use futures::{Async, Future, Poll, Sink};
use quinn_proto::{self as quinn, ConnectionHandle, Directionality, Side, StreamId, TimerUpdate};
use slog::Logger;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::Delay;

pub use crate::quinn::{
    ConnectError, ConnectionError, ConnectionId, DatagramEvent, ServerConfig, Transmit,
    TransportConfig, ALPN_QUIC_H3, ALPN_QUIC_HTTP,
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
    ) -> Result<ConnectingFuture, ConnectError> {
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
    ) -> Result<ConnectingFuture, ConnectError> {
        let mut endpoint = self.inner.borrow_mut();
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(*addr))
        } else {
            *addr
        };
        let (ch, conn) = endpoint.inner.connect(
            addr,
            config.transport.clone(),
            config.tls_config.clone(),
            server_name,
        )?;
        Ok(ConnectingFuture(Some(ConnectionDriver(
            endpoint.create_connection(ch, conn),
        ))))
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

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.borrow().socket.local_addr()
    }
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `Driver` instances do not terminate (always yields `NotReady`) except in case of an error.
#[must_use]
pub struct Driver(Rc<RefCell<EndpointInner>>);

/// Maximum number of send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link. Value selected
/// more or less arbitrarily.
const IO_LOOP_BOUND: usize = 10;

impl Future for Driver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let endpoint = &mut *self.0.borrow_mut();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(task::current());
        }
        let now = Instant::now();
        loop {
            let mut keep_going = false;
            keep_going |= endpoint.drive_recv(now)?;
            endpoint.drive_incoming();
            let _ = endpoint.incoming.poll_complete();
            endpoint.handle_events()?;
            keep_going |= endpoint.drive_send()?;
            if !keep_going {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        for sender in self.0.borrow_mut().connections.values() {
            // Ignoring errors from non-existent connections
            let _ = sender.unbounded_send(ConnectionEvent::Close(quinn::TransportError {
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
    outgoing: VecDeque<quinn::Transmit>,
    buffered_incoming: VecDeque<(ConnectionHandle, Rc<RefCell<ConnectionInner>>)>,
    incoming: mpsc::Sender<NewConnection>,
    driver: Option<Task>,
    ipv6: bool,
    connections: FnvHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    // Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
}

impl EndpointInner {
    pub(crate) fn new(
        log: Logger,
        socket: UdpSocket,
        inner: quinn::Endpoint,
        incoming: mpsc::Sender<NewConnection>,
        ipv6: bool,
    ) -> Self {
        let (sender, events) = mpsc::unbounded();
        Self {
            log,
            socket,
            inner,
            incoming,
            ipv6,
            sender,
            events,
            outgoing: VecDeque::new(),
            buffered_incoming: VecDeque::new(),
            driver: None,
            connections: FnvHashMap::default(),
        }
    }

    fn drive_recv(&mut self, now: Instant) -> Result<bool, io::Error> {
        let mut buf = [0; 64 * 1024];
        let mut recvd = 0;
        loop {
            match self.socket.poll_recv(&mut buf) {
                Ok(Async::Ready((n, addr, ecn))) => {
                    match self.inner.handle(now, addr, ecn, (&buf[0..n]).into()) {
                        Some((handle, DatagramEvent::NewConnection(conn))) => {
                            let conn = self.create_connection(handle, conn);
                            self.buffered_incoming.push_back((handle, conn));
                        }
                        Some((handle, DatagramEvent::ConnectionEvent(event))) => {
                            self.connections
                                .get_mut(&handle)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event))
                                .unwrap();
                        }
                        None => {}
                    }
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
            recvd += 1;
            if recvd >= IO_LOOP_BOUND {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn drive_incoming(&mut self) {
        while let Ok(Async::Ready(())) = self.incoming.poll_ready() {
            if let Some((_, conn)) = self.buffered_incoming.pop_front() {
                self.incoming
                    .start_send(NewConnection {
                        driver: ConnectionDriver(conn.clone()),
                        connection: Connection(conn.clone()),
                        incoming: IncomingStreams(conn),
                    })
                    .unwrap();
                self.inner.accept();
            } else {
                break;
            }
        }
    }

    fn drive_send(&mut self) -> Result<bool, io::Error> {
        let mut sent = 0;
        while let Some(t) = self.outgoing.pop_front() {
            match self.socket.poll_send(&t.destination, t.ecn, &t.packet) {
                Ok(Async::Ready(_)) => {}
                Ok(Async::NotReady) => {
                    self.outgoing.push_front(t);
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    self.outgoing.push_front(t);
                    break;
                }
                Err(e) => {
                    return Err(e);
                }
            }
            sent += 1;
            if sent == IO_LOOP_BOUND {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn handle_events(&mut self) -> Result<(), io::Error> {
        use EndpointEvent::*;
        loop {
            match self.events.poll() {
                Ok(Async::Ready(Some((ch, event)))) => match event {
                    Proto(e) => {
                        if let quinn::EndpointEvent::Closed { .. } = &e {
                            self.connections.remove(&ch);
                        }
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            self.connections
                                .get_mut(&ch)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event))
                                .unwrap();
                        }
                    }
                    Transmit(t) => self.outgoing.push_back(t),
                },
                Ok(Async::Ready(None)) => unreachable!("EndpointInner owns one sender"),
                Ok(Async::NotReady) => {
                    return Ok(());
                }
                Err(_) => unreachable!(),
            }
        }
    }

    fn create_connection(
        &mut self,
        handle: ConnectionHandle,
        conn: quinn::Connection,
    ) -> Rc<RefCell<ConnectionInner>> {
        let pending = Pending::new();
        let (conn_events_sender, conn_events) = mpsc::unbounded();
        let endpoint_events = self.sender.clone();
        self.connections.insert(handle, conn_events_sender);
        Rc::new(RefCell::new(ConnectionInner {
            log: self.log.clone(),
            side: conn.side(),
            inner: conn,
            handle,
            pending,
            driver: None,
            timers: FuturesUnordered::new(),
            conn_events,
            endpoint_events,
            connected: false,
            closed: false,
        }))
    }
}

struct Pending {
    blocked_writers: FnvHashMap<StreamId, Task>,
    blocked_readers: FnvHashMap<StreamId, Task>,
    uni_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    cancel_timers: [Option<oneshot::Sender<()>>; quinn::Timer::COUNT],
    incoming_streams_reader: Option<Task>,
    finishing: FnvHashMap<StreamId, oneshot::Sender<Option<ConnectionError>>>,
    error: Option<ConnectionError>,
    closing: Option<oneshot::Sender<()>>,
}

impl Pending {
    fn new() -> Self {
        Self {
            blocked_writers: FnvHashMap::default(),
            blocked_readers: FnvHashMap::default(),
            uni_opening: VecDeque::new(),
            bi_opening: VecDeque::new(),
            cancel_timers: [None, None, None, None, None, None],
            incoming_streams_reader: None,
            finishing: FnvHashMap::default(),
            error: None,
            closing: None,
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
pub type Incoming = mpsc::Receiver<NewConnection>;

/// A new connection (initiated locally or remotely)
pub struct NewConnection {
    /// The driver for the connection; this must be spawned for the connection to make progress
    pub driver: ConnectionDriver,
    /// The connection itself.
    pub connection: Connection,
    /// The stream of QUIC streams initiated by the client.
    pub incoming: IncomingStreams,
}

impl NewConnection {
    fn new(conn: Rc<RefCell<ConnectionInner>>) -> Self {
        Self {
            driver: ConnectionDriver(conn.clone()),
            connection: Connection(conn.clone()),
            incoming: IncomingStreams(conn),
        }
    }
}

/// Connecting future
pub struct ConnectingFuture(Option<ConnectionDriver>);

impl Future for ConnectingFuture {
    type Item = NewConnection;
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let connected = match &mut self.0 {
            Some(driver) => {
                match driver.poll()? {
                    Async::Ready(()) => unreachable!("cannot close without completing"),
                    Async::NotReady => {}
                }
                (driver.0).borrow().connected
            }
            None => panic!("polled after yielding Ready"),
        };
        if connected {
            let ConnectionDriver(conn) = self.0.take().unwrap();
            conn.borrow_mut().driver.take();
            Ok(Async::Ready(NewConnection::new(conn)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// A future that drives protocol logic for a connection
///
/// This future handles the protocol logic for a single connection, routing events from the
/// `Connection` API object to the `Endpoint` task and the related stream-related interfaces.
/// It also keeps track of outstanding timeouts for the `Connection`.
///
/// If the connection encounters an error condition, this future will yield an error. It
/// will terminate (yielding `Ready(())`) if the connection was closed without error.
#[must_use]
pub struct ConnectionDriver(Rc<RefCell<ConnectionInner>>);

impl Future for ConnectionDriver {
    type Item = ();
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let conn = &mut *self.0.borrow_mut();
        if let Some(e) = &conn.pending.error {
            return Err(e.clone());
        }

        if conn.driver.is_none() {
            conn.driver = Some(task::current());
        }

        let now = Instant::now();
        loop {
            let mut keep_going = false;
            conn.process_conn_events().unwrap();
            conn.forward_app_events();
            conn.forward_endpoint_events();
            conn.drive_transmit(now);
            keep_going |= conn.drive_timers(now);
            conn.handle_timer_updates();
            if !keep_going || conn.closed {
                break;
            }
        }

        if conn.closed {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
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
pub struct Connection(Rc<RefCell<ConnectionInner>>);

impl Connection {
    /// Initite a new outgoing unidirectional stream.
    pub fn open_uni(&self) -> impl Future<Item = SendStream, Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.borrow_mut();
            if let Some(x) = conn.inner.open(Directionality::Uni) {
                let _ = send.send(Ok(x));
            } else {
                conn.pending.uni_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        let conn = self.0.clone();
        recv.map_err(|_| unreachable!())
            .and_then(|result| result)
            .map(move |stream| SendStream(BiStream::new(conn.clone(), stream)))
    }

    /// Initiate a new outgoing bidirectional stream.
    pub fn open_bi(&self) -> impl Future<Item = BiStream, Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.borrow_mut();
            if let Some(x) = conn.inner.open(Directionality::Bi) {
                let _ = send.send(Ok(x));
            } else {
                conn.pending.bi_opening.push_back(send);
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
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// # Panics
    /// - If called more than once on handles to the same connection
    // FIXME: Infallible
    pub fn close(&self, error_code: u16, reason: &[u8]) -> impl Future<Item = (), Error = ()> {
        let (send, recv) = oneshot::channel();
        {
            let conn = &mut *self.0.borrow_mut();
            assert!(
                conn.pending.closing.is_none(),
                "a connection can only be closed once"
            );
            conn.pending.closing = Some(send);
            conn.inner.close(Instant::now(), error_code, reason.into());
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
        self.0.borrow().inner.remote()
    }

    /// The `ConnectionId` defined for `conn` by the peer.
    pub fn remote_id(&self) -> ConnectionId {
        self.0.borrow().inner.rem_cid()
    }

    /// The negotiated application protocol
    pub fn protocol(&self) -> Option<Box<[u8]>> {
        self.0.borrow().inner.protocol().map(|x| x.into())
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.borrow_mut().inner.force_key_update()
    }
}

struct ConnectionInner {
    log: Logger,
    inner: quinn::Connection,
    driver: Option<Task>,
    handle: ConnectionHandle,
    pending: Pending,
    side: Side,
    // TODO: Replace this with something custom that avoids using oneshots to cancel
    timers: FuturesUnordered<Timer>,
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    connected: bool,
    closed: bool,
}

impl ConnectionInner {
    fn drive_transmit(&mut self, now: Instant) {
        while let Some(t) = self.inner.poll_transmit(now) {
            self.endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Transmit(t)))
                .unwrap();
        }
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            if let quinn::EndpointEvent::Closed { .. } = &event {
                self.closed = true;
                self.pending
                    .fail(ConnectionError::TransportError(quinn::TransportError {
                        code: quinn::TransportErrorCode::NO_ERROR,
                        frame: None,
                        reason: "connection is closing".to_string(),
                    }));
            }
            self.endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Proto(event)))
                .unwrap();
        }
    }

    fn process_conn_events(&mut self) -> Result<(), ()> {
        loop {
            match self.conn_events.poll() {
                Ok(Async::Ready(Some(ConnectionEvent::Proto(event)))) => {
                    self.inner.handle_event(event);
                }
                Ok(Async::Ready(Some(ConnectionEvent::Close(_)))) => {
                    self.closed = true;
                    self.pending
                        .fail(ConnectionError::TransportError(quinn::TransportError {
                            code: quinn::TransportErrorCode::NO_ERROR,
                            frame: None,
                            reason: "connection is closing".to_string(),
                        }));
                }
                Ok(Async::Ready(None)) | Ok(Async::NotReady) => {
                    return Ok(());
                }
                Err(_) => {
                    unreachable!("channel receivers never fail");
                }
            }
        }
    }

    fn forward_app_events(&mut self) {
        while let Some(event) = self.inner.poll() {
            use crate::quinn::Event::*;
            match event {
                Connected { .. } => {
                    self.connected = true;
                }
                ConnectionLost { reason } => {
                    self.pending.fail(reason);
                }
                StreamWritable { stream } => {
                    if let Some(writer) = self.pending.blocked_writers.remove(&stream) {
                        writer.notify();
                    }
                }
                StreamOpened => {
                    if let Some(x) = self.pending.incoming_streams_reader.take() {
                        x.notify();
                    }
                }
                StreamReadable { stream } => {
                    if let Some(reader) = self.pending.blocked_readers.remove(&stream) {
                        reader.notify();
                    }
                }
                StreamAvailable { directionality } => {
                    let queue = match directionality {
                        Directionality::Uni => &mut self.pending.uni_opening,
                        Directionality::Bi => &mut self.pending.bi_opening,
                    };
                    while let Some(connection) = queue.pop_front() {
                        if let Some(id) = self.inner.open(directionality) {
                            let _ = connection.send(Ok(id));
                        } else {
                            queue.push_front(connection);
                            break;
                        }
                    }
                }
                StreamFinished { stream } => {
                    let _ = self.pending.finishing.remove(&stream).unwrap().send(None);
                }
            }
        }
    }

    fn drive_timers(&mut self, now: Instant) -> bool {
        let mut keep_going = false;
        loop {
            match self.timers.poll() {
                Ok(Async::Ready(Some(Some(timer)))) => {
                    trace!(self.log, "timeout"; "timer" => ?timer);
                    self.inner
                        .handle_event(quinn::ConnectionEvent::Timer(now, timer));
                    if timer == quinn::Timer::Close {
                        if let Some(x) = self.pending.closing.take() {
                            let _ = x.send(());
                        }
                    }
                    // Timeout call may have queued sends
                    keep_going = true;
                }
                Ok(Async::Ready(Some(None))) => {}
                Ok(Async::Ready(None)) | Ok(Async::NotReady) => {
                    break;
                }
                Err(()) => unreachable!(),
            }
        }
        keep_going
    }

    fn handle_timer_updates(&mut self) {
        while let Some(update) = self.inner.poll_timers() {
            match update {
                TimerUpdate {
                    timer: timer @ quinn::Timer::Close,
                    update: quinn::TimerSetting::Start(time),
                } => {
                    self.timers.push(Timer {
                        ty: timer,
                        delay: Delay::new(time),
                        cancel: None,
                    });
                }
                TimerUpdate {
                    timer,
                    update: quinn::TimerSetting::Start(time),
                } => {
                    let cancel = &mut self.pending.cancel_timers[timer as usize];
                    if let Some(cancel) = cancel.take() {
                        let _ = cancel.send(());
                    }
                    let (send, recv) = oneshot::channel();
                    *cancel = Some(send);
                    trace!(self.log, "timer start"; "timer" => ?timer, "time" => ?time);
                    self.timers.push(Timer {
                        ty: timer,
                        delay: Delay::new(time),
                        cancel: Some(recv),
                    });
                }
                TimerUpdate {
                    timer,
                    update: quinn::TimerSetting::Stop,
                } => {
                    trace!(self.log, "timer stop"; "timer" => ?timer);
                    // If a connection was lost, we already canceled its loss/idle timers.
                    if let Some(x) = self.pending.cancel_timers[timer as usize].take() {
                        let _ = x.send(());
                    }
                }
            }
        }
    }

    /// Wake up a blocked `Driver` task to process I/O
    fn notify(&self) {
        if let Some(x) = self.driver.as_ref() {
            x.notify();
        }
    }
}

/// A stream of QUIC streams initiated by a remote peer.
pub struct IncomingStreams(Rc<RefCell<ConnectionInner>>);

impl FuturesStream for IncomingStreams {
    type Item = NewStream;
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut conn = self.0.borrow_mut();
        if conn.closed {
            return Ok(Async::Ready(None));
        }
        if let Some(x) = conn.inner.accept() {
            let stream = BiStream::new(self.0.clone(), x);
            let stream = if x.directionality() == Directionality::Uni {
                NewStream::Uni(RecvStream(stream))
            } else {
                NewStream::Bi(stream)
            };
            return Ok(Async::Ready(Some(stream)));
        }
        if let Some(ref x) = conn.pending.error {
            Err(x.clone())
        } else {
            conn.pending.incoming_streams_reader = Some(task::current());
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
    conn: Rc<RefCell<ConnectionInner>>,
    stream: StreamId,

    // Send only
    finishing: Option<oneshot::Receiver<Option<ConnectionError>>>,
    finished: bool,

    // Recv only
    // Whether data reception is complete (due to receiving finish or reset or sending stop)
    recvd: bool,
}

impl BiStream {
    fn new(conn: Rc<RefCell<ConnectionInner>>, stream: StreamId) -> Self {
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
        use crate::quinn::WriteError::*;
        let mut conn = self.conn.borrow_mut();
        let n = match conn.inner.write(self.stream, buf) {
            Ok(n) => n,
            Err(Blocked) => {
                if let Some(ref x) = conn.pending.error {
                    return Err(WriteError::ConnectionClosed(x.clone()));
                }
                conn.pending
                    .blocked_writers
                    .insert(self.stream, task::current());
                return Ok(Async::NotReady);
            }
            Err(Stopped { error_code }) => {
                return Err(WriteError::Stopped { error_code });
            }
        };
        conn.notify();
        Ok(Async::Ready(n))
    }

    fn poll_finish(&mut self) -> Poll<(), ConnectionError> {
        if self.finishing.is_none() {
            let mut conn = self.conn.borrow_mut();
            conn.inner.finish(self.stream);
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            conn.pending.finishing.insert(self.stream, send);
            conn.notify();
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
        let mut conn = self.conn.borrow_mut();
        conn.inner.reset(self.stream, error_code);
        conn.notify();
    }
}

impl Read for BiStream {
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError> {
        use crate::quinn::ReadError::*;
        let mut conn = self.conn.borrow_mut();
        match conn.inner.read_unordered(self.stream) {
            Ok((bytes, offset)) => Ok(Async::Ready((bytes, offset))),
            Err(Blocked) => {
                if let Some(ref x) = conn.pending.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                conn.pending
                    .blocked_readers
                    .insert(self.stream, task::current());
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
            Err(UnknownStream) => Err(ReadError::UnknownStream),
        }
    }

    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError> {
        use crate::quinn::ReadError::*;
        let mut conn = self.conn.borrow_mut();
        match conn.inner.read(self.stream, buf) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(Blocked) => {
                if let Some(ref x) = conn.pending.error {
                    return Err(ReadError::ConnectionClosed(x.clone()));
                }
                conn.pending
                    .blocked_readers
                    .insert(self.stream, task::current());
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
            Err(UnknownStream) => Err(ReadError::UnknownStream),
        }
    }

    fn stop(&mut self, error_code: u16) {
        let mut conn = self.conn.borrow_mut();
        conn.inner.stop_sending(self.stream, error_code);
        conn.notify();
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
        let mut conn = self.conn.borrow_mut();
        let ours = self.stream.initiator() == conn.side;
        let (send, recv) = match self.stream.directionality() {
            Directionality::Bi => (true, true),
            Directionality::Uni => (ours, !ours),
        };

        if conn.pending.closing.is_some() || conn.pending.error.is_some() {
            return;
        }
        if send && !self.finished {
            conn.inner.reset(self.stream, 0);
        }
        if recv && !self.recvd {
            conn.inner.stop_sending(self.stream, 0);
        }
        conn.notify();
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
            Err(UnknownStream) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("unknown stream"),
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
    ty: quinn::Timer,
    delay: Delay,
    cancel: Option<oneshot::Receiver<()>>,
}

impl Future for Timer {
    type Item = Option<quinn::Timer>;
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
            Ok(Async::Ready(())) => Ok(Async::Ready(Some(self.ty))),
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
    /// Unknown stream
    #[error(display = "unknown stream")]
    UnknownStream,
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

enum ConnectionEvent {
    Close(quinn::TransportError),
    Proto(quinn::ConnectionEvent),
}

enum EndpointEvent {
    Proto(quinn::EndpointEvent),
    Transmit(quinn::Transmit),
}
