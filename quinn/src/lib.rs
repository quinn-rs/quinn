#![feature(await_macro, async_await, futures_api, arbitrary_self_types)]
//! QUIC transport protocol support for Tokio
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing
//! shortcomings of TCP, such as head-of-line blocking, poor security, slow handshakes, and
//! inefficient congestion control. This crate provides a portable userspace implementation.
//!
//! The entry point of this crate is the [`Endpoint`](struct.Endpoint.html).
//!
//! ```no_run
//! use futures::TryFutureExt;
//! # fn main() {
//! let mut builder = quinn::Endpoint::new();
//! // <configure builder>
//! let (endpoint, driver, incoming_conns) = builder.bind("[::1]:0").unwrap();
//! tokio::run(futures::future::lazy(move |_| {
//!     tokio::spawn(driver.map_err(|e| panic!("IO error: {}", e)).compat());
//!     // <use endpoint, handle incoming_conns, ...>
//!     Ok(())
//! }).compat());
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

use std::collections::VecDeque;
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};
use std::time::Instant;
use std::{io, iter, mem};

use bytes::Bytes;
use err_derive::Error;
use futures::io::{AsyncRead, AsyncWrite};
use futures::{channel::oneshot, future, ready, Stream};
use fxhash::{FxHashMap, FxHashSet};
use quinn_proto::{self as quinn, ConnectionHandle, Directionality, StreamId, Transmit};
use tokio_timer::{delay_queue, DelayQueue};

pub use crate::builders::{
    ClientConfig, ClientConfigBuilder, EndpointBuilder, EndpointError, ServerConfigBuilder,
};
pub use crate::quinn::{
    ConnectError, ConnectionClose, ConnectionError, ConnectionId, ServerConfig, TransportConfig,
    TransportError, TransportErrorCode, ALPN_QUIC_H3, ALPN_QUIC_HTTP,
};
pub use crate::tls::{Certificate, CertificateChain, PrivateKey};

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
    inner: Arc<Mutex<EndpointInner>>,
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
    pub fn connect(&self, addr: &SocketAddr, server_name: &str) -> Result<Handshake, ConnectError> {
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
    ) -> Result<Handshake, ConnectError> {
        let mut inner = self.inner.lock().unwrap();
        let addr = if inner.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            *addr
        };
        let ch = inner.endpoint.connect(
            addr,
            config.transport.clone(),
            config.tls_config.clone(),
            server_name,
        )?;
        let conn = Connection::new(self.inner.clone(), ch);
        let mut state = ConnState::new(Arc::downgrade(&conn.0));
        let mut hs = Handshake::new(conn);
        let (send, recv) = oneshot::channel();
        state.connected = Some(send);
        hs.connected = Some(recv);
        inner.insert(ch, state);
        inner.wake();
        Ok(hs)
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
        let mut inner = self.inner.lock().unwrap();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();
        Ok(())
    }
}

/// A connection in the process of becoming established
pub struct Handshake {
    conn: Connection,
    connected: Option<oneshot::Receiver<()>>,
}

impl Handshake {
    fn new(conn: Connection) -> Self {
        Handshake {
            conn,
            connected: None,
        }
    }

    /// Complete the handshake.
    pub async fn establish(self) -> Result<(Connection, IncomingStreams), ConnectionError> {
        if let Some(connected) = self.connected {
            await!(connected).unwrap();
        }
        self.conn.0.check_err()?;
        self.conn.0.inner.lock().unwrap().check_err()?;
        let incoming = IncomingStreams(self.conn.0.clone());
        Ok((self.conn, incoming))
    }

    // TODO: 0/0.5-RTT

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }
}

/// A future that drives I/O on an endpoint.
///
/// Only completes if an unexpected error occurs.
pub struct Driver(Arc<Mutex<EndpointInner>>);

/// Maximum number of send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link. Value selected
/// more or less arbitrarily.
const IO_LOOP_BOUND: usize = 10;

impl Future for Driver {
    type Output = Result<(), io::Error>;

    fn poll(mut self: Pin<&mut Self>, waker: &Waker) -> Poll<Self::Output> {
        let inner_cloned = self.0.clone();
        let inner = &mut *self.0.lock().unwrap();
        let now = Instant::now();

        // timers must be polled after they're touched to ensure our next wakeup is appropriate
        let mut keep_going = true;
        while keep_going {
            keep_going = false;
            // Incoming packets
            // Might queue output and events
            let mut buf = [0; 64 * 1024];
            let mut recvd = 0;
            loop {
                match inner.socket.poll_recv(&mut buf) {
                    Poll::Pending => {
                        break;
                    }
                    // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                    // attacker
                    Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok((n, addr, ecn))) => {
                        inner.endpoint.handle(now, addr, ecn, (&buf[0..n]).into());
                    }
                }
                recvd += 1;
                if recvd >= IO_LOOP_BOUND {
                    keep_going = true;
                    break;
                }
            }

            // Timeouts
            // Might queue output and events
            loop {
                use futures_01::Stream;
                match inner.timers.poll() {
                    Ok(futures_01::Async::Ready(Some(expired))) => {
                        let timer = expired.into_inner();
                        inner.endpoint.timeout(now, timer.ch, timer.ty);
                        let conn = inner.conns[timer.ch.0].as_mut().unwrap();
                        conn.timers[timer.ty as usize]
                            .take()
                            .expect("unset timer expired");
                        if timer.ty == quinn::Timer::Close {
                            if let Some(conn_inner) = conn.inner.upgrade() {
                                let mut inner_state = conn_inner.state.lock().unwrap();
                                if inner_state.locally_closed {
                                    if let Some(x) = conn.closing.take() {
                                        if inner_state.error.is_none() {
                                            // For the Connection::close future to find
                                            inner_state.error = Some(closed());
                                        }
                                        x.wake();
                                    }
                                }
                            }
                            inner.forget(timer.ch);
                        }
                    }
                    Ok(futures_01::Async::Ready(None)) | Ok(futures_01::Async::NotReady) => {
                        break;
                    }
                    Err(e) => unreachable!(e),
                }
            }

            // Events
            // Generated based on handled packets and timeouts
            while let Some((ch, event)) = inner.endpoint.poll() {
                use quinn_proto::Event::*;
                if let Handshaking = event {
                    let conn = Connection::new(inner_cloned.clone(), ch);
                    inner.insert(ch, ConnState::new(Arc::downgrade(&conn.0)));
                    inner.incoming.push_back(conn);
                    if let Some(task) = inner.accepting.take() {
                        task.wake();
                    }
                }
                let conn = inner.conns[ch.0].as_mut().unwrap();
                match event {
                    Handshaking => {}
                    Connected => {
                        if let Some(sender) = conn.connected.take() {
                            // Only exists if a task is already waiting
                            let _ = sender.send(());
                        }
                    }
                    ConnectionLost { reason } => {
                        if let Some(inner) = conn.inner.upgrade() {
                            inner.state.lock().unwrap().error = Some(reason);
                            conn.wake_all();
                        }
                    }
                    StreamOpened => {
                        if let Some(task) = conn.accepting.take() {
                            task.wake();
                        }
                    }
                    StreamReadable { stream } => {
                        if let Some(task) = conn.blocked_readers.remove(&stream) {
                            task.wake();
                        }
                    }
                    StreamWritable { stream } => {
                        if let Some(task) = conn.blocked_writers.remove(&stream) {
                            task.wake();
                        }
                    }
                    StreamFinished { stream } => {
                        conn.finished.insert(stream);
                        if let Some(task) = conn.finishing.remove(&stream) {
                            task.wake();
                        }
                    }
                    StreamAvailable {
                        directionality: Directionality::Bi,
                    } => {
                        for task in conn.bi_opening.drain(..) {
                            task.wake();
                        }
                    }
                    StreamAvailable {
                        directionality: Directionality::Uni,
                    } => {
                        for task in conn.uni_opening.drain(..) {
                            task.wake();
                        }
                    }
                }
            }

            // Transmit packets
            // Triggered by handled packets, timeouts, and application activity
            let mut sent = 0;
            while let Some(xmit) = inner
                .buffered
                .take()
                .or_else(|| inner.endpoint.poll_transmit(now))
            {
                match inner.poll_send(&xmit) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        inner.buffered = Some(xmit);
                        break;
                    }
                }
                sent += 1;
                if sent >= IO_LOOP_BOUND {
                    keep_going = true;
                    break;
                }
            }

            // Update timers
            // Triggered by handled packets, timeouts, and sent packets.
            while let Some((ch, x)) = inner.endpoint.poll_timers() {
                keep_going = true; // Timers need to be polled to be scheduled
                use quinn_proto::TimerSetting::*;
                let conn = inner.conns[ch.0].as_mut().unwrap();
                match x.update {
                    Start(time) => {
                        if let Some(existing) = conn.timers[x.timer as usize].clone() {
                            inner.timers.reset_at(&existing, time);
                        } else {
                            let key = inner.timers.insert_at(Timer { ch, ty: x.timer }, time);
                            conn.timers[x.timer as usize] = Some(key);
                        }
                    }
                    Stop => {
                        if let Some(existing) = conn.timers[x.timer as usize].take() {
                            inner.timers.remove(&existing);
                        }
                    }
                }
            }
        }

        inner.driver = Some(waker.clone());
        Poll::Pending
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let inner = &mut *self.0.lock().unwrap();
        inner.dead = true;
        for mut conn in inner.conns.drain(..).filter_map(|x| x) {
            conn.wake_all();
        }
    }
}

struct EndpointInner {
    endpoint: quinn::Endpoint,
    socket: UdpSocket,
    /// Automatically convert `SocketAddr::V4`s to `V6` form for dual-stack sockets.
    ipv6: bool,
    conns: Vec<Option<ConnState>>,
    timers: DelayQueue<Timer>,
    driver: Option<Waker>,
    accepting: Option<Waker>,
    /// Packets that have been queued but not yet physically sent
    buffered: Option<Transmit>,
    /// Whether the driver was dropped
    dead: bool,
    incoming: VecDeque<Connection>,
}

impl EndpointInner {
    fn new(endpoint: quinn::Endpoint, socket: UdpSocket, ipv6: bool) -> Self {
        Self {
            endpoint,
            socket,
            ipv6,
            conns: Vec::new(),
            timers: DelayQueue::new(),
            driver: None,
            accepting: None,
            buffered: None,
            dead: false,
            incoming: VecDeque::new(),
        }
    }

    fn check_err(&self) -> Result<(), ConnectionError> {
        if self.dead {
            return Err(ConnectionError::TransportError(TransportError {
                code: TransportErrorCode::INTERNAL_ERROR,
                frame: None,
                reason: "driver future dropped".into(),
            }));
        } else {
            Ok(())
        }
    }

    fn forget(&mut self, ch: ConnectionHandle) {
        self.conns[ch.0 as usize].take().unwrap();
    }

    /// Wake up a blocked `Driver` task to process application input
    fn wake(&self) {
        if let Some(ref task) = self.driver {
            task.wake();
        }
    }

    fn poll_send(&self, xmit: &Transmit) -> Poll<Result<(), io::Error>> {
        match ready!(self
            .socket
            .poll_send(&xmit.destination, xmit.ecn, &xmit.packet))
        {
            Ok(_) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn insert(&mut self, ch: ConnectionHandle, conn: ConnState) {
        if let Some(diff) = ch.0.checked_sub(self.conns.len()) {
            self.conns.extend(iter::repeat_with(|| None).take(diff + 1));
        }
        let old = mem::replace(&mut self.conns[ch.0], Some(conn));
        debug_assert!(old.is_none(), "a prior connection wasn't cleaned up");
    }
}

struct ConnState {
    inner: Weak<ConnInner>,
    connected: Option<oneshot::Sender<()>>,
    timers: [Option<delay_queue::Key>; quinn::Timer::COUNT],
    bi_opening: Vec<Waker>,
    uni_opening: Vec<Waker>,
    blocked_readers: FxHashMap<StreamId, Waker>,
    blocked_writers: FxHashMap<StreamId, Waker>,
    finishing: FxHashMap<StreamId, Waker>,
    finished: FxHashSet<StreamId>,
    accepting: Option<Waker>,
    closing: Option<Waker>,
}

impl ConnState {
    fn new(inner: Weak<ConnInner>) -> Self {
        Self {
            inner,
            connected: None,
            timers: [None, None, None, None, None, None],
            bi_opening: Vec::new(),
            uni_opening: Vec::new(),
            blocked_readers: FxHashMap::default(),
            blocked_writers: FxHashMap::default(),
            finishing: FxHashMap::default(),
            finished: FxHashSet::default(),
            accepting: None,
            closing: None,
        }
    }

    fn wake_all(&mut self) {
        if let Some(connected) = self.connected.take() {
            let _ = connected.send(());
        }
        for task in self.uni_opening.drain(..) {
            task.wake();
        }
        for task in self.bi_opening.drain(..) {
            task.wake();
        }
        for (_, task) in self.blocked_readers.drain() {
            task.wake();
        }
        for (_, task) in self.blocked_writers.drain() {
            task.wake();
        }
        for (_, task) in self.finishing.drain() {
            task.wake();
        }
        if let Some(task) = self.accepting.take() {
            task.wake();
        }
        if let Some(task) = self.closing.take() {
            task.wake();
        }
    }
}

#[derive(Debug)]
struct Timer {
    ch: ConnectionHandle,
    ty: quinn::Timer,
}

/// A QUIC connection.
///
/// If a `Connection` and all its streams are dropped without being explicitly closed, it will be
/// automatically closed with an `error_code` of 0 and an empty `reason`.
///
/// Cloning a connection yields another handle to the same connection.
#[derive(Clone)]
pub struct Connection(Arc<ConnInner>);

impl Connection {
    fn new(inner: Arc<Mutex<EndpointInner>>, ch: ConnectionHandle) -> Self {
        Connection(Arc::new(ConnInner {
            inner,
            ch,
            state: Mutex::new(ConnInnerState {
                locally_closed: false,
                error: None,
            }),
        }))
    }

    /// Initite a new outgoing unidirectional stream.
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        let id = await!(self.open_inner(Directionality::Uni))?;
        Ok(SendStream::new(self.0.clone(), id))
    }

    /// Initiate a new outgoing bidirectional stream.
    pub async fn open_bi(&self) -> Result<BiStream, ConnectionError> {
        let id = await!(self.open_inner(Directionality::Bi))?;
        Ok(BiStream::new(self.0.clone(), id))
    }

    async fn open_inner(&self, dir: Directionality) -> Result<StreamId, ConnectionError> {
        await!(future::poll_fn(move |waker| {
            self.0.check_err()?;
            let inner = &mut *self.0.inner.lock().unwrap();
            inner.check_err()?;
            if let Some(id) = inner.endpoint.open(self.0.ch, dir) {
                Poll::Ready(Ok(id))
            } else {
                let conn = inner.conns[self.0.ch.0].as_mut().unwrap();
                let wakers = match dir {
                    Directionality::Bi => &mut conn.bi_opening,
                    Directionality::Uni => &mut conn.uni_opening,
                };
                wakers.push(waker.clone());
                Poll::Pending
            }
        }))
    }

    /// Close the connection immediately.
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to
    /// call this only when all important communications have been completed.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to be certain it is
    /// preserved in full, it should be kept under 1KiB.
    pub async fn close<'a>(&'a self, error_code: u16, reason: &'a [u8]) {
        self.0.close(error_code, reason);
        // If we're already closing the connection, we by don't care if the connection fails;
        // anything we cared about must have been accounted for already.
        await!(future::poll_fn(move |waker| -> Poll<()> {
            if self.0.state.lock().unwrap().error.is_some() {
                return Poll::Ready(());
            }
            let inner = &mut *self.0.inner.lock().unwrap();
            if inner.check_err().is_err() {
                return Poll::Ready(());
            }
            let conn = inner.conns[self.0.ch.0].as_mut().unwrap();
            conn.closing = Some(waker.clone());
            Poll::Pending
        }));
    }

    fn get<T>(&self, f: impl FnOnce(&quinn::Connection) -> T) -> T {
        f(self.0.inner.lock().unwrap().endpoint.connection(self.0.ch))
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.get(|x| x.remote())
    }

    /// The `ConnectionId`s defined for `conn` locally.
    pub fn local_ids(&self) -> impl Iterator<Item = ConnectionId> {
        self.get(|x| x.loc_cids().cloned().collect::<Vec<_>>().into_iter())
    }

    /// The `ConnectionId` defined for `conn` by the peer.
    pub fn remote_id(&self) -> ConnectionId {
        self.get(|x| x.rem_cid())
    }

    /// The negotiated application protocol
    pub fn protocol(&self) -> Option<Box<[u8]>> {
        self.get(|x| x.protocol().map(|x| x.to_vec().into()))
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0
            .inner
            .lock()
            .unwrap()
            .endpoint
            .force_key_update(self.0.ch);
    }
}

struct ConnInner {
    inner: Arc<Mutex<EndpointInner>>,
    ch: ConnectionHandle,
    state: Mutex<ConnInnerState>,
}

impl ConnInner {
    fn close(&self, error_code: u16, reason: &[u8]) {
        {
            let mut state = self.state.lock().unwrap();
            if state.locally_closed || state.error.is_some() {
                // Already closed
                return;
            }
            state.locally_closed = true;
        }
        let inner = &mut *self.inner.lock().unwrap();
        if inner.check_err().is_err() {
            return;
        }
        let now = Instant::now();
        let conn = inner.conns[self.ch.0 as usize].as_mut().unwrap();
        inner
            .endpoint
            .close(now, self.ch, error_code, reason.into());
        conn.wake_all();
        inner.wake();
    }

    fn check_err(&self) -> Result<(), ConnectionError> {
        let state = self.state.lock().unwrap();
        if state.locally_closed {
            return Err(closed());
        }
        if let Some(ref e) = state.error {
            return Err(e.clone());
        }
        Ok(())
    }
}

impl Drop for ConnInner {
    fn drop(&mut self) {
        self.close(0, &[]);
    }
}

struct ConnInnerState {
    /// Whether a locally-initiated close is underway
    locally_closed: bool,
    error: Option<ConnectionError>,
}

/// A bidirectional stream, consisting of send and receive halves
pub struct BiStream {
    /// The half of the stream on which outgoing data is written
    pub send: SendStream,
    /// The half of the stream on which incoming data is read
    pub recv: RecvStream,
}

impl BiStream {
    fn new(conn: Arc<ConnInner>, id: StreamId) -> Self {
        debug_assert_eq!(id.directionality(), Directionality::Bi);
        Self {
            send: SendStream::new(conn.clone(), id),
            recv: RecvStream::new(conn, id),
        }
    }
}

/// A stream that can only be used to send data
pub struct SendStream {
    conn: Arc<ConnInner>,
    id: StreamId,
    finishing: bool,
    closed: bool,
}

impl SendStream {
    fn new(conn: Arc<ConnInner>, id: StreamId) -> Self {
        Self {
            conn,
            id,
            finishing: false,
            closed: false,
        }
    }

    fn write_inner(&mut self, lw: &Waker, buf: &[u8]) -> Poll<Result<usize, WriteError>> {
        self.conn.check_err().map_err(WriteError::ConnectionLost)?;
        let inner = &mut *self.conn.inner.lock().unwrap();
        inner.check_err().map_err(WriteError::ConnectionLost)?;
        use crate::quinn::WriteError::*;
        match inner.endpoint.write(self.conn.ch, self.id, buf) {
            Ok(n) => {
                inner.wake();
                Poll::Ready(Ok(n))
            }
            Err(Blocked) => {
                let conn = inner.conns[self.conn.ch.0].as_mut().unwrap();
                conn.blocked_writers.insert(self.id, lw.clone());
                Poll::Pending
            }
            Err(Stopped { error_code }) => Poll::Ready(Err(WriteError::Stopped { error_code })),
        }
    }

    /// Write bytes to the stream.
    ///
    /// Returns the number of bytes written on success. Congestion and flow control may cause this
    /// to be shorter than `buf.len()`, indicating that only a prefix of `buf` was written.
    pub async fn write<'a>(&'a mut self, buf: &'a [u8]) -> Result<usize, WriteError> {
        await!(future::poll_fn(move |waker| self.write_inner(waker, buf)))
    }

    /// Write the full length of `buf` to the stream.
    pub async fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Result<(), WriteError> {
        let mut written = 0;
        while written != buf.len() {
            written += await!(self.write(&buf[written..]))?;
        }
        Ok(())
    }

    /// Shut down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        self.start_finish()?;
        await!(future::poll_fn(move |waker| self.poll_finish(waker)))
    }

    fn start_finish(&mut self) -> Result<(), ConnectionError> {
        self.finishing = true;
        if self.closed {
            return Ok(());
        }
        self.conn.check_err()?;
        {
            let inner = &mut *self.conn.inner.lock().unwrap();
            inner.check_err()?;
            inner.endpoint.finish(self.conn.ch, self.id);
        }
        Ok(())
    }

    fn poll_finish(&mut self, lw: &Waker) -> Poll<Result<(), ConnectionError>> {
        self.conn.check_err()?;
        let inner = &mut *self.conn.inner.lock().unwrap();
        inner.check_err()?;
        let conn = inner.conns[self.conn.ch.0].as_mut().unwrap();
        if conn.finished.remove(&self.id) {
            inner.wake();
            self.closed = true;
            Poll::Ready(Ok(()))
        } else {
            conn.finishing.insert(self.id, lw.clone());
            Poll::Pending
        }
    }

    /// Close the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped, and
    /// previously transmitted data will no longer be retransmitted if lost. If `finish` was called
    /// previously and all data has already been transmitted at least once, the peer may receive all
    /// written data and ignore the reset.
    pub fn reset(&mut self, error_code: u16) {
        if mem::replace(&mut self.closed, true) {
            return;
        }
        if self.conn.check_err().is_err() {
            return;
        }
        let inner = &mut *self.conn.inner.lock().unwrap();
        if inner.check_err().is_err() {
            return;
        }
        inner.endpoint.reset(self.conn.ch, self.id, error_code);
        inner.wake();
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(&mut self, lw: &Waker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.write_inner(lw, buf).map(|x| x.map_err(Into::into))
    }

    fn poll_flush(&mut self, _: &Waker) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(&mut self, lw: &Waker) -> Poll<Result<(), io::Error>> {
        if !self.finishing {
            self.start_finish()?;
        }
        self.poll_finish(lw).map(|x| x.map_err(Into::into))
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        self.reset(0);
    }
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
    /// The connection was lost.
    #[error(display = "connection lost: {}", _0)]
    ConnectionLost(ConnectionError),
}

impl From<WriteError> for io::Error {
    fn from(x: WriteError) -> Self {
        use self::WriteError::*;
        match x {
            Stopped { error_code } => io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream stopped by peer: error {}", error_code),
            ),
            ConnectionLost(e) => e.into(),
        }
    }
}

/// A stream that can only be used to receive data
pub struct RecvStream {
    conn: Arc<ConnInner>,
    id: StreamId,
    closed: bool,
}

impl RecvStream {
    fn new(conn: Arc<ConnInner>, id: StreamId) -> Self {
        Self {
            conn,
            id,
            closed: false,
        }
    }

    fn read_inner(&mut self, lw: &Waker, buf: &mut [u8]) -> Poll<Result<usize, ReadError>> {
        self.conn.check_err().map_err(ReadError::ConnectionLost)?;
        let inner = &mut *self.conn.inner.lock().unwrap();
        inner.check_err().map_err(ReadError::ConnectionLost)?;
        use crate::quinn::ReadError::*;
        match inner.endpoint.read(self.conn.ch, self.id, buf) {
            Ok(n) => {
                inner.wake();
                Poll::Ready(Ok(n))
            }
            Err(Blocked) => {
                let conn = inner.conns[self.conn.ch.0].as_mut().unwrap();
                conn.blocked_readers.insert(self.id, lw.clone());
                Poll::Pending
            }
            Err(Reset { error_code }) => {
                self.closed = true;
                Poll::Ready(Err(ReadError::Reset { error_code }))
            }
            Err(Finished) => {
                self.closed = true;
                Poll::Ready(Err(ReadError::Finished))
            }
            Err(UnknownStream) => Poll::Ready(Err(ReadError::UnknownStream)),
        }
    }

    /// Read data contiguously from the stream.
    ///
    /// Returns the number of bytes read into `buf` on success.
    ///
    /// Applications involving bulk data transfer should consider using unordered reads for improved
    /// performance.
    ///
    /// # Panics
    /// - If called after `read_unordered` was called on the same stream.
    ///   This is forbidden because an unordered read could consume a segment of data from a
    ///   location other than the start of the receive buffer, making it impossible for future
    ///   ordered reads to proceed.
    pub async fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<usize, ReadError> {
        await!(future::poll_fn(move |waker| self.read_inner(waker, buf)))
    }

    /// Read a segment of data from any offset in the stream.
    ///
    /// Returns a segment of data and their offset in the stream. Segments may be received in any
    /// order and may overlap.
    ///
    /// Unordered reads have reduced overhead and higher throughput, and should therefore be
    /// preferred when applicable.
    pub async fn read_unordered(&mut self) -> Result<(Bytes, u64), ReadError> {
        await!(future::poll_fn(move |waker| {
            self.conn.check_err().map_err(ReadError::ConnectionLost)?;
            let inner = &mut *self.conn.inner.lock().unwrap();
            inner.check_err().map_err(ReadError::ConnectionLost)?;
            use crate::quinn::ReadError::*;
            match inner.endpoint.read_unordered(self.conn.ch, self.id) {
                Ok(x) => {
                    inner.wake();
                    Poll::Ready(Ok(x))
                }
                Err(Blocked) => {
                    let conn = inner.conns[self.conn.ch.0].as_mut().unwrap();
                    conn.blocked_readers.insert(self.id, waker.clone());
                    Poll::Pending
                }
                Err(Reset { error_code }) => {
                    self.closed = true;
                    Poll::Ready(Err(ReadError::Reset { error_code }))
                }
                Err(Finished) => {
                    self.closed = true;
                    Poll::Ready(Err(ReadError::Finished))
                }
                Err(UnknownStream) => Poll::Ready(Err(ReadError::UnknownStream)),
            }
        }))
    }

    /// Close the receive stream immediately.
    ///
    /// The peer is notified and will cease transmitting on this stream, as if it had reset the
    /// stream itself. Further data may still be received on this stream if it was already in
    /// flight. Once called, a [`ReadError::Reset`] should be expected soon, although a peer might
    /// manage to finish the stream before it receives the reset, and a misbehaving peer might
    /// ignore the request entirely and continue sending until halted by flow control.
    ///
    /// Has no effect if the incoming stream already finished.
    pub fn stop(&mut self, error_code: u16) {
        if mem::replace(&mut self.closed, true) {
            return;
        }
        if self.conn.check_err().is_err() {
            return;
        }
        let inner = &mut *self.conn.inner.lock().unwrap();
        if inner.check_err().is_err() {
            return;
        }
        inner
            .endpoint
            .stop_sending(self.conn.ch, self.id, error_code);
        inner.wake();
    }

    /// Read the entire stream, or return [`ReadError::Finished`] if it exceeds `limit` bytes.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Box<[u8]>, ReadError> {
        let mut buf = Vec::new();
        loop {
            match await!(self.read_unordered()) {
                Ok((data, offset)) => {
                    let len = buf.len().max(offset as usize + data.len());
                    if len > limit {
                        return Err(ReadError::Finished);
                    }
                    buf.resize(len, 0);
                    buf[offset as usize..offset as usize + data.len()].copy_from_slice(&data);
                }
                Err(ReadError::Finished) => {
                    return Ok(buf.into());
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(&mut self, lw: &Waker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        self.read_inner(lw, buf).map(|x| x.map_err(Into::into))
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        self.stop(0);
    }
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
    /// The connection was lost.
    #[error(display = "connection lost: {}", _0)]
    ConnectionLost(ConnectionError),
    /// Either `Finished` or `Reset` was returned from a previous call, invalidating the stream.
    ///
    /// A well-behaved application should never call `read` after receiving either error, and will
    /// therefore never encounter this error.
    #[error(display = "stream no longer exists")]
    UnknownStream,
}

impl From<ReadError> for io::Error {
    fn from(x: ReadError) -> Self {
        use self::ReadError::*;
        match x {
            ConnectionLost(e) => e.into(),
            Reset { error_code } => io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset by peer: error {}", error_code),
            ),
            Finished => io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished"),
            UnknownStream => io::Error::new(io::ErrorKind::NotConnected, "stream no longer exists"),
        }
    }
}

/// Connections initiated by remote clients
pub struct IncomingConnections(Arc<Mutex<EndpointInner>>);

impl Stream for IncomingConnections {
    type Item = Handshake;
    fn poll_next(mut self: Pin<&mut Self>, lw: &Waker) -> Poll<Option<Self::Item>> {
        let inner = &mut *self.0.lock().unwrap();
        if inner.check_err().is_err() {
            return Poll::Ready(None);
        }
        if let Some(conn) = inner.incoming.pop_front() {
            inner.endpoint.accept();
            let ch = conn.0.ch;
            let mut hs = Handshake::new(conn);
            if inner.endpoint.connection(ch).is_handshaking() {
                let (send, recv) = oneshot::channel();
                inner.conns[ch.0].as_mut().unwrap().connected = Some(send);
                hs.connected = Some(recv);
            }
            return Poll::Ready(Some(hs));
        }
        inner.accepting = Some(lw.clone());
        Poll::Pending
    }
}

/// Streams initiated by the remote peer
pub struct IncomingStreams(Arc<ConnInner>);

impl Stream for IncomingStreams {
    type Item = NewStream;
    fn poll_next(mut self: Pin<&mut Self>, lw: &Waker) -> Poll<Option<Self::Item>> {
        let cloned = self.0.clone();
        if self.0.check_err().is_err() {
            return Poll::Ready(None);
        }
        let inner = &mut *self.0.inner.lock().unwrap();
        if inner.check_err().is_err() {
            return Poll::Ready(None);
        }
        let conn = inner.conns[cloned.ch.0].as_mut().unwrap();
        if let Some(id) = inner.endpoint.accept_stream(cloned.ch) {
            let recv = RecvStream::new(cloned.clone(), id);
            return Poll::Ready(Some(match id.directionality() {
                Directionality::Bi => NewStream::Bi(BiStream {
                    send: SendStream::new(cloned, id),
                    recv,
                }),
                Directionality::Uni => NewStream::Uni(recv),
            }));
        }
        conn.accepting = Some(lw.clone());
        Poll::Pending
    }
}

/// A stream initiated by a remote peer.
pub enum NewStream {
    /// A bidirectional stream.
    Bi(BiStream),
    /// A unidirectional stream.
    Uni(RecvStream),
}

fn ensure_ipv6(x: &SocketAddr) -> SocketAddrV6 {
    match *x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(ref x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

/// Construct the error that a peer might produce in response to a locally initiated close
fn closed() -> ConnectionError {
    ConnectionError::ConnectionClosed {
        reason: ConnectionClose {
            error_code: TransportErrorCode::NO_ERROR,
            frame_type: None,
            reason: [][..].into(),
        },
    }
}
