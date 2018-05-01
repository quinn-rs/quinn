//! QUIC transport protocol support for Tokio
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing shortcomings of TCP, such as
//! head-of-line blocking, poor security, slow handshakes, and inefficient congestion control. This crate provides a
//! portable userspace implementation.
//!
//! The entry point of this crate is the [`Endpoint`](struct.Endpoint.html).
//!
//! The futures and streams defined in this crate are not `Send` because they necessarily share state with eachother. As
//! a result, they must be spawned using an executor that operates on the same thread that they were constructed, such
//! as with `tokio::executor::current_thread`. The standard tokio runtime offloads futures to a threadpool, so its
//! components must instead be pieced together by hand as follows:
//!
//! ```
//! extern crate tokio;
//! extern crate tokio_timer;
//! extern crate quicr;
//! extern crate futures;
//!
//! use futures::Future;
//!
//! fn main() {
//!   let reactor = tokio::reactor::Reactor::new().unwrap();
//!   let reactor_handle = reactor.handle();
//!   let timer = tokio_timer::Timer::new(reactor);
//!   let timer_handle = timer.handle();
//!   let mut executor = tokio::executor::current_thread::CurrentThread::new_with_park(timer);
//!
//!   let mut builder = quicr::Endpoint::new();
//!   builder.reactor(&reactor_handle).timer(timer_handle);
//!   let (endpoint, driver, _) = builder.bind("[::]:0").unwrap();
//!
//!   executor.spawn(driver.map_err(|e| panic!("IO error: {}", e)));
//!   // ...
//! }
//! ```

#![warn(missing_docs)]

extern crate quicr_core as quicr;
extern crate tokio_reactor;
extern crate tokio_udp;
extern crate tokio_io;
extern crate tokio_timer;
#[macro_use]
extern crate slog;
extern crate futures;
extern crate fnv;
extern crate openssl;
#[macro_use]
extern crate failure;
extern crate bytes;
extern crate rand;

use std::{io, mem};
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::{VecDeque, hash_map};
use std::time::{Instant, Duration};
use std::borrow::Cow;

use tokio_udp::UdpSocket;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::{Delay, timer};
use slog::Logger;
use futures::{Future, Poll, Async};
use futures::Stream as FuturesStream;
use futures::unsync::{oneshot, mpsc};
use futures::task::{self, Task};
use futures::stream::FuturesUnordered;
use fnv::FnvHashMap;
use openssl::ssl;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl::asn1::Asn1Time;
use bytes::Bytes;

use quicr::{Directionality, StreamId, ConnectionHandle, Side, CertConfig};

pub use quicr::{Config, ConnectionError, ConnectionId, ListenKeys};

/// Errors that can occur during the construction of an `Endpoint`.
#[derive(Debug, Fail)]
pub enum Error {
    /// An error arising during setup of the underlying UDP socket.
    #[fail(display = "failed to set up UDP socket: {}", _0)]
    Socket(io::Error),
    /// An error arising from the TLS layer.
    #[fail(display = "failed to set up TLS: {}", _0)]
    Tls(ssl::Error),
    /// An error arising from opening a file for logging TLS keys.
    #[fail(display = "failed open keylog file: {}", _0)]
    Keylog(io::Error),
}

impl From<quicr::EndpointError> for Error {
    fn from(x: quicr::EndpointError) -> Self {
        use quicr::EndpointError::*;
        match x {
            Tls(x) => Error::Tls(x),
            Keylog(x) => Error::Keylog(x),
        }
    }
}

struct EndpointInner {
    log: Logger,
    timer: timer::Handle,
    socket: UdpSocket,
    inner: quicr::Endpoint,
    outgoing: VecDeque<(SocketAddrV6, Box<[u8]>)>,
    epoch: Instant,
    pending: FnvHashMap<ConnectionHandle, Pending>,
    // TODO: Replace this with something custom that avoids using oneshots to cancel
    timers: FuturesUnordered<Timer>,
    incoming: mpsc::UnboundedSender<NewConnection>,
    driver: Option<Task>,
}

impl EndpointInner {
    /// Wake up a blocked `Driver` task to process I/O
    fn notify(&self) { self.driver.as_ref().map(|x| x.notify()); }
}

struct Pending {
    blocked_writers: FnvHashMap<StreamId, Task>,
    blocked_readers: FnvHashMap<StreamId, Task>,
    connecting: Option<oneshot::Sender<Option<ConnectionError>>>,
    uni_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionError>>>,
    cancel_loss_detect: Option<oneshot::Sender<()>>,
    cancel_idle: Option<oneshot::Sender<()>>,
    incoming_streams: VecDeque<StreamId>,
    incoming_streams_reader: Option<Task>,
    finishing: FnvHashMap<StreamId, oneshot::Sender<Option<ConnectionError>>>,
    error: Option<ConnectionError>,
    draining: Option<oneshot::Sender<()>>,
    drained: bool,
}

impl Pending {
    fn new(connecting: Option<oneshot::Sender<Option<ConnectionError>>>) -> Self { Self {
        blocked_writers: FnvHashMap::default(),
        blocked_readers: FnvHashMap::default(),
        connecting,
        uni_opening: VecDeque::new(),
        bi_opening: VecDeque::new(),
        cancel_loss_detect: None,
        cancel_idle: None,
        incoming_streams: VecDeque::new(),
        incoming_streams_reader: None,
        finishing: FnvHashMap::default(),
        error: None,
        draining: None,
        drained: false,
    }}

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

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both client and server for
/// different connections.
pub struct Endpoint(Rc<RefCell<EndpointInner>>);

/// A future that drives IO on an endpoint.
pub struct Driver(Rc<RefCell<EndpointInner>>);

/// Stream of incoming connections.
pub type Incoming = mpsc::UnboundedReceiver<NewConnection>;

/// A helper for constructing an `Endpoint`.
pub struct EndpointBuilder<'a> {
    reactor: Option<&'a tokio_reactor::Handle>,
    timer: Option<timer::Handle>,
    logger: Logger,
    listen: Option<ListenKeys>,
    config: Config,
    private_key: Option<PKey<Private>>,
    cert: Option<X509>,
}

#[allow(missing_docs)]
impl<'a> EndpointBuilder<'a> {
    pub fn reactor(&mut self, handle: &'a tokio_reactor::Handle) -> &mut Self { self.reactor = Some(handle); self }
    pub fn timer(&mut self, handle: timer::Handle) -> &mut Self { self.timer = Some(handle); self }
    pub fn logger(&mut self, logger: Logger) -> &mut Self { self.logger = logger; self }
    pub fn config(&mut self, config: Config) -> &mut Self { self.config = config; self }

    /// Prefer `listen_with_keys`.
    pub fn listen(&mut self) -> &mut Self { self.listen = Some(ListenKeys::new(&mut rand::thread_rng())); self }

    /// Use with persistent `keys` instead of `listen` to allow graceful reset of clients when the server restarts.
    pub fn listen_with_keys(&mut self, keys: ListenKeys) -> &mut Self { self.listen = Some(keys); self }

    pub fn private_key_pem(&mut self, key: &[u8]) -> Result<&mut Self, ssl::Error> {
        self.private_key = Some(PKey::<Private>::private_key_from_pem(key)?);
        Ok(self)
    }
    pub fn certificate_pem(&mut self, cert: &[u8]) -> Result<&mut Self, ssl::Error> {
        self.cert = Some(X509::from_pem(&cert)?);
        Ok(self)
    }
    pub fn private_key_der(&mut self, key: &[u8]) -> Result<&mut Self, ssl::Error> {
        self.private_key = Some(PKey::<Private>::private_key_from_der(key)?);
        Ok(self)
    }
    pub fn certificate_der(&mut self, cert: &[u8]) -> Result<&mut Self, ssl::Error> {
        self.cert = Some(X509::from_der(&cert)?);
        Ok(self)
    }

    /// Generate a key pair and self-signed TLS certificate.
    ///
    /// Peers will be unable to verify this endpoint's identity. Useful when want to host a server with a minimum of
    /// set-up and don't need to prevent man-in-the-middle attacks.
    pub fn generate_insecure_certificate(&mut self) -> Result<&mut Self, ssl::Error> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut cert = X509::builder()?;
        cert.set_pubkey(&key)?;
        let now = Asn1Time::days_from_now(0)?;
        cert.set_not_before(&now)?;
        let forever = Asn1Time::days_from_now(u32::max_value())?;
        cert.set_not_after(&forever)?;
        cert.sign(&key, openssl::hash::MessageDigest::sha256())?;
        self.cert = Some(cert.build());
        self.private_key = Some(key);
        Ok(self)
    }

    pub fn from_socket(self, socket: std::net::UdpSocket) -> Result<(Endpoint, Driver, Incoming), Error> {
        let cert = self.cert;
        let cert_config = self.private_key.as_ref().and_then(|private_key| cert.as_ref().map(|cert| CertConfig { private_key, cert }));
        let reactor = if let Some(x) = self.reactor { Cow::Borrowed(x) } else { Cow::Owned(tokio_reactor::Handle::current()) };
        let socket = UdpSocket::from_std(socket, &reactor).map_err(Error::Socket)?;
        let (send, recv) = mpsc::unbounded();
        let rc = Rc::new(RefCell::new(EndpointInner {
            timer: self.timer.unwrap_or_else(|| timer::Handle::current()),
            log: self.logger.clone(),
            socket: socket,
            inner: quicr::Endpoint::new(self.logger, self.config, cert_config, self.listen)?,
            outgoing: VecDeque::new(),
            epoch: Instant::now(),
            pending: FnvHashMap::default(),
            timers: FuturesUnordered::new(),
            incoming: send,
            driver: None,
        }));
        Ok((Endpoint(rc.clone()), Driver(rc), recv))
    }

    pub fn bind<T: ToSocketAddrs>(self, addr: T) -> Result<(Endpoint, Driver, Incoming), Error> {
        let socket = std::net::UdpSocket::bind(addr).map_err(Error::Socket)?;
        self.from_socket(socket)
    }
}

impl<'a> Default for EndpointBuilder<'a> {
    fn default() -> Self { Endpoint::new() }
}

impl Endpoint {
    /// Begin constructing an `Endpoint`
    pub fn new<'a>() -> EndpointBuilder<'a> { EndpointBuilder {
        reactor: None,
        timer: None,
        logger: Logger::root(slog::Discard, o!()),
        listen: None,
        config: Config::default(),
        cert: None,
        private_key: None,
    }}

    /// Connect to a remote endpoint.
    ///
    /// `hostname` is used by the remote endpoint for disambiguation if `addr` hosts multiple services.
    pub fn connect(&self, addr: &SocketAddr, hostname: Option<&[u8]>) -> Box<Future<Item=(Connection, IncomingStreams), Error=ConnectionError>> {
        let (send, recv) = oneshot::channel();
        let conn = {
            let mut endpoint = self.0.borrow_mut();
            let conn = endpoint.inner.connect(normalize(*addr), hostname);
            endpoint.pending.insert(conn, Pending::new(Some(send)));
            conn
        };
        let endpoint = Endpoint(self.0.clone());
        let conn = Rc::new(ConnectionInner { endpoint: Endpoint(self.0.clone()), conn, side: Side::Client });
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(move |err| if let Some(err) = err { Err(err) } else {
                    Ok((Connection(conn.clone()), IncomingStreams { endpoint, conn }))
                })
        )
    }
}

/// A connection initiated by a remote client.
pub struct NewConnection {
    /// The connection itself.
    pub connection: Connection,
    /// The stream of QUIC streams initiated by the client.
    pub incoming: IncomingStreams,
    /// Identifier of the application-layer protocol that was negotiated.
    pub protocol: Option<Box<[u8]>>,
}

impl NewConnection {
    fn new(endpoint: Endpoint, info: quicr::NewConnection) -> Self {
        let quicr::NewConnection { handle, protocol } = info;
        let conn = Rc::new(ConnectionInner {
            endpoint: Endpoint(endpoint.0.clone()),
            conn: handle,
            side: Side::Server,
        });
        NewConnection {
            connection: Connection(conn.clone()),
            incoming: IncomingStreams { endpoint, conn },
            protocol,
        }
    }
}

impl Future for Driver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut buf = [0; 64 * 1024];
        let endpoint = &mut *self.0.borrow_mut();
        if endpoint.driver.is_none() { endpoint.driver = Some(task::current()); }
        let now = micros_from(endpoint.epoch.elapsed());
        loop {
            loop {
                match endpoint.socket.poll_recv_from(&mut buf) {
                    Ok(Async::Ready((n, addr))) => {
                        endpoint.inner.handle(now, normalize(addr), (&buf[0..n]).into());
                    }
                    Ok(Async::NotReady) => { break; }
                    // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an attacker
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => { continue; }
                    Err(e) => { return Err(e); }
                }
            }
            while let Some((connection, event)) = endpoint.inner.poll() {
                use quicr::Event::*;
                match event {
                    Connected { .. } => {
                        let _ = endpoint.pending.get_mut(&connection).unwrap().connecting.take()
                            .expect("got Connected event for unknown connection")
                            .send(None);
                    }
                    ConnectionLost { reason } => {
                        endpoint.pending.get_mut(&connection).unwrap().fail(reason);
                    }
                    ConnectionDrained => {
                        if let Some(x) = endpoint.pending.get_mut(&connection).and_then(|p| { p.drained = true; p.draining.take() }) {
                            let _ = x.send(());
                        }
                    }
                    StreamWritable { stream } => {
                        if let Some(writer) = endpoint.pending.get_mut(&connection).unwrap().blocked_writers.remove(&stream) {
                            writer.notify();
                        }
                    }
                    StreamReadable { stream, fresh } => {
                        let pending = endpoint.pending.get_mut(&connection).unwrap();
                        if let Some(reader) = pending.blocked_readers.remove(&stream) {
                            reader.notify();
                        }
                        if fresh {
                            pending.incoming_streams.push_back(stream);
                            if let Some(x) = pending.incoming_streams_reader.take() { x.notify(); }
                        }
                    }
                    StreamAvailable { directionality } => {
                        let pending = endpoint.pending.get_mut(&connection).unwrap();
                        let queue = match directionality {
                            Directionality::Uni => &mut pending.uni_opening,
                            Directionality::Bi => &mut pending.bi_opening,
                        };
                        while let Some(ch) = queue.pop_front() {
                            if let Some(id) = endpoint.inner.open(connection, directionality) {
                                let _ = ch.send(Ok(id));
                            } else {
                                queue.push_front(ch);
                                break;
                            }
                        }
                    }
                    StreamFinished { stream } => {
                        let _ = endpoint.pending.get_mut(&connection).unwrap()
                            .finishing.remove(&stream).unwrap().send(None);
                    }
                }
            }
            let mut blocked = false;
            while !endpoint.outgoing.is_empty() {
                {
                    let front = endpoint.outgoing.front().unwrap();
                    match endpoint.socket.poll_send_to(&front.1, &front.0.into()) {
                        Ok(Async::Ready(_)) => {}
                        Ok(Async::NotReady) => { blocked = true; break; }
                        Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => { blocked = true; break; }
                        Err(e) => { return Err(e); }
                    }
                }
                endpoint.outgoing.pop_front();
            }
            while let Some(io) = endpoint.inner.poll_io(now) {
                use quicr::Io::*;
                match io {
                    Transmit { destination, packet } => {
                        if !blocked {
                            match endpoint.socket.poll_send_to(&packet, &destination.into()) {
                                Ok(Async::Ready(_)) => {}
                                Ok(Async::NotReady) => { blocked = true; }
                                Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => { blocked = true; }
                                Err(e) => { return Err(e); }
                            }
                        }
                        if blocked {
                            endpoint.outgoing.push_front((destination, packet));
                        }
                    }
                    TimerStart { connection, timer: timer@quicr::Timer::Close, time } => {
                        let instant = endpoint.epoch + duration_micros(time);
                        endpoint.timers.push(Timer {
                            conn: connection,
                            ty: timer,
                            delay: endpoint.timer.delay(instant),
                            cancel: None,
                        });
                    }
                    TimerStart { connection, timer, time } => {
                        // Loss detection and idle timers start before the connection is established
                        let pending = endpoint.pending.entry(connection).or_insert_with(|| Pending::new(None));
                        use quicr::Timer::*;
                        let mut cancel = match timer {
                            LossDetection => &mut pending.cancel_loss_detect,
                            Idle => &mut pending.cancel_idle,
                            Close => unreachable!()
                        };
                        let instant = endpoint.epoch + duration_micros(time);
                        if let Some(cancel) = cancel.take() {
                            let _ = cancel.send(());
                        }
                        let (send, recv) = oneshot::channel();
                        *cancel = Some(send);
                        trace!(endpoint.log, "timer start"; "timer" => ?timer, "time" => ?duration_micros(time));
                        endpoint.timers.push(Timer {
                            conn: connection,
                            ty: timer,
                            delay: endpoint.timer.delay(instant),
                            cancel: Some(recv),
                        });
                    }
                    TimerStop { connection, timer } => {
                        trace!(endpoint.log, "timer stop"; "timer" => ?timer);
                        // If a connection was lost, we already canceled its loss/idle timers.
                        if let Some(pending) = endpoint.pending.get_mut(&connection) {
                            use quicr::Timer::*;
                            match timer {
                                LossDetection => { pending.cancel_loss_detect.take().map(|x| x.send(()).unwrap()); }
                                Idle => { pending.cancel_idle.take().map(|x| x.send(())); }
                                Close => { unreachable!() }
                            }
                        }
                    }
                }
            }
            while let Some(x) = endpoint.inner.accept() {
                let _ = endpoint.incoming.unbounded_send(NewConnection::new(Endpoint(self.0.clone()), x));
            }
            let mut fired = false;
            loop {
                match endpoint.timers.poll() {
                    Ok(Async::Ready(Some(Some((conn, timer))))) => {
                        trace!(endpoint.log, "timeout"; "timer" => ?timer);
                        endpoint.inner.timeout(now, conn, timer);
                        fired = true;
                    }
                    Ok(Async::Ready(Some(None))) => {}
                    Ok(Async::Ready(None)) | Ok(Async::NotReady) => { break; }
                    Err(()) => unreachable!()
                }
            }
            if !fired { break; }
        }
        Ok(Async::NotReady)
    }
}

fn duration_micros(x: u64) -> Duration { Duration::new(x / (1000 * 1000), (x % (1000 * 1000)) as u32 * 1000) }
fn micros_from(x: Duration) -> u64 { x.as_secs() * 1000 * 1000 + (x.subsec_nanos() / 1000) as u64 }

fn normalize(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

struct ConnectionInner {
    endpoint: Endpoint,
    conn: ConnectionHandle,
    side: Side,
}

/// A QUIC connection.
///
/// If a `Connection` is dropped without being explicitly closed, it will be automatically closed with an `error_code`
/// of 0 and an empty `reason`.
pub struct Connection(Rc<ConnectionInner>);

impl Connection {
    /// Initite a new outgoing unidirectional stream.
    pub fn open_uni(&self) -> Box<Future<Item=SendStream, Error=ConnectionError>> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.0.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.conn, Directionality::Uni) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.conn).unwrap();
                pending.uni_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more streams
            }
        }
        let conn = self.0.clone();
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(|result| result)
                .map(move |stream| SendStream(Stream::new(conn, stream)))
        )
    }

    /// Initiate a new outgoing bidirectional stream.
    pub fn open_bi(&self) -> Box<Future<Item=Stream, Error=ConnectionError>> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.0.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.conn, Directionality::Bi) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.conn).unwrap();
                pending.bi_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more streams
            }
        }
        let conn = self.0.clone();
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(|result| result)
                .map(move |stream| {
                    Stream::new(conn.clone(), stream)
                })
        )
    }

    /// Close the connection immediately.
    ///
    /// This does not ensure delivery of outstanding data. It is the application's responsibility to call this only when
    /// all important communications have been completed.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to be certain it is preserved in full, it
    /// should be kept under 1KiB.
    // FIXME: Infallible
    pub fn close(self, error_code: u16, reason: &[u8]) -> Box<Future<Item=(), Error=()>> {
        let (send, recv) = oneshot::channel();
        {
            let endpoint = &mut *self.0.endpoint.0.borrow_mut();
            endpoint.inner.close(micros_from(endpoint.epoch.elapsed()), self.0.conn, error_code, reason.into());
            let pending = endpoint.pending.get_mut(&self.0.conn).unwrap();
            pending.draining = Some(send);
        }
        Box::new(recv.then(move |_| { let _ = self; Ok(()) }))
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        (*self.0.endpoint.0.borrow().inner.get_remote_address(self.0.conn)).into()
    }

    /// The `ConnectionId` used for `conn` locally.
    pub fn local_id(&self) -> ConnectionId {
        self.0.endpoint.0.borrow().inner.get_local_id(self.0.conn).clone()
    }
    /// The `ConnectionId` used for `conn` by the peer.
    pub fn remote_id(&self) -> ConnectionId {
        self.0.endpoint.0.borrow().inner.get_remote_id(self.0.conn).clone()
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        if let hash_map::Entry::Occupied(pending) = endpoint.pending.entry(self.conn) {
            if pending.get().draining.is_none() && !pending.get().drained {
                endpoint.inner.close(micros_from(endpoint.epoch.elapsed()), self.conn, 0, (&[][..]).into());
                endpoint.driver.as_ref().map(|x| x.notify());
            }
            pending.remove_entry();
        } else { unreachable!() }
    }
}

/// Trait of readable streams
pub trait Read {
    /// Read a segment of data from any offset in the stream.
    ///
    /// Returns a segment of data and their offset in the stream. Segments may be received in any order and may overlap.
    ///
    /// Using this function reduces latency improves throughput by avoiding head-of-line blocking within the stream, and
    /// reduces computational overhead by allowing data to be passed on without any intermediate buffering. Prefer it
    /// whenever possible.
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError>;

    /// Read data contiguously from the stream.
    ///
    /// Incurs latency, throughput, and computational overhead and is not necessary for most applications. Prefer
    /// `poll_read_unordered` whenever possible.
    ///
    /// # Panics
    /// - If called after `poll_read_unordered` was called on the same stream.
    ///   This is forbidden because an unordered read could consume a segment of data from a location other than the start
    ///   of the receive buffer, making it impossible for future ordered reads to proceed.
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError>;

    /// Abandon receiving data on this stream.
    ///
    /// The peer is notified and will reset this stream in response.
    fn stop(&mut self, error_code: u16);
}

/// Trait of writable streams
pub trait Write {
    /// Write some bytes to the stream.
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError>;

    /// Indicate that no more data will be written.
    ///
    /// Completes when the peer has acknowledged all sent data.
    fn poll_finish(&mut self) -> Poll<(), ConnectionError>;

    /// Abandon transmitting data on this stream.
    ///
    /// No new data may be transmitted, and no previously transmitted data will be retransmitted if lost.
    fn reset(&mut self, error_code: u16);
}

/// A stream that supports both sending and receiving data
pub struct Stream {
    conn: Rc<ConnectionInner>,
    stream: StreamId,

    // Send only
    finishing: Option<oneshot::Receiver<Option<ConnectionError>>>,
    finished: bool,

    // Recv only
    // Whether data reception is complete (due to receiving finish or reset or sending stop)
    recvd: bool,
}

impl Stream {
    fn new(conn: Rc<ConnectionInner>, stream: StreamId) -> Self { Self {
        conn, stream,
        finishing: None,
        finished: false,
        recvd: false,
    }}
}

impl Write for Stream {
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> {
        let mut endpoint = self.conn.endpoint.0.borrow_mut();
        use quicr::WriteError::*;
        let n = match endpoint.inner.write(self.conn.conn, self.stream, buf) {
            Ok(n) => n,
            Err(Blocked) => {
                let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
                if let Some(ref x) = pending.error { return Err(WriteError::ConnectionClosed(x.clone())); }
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
        let mut endpoint = self.conn.endpoint.0.borrow_mut();
        if self.finishing.is_none() {
            endpoint.inner.finish(self.conn.conn, self.stream);
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            endpoint.pending.get_mut(&self.conn.conn).unwrap().finishing.insert(self.stream, send);
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
        let endpoint = &mut *self.conn.endpoint.0.borrow_mut();
        endpoint.inner.reset(self.conn.conn, self.stream, error_code);
        endpoint.notify();
    }
}

impl Read for Stream {
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError> {
        let endpoint = &mut *self.conn.endpoint.0.borrow_mut();
        use quicr::ReadError::*;
        let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
        match endpoint.inner.read_unordered(self.conn.conn, self.stream) {
            Ok((bytes, offset)) => Ok(Async::Ready((bytes, offset))),
            Err(Blocked) => {
                if let Some(ref x) = pending.error { return Err(ReadError::ConnectionClosed(x.clone())); }
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
        let endpoint = &mut *self.conn.endpoint.0.borrow_mut();
        use quicr::ReadError::*;
        let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
        match endpoint.inner.read(self.conn.conn, self.stream, buf) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(Blocked) => {
                if let Some(ref x) = pending.error { return Err(ReadError::ConnectionClosed(x.clone())); }
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
        let endpoint = &mut *self.conn.endpoint.0.borrow_mut();
        endpoint.inner.stop_sending(self.conn.conn, self.stream, error_code);
        endpoint.notify();
        self.recvd = true;
    }
}

impl io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Write::poll_write(self, buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(WriteError::Stopped { error_code }) =>
                Err(io::Error::new(io::ErrorKind::ConnectionReset, format!("stream stopped by peer: error {}", error_code))),
            Err(WriteError::ConnectionClosed(e)) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("connection closed: {}", e))),
        }
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsyncWrite for Stream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.poll_finish().map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("connection closed: {}", e)))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let endpoint = &mut *self.conn.endpoint.0.borrow_mut();
        let ours = self.stream.initiator() == self.conn.side;
        let (send, recv) = match self.stream.directionality() {
            Directionality::Bi => (true, true),
            Directionality::Uni => (ours, !ours),
        };
        if send && !self.finished {
            endpoint.inner.reset(self.conn.conn, self.stream, 0);
        }
        if recv && !self.recvd {
            endpoint.inner.stop_sending(self.conn.conn, self.stream, 0);
        }
        endpoint.notify();
    }
}

/// Errors that arise from writing to a stream
#[derive(Debug, Fail, Clone)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream.
    #[fail(display = "sending stopped by peer: error {}", error_code)]
    Stopped {
        /// The error code supplied by the peer.
        error_code: u16
    },
    /// The connection was closed.
    #[fail(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ReadError::*;
        match Read::poll_read(self, buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Err(Finished) => Ok(0),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(Reset { error_code }) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("stream reset by peer: error {}", error_code))),
            Err(ConnectionClosed(e)) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("connection closed: {}", e))),
        }
    }
}

impl AsyncRead for Stream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool { false }
}

/// A stream that can only be used to send data
pub struct SendStream(Stream);

impl Write for SendStream {
    fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> { Write::poll_write(&mut self.0, buf) }
    fn poll_finish(&mut self) -> Poll<(), ConnectionError> { self.0.poll_finish() }
    fn reset(&mut self, error_code: u16) { self.0.reset(error_code); }
}

impl io::Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.0.write(buf) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsyncWrite for SendStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> { self.0.shutdown() }
}

/// A stream that can only be used to receive data
pub struct RecvStream(Stream);

impl Read for RecvStream {
    fn poll_read_unordered(&mut self) -> Poll<(Bytes, u64), ReadError> { self.0.poll_read_unordered() }
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, ReadError> { Read::poll_read(&mut self.0, buf) }
    fn stop(&mut self, error_code: u16) { self.0.stop(error_code) }
}

impl io::Read for RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}

impl AsyncRead for RecvStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool { false }
}

/// Errors that arise from reading from a stream.
#[derive(Debug, Fail, Clone)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream.
    #[fail(display = "stream reset by peer: error {}", error_code)]
    Reset {
        /// The error code supplied by the peer.
        error_code: u16
    },
    /// The data on this stream has been fully delivered and no more will be transmitted.
    #[fail(display = "the stream has been completely received")]
    Finished,
    /// The connection was closed.
    #[fail(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

struct Timer {
    conn: ConnectionHandle,
    ty: quicr::Timer,
    delay: Delay,
    cancel: Option<oneshot::Receiver<()>>,
}

impl Future for Timer {
    type Item = Option<(ConnectionHandle, quicr::Timer)>;
    type Error = ();            // FIXME
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref mut cancel) = self.cancel {
            if let Ok(Async::NotReady) = cancel.poll() {}
            else {
                return Ok(Async::Ready(None));
            }
        }
        match self.delay.poll() {
            Err(e) => panic!("unexpected timer error: {}", e),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(())) => Ok(Async::Ready(Some((self.conn, self.ty)))),
        }
    }
}

/// A stream of QUIC streams initiated by a remote peer.
pub struct IncomingStreams {
    endpoint: Endpoint,
    conn: Rc<ConnectionInner>,
}

/// A stream initiated by a remote peer.
pub enum NewStream {
    /// A unidirectional stream.
    Uni(RecvStream),
    /// A bidirectional stream.
    Bi(Stream),
}

impl FuturesStream for IncomingStreams {
    type Item = NewStream;
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut endpoint = self.endpoint.0.borrow_mut();
        let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
        if let Some(ref x) = pending.error { return Err(x.clone()); }
        if let Some(x) = pending.incoming_streams.pop_front() {
            let stream = Stream::new(self.conn.clone(), x);
            let stream = if x.directionality() == Directionality::Uni {
                NewStream::Uni(RecvStream(stream))
            } else {
                NewStream::Bi(stream)
            };
            return Ok(Async::Ready(Some(stream)));
        }
        if let Some(ref x) = pending.error {
            Err(x.clone())
        } else {
            pending.incoming_streams_reader = Some(task::current());
            Ok(Async::NotReady)
        }
    }
}


/// Uses unordered reads to be more efficient than using `AsyncRead` would allow
pub fn read_to_end<T: Read>(stream: T, size_limit: usize) -> ReadToEnd<T> {
    ReadToEnd { stream: Some(stream), size_limit, buffer: Vec::new() }
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
                    if len > self.size_limit { return Err(ReadError::Finished); }
                    self.buffer.resize(len, 0);
                    self.buffer[offset as usize..offset as usize+data.len()].copy_from_slice(&data);
                }
                Ok(Async::NotReady) => { return Ok(Async::NotReady); }
                Err(ReadError::Finished) => {
                    return Ok(Async::Ready((self.stream.take().unwrap(), mem::replace(&mut self.buffer, Vec::new()).into())));
                }
                Err(e) => { return Err(e); }
            }
        }
    }
}
