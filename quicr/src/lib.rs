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

use std::{io, mem};
use std::net::{SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Instant, Duration};

use tokio_udp::UdpSocket;
use tokio_io::{AsyncWrite};
use tokio_timer::{Delay, timer};
use slog::Logger;
use futures::{Future, Poll, Async};
use futures::Stream as FuturesStream;
use futures::unsync::{oneshot, mpsc};
use futures::task::{self, Task};
use futures::stream::FuturesUnordered;
use fnv::{FnvHashMap, FnvHashSet};
use openssl::ssl;

use quicr::{Directionality, StreamId, ConnectionHandle};

pub use quicr::{Config, ListenConfig, PersistentState, ConnectionError, TransportError, ReadError, WriteError};

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Io(io::Error),
    #[fail(display = "{}", _0)]
    Transport(TransportError),
    #[fail(display = "{}", _0)]
    Ssl(openssl::ssl::Error),
}

impl From<io::Error> for Error { fn from(x: io::Error) -> Self { Error::Io(x) } }
impl From<TransportError> for Error { fn from(x: TransportError) -> Self { Error::Transport(x) } }
impl From<ssl::Error> for Error { fn from(x: ssl::Error) -> Self { Error::Ssl(x) } }

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

struct Pending {
    blocked_writers: FnvHashMap<StreamId, Task>,
    blocked_readers: FnvHashMap<StreamId, Task>,
    connecting: Option<oneshot::Sender<Option<ConnectionError>>>,
    uni_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionLost>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<StreamId, ConnectionLost>>>,
    cancel_loss_detect: Option<oneshot::Sender<()>>,
    cancel_idle: Option<oneshot::Sender<()>>,
    incoming_streams: VecDeque<StreamId>,
    incoming_streams_reader: Option<Task>,
    remote_recv_streams: FnvHashSet<StreamId>,
    finishing: FnvHashMap<StreamId, oneshot::Sender<()>>,
}

impl Pending {
    pub fn new(connecting: Option<oneshot::Sender<Option<ConnectionError>>>) -> Self { Self {
        blocked_writers: FnvHashMap::default(),
        blocked_readers: FnvHashMap::default(),
        connecting,
        uni_opening: VecDeque::new(),
        bi_opening: VecDeque::new(),
        cancel_loss_detect: None,
        cancel_idle: None,
        incoming_streams: VecDeque::new(),
        incoming_streams_reader: None,
        remote_recv_streams: FnvHashSet::default(),
        finishing: FnvHashMap::default(),
    }}
}

#[derive(Clone)]
pub struct Endpoint(Rc<RefCell<EndpointInner>>);

/// A future that drives an endpoint
pub struct Driver(Rc<RefCell<EndpointInner>>);

pub type Incoming = mpsc::UnboundedReceiver<NewConnection>;

impl Endpoint {
    pub fn from_std(reactor: &tokio_reactor::Handle, timer: timer::Handle, socket: std::net::UdpSocket,
                    log: Logger, config: Config, listen: Option<ListenConfig>) ->
        Result<(Self, Driver, Incoming), Error>
    {
        let (send, recv) = mpsc::unbounded();
        let rc = Rc::new(RefCell::new(EndpointInner {
            timer,
            log: log.clone(),
            socket: UdpSocket::from_std(socket, reactor)?,
            inner: quicr::Endpoint::new(log, config, listen)?,
            outgoing: VecDeque::new(),
            epoch: Instant::now(),
            pending: FnvHashMap::default(),
            timers: FuturesUnordered::new(),
            incoming: send,
            driver: None,
        }));
        Ok((Endpoint(rc.clone()), Driver(rc), recv))
    }

    pub fn connect(&self, addr: &SocketAddr, hostname: Option<&[u8]>) -> Box<Future<Item=(Connection, IncomingStreams), Error=ConnectionError>> {
        let (send, recv) = oneshot::channel();
        let conn = {
            let mut endpoint = self.0.borrow_mut();
            let conn = endpoint.inner.connect(normalize(*addr), hostname);
            endpoint.pending.insert(conn, Pending::new(Some(send)));
            conn
        };
        let endpoint = self.clone();
        let conn = Rc::new(ConnectionInner { endpoint: endpoint.clone(), conn });
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(move |err| if let Some(err) = err { Err(err) } else {
                    Ok((Connection(conn.clone()), IncomingStreams { endpoint, conn }))
                })
        )
    }
}

pub struct NewConnection {
    pub connection: Connection,
    pub incoming: IncomingStreams,
    pub address: SocketAddr,
    pub protocol: Option<Box<[u8]>>,
}

impl Future for Driver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut buf = [0; 64 * 1024];
        let mut endpoint = self.0.borrow_mut();
        let endpoint = &mut *endpoint;
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
                    Connected { address, protocol } => {
                        if let Some(c) = endpoint.pending.get_mut(&connection).unwrap().connecting.take() {
                            // Graceful close should be handled by drop impl
                            let _ = c.send(None);
                        } else {
                            let conn = Rc::new(ConnectionInner { endpoint: Endpoint(self.0.clone()), conn: connection });
                            let _ = endpoint.incoming.unbounded_send(NewConnection {
                                connection: Connection(conn.clone()),
                                incoming: IncomingStreams { endpoint: Endpoint(self.0.clone()), conn },
                                address: address.into(),
                                protocol,
                            });
                        }
                    }
                    ConnectionLost { reason } => {
                        if let Some(c) = endpoint.pending.get_mut(&connection).unwrap().connecting.take() {
                            // Graceful close should be handled by drop impl
                            let _ = c.send(Some(reason));
                        }
                    }
                    StreamWritable { stream } => {
                        if let Some(writer) = endpoint.pending.get_mut(&connection).unwrap().blocked_writers.remove(&stream) {
                            writer.notify();
                        }
                    }
                    StreamReadable { stream } => {
                        let pending = endpoint.pending.get_mut(&connection).unwrap();
                        if let Some(reader) = pending.blocked_readers.remove(&stream) {
                            reader.notify();
                        }
                        if !pending.remote_recv_streams.contains(&stream) {
                            pending.remote_recv_streams.insert(stream);
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
                            .finishing.remove(&stream).unwrap().send(());
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
                    TimerStart { connection, timer, time } => {
                        // Loss detection and idle timers start before the connection is established
                        let pending = endpoint.pending.entry(connection).or_insert_with(|| Pending::new(None));
                        use quicr::Timer::*;
                        let mut cancel = match timer {
                            LossDetection => Some(&mut pending.cancel_loss_detect),
                            Idle => Some(&mut pending.cancel_idle),
                            Close => None
                        };
                        let instant = endpoint.epoch + duration_micros(time);
                        if let Some(cancel) = cancel.as_mut().and_then(|x| x.take()) {
                            let _ = cancel.send(());
                        }
                        let (send, recv) = oneshot::channel();
                        if let Some(cancel) = cancel { *cancel = Some(send); }
                        trace!(endpoint.log, "timer start"; "timer" => ?timer, "time" => ?duration_micros(time));
                        endpoint.timers.push(Timer {
                            conn: connection,
                            ty: timer,
                            delay: endpoint.timer.delay(instant),
                            cancel: recv,
                        });
                    }
                    TimerStop { connection, timer } => {
                        trace!(endpoint.log, "timer stop"; "timer" => ?timer);
                        let pending = endpoint.pending.get_mut(&connection).unwrap();
                        use quicr::Timer::*;
                        match timer {
                            LossDetection => { pending.cancel_loss_detect.take().map(|x| x.send(()).unwrap()); }
                            Idle => { pending.cancel_idle.take().map(|x| x.send(())); }
                            Close => { unreachable!() }
                        }
                    }
                }
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
}

pub struct Connection(Rc<ConnectionInner>);

#[derive(Copy, Clone, Debug, Fail)]
#[fail(display = "connection lost")]
pub struct ConnectionLost;

impl Connection {
    pub fn open_uni(&self) -> Box<Future<Item=SendStream, Error=ConnectionLost>> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.0.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.conn, Directionality::Uni) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.conn).unwrap();
                pending.uni_opening.push_back(send);
            }
        }
        let endpoint = self.0.endpoint.clone();
        let conn = self.0.clone();
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(|result| result)
                .map(move |stream| SendStream::new(endpoint, conn, stream))
        )
    }

    pub fn open_bi(&self) -> Box<Future<Item=(SendStream, RecvStream), Error=ConnectionLost>> {
        let (send, recv) = oneshot::channel();
        {
            let mut endpoint = self.0.endpoint.0.borrow_mut();
            if let Some(x) = endpoint.inner.open(self.0.conn, Directionality::Bi) {
                let _ = send.send(Ok(x));
            } else {
                let pending = endpoint.pending.get_mut(&self.0.conn).unwrap();
                pending.bi_opening.push_back(send);
            }
        }
        let endpoint = self.0.endpoint.clone();
        let conn = self.0.clone();
        Box::new(
            recv.map_err(|_| unreachable!())
                .and_then(|result| result)
                .map(move |stream| {
                    (SendStream::new(endpoint.clone(), conn.clone(), stream), RecvStream::new(endpoint, conn, stream))
                })
        )
    }

    pub fn close(&self, error_code: u16, reason: &[u8]) {
        let endpoint = &mut *self.0.endpoint.0.borrow_mut();
        endpoint.inner.close(micros_from(endpoint.epoch.elapsed()), self.0.conn, error_code, reason.into());
        endpoint.driver.as_ref().map(|x| x.notify());
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        endpoint.inner.close(micros_from(endpoint.epoch.elapsed()), self.conn, 0, (&[][..]).into());
        endpoint.driver.as_ref().map(|x| x.notify());
    }
}

pub struct SendStream {
    endpoint: Endpoint,
    conn: Rc<ConnectionInner>,
    stream: StreamId,
    finishing: Option<oneshot::Receiver<()>>,
    stop_reason: Option<u16>,
    finished: bool,
}

pub struct RecvStream {
    endpoint: Endpoint,
    conn: Rc<ConnectionInner>,
    stream: StreamId,
    recvd: bool,
}

impl SendStream {
    fn new(endpoint: Endpoint, conn: Rc<ConnectionInner>, stream: StreamId) -> Self { Self {
        endpoint, conn, stream,
        finishing: None,
        stop_reason: None,
        finished: false,
    }}
}

impl RecvStream {
    fn new(endpoint: Endpoint, conn: Rc<ConnectionInner>, stream: StreamId) -> Self { Self {
        endpoint, conn, stream,
        recvd: false,
    }}
}

impl SendStream {
    /// The error code provided by the remote application explaining why we must stop writing to this stream
    pub fn stop_reason(&self) -> Option<u16> { self.stop_reason }

    pub fn poll_write(&mut self, buf: &[u8]) -> Poll<usize, WriteError> {
        let mut endpoint = self.endpoint.0.borrow_mut();
        let n = match endpoint.inner.write(self.conn.conn, self.stream, buf.into()) {
            Ok(()) => buf.len(),
            Err((ref unwritten, WriteError::Blocked)) if unwritten.len() < buf.len() => buf.len() - unwritten.len(),
            Err((_, WriteError::Blocked)) => {
                endpoint.pending.get_mut(&self.conn.conn).unwrap().blocked_writers.insert(self.stream, task::current());
                return Ok(Async::NotReady);
            }
            Err((_, WriteError::Stopped { error_code })) => {
                self.stop_reason = Some(error_code);
                return Err(WriteError::Stopped { error_code });
            }
        };
        endpoint.driver.as_ref().map(|x| x.notify());
        Ok(Async::Ready(n))
    }

    pub fn poll_finish(&mut self) -> Async<()> {
        let mut endpoint = self.endpoint.0.borrow_mut();
        if self.finishing.is_none() {
            endpoint.inner.finish(self.conn.conn, self.stream);
            let (send, recv) = oneshot::channel();
            self.finishing = Some(recv);
            endpoint.pending.get_mut(&self.conn.conn).unwrap().finishing.insert(self.stream, send);
        }
        let r = self.finishing.as_mut().unwrap().poll().unwrap();
        if let Async::Ready(()) = r { self.finished = true; }
        r
    }

    pub fn reset(&self, error_code: u16) {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        endpoint.inner.reset(self.conn.conn, self.stream, error_code);
        endpoint.driver.as_ref().map(|x| x.notify());
    }
}

impl io::Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match SendStream::poll_write(self, buf) {
            Ok(Async::Ready(n)) => Ok(n),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "stream blocked")),
            Err(WriteError::Stopped { .. }) => Err(io::Error::new(io::ErrorKind::ConnectionReset, "peer stopped this stream")),
            Err(WriteError::Blocked) => unreachable!(),
        }
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsyncWrite for SendStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(self.poll_finish())
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        if !self.finished {
            endpoint.inner.reset(self.conn.conn, self.stream, 0);
        }
        endpoint.driver.as_ref().map(|x| x.notify());
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        if !self.recvd {
            endpoint.inner.stop_sending(self.conn.conn, self.stream, 0);
        }
        endpoint.driver.as_ref().map(|x| x.notify());
    }
}

impl RecvStream {
    pub fn poll_read_unordered(&mut self) -> Poll<(Box<[u8]>, u64), ReadError> {
        let endpoint = &mut *self.endpoint.0.borrow_mut();
        use ReadError::*;
        let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
        match endpoint.inner.read_unordered(self.conn.conn, self.stream) {
            Ok((bytes, offset)) => Ok(Async::Ready((bytes.to_vec().into(), offset))),
            Err(Blocked) => {
                pending.blocked_readers.insert(self.stream, task::current());
                Ok(Async::NotReady)
            }
            Err(e@Reset { .. }) => {
                pending.remote_recv_streams.remove(&self.stream);
                Err(e)
            }
            Err(e@Finished) => {
                pending.remote_recv_streams.remove(&self.stream);
                self.recvd = true;
                Err(e)
            }
        }
    }

    pub fn read_to_end(self, size_limit: usize) -> ReadToEnd {
        ReadToEnd { stream: self, size_limit, buffer: Vec::new() }
    }
}

struct Timer {
    conn: ConnectionHandle,
    ty: quicr::Timer,
    delay: Delay,
    cancel: oneshot::Receiver<()>,
}

impl Future for Timer {
    type Item = Option<(ConnectionHandle, quicr::Timer)>;
    type Error = ();            // FIXME
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.ty != quicr::Timer::Close {
            if let Async::Ready(()) = self.cancel.poll().unwrap() {
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

pub struct IncomingStreams {
    endpoint: Endpoint,
    conn: Rc<ConnectionInner>,
}

pub enum NewStream {
    Uni(RecvStream),
    Bi(SendStream, RecvStream),
}

impl FuturesStream for IncomingStreams {
    type Item = NewStream;
    type Error = ();            // FIXME
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut endpoint = self.endpoint.0.borrow_mut();
        let pending = endpoint.pending.get_mut(&self.conn.conn).unwrap();
        if let Some(x) = pending.incoming_streams.pop_front() {
            let recv = RecvStream::new(self.endpoint.clone(), self.conn.clone(), x);
            let stream = if x.directionality() == Directionality::Uni {
                NewStream::Uni(recv)
            } else {
                NewStream::Bi(SendStream::new(self.endpoint.clone(), self.conn.clone(), x), recv)
            };
            return Ok(Async::Ready(Some(stream)));
        }
        pending.incoming_streams_reader = Some(task::current());
        return Ok(Async::NotReady);
    }
}

/// Uses unordered reads to be more efficient than using `AsyncRead`
pub struct ReadToEnd {
    stream: RecvStream,
    buffer: Vec<u8>,
    size_limit: usize,
}

impl Future for ReadToEnd {
    type Item = Box<[u8]>;
    type Error = ReadError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let endpoint = &mut *self.stream.endpoint.0.borrow_mut();
        use ReadError::*;
        let pending = endpoint.pending.get_mut(&self.stream.conn.conn).unwrap();
        loop {
            match endpoint.inner.read_unordered(self.stream.conn.conn, self.stream.stream) {
                Ok((data, offset)) => {
                    let len = self.buffer.len().max(offset as usize + data.len());
                    if len > self.size_limit { return Err(Finished); }
                    self.buffer.resize(len, 0);
                    self.buffer[offset as usize..offset as usize+data.len()].copy_from_slice(&data);
                }
                Err(Blocked) => {
                    pending.blocked_readers.insert(self.stream.stream, task::current());
                    return Ok(Async::NotReady);
                }
                Err(e@Reset { .. }) => {
                    pending.remote_recv_streams.remove(&self.stream.stream);
                    return Err(e);
                }
                Err(Finished) => {
                    self.stream.recvd = true;
                    pending.remote_recv_streams.remove(&self.stream.stream);
                    return Ok(Async::Ready(mem::replace(&mut self.buffer, Vec::new()).into()));
                }
            }
        }
    }
}
