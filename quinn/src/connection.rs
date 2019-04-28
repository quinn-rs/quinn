use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use fnv::FnvHashMap;
use futures::sync::{mpsc, oneshot};
use futures::task::{self, Task};
use futures::Stream as FuturesStream;
use futures::{Async, Future, Poll};
use proto::{
    ConnectionError, ConnectionHandle, ConnectionId, Directionality, StreamId, TimerUpdate,
};
use slog::Logger;
use tokio_timer::Delay;

use crate::streams::{NewStream, RecvStream, SendStream, WriteError};
use crate::{ConnectionEvent, EndpointEvent};

/// In-progress connection attempt future
///
/// Be sure to spawn the `ConnectionDriver` when complete.
pub struct Connecting(Option<ConnectionDriver>);

impl Connecting {
    pub(crate) fn new(conn: ConnectionRef) -> Self {
        Self(Some(ConnectionDriver(conn)))
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security. Be sure to
    /// spawn the `ConnectionDriver`.
    ///
    /// Opens up the connection for use before the handshake finishes, allowing the API user to
    /// send data with 0-RTT encryption if the necessary key material is available. This is useful
    /// for reducing start-up latency by beginning transmission of application data without waiting
    /// for the handshake's cryptographic security guarantees to be established.
    ///
    /// # Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which might be vulnerable
    /// to replay attacks, and should therefore never invoke non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data, which might be
    /// intercepted by a man-in-the-middle. If this occurs, the handshake will not complete
    /// successfully.
    ///
    /// Once [`Connection::is_handshaking`] returns false, further transmissions are unaffected by
    /// these weaknesses.
    ///
    /// # Errors
    ///
    /// Outgoing connections are only 0-RTT-capable when a cryptographic session ticket cached from
    /// a previous connection to the same server is available, and includes a 0-RTT key. If no such
    /// ticket is found, `self` is returned unmodified.
    ///
    /// For incoming connections, a 0.5-RTT connection will always be successfully constructed.
    pub fn into_0rtt(mut self) -> Result<(ConnectionDriver, Connection, IncomingStreams), Self> {
        if (self.0.as_mut().unwrap().0)
            .lock()
            .unwrap()
            .inner
            .has_0rtt()
        {
            let ConnectionDriver(conn) = self.0.take().unwrap();
            Ok(new_connection(conn))
        } else {
            Err(self)
        }
    }
}

impl Future for Connecting {
    type Item = (ConnectionDriver, Connection, IncomingStreams);
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let connected = match &mut self.0 {
            Some(driver) => match driver.poll()? {
                Async::Ready(()) => {
                    return Err((driver.0).lock().unwrap().error.as_ref().unwrap().clone());
                }
                Async::NotReady => (driver.0).lock().unwrap().connected,
            },
            None => panic!("polled after yielding Ready"),
        };
        if connected {
            let ConnectionDriver(conn) = self.0.take().unwrap();
            Ok(Async::Ready(new_connection(conn)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

fn new_connection(conn: ConnectionRef) -> (ConnectionDriver, Connection, IncomingStreams) {
    (
        ConnectionDriver(conn.clone()),
        Connection(conn.clone()),
        IncomingStreams(conn),
    )
}

/// A future that drives protocol logic for a connection
///
/// This future handles the protocol logic for a single connection, routing events from the
/// `Connection` API object to the `Endpoint` task and the related stream-related interfaces.
/// It also keeps track of outstanding timeouts for the `Connection`.
///
/// If the connection encounters an error condition, this future will yield an error. It will
/// terminate (yielding `Ok(())`) if the connection was closed without error. Unlike other
/// connection-related futures, this waits for the draining period to complete to ensure that
/// packets still in flight from the peer are handled gracefully.
#[must_use = "connection drivers must be spawned for their connections to function"]
pub struct ConnectionDriver(pub(crate) ConnectionRef);

impl Future for ConnectionDriver {
    type Item = ();
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let conn = &mut *self.0.lock().unwrap();

        loop {
            let now = Instant::now();
            let mut keep_going = false;
            if let Err(e) = conn.process_conn_events() {
                conn.terminate(e.clone());
                return Err(e);
            }
            conn.drive_transmit(now);
            keep_going |= conn.drive_timers(now);
            keep_going |= conn.handle_timer_updates();
            conn.forward_endpoint_events();
            conn.forward_app_events();
            if !keep_going || conn.inner.is_drained() {
                break;
            }
        }

        if !conn.inner.is_drained() {
            conn.driver = Some(task::current());
            return Ok(Async::NotReady);
        }
        match conn.error {
            Some(ConnectionError::LocallyClosed) => Ok(Async::Ready(())),
            Some(ref e) => Err(e.clone()),
            None => unreachable!("drained connections always have an error"),
        }
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, `IncomingStreams`,
/// and the various stream types) other than the `ConnectionDriver` have been dropped, the
/// the connection will be automatically closed with an `error_code` of 0 and an empty
/// `reason`. You can also close the connection explicitly by calling `Connection::close()`.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Clone)]
pub struct Connection(ConnectionRef);

impl Connection {
    /// Initite a new outgoing unidirectional stream.
    pub fn open_uni(&self) -> impl Future<Item = SendStream, Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.lock().unwrap();
            if let Some(x) = conn.inner.open(Directionality::Uni) {
                let _ = send.send(Ok((x, conn.inner.is_handshaking())));
            } else {
                conn.uni_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        let conn = self.0.clone();
        recv.map_err(|_| unreachable!())
            .and_then(|result| result)
            .map(move |(stream, is_0rtt)| SendStream::new(conn.clone(), stream, is_0rtt))
    }

    /// Initiate a new outgoing bidirectional stream.
    pub fn open_bi(&self) -> impl Future<Item = (SendStream, RecvStream), Error = ConnectionError> {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.lock().unwrap();
            if let Some(x) = conn.inner.open(Directionality::Bi) {
                let _ = send.send(Ok((x, conn.inner.is_handshaking())));
            } else {
                conn.bi_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        let conn = self.0.clone();
        recv.map_err(|_| unreachable!())
            .and_then(|result| result)
            .map(move |(stream, is_0rtt)| {
                (
                    SendStream::new(conn.clone(), stream, is_0rtt),
                    RecvStream::new(conn, stream, is_0rtt),
                )
            })
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with `ConnectionError::LocallyClosed`. Delivery of
    /// data on unfinished streams is not guaranteed, so the application must call this only when
    /// all important communications have been completed.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    pub fn close(&self, error_code: u16, reason: &[u8]) {
        let conn = &mut *self.0.lock().unwrap();
        conn.close(error_code, reason.into());
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.lock().unwrap().inner.remote()
    }

    /// The `ConnectionId` defined for `conn` by the peer.
    pub fn remote_id(&self) -> ConnectionId {
        self.0.lock().unwrap().inner.rem_cid()
    }

    /// The negotiated application protocol
    pub fn protocol(&self) -> Option<Box<[u8]>> {
        self.0.lock().unwrap().inner.protocol().map(|x| x.into())
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.lock().unwrap().inner.force_key_update()
    }

    /// Replace the diagnostic logger
    pub fn set_logger(&self, log: Logger) {
        let mut conn = self.0.lock().unwrap();
        conn.log = log.clone();
        conn.inner.set_logger(log);
    }
}

/// A stream of QUIC streams initiated by a remote peer.
pub struct IncomingStreams(ConnectionRef);

impl FuturesStream for IncomingStreams {
    type Item = NewStream;
    type Error = ConnectionError;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut conn = self.0.lock().unwrap();
        if let Some(ConnectionError::LocallyClosed) = conn.error {
            Ok(Async::Ready(None))
        } else if let Some(ref e) = conn.error {
            Err(e.clone())
        } else if let Some(x) = conn.inner.accept() {
            mem::drop(conn); // Release the lock so clone can take it
            let stream = if x.directionality() == Directionality::Uni {
                NewStream::Uni(RecvStream::new(self.0.clone(), x, false))
            } else {
                NewStream::Bi(
                    SendStream::new(self.0.clone(), x, false),
                    RecvStream::new(self.0.clone(), x, false),
                )
            };
            Ok(Async::Ready(Some(stream)))
        } else {
            conn.incoming_streams_reader = Some(task::current());
            Ok(Async::NotReady)
        }
    }
}

pub struct ConnectionRef(Arc<Mutex<ConnectionInner>>);

impl ConnectionRef {
    pub(crate) fn new(
        log: Logger,
        handle: ConnectionHandle,
        conn: proto::Connection,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    ) -> Self {
        Self(Arc::new(Mutex::new(ConnectionInner {
            log,
            epoch: Instant::now(),
            inner: conn,
            driver: None,
            handle,
            connected: false,
            timers: [None, None, None, None, None, None],
            conn_events,
            endpoint_events,
            blocked_writers: FnvHashMap::default(),
            blocked_readers: FnvHashMap::default(),
            uni_opening: VecDeque::new(),
            bi_opening: VecDeque::new(),
            incoming_streams_reader: None,
            finishing: FnvHashMap::default(),
            error: None,
            ref_count: 0,
        })))
    }
}

impl Clone for ConnectionRef {
    fn clone(&self) -> Self {
        self.0.lock().unwrap().ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        let conn = &mut *self.0.lock().unwrap();
        if let Some(x) = conn.ref_count.checked_sub(1) {
            conn.ref_count = x;
            if x == 0
                && !conn.inner.is_closed()
                && conn.uni_opening.is_empty()
                && conn.bi_opening.is_empty()
            {
                // If the driver is alive, it's just it and us, so we'd better shut it down. If it's
                // not, we can't do any harm. If there were any streams being opened, then either
                // the connection will be closed for an unrelated reason or a fresh reference will
                // be constructed for the newly opened stream.
                conn.implicit_close();
            }
        }
    }
}

impl std::ops::Deref for ConnectionRef {
    type Target = Mutex<ConnectionInner>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ConnectionInner {
    log: Logger,
    epoch: Instant,
    pub(crate) inner: proto::Connection,
    driver: Option<Task>,
    handle: ConnectionHandle,
    connected: bool,
    timers: [Option<Delay>; proto::Timer::COUNT],
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    pub(crate) blocked_writers: FnvHashMap<StreamId, Task>,
    pub(crate) blocked_readers: FnvHashMap<StreamId, Task>,
    uni_opening: VecDeque<oneshot::Sender<Result<(StreamId, bool), ConnectionError>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<(StreamId, bool), ConnectionError>>>,
    incoming_streams_reader: Option<Task>,
    pub(crate) finishing: FnvHashMap<StreamId, oneshot::Sender<Option<WriteError>>>,
    /// Always set to Some before the connection becomes drained
    pub(crate) error: Option<ConnectionError>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
}

impl ConnectionInner {
    fn drive_transmit(&mut self, now: Instant) {
        while let Some(t) = self.inner.poll_transmit(now) {
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Transmit(t)));
        }
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Proto(event)));
        }
    }

    /// If this returns `Err`, the endpoint is dead, so the driver should exit immediately.
    fn process_conn_events(&mut self) -> Result<(), ConnectionError> {
        loop {
            match self
                .conn_events
                .poll()
                .expect("mpsc receiver is infallible")
            {
                Async::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }
                Async::Ready(Some(ConnectionEvent::Close { reason, error_code })) => {
                    self.close(error_code, reason);
                }
                Async::Ready(None) => {
                    return Err(ConnectionError::TransportError(proto::TransportError {
                        code: proto::TransportErrorCode::INTERNAL_ERROR,
                        frame: None,
                        reason: "endpoint driver future was dropped".to_string(),
                    }));
                }
                Async::NotReady => {
                    return Ok(());
                }
            }
        }
    }

    fn forward_app_events(&mut self) {
        while let Some(event) = self.inner.poll() {
            use proto::Event::*;
            match event {
                Connected { .. } => {
                    self.connected = true;
                }
                ConnectionLost { reason } => {
                    self.terminate(reason);
                }
                StreamWritable { stream } => {
                    if let Some(writer) = self.blocked_writers.remove(&stream) {
                        writer.notify();
                    }
                }
                StreamOpened => {
                    if let Some(x) = self.incoming_streams_reader.take() {
                        x.notify();
                    }
                }
                StreamReadable { stream } => {
                    if let Some(reader) = self.blocked_readers.remove(&stream) {
                        reader.notify();
                    }
                }
                StreamAvailable { directionality } => {
                    let queue = match directionality {
                        Directionality::Uni => &mut self.uni_opening,
                        Directionality::Bi => &mut self.bi_opening,
                    };
                    while let Some(connection) = queue.pop_front() {
                        if let Some(id) = self.inner.open(directionality) {
                            let _ = connection.send(Ok((id, self.inner.is_handshaking())));
                        } else {
                            queue.push_front(connection);
                            break;
                        }
                    }
                }
                StreamFinished {
                    stream,
                    stop_reason,
                } => {
                    let _ = self
                        .finishing
                        .remove(&stream)
                        .unwrap()
                        .send(stop_reason.map(|e| WriteError::Stopped { error_code: e }));
                }
            }
        }
    }

    fn drive_timers(&mut self, now: Instant) -> bool {
        let mut keep_going = false;
        for (timer, slot) in proto::Timer::iter().zip(&mut self.timers) {
            if let Some(ref mut delay) = slot {
                match delay.poll().unwrap() {
                    Async::Ready(()) => {
                        *slot = None;
                        trace!(self.log, "{timer:?} timeout", timer = timer);
                        self.inner
                            .handle_event(proto::ConnectionEvent::Timer(now, timer));
                        // Timeout call may have queued sends
                        keep_going = true;
                    }
                    Async::NotReady => {}
                }
            }
        }
        keep_going
    }

    fn handle_timer_updates(&mut self) -> bool {
        let mut keep_going = false;
        while let Some(update) = self.inner.poll_timers() {
            keep_going = true; // Timers must be polled once set
            match update {
                TimerUpdate {
                    timer,
                    update: proto::TimerSetting::Start(time),
                } => match self.timers[timer as usize] {
                    ref mut x @ None => {
                        trace!(self.log, "{timer:?} timer start", timer=timer; "time" => ?time.duration_since(self.epoch));
                        *x = Some(Delay::new(time));
                    }
                    Some(ref mut x) => {
                        trace!(self.log, "{timer:?} timer reset", timer=timer; "time" => ?time.duration_since(self.epoch));
                        x.reset(time);
                    }
                },
                TimerUpdate {
                    timer,
                    update: proto::TimerSetting::Stop,
                } => {
                    if self.timers[timer as usize].take().is_some() {
                        trace!(self.log, "{timer:?} timer stop", timer = timer);
                    }
                }
            }
        }
        keep_going
    }

    /// Wake up a blocked `Driver` task to process I/O
    pub(crate) fn notify(&self) {
        if let Some(x) = self.driver.as_ref() {
            x.notify();
        }
    }

    /// Used to wake up all blocked futures when the connection becomes closed for any reason
    fn terminate(&mut self, reason: ConnectionError) {
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
            let _ = x.send(Some(WriteError::ConnectionClosed(reason.clone())));
        }
    }

    fn close(&mut self, error_code: u16, reason: Bytes) {
        self.inner.close(Instant::now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed);
        self.notify();
    }

    /// Close for a reason other than the application's explicit request
    pub fn implicit_close(&mut self) {
        self.close(0, Bytes::new());
    }

    pub(crate) fn check_0rtt(&self) -> Result<(), ()> {
        if self.inner.is_handshaking() || self.inner.accepted_0rtt() {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        if !self.inner.is_drained() {
            // Ensure the endpoint can tidy up
            let _ = self.endpoint_events.unbounded_send((
                self.handle,
                EndpointEvent::Proto(proto::EndpointEvent::Drained),
            ));
        }
    }
}
