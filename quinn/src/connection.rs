use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use fnv::FnvHashMap;
use futures::channel::{mpsc, oneshot};
use futures::task::{Context, Waker};
use futures::{ready, Future, FutureExt, Poll, StreamExt};
use proto::{ConnectionError, ConnectionHandle, ConnectionId, Dir, StreamId, TimerUpdate};
use slog::Logger;
use tokio_timer::{delay, Delay};

use crate::streams::{RecvStream, SendStream, WriteError};
use crate::{ConnectionEvent, EndpointEvent, VarInt};

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
    /// # Errors
    ///
    /// Outgoing connections are only 0-RTT-capable when a cryptographic session ticket cached from
    /// a previous connection to the same server is available, and includes a 0-RTT key. If no such
    /// ticket is found, `self` is returned unmodified.
    ///
    /// For incoming connections, a 0.5-RTT connection will always be successfully constructed.
    pub fn into_0rtt(mut self) -> Result<NewConnection, Self> {
        // This lock borrows `self` and would normally be dropped at the end of this scope, so we'll
        // have to release it explicitly before returning `self` by value.
        let conn = (self.0.as_mut().unwrap().0).lock().unwrap();
        if conn.inner.has_0rtt() || conn.inner.side().is_server() {
            drop(conn);
            let ConnectionDriver(conn) = self.0.take().unwrap();
            Ok(NewConnection::new(conn))
        } else {
            drop(conn);
            Err(self)
        }
    }
}

impl Future for Connecting {
    type Output = Result<NewConnection, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let connected = match self.0 {
            Some(ref mut driver) => {
                let r = driver.poll_unpin(cx)?;
                let driver = self.0.as_mut().unwrap().0.lock().unwrap(); // borrowck workaround
                match r {
                    Poll::Ready(()) => {
                        return Poll::Ready(Err(driver.error.as_ref().unwrap().clone()));
                    }
                    Poll::Pending => driver.connected,
                }
            }
            None => panic!("polled after yielding Ready"),
        };
        if connected {
            let ConnectionDriver(conn) = self.0.take().unwrap();
            Poll::Ready(Ok(NewConnection::new(conn)))
        } else {
            Poll::Pending
        }
    }
}

/// Components of a newly established connection
///
/// Ensure `driver` runs or the connection will not work.
pub struct NewConnection {
    /// The future responsible for handling I/O on the connection
    pub driver: ConnectionDriver,
    /// Handle for interacting with the connection
    pub connection: Connection,
    /// Unidirectional streams initiated by the peer, in the order they were opened
    pub uni_streams: IncomingUniStreams,
    /// Bidirectional streams initiated by the peer, in the order they were opened
    pub bi_streams: IncomingBiStreams,
    /// Leave room for future extensions
    _non_exhaustive: (),
}

impl NewConnection {
    fn new(conn: ConnectionRef) -> Self {
        Self {
            driver: ConnectionDriver(conn.clone()),
            connection: Connection(conn.clone()),
            uni_streams: IncomingUniStreams(conn.clone()),
            bi_streams: IncomingBiStreams(conn),
            _non_exhaustive: (),
        }
    }
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
    type Output = Result<(), ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let conn = &mut *self.0.lock().unwrap();

        loop {
            let now = Instant::now();
            let mut keep_going = false;
            if let Err(e) = conn.process_conn_events(cx) {
                conn.terminate(e.clone());
                return Poll::Ready(Err(e));
            }
            conn.drive_transmit(now);
            keep_going |= conn.drive_timers(cx, now);
            keep_going |= conn.handle_timer_updates();
            conn.forward_endpoint_events();
            conn.forward_app_events();
            if !keep_going || conn.inner.is_drained() {
                break;
            }
        }

        if !conn.inner.is_drained() {
            conn.driver = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match conn.error {
            Some(ConnectionError::LocallyClosed) => Poll::Ready(Ok(())),
            Some(ref e) => Poll::Ready(Err(e.clone())),
            None => unreachable!("drained connections always have an error"),
        }
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, streams of
/// incoming streams, and the various stream types) other than the `ConnectionDriver` have been
/// dropped, the the connection will be automatically closed with an `error_code` of 0 and an empty
/// `reason`. You can also close the connection explicitly by calling `Connection::close()`.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Clone)]
pub struct Connection(ConnectionRef);

impl Connection {
    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_uni(&self) -> OpenUni {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.lock().unwrap();
            if let Some(ref e) = conn.error {
                let _ = send.send(Err(e.clone()));
            } else if let Some(x) = conn.inner.open(Dir::Uni) {
                let _ = send.send(Ok((
                    x,
                    conn.inner.side().is_client() && conn.inner.is_handshaking(),
                )));
            } else {
                conn.uni_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        OpenUni {
            recv,
            conn: self.0.clone(),
        }
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_bi(&self) -> OpenBi {
        let (send, recv) = oneshot::channel();
        {
            let mut conn = self.0.lock().unwrap();
            if let Some(ref e) = conn.error {
                let _ = send.send(Err(e.clone()));
            } else if let Some(x) = conn.inner.open(Dir::Bi) {
                let _ = send.send(Ok((
                    x,
                    conn.inner.side().is_client() && conn.inner.is_handshaking(),
                )));
            } else {
                conn.bi_opening.push_back(send);
                // We don't notify the driver here because there's no way to ask the peer for more
                // streams
            }
        }
        OpenBi {
            recv,
            conn: self.0.clone(),
        }
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
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
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
        self.0.lock().unwrap().inner.initiate_key_update()
    }

    /// Replace the diagnostic logger
    pub fn set_logger(&self, log: Logger) {
        let mut conn = self.0.lock().unwrap();
        conn.log = log.clone();
        conn.inner.set_logger(log);
    }
}

/// A stream of unidirectional QUIC streams initiated by a remote peer.
///
/// Incoming streams are *always* opened in the same order that the peer created them, but data can
/// be delivered to open streams in any order. This allows meaning to be assigned to the sequence in
/// which streams are opened. For example, a file transfer protocol might designate the first stream
/// the client opens as a "control" stream, using all others for exchanging file data.
///
/// Processing streams in the order they're opened will produce head-of-line blocking. For best
/// performance, an application should be prepared to fully process later streams before any data is
/// received on earlier streams.
pub struct IncomingUniStreams(ConnectionRef);

impl futures::Stream for IncomingUniStreams {
    type Item = Result<RecvStream, ConnectionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut conn = self.0.lock().unwrap();
        if let Some(x) = conn.inner.accept(Dir::Uni) {
            mem::drop(conn); // Release the lock so clone can take it
            Poll::Ready(Some(Ok(RecvStream::new(self.0.clone(), x, false))))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.incoming_uni_streams_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A stream of bidirectional QUIC streams initiated by a remote peer.
///
/// See `IncomingUniStreams` for information about incoming streams in general.
pub struct IncomingBiStreams(ConnectionRef);

impl futures::Stream for IncomingBiStreams {
    type Item = Result<(SendStream, RecvStream), ConnectionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut conn = self.0.lock().unwrap();
        if let Some(x) = conn.inner.accept(Dir::Bi) {
            mem::drop(conn); // Release the lock so clone can take it
            Poll::Ready(Some(Ok((
                SendStream::new(self.0.clone(), x, false),
                RecvStream::new(self.0.clone(), x, false),
            ))))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.incoming_bi_streams_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A future that will resolve into an opened outgoing unidirectional stream
pub struct OpenUni {
    recv: oneshot::Receiver<Result<(StreamId, bool), ConnectionError>>,
    conn: ConnectionRef,
}

impl Future for OpenUni {
    type Output = Result<SendStream, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match ready!(self.recv.poll_unpin(cx)) {
            Err(oneshot::Canceled) => unreachable!(
                "oneshot sender won't be dropped while `self.conn` is keeping the \
                 `ConnectionInner` alive"
            ),
            Ok(Err(c)) => Poll::Ready(Err(c)),
            Ok(Ok((stream, is_0rtt))) => {
                Poll::Ready(Ok(SendStream::new(self.conn.clone(), stream, is_0rtt)))
            }
        }
    }
}

/// A future that will resolve into an opened outgoing bidirectional stream
pub struct OpenBi {
    recv: oneshot::Receiver<Result<(StreamId, bool), ConnectionError>>,
    conn: ConnectionRef,
}

impl Future for OpenBi {
    type Output = Result<(SendStream, RecvStream), ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match ready!(self.recv.poll_unpin(cx)) {
            Err(oneshot::Canceled) => unreachable!(
                "oneshot sender won't be dropped while `self.conn` is keeping the \
                 `ConnectionInner` alive"
            ),
            Ok(Err(c)) => Poll::Ready(Err(c)),
            Ok(Ok((stream, is_0rtt))) => Poll::Ready(Ok((
                SendStream::new(self.conn.clone(), stream, is_0rtt),
                RecvStream::new(self.conn.clone(), stream, is_0rtt),
            ))),
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
            timers: Default::default(),
            conn_events,
            endpoint_events,
            blocked_writers: FnvHashMap::default(),
            blocked_readers: FnvHashMap::default(),
            uni_opening: VecDeque::new(),
            bi_opening: VecDeque::new(),
            incoming_uni_streams_reader: None,
            incoming_bi_streams_reader: None,
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
    driver: Option<Waker>,
    handle: ConnectionHandle,
    connected: bool,
    timers: proto::TimerTable<Option<Delay>>,
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    pub(crate) blocked_writers: FnvHashMap<StreamId, Waker>,
    pub(crate) blocked_readers: FnvHashMap<StreamId, Waker>,
    uni_opening: VecDeque<oneshot::Sender<Result<(StreamId, bool), ConnectionError>>>,
    bi_opening: VecDeque<oneshot::Sender<Result<(StreamId, bool), ConnectionError>>>,
    incoming_uni_streams_reader: Option<Waker>,
    incoming_bi_streams_reader: Option<Waker>,
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
    fn process_conn_events(&mut self, cx: &mut Context) -> Result<(), ConnectionError> {
        loop {
            match self.conn_events.poll_next_unpin(cx) {
                Poll::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }
                Poll::Ready(Some(ConnectionEvent::Close { reason, error_code })) => {
                    self.close(error_code, reason);
                }
                Poll::Ready(None) => {
                    return Err(ConnectionError::TransportError(proto::TransportError {
                        code: proto::TransportErrorCode::INTERNAL_ERROR,
                        frame: None,
                        reason: "endpoint driver future was dropped".to_string(),
                    }));
                }
                Poll::Pending => {
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
                        writer.wake();
                    }
                }
                StreamOpened { dir: Dir::Uni } => {
                    if let Some(x) = self.incoming_uni_streams_reader.take() {
                        x.wake();
                    }
                }
                StreamOpened { dir: Dir::Bi } => {
                    if let Some(x) = self.incoming_bi_streams_reader.take() {
                        x.wake();
                    }
                }
                StreamReadable { stream } => {
                    if let Some(reader) = self.blocked_readers.remove(&stream) {
                        reader.wake();
                    }
                }
                StreamAvailable { dir } => {
                    let queue = match dir {
                        Dir::Uni => &mut self.uni_opening,
                        Dir::Bi => &mut self.bi_opening,
                    };
                    while let Some(connection) = queue.pop_front() {
                        if let Some(id) = self.inner.open(dir) {
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
                    if let Some(finishing) = self.finishing.remove(&stream) {
                        // If the finishing stream was already dropped, there's nothing more to do.
                        let _ = finishing
                            .send(stop_reason.map(|e| WriteError::Stopped { error_code: e }));
                    }
                }
            }
        }
    }

    fn drive_timers(&mut self, cx: &mut Context, now: Instant) -> bool {
        let mut keep_going = false;
        for (timer, slot) in &mut self.timers {
            if let Some(ref mut delay) = slot {
                match delay.poll_unpin(cx) {
                    Poll::Ready(()) => {
                        *slot = None;
                        trace!(self.log, "{timer:?} timeout", timer = timer);
                        self.inner.handle_timeout(now, timer);
                        // Timeout call may have queued sends
                        keep_going = true;
                    }
                    Poll::Pending => {}
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
                } => match self.timers[timer] {
                    ref mut x @ None => {
                        trace!(self.log, "{timer:?} timer start", timer=timer; "time" => ?time.duration_since(self.epoch));
                        *x = Some(delay(time));
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
                    if self.timers[timer].take().is_some() {
                        trace!(self.log, "{timer:?} timer stop", timer = timer);
                    }
                }
            }
        }
        keep_going
    }

    /// Wake up a blocked `Driver` task to process I/O
    pub(crate) fn wake(&mut self) {
        if let Some(x) = self.driver.take() {
            x.wake();
        }
    }

    /// Used to wake up all blocked futures when the connection becomes closed for any reason
    fn terminate(&mut self, reason: ConnectionError) {
        self.error = Some(reason.clone());
        for (_, writer) in self.blocked_writers.drain() {
            writer.wake()
        }
        for (_, reader) in self.blocked_readers.drain() {
            reader.wake()
        }
        for x in self.uni_opening.drain(..) {
            let _ = x.send(Err(reason.clone()));
        }
        for x in self.bi_opening.drain(..) {
            let _ = x.send(Err(reason.clone()));
        }
        if let Some(x) = self.incoming_uni_streams_reader.take() {
            x.wake();
        }
        if let Some(x) = self.incoming_bi_streams_reader.take() {
            x.wake();
        }
        for (_, x) in self.finishing.drain() {
            let _ = x.send(Some(WriteError::ConnectionClosed(reason.clone())));
        }
    }

    fn close(&mut self, error_code: VarInt, reason: Bytes) {
        self.inner.close(Instant::now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed);
        self.wake();
    }

    /// Close for a reason other than the application's explicit request
    pub fn implicit_close(&mut self) {
        self.close(0u32.into(), Bytes::new());
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
                EndpointEvent::Proto(proto::EndpointEvent::drained()),
            ));
        }
    }
}
