use std::{
    any::Any,
    fmt,
    future::Future,
    mem,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::Bytes;
use proto::{ConnectionError, ConnectionHandle, ConnectionStats, Dir, StreamEvent, StreamId};
use rustc_hash::FxHashMap;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{sleep_until, Instant as TokioInstant, Sleep};
use tracing::info_span;
use udp::UdpState;

use crate::{
    mutex::Mutex,
    poll_fn,
    recv_stream::RecvStream,
    send_stream::{SendStream, WriteError},
    ConnectionEvent, EndpointEvent, VarInt,
};
use proto::congestion::Controller;

/// In-progress connection attempt future
#[derive(Debug)]
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct Connecting {
    conn: Option<ConnectionRef>,
    connected: oneshot::Receiver<bool>,
    handshake_data_ready: Option<oneshot::Receiver<()>>,
}

impl Connecting {
    pub(crate) fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
        udp_state: Arc<UdpState>,
    ) -> Connecting {
        let (on_handshake_data_send, on_handshake_data_recv) = oneshot::channel();
        let (on_connected_send, on_connected_recv) = oneshot::channel();
        let conn = ConnectionRef::new(
            handle,
            conn,
            endpoint_events,
            conn_events,
            on_handshake_data_send,
            on_connected_send,
            udp_state,
        );

        tokio::spawn(ConnectionDriver(conn.clone()));

        Connecting {
            conn: Some(conn),
            connected: on_connected_recv,
            handshake_data_ready: Some(on_handshake_data_recv),
        }
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security
    ///
    /// Opens up the connection for use before the handshake finishes, allowing the API user to
    /// send data with 0-RTT encryption if the necessary key material is available. This is useful
    /// for reducing start-up latency by beginning transmission of application data without waiting
    /// for the handshake's cryptographic security guarantees to be established.
    ///
    /// When the `ZeroRttAccepted` future completes, the connection has been fully established.
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
    pub fn into_0rtt(mut self) -> Result<(NewConnection, ZeroRttAccepted), Self> {
        // This lock borrows `self` and would normally be dropped at the end of this scope, so we'll
        // have to release it explicitly before returning `self` by value.
        let conn = (self.conn.as_mut().unwrap()).lock("into_0rtt");

        let is_ok = conn.inner.has_0rtt() || conn.inner.side().is_server();
        drop(conn);

        if is_ok {
            let conn = self.conn.take().unwrap();
            Ok((NewConnection::new(conn), ZeroRttAccepted(self.connected)))
        } else {
            Err(self)
        }
    }

    /// Parameters negotiated during the handshake
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a
    /// [`crypto::rustls::HandshakeData`](crate::crypto::rustls::HandshakeData).
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        // Taking &mut self allows us to use a single oneshot channel rather than dealing with
        // potentially many tasks waiting on the same event. It's a bit of a hack, but keeps things
        // simple.
        if let Some(x) = self.handshake_data_ready.take() {
            let _ = x.await;
        }
        let conn = self.conn.as_ref().unwrap();
        let inner = conn.lock("handshake");
        inner
            .inner
            .crypto_session()
            .handshake_data()
            .ok_or_else(|| {
                inner
                    .error
                    .clone()
                    .expect("spurious handshake data ready notification")
            })
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_ip(&self) -> Option<IpAddr> {
        let conn = self.conn.as_ref().unwrap();
        let inner = conn.lock("local_ip");

        inner.inner.local_ip()
    }
}

impl Future for Connecting {
    type Output = Result<NewConnection, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.connected).poll(cx).map(|_| {
            let conn = self.conn.take().unwrap();
            let inner = conn.lock("connecting");
            if inner.connected {
                drop(inner);
                Ok(NewConnection::new(conn))
            } else {
                Err(inner
                    .error
                    .clone()
                    .expect("connected signaled without connection success or error"))
            }
        })
    }
}

impl Connecting {
    /// The peer's UDP address.
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub fn remote_address(&self) -> SocketAddr {
        let conn_ref: &ConnectionRef = self.conn.as_ref().expect("used after yielding Ready");
        conn_ref.lock("remote_address").inner.remote_address()
    }
}

/// Future that completes when a connection is fully established
///
/// For clients, the resulting value indicates if 0-RTT was accepted. For servers, the resulting
/// value is meaningless.
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct ZeroRttAccepted(oneshot::Receiver<bool>);

impl Future for ZeroRttAccepted {
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|x| x.unwrap_or(false))
    }
}

/// Components of a newly established connection
///
/// All fields of this struct, in addition to any other handles constructed later, must be dropped
/// for a connection to be implicitly closed. If the `NewConnection` is stored in a long-lived
/// variable, moving individual fields won't cause remaining unused fields to be dropped, even with
/// pattern-matching. The easiest way to ensure unused fields are dropped is to pattern-match on the
/// variable wrapped in brackets, which forces the entire `NewConnection` to be moved out of the
/// variable and into a temporary, ensuring all unused fields are dropped at the end of the
/// statement:
///
#[cfg_attr(
    feature = "rustls",
    doc = "```rust
# use quinn::NewConnection;
# fn dummy(new_connection: NewConnection) {
let NewConnection { connection, .. } = { new_connection };
# }
```"
)]
///
/// You can also explicitly invoke [`Connection::close()`] at any time.
///
/// [`Connection::close()`]: crate::Connection::close
#[derive(Debug)]
#[non_exhaustive]
pub struct NewConnection {
    /// Handle for interacting with the connection
    pub connection: Connection,
    /// Unidirectional streams initiated by the peer, in the order they were opened
    ///
    /// Note that data for separate streams may be delivered in any order. In other words, reading
    /// from streams in the order they're opened is not optimal. See [`IncomingUniStreams`] for
    /// details.
    ///
    /// [`IncomingUniStreams`]: crate::IncomingUniStreams
    pub uni_streams: IncomingUniStreams,
    /// Bidirectional streams initiated by the peer, in the order they were opened
    pub bi_streams: IncomingBiStreams,
    /// Unordered, unreliable datagrams sent by the peer
    pub datagrams: Datagrams,
}

impl NewConnection {
    fn new(conn: ConnectionRef) -> Self {
        Self {
            connection: Connection(conn.clone()),
            uni_streams: IncomingUniStreams(conn.clone()),
            bi_streams: IncomingBiStreams(conn.clone()),
            datagrams: Datagrams(conn),
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
#[derive(Debug)]
struct ConnectionDriver(ConnectionRef);

impl Future for ConnectionDriver {
    type Output = ();

    #[allow(unused_mut)] // MSRV
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let conn = &mut *self.0.lock("poll");

        let span = info_span!("drive", id = conn.handle.0);
        let _guard = span.enter();

        if let Err(e) = conn.process_conn_events(cx) {
            conn.terminate(e);
            return Poll::Ready(());
        }
        let mut keep_going = conn.drive_transmit();
        // If a timer expires, there might be more to transmit. When we transmit something, we
        // might need to reset a timer. Hence, we must loop until neither happens.
        keep_going |= conn.drive_timer(cx);
        conn.forward_endpoint_events();
        conn.forward_app_events();

        if !conn.inner.is_drained() {
            if keep_going {
                // If the connection hasn't processed all tasks, schedule it again
                cx.waker().wake_by_ref();
            } else {
                conn.driver = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        if conn.error.is_none() {
            unreachable!("drained connections always have an error");
        }
        Poll::Ready(())
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, streams of
/// incoming streams, and the various stream types) have been dropped, then the connection will be
/// automatically closed with an `error_code` of 0 and an empty `reason`. You can also close the
/// connection explicitly by calling [`Connection::close()`].
///
/// May be cloned to obtain another handle to the same connection.
///
/// [`Connection::close()`]: Connection::close
#[derive(Debug)]
pub struct Connection(ConnectionRef);

impl Connection {
    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        let (id, is_0rtt) = self.open(Dir::Uni).await?;
        Ok(SendStream::new(self.0.clone(), id, is_0rtt))
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (id, is_0rtt) = self.open(Dir::Bi).await?;
        Ok((
            SendStream::new(self.0.clone(), id, is_0rtt),
            RecvStream::new(self.0.clone(), id, is_0rtt),
        ))
    }

    async fn open(&self, dir: Dir) -> Result<(StreamId, bool), ConnectionError> {
        loop {
            let opening;
            {
                let mut conn = self.0.lock("open");
                if let Some(ref e) = conn.error {
                    return Err(e.clone());
                }
                if let Some(id) = conn.inner.streams().open(dir) {
                    let is_0rtt = conn.inner.side().is_client() && conn.inner.is_handshaking();
                    return Ok((id, is_0rtt));
                }
                // Clone the `Arc<Notify>` so we can wait on the underlying `Notify` without holding
                // the lock. Store it in the outer scope to ensure it outlives the lock guard.
                opening = conn.stream_opening[dir as usize].clone();
                // Construct the future while the lock is held to ensure we can't miss a wakeup if
                // the `Notify` is signaled immediately after we release the lock. `await` it after
                // the lock guard is out of scope.
                opening.notified()
            }
            .await
        }
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. Delivery
    /// of data on unfinished streams is not guaranteed, so the application must call this only
    /// when all important communications have been completed, e.g. by calling [`finish`] on
    /// outstanding [`SendStream`]s and waiting for the resulting futures to complete.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// [`ConnectionError::LocallyClosed`]: crate::ConnectionError::LocallyClosed
    /// [`finish`]: crate::SendStream::finish
    /// [`SendStream`]: crate::SendStream
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let conn = &mut *self.0.lock("close");
        conn.close(error_code, Bytes::copy_from_slice(reason));
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out of order,
    /// and `data` must both fit inside a single QUIC packet and be smaller than the maximum
    /// dictated by the peer.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let conn = &mut *self.0.lock("send_datagram");
        if let Some(ref x) = conn.error {
            return Err(SendDatagramError::ConnectionLost(x.clone()));
        }
        use proto::SendDatagramError::*;
        match conn.inner.datagrams().send(data) {
            Ok(()) => {
                conn.wake();
                Ok(())
            }
            Err(e) => Err(match e {
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            }),
        }
    }

    /// Compute the maximum size of datagrams that may be passed to [`send_datagram()`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.0
            .lock("max_datagram_size")
            .inner
            .datagrams()
            .max_size()
    }

    /// The peer's UDP address
    ///
    /// If `ServerConfig::migration` is `true`, clients may change addresses at will, e.g. when
    /// switching to a cellular internet connection.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.lock("remote_address").inner.remote_address()
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.0.lock("local_ip").inner.local_ip()
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        self.0.lock("rtt").inner.rtt()
    }

    /// Returns connection statistics
    pub fn stats(&self) -> ConnectionStats {
        self.0.lock("stats").inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes
    pub fn congestion_state(&self) -> Box<dyn Controller> {
        self.0
            .lock("congestion_state")
            .inner
            .congestion_state()
            .clone_box()
    }

    /// Parameters negotiated during the handshake
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for details on
    /// the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::Connecting::handshake_data
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.0
            .lock("handshake_data")
            .inner
            .crypto_session()
            .handshake_data()
    }

    /// Cryptographic identity of the peer
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a <code>Vec<[rustls::Certificate](rustls::Certificate)></code>
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.0
            .lock("peer_identity")
            .inner
            .crypto_session()
            .peer_identity()
    }

    /// A stable identifier for this connection
    ///
    /// Peer addresses and connection IDs can change, but this value will remain
    /// fixed for the lifetime of the connection.
    pub fn stable_id(&self) -> usize {
        self.0.stable_id()
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.lock("force_key_update").inner.initiate_key_update()
    }

    /// Derive keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), proto::crypto::ExportKeyingMaterialError> {
        self.0
            .lock("export_keying_material")
            .inner
            .crypto_session()
            .export_keying_material(output, label, context)
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Connection(self.0.clone())
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
#[derive(Debug)]
pub struct IncomingUniStreams(ConnectionRef);

impl IncomingUniStreams {
    /// Fetch the next incoming unidirectional stream
    pub async fn next(&mut self) -> Option<Result<RecvStream, ConnectionError>> {
        poll_fn(move |cx| self.poll(cx)).await
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Option<Result<RecvStream, ConnectionError>>> {
        let mut conn = self.0.lock("IncomingUniStreams::poll");
        if let Some(x) = conn.inner.streams().accept(Dir::Uni) {
            conn.wake(); // To send additional stream ID credit
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

#[cfg(feature = "futures-core")]
impl futures_core::Stream for IncomingUniStreams {
    type Item = Result<RecvStream, ConnectionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.poll(cx)
    }
}

/// A stream of bidirectional QUIC streams initiated by a remote peer.
///
/// See `IncomingUniStreams` for information about incoming streams in general.
#[derive(Debug)]
pub struct IncomingBiStreams(ConnectionRef);

impl IncomingBiStreams {
    /// Fetch the next incoming unidirectional stream
    pub async fn next(&mut self) -> Option<Result<(SendStream, RecvStream), ConnectionError>> {
        poll_fn(move |cx| self.poll(cx)).await
    }

    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<Result<(SendStream, RecvStream), ConnectionError>>> {
        let mut conn = self.0.lock("IncomingBiStreams::poll");
        if let Some(x) = conn.inner.streams().accept(Dir::Bi) {
            let is_0rtt = conn.inner.is_handshaking();
            conn.wake(); // To send additional stream ID credit
            mem::drop(conn); // Release the lock so clone can take it
            Poll::Ready(Some(Ok((
                SendStream::new(self.0.clone(), x, is_0rtt),
                RecvStream::new(self.0.clone(), x, is_0rtt),
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

#[cfg(feature = "futures-core")]
impl futures_core::Stream for IncomingBiStreams {
    type Item = Result<(SendStream, RecvStream), ConnectionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.poll(cx)
    }
}

/// Stream of unordered, unreliable datagrams sent by the peer
#[derive(Debug)]
pub struct Datagrams(ConnectionRef);

impl Datagrams {
    /// Fetch the next application datagram from the peer
    pub async fn next(&mut self) -> Option<Result<Bytes, ConnectionError>> {
        poll_fn(move |cx| self.poll(cx)).await
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Option<Result<Bytes, ConnectionError>>> {
        let mut conn = self.0.lock("Datagrams::poll_next");
        if let Some(x) = conn.inner.datagrams().recv() {
            Poll::Ready(Some(Ok(x)))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.datagram_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[cfg(feature = "futures-core")]
impl futures_core::Stream for Datagrams {
    type Item = Result<Bytes, ConnectionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.poll(cx)
    }
}

#[derive(Debug)]
pub struct ConnectionRef(Arc<Mutex<ConnectionInner>>);

impl ConnectionRef {
    fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
        on_handshake_data: oneshot::Sender<()>,
        on_connected: oneshot::Sender<bool>,
        udp_state: Arc<UdpState>,
    ) -> Self {
        Self(Arc::new(Mutex::new(ConnectionInner {
            inner: conn,
            driver: None,
            handle,
            on_handshake_data: Some(on_handshake_data),
            on_connected: Some(on_connected),
            connected: false,
            timer: None,
            timer_deadline: None,
            conn_events,
            endpoint_events,
            blocked_writers: FxHashMap::default(),
            blocked_readers: FxHashMap::default(),
            stream_opening: [Arc::new(Notify::new()), Arc::new(Notify::new())],
            incoming_uni_streams_reader: None,
            incoming_bi_streams_reader: None,
            datagram_reader: None,
            finishing: FxHashMap::default(),
            stopped: FxHashMap::default(),
            error: None,
            ref_count: 0,
            udp_state,
        })))
    }

    fn stable_id(&self) -> usize {
        &*self.0 as *const _ as usize
    }
}

impl Clone for ConnectionRef {
    fn clone(&self) -> Self {
        self.lock("clone").ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        let conn = &mut *self.lock("drop");
        if let Some(x) = conn.ref_count.checked_sub(1) {
            conn.ref_count = x;
            if x == 0 && !conn.inner.is_closed() {
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
    pub(crate) inner: proto::Connection,
    driver: Option<Waker>,
    handle: ConnectionHandle,
    on_handshake_data: Option<oneshot::Sender<()>>,
    on_connected: Option<oneshot::Sender<bool>>,
    connected: bool,
    timer: Option<Pin<Box<Sleep>>>,
    timer_deadline: Option<TokioInstant>,
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    pub(crate) blocked_writers: FxHashMap<StreamId, Waker>,
    pub(crate) blocked_readers: FxHashMap<StreamId, Waker>,
    stream_opening: [Arc<Notify>; 2],
    incoming_uni_streams_reader: Option<Waker>,
    incoming_bi_streams_reader: Option<Waker>,
    datagram_reader: Option<Waker>,
    pub(crate) finishing: FxHashMap<StreamId, oneshot::Sender<Option<WriteError>>>,
    pub(crate) stopped: FxHashMap<StreamId, Waker>,
    /// Always set to Some before the connection becomes drained
    pub(crate) error: Option<ConnectionError>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    udp_state: Arc<UdpState>,
}

impl ConnectionInner {
    fn drive_transmit(&mut self) -> bool {
        let now = Instant::now();
        let mut transmits = 0;

        let max_datagrams = self.udp_state.max_gso_segments();

        while let Some(t) = self.inner.poll_transmit(now, max_datagrams) {
            transmits += match t.segment_size {
                None => 1,
                Some(s) => (t.contents.len() + s - 1) / s, // round up
            };
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .send((self.handle, EndpointEvent::Transmit(t)));

            if transmits >= MAX_TRANSMIT_DATAGRAMS {
                // TODO: What isn't ideal here yet is that if we don't poll all
                // datagrams that could be sent we don't go into the `app_limited`
                // state and CWND continues to grow until we get here the next time.
                // See https://github.com/quinn-rs/quinn/issues/1126
                return true;
            }
        }

        false
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .send((self.handle, EndpointEvent::Proto(event)));
        }
    }

    /// If this returns `Err`, the endpoint is dead, so the driver should exit immediately.
    fn process_conn_events(&mut self, cx: &mut Context) -> Result<(), ConnectionError> {
        loop {
            match self.conn_events.poll_recv(cx) {
                Poll::Ready(Some(ConnectionEvent::Ping)) => {
                    self.inner.ping();
                }
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
                HandshakeDataReady => {
                    if let Some(x) = self.on_handshake_data.take() {
                        let _ = x.send(());
                    }
                }
                Connected => {
                    self.connected = true;
                    if let Some(x) = self.on_connected.take() {
                        // We don't care if the on-connected future was dropped
                        let _ = x.send(self.inner.accepted_0rtt());
                    }
                }
                ConnectionLost { reason } => {
                    self.terminate(reason);
                }
                Stream(StreamEvent::Writable { id }) => {
                    if let Some(writer) = self.blocked_writers.remove(&id) {
                        writer.wake();
                    }
                }
                Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    if let Some(x) = self.incoming_uni_streams_reader.take() {
                        x.wake();
                    }
                }
                Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    if let Some(x) = self.incoming_bi_streams_reader.take() {
                        x.wake();
                    }
                }
                DatagramReceived => {
                    if let Some(x) = self.datagram_reader.take() {
                        x.wake();
                    }
                }
                Stream(StreamEvent::Readable { id }) => {
                    if let Some(reader) = self.blocked_readers.remove(&id) {
                        reader.wake();
                    }
                }
                Stream(StreamEvent::Available { dir }) => {
                    self.stream_opening[dir as usize].notify_one();
                }
                Stream(StreamEvent::Finished { id }) => {
                    if let Some(finishing) = self.finishing.remove(&id) {
                        // If the finishing stream was already dropped, there's nothing more to do.
                        let _ = finishing.send(None);
                    }
                }
                Stream(StreamEvent::Stopped { id, error_code }) => {
                    if let Some(stopped) = self.stopped.remove(&id) {
                        stopped.wake();
                    }
                    if let Some(finishing) = self.finishing.remove(&id) {
                        let _ = finishing.send(Some(WriteError::Stopped(error_code)));
                    }
                    if let Some(writer) = self.blocked_writers.remove(&id) {
                        writer.wake();
                    }
                }
            }
        }
    }

    fn drive_timer(&mut self, cx: &mut Context) -> bool {
        // Check whether we need to (re)set the timer. If so, we must poll again to ensure the
        // timer is registered with the runtime (and check whether it's already
        // expired).
        match self.inner.poll_timeout().map(TokioInstant::from_std) {
            Some(deadline) => {
                if let Some(delay) = &mut self.timer {
                    // There is no need to reset the tokio timer if the deadline
                    // did not change
                    if self
                        .timer_deadline
                        .map(|current_deadline| current_deadline != deadline)
                        .unwrap_or(true)
                    {
                        delay.as_mut().reset(deadline);
                    }
                } else {
                    self.timer = Some(Box::pin(sleep_until(deadline)));
                }
                // Store the actual expiration time of the timer
                self.timer_deadline = Some(deadline);
            }
            None => {
                self.timer_deadline = None;
                return false;
            }
        }

        if self.timer_deadline.is_none() {
            return false;
        }

        let delay = self
            .timer
            .as_mut()
            .expect("timer must exist in this state")
            .as_mut();
        if delay.poll(cx).is_pending() {
            // Since there wasn't a timeout event, there is nothing new
            // for the connection to do
            return false;
        }

        // A timer expired, so the caller needs to check for
        // new transmits, which might cause new timers to be set.
        self.inner.handle_timeout(Instant::now());
        self.timer_deadline = None;
        true
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
        if let Some(x) = self.on_handshake_data.take() {
            let _ = x.send(());
        }
        for (_, writer) in self.blocked_writers.drain() {
            writer.wake()
        }
        for (_, reader) in self.blocked_readers.drain() {
            reader.wake()
        }
        self.stream_opening[Dir::Uni as usize].notify_waiters();
        self.stream_opening[Dir::Bi as usize].notify_waiters();
        if let Some(x) = self.incoming_uni_streams_reader.take() {
            x.wake();
        }
        if let Some(x) = self.incoming_bi_streams_reader.take() {
            x.wake();
        }
        if let Some(x) = self.datagram_reader.take() {
            x.wake();
        }
        for (_, x) in self.finishing.drain() {
            let _ = x.send(Some(WriteError::ConnectionLost(reason.clone())));
        }
        if let Some(x) = self.on_connected.take() {
            let _ = x.send(false);
        }
        for (_, waker) in self.stopped.drain() {
            waker.wake();
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
        if self.inner.is_handshaking()
            || self.inner.accepted_0rtt()
            || self.inner.side().is_server()
        {
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
            let _ = self.endpoint_events.send((
                self.handle,
                EndpointEvent::Proto(proto::EndpointEvent::drained()),
            ));
        }
    }
}

impl fmt::Debug for ConnectionInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionInner")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
}

/// The maximum amount of datagrams which will be produced in a single `drive_transmit` call
///
/// This limits the amount of CPU resources consumed by datagram generation,
/// and allows other tasks (like receiving ACKs) to run in between.
const MAX_TRANSMIT_DATAGRAMS: usize = 20;

/// Error indicating that a stream has already been finished or reset
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unknown stream")]
pub struct UnknownStream {
    _private: (),
}

impl From<proto::UnknownStream> for UnknownStream {
    fn from(_: proto::UnknownStream) -> Self {
        UnknownStream { _private: () }
    }
}
