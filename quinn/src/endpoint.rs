use std::{
    collections::VecDeque,
    future::Future,
    io,
    io::IoSliceMut,
    mem,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use crate::runtime::{default_runtime, AsyncUdpSocket, Runtime};
use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent,
    ServerConfig,
};
use rustc_hash::FxHashMap;
use tokio::sync::{futures::Notified, mpsc, Notify};
use tracing::{Instrument, Span};
use udp::{RecvMeta, BATCH_SIZE};

use crate::{
    connection::Connecting, incoming::Incoming, work_limiter::WorkLimiter, ConnectionEvent,
    EndpointConfig, EndpointEvent, VarInt, IO_LOOP_BOUND, MAX_INCOMING_CONNECTIONS,
    MAX_TRANSMIT_QUEUE_CONTENTS_LEN, RECV_TIME_BOUND, SEND_TIME_BOUND,
};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: Option<ClientConfig>,
    runtime: Arc<dyn Runtime>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket(config, server_config, socket, runtime)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        let allow_mtud = !socket.may_fragment();
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(
                Arc::new(config),
                server_config.map(Arc::new),
                allow_mtud,
                None,
            ),
            addr.is_ipv6(),
            runtime.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        Ok(Self {
            inner: rc,
            default_client_config: None,
            runtime,
        })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is [`close`](Self::close)d. [`Incoming`]
    /// can be `await`ed to obtain the final [`Connection`](crate::Connection), or used to e.g.
    /// filter connection attempts or force address validation, or converted into an intermediate
    /// `Connecting` future which can be used to e.g. send 0.5-RTT data.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&mut self, config: ClientConfig) {
        self.default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let config = match &self.default_client_config {
            Some(config) => config.clone(),
            None => return Err(ConnectError::NoDefaultClientConfig),
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.state.lock().unwrap();
        if endpoint.driver_lost || endpoint.recv_state.connections.close.is_some() {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = endpoint
            .inner
            .connect(Instant::now(), config, addr, server_name)?;

        let socket = endpoint.socket.clone();
        Ok(endpoint
            .recv_state
            .connections
            .insert(ch, conn, socket, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// See [`Endpoint::rebind_abstract()`] for details.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(self.runtime.wrap_udp_socket(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind_abstract(&self, socket: Arc<dyn AsyncUdpSocket>) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let mut inner = self.inner.state.lock().unwrap();
        inner.prev_socket = Some(mem::replace(&mut inner.socket, socket));
        inner.ipv6 = addr.is_ipv6();

        // Generate some activity so peers notice the rebind
        for sender in inner.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::LocalAddressChanged);
        }

        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .unwrap()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.state.lock().unwrap().socket.local_addr()
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner.state.lock().unwrap().inner.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.state.lock().unwrap();
        endpoint.recv_state.connections.close = Some((error_code, reason.clone()));
        for sender in endpoint.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.inner.shared.incoming.notify_waiters();
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock().unwrap();
                if endpoint.recv_state.connections.is_empty() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
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
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    #[allow(unused_mut)] // MSRV
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut endpoint = self.0.state.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let now = Instant::now();
        let mut keep_going = false;
        keep_going |= endpoint.drive_recv(cx, now)?;
        keep_going |= endpoint.handle_events(cx, &self.0.shared);
        keep_going |= endpoint.drive_send(cx)?;

        if !endpoint.recv_state.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        if endpoint.ref_count == 0 && endpoint.recv_state.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.state.lock().unwrap();
        endpoint.driver_lost = true;
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.recv_state.connections.senders.clear();
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl EndpointInner {
    pub(crate) fn accept(
        &self,
        incoming: proto::Incoming,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = BytesMut::new();
        match state.inner.accept(
            incoming,
            Instant::now(),
            &mut response_buffer,
            server_config,
        ) {
            Ok((handle, conn)) => {
                let socket = state.socket.clone();
                let runtime = state.runtime.clone();
                Ok(state
                    .recv_state
                    .connections
                    .insert(handle, conn, socket, runtime))
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    state.transmit_state.respond(transmit, response_buffer);
                }
                Err(error.cause)
            }
        }
    }

    pub(crate) fn refuse(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = BytesMut::new();
        let transmit = state.inner.refuse(incoming, &mut response_buffer);
        state.transmit_state.respond(transmit, response_buffer);
    }

    pub(crate) fn retry(&self, incoming: proto::Incoming) -> Result<(), proto::RetryError> {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = BytesMut::new();
        let transmit = state.inner.retry(incoming, &mut response_buffer)?;
        state.transmit_state.respond(transmit, response_buffer);
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct State {
    socket: Arc<dyn AsyncUdpSocket>,
    /// During an active migration, abandoned_socket receives traffic
    /// until the first packet arrives on the new socket.
    prev_socket: Option<Arc<dyn AsyncUdpSocket>>,
    inner: proto::Endpoint,
    transmit_state: TransmitState,
    recv_state: RecvState,
    driver: Option<Waker>,
    ipv6: bool,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    driver_lost: bool,
    send_limiter: WorkLimiter,
    runtime: Arc<dyn Runtime>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
}

impl State {
    fn drive_recv(&mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        self.recv_state.recv_limiter.start_cycle();
        if let Some(socket) = &self.prev_socket {
            // We don't care about the `PollProgress` from old sockets.
            let poll_res = self.recv_state.poll_socket(
                cx,
                &mut self.inner,
                &mut self.transmit_state,
                &**socket,
                now,
            );
            if poll_res.is_err() {
                self.prev_socket = None;
            }
        };
        let poll_res = self.recv_state.poll_socket(
            cx,
            &mut self.inner,
            &mut self.transmit_state,
            &*self.socket,
            now,
        );
        self.recv_state.recv_limiter.finish_cycle();
        let poll_res = poll_res?;
        if poll_res.received_connection_packet {
            // Traffic has arrived on self.socket, therefore there is no need for the abandoned
            // one anymore. TODO: Account for multiple outgoing connections.
            self.prev_socket = None;
        }
        Ok(poll_res.keep_going)
    }

    fn drive_send(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        self.send_limiter.start_cycle();

        let result = loop {
            if self.transmit_state.outgoing.is_empty() {
                break Ok(false);
            }

            if !self.send_limiter.allow_work() {
                break Ok(true);
            }

            match self.socket.poll_send(cx, self.transmit_state.transmits()) {
                Poll::Ready(Ok(n)) => {
                    self.transmit_state.dequeue(n);
                    // We count transmits instead of `poll_send` calls since the cost
                    // of a `sendmmsg` still linearly increases with number of packets.
                    self.send_limiter.record_work(n);
                }
                Poll::Pending => {
                    break Ok(false);
                }
                Poll::Ready(Err(e)) => {
                    break Err(e);
                }
            }
        };

        self.send_limiter.finish_cycle();
        result
    }

    fn handle_events(&mut self, cx: &mut Context, shared: &Shared) -> bool {
        use EndpointEvent::*;
        for _ in 0..IO_LOOP_BOUND {
            match self.events.poll_recv(cx) {
                Poll::Ready(Some((ch, event))) => match event {
                    Proto(e) => {
                        if e.is_drained() {
                            self.recv_state.connections.senders.remove(&ch);
                            if self.recv_state.connections.is_empty() {
                                shared.idle.notify_waiters();
                            }
                        }
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            // Ignoring errors from dropped connections that haven't yet been cleaned up
                            let _ = self
                                .recv_state
                                .connections
                                .senders
                                .get_mut(&ch)
                                .unwrap()
                                .send(ConnectionEvent::Proto(event));
                        }
                    }
                    Transmit(t, buf) => self.transmit_state.enqueue(t, buf),
                },
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Debug, Default)]
struct TransmitState {
    outgoing: VecDeque<udp::Transmit>,
    /// The aggregateed contents length of the packets in the transmit queue
    contents_len: usize,
}

impl TransmitState {
    fn respond(&mut self, transmit: proto::Transmit, mut response_buffer: BytesMut) {
        // Limiting the memory usage for items queued in the outgoing queue from endpoint
        // generated packets. Otherwise, we may see a build-up of the queue under test with
        // flood of initial packets against the endpoint. The sender with the sender-limiter
        // may not keep up the pace of these packets queued into the queue.
        if self.contents_len >= MAX_TRANSMIT_QUEUE_CONTENTS_LEN {
            return;
        }

        let contents_len = transmit.size;
        self.outgoing.push_back(udp_transmit(
            transmit,
            response_buffer.split_to(contents_len).freeze(),
        ));
        self.contents_len = self.contents_len.saturating_add(contents_len);
    }

    fn enqueue(&mut self, t: proto::Transmit, buf: Bytes) {
        let contents_len = buf.len();
        self.outgoing.push_back(udp_transmit(t, buf));
        self.contents_len = self.contents_len.saturating_add(contents_len);
    }

    fn dequeue(&mut self, sent: usize) {
        self.contents_len = self
            .contents_len
            .saturating_sub(self.outgoing.drain(..sent).map(|t| t.contents.len()).sum());
    }

    fn transmits(&self) -> &[udp::Transmit] {
        self.outgoing.as_slices().0
    }
}

#[inline]
fn udp_transmit(t: proto::Transmit, buffer: Bytes) -> udp::Transmit {
    udp::Transmit {
        destination: t.destination,
        ecn: t.ecn.map(udp_ecn),
        contents: buffer,
        segment_size: t.segment_size,
        src_ip: t.src_ip,
    }
}

#[inline]
fn udp_ecn(ecn: proto::EcnCodepoint) -> udp::EcnCodepoint {
    match ecn {
        proto::EcnCodepoint::Ect0 => udp::EcnCodepoint::Ect0,
        proto::EcnCodepoint::Ect1 => udp::EcnCodepoint::Ect1,
        proto::EcnCodepoint::Ce => udp::EcnCodepoint::Ce,
    }
}

#[inline]
fn proto_ecn(ecn: udp::EcnCodepoint) -> proto::EcnCodepoint {
    match ecn {
        udp::EcnCodepoint::Ect0 => proto::EcnCodepoint::Ect0,
        udp::EcnCodepoint::Ect1 => proto::EcnCodepoint::Ect1,
        udp::EcnCodepoint::Ce => proto::EcnCodepoint::Ce,
    }
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, ref reason)) = self.close {
            send.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        self.senders.insert(handle, send);
        Connecting::new(handle, conn, self.sender.clone(), recv, socket, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl<'a> Future for Accept<'a> {
    type Output = Option<Incoming>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut endpoint = this.endpoint.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(incoming) = endpoint.recv_state.incoming.pop_front() {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(endpoint);
            let incoming = Incoming::new(incoming, this.endpoint.inner.clone());
            return Poll::Ready(Some(incoming));
        }
        if endpoint.recv_state.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(
        socket: Arc<dyn AsyncUdpSocket>,
        inner: proto::Endpoint,
        ipv6: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let recv_state = RecvState::new(sender, socket.max_receive_segments(), &inner);
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
            },
            state: Mutex::new(State {
                socket,
                prev_socket: None,
                inner,
                transmit_state: TransmitState::default(),
                ipv6,
                events,
                driver: None,
                ref_count: 0,
                driver_lost: false,
                send_limiter: WorkLimiter::new(SEND_TIME_BOUND),
                recv_state,
                runtime,
            }),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.state.lock().unwrap().ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.state.lock().unwrap();
        if let Some(x) = endpoint.ref_count.checked_sub(1) {
            endpoint.ref_count = x;
            if x == 0 {
                // If the driver is about to be on its own, ensure it can shut down if the last
                // connection is gone.
                if let Some(task) = endpoint.driver.take() {
                    task.wake();
                }
            }
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// State directly involved in handling incoming packets
#[derive(Debug)]
struct RecvState {
    incoming: VecDeque<proto::Incoming>,
    connections: ConnectionSet,
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
}

impl RecvState {
    fn new(
        sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        max_receive_segments: usize,
        endpoint: &proto::Endpoint,
    ) -> Self {
        let recv_buf = vec![
            0;
            endpoint.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * max_receive_segments
                * BATCH_SIZE
        ];
        Self {
            connections: ConnectionSet {
                senders: FxHashMap::default(),
                sender,
                close: None,
            },
            incoming: VecDeque::new(),
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
        }
    }

    fn poll_socket(
        &mut self,
        cx: &mut Context,
        endpoint: &mut proto::Endpoint,
        transmit_state: &mut TransmitState,
        socket: &dyn AsyncUdpSocket,
        now: Instant,
    ) -> Result<PollProgress, io::Error> {
        let mut received_connection_packet = false;
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs: [IoSliceMut; BATCH_SIZE] = {
            let mut bufs = self
                .recv_buf
                .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
                .map(IoSliceMut::new);

            // expect() safe as self.recv_buf is chunked into BATCH_SIZE items
            // and iovs will be of size BATCH_SIZE, thus from_fn is called
            // exactly BATCH_SIZE times.
            std::array::from_fn(|_| bufs.next().expect("BATCH_SIZE elements"))
        };
        loop {
            match socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {
                            let buf = data.split_to(meta.stride.min(data.len()));
                            let mut response_buffer = BytesMut::new();
                            match endpoint.handle(
                                now,
                                meta.addr,
                                meta.dst_ip,
                                meta.ecn.map(proto_ecn),
                                buf,
                                &mut response_buffer,
                            ) {
                                Some(DatagramEvent::NewConnection(incoming)) => {
                                    if self.incoming.len() < MAX_INCOMING_CONNECTIONS
                                        && self.connections.close.is_none()
                                    {
                                        self.incoming.push_back(incoming);
                                    } else {
                                        let transmit =
                                            endpoint.refuse(incoming, &mut response_buffer);
                                        transmit_state.respond(transmit, response_buffer);
                                    }
                                }
                                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                                    // Ignoring errors from dropped connections that haven't yet been cleaned up
                                    received_connection_packet = true;
                                    let _ = self
                                        .connections
                                        .senders
                                        .get_mut(&handle)
                                        .unwrap()
                                        .send(ConnectionEvent::Proto(event));
                                }
                                Some(DatagramEvent::Response(transmit)) => {
                                    transmit_state.respond(transmit, response_buffer);
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => {
                    return Ok(PollProgress {
                        received_connection_packet,
                        keep_going: false,
                    });
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
            if !self.recv_limiter.allow_work() {
                return Ok(PollProgress {
                    received_connection_packet,
                    keep_going: true,
                });
            }
        }
    }
}

#[derive(Default)]
struct PollProgress {
    /// Whether a datagram was routed to an existing connection
    received_connection_packet: bool,
    /// Whether datagram handling was interrupted early by the work limiter for fairness
    keep_going: bool,
}
