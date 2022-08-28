use std::{
    collections::VecDeque,
    future::Future,
    io,
    io::IoSliceMut,
    mem::MaybeUninit,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use crate::runtime::{default_runtime, AsyncTimer, AsyncUdpSocket, Runtime};
use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, ServerConfig,
};
use rustc_hash::FxHashMap;
use tokio::sync::{futures::Notified, mpsc, Notify};
use udp::{RecvMeta, UdpState, BATCH_SIZE};

use crate::{
    connection::{Connecting, ConnectionRef},
    delay_queue::DelayQueue,
    work_limiter::WorkLimiter,
    EndpointConfig, VarInt, RECV_TIME_BOUND, SEND_TIME_BOUND,
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
    #[cfg(feature = "ring")]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_runtime(
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
    #[cfg(feature = "ring")]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        Self::new_with_runtime(
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
        runtime: impl Runtime,
    ) -> io::Result<Self> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_runtime(config, server_config, socket, Arc::new(runtime))
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: impl AsyncUdpSocket,
        runtime: impl Runtime,
    ) -> io::Result<Self> {
        Self::new_with_runtime(config, server_config, Box::new(socket), Arc::new(runtime))
    }

    fn new_with_runtime(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Box<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        let rc = EndpointRef::new(
            socket,
            proto::Endpoint::new(Arc::new(config), server_config.map(Arc::new)),
            addr.is_ipv6(),
            runtime.clone(),
        );
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(async {
            if let Err(e) = driver.await {
                tracing::error!("I/O error: {}", e);
            }
        }));
        Ok(Self {
            inner: rc,
            default_client_config: None,
            runtime,
        })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields [`Connecting`] futures that must be `await`ed to obtain the final `Connection`, or
    /// `None` if the endpoint is [`close`](Self::close)d.
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
        if endpoint.driver_lost {
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
        let (ch, conn) = endpoint.inner.connect(config, addr, server_name)?;
        let dirty = endpoint.dirty_send.clone();
        Ok(endpoint.connections.insert(dirty, ch, conn))
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let socket = self.runtime.wrap_udp_socket(socket)?;
        let mut inner = self.inner.state.lock().unwrap();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();

        // Generate some activity so peers notice the rebind
        for conn in inner.connections.refs.values() {
            let mut state = conn.state.lock("ping");
            state.inner.ping();
            state.wake();
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

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.state.lock().unwrap();
        endpoint.connections.close = Some((error_code, reason.clone()));
        for conn in endpoint.connections.refs.values() {
            let mut state = conn.state.lock("close");
            state.close(error_code, reason.clone(), &conn.shared);
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
                if endpoint.connections.is_empty() {
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
        let mut endpoint = &mut *self.0.state.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let mut keep_going = endpoint.drive_recv(cx, Instant::now())?;
        keep_going |= endpoint.drive_connections(cx, &self.0.shared);
        keep_going |= endpoint.drive_send(cx)?;

        if !endpoint.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        if endpoint.ref_count == 0 && endpoint.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
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
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

#[derive(Debug)]
pub(crate) struct State {
    runtime: Arc<dyn Runtime>,
    socket: Box<dyn AsyncUdpSocket>,
    udp_state: UdpState,
    inner: proto::Endpoint,
    outgoing: VecDeque<proto::Transmit>,
    incoming: VecDeque<Connecting>,
    driver: Option<Waker>,
    ipv6: bool,
    connections: ConnectionSet,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    driver_lost: bool,
    recv_limiter: WorkLimiter,
    recv_buf: Box<[u8]>,
    send_limiter: WorkLimiter,
    /// Connections add themselves to this queue when they need to be driven
    ///
    /// Occurs e.g. due to application-layer activity
    dirty_recv: mpsc::UnboundedReceiver<ConnectionHandle>,
    /// Passed in to connections to enable the above
    dirty_send: mpsc::UnboundedSender<ConnectionHandle>,
    timers: DelayQueue<ConnectionHandle>,
    timer_epoch: Instant,
    base_timer: Option<Pin<Box<dyn AsyncTimer>>>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
}

impl State {
    fn drive_recv<'a>(&'a mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        self.recv_limiter.start_cycle();
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs = MaybeUninit::<[IoSliceMut<'a>; BATCH_SIZE]>::uninit();
        self.recv_buf
            .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
            .enumerate()
            .for_each(|(i, buf)| unsafe {
                iovs.as_mut_ptr()
                    .cast::<IoSliceMut>()
                    .add(i)
                    .write(IoSliceMut::<'a>::new(buf));
            });
        let mut iovs = unsafe { iovs.assume_init() };
        loop {
            match self.socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    self.recv_limiter.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {
                            let buf = data.split_to(meta.stride.min(data.len()));
                            match self
                                .inner
                                .handle(now, meta.addr, meta.dst_ip, meta.ecn, buf)
                            {
                                Some((handle, DatagramEvent::NewConnection(conn))) => {
                                    let conn = self.connections.insert(
                                        self.dirty_send.clone(),
                                        handle,
                                        conn,
                                    );
                                    self.incoming.push_back(conn);
                                }
                                Some((handle, DatagramEvent::ConnectionEvent(event))) => {
                                    let conn = self.connections.refs.get(&handle).unwrap();
                                    let mut state = conn.state.lock("handle_event");
                                    state.inner.handle_event(event);
                                    state.wake();
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => {
                    break;
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
                self.recv_limiter.finish_cycle();
                return Ok(true);
            }
        }

        self.recv_limiter.finish_cycle();
        Ok(false)
    }

    fn drive_timers(&mut self, cx: &mut Context, now: Instant) -> bool {
        let mut keep_going = false;
        // `DelayQueue::poll` currently yields timers expiring in the same millisecond in LIFO
        // order. This doesn't matter so long as we're processing all expiries, but if the below
        // loop is ever updated to bail out early to improve fairness under heavy load, then we
        // should carefully consider whether serving newer events (more likely to still be relevant)
        // or older ones (more likely to allow us to free resources) should take priority.
        while let Some(conn_handle) = self
            .timers
            .poll((now - self.timer_epoch).as_millis() as u64)
        {
            let conn = match self.connections.refs.get(&conn_handle) {
                Some(c) => c,
                None => continue,
            };
            let mut state = &mut *conn.state.lock("poll timeouts");
            let _guard = state.span.clone().entered();
            state.inner.handle_timeout(now);
            state.timer_handle = None;
            state.timer_deadline = None;
            state.wake();
        }
        if let Some(deadline) = self.timers.next_timeout() {
            let deadline = self.timer_epoch + std::time::Duration::from_millis(deadline);
            let timer = match self.base_timer {
                Some(ref mut x) => {
                    x.as_mut().reset(deadline);
                    x
                }
                None => self.base_timer.insert(self.runtime.new_timer(deadline)),
            };
            if let Poll::Ready(()) = timer.as_mut().poll(cx) {
                keep_going = true;
            }
        }
        keep_going
    }

    fn drive_send(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        self.send_limiter.start_cycle();

        let result = loop {
            while self.outgoing.len() < BATCH_SIZE {
                match self.inner.poll_transmit() {
                    Some(x) => self.outgoing.push_back(x),
                    None => break,
                }
            }

            if self.outgoing.is_empty() {
                break Ok(false);
            }

            if !self.send_limiter.allow_work() {
                break Ok(true);
            }

            match self
                .socket
                .poll_send(&self.udp_state, cx, self.outgoing.as_slices().0)
            {
                Poll::Ready(Ok(n)) => {
                    self.outgoing.drain(..n);
                    // We count transmits instead of `poll_send` calls since the cost
                    // of a `sendmmsg` still linearily increases with number of packets.
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

    /// Process connections on which there's been timeouts, packets received, or application
    /// activity ("dirty" connections)
    fn drive_connections(&mut self, cx: &mut Context, shared: &Shared) -> bool {
        let mut keep_going = false;

        keep_going |= self.drive_timers(cx, Instant::now());

        let mut dirty_buffer = Vec::new();

        // Buffer the list of initially dirty connections, guaranteeing that the connection
        // processing loop below takes a predictable amount of time.
        while let Poll::Ready(Some(conn_handle)) = self.dirty_recv.poll_recv(cx) {
            dirty_buffer.push(conn_handle);
        }

        let max_datagrams = self.udp_state.max_gso_segments();
        let mut drained = Vec::new();
        for conn_handle in dirty_buffer {
            let conn = match self.connections.refs.get(&conn_handle) {
                Some(c) => c,
                None => continue,
            };
            let mut state = conn.state.lock("poll dirty");
            state.is_dirty = false;
            let _guard = state.span.clone().entered();
            let mut keep_conn_going = state.drive_transmit(&mut self.outgoing, max_datagrams);
            if let Some(deadline) = state.inner.poll_timeout() {
                if Some(deadline) != state.timer_deadline {
                    let deadline = (deadline - self.timer_epoch).as_millis() as u64;
                    match state.timer_handle {
                        Some(key) => {
                            self.timers.reset(key, deadline);
                        }
                        None => {
                            state.timer_handle = Some(self.timers.insert(deadline, conn_handle));
                        }
                    }
                    // base timer may need to be updated
                    keep_going = true;
                }
            }
            while let Some(event) = state.inner.poll_endpoint_events() {
                if event.is_drained() {
                    drained.push(conn_handle);
                }
                if let Some(event) = self.inner.handle_event(conn_handle, event) {
                    state.inner.handle_event(event);
                    keep_conn_going = true;
                }
            }
            state.forward_app_events(&conn.shared);
            if keep_conn_going {
                state.wake();
                keep_going = true;
            }
        }

        for conn_handle in drained {
            self.connections.refs.remove(&conn_handle);
        }
        if self.connections.is_empty() {
            shared.idle.notify_waiters();
        }

        keep_going
    }
}

#[derive(Debug)]
struct ConnectionSet {
    refs: FxHashMap<ConnectionHandle, ConnectionRef>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        dirty: mpsc::UnboundedSender<ConnectionHandle>,
        handle: ConnectionHandle,
        conn: proto::Connection,
    ) -> Connecting {
        let (future, conn) = Connecting::new(dirty, handle, conn);
        if let Some((error_code, ref reason)) = self.close {
            let mut state = conn.state.lock("close");
            state.close(error_code, reason.clone(), &conn.shared);
        }
        self.refs.insert(handle, conn);
        future
    }

    fn is_empty(&self) -> bool {
        self.refs.is_empty()
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
    type Output = Option<Connecting>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let endpoint = &mut *this.endpoint.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(conn) = endpoint.incoming.pop_front() {
            return Poll::Ready(Some(conn));
        }
        if endpoint.connections.close.is_some() {
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
        socket: Box<dyn AsyncUdpSocket>,
        inner: proto::Endpoint,
        ipv6: bool,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let udp_state = UdpState::new();
        let recv_buf = vec![
            0;
            inner.config().get_max_udp_payload_size().min(64 * 1024) as usize
                * udp_state.gro_segments()
                * BATCH_SIZE
        ];
        let (dirty_send, dirty_recv) = mpsc::unbounded_channel();
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
            },
            state: Mutex::new(State {
                runtime,
                socket,
                udp_state,
                inner,
                ipv6,
                outgoing: VecDeque::new(),
                incoming: VecDeque::new(),
                driver: None,
                connections: ConnectionSet {
                    refs: FxHashMap::default(),
                    close: None,
                },
                ref_count: 0,
                driver_lost: false,
                recv_buf: recv_buf.into(),
                recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
                send_limiter: WorkLimiter::new(SEND_TIME_BOUND),
                dirty_recv,
                dirty_send,
                timers: DelayQueue::new(),
                timer_epoch: Instant::now(),
                base_timer: None,
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
