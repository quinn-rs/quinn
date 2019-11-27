use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    str,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use bytes::Bytes;
use futures::{channel::mpsc, FutureExt, StreamExt};
use proto::{self as proto, ClientConfig, ConnectError, ConnectionHandle, DatagramEvent};

use crate::{
    builders::EndpointBuilder,
    connection::{Connecting, ConnectionDriver, ConnectionRef},
    udp::UdpSocket,
    ConnectionEvent, EndpointEvent, VarInt, IO_LOOP_BOUND,
};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: ClientConfig,
}

impl Endpoint {
    /// Begin constructing an `Endpoint`
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Connect to a remote endpoint. Be sure to spawn the `ConnectionDriver` after connecting.
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        self.connect_with(self.default_client_config.clone(), addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See `connect` for details.
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.lock().unwrap();
        if endpoint.driver_lost {
            return Err(ConnectError::EndpointStopping);
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(*addr))
        } else {
            *addr
        };
        let (ch, conn) = endpoint.inner.connect(config, addr, server_name)?;
        Ok(Connecting::new(endpoint.create_connection(ch, conn)))
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        let addr = socket.local_addr()?;
        let socket = UdpSocket::from_std(socket)?;
        let mut inner = self.inner.lock().unwrap();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();
        Ok(())
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.lock().unwrap().socket.local_addr()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See `Connection::close` for details.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.lock().unwrap();
        endpoint.close = Some((error_code, reason.clone()));
        for sender in endpoint.connections.values() {
            // Ignoring errors from dropped connections
            let _ = sender.unbounded_send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        if let Some(task) = endpoint.incoming_reader.take() {
            task.wake();
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
/// `EndpointDriver` futures terminate when the `Incoming` stream and all clones of the `Endpoint`
/// have been dropped, or when an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let endpoint = &mut *self.0.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }
        loop {
            let now = Instant::now();
            let mut keep_going = false;
            keep_going |= endpoint.drive_recv(cx, now)?;
            endpoint.drive_incoming(cx);
            endpoint.handle_events(cx);
            keep_going |= endpoint.drive_send(cx)?;
            if !keep_going {
                break;
            }
        }
        if endpoint.ref_count == 0 && endpoint.connections.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.lock().unwrap();
        endpoint.driver_lost = true;
        if let Some(task) = endpoint.incoming_reader.take() {
            task.wake();
        }
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.connections.clear();
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    socket: UdpSocket,
    inner: proto::Endpoint,
    outgoing: VecDeque<proto::Transmit>,
    incoming: VecDeque<ConnectionDriver>,
    incoming_reader: Option<Waker>,
    /// Whether the `Incoming` stream has not yet been dropped
    incoming_live: bool,
    driver: Option<Waker>,
    ipv6: bool,
    connections: HashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    // Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
    driver_lost: bool,
}

impl EndpointInner {
    fn drive_recv(&mut self, cx: &mut Context, now: Instant) -> Result<bool, io::Error> {
        let mut buf = [0; 64 * 1024];
        let mut recvd = 0;
        loop {
            match self.socket.poll_recv(cx, &mut buf) {
                Poll::Ready(Ok((n, addr, ecn))) => {
                    match self.inner.handle(now, addr, ecn, (&buf[0..n]).into()) {
                        Some((handle, DatagramEvent::NewConnection(conn))) => {
                            let conn = ConnectionDriver(self.create_connection(handle, conn));
                            if !self.incoming_live {
                                conn.0.lock().unwrap().implicit_close();
                            }
                            self.incoming.push_back(conn);
                            if let Some(task) = self.incoming_reader.take() {
                                task.wake();
                            }
                        }
                        Some((handle, DatagramEvent::ConnectionEvent(event))) => {
                            // Ignoring errors from dropped connections that haven't yet been cleaned up
                            let _ = self
                                .connections
                                .get_mut(&handle)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event));
                        }
                        None => {}
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
            recvd += 1;
            if recvd >= IO_LOOP_BOUND {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn drive_incoming(&mut self, cx: &mut Context) {
        for i in (0..self.incoming.len()).rev() {
            match self.incoming[i].poll_unpin(cx) {
                Poll::Ready(Ok(())) | Poll::Ready(Err(_)) if !self.incoming_live => {
                    let _ = self.incoming.swap_remove_back(i);
                }
                // It's safe to poll an already dead connection
                _ => {}
            }
        }
    }

    fn drive_send(&mut self, cx: &mut Context) -> Result<bool, io::Error> {
        let mut calls = 0;
        loop {
            while self.outgoing.len() < crate::udp::BATCH_SIZE {
                match self.inner.poll_transmit() {
                    Some(x) => self.outgoing.push_back(x),
                    None => break,
                }
            }
            if self.outgoing.is_empty() {
                return Ok(false);
            }
            match self.socket.poll_send(cx, self.outgoing.as_slices().0) {
                Poll::Ready(Ok(n)) => {
                    self.outgoing.drain(..n);
                    calls += 1;
                    if calls == IO_LOOP_BOUND {
                        return Ok(true);
                    }
                }
                Poll::Pending => {
                    return Ok(false);
                }
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                    return Ok(false);
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
            }
        }
    }

    fn handle_events(&mut self, cx: &mut Context) {
        use EndpointEvent::*;
        loop {
            match self.events.poll_next_unpin(cx) {
                Poll::Ready(Some((ch, event))) => match event {
                    Proto(e) => {
                        if e.is_drained() {
                            self.connections.remove(&ch);
                        }
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            // Ignoring errors from dropped connections that haven't yet been cleaned up
                            let _ = self
                                .connections
                                .get_mut(&ch)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event));
                        }
                    }
                    Transmit(t) => self.outgoing.push_back(t),
                },
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return;
                }
            }
        }
    }

    fn create_connection(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
    ) -> ConnectionRef {
        let (send, recv) = mpsc::unbounded();
        if let Some((error_code, ref reason)) = self.close {
            send.unbounded_send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        self.connections.insert(handle, send);
        ConnectionRef::new(handle, conn, self.sender.clone(), recv)
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

/// Stream of incoming connections.
#[derive(Debug)]
pub struct Incoming(EndpointRef);

impl Incoming {
    pub(crate) fn new(inner: EndpointRef) -> Self {
        Self(inner)
    }
}

impl futures::Stream for Incoming {
    type Item = Connecting;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let endpoint = &mut *self.0.lock().unwrap();
        if endpoint.driver_lost {
            Poll::Ready(None)
        } else if let Some(conn) = endpoint.incoming.pop_front() {
            endpoint.inner.accept();
            Poll::Ready(Some(Connecting::new(conn.0)))
        } else if endpoint.close.is_some() {
            Poll::Ready(None)
        } else {
            endpoint.incoming_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.lock().unwrap();
        endpoint.inner.reject_new_connections();
        endpoint.incoming_live = false;
        endpoint.incoming_reader = None;
        for conn in &mut endpoint.incoming {
            conn.0.lock().unwrap().implicit_close();
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<Mutex<EndpointInner>>);

impl EndpointRef {
    pub(crate) fn new(socket: UdpSocket, inner: proto::Endpoint, ipv6: bool) -> Self {
        let (sender, events) = mpsc::unbounded();
        Self(Arc::new(Mutex::new(EndpointInner {
            socket,
            inner,
            ipv6,
            sender,
            events,
            outgoing: VecDeque::new(),
            incoming: VecDeque::new(),
            incoming_live: true,
            incoming_reader: None,
            driver: None,
            connections: HashMap::new(),
            ref_count: 0,
            close: None,
            driver_lost: false,
        })))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.lock().unwrap().ref_count += 1;
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        let endpoint = &mut *self.0.lock().unwrap();
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
    type Target = Mutex<EndpointInner>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
