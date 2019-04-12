use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use fnv::FnvHashMap;
use futures::sync::mpsc;
use futures::task::{self, Task};
use futures::Stream as FuturesStream;
use futures::{Async, Future, Poll};
use quinn_proto::{self as quinn, ConnectionHandle};
use slog::Logger;

pub use crate::quinn::{
    ClientConfig, ConnectError, ConnectionError, ConnectionId, DatagramEvent, ServerConfig,
    Transmit, TransportConfig, ALPN_QUIC_H3, ALPN_QUIC_HTTP,
};
pub use crate::tls::{Certificate, CertificateChain, PrivateKey};

pub use crate::builders::{
    ClientConfigBuilder, EndpointBuilder, EndpointError, ServerConfigBuilder,
};
use crate::connection::{
    new_connection, Connecting, Connection, ConnectionDriver, ConnectionRef, IncomingStreams,
};
use crate::udp::UdpSocket;
use crate::{ConnectionEvent, EndpointEvent, IO_LOOP_BOUND};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: ClientConfig,
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
    ) -> Result<Connecting, ConnectError> {
        self.connect_with(self.default_client_config.clone(), addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
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
        let log = config.log.clone();
        let (ch, conn) = endpoint.inner.connect(config, addr, server_name)?;
        Ok(Connecting::new(endpoint.create_connection(log, ch, conn)))
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

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.lock().unwrap().socket.local_addr()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See `Connection::close` for details.
    pub fn close(&self, error_code: u16, reason: &[u8]) {
        let reason = Bytes::from(reason);
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
            task.notify();
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
pub struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let endpoint = &mut *self.0.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(task::current());
        }
        loop {
            let now = Instant::now();
            let mut keep_going = false;
            keep_going |= endpoint.drive_recv(now)?;
            endpoint.drive_incoming();
            endpoint.handle_events()?;
            keep_going |= endpoint.drive_send()?;
            if !keep_going {
                break;
            }
        }
        Ok(
            if endpoint.ref_count == 0 && endpoint.connections.is_empty() {
                Async::Ready(())
            } else {
                Async::NotReady
            },
        )
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.lock().unwrap();
        endpoint.driver_lost = true;
        if let Some(task) = endpoint.incoming_reader.take() {
            task.notify();
        }
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.connections.clear();
    }
}

pub(crate) struct EndpointInner {
    log: Logger,
    socket: UdpSocket,
    inner: quinn::Endpoint,
    outgoing: VecDeque<quinn::Transmit>,
    incoming: VecDeque<ConnectionDriver>,
    incoming_reader: Option<Task>,
    /// Whether the `Incoming` stream has not yet been dropped
    incoming_live: bool,
    driver: Option<Task>,
    ipv6: bool,
    connections: FnvHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    // Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
    /// Set if the endpoint has been manually closed
    close: Option<(u16, Bytes)>,
    driver_lost: bool,
}

impl EndpointInner {
    fn drive_recv(&mut self, now: Instant) -> Result<bool, io::Error> {
        let mut buf = [0; 64 * 1024];
        let mut recvd = 0;
        loop {
            match self.socket.poll_recv(&mut buf) {
                Ok(Async::Ready((n, addr, ecn))) => {
                    match self.inner.handle(now, addr, ecn, (&buf[0..n]).into()) {
                        Some((handle, DatagramEvent::NewConnection(conn))) => {
                            let conn = ConnectionDriver(self.create_connection(None, handle, conn));
                            if !self.incoming_live {
                                conn.0.lock().unwrap().implicit_close();
                            }
                            self.incoming.push_back(conn);
                            if let Some(task) = self.incoming_reader.take() {
                                task.notify();
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
        for i in (0..self.incoming.len()).rev() {
            match self.incoming[i].poll() {
                Ok(Async::Ready(())) | Err(_) if !self.incoming_live => {
                    let _ = self.incoming.swap_remove_back(i);
                }
                // It's safe to poll an already dead connection
                _ => {}
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
                        if let quinn::EndpointEvent::Drained = e {
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
        log: Option<Logger>,
        handle: ConnectionHandle,
        conn: quinn::Connection,
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
        ConnectionRef::new(
            log.unwrap_or_else(|| self.log.clone()),
            handle,
            conn,
            self.sender.clone(),
            recv,
        )
    }
}

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

/// Stream of incoming connections.
pub struct Incoming(EndpointRef);

impl Incoming {
    pub(crate) fn new(inner: EndpointRef) -> Self {
        Self(inner)
    }
}

impl FuturesStream for Incoming {
    type Item = (ConnectionDriver, Connection, IncomingStreams);
    type Error = (); // FIXME: Infallible
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let endpoint = &mut *self.0.lock().unwrap();
        if endpoint.driver_lost {
            Ok(Async::Ready(None))
        } else if let Some(conn) = endpoint.incoming.pop_front() {
            endpoint.inner.accept();
            Ok(Async::Ready(Some(new_connection(conn.0))))
        } else if endpoint.close.is_some() {
            Ok(Async::Ready(None))
        } else {
            endpoint.incoming_reader = Some(task::current());
            Ok(Async::NotReady)
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

pub(crate) struct EndpointRef(Arc<Mutex<EndpointInner>>);

impl EndpointRef {
    pub(crate) fn new(log: Logger, socket: UdpSocket, inner: quinn::Endpoint, ipv6: bool) -> Self {
        let (sender, events) = mpsc::unbounded();
        Self(Arc::new(Mutex::new(EndpointInner {
            log,
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
            connections: FnvHashMap::default(),
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
                    task.notify();
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
