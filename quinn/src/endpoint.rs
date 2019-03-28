use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Instant;

use fnv::FnvHashMap;
use futures::sync::mpsc;
use futures::task::{self, Task};
use futures::Stream as FuturesStream;
use futures::{Async, Future, Poll, Sink};
use quinn_proto::{self as quinn, ConnectionHandle};
use slog::Logger;

pub use crate::quinn::{
    ConnectError, ConnectionError, ConnectionId, DatagramEvent, ServerConfig, Transmit,
    TransportConfig, ALPN_QUIC_H3, ALPN_QUIC_HTTP,
};
pub use crate::tls::{Certificate, CertificateChain, PrivateKey};

pub use crate::builders::{
    ClientConfig, ClientConfigBuilder, EndpointBuilder, EndpointError, ServerConfigBuilder,
};
use crate::connection::{ConnectingFuture, ConnectionRef, NewConnection};
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
    pub(crate) inner: Rc<RefCell<EndpointInner>>,
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
    ) -> Result<ConnectingFuture, ConnectError> {
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
    ) -> Result<ConnectingFuture, ConnectError> {
        let mut endpoint = self.inner.borrow_mut();
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(*addr))
        } else {
            *addr
        };
        let (ch, conn) = endpoint.inner.connect(
            addr,
            config.transport.clone(),
            config.tls_config.clone(),
            server_name,
        )?;
        Ok(ConnectingFuture::new(endpoint.create_connection(ch, conn)))
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
        let mut inner = self.inner.borrow_mut();
        inner.socket = socket;
        inner.ipv6 = addr.is_ipv6();
        Ok(())
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.borrow().socket.local_addr()
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
/// `Driver` instances do not terminate (always yields `NotReady`) except in case of an error.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
pub struct Driver(pub(crate) Rc<RefCell<EndpointInner>>);

impl Future for Driver {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let endpoint = &mut *self.0.borrow_mut();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(task::current());
        }
        let now = Instant::now();
        loop {
            let mut keep_going = false;
            keep_going |= endpoint.drive_recv(now)?;
            endpoint.drive_incoming();
            let _ = endpoint.incoming.poll_complete();
            endpoint.handle_events()?;
            keep_going |= endpoint.drive_send()?;
            if !keep_going {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        for sender in self.0.borrow_mut().connections.values() {
            // Ignoring errors from non-existent connections
            let _ = sender.unbounded_send(ConnectionEvent::DriverLost);
        }
    }
}

pub(crate) struct EndpointInner {
    log: Logger,
    socket: UdpSocket,
    inner: quinn::Endpoint,
    outgoing: VecDeque<quinn::Transmit>,
    buffered_incoming: VecDeque<(ConnectionHandle, ConnectionRef)>,
    incoming: mpsc::Sender<NewConnection>,
    driver: Option<Task>,
    ipv6: bool,
    connections: FnvHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    // Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
}

impl EndpointInner {
    pub(crate) fn new(
        log: Logger,
        socket: UdpSocket,
        inner: quinn::Endpoint,
        incoming: mpsc::Sender<NewConnection>,
        ipv6: bool,
    ) -> Self {
        let (sender, events) = mpsc::unbounded();
        Self {
            log,
            socket,
            inner,
            incoming,
            ipv6,
            sender,
            events,
            outgoing: VecDeque::new(),
            buffered_incoming: VecDeque::new(),
            driver: None,
            connections: FnvHashMap::default(),
        }
    }

    fn drive_recv(&mut self, now: Instant) -> Result<bool, io::Error> {
        let mut buf = [0; 64 * 1024];
        let mut recvd = 0;
        loop {
            match self.socket.poll_recv(&mut buf) {
                Ok(Async::Ready((n, addr, ecn))) => {
                    match self.inner.handle(now, addr, ecn, (&buf[0..n]).into()) {
                        Some((handle, DatagramEvent::NewConnection(conn))) => {
                            let conn = self.create_connection(handle, conn);
                            self.buffered_incoming.push_back((handle, conn));
                        }
                        Some((handle, DatagramEvent::ConnectionEvent(event))) => {
                            self.connections
                                .get_mut(&handle)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event))
                                .unwrap();
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
        while let Ok(Async::Ready(())) = self.incoming.poll_ready() {
            if let Some((_, conn)) = self.buffered_incoming.pop_front() {
                self.incoming.start_send(NewConnection::new(conn)).unwrap();
                self.inner.accept();
            } else {
                break;
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
                        if let quinn::EndpointEvent::Closed { .. } = &e {
                            self.connections.remove(&ch);
                        }
                        if let Some(event) = self.inner.handle_event(ch, e) {
                            self.connections
                                .get_mut(&ch)
                                .unwrap()
                                .unbounded_send(ConnectionEvent::Proto(event))
                                .unwrap();
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
        handle: ConnectionHandle,
        conn: quinn::Connection,
    ) -> ConnectionRef {
        let (send, recv) = mpsc::unbounded();
        self.connections.insert(handle, send);
        ConnectionRef::new(self.log.clone(), handle, conn, self.sender.clone(), recv)
    }
}

/// Stream of incoming connections.
pub type Incoming = mpsc::Receiver<NewConnection>;

fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}
