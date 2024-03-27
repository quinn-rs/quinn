use std::{
    cmp,
    collections::{HashMap, VecDeque},
    env,
    io::{self, Write},
    mem,
    net::{Ipv6Addr, SocketAddr, UdpSocket},
    ops::RangeFrom,
    str,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use assert_matches::assert_matches;
use bytes::BytesMut;
use lazy_static::lazy_static;
use rustls::{Certificate, KeyLogFile, PrivateKey};
use tracing::{info_span, trace};

use super::*;

pub(super) const DEFAULT_MTU: usize = 1452;

pub(super) struct Pair {
    pub(super) server: TestEndpoint,
    pub(super) client: TestEndpoint,
    /// Start time
    epoch: Instant,
    /// Current time
    pub(super) time: Instant,
    /// Simulates the maximum size allowed for UDP payloads by the link (packets exceeding this size will be dropped)
    pub(super) mtu: usize,
    /// Simulates explicit congestion notification
    pub(super) congestion_experienced: bool,
    // One-way
    pub(super) latency: Duration,
    /// Number of spin bit flips
    pub(super) spins: u64,
    last_spin: bool,
}

impl Pair {
    pub(super) fn default_with_deterministic_pns() -> Self {
        let mut cfg = server_config();
        let mut transport = TransportConfig::default();
        transport.deterministic_packet_numbers(true);
        cfg.transport = Arc::new(transport);
        Self::new(Default::default(), cfg)
    }

    pub(super) fn new(endpoint_config: Arc<EndpointConfig>, server_config: ServerConfig) -> Self {
        let server = Endpoint::new(
            endpoint_config.clone(),
            Some(Arc::new(server_config)),
            true,
            None,
        );
        let client = Endpoint::new(endpoint_config, None, true, None);

        Self::new_from_endpoint(client, server)
    }

    pub(super) fn new_from_endpoint(client: Endpoint, server: Endpoint) -> Self {
        let server_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            SERVER_PORTS.lock().unwrap().next().unwrap(),
        );
        let client_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
        );
        let now = Instant::now();
        Self {
            server: TestEndpoint::new(server, server_addr),
            client: TestEndpoint::new(client, client_addr),
            epoch: now,
            time: now,
            mtu: DEFAULT_MTU,
            latency: Duration::new(0, 0),
            spins: 0,
            last_spin: false,
            congestion_experienced: false,
        }
    }

    /// Returns whether the connection is not idle
    pub(super) fn step(&mut self) -> bool {
        self.drive_client();
        self.drive_server();
        if self.client.is_idle() && self.server.is_idle() {
            return false;
        }

        let client_t = self.client.next_wakeup();
        let server_t = self.server.next_wakeup();
        match min_opt(client_t, server_t) {
            Some(t) if Some(t) == client_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for client", self.time - self.epoch);
                }
                true
            }
            Some(t) if Some(t) == server_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for server", self.time - self.epoch);
                }
                true
            }
            Some(_) => unreachable!(),
            None => false,
        }
    }

    /// Advance time until both connections are idle
    pub(super) fn drive(&mut self) {
        while self.step() {}
    }

    /// Advance time until both connections are idle, or after 100 steps have been executed
    ///
    /// Returns true if the amount of steps exceeds the bounds, because the connections never became
    /// idle
    pub(super) fn drive_bounded(&mut self) -> bool {
        for _ in 0..100 {
            if !self.step() {
                return false;
            }
        }

        true
    }

    pub(super) fn drive_client(&mut self) {
        let span = info_span!("client");
        let _guard = span.enter();
        self.client.drive(self.time, self.server.addr);
        for (packet, buffer) in self.client.outbound.drain(..) {
            let packet_size = packet_size(&packet, &buffer);
            if packet_size > self.mtu {
                info!(packet_size, "dropping packet (max size exceeded)");
                continue;
            }
            if buffer[0] & packet::LONG_HEADER_FORM == 0 {
                let spin = buffer[0] & packet::SPIN_BIT != 0;
                self.spins += (spin == self.last_spin) as u64;
                self.last_spin = spin;
            }
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&buffer, packet.destination).unwrap();
            }
            if self.server.addr == packet.destination {
                let ecn = set_congestion_experienced(packet.ecn, self.congestion_experienced);
                self.server.inbound.push_back((
                    self.time + self.latency,
                    ecn,
                    buffer.as_ref().into(),
                ));
            }
        }
    }

    pub(super) fn drive_server(&mut self) {
        let span = info_span!("server");
        let _guard = span.enter();
        self.server.drive(self.time, self.client.addr);
        for (packet, buffer) in self.server.outbound.drain(..) {
            let packet_size = packet_size(&packet, &buffer);
            if packet_size > self.mtu {
                info!(packet_size, "dropping packet (max size exceeded)");
                continue;
            }
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&buffer, packet.destination).unwrap();
            }
            if self.client.addr == packet.destination {
                let ecn = set_congestion_experienced(packet.ecn, self.congestion_experienced);
                self.client.inbound.push_back((
                    self.time + self.latency,
                    ecn,
                    buffer.as_ref().into(),
                ));
            }
        }
    }

    pub(super) fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        self.connect_with(client_config())
    }

    pub(super) fn connect_with(
        &mut self,
        config: ClientConfig,
    ) -> (ConnectionHandle, ConnectionHandle) {
        info!("connecting");
        let client_ch = self.begin_connect(config);
        self.drive();
        let server_ch = self.server.assert_accept();
        self.finish_connect(client_ch, server_ch);
        (client_ch, server_ch)
    }

    /// Just start connecting the client
    pub(super) fn begin_connect(&mut self, config: ClientConfig) -> ConnectionHandle {
        let span = info_span!("client");
        let _guard = span.enter();
        let (client_ch, client_conn) = self
            .client
            .connect(Instant::now(), config, self.server.addr, "localhost")
            .unwrap();
        self.client.connections.insert(client_ch, client_conn);
        client_ch
    }

    fn finish_connect(&mut self, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
        assert_matches!(
            self.client_conn_mut(client_ch).poll(),
            Some(Event::HandshakeDataReady)
        );
        assert_matches!(
            self.client_conn_mut(client_ch).poll(),
            Some(Event::Connected { .. })
        );
        assert_matches!(
            self.server_conn_mut(server_ch).poll(),
            Some(Event::HandshakeDataReady)
        );
        assert_matches!(
            self.server_conn_mut(server_ch).poll(),
            Some(Event::Connected { .. })
        );
    }

    pub(super) fn client_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.client.connections.get_mut(&ch).unwrap()
    }

    pub(super) fn client_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.client_conn_mut(ch).streams()
    }

    pub(super) fn client_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.client_conn_mut(ch).send_stream(s)
    }

    pub(super) fn client_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.client_conn_mut(ch).recv_stream(s)
    }

    pub(super) fn client_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.client_conn_mut(ch).datagrams()
    }

    pub(super) fn server_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.server.connections.get_mut(&ch).unwrap()
    }

    pub(super) fn server_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.server_conn_mut(ch).streams()
    }

    pub(super) fn server_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.server_conn_mut(ch).send_stream(s)
    }

    pub(super) fn server_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.server_conn_mut(ch).recv_stream(s)
    }

    pub(super) fn server_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.server_conn_mut(ch).datagrams()
    }
}

impl Default for Pair {
    fn default() -> Self {
        Self::new(Default::default(), server_config())
    }
}

pub(super) struct TestEndpoint {
    pub(super) endpoint: Endpoint,
    pub(super) addr: SocketAddr,
    socket: Option<UdpSocket>,
    timeout: Option<Instant>,
    pub(super) outbound: VecDeque<(Transmit, Bytes)>,
    delayed: VecDeque<(Transmit, Bytes)>,
    pub(super) inbound: VecDeque<(Instant, Option<EcnCodepoint>, BytesMut)>,
    accepted: Option<Result<ConnectionHandle, ConnectionError>>,
    pub(super) connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    pub(super) captured_packets: Vec<Vec<u8>>,
    pub(super) capture_inbound_packets: bool,
    pub(super) incoming_connection_behavior: IncomingConnectionBehavior,
}

#[derive(Debug, Copy, Clone)]
pub(super) enum IncomingConnectionBehavior {
    AcceptAll,
    RejectAll,
    Validate,
}

impl TestEndpoint {
    fn new(endpoint: Endpoint, addr: SocketAddr) -> Self {
        let socket = if env::var_os("SSLKEYLOGFILE").is_some() {
            let socket = UdpSocket::bind(addr).expect("failed to bind UDP socket");
            socket
                .set_read_timeout(Some(Duration::new(0, 10_000_000)))
                .unwrap();
            Some(socket)
        } else {
            None
        };
        Self {
            endpoint,
            addr,
            socket,
            timeout: None,
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
            accepted: None,
            connections: HashMap::default(),
            conn_events: HashMap::default(),
            captured_packets: Vec::new(),
            capture_inbound_packets: false,
            incoming_connection_behavior: IncomingConnectionBehavior::AcceptAll,
        }
    }

    pub(super) fn drive(&mut self, now: Instant, remote: SocketAddr) {
        self.drive_incoming(now, remote);
        self.drive_outgoing(now);
    }

    pub(super) fn drive_incoming(&mut self, now: Instant, remote: SocketAddr) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }
        let buffer_size = self.endpoint.config().get_max_udp_payload_size() as usize;
        let mut buf = BytesMut::with_capacity(buffer_size);

        while self.inbound.front().map_or(false, |x| x.0 <= now) {
            let (recv_time, ecn, packet) = self.inbound.pop_front().unwrap();
            if let Some(event) = self
                .endpoint
                .handle(recv_time, remote, None, ecn, packet, &mut buf)
            {
                match event {
                    DatagramEvent::NewConnection(incoming) => {
                        match self.incoming_connection_behavior {
                            IncomingConnectionBehavior::AcceptAll => {
                                let _ = self.try_accept(incoming, now);
                            }
                            IncomingConnectionBehavior::RejectAll => {
                                self.reject(incoming);
                            }
                            IncomingConnectionBehavior::Validate => {
                                if incoming.remote_address_validated() {
                                    let _ = self.try_accept(incoming, now);
                                } else {
                                    self.retry(incoming);
                                }
                            }
                        }
                    }
                    DatagramEvent::ConnectionEvent(ch, event) => {
                        if self.capture_inbound_packets {
                            let packet = self.connections[&ch].decode_packet(&event);
                            self.captured_packets.extend(packet);
                        }

                        self.conn_events.entry(ch).or_default().push_back(event);
                    }
                    DatagramEvent::Response(transmit) => {
                        let size = transmit.size;
                        self.outbound
                            .extend(split_transmit(transmit, buf.split_to(size).freeze()));
                    }
                }
            }
        }
    }

    pub(super) fn drive_outgoing(&mut self, now: Instant) {
        let buffer_size = self.endpoint.config().get_max_udp_payload_size() as usize;
        let mut buf = BytesMut::with_capacity(buffer_size);

        loop {
            let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = vec![];
            for (ch, conn) in self.connections.iter_mut() {
                if self.timeout.map_or(false, |x| x <= now) {
                    self.timeout = None;
                    conn.handle_timeout(now);
                }

                for (_, mut events) in self.conn_events.drain() {
                    for event in events.drain(..) {
                        conn.handle_event(event);
                    }
                }

                while let Some(event) = conn.poll_endpoint_events() {
                    endpoint_events.push((*ch, event));
                }
                while let Some(transmit) = conn.poll_transmit(now, MAX_DATAGRAMS, &mut buf) {
                    let size = transmit.size;
                    self.outbound
                        .extend(split_transmit(transmit, buf.split_to(size).freeze()));
                }
                self.timeout = conn.poll_timeout();
            }

            if endpoint_events.is_empty() {
                break;
            }

            for (ch, event) in endpoint_events {
                if let Some(event) = self.handle_event(ch, event) {
                    if let Some(conn) = self.connections.get_mut(&ch) {
                        conn.handle_event(event);
                    }
                }
            }
        }
    }

    pub(super) fn next_wakeup(&self) -> Option<Instant> {
        let next_inbound = self.inbound.front().map(|x| x.0);
        min_opt(self.timeout, next_inbound)
    }

    fn is_idle(&self) -> bool {
        self.connections.values().all(|x| x.is_idle())
    }

    pub(super) fn delay_outbound(&mut self) {
        assert!(self.delayed.is_empty());
        mem::swap(&mut self.delayed, &mut self.outbound);
    }

    pub(super) fn finish_delay(&mut self) {
        self.outbound.extend(self.delayed.drain(..));
    }

    pub(super) fn try_accept(
        &mut self,
        incoming: Incoming,
        now: Instant,
    ) -> Result<ConnectionHandle, ConnectionError> {
        let mut buf = BytesMut::new();
        self.endpoint
            .accept(incoming, now, &mut buf)
            .map(|(ch, conn)| {
                self.connections.insert(ch, conn);
                self.accepted = Some(Ok(ch));
                ch
            })
            .map_err(|(e, transmit)| {
                if let Some(transmit) = transmit {
                    let size = transmit.size;
                    self.outbound
                        .extend(split_transmit(transmit, buf.split_to(size).freeze()));
                }
                self.accepted = Some(Err(e.clone()));
                e
            })
    }

    pub(super) fn retry(&mut self, incoming: Incoming) {
        let mut buf = BytesMut::new();
        let transmit = self.endpoint.retry(incoming, &mut buf).unwrap();
        let size = transmit.size;
        self.outbound
            .extend(split_transmit(transmit, buf.split_to(size).freeze()));
    }

    pub(super) fn reject(&mut self, incoming: Incoming) {
        let mut buf = BytesMut::new();
        let transmit = self.endpoint.reject(incoming, &mut buf);
        let size = transmit.size;
        self.outbound
            .extend(split_transmit(transmit, buf.split_to(size).freeze()));
    }

    pub(super) fn assert_accept(&mut self) -> ConnectionHandle {
        self.accepted
            .take()
            .expect("server didn't try connecting")
            .expect("server experienced error connecting")
    }

    pub(super) fn assert_accept_error(&mut self) -> ConnectionError {
        self.accepted
            .take()
            .expect("server didn't try connecting")
            .expect_err("server did unexpectedly connect without error")
    }

    pub(super) fn assert_no_accept(&self) {
        assert!(self.accepted.is_none(), "server did unexpectedly connect")
    }
}

impl ::std::ops::Deref for TestEndpoint {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl ::std::ops::DerefMut for TestEndpoint {
    fn deref_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }
}

pub(super) fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

struct TestWriter;

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

pub(super) fn server_config() -> ServerConfig {
    ServerConfig::with_crypto(Arc::new(server_crypto()))
}

pub(super) fn server_config_with_cert(cert: Certificate, key: PrivateKey) -> ServerConfig {
    ServerConfig::with_crypto(Arc::new(server_crypto_with_cert(cert, key)))
}

pub(super) fn server_crypto() -> rustls::ServerConfig {
    let cert = Certificate(CERTIFICATE.serialize_der().unwrap());
    let key = PrivateKey(CERTIFICATE.serialize_private_key_der());
    server_crypto_with_cert(cert, key)
}

pub(super) fn server_crypto_with_cert(cert: Certificate, key: PrivateKey) -> rustls::ServerConfig {
    crate::crypto::rustls::server_config(vec![cert], key).unwrap()
}

pub(super) fn client_config() -> ClientConfig {
    ClientConfig::new(Arc::new(client_crypto()))
}

pub(super) fn client_config_with_deterministic_pns() -> ClientConfig {
    let mut cfg = ClientConfig::new(Arc::new(client_crypto()));
    let mut transport = TransportConfig::default();
    transport.deterministic_packet_numbers(true);
    cfg.transport = Arc::new(transport);
    cfg
}

pub(super) fn client_config_with_certs(certs: Vec<rustls::Certificate>) -> ClientConfig {
    ClientConfig::new(Arc::new(client_crypto_with_certs(certs)))
}

pub(super) fn client_crypto() -> rustls::ClientConfig {
    let cert = rustls::Certificate(CERTIFICATE.serialize_der().unwrap());
    client_crypto_with_certs(vec![cert])
}

pub(super) fn client_crypto_with_certs(certs: Vec<rustls::Certificate>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(&cert).unwrap();
    }
    let mut config = crate::crypto::rustls::client_config(roots);
    config.key_log = Arc::new(KeyLogFile::new());
    config
}

pub(super) fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}

/// The maximum of datagrams TestEndpoint will produce via `poll_transmit`
const MAX_DATAGRAMS: usize = 10;

fn split_transmit(transmit: Transmit, mut buffer: Bytes) -> Vec<(Transmit, Bytes)> {
    let segment_size = match transmit.segment_size {
        Some(segment_size) => segment_size,
        _ => return vec![(transmit, buffer)],
    };

    let mut transmits = Vec::new();
    while !buffer.is_empty() {
        let end = segment_size.min(buffer.len());

        let contents = buffer.split_to(end);
        transmits.push((
            Transmit {
                destination: transmit.destination,
                size: buffer.len(),
                ecn: transmit.ecn,
                segment_size: None,
                src_ip: transmit.src_ip,
            },
            contents,
        ));
    }

    transmits
}

fn packet_size(transmit: &Transmit, buffer: &Bytes) -> usize {
    if transmit.segment_size.is_some() {
        panic!("This transmit is meant to be split into multiple packets!");
    }

    buffer.len()
}

fn set_congestion_experienced(
    x: Option<EcnCodepoint>,
    congestion_experienced: bool,
) -> Option<EcnCodepoint> {
    x.map(|codepoint| match congestion_experienced {
        true => EcnCodepoint::Ce,
        false => codepoint,
    })
}

lazy_static! {
    pub static ref SERVER_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
    pub static ref CLIENT_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(44433..);
    pub(crate) static ref CERTIFICATE: rcgen::Certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
}
