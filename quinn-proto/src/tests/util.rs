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

use lazy_static::lazy_static;
use rustls::KeyLogFile;
use tracing::{info_span, trace};

use super::*;
use crate::timer::TimerKind;

pub struct Pair {
    pub server: TestEndpoint,
    pub client: TestEndpoint,
    pub time: Instant,
    // One-way
    pub latency: Duration,
    /// Number of spin bit flips
    pub spins: u64,
    last_spin: bool,
}

impl Pair {
    pub fn new(endpoint_config: Arc<EndpointConfig>, server_config: ServerConfig) -> Self {
        let server = Endpoint::new(endpoint_config.clone(), Some(Arc::new(server_config))).unwrap();
        let client = Endpoint::new(endpoint_config, None).unwrap();

        let server_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            SERVER_PORTS.lock().unwrap().next().unwrap(),
        );
        let client_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
        );
        Self {
            server: TestEndpoint::new(server, server_addr),
            client: TestEndpoint::new(client, client_addr),
            time: Instant::now(),
            latency: Duration::new(0, 0),
            spins: 0,
            last_spin: false,
        }
    }

    /// Returns whether the connection is not idle
    pub fn step(&mut self) -> bool {
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
                    trace!("advancing to {:?} for client", self.time);
                }
                true
            }
            Some(t) if Some(t) == server_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for server", self.time);
                }
                true
            }
            Some(_) => unreachable!(),
            None => false,
        }
    }

    /// Advance time until both connections are idle
    pub fn drive(&mut self) {
        while self.step() {}
    }

    pub fn drive_client(&mut self) {
        let span = info_span!("client");
        let _guard = span.enter();
        self.client.drive(self.time, self.server.addr);
        for x in self.client.outbound.drain(..) {
            if x.contents[0] & packet::LONG_HEADER_FORM == 0 {
                let spin = x.contents[0] & packet::SPIN_BIT != 0;
                self.spins += (spin == self.last_spin) as u64;
                self.last_spin = spin;
            }
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&x.contents, x.destination).unwrap();
            }
            if self.server.addr == x.destination {
                self.server
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.contents));
            }
        }
    }

    pub fn drive_server(&mut self) {
        let span = info_span!("server");
        let _guard = span.enter();
        self.server.drive(self.time, self.client.addr);
        for x in self.server.outbound.drain(..) {
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&x.contents, x.destination).unwrap();
            }
            if self.client.addr == x.destination {
                self.client
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.contents));
            }
        }
    }

    pub fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        info!("connecting");
        let client_ch = self.begin_connect(client_config());
        self.drive();
        let server_ch = self.server.assert_accept();
        assert_matches!(
            self.client_conn_mut(client_ch).poll(),
            Some(Event::Connected { .. })
        );
        assert_matches!(
            self.server_conn_mut(server_ch).poll(),
            Some(Event::Connected { .. })
        );
        (client_ch, server_ch)
    }

    /// Just start connecting the client
    pub fn begin_connect(&mut self, config: ClientConfig) -> ConnectionHandle {
        let span = info_span!("client");
        let _guard = span.enter();
        let (client_ch, client_conn) = self
            .client
            .connect(config, self.server.addr, "localhost")
            .unwrap();
        self.client.connections.insert(client_ch, client_conn);
        client_ch
    }

    pub fn client_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.client.connections.get_mut(&ch).unwrap()
    }

    pub fn server_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.server.connections.get_mut(&ch).unwrap()
    }
}

impl Default for Pair {
    fn default() -> Self {
        Pair::new(Default::default(), server_config())
    }
}

pub struct TestEndpoint {
    pub endpoint: Endpoint,
    pub addr: SocketAddr,
    socket: Option<UdpSocket>,
    timers: TimerTable<Option<Instant>>,
    pub outbound: VecDeque<Transmit>,
    delayed: VecDeque<Transmit>,
    pub inbound: VecDeque<(Instant, Option<EcnCodepoint>, Box<[u8]>)>,
    accepted: Option<ConnectionHandle>,
    pub connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
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
            timers: Default::default(),
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
            accepted: None,
            connections: HashMap::default(),
            conn_events: HashMap::default(),
        }
    }

    pub fn drive(&mut self, now: Instant, remote: SocketAddr) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }

        while self.inbound.front().map_or(false, |x| x.0 <= now) {
            let (_, ecn, packet) = self.inbound.pop_front().unwrap();
            if let Some((ch, event)) =
                self.endpoint
                    .handle(now, remote, ecn, Vec::from(packet).as_slice().into())
            {
                match event {
                    DatagramEvent::NewConnection(conn) => {
                        self.connections.insert(ch, conn);
                        self.accepted = Some(ch);
                    }
                    DatagramEvent::ConnectionEvent(event) => {
                        self.conn_events
                            .entry(ch)
                            .or_insert_with(|| VecDeque::new())
                            .push_back(event);
                    }
                }
            }
        }

        while let Some(x) = self.poll_transmit() {
            self.outbound.push_back(x);
        }

        let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = vec![];
        for (ch, conn) in self.connections.iter_mut() {
            for (timer, setting) in &mut self.timers {
                if let Some(time) = *setting {
                    if time <= now {
                        trace!("{:?} timeout", timer);
                        *setting = None;
                        conn.handle_timeout(now, timer);
                    }
                }
            }

            for (_, mut events) in self.conn_events.drain() {
                for event in events.drain(..) {
                    conn.handle_event(event);
                }
            }

            while let Some(event) = conn.poll_endpoint_events() {
                endpoint_events.push((*ch, event));
            }

            while let Some(x) = conn.poll_transmit(now) {
                self.outbound.push_back(x);
            }

            while let Some(x) = conn.poll_timers() {
                self.timers[x.timer] = match x.update {
                    TimerSetting::Stop => {
                        trace!("{:?} stop", x.timer);
                        None
                    }
                    TimerSetting::Start(time) => {
                        trace!("{:?} set to expire at {:?}", x.timer, time);
                        Some(time)
                    }
                };
            }
        }

        for (ch, event) in endpoint_events {
            if let Some(event) = self.handle_event(ch, event) {
                if let Some(conn) = self.connections.get_mut(&ch) {
                    conn.handle_event(event);
                }
            }
        }
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        let next_timer = self.timers.iter().filter_map(|(_, t)| *t).min();
        let next_inbound = self.inbound.front().map(|x| x.0);
        min_opt(next_timer, next_inbound)
    }

    fn is_idle(&self) -> bool {
        let t = self.next_wakeup();
        t == self.timers[Timer(TimerKind::Idle)] || t == self.timers[Timer(TimerKind::KeepAlive)]
    }

    pub fn delay_outbound(&mut self) {
        assert!(self.delayed.is_empty());
        mem::swap(&mut self.delayed, &mut self.outbound);
    }

    pub fn finish_delay(&mut self) {
        self.outbound.extend(self.delayed.drain(..));
    }

    pub fn assert_accept(&mut self) -> ConnectionHandle {
        if let Some(c) = self.accepted.take() {
            self.accept();
            c
        } else {
            panic!("server didn't connect");
        }
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

pub fn subscribe() -> tracing::subscriber::DefaultGuard {
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

pub fn server_config() -> ServerConfig {
    let key = CERTIFICATE.serialize_private_key_der();
    let cert = CERTIFICATE.serialize_pem().unwrap();

    let mut crypto = crypto::ServerConfig::new();
    Arc::make_mut(&mut crypto)
        .set_single_cert(
            rustls::internal::pemfile::certs(&mut cert.as_bytes()).unwrap(),
            rustls::PrivateKey(key.to_vec()),
        )
        .unwrap();
    ServerConfig {
        crypto,
        ..Default::default()
    }
}

pub fn client_config() -> ClientConfig {
    let cert = CERTIFICATE.serialize_der().unwrap();
    let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(&cert).unwrap();
    let anchor_vec = vec![anchor];

    let mut crypto = crypto::ClientConfig::new();
    Arc::make_mut(&mut crypto)
        .root_store
        .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&anchor_vec));
    Arc::make_mut(&mut crypto).key_log = Arc::new(KeyLogFile::new());
    Arc::make_mut(&mut crypto).enable_early_data = true;
    ClientConfig {
        transport: Default::default(),
        crypto,
        ..Default::default()
    }
}

pub fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}

lazy_static! {
    pub static ref SERVER_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
    pub static ref CLIENT_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(44433..);
    static ref CERTIFICATE: rcgen::Certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
}
