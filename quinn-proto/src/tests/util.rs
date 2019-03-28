use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::ops::RangeFrom;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{cmp, env, fmt, mem, str};

use fnv::FnvHashMap;
use rustls::{KeyLogFile, ProtocolVersion};
use slog::{Drain, Logger, KV};
use untrusted::Input;

use super::*;

pub struct Pair {
    pub log: Logger,
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
        let log = logger();
        let server = Endpoint::new(
            log.new(o!("side" => "Server")),
            endpoint_config.clone(),
            Some(Arc::new(server_config)),
        )
        .unwrap();
        let client = Endpoint::new(log.new(o!("side" => "Client")), endpoint_config, None).unwrap();

        let server_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            SERVER_PORTS.lock().unwrap().next().unwrap(),
        );
        let client_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
        );
        Self {
            log,
            server: TestEndpoint::new(Side::Server, server, server_addr),
            client: TestEndpoint::new(Side::Client, client, client_addr),
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
                    trace!(self.log, "advancing to {:?} for client", self.time);
                }
                true
            }
            Some(t) if Some(t) == server_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!(self.log, "advancing to {:?} for server", self.time);
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
        trace!(self.log, "client running");
        self.client.drive(&self.log, self.time, self.server.addr);
        for x in self.client.outbound.drain(..) {
            if x.packet[0] & packet::LONG_HEADER_FORM == 0 {
                let spin = x.packet[0] & packet::SPIN_BIT != 0;
                self.spins += (spin == self.last_spin) as u64;
                self.last_spin = spin;
            }
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&x.packet, x.destination).unwrap();
            }
            if self.server.addr == x.destination {
                self.server
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.packet));
            }
        }
    }

    fn drive_server(&mut self) {
        trace!(self.log, "server running");
        self.server.drive(&self.log, self.time, self.client.addr);
        for x in self.server.outbound.drain(..) {
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&x.packet, x.destination).unwrap();
            }
            if self.client.addr == x.destination {
                self.client
                    .inbound
                    .push_back((self.time + self.latency, x.ecn, x.packet));
            }
        }
    }

    pub fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        info!(self.log, "connecting");
        let (client_ch, client_conn) = self
            .client
            .connect(
                self.server.addr,
                Default::default(),
                client_config(),
                "localhost",
            )
            .unwrap();
        self.client.connections.insert(client_ch, client_conn);
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
    side: Side,
    pub endpoint: Endpoint,
    pub addr: SocketAddr,
    socket: Option<UdpSocket>,
    timers: [Option<Instant>; Timer::COUNT],
    pub outbound: VecDeque<Transmit>,
    delayed: VecDeque<Transmit>,
    pub inbound: VecDeque<(Instant, Option<EcnCodepoint>, Box<[u8]>)>,
    accepted: Option<ConnectionHandle>,
    pub connections: FnvHashMap<ConnectionHandle, Connection>,
    conn_events: FnvHashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
}

impl TestEndpoint {
    fn new(side: Side, endpoint: Endpoint, addr: SocketAddr) -> Self {
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
            side,
            endpoint,
            addr,
            socket,
            timers: [None; Timer::COUNT],
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
            accepted: None,
            connections: FnvHashMap::default(),
            conn_events: FnvHashMap::default(),
        }
    }

    pub fn drive(&mut self, log: &Logger, now: Instant, remote: SocketAddr) {
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
                    .handle(now, remote, ecn, Vec::from(packet).into())
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
            for timer in Timer::iter() {
                if let Some(time) = self.timers[timer as usize] {
                    if time <= now {
                        trace!(
                            log,
                            "{side:?} {timer:?} timeout",
                            side = self.side,
                            timer = timer
                        );
                        self.timers[timer as usize] = None;
                        conn.timeout(now, timer);
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
                self.timers[x.timer as usize] = match x.update {
                    TimerSetting::Stop => {
                        trace!(
                            log,
                            "{side:?} {timer:?} stop",
                            side = self.side,
                            timer = x.timer
                        );
                        None
                    }
                    TimerSetting::Start(time) => {
                        trace!(
                            log,
                            "{side:?} {timer:?} set to expire at {:?}",
                            time,
                            side = self.side,
                            timer = x.timer,
                        );
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
        let next_timer = self.timers.iter().cloned().filter_map(|t| t).min();
        let next_inbound = self.inbound.front().map(|x| x.0);
        min_opt(next_timer, next_inbound)
    }

    fn is_idle(&self) -> bool {
        let t = self.next_wakeup();
        t == self.timers[Timer::Idle as usize] || t == self.timers[Timer::KeepAlive as usize]
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

pub fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

struct TestDrain;

impl Drain for TestDrain {
    type Ok = ();
    type Err = io::Error;
    fn log(&self, record: &slog::Record<'_>, values: &slog::OwnedKVList) -> Result<(), io::Error> {
        let mut vals = Vec::new();
        values.serialize(&record, &mut TestSerializer(&mut vals))?;
        record
            .kv()
            .serialize(&record, &mut TestSerializer(&mut vals))?;
        println!(
            "{} {}{}",
            record.level(),
            record.msg(),
            str::from_utf8(&vals).unwrap()
        );
        Ok(())
    }
}

struct TestSerializer<'a, W>(&'a mut W);

impl<'a, W> slog::Serializer for TestSerializer<'a, W>
where
    W: Write + 'a,
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        write!(self.0, ", {}: {}", key, val).unwrap();
        Ok(())
    }
}

pub fn server_config() -> ServerConfig {
    let key = CERTIFICATE.serialize_private_key_der();
    let cert = CERTIFICATE.serialize_der();

    let mut tls_config = crypto::build_server_config();
    tls_config.set_protocols(&[str::from_utf8(ALPN_QUIC_HTTP).unwrap().into()]);
    tls_config
        .set_single_cert(vec![rustls::Certificate(cert)], rustls::PrivateKey(key))
        .unwrap();
    tls_config.max_early_data_size = 0xffff_ffff;
    ServerConfig {
        tls_config: Arc::new(tls_config),
        ..Default::default()
    }
}

pub fn client_config() -> Arc<ClientConfig> {
    let cert = CERTIFICATE.serialize_der();
    let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&cert)).unwrap();
    let anchor_vec = vec![anchor];

    let mut tls_client_config = ClientConfig::new();
    tls_client_config.versions = vec![ProtocolVersion::TLSv1_3];
    tls_client_config.set_protocols(&[str::from_utf8(ALPN_QUIC_HTTP).unwrap().into()]);
    tls_client_config
        .root_store
        .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&anchor_vec));
    tls_client_config.key_log = Arc::new(KeyLogFile::new());
    tls_client_config.enable_early_data = true;
    Arc::new(tls_client_config)
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
        rcgen::generate_simple_self_signed(vec!["localhost".into()]);
}
