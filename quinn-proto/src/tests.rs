use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::ops::RangeFrom;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{cmp, env, fmt, mem, str};

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use rand::RngCore;
use ring::digest;
use ring::hmac::SigningKey;
use rustls::internal::msgs::enums::AlertDescription;
use rustls::{KeyLogFile, ProtocolVersion};
use slog::{Drain, Logger, KV};
use untrusted::Input;

use super::*;

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

fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

lazy_static! {
    static ref SERVER_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
    static ref CLIENT_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(44433..);
    static ref CERTIFICATE: rcgen::Certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]);
}

struct Pair {
    log: Logger,
    server: TestEndpoint,
    client: TestEndpoint,
    time: Instant,
    // One-way
    latency: Duration,
    /// Number of spin bit flips
    spins: u64,
    last_spin: bool,
}

impl Default for Pair {
    fn default() -> Self {
        Pair::new(Default::default(), server_config())
    }
}

fn server_config() -> ServerConfig {
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

fn client_config() -> Arc<ClientConfig> {
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

impl Pair {
    fn new(endpoint_config: Arc<EndpointConfig>, server_config: ServerConfig) -> Self {
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
    fn step(&mut self) -> bool {
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
    fn drive(&mut self) {
        while self.step() {}
    }

    fn drive_client(&mut self) {
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

    fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        info!(self.log, "connecting");
        let client_ch = self
            .client
            .connect(
                self.server.addr,
                Default::default(),
                client_config(),
                "localhost",
            )
            .unwrap();
        self.drive();
        let server_ch = self.server.assert_accept();
        assert_matches!(self.client.poll(), Some((ch, Event::Connected { .. })) if ch == client_ch);
        assert_matches!(self.server.poll(), Some((ch, Event::Connected { .. })) if ch == server_ch);
        (client_ch, server_ch)
    }
}

struct TestEndpoint {
    side: Side,
    endpoint: Endpoint,
    addr: SocketAddr,
    socket: Option<UdpSocket>,
    timers: [Option<Instant>; Timer::COUNT],
    conn: Option<ConnectionHandle>,
    outbound: VecDeque<Transmit>,
    delayed: VecDeque<Transmit>,
    inbound: VecDeque<(Instant, Option<EcnCodepoint>, Box<[u8]>)>,
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
            conn: None,
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
        }
    }

    fn drive(&mut self, log: &Logger, now: Instant, remote: SocketAddr) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }
        if let Some(conn) = self.conn {
            for &timer in Timer::VALUES.iter() {
                if let Some(time) = self.timers[timer as usize] {
                    if time <= now {
                        trace!(
                            log,
                            "{side:?} {timer:?} timeout",
                            side = self.side,
                            timer = timer
                        );
                        self.timers[timer as usize] = None;
                        self.endpoint.timeout(now, conn, timer);
                    }
                }
            }
        }
        while self.inbound.front().map_or(false, |x| x.0 <= now) {
            let (_, ecn, packet) = self.inbound.pop_front().unwrap();
            self.endpoint
                .handle(now, remote, ecn, Vec::from(packet).into());
        }
        while let Some(x) = self.endpoint.poll_transmit(now) {
            self.outbound.push_back(x);
        }
        while let Some((ch, x)) = self.endpoint.poll_timers() {
            self.conn = Some(ch);
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

    fn next_wakeup(&self) -> Option<Instant> {
        let next_timer = self.timers.iter().cloned().filter_map(|t| t).min();
        let next_inbound = self.inbound.front().map(|x| x.0);
        min_opt(next_timer, next_inbound)
    }

    fn is_idle(&self) -> bool {
        let t = self.next_wakeup();
        t == self.timers[Timer::Idle as usize] || t == self.timers[Timer::KeepAlive as usize]
    }

    fn delay_outbound(&mut self) {
        assert!(self.delayed.is_empty());
        mem::swap(&mut self.delayed, &mut self.outbound);
    }

    fn finish_delay(&mut self) {
        self.outbound.extend(self.delayed.drain(..));
    }

    fn assert_accept(&mut self) -> ConnectionHandle {
        if let Some((c, Event::Handshaking)) = self.poll() {
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

#[test]
fn version_negotiate() {
    let log = logger();
    let client_addr = "[::2]:7890".parse().unwrap();
    let mut server = Endpoint::new(
        log.new(o!("peer" => "server")),
        Default::default(),
        Some(Arc::new(server_config())),
    )
    .unwrap();
    let now = Instant::now();
    server.handle(
        now,
        client_addr,
        None,
        // Long-header packet with reserved version number
        hex!(
            "80 0a1a2a3a
                        11 00000000 00000000
                        00"
        )[..]
            .into(),
    );
    let io = server.poll_transmit(now);
    assert!(io.is_some());
    if let Some(Transmit { packet, .. }) = io {
        assert_ne!(packet[0] & 0x80, 0);
        assert_eq!(&packet[1..14], hex!("00000000 11 00000000 00000000"));
        assert!(packet[14..]
            .chunks(4)
            .any(|x| BigEndian::read_u32(x) == VERSION));
    }
    assert_matches!(server.poll_transmit(now), None);
    assert_matches!(server.poll(), None);
}

#[test]
fn lifecycle() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    assert_matches!(pair.client.poll(), None);
    assert!(pair.client.connection(client_ch).using_ecn());
    assert!(pair.server.connection(server_ch).using_ecn());

    const REASON: &[u8] = b"whee";
    info!(pair.log, "closing");
    pair.client.close(pair.time, client_ch, 42, REASON.into());
    pair.drive();
    assert!(pair.spins > 0);
    assert_matches!(pair.server.poll(),
                    Some((_, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed {
                        reason: ApplicationClose { error_code: 42, ref reason }
                    }})) if reason == REASON);
    assert_matches!(pair.client.poll(), None);
}

#[test]
fn stateless_retry() {
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            use_stateless_retry: true,
            ..server_config()
        },
    );
    pair.connect();
}

#[test]
fn server_stateless_reset() {
    let mut reset_value = [0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_value);

    let reset_key = SigningKey::new(&digest::SHA512_256, &reset_value);

    let endpoint_config = Arc::new(EndpointConfig {
        reset_key,
        ..Default::default()
    });

    let mut pair = Pair::new(endpoint_config.clone(), server_config());
    let (client_ch, _) = pair.connect();
    pair.server.endpoint = Endpoint::new(
        pair.log.new(o!("side" => "Server")),
        endpoint_config,
        Some(Arc::new(server_config())),
    )
    .unwrap();
    // Send something big enough to allow room for a smaller stateless reset.
    pair.client
        .close(pair.time, client_ch, 42, (&[0xab; 128][..]).into());
    info!(pair.log, "resetting");
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::ConnectionLost { reason: ConnectionError::Reset })) if conn == client_ch);
}

#[test]
fn client_stateless_reset() {
    let mut reset_value = [0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_value);

    let reset_key = SigningKey::new(&digest::SHA512_256, &reset_value);

    let endpoint_config = Arc::new(EndpointConfig {
        reset_key,
        ..Default::default()
    });

    let mut pair = Pair::new(endpoint_config.clone(), server_config());
    let (_, server_ch) = pair.connect();
    pair.client.endpoint = Endpoint::new(
        pair.log.new(o!("side" => "Client")),
        endpoint_config,
        Some(Arc::new(server_config())),
    )
    .unwrap();
    // Send something big enough to allow room for a smaller stateless reset.
    pair.server
        .close(pair.time, server_ch, 42, (&[0xab; 128][..]).into());
    info!(pair.log, "resetting");
    pair.drive();
    assert_matches!(pair.server.poll(), Some((conn, Event::ConnectionLost { reason: ConnectionError::Reset })) if conn == server_ch);
}

#[test]
fn finish_stream() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client.open(client_ch, Directionality::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client.write(client_ch, s, MSG).unwrap();
    pair.client.finish(client_ch, s);
    pair.drive();

    assert_matches!(pair.client.poll(), Some((conn, Event::StreamFinished { stream })) if conn == client_ch && stream == s);
    assert_matches!(pair.client.poll(), None);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(pair.server.read_unordered(server_ch, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Err(ReadError::Finished)
    );
}

#[test]
fn reset_stream() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client.open(client_ch, Directionality::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client.write(client_ch, s, MSG).unwrap();
    pair.drive();

    info!(pair.log, "resetting stream");
    const ERROR: u16 = 42;
    pair.client.reset(client_ch, s, ERROR);
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Err(ReadError::Reset { error_code: ERROR })
    );
    assert_matches!(pair.client.poll(), None);
}

#[test]
fn stop_stream() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client.open(client_ch, Directionality::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client.write(client_ch, s, MSG).unwrap();
    pair.drive();

    info!(pair.log, "stopping stream");
    const ERROR: u16 = 42;
    pair.server.stop_sending(server_ch, s, ERROR);
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Err(ReadError::Reset { error_code: ERROR })
    );

    assert_matches!(
        pair.client.write(client_ch, s, b"foo"),
        Err(WriteError::Stopped { error_code: ERROR })
    );
}

#[test]
fn reject_self_signed_cert() {
    let mut client_config = ClientConfig::new();
    client_config.versions = vec![ProtocolVersion::TLSv1_3];
    client_config.set_protocols(&[str::from_utf8(ALPN_QUIC_HTTP).unwrap().into()]);

    let mut pair = Pair::default();
    info!(pair.log, "connecting");
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            Arc::new(client_config),
            "localhost",
        )
        .unwrap();
    pair.drive();
    assert_matches!(pair.client.poll(),
                    Some((conn, Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)}))
                    if conn == client_ch && error.code == TransportErrorCode::crypto(AlertDescription::BadCertificate.get_u8()));
}

#[test]
fn congestion() {
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();

    let initial_congestion_state = pair.client.connection(client_ch).congestion_state();
    let s = pair.client.open(client_ch, Directionality::Uni).unwrap();
    loop {
        match pair.client.write(client_ch, s, &[42; 1024]) {
            Ok(n) => {
                assert!(n <= 1024);
                pair.drive_client();
            }
            Err(WriteError::Blocked) => {
                break;
            }
            Err(e) => {
                panic!("unexpected write error: {}", e);
            }
        }
    }
    pair.drive();
    assert!(pair.client.connection(client_ch).congestion_state() >= initial_congestion_state);
    pair.client.write(client_ch, s, &[42; 1024]).unwrap();
}

#[test]
fn high_latency_handshake() {
    let mut pair = Pair::default();
    pair.latency = Duration::from_micros(200 * 1000);
    let (client_ch, server_ch) = pair.connect();
    assert_eq!(pair.client.connection(client_ch).bytes_in_flight(), 0);
    assert_eq!(pair.server.connection(server_ch).bytes_in_flight(), 0);
    assert!(pair.client.connection(client_ch).using_ecn());
    assert!(pair.server.connection(server_ch).using_ecn());
}

#[test]
fn zero_rtt() {
    let mut pair = Pair::default();
    let config = client_config();

    // Establish normal connection
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            config.clone(),
            "localhost",
        )
        .unwrap();
    pair.drive();
    pair.server.assert_accept();
    pair.client.close(pair.time, client_ch, 0, [][..].into());
    pair.drive();

    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    info!(pair.log, "resuming session");
    let client_ch = pair
        .client
        .connect(pair.server.addr, Default::default(), config, "localhost")
        .unwrap();
    assert!(pair.client.connection(client_ch).has_0rtt());
    let s = pair.client.open(client_ch, Directionality::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client.write(client_ch, s, MSG).unwrap();
    pair.drive();
    assert!(pair.client.connection(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();
    assert_matches!(pair.server.read_unordered(server_ch, s), Ok((ref data, 0)) if data == MSG);
    assert_eq!(pair.client.connection(client_ch).lost_packets(), 0);
}

#[test]
fn zero_rtt_rejection() {
    let mut pair = Pair::default();
    let mut config = client_config();

    // Establish normal connection
    let client_conn = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            config.clone(),
            "localhost",
        )
        .unwrap();
    pair.drive();
    pair.server.assert_accept();
    assert_matches!(pair.server.poll(), Some((_, Event::Connected)));
    assert_matches!(pair.server.poll(), None);
    pair.client.close(pair.time, client_conn, 0, [][..].into());
    pair.drive();
    assert_matches!(pair.server.poll(), Some((_, Event::ConnectionLost { .. })));
    assert_matches!(pair.server.poll(), None);

    // Changing protocols invalidates 0-RTT
    Arc::get_mut(&mut config)
        .unwrap()
        .set_protocols(&["foo".into()]);
    info!(pair.log, "resuming session");
    let client_conn = pair
        .client
        .connect(pair.server.addr, Default::default(), config, "localhost")
        .unwrap();
    assert!(pair.client.connection(client_conn).has_0rtt());
    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client.write(client_conn, s, MSG).unwrap();
    pair.drive();
    assert!(!pair.client.connection(client_conn).accepted_0rtt());
    let server_conn = pair.server.assert_accept();
    assert_matches!(pair.server.poll(), Some((_, Event::Connected)));
    assert_matches!(pair.server.poll(), None);
    let s2 = pair.client.open(client_conn, Directionality::Uni).unwrap();
    assert_eq!(s, s2);
    assert_eq!(
        pair.server.read_unordered(server_conn, s2),
        Err(ReadError::Blocked)
    );
    assert_eq!(pair.client.connection(client_conn).lost_packets(), 0);
}

#[test]
fn close_during_handshake() {
    let mut pair = Pair::default();
    let c = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.client.close(pair.time, c, 0, Bytes::new());
    // This never actually sends the client's Initial; we may want to behave better here.
}

#[test]
fn stream_id_backpressure() {
    let server = ServerConfig {
        transport_config: Arc::new(TransportConfig {
            stream_window_uni: 1,
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();

    let s = pair
        .client
        .open(client_ch, Directionality::Uni)
        .expect("couldn't open first stream");
    assert_eq!(
        pair.client.open(client_ch, Directionality::Uni),
        None,
        "only one stream is permitted at a time"
    );
    // Close the first stream to make room for the second
    pair.client.finish(client_ch, s);
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::StreamFinished { stream })) if conn == client_ch && stream == s);
    assert_matches!(pair.client.poll(), None);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Err(ReadError::Finished)
    );
    // Server will only send MAX_STREAM_ID now that the application's been notified
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::StreamAvailable { directionality: Directionality::Uni })) if conn == client_ch);
    assert_matches!(pair.client.poll(), None);

    // Try opening the second stream again, now that we've made room
    let s = pair
        .client
        .open(client_ch, Directionality::Uni)
        .expect("didn't get stream id budget");
    pair.client.finish(client_ch, s);
    pair.drive();
    // Make sure the server actually processes data on the newly-available stream
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Err(ReadError::Finished)
    );
}

#[test]
fn key_update() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let s = pair
        .client
        .open(client_ch, Directionality::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"hello1";
    pair.client.write(client_ch, s, MSG1).unwrap();
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Ok((ref data, 0)) if data == MSG1
    );

    pair.client.connections[client_ch].force_key_update();

    const MSG2: &[u8] = b"hello2";
    pair.client.write(client_ch, s, MSG2).unwrap();
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream })) if conn == server_ch && stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Ok((ref data, 6)) if data == MSG2
    );
}

#[test]
fn key_update_reordered() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let s = pair
        .client
        .open(client_ch, Directionality::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"1";
    pair.client.write(client_ch, s, MSG1).unwrap();
    pair.client.drive(&pair.log, pair.time, pair.server.addr);
    assert!(!pair.client.outbound.is_empty());
    pair.client.delay_outbound();

    pair.client.connections[client_ch].force_key_update();
    info!(pair.log, "updated keys");

    const MSG2: &[u8] = b"two";
    pair.client.write(client_ch, s, MSG2).unwrap();
    pair.client.drive(&pair.log, pair.time, pair.server.addr);
    pair.client.finish_delay();
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_ch);
    assert_matches!(pair.server.accept_stream(server_ch), Some(stream) if stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Ok((ref data, 1)) if data == MSG2
    );
    assert_matches!(
        pair.server.read_unordered(server_ch, s),
        Ok((ref data, 0)) if data == MSG1
    );

    assert_eq!(pair.client.connection(client_ch).lost_packets(), 0);
}

#[test]
fn initial_retransmit() {
    let mut pair = Pair::default();
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.client.drive(&pair.log, pair.time, pair.server.addr);
    pair.client.outbound.clear(); // Drop initial
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_ch);
}

#[test]
fn instant_close() {
    let mut pair = Pair::default();
    info!(pair.log, "connecting");
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.client.close(pair.time, client_ch, 0, Bytes::new());
    pair.drive();
    assert_matches!(pair.client.poll(), None);
    assert_matches!(pair.server.poll(), None);
}

#[test]
fn instant_close_2() {
    let mut pair = Pair::default();
    info!(pair.log, "connecting");
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    // Unlike `instant_close`, the server sees a valid Initial packet first.
    pair.drive_client();
    pair.client.close(pair.time, client_ch, 42, Bytes::new());
    pair.drive();
    assert_matches!(pair.client.poll(), None);
    pair.server.assert_accept();
    assert_matches!(pair.server.poll(), Some((_, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed {
        reason: ApplicationClose { error_code: 42, ref reason }
    }})) if reason.is_empty());
}

#[test]
fn idle_timeout() {
    const IDLE_TIMEOUT: u64 = 10;
    let server = ServerConfig {
        transport_config: Arc::new(TransportConfig {
            idle_timeout: IDLE_TIMEOUT,
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    pair.client.ping(client_ch);
    let start = pair.time;

    while !pair.client.connection(client_ch).is_closed()
        || !pair.server.connection(server_ch).is_closed()
    {
        if !pair.step() {
            if let Some(t) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = t;
            }
        }
        pair.client.inbound.clear(); // Simulate total S->C packet loss
    }

    assert!(pair.time - start < 2 * Duration::from_secs(IDLE_TIMEOUT));
    assert_matches!(
        pair.client.poll(),
        Some((
            _,
            Event::ConnectionLost {
                reason: ConnectionError::TimedOut,
            },
        ))
    );
    assert_matches!(
        pair.server.poll(),
        Some((
            _,
            Event::ConnectionLost {
                reason: ConnectionError::TimedOut,
            },
        ))
    );
}

#[test]
fn server_busy() {
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            accept_buffer: 0,
            ..server_config()
        },
    );
    pair.client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.drive();
    assert_matches!(
        pair.client.poll(),
        Some((
            _,
            Event::ConnectionLost {
                reason:
                    ConnectionError::ConnectionClosed {
                        reason:
                            frame::ConnectionClose {
                                error_code: TransportErrorCode::SERVER_BUSY,
                                ..
                            },
                    },
            },
        ))
    );
    assert_matches!(pair.server.poll(), None);
}

#[test]
fn server_hs_retransmit() {
    let mut pair = Pair::default();
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.step();
    assert!(pair.client.inbound.len() > 1); // Initial + Handshakes
    info!(
        pair.log,
        "dropping {} server handshake packets",
        pair.client.inbound.len() - 1
    );
    pair.client.inbound.drain(1..);
    // Client's Initial ACK buys a lot of budget, so keep dropping...
    for _ in 0..3 {
        pair.step();
        info!(
            pair.log,
            "dropping {} server handshake packets",
            pair.client.inbound.len()
        );
        pair.client.inbound.drain(..);
    }
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_ch);
}

#[test]
fn decode_coalesced() {
    // We can't currently generate coalesced packets natively, but we must support decoding
    // them. Hack around the problem by manually concatenating the server's first flight.
    let mut pair = Pair::default();
    let client_ch = pair
        .client
        .connect(
            pair.server.addr,
            Default::default(),
            client_config(),
            "localhost",
        )
        .unwrap();
    pair.step();
    assert!(
        pair.client.inbound.len() > 1,
        "if the server's flight isn't multiple packets, this test is redundant"
    );
    let mut coalesced = Vec::new();
    for (_, _, packet) in pair.client.inbound.drain(..) {
        coalesced.extend_from_slice(&packet);
    }
    pair.client
        .inbound
        .push_back((pair.time, Some(EcnCodepoint::ECT0), coalesced.into()));
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_ch);
    assert_eq!(pair.client.connection(client_ch).lost_packets(), 0);
}

#[test]
fn migration() {
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    pair.client.addr = SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 1).into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    pair.client.ping(client_ch);
    pair.drive();
    assert_matches!(pair.client.poll(), None);
    assert_eq!(pair.server.connection(server_ch).remote(), pair.client.addr);
}

fn test_flow_control(config: TransportConfig, window_size: usize) {
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            transport_config: Arc::new(config),
            ..server_config()
        },
    );
    let (client_conn, server_conn) = pair.connect();
    let msg = vec![0xAB; window_size + 10];
    let mut buf = [0; 4096];

    // Stream reset before read
    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    assert_eq!(pair.client.write(client_conn, s, &msg), Ok(window_size));
    assert_eq!(
        pair.client.write(client_conn, s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );
    pair.drive();
    pair.client.reset(client_conn, s, 42);
    pair.drive();
    assert_eq!(
        pair.server.read(server_conn, s, &mut buf),
        Err(ReadError::Reset { error_code: 42 })
    );

    // Happy path
    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    assert_eq!(pair.client.write(client_conn, s, &msg), Ok(window_size));
    assert_eq!(
        pair.client.write(client_conn, s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );
    pair.drive();
    let mut cursor = 0;
    loop {
        match pair.server.read(server_conn, s, &mut buf[cursor..]) {
            Ok(n) => {
                cursor += n;
            }
            Err(ReadError::Blocked) => {
                break;
            }
            Err(e) => {
                panic!(e);
            }
        }
    }
    assert_eq!(cursor, window_size);
    pair.drive();
    assert_eq!(pair.client.write(client_conn, s, &msg), Ok(window_size));
    assert_eq!(
        pair.client.write(client_conn, s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );
    pair.drive();
    let mut cursor = 0;
    loop {
        match pair.server.read(server_conn, s, &mut buf[cursor..]) {
            Ok(n) => {
                cursor += n;
            }
            Err(ReadError::Blocked) => {
                break;
            }
            Err(e) => {
                panic!(e);
            }
        }
    }
    assert_eq!(cursor, window_size);
}

#[test]
fn stream_flow_control() {
    test_flow_control(
        TransportConfig {
            stream_receive_window: 2000,
            ..TransportConfig::default()
        },
        2000,
    );
}

#[test]
fn conn_flow_control() {
    test_flow_control(
        TransportConfig {
            receive_window: 2000,
            ..TransportConfig::default()
        },
        2000,
    );
}

#[test]
fn stop_opens_bidi() {
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();
    let s = pair.client.open(client_conn, Directionality::Bi).unwrap();
    const ERROR: u16 = 42;
    pair.client.stop_sending(server_conn, s, ERROR);
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_conn);
    assert_matches!(pair.server.accept_stream(server_conn), Some(stream) if stream == s);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Blocked)
    );
    assert_matches!(
        pair.server.write(server_conn, s, b"foo"),
        Err(WriteError::Stopped { error_code: ERROR })
    );
}

#[test]
fn implicit_open() {
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();
    let s1 = pair.client.open(client_conn, Directionality::Uni).unwrap();
    let s2 = pair.client.open(client_conn, Directionality::Uni).unwrap();
    pair.client.write(client_conn, s2, b"hello").unwrap();
    pair.drive();
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamOpened)) if conn == server_conn);
    assert_eq!(pair.server.accept_stream(server_conn), Some(s1));
    assert_eq!(pair.server.accept_stream(server_conn), Some(s2));
    assert_eq!(pair.server.accept_stream(server_conn), None);
}

#[test]
fn zero_length_cid() {
    let mut pair = Pair::new(
        Arc::new(EndpointConfig {
            local_cid_len: 0,
            ..EndpointConfig::default()
        }),
        server_config(),
    );
    let (client_ch, server_ch) = pair.connect();
    // Ensure we can reconnect after a previous connection is cleaned up
    info!(pair.log, "closing");
    pair.client.close(pair.time, client_ch, 42, Bytes::new());
    pair.drive();
    pair.server.close(pair.time, server_ch, 42, Bytes::new());
    pair.connect();
}

#[test]
fn keep_alive() {
    const IDLE_TIMEOUT: u64 = 10;
    let server = ServerConfig {
        transport_config: Arc::new(TransportConfig {
            keep_alive_interval: IDLE_TIMEOUT as u32 / 2,
            idle_timeout: IDLE_TIMEOUT,
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    // Run a good while longer than the idle timeout
    let end = pair.time + Duration::new(20 * IDLE_TIMEOUT, 0);
    while pair.time < end {
        if !pair.step() {
            if let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = time;
            }
        }
        assert!(!pair.client.connection(client_ch).is_closed());
        assert!(!pair.server.connection(server_ch).is_closed());
    }
}

fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}
