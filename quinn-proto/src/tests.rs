use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::ops::RangeFrom;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fmt, fs, str};

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use rand::RngCore;
use ring::digest;
use ring::hmac::SigningKey;
use rustls::internal::msgs::enums::AlertDescription;
use rustls::{internal::pemfile, KeyLogFile, ProtocolVersion};
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
}

struct Pair {
    log: Logger,
    server: TestEndpoint,
    client: TestEndpoint,
    time: u64,
    // One-way
    latency: u64,
}

impl Default for Pair {
    fn default() -> Self {
        let mut server = Config::default();
        server.max_remote_uni_streams = 32;
        server.max_remote_bi_streams = 32;
        Pair::new(server, Default::default(), server_config())
    }
}

fn server_config() -> ServerConfig {
    let certs = {
        let f =
            fs::File::open("../certs/server.chain").expect("cannot open '../certs/server.chain'");
        let mut reader = io::BufReader::new(f);
        pemfile::certs(&mut reader).expect("cannot read certificates")
    };

    let keys = {
        let f = fs::File::open("../certs/server.rsa").expect("cannot open '../certs/server.rsa'");
        let mut reader = io::BufReader::new(f);
        pemfile::rsa_private_keys(&mut reader).expect("cannot read private keys")
    };

    let mut tls_config = crypto::build_server_config();
    tls_config.set_protocols(&[str::from_utf8(ALPN_QUIC_HTTP).unwrap().into()]);
    tls_config.set_single_cert(certs, keys[0].clone()).unwrap();
    ServerConfig {
        tls_config: Arc::new(tls_config),
        ..Default::default()
    }
}

fn client_config() -> Arc<ClientConfig> {
    let mut f = fs::File::open("../certs/ca.der").expect("cannot open '../certs/ca.der'");
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).expect("error while reading");

    let anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::from(&bytes)).unwrap();
    let anchor_vec = vec![anchor];

    let mut tls_client_config = ClientConfig::new();
    tls_client_config.versions = vec![ProtocolVersion::TLSv1_3];
    tls_client_config.set_protocols(&[str::from_utf8(ALPN_QUIC_HTTP).unwrap().into()]);
    tls_client_config
        .root_store
        .add_server_trust_anchors(&webpki::TLSServerTrustAnchors(&anchor_vec));
    tls_client_config.key_log = Arc::new(KeyLogFile::new());
    Arc::new(tls_client_config)
}

impl Pair {
    fn new(server_config: Config, client_config: Config, listen_keys: ServerConfig) -> Self {
        let log = logger();
        let server = Endpoint::new(
            log.new(o!("side" => "Server")),
            server_config,
            Some(listen_keys),
        )
        .unwrap();
        let client = Endpoint::new(log.new(o!("side" => "Client")), client_config, None).unwrap();

        let localhost = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let server_addr = SocketAddrV6::new(
            localhost,
            SERVER_PORTS.lock().unwrap().next().unwrap(),
            0,
            0,
        );
        let client_addr = SocketAddrV6::new(
            localhost,
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
            0,
            0,
        );
        Self {
            log,
            server: TestEndpoint::new(Side::Server, server, server_addr),
            client: TestEndpoint::new(Side::Client, client, client_addr),
            time: 0,
            latency: 0,
        }
    }

    /// Returns whether the connection is not idle
    fn step(&mut self) -> bool {
        self.drive_client();
        self.drive_server();
        let client_t = self.client.next_wakeup();
        let server_t = self.server.next_wakeup();
        if client_t == self.client.idle && server_t == self.server.idle {
            return false;
        }
        if client_t < server_t {
            if client_t != self.time {
                self.time = self.time.max(client_t);
                trace!(self.log, "advancing to {time} for client", time = self.time);
            }
        } else {
            if server_t != self.time {
                self.time = self.time.max(server_t);
                trace!(self.log, "advancing to {time} for server", time = self.time);
            }
        }
        true
    }

    /// Advance time until both connections are idle
    fn drive(&mut self) {
        while self.step() {}
    }

    fn drive_client(&mut self) {
        trace!(self.log, "client running");
        self.client.drive(&self.log, self.time, self.server.addr);
        for packet in self.client.outbound.drain(..) {
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&packet, self.server.addr).unwrap();
            }
            self.server
                .inbound
                .push_back((self.time + self.latency, packet));
        }
    }

    fn drive_server(&mut self) {
        trace!(self.log, "server running");
        self.server.drive(&self.log, self.time, self.client.addr);
        for packet in self.server.outbound.drain(..) {
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&packet, self.client.addr).unwrap();
            }
            self.client
                .inbound
                .push_back((self.time + self.latency, packet));
        }
    }

    fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        info!(self.log, "connecting");
        let client_conn = self
            .client
            .connect(self.server.addr, &client_config(), "localhost")
            .unwrap();
        self.drive();
        let server_conn = if let Some(c) = self.server.accept() {
            c
        } else {
            panic!("server didn't connect");
        };
        assert_matches!(self.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_conn);
        (client_conn, server_conn)
    }
}

struct TestEndpoint {
    side: Side,
    endpoint: Endpoint,
    addr: SocketAddrV6,
    socket: Option<UdpSocket>,
    idle: u64,
    loss: u64,
    close: u64,
    conn: Option<ConnectionHandle>,
    outbound: VecDeque<Box<[u8]>>,
    inbound: VecDeque<(u64, Box<[u8]>)>,
}

impl TestEndpoint {
    fn new(side: Side, endpoint: Endpoint, addr: SocketAddrV6) -> Self {
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
            idle: u64::max_value(),
            loss: u64::max_value(),
            close: u64::max_value(),
            conn: None,
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
        }
    }

    fn drive(&mut self, log: &Logger, now: u64, remote: SocketAddrV6) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }
        if let Some(conn) = self.conn {
            if self.loss <= now {
                trace!(
                    log,
                    "{side:?} {timer:?} timeout",
                    side = self.side,
                    timer = Timer::LossDetection
                );
                self.loss = u64::max_value();
                self.endpoint.timeout(now, conn, Timer::LossDetection);
            }
            if self.idle <= now {
                trace!(
                    log,
                    "{side:?} {timer:?} timeout",
                    side = self.side,
                    timer = Timer::Idle
                );
                self.idle = u64::max_value();
                self.endpoint.timeout(now, conn, Timer::Idle);
            }
            if self.close <= now {
                trace!(
                    log,
                    "{side:?} {timer:?} timeout",
                    side = self.side,
                    timer = Timer::Close
                );
                self.close = u64::max_value();
                self.endpoint.timeout(now, conn, Timer::Close);
            }
        }
        while self.inbound.front().map_or(false, |x| x.0 <= now) {
            self.endpoint.handle(
                now,
                remote,
                Vec::from(self.inbound.pop_front().unwrap().1).into(),
            );
        }
        while let Some(x) = self.endpoint.poll_io(now) {
            match x {
                Io::Transmit { packet, .. } => {
                    self.outbound.push_back(packet);
                }
                Io::TimerStart {
                    timer,
                    time,
                    connection,
                } => {
                    self.conn = Some(connection);
                    trace!(
                        log,
                        "{side:?} {timer:?} start: {dt}",
                        side = self.side,
                        timer = timer,
                        dt = (time - now)
                    );
                    match timer {
                        Timer::LossDetection => {
                            self.loss = time;
                        }
                        Timer::Idle => {
                            self.idle = time;
                        }
                        Timer::Close => {
                            self.close = time;
                        }
                    }
                }
                Io::TimerStop { timer, .. } => {
                    trace!(
                        log,
                        "{side:?} {timer:?} stop",
                        side = self.side,
                        timer = timer
                    );
                    match timer {
                        Timer::LossDetection => {
                            self.loss = u64::max_value();
                        }
                        Timer::Idle => {
                            self.idle = u64::max_value();
                        }
                        Timer::Close => {
                            self.close = u64::max_value();
                        }
                    }
                }
            }
        }
    }

    fn next_wakeup(&self) -> u64 {
        self.idle
            .min(self.loss)
            .min(self.close)
            .min(self.inbound.front().map_or(u64::max_value(), |x| x.0))
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
        Config::default(),
        Some(server_config()),
    )
    .unwrap();
    server.handle(
        0,
        client_addr,
        // Long-header packet with reserved version number
        hex!(
            "80 0a1a2a3a
                        11 00000000 00000000
                        00"
        )[..]
            .into(),
    );
    let io = server.poll_io(0);
    assert_matches!(io, Some(Io::Transmit { .. }));
    if let Some(Io::Transmit { packet, .. }) = io {
        assert_ne!(packet[0] & 0x80, 0);
        assert_eq!(&packet[1..14], hex!("00000000 11 00000000 00000000"));
        assert!(packet[14..]
            .chunks(4)
            .any(|x| BigEndian::read_u32(x) == VERSION));
    }
    assert_matches!(server.poll_io(0), None);
    assert_matches!(server.poll(), None);
}

#[test]
fn lifecycle() {
    let mut pair = Pair::default();
    let (client_conn, _) = pair.connect();
    assert_matches!(pair.client.poll(), None);

    const REASON: &[u8] = b"whee";
    info!(pair.log, "closing");
    pair.client.close(pair.time, client_conn, 42, REASON.into());
    pair.drive();
    assert_matches!(pair.server.poll(),
                    Some((_, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed {
                        reason: ApplicationClose { error_code: 42, ref reason }
                    }})) if reason == REASON);
    assert_matches!(pair.client.poll(), Some((conn, Event::ConnectionDrained)) if conn == client_conn);
}

#[test]
fn stateless_retry() {
    let mut pair = Pair::new(
        Config::default(),
        Config::default(),
        ServerConfig {
            use_stateless_retry: true,
            ..server_config()
        },
    );
    pair.connect();
}

#[test]
fn stateless_reset() {
    let mut server = Config::default();
    server.max_remote_uni_streams = 32;
    server.max_remote_bi_streams = 32;

    let mut token_value = [0; 64];
    let mut reset_value = [0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut token_value);
    rng.fill_bytes(&mut reset_value);

    let listen_key = ServerConfig {
        token_key: TokenKey::new(&token_value),
        reset_key: SigningKey::new(&digest::SHA512_256, &reset_value),
        ..server_config()
    };

    let pair_listen_keys = ServerConfig {
        token_key: TokenKey::new(&token_value),
        reset_key: SigningKey::new(&digest::SHA512_256, &reset_value),
        ..server_config()
    };

    let mut pair = Pair::new(server, Default::default(), listen_key);
    let (client_conn, _) = pair.connect();
    pair.server.endpoint = Endpoint::new(
        pair.log.new(o!("peer" => "server")),
        Config::default(),
        Some(pair_listen_keys),
    )
    .unwrap();
    pair.client.ping(client_conn);
    info!(pair.log, "resetting");
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::ConnectionLost { reason: ConnectionError::Reset })) if conn == client_conn);
}

#[test]
fn finish_stream() {
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();

    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client.write(client_conn, s, MSG).unwrap();
    pair.client.finish(client_conn, s);
    pair.drive();

    assert_matches!(pair.client.poll(), Some((conn, Event::StreamFinished { stream })) if conn == client_conn && stream == s);
    assert_matches!(pair.client.poll(), None);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: true })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(pair.server.read_unordered(server_conn, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Finished)
    );
}

#[test]
fn reset_stream() {
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();

    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client.write(client_conn, s, MSG).unwrap();
    pair.drive();

    info!(pair.log, "resetting stream");
    const ERROR: u16 = 42;
    pair.client.reset(client_conn, s, ERROR);
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: true })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: false })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.read_unordered(server_conn, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Reset { error_code: ERROR })
    );
    assert_matches!(pair.client.poll(), None);
}

#[test]
fn stop_stream() {
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();

    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client.write(client_conn, s, MSG).unwrap();
    pair.drive();

    info!(pair.log, "stopping stream");
    const ERROR: u16 = 42;
    pair.server.stop_sending(server_conn, s, ERROR);
    pair.drive();

    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: true })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: false })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.read_unordered(server_conn, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Reset { error_code: ERROR })
    );

    assert_matches!(
        pair.client.write(client_conn, s, b"foo"),
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
    let client_conn = pair
        .client
        .connect(pair.server.addr, &Arc::new(client_config), "localhost")
        .unwrap();
    pair.drive();
    assert_matches!(pair.client.poll(),
                    Some((conn, Event::ConnectionLost { reason: ConnectionError::TransportError {
                        error_code
                    }})) if conn == client_conn && error_code == TransportError::crypto(AlertDescription::BadCertificate));
}

#[test]
fn congestion() {
    let mut pair = Pair::default();
    let (client_conn, _) = pair.connect();

    let initial_congestion_state = pair.client.get_congestion_state(client_conn);
    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    loop {
        match pair.client.write(client_conn, s, &[42; 1024]) {
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
    assert!(pair.client.get_congestion_state(client_conn) >= initial_congestion_state);
    pair.client.write(client_conn, s, &[42; 1024]).unwrap();
}

#[test]
fn high_latency_handshake() {
    let mut pair = Pair::default();
    pair.latency = 200 * 1000;
    let client_conn = pair
        .client
        .connect(pair.server.addr, &client_config(), "localhost")
        .unwrap();
    pair.drive();
    let server_conn = if let Some(c) = pair.server.accept() {
        c
    } else {
        panic!("server didn't connect");
    };
    assert_matches!(pair.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_conn);
    assert_eq!(pair.client.get_bytes_in_flight(client_conn), 0);
    assert_eq!(pair.server.get_bytes_in_flight(server_conn), 0);
}

/*
#[test]
fn zero_rtt() {
    let mut pair = Pair::default();
    let (c, _) = pair.connect();
    let ticket = match pair.client.poll() {
        Some((conn, Event::NewSessionTicket { ref ticket })) if conn == c => ticket.clone(),
        e => panic!("unexpected poll result: {:?}", e),
    };
    info!(pair.log, "closing"; "ticket size" => ticket.len());
    pair.client.close(pair.time, c, 42, (&[][..]).into());
    pair.drive();
    info!(pair.log, "resuming");
    let cc = pair
        .client
        .connect(
            pair.server.addr,
            "localhost",
        )
        .unwrap();
    let s = pair.client.open(cc, Directionality::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client.write(cc, s, MSG).unwrap();
    pair.drive();
    assert!(pair.client.get_session_resumed(c));
    let sc = if let Some(c) = pair.server.accept() {
        c
    } else {
        panic!("server didn't connect");
    };
    assert_matches!(pair.server.read_unordered(sc, s), Ok((ref data, 0)) if data == MSG);
}
*/

#[test]
fn close_during_handshake() {
    let mut pair = Pair::default();
    let c = pair
        .client
        .connect(pair.server.addr, &client_config(), "localhost")
        .unwrap();
    pair.client.close(pair.time, c, 0, Bytes::new());
    // This never actually sends the client's Initial; we may want to behave better here.
}

#[test]
fn stream_id_backpressure() {
    let server = Config {
        max_remote_uni_streams: 1,
        ..Config::default()
    };
    let mut pair = Pair::new(server, Default::default(), server_config());
    let (client_conn, server_conn) = pair.connect();

    let s = pair
        .client
        .open(client_conn, Directionality::Uni)
        .expect("couldn't open first stream");
    assert_eq!(
        pair.client.open(client_conn, Directionality::Uni),
        None,
        "only one stream is permitted at a time"
    );
    // Close the first stream to make room for the second
    pair.client.finish(client_conn, s);
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::StreamFinished { stream })) if conn == client_conn && stream == s);
    assert_matches!(pair.client.poll(), None);
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: true })) if conn == server_conn && stream == s);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Finished)
    );
    // Server will only send MAX_STREAM_ID now that the application's been notified
    pair.drive();
    assert_matches!(pair.client.poll(), Some((conn, Event::StreamAvailable { directionality: Directionality::Uni })) if conn == client_conn);
    assert_matches!(pair.client.poll(), None);

    // Try opening the second stream again, now that we've made room
    let s = pair
        .client
        .open(client_conn, Directionality::Uni)
        .expect("didn't get stream id budget");
    pair.client.finish(client_conn, s);
    pair.drive();
    // Make sure the server actually processes data on the newly-available stream
    assert_matches!(pair.server.poll(), Some((conn, Event::StreamReadable { stream, fresh: true })) if conn == server_conn && stream == s);
    assert_matches!(pair.server.poll(), None);
    assert_matches!(
        pair.server.read_unordered(server_conn, s),
        Err(ReadError::Finished)
    );
}
