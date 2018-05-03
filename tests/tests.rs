extern crate quicr_core as quicr;
extern crate openssl;
extern crate rand;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate lazy_static;
extern crate bytes;
#[macro_use]
extern crate hex_literal;
extern crate byteorder;

use std::net::SocketAddrV6;
use std::{fmt, str};
use std::io::{self, Write};

use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl::asn1::Asn1Time;
use slog::{Logger, Drain, KV};
use byteorder::{ByteOrder, BigEndian};

use quicr::*;

struct TestDrain;

impl Drain for TestDrain {
    type Ok = ();
    type Err = io::Error;
    fn log(&self, record: &slog::Record, values: &slog::OwnedKVList) -> Result<(), io::Error> {
        let mut vals = Vec::new();
        values.serialize(&record, &mut TestSerializer(&mut vals))?;
        record.kv().serialize(&record, &mut TestSerializer(&mut vals))?;
        println!("{} {}{}", record.level(), record.msg(), str::from_utf8(&vals).unwrap());
        Ok(())
    }
}

struct TestSerializer<'a, W: 'a>(&'a mut W);
impl<'a, W> slog::Serializer for TestSerializer<'a, W>
    where W: Write + 'a
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments) -> slog::Result {
        write!(self.0, ", {}: {}", key, val).unwrap();
        Ok(())
    }
}

fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

lazy_static! {
    static ref KEY: PKey<Private> = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    static ref CERT: X509 = {
        let mut cert = X509::builder().unwrap();
        cert.set_pubkey(&KEY).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(u32::max_value()).unwrap()).unwrap();
        cert.sign(&KEY, openssl::hash::MessageDigest::sha256()).unwrap();
        cert.build()
    };
    static ref LISTEN_KEYS: ListenKeys = ListenKeys::new(&mut rand::thread_rng());
}

struct Pair {
    log: Logger,
    server: Endpoint,
    server_addr: SocketAddrV6,
    client: Endpoint,
    client_addr: SocketAddrV6,
}

impl Default for Pair {
    fn default() -> Self {
        Pair::new(Config { max_remote_uni_streams: 32, max_remote_bi_streams: 32, ..Config::default() },
                  Config { accept_insecure_certs: true, ..Config::default() })
    }
}

impl Pair {
    fn new(server_config: Config, client_config: Config) -> Self {
        let log = logger();
        let server_addr = "[::1]:42".parse().unwrap();
        let server = Endpoint::new(
            log.new(o!("side" => "Server")),
            server_config,
            Some(CertConfig {
                private_key: &KEY,
                cert: &CERT,
            }),
            Some(*LISTEN_KEYS)).unwrap();
        let client_addr = "[::2]:7890".parse().unwrap();
        let client = Endpoint::new(log.new(o!("side" => "Client")), client_config, None, None).unwrap();

        Self { log, server_addr, server, client_addr, client }
    }

    fn drive(&mut self) {
        loop {
            let s = self.server.poll_io(0);
            let c = self.client.poll_io(0);
            if s.is_none() && c.is_none() { break; }
            if let Some(x) = s { self.handle(Side::Client, x); }
            if let Some(x) = c { self.handle(Side::Server, x); }
        }
    }

    fn handle(&mut self, side: Side, io: Io) {
        let endpoint = match side { Side::Client => &mut self.client, Side::Server => &mut self.server };
        let src =  match !side { Side::Client => self.client_addr, Side::Server => self.server_addr };
        let dest = match  side { Side::Client => self.client_addr, Side::Server => self.server_addr };
        match io {
            Io::Transmit { destination, packet } => {
                trace!(self.log, "recv"; "side" => ?!side);
                assert_eq!(destination, dest);
                endpoint.handle(0, src, Vec::from(packet).into())
            }
            Io::TimerStart { .. } | Io::TimerStop { .. } => {} // No time passes
        }
    }

    fn drive_cs(&mut self) {
        while let Some(x) = self.client.poll_io(0) {
            self.handle(Side::Server, x);
        }
    }

    fn drive_sc(&mut self) {
        while let Some(x) = self.server.poll_io(0) {
            self.handle(Side::Client, x);
        }
    }

    fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        info!(self.log, "connecting");
        let client_conn = self.client.connect(self.server_addr, None);
        self.drive();
        let server_conn = if let Some(c) = self.server.accept() { c } else { panic!("server didn't connect"); };
        assert_matches!(self.client.poll(), Some((conn, Event::Connected { .. })) if conn == client_conn);
        (client_conn, server_conn)
    }
}

#[test]
fn version_negotiate() {
    let log = logger();
    let client_addr = "[::2]:7890".parse().unwrap();
    let mut server = Endpoint::new(
        log.new(o!("peer" => "server")),
        Config::default(),
        Some(CertConfig {
            private_key: &KEY,
            cert: &CERT,
        }),
        Some(*LISTEN_KEYS)).unwrap();
    server.handle(0, client_addr,
                  // Long-header packet with reserved version number
                  hex!("80 0a1a2a3a
                        11 00000000 00000000
                        00")[..].into());
    let io = server.poll_io(0);
    assert_matches!(io, Some(Io::Transmit { .. }));
    if let Some(Io::Transmit { packet, .. }) = io {
        assert!(packet[0] | 0x80 != 0);
        assert!(&packet[1..14] == hex!("00000000 11 00000000 00000000"));
        assert!(packet[14..].chunks(4).any(|x| BigEndian::read_u32(x) == VERSION));
    }
    assert_matches!(server.poll_io(0), None);
    assert_matches!(server.poll(), None);
}

#[test]
fn lifecycle() {
    let mut pair = Pair::default();
    let (client_conn, _) = pair.connect();

    const REASON: &[u8] = b"whee";
    info!(pair.log, "closing");
    pair.client.close(0, client_conn, 42, REASON.into());
    pair.drive();
    assert_matches!(pair.server.poll(),
                    Some((_, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed {
                        reason: ApplicationClose { error_code: 42, ref reason }
                    }})) if reason == REASON);
    assert_matches!(pair.client.poll(), None);
}

#[test]
fn stateless_reset() {
    let mut pair = Pair::default();
    let (client_conn, _) = pair.connect();
    pair.server = Endpoint::new(
        pair.log.new(o!("peer" => "server")),
        Config::default(),
        Some(CertConfig {
            private_key: &KEY,
            cert: &CERT,
        }),
        Some(*LISTEN_KEYS)).unwrap();
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
    assert_matches!(pair.server.read_unordered(server_conn, s), Err(ReadError::Finished));
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
    assert_matches!(pair.server.poll(), None);
    assert_matches!(pair.server.read_unordered(server_conn, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(pair.server.read_unordered(server_conn, s), Err(ReadError::Reset { error_code: ERROR }));
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
    assert_matches!(pair.server.poll(), None);
    assert_matches!(pair.server.read_unordered(server_conn, s), Ok((ref data, 0)) if data == MSG);
    assert_matches!(pair.server.read_unordered(server_conn, s), Err(ReadError::Reset { error_code: 0 }));

    assert_matches!(pair.client.write(client_conn, s, b"foo"), Err(WriteError::Stopped { error_code: ERROR }));
}

#[test]
fn reject_self_signed_cert() {
    let mut pair = Pair::new(Config::default(), Config::default());
    info!(pair.log, "connecting");
    let client_conn = pair.client.connect(pair.server_addr, None);
    pair.drive();
    assert_matches!(pair.client.poll(),
                    Some((conn, Event::ConnectionLost { reason: ConnectionError::TransportError {
                        error_code: TransportError::TLS_HANDSHAKE_FAILED
                    }})) if conn == client_conn);
}

#[test]
fn congestion() {
    let mut pair = Pair::default();
    let (client_conn, _) = pair.connect();

    let initial_congestion_state = pair.client.get_congestion_state(client_conn);
    let s = pair.client.open(client_conn, Directionality::Uni).unwrap();
    loop {
        match pair.client.write(client_conn, s, &[42; 1024]) {
            Ok(n) => { assert!(n <= 1024); pair.drive_cs(); }
            Err(WriteError::Blocked) => { break; }
            Err(e) => { panic!("unexpected write error: {}", e); }
        }
    }
    pair.drive_sc();
    assert!(pair.client.get_congestion_state(client_conn) >= initial_congestion_state);
    pair.client.write(client_conn, s, &[42; 1024]).unwrap();
}
