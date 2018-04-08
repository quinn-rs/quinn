extern crate quicr;
extern crate openssl;
extern crate rand;
#[macro_use]
extern crate slog;
extern crate slog_term;
#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate lazy_static;
extern crate bytes;
#[macro_use]
extern crate hex_literal;
extern crate byteorder;

use std::net::SocketAddrV6;

use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl::asn1::Asn1Time;
use slog::{Logger, Drain};
use byteorder::{ByteOrder, BigEndian};

use quicr::*;

fn logger() -> Logger {
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
    let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
    Logger::root(drain, o!())
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
    static ref STATE: PersistentState = rand::random();
}

struct Pair {
    log: Logger,
    server: Endpoint,
    server_addr: SocketAddrV6,
    client: Endpoint,
    client_addr: SocketAddrV6,
}

impl Pair {
    fn new(log: Logger) -> Self {
        let server_addr = "[::1]:42".parse().unwrap();
        let server = Endpoint::new(
            log.new(o!("peer" => "server")),
            Config::default(),
            *STATE,
            Some(ListenConfig {
                private_key: &KEY,
                cert: &CERT,
            })).unwrap();
        let client_addr = "[::2]:7890".parse().unwrap();
        let client = Endpoint::new(log.new(o!("peer" => "client")), Config::default(), *STATE, None).unwrap();

        Self { log, server_addr, server, client_addr, client }
    }

    fn drive(&mut self) {
        loop {
            let s = self.server.poll_io();
            let c = self.client.poll_io();
            if s.is_none() && c.is_none() { break; }
            match s {
                None => {}
                Some(Io::Transmit { destination, packet }) => {
                    trace!(self.log, "server -> client");
                    self.client.handle(0, self.server_addr, destination, Vec::from(packet).into());
                }
                Some(Io::TimerStart { .. }) | Some(Io::TimerStop { .. }) => {} // No time passes
            }
            match c {
                None => {}
                Some(Io::Transmit { destination, packet }) => {
                    trace!(self.log, "client -> server");
                    self.server.handle(0, self.client_addr, destination, Vec::from(packet).into())
                }
                Some(Io::TimerStart { .. }) | Some(Io::TimerStop { .. }) => {} // No time passes
            }
        }
    }
}

#[test]
fn version_negotiate() {
    let log = logger();
    let server_addr = "[::1]:42".parse().unwrap();
    let client_addr = "[::2]:7890".parse().unwrap();
    let mut server = Endpoint::new(
        log.new(o!("peer" => "server")),
        Config::default(),
        *STATE,
        Some(ListenConfig {
            private_key: &KEY,
            cert: &CERT,
        })).unwrap();
    server.handle(0, client_addr, server_addr,
                  // Long-header packet with reserved version number
                  hex!("80 0a1a2a3a
                        11 00000000 00000000
                        00")[..].into());
    let io = server.poll_io();
    assert_matches!(io, Some(Io::Transmit { .. }));
    if let Some(Io::Transmit { packet, .. }) = io {
        assert!(packet[0] | 0x80 != 0);
        assert!(&packet[1..14] == hex!("00000000 11 00000000 00000000"));
        assert!(packet[14..].chunks(4).any(|x| BigEndian::read_u32(x) == VERSION));
    }
    assert_matches!(server.poll_io(), None);
    assert_matches!(server.poll(), None);
}

#[test]
fn connect() {
    let log = logger();
    let mut pair = Pair::new(log);
    let client_conn = pair.client.connect(0, pair.client_addr, pair.server_addr).unwrap();
    info!(pair.log, "connecting");
    pair.drive();
    assert_matches!(pair.server.poll(), Some(Event::Connected(_)));
    assert_matches!(pair.client.poll(), Some(Event::Connected(x)) if x == client_conn);
    const REASON: &[u8] = b"whee";
    pair.client.close(0, client_conn, 42, REASON.into());
    info!(pair.log, "closing");
    pair.drive();
    assert_matches!(pair.server.poll(), Some(Event::ConnectionLost { reason: ConnectionError::ApplicationClosed {
        reason: ApplicationClose { error_code: 42, ref reason }
    }, .. }) if reason == REASON);
    assert_matches!(pair.client.poll(), None);
}

#[test]
fn reset() {
    let log = logger();
    let mut pair = Pair::new(log);
    let client_conn = pair.client.connect(0, pair.client_addr, pair.server_addr).unwrap();
    info!(pair.log, "connecting");
    pair.drive();
    assert_matches!(pair.client.poll(), Some(Event::Connected(x)) if x == client_conn);
    pair.server = Endpoint::new(
        pair.log.new(o!("peer" => "server")),
        Config::default(),
        *STATE,
        Some(ListenConfig {
            private_key: &KEY,
            cert: &CERT,
        })).unwrap();
    assert!(pair.client.ping(0, client_conn));
    info!(pair.log, "resetting");
    pair.drive();
    assert_matches!(pair.client.poll(), Some(Event::ConnectionLost { reason: ConnectionError::Reset, connection }) if connection == client_conn);
}
