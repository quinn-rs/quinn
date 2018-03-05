extern crate quicr;
extern crate openssl;
#[macro_use]
extern crate slog;
extern crate slog_term;
#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate lazy_static;

use std::net::SocketAddrV6;

use std::ops::Deref;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::ec::EcKey;
use openssl::x509::X509;
use slog::{Logger, Drain};

use quicr::*;

fn logger() -> Logger {
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
    let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
    Logger::root(drain, o!())
}

lazy_static! {
    static ref PRIVATE_KEY: EcKey<Private> = {
        EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(
                openssl::nid::Nid::SECP224R1).unwrap()
        ).unwrap()
    };
    static ref CERT: X509 = {
        let key = PKey::from_ec_key(PRIVATE_KEY.clone()).unwrap();
        let mut cert = X509::builder().unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.sign(&key, openssl::hash::MessageDigest::sha256()).unwrap();
        cert.build()
    };
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
            Config {
                listen: Some(ListenConfig {
                    private_key: PKey::from_ec_key(PRIVATE_KEY.clone()).unwrap(),
                    cert: CERT.clone(),
                }),
                ..Config::default()
            }).unwrap();
        let client_addr = "[::2]:7890".parse().unwrap();
        let client = Endpoint::new(log.new(o!("peer" => "client")), Config::default()).unwrap();

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
                    self.client.handle(self.server_addr, destination, Vec::from(packet).into());
                }
            }
            match c {
                None => {}
                Some(Io::Transmit { destination, packet }) => {
                    trace!(self.log, "client -> server");
                    self.server.handle(self.client_addr, destination, Vec::from(packet).into())
                }
            }
        }
    }
}

#[test]
fn connect() {
    let log = logger();
    let mut pair = Pair::new(log);
    if let Err(e) = pair.client.connect(pair.client_addr, pair.server_addr) {
        panic!("{}", e);
    }
    pair.drive();
    assert_matches!(pair.client.poll().unwrap(), Event::Connected(_));
    assert_matches!(pair.server.poll().unwrap(), Event::Connected(_));
}
