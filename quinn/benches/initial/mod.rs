//! Server cost of one new Initial, without I/O. Packet preparation is not measured.
use std::{hint::black_box, net::SocketAddr, sync::Arc, time::Instant};

use bencher::{Bencher, benchmark_group};
use proto::{ConnectionId, DatagramEvent, TokenStore};

benchmark_group!(
    benches,
    initial_retry,
    initial_retry_bogus_token,
    initial_ignore,
    initial_ignore_bogus_token,
    initial_ignore_validated,
    initial_refuse,
    initial_short_dcid,
    initial_invalid_retry_token
);

fn initial_retry(b: &mut Bencher) {
    run(b, Response::Retry, Token::None);
}

fn initial_retry_bogus_token(b: &mut Bencher) {
    run(b, Response::Retry, Token::Bogus);
}

fn initial_ignore(b: &mut Bencher) {
    run(b, Response::Ignore, Token::None);
}

fn initial_ignore_bogus_token(b: &mut Bencher) {
    run(b, Response::Ignore, Token::Bogus);
}

fn initial_ignore_validated(b: &mut Bencher) {
    run(b, Response::Ignore, Token::Retry);
}

fn initial_refuse(b: &mut Bencher) {
    run(b, Response::Refuse, Token::None);
}

fn initial_short_dcid(b: &mut Bencher) {
    run_invalid(b, Token::None, true);
}

fn initial_invalid_retry_token(b: &mut Bencher) {
    run_invalid(b, Token::Retry, false);
}

/// What the application does with the `Incoming`
#[derive(Copy, Clone, Eq, PartialEq)]
enum Response {
    Retry,
    Ignore,
    Refuse,
}

/// Token carried by the Initial
#[derive(Copy, Clone, Eq, PartialEq)]
enum Token {
    None,
    /// Not issued by the server
    Bogus,
    /// Issued by the server in a Retry
    Retry,
}

/// An Initial as it reaches the server
struct Setup {
    server_config: Arc<proto::ServerConfig>,
    packet: Vec<u8>,
    now: Instant,
    /// Where the client sent it from
    addr: SocketAddr,
}

/// Have a client produce an Initial, with a destination CID shorter than a server accepts if
/// `short_dcid` is set
fn setup(token: Token, short_dcid: bool) -> Setup {
    let super::Context {
        server_config,
        mut client_config,
    } = super::Context::new();
    if short_dcid {
        client_config.initial_dst_cid_provider(Arc::new(|| ConnectionId::new(&[0xab; 4])));
    }
    let store = Arc::new(proto::TokenMemoryCache::default());
    if token == Token::Bogus {
        store.insert("localhost", vec![7; 80].into());
    }
    client_config.token_store(store);

    let mut now = Instant::now();
    let addr = "[::1]:4433".parse().unwrap();
    let mut client = proto::Endpoint::new(Default::default(), None, true);
    let (_, mut connection) = client
        .connect(now, client_config, addr, "localhost")
        .unwrap();
    let mut packet = Vec::new();
    let _ = connection.poll_transmit(now, 1, &mut packet).unwrap();

    let server_config = Arc::new(server_config);
    if token == Token::Retry {
        // Have a throwaway endpoint with the same token key issue a Retry, and let the client
        // answer it
        let mut issuer =
            proto::Endpoint::new(Default::default(), Some(server_config.clone()), true);
        let mut retry = Vec::new();
        let Some(DatagramEvent::NewConnection(incoming)) =
            issuer.handle(now, addr, None, None, packet.as_slice().into(), &mut retry)
        else {
            panic!("expected an Incoming");
        };
        let _ = issuer.retry(incoming, &mut retry).unwrap();
        let Some(DatagramEvent::ConnectionEvent(_, event)) = client.handle(
            now,
            addr,
            None,
            None,
            retry.as_slice().into(),
            &mut Vec::new(),
        ) else {
            panic!("expected the Retry to reach the connection");
        };
        connection.handle_event(event);
        packet.clear();
        // The first Initial used up the client's pacing burst, so the retried one is sent when
        // the pacing timer fires
        if connection.poll_transmit(now, 1, &mut packet).is_none() {
            now = connection.poll_timeout().expect("pacing timer must be set");
            connection.handle_timeout(now);
            let _ = connection
                .poll_transmit(now, 1, &mut packet)
                .expect("client did not emit the retried Initial");
        }
    }

    Setup {
        server_config,
        packet,
        now,
        addr,
    }
}

fn run(b: &mut Bencher, response: Response, token: Token) {
    let Setup {
        server_config,
        packet,
        now,
        addr,
    } = setup(token, false);
    let mut server = proto::Endpoint::new(Default::default(), Some(server_config), true);
    b.bytes = packet.len() as u64;
    b.iter(|| {
        let mut out = Vec::new();
        let Some(DatagramEvent::NewConnection(incoming)) =
            server.handle(now, addr, None, None, packet.as_slice().into(), &mut out)
        else {
            panic!("expected an Incoming");
        };
        assert_eq!(incoming.remote_address_validated(), token == Token::Retry);
        match response {
            Response::Retry => {
                let _ = server.retry(incoming, &mut out).unwrap();
                assert_eq!(out[0] & 0xf0, 0xf0, "expected a Retry packet");
            }
            Response::Ignore => {
                server.ignore(incoming);
                assert!(out.is_empty());
            }
            Response::Refuse => {
                let _ = server.refuse(incoming, &mut out);
                assert!(!out.is_empty());
            }
        }
        black_box(out);
    });
}

/// Initials that the endpoint turns down by itself, without involving the application
fn run_invalid(b: &mut Bencher, token: Token, short_dcid: bool) {
    let Setup {
        server_config,
        packet,
        now,
        mut addr,
    } = setup(token, short_dcid);
    if token == Token::Retry {
        // A Retry token is only valid for the address it was issued to
        addr.set_port(addr.port() + 1);
    }
    let mut server = proto::Endpoint::new(Default::default(), Some(server_config), true);
    b.bytes = packet.len() as u64;
    b.iter(|| {
        let mut out = Vec::new();
        let event = server.handle(now, addr, None, None, packet.as_slice().into(), &mut out);
        assert!(
            matches!(event, Some(DatagramEvent::Response(_))),
            "expected a close"
        );
        black_box(out);
    });
}
