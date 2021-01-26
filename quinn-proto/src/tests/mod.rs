use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use assert_matches::assert_matches;
use bytes::Bytes;
use hex_literal::hex;
use rand::RngCore;
use ring::hmac;
use rustls::internal::msgs::enums::AlertDescription;
use tracing::info;

use super::*;
use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
use crate::crypto::Session as _;
mod util;
use util::*;

#[test]
fn version_negotiate_server() {
    let _guard = subscribe();
    let client_addr = "[::2]:7890".parse().unwrap();
    let mut server = Endpoint::new(Default::default(), Some(Arc::new(server_config())));
    let now = Instant::now();
    let event = server.handle(
        now,
        client_addr,
        None,
        None,
        // Long-header packet with reserved version number
        hex!("80 0a1a2a3a 04 00000000 04 00000000 00")[..].into(),
    );
    assert!(event.is_none());

    let io = server.poll_transmit();
    assert!(io.is_some());
    if let Some(Transmit { contents, .. }) = io {
        assert_ne!(contents[0] & 0x80, 0);
        assert_eq!(&contents[1..15], hex!("00000000 04 00000000 04 00000000"));
        assert!(contents[15..].chunks(4).any(is_supported_version));
    }
    assert_matches!(server.poll_transmit(), None);
}

#[test]
fn version_negotiate_client() {
    let _guard = subscribe();
    let server_addr = "[::2]:7890".parse().unwrap();
    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(RandomConnectionIdGenerator::new(0));
    let mut client = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..Default::default()
        }),
        None,
    );
    let (_, mut client_conn) = client
        .connect(client_config(), server_addr, "localhost")
        .unwrap();
    let now = Instant::now();
    let opt_event = client.handle(
        now,
        server_addr,
        None,
        None,
        // Version negotiation packet for reserved version
        hex!(
            "80 00000000 04 00000000 04 00000000
             0a1a2a3a"
        )[..]
            .into(),
    );
    if let Some((_, DatagramEvent::ConnectionEvent(event))) = opt_event {
        client_conn.handle_event(event);
    }
    assert_matches!(
        client_conn.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::VersionMismatch,
        })
    );
}

#[test]
fn lifecycle() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());

    const REASON: &[u8] = b"whee";
    info!("closing");
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        REASON.into(),
    );
    pair.drive();
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ApplicationClosed(
                        ApplicationClose { error_code: VarInt(42), ref reason }
                    )}) if reason == REASON);
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn stateless_retry() {
    let _guard = subscribe();
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
    let _guard = subscribe();
    let mut reset_key = vec![0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_key);
    let reset_key = hmac::Key::new(hmac::HMAC_SHA256, &reset_key);

    let endpoint_config = Arc::new(EndpointConfig::new(reset_key));

    let mut pair = Pair::new(endpoint_config.clone(), server_config());
    let (client_ch, _) = pair.connect();
    pair.server.endpoint = Endpoint::new(endpoint_config, Some(Arc::new(server_config())));
    // Send something big enough to allow room for a smaller stateless reset.
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        (&[0xab; 128][..]).into(),
    );
    info!("resetting");
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::Reset
        })
    );
}

#[test]
fn client_stateless_reset() {
    let _guard = subscribe();
    let mut reset_key = vec![0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_key);
    let reset_key = hmac::Key::new(hmac::HMAC_SHA256, &reset_key);

    let endpoint_config = Arc::new(EndpointConfig::new(reset_key));

    let mut pair = Pair::new(endpoint_config.clone(), server_config());
    let (_, server_ch) = pair.connect();
    pair.client.endpoint = Endpoint::new(endpoint_config, Some(Arc::new(server_config())));
    // Send something big enough to allow room for a smaller stateless reset.
    pair.server.connections.get_mut(&server_ch).unwrap().close(
        pair.time,
        VarInt(42),
        (&[0xab; 128][..]).into(),
    );
    info!("resetting");
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::Reset
        })
    );
}

#[test]
fn export_keying_material() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    const LABEL: &[u8] = b"test_label";
    const CONTEXT: &[u8] = b"test_context";

    // client keying material
    let mut client_buf = [0u8; 64];
    pair.client_conn_mut(client_ch)
        .crypto_session()
        .export_keying_material(&mut client_buf, LABEL, CONTEXT)
        .unwrap();

    // server keying material
    let mut server_buf = [0u8; 64];
    pair.server_conn_mut(server_ch)
        .crypto_session()
        .export_keying_material(&mut server_buf, LABEL, CONTEXT)
        .unwrap();

    assert_eq!(&client_buf[..], &server_buf[..]);
}

#[test]
fn finish_stream_simple() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    assert_eq!(pair.client_conn_mut(client_ch).send_streams(), 1);
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(pair.client_conn_mut(client_ch).send_streams(), 0);
    assert_eq!(pair.server_conn_mut(client_ch).send_streams(), 0);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    // Receive-only streams do not get `StreamFinished` events
    assert_eq!(pair.server_conn_mut(client_ch).send_streams(), 0);
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
}

#[test]
fn reset_stream() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();

    info!("resetting stream");
    const ERROR: VarInt = VarInt(42);
    pair.client_conn_mut(client_ch).reset(s, ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Err(ReadError::Reset(ERROR))
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
}

#[test]
fn stop_stream() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();

    info!("stopping stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_conn_mut(server_ch).stop(s, ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);

    assert_matches!(
        pair.client_conn_mut(client_ch).write(s, b"foo"),
        Err(WriteError::Stopped(ERROR))
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).finish(s),
        Err(FinishError::Stopped(ERROR))
    );
}

#[test]
fn reject_self_signed_server_cert() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    info!("connecting");
    let client_ch = pair.begin_connect(ClientConfig::default());
    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)})
                    if error.code == TransportErrorCode::crypto(AlertDescription::BadCertificate.get_u8()));
}

#[test]
fn reject_missing_client_cert() {
    let _guard = subscribe();
    let mut server_config = server_config();
    Arc::make_mut(&mut server_config.crypto).set_client_certificate_verifier(
        rustls::AllowAnyAuthenticatedClient::new(rustls::RootCertStore::empty()),
    );
    let mut pair = Pair::new(Default::default(), server_config);
    info!("connecting");
    let client_ch = pair.begin_connect(client_config());
    pair.drive();

    // The client completes the connection, but finds it immediately closed
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(ref close)})
                    if close.error_code == TransportErrorCode::crypto(AlertDescription::CertificateRequired.get_u8()));

    // The server never completes the connection
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref error)})
                    if error.code == TransportErrorCode::crypto(AlertDescription::CertificateRequired.get_u8()));
}

#[test]
fn congestion() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();

    const TARGET: u64 = 2048;
    assert!(pair.client_conn_mut(client_ch).congestion_state() > TARGET);
    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    // Send data without receiving ACKs until the congestion state falls below target
    while pair.client_conn_mut(client_ch).congestion_state() > TARGET {
        let n = pair
            .client_conn_mut(client_ch)
            .write(s, &[42; 1024])
            .unwrap();
        assert_eq!(n, 1024);
        pair.drive_client();
    }
    // Ensure that the congestion state recovers after receiving the ACKs
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).congestion_state() >= TARGET);
    pair.client_conn_mut(client_ch)
        .write(s, &[42; 1024])
        .unwrap();
}

#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
#[test]
fn high_latency_handshake() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.latency = Duration::from_micros(200 * 1000);
    let (client_ch, server_ch) = pair.connect();
    assert_eq!(pair.client_conn_mut(client_ch).bytes_in_flight(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).bytes_in_flight(), 0);
    assert!(pair.client_conn_mut(client_ch).using_ecn());
    assert!(pair.server_conn_mut(server_ch).using_ecn());
}

#[test]
fn zero_rtt_happypath() {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            use_stateless_retry: true,
            ..server_config()
        },
    );
    let config = client_config();

    // Establish normal connection
    let client_ch = pair.begin_connect(config.clone());
    pair.drive();
    pair.server.assert_accept();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();

    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    info!("resuming session");
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
}

#[test]
fn zero_rtt_rejection() {
    let _guard = subscribe();
    let mut server_config = server_config();
    Arc::get_mut(&mut server_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into(), "bar".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config);
    let mut client_config = client_config();
    Arc::get_mut(&mut client_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into()]);

    // Establish normal connection
    let client_ch = pair.begin_connect(client_config.clone());
    pair.drive();
    let server_conn = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.server_conn_mut(server_conn).poll(), None);
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::ConnectionLost { .. })
    );
    assert_matches!(pair.server_conn_mut(server_conn).poll(), None);
    pair.client.connections.clear();
    pair.server.connections.clear();

    // Changing protocols invalidates 0-RTT
    Arc::get_mut(&mut client_config.crypto)
        .unwrap()
        .set_protocols(&["bar".into()]);
    info!("resuming session");
    let client_ch = pair.begin_connect(client_config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_conn = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Connected)
    );
    assert_matches!(pair.server_conn_mut(server_conn).poll(), None);
    let s2 = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    assert_eq!(s, s2);
    assert_eq!(
        pair.server_conn_mut(server_conn)
            .read(s2, usize::MAX, false),
        Err(ReadError::Blocked)
    );
    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
}

#[test]
fn alpn_success() {
    let _guard = subscribe();
    let mut server_config = server_config();
    Arc::get_mut(&mut server_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into(), "bar".into(), "baz".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config);
    let mut client_config = client_config();
    Arc::get_mut(&mut client_config.crypto)
        .unwrap()
        .set_protocols(&["bar".into(), "quux".into(), "corge".into()]);

    // Establish normal connection
    let client_conn = pair.begin_connect(client_config);
    pair.drive();
    let server_conn = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Connected)
    );

    let hd = pair
        .client_conn_mut(client_conn)
        .crypto_session()
        .handshake_data()
        .unwrap();
    assert_eq!(hd.protocol.unwrap(), &b"bar"[..]);
}

#[test]
fn server_alpn_unset() {
    let _guard = subscribe();
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config());
    let mut client_config = client_config();
    Arc::get_mut(&mut client_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into()]);

    let client_conn = pair.begin_connect(client_config);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_conn).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::TransportError(ref err) }) if err.code == TransportErrorCode::crypto(0x78)
    );
}

#[test]
fn client_alpn_unset() {
    let _guard = subscribe();
    let mut server_config = server_config();
    Arc::get_mut(&mut server_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into(), "bar".into(), "baz".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config);

    let client_conn = pair.begin_connect(client_config());
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_conn).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) }) if err.error_code == TransportErrorCode::crypto(0x78)
    );
}

#[test]
fn alpn_mismatch() {
    let mut server_config = server_config();
    Arc::get_mut(&mut server_config.crypto)
        .unwrap()
        .set_protocols(&["foo".into(), "bar".into(), "baz".into()]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config);
    let mut client_config = client_config();
    Arc::get_mut(&mut client_config.crypto)
        .unwrap()
        .set_protocols(&["quux".into(), "corge".into()]);

    let client_conn = pair.begin_connect(client_config);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_conn).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) }) if err.error_code == TransportErrorCode::crypto(0x78)
    );
}

#[test]
fn stream_id_limit() {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_uni_streams: 1u32.into(),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();

    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .open(Dir::Uni)
        .expect("couldn't open first stream");
    assert_eq!(
        pair.client_conn_mut(client_ch).open(Dir::Uni),
        None,
        "only one stream is permitted at a time"
    );
    // Generate some activity to allow the server to see the stream
    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_eq!(
        pair.client_conn_mut(client_ch).open(Dir::Uni),
        None,
        "server does not immediately grant additional credit"
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).read(s, usize::MAX, false), Ok(Some((msg, 0))) if msg == MSG);
    assert_eq!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
    // Server will only send MAX_STREAM_ID now that the application's been notified
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Available { dir: Dir::Uni }))
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);

    // Try opening the second stream again, now that we've made room
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .open(Dir::Uni)
        .expect("didn't get stream id budget");
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive();
    // Make sure the server actually processes data on the newly-available stream
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
}

#[test]
fn key_update_simple() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .open(Dir::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"hello1";
    pair.client_conn_mut(client_ch).write(s, MSG1).unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Bi), Some(stream) if stream == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG1
    );

    info!("initiating key update");
    pair.client_conn_mut(client_ch).initiate_key_update();

    const MSG2: &[u8] = b"hello2";
    pair.client_conn_mut(client_ch).write(s, MSG2).unwrap();
    pair.drive();

    assert_matches!(pair.server_conn_mut(server_ch).poll(), Some(Event::Stream(StreamEvent::Readable { id })) if id == s);
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 6))) if data == MSG2
    );

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).lost_packets(), 0);
}

#[test]
fn key_update_reordered() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    let s = pair
        .client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .open(Dir::Bi)
        .expect("couldn't open first stream");

    const MSG1: &[u8] = b"1";
    pair.client_conn_mut(client_ch).write(s, MSG1).unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    assert!(!pair.client.outbound.is_empty());
    pair.client.delay_outbound();

    pair.client_conn_mut(client_ch).initiate_key_update();
    info!("updated keys");

    const MSG2: &[u8] = b"two";
    pair.client_conn_mut(client_ch).write(s, MSG2).unwrap();
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.finish_delay();
    pair.drive();

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Bi), Some(stream) if stream == s);

    let buf1 = pair
        .server_conn_mut(server_ch)
        .read(s, usize::MAX, true)
        .unwrap()
        .unwrap();
    assert_matches!(&*buf1.0, MSG1);
    let buf2 = pair
        .server_conn_mut(server_ch)
        .read(s, usize::MAX, true)
        .unwrap()
        .unwrap();
    assert_eq!(buf2.0, MSG2);

    assert_eq!(pair.client_conn_mut(client_ch).lost_packets(), 0);
    assert_eq!(pair.server_conn_mut(server_ch).lost_packets(), 0);
}

#[test]
fn initial_retransmit() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config());
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.outbound.clear(); // Drop initial
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[test]
fn instant_close_1() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    info!("connecting");
    let client_ch = pair.begin_connect(client_config());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), Bytes::new());
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason:
                ConnectionError::ConnectionClosed(ConnectionClose {
                    error_code: TransportErrorCode::APPLICATION_ERROR,
                    ..
                }),
        })
    );
}

#[test]
fn instant_close_2() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    info!("connecting");
    let client_ch = pair.begin_connect(client_config());
    // Unlike `instant_close`, the server sees a valid Initial packet first.
    pair.drive_client();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason:
                ConnectionError::ConnectionClosed(ConnectionClose {
                    error_code: TransportErrorCode::APPLICATION_ERROR,
                    ..
                }),
        })
    );
}

#[test]
fn idle_timeout() {
    let _guard = subscribe();
    const IDLE_TIMEOUT: Duration = Duration::from_millis(10);
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_idle_timeout: Some(IDLE_TIMEOUT),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    pair.client_conn_mut(client_ch).ping();
    let start = pair.time;

    while !pair.client_conn_mut(client_ch).is_closed()
        || !pair.server_conn_mut(server_ch).is_closed()
    {
        if !pair.step() {
            if let Some(t) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = t;
            }
        }
        pair.client.inbound.clear(); // Simulate total S->C packet loss
    }

    assert!(pair.time - start < 2 * IDLE_TIMEOUT);
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );
}

#[test]
fn concurrent_connections_full() {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            concurrent_connections: 0,
            ..server_config()
        },
    );
    let client_ch = pair.begin_connect(client_config());
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason:
                ConnectionError::ConnectionClosed(frame::ConnectionClose {
                    error_code: TransportErrorCode::CONNECTION_REFUSED,
                    ..
                }),
        })
    );
    assert_eq!(pair.server.connections.len(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn server_hs_retransmit() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config());
    pair.step();
    assert!(!pair.client.inbound.is_empty()); // Initial + Handshakes
    pair.client.inbound.clear();
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[test]
fn migration() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    pair.client.addr = SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 1).into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    pair.client_conn_mut(client_ch).ping();
    pair.drive();
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_eq!(
        pair.server_conn_mut(server_ch).remote_address(),
        pair.client.addr
    );
}

fn test_flow_control(config: TransportConfig, window_size: usize) {
    let _guard = subscribe();
    let mut pair = Pair::new(
        Default::default(),
        ServerConfig {
            transport: Arc::new(config),
            ..server_config()
        },
    );
    let (client_conn, server_conn) = pair.connect();
    let msg = vec![0xAB; window_size + 10];

    // Stream reset before read
    let s = pair.client_conn_mut(client_conn).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.client_conn_mut(client_conn).write(s, &msg),
        Ok(window_size)
    );
    assert_eq!(
        pair.client_conn_mut(client_conn)
            .write(s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );
    pair.drive();
    pair.client_conn_mut(client_conn)
        .reset(s, VarInt(42))
        .unwrap();
    pair.drive();
    assert_eq!(
        pair.server_conn_mut(server_conn).read(s, usize::MAX, true),
        Err(ReadError::Reset(VarInt(42)))
    );

    // Happy path
    let s = pair.client_conn_mut(client_conn).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.client_conn_mut(client_conn).write(s, &msg),
        Ok(window_size)
    );
    assert_eq!(
        pair.client_conn_mut(client_conn)
            .write(s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );

    pair.drive();
    let mut cursor = 0;
    loop {
        match pair.server_conn_mut(server_conn).read(s, usize::MAX, true) {
            Ok(Some((buf, _))) => {
                cursor += buf.len();
            }
            Ok(None) => {
                panic!("end of stream");
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
    assert_eq!(
        pair.client_conn_mut(client_conn).write(s, &msg),
        Ok(window_size)
    );
    assert_eq!(
        pair.client_conn_mut(client_conn)
            .write(s, &msg[window_size..]),
        Err(WriteError::Blocked)
    );

    pair.drive();
    let mut cursor = 0;
    loop {
        match pair.server_conn_mut(server_conn).read(s, usize::MAX, true) {
            Ok(Some((buf, _))) => {
                cursor += buf.len();
            }
            Ok(None) => {
                panic!("end of stream");
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
            stream_receive_window: 2000u32.into(),
            ..TransportConfig::default()
        },
        2000,
    );
}

#[test]
fn conn_flow_control() {
    test_flow_control(
        TransportConfig {
            receive_window: 2000u32.into(),
            ..TransportConfig::default()
        },
        2000,
    );
}

#[test]
fn stop_opens_bidi() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();
    assert_eq!(pair.client_conn_mut(client_conn).send_streams(), 0);
    let s = pair.client_conn_mut(client_conn).open(Dir::Bi).unwrap();
    assert_eq!(pair.client_conn_mut(client_conn).send_streams(), 1);
    const ERROR: VarInt = VarInt(42);
    pair.client
        .connections
        .get_mut(&server_conn)
        .unwrap()
        .stop(s, ERROR)
        .unwrap();
    pair.drive();

    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi }))
    );
    assert_eq!(pair.server_conn_mut(client_conn).send_streams(), 0);
    assert_matches!(pair.server_conn_mut(server_conn).accept(Dir::Bi), Some(stream) if stream == s);
    assert_eq!(pair.server_conn_mut(client_conn).send_streams(), 1);
    assert_matches!(
        pair.server_conn_mut(server_conn).read(s, usize::MAX, false),
        Err(ReadError::Blocked)
    );
    assert_matches!(
        pair.server_conn_mut(server_conn).write(s, b"foo"),
        Err(WriteError::Stopped(ERROR))
    );
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Stream(StreamEvent::Stopped {
            id: _,
            error_code: ERROR
        }))
    );
    assert_matches!(pair.server_conn_mut(server_conn).poll(), None);
}

#[test]
fn implicit_open() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_conn, server_conn) = pair.connect();
    let s1 = pair.client_conn_mut(client_conn).open(Dir::Uni).unwrap();
    let s2 = pair.client_conn_mut(client_conn).open(Dir::Uni).unwrap();
    pair.client_conn_mut(client_conn)
        .write(s2, b"hello")
        .unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_conn).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_eq!(pair.server_conn_mut(server_conn).accept(Dir::Uni), Some(s1));
    assert_eq!(pair.server_conn_mut(server_conn).accept(Dir::Uni), Some(s2));
    assert_eq!(pair.server_conn_mut(server_conn).accept(Dir::Uni), None);
}

#[test]
fn zero_length_cid() {
    let _guard = subscribe();
    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(RandomConnectionIdGenerator::new(0));
    let mut pair = Pair::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..EndpointConfig::default()
        }),
        server_config(),
    );
    let (client_ch, server_ch) = pair.connect();
    // Ensure we can reconnect after a previous connection is cleaned up
    info!("closing");
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    pair.server
        .connections
        .get_mut(&server_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.connect();
}

#[test]
fn keep_alive() {
    let _guard = subscribe();
    const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            keep_alive_interval: Some(IDLE_TIMEOUT / 2),
            max_idle_timeout: Some(IDLE_TIMEOUT),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    // Run a good while longer than the idle timeout
    let end = pair.time + 20 * IDLE_TIMEOUT;
    while pair.time < end {
        if !pair.step() {
            if let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                pair.time = time;
            }
        }
        assert!(!pair.client_conn_mut(client_ch).is_closed());
        assert!(!pair.server_conn_mut(server_ch).is_closed());
    }
}

#[test]
fn cid_rotation() {
    let _guard = subscribe();
    const CID_TIMEOUT: Duration = Duration::from_secs(2);

    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(*RandomConnectionIdGenerator::new(8).set_lifetime(CID_TIMEOUT));

    // Only test cid rotation on server side to have a clear output trace
    let server = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..EndpointConfig::default()
        }),
        Some(Arc::new(server_config())),
    );
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None);

    let mut pair = Pair::new_from_endpoint(client, server);
    let (_, server_ch) = pair.connect();

    let mut round: u64 = 1;
    let mut stop = pair.time;
    let end = pair.time + 5 * CID_TIMEOUT;

    use crate::cid_queue::CidQueue;
    use crate::LOC_CID_COUNT;
    let mut active_cid_num = CidQueue::LEN as u64 + 1;
    active_cid_num = active_cid_num.min(LOC_CID_COUNT);
    let mut left_bound = 0;
    let mut right_bound = active_cid_num - 1;

    while pair.time < end {
        stop += CID_TIMEOUT;
        // Run a while until PushNewCID timer fires
        while pair.time < stop {
            if !pair.step() {
                if let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                    pair.time = time;
                }
            }
        }
        info!(
            "Checking active cid sequence range before {:?} seconds",
            round * CID_TIMEOUT.as_secs()
        );
        let _bound = (left_bound, right_bound);
        assert_matches!(
            pair.server_conn_mut(server_ch).active_local_cid_seq(),
            _bound
        );
        round += 1;
        left_bound += active_cid_num;
        right_bound += active_cid_num;
        pair.drive_server();
    }
}

#[test]
fn cid_retirement() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    // Server retires current active remote CIDs
    pair.server_conn_mut(server_ch)
        .rotate_local_cid(1, Instant::now());
    pair.drive();
    // Any unexpected behavior may trigger TransportError::CONNECTION_ID_LIMIT_ERROR
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert_matches!(pair.client_conn_mut(client_ch).active_rem_cid_seq(), 1);

    use crate::cid_queue::CidQueue;
    use crate::LOC_CID_COUNT;
    let mut active_cid_num = CidQueue::LEN as u64;
    active_cid_num = active_cid_num.min(LOC_CID_COUNT);

    let next_retire_prior_to = active_cid_num + 1;
    pair.client_conn_mut(client_ch).ping();
    // Server retires all valid remote CIDs
    pair.server_conn_mut(server_ch)
        .rotate_local_cid(next_retire_prior_to, Instant::now());
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    assert_matches!(
        pair.client_conn_mut(client_ch).active_rem_cid_seq(),
        _next_retire_prior_to
    );
}

#[test]
fn finish_stream_flow_control_reordered() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive_client(); // Send stream data
    pair.server.drive(pair.time, pair.client.addr); // Receive

    // Issue flow control credit
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
    pair.server.drive(pair.time, pair.client.addr);
    pair.server.delay_outbound(); // Delay it

    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive_client(); // Send FIN
    pair.server.drive(pair.time, pair.client.addr); // Acknowledge
    pair.server.finish_delay(); // Add flow control packets after
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
}

#[test]
fn handshake_1rtt_handling() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let server_ch = pair.server.assert_accept();
    // Server now has 1-RTT keys, but remains in Handshake state until the TLS CFIN has
    // authenticated the client. Delay the final client handshake flight so that doesn't happen yet.
    pair.client.drive(pair.time, pair.server.addr);
    pair.client.delay_outbound();

    // Send some 1-RTT data which will be received first.
    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.client.drive(pair.time, pair.server.addr);

    // Add the handshake flight back on.
    pair.client.finish_delay();

    pair.drive();

    assert!(pair.client_conn_mut(client_ch).lost_packets() != 0);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
}

#[test]
fn stop_before_finish() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();

    info!("stopping stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_conn_mut(server_ch).stop(s, ERROR).unwrap();
    pair.drive();

    assert_matches!(
        pair.client_conn_mut(client_ch).finish(s),
        Err(FinishError::Stopped(ERROR))
    );
}

#[test]
fn stop_during_finish() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive();

    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    info!("stopping and finishing stream");
    const ERROR: VarInt = VarInt(42);
    pair.server_conn_mut(server_ch).stop(s, ERROR).unwrap();
    pair.drive_server();
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive_client();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Stopped { id, error_code: ERROR })) if id == s
    );
}

// Ensure we can recover from loss of tail packets when the congestion window is full
#[test]
fn congested_tail_loss() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, _) = pair.connect();

    const TARGET: u64 = 2048;
    assert!(pair.client_conn_mut(client_ch).congestion_state() > TARGET);
    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();
    // Send data without receiving ACKs until the congestion state falls below target
    while pair.client_conn_mut(client_ch).congestion_state() > TARGET {
        let n = pair
            .client_conn_mut(client_ch)
            .write(s, &[42; 1024])
            .unwrap();
        assert_eq!(n, 1024);
        pair.drive_client();
    }
    assert!(!pair.server.inbound.is_empty());
    pair.server.inbound.clear();
    // Ensure that the congestion state recovers after retransmits occur and are ACKed
    info!("recovering");
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).congestion_state() > TARGET);
    pair.client_conn_mut(client_ch)
        .write(s, &[42; 1024])
        .unwrap();
}

#[test]
fn datagram_send_recv() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(pair.client_conn_mut(client_ch).max_datagram_size(), Some(x) if x > 0);

    const DATA: &[u8] = b"whee";
    pair.client_conn_mut(client_ch)
        .send_datagram(DATA.into())
        .unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::DatagramReceived)
    );
    assert_eq!(
        pair.server_conn_mut(server_ch).recv_datagram().unwrap(),
        DATA
    );
    assert_matches!(pair.server_conn_mut(server_ch).recv_datagram(), None);
}

#[test]
fn datagram_recv_buffer_overflow() {
    let _guard = subscribe();
    const WINDOW: usize = 100;
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            datagram_receive_buffer_size: Some(WINDOW),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(
        pair.client_conn_mut(client_ch).max_datagram_size(),
        Some(WINDOW)
    );

    const DATA1: &[u8] = &[0xAB; (WINDOW / 3) + 1];
    const DATA2: &[u8] = &[0xBC; (WINDOW / 3) + 1];
    const DATA3: &[u8] = &[0xCD; (WINDOW / 3) + 1];
    pair.client_conn_mut(client_ch)
        .send_datagram(DATA1.into())
        .unwrap();
    pair.client_conn_mut(client_ch)
        .send_datagram(DATA2.into())
        .unwrap();
    pair.client_conn_mut(client_ch)
        .send_datagram(DATA3.into())
        .unwrap();
    pair.drive();
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::DatagramReceived)
    );
    assert_eq!(
        pair.server_conn_mut(server_ch).recv_datagram().unwrap(),
        DATA2
    );
    assert_eq!(
        pair.server_conn_mut(server_ch).recv_datagram().unwrap(),
        DATA3
    );
    assert_matches!(pair.server_conn_mut(server_ch).recv_datagram(), None);

    pair.client_conn_mut(client_ch)
        .send_datagram(DATA1.into())
        .unwrap();
    pair.drive();
    assert_eq!(
        pair.server_conn_mut(server_ch).recv_datagram().unwrap(),
        DATA1
    );
    assert_matches!(pair.server_conn_mut(server_ch).recv_datagram(), None);
}

#[test]
fn datagram_unsupported() {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            datagram_receive_buffer_size: None,
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);
    assert_matches!(pair.client_conn_mut(client_ch).max_datagram_size(), None);

    match pair.client_conn_mut(client_ch).send_datagram(Bytes::new()) {
        Err(SendDatagramError::UnsupportedByPeer) => {}
        Err(e) => panic!("unexpected error: {}", e),
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn large_initial() {
    let _guard = subscribe();
    let mut server_config = server_config();
    Arc::get_mut(&mut server_config.crypto)
        .unwrap()
        .set_protocols(&[vec![0, 0, 0, 42]]);
    let mut pair = Pair::new(Arc::new(EndpointConfig::default()), server_config);
    let mut cfg = client_config();
    let protocols = (0..1000u32)
        .map(|x| x.to_be_bytes().to_vec())
        .collect::<Vec<_>>();
    Arc::get_mut(&mut cfg.crypto)
        .unwrap()
        .set_protocols(&protocols);
    let client_ch = pair.begin_connect(cfg);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected { .. })
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Connected { .. })
    );
}

#[test]
/// Ensure that we don't yield a finish event before the actual FIN is acked so the peer isn't left
/// hanging
fn finish_acked() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    info!("client sends data to server");
    pair.drive_client(); // send data to server
    info!("server acknowledges data");
    pair.drive_server(); // process data and send data ack

    // Receive data
    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.server_conn_mut(server_ch).poll(), None);

    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Err(ReadError::Blocked)
    );

    // Finish before receiving data ack
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    // Send FIN, receive data ack
    info!("client receives ACK, sends FIN");
    pair.drive_client();
    // Check for premature finish from data ack
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    // Process FIN ack
    info!("server ACKs FIN");
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
}

#[test]
/// Ensure that we don't yield a finish event while there's still unacknowledged data
fn finish_retransmit() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect();

    let s = pair.client_conn_mut(client_ch).open(Dir::Uni).unwrap();

    const MSG: &[u8] = b"hello";
    pair.client_conn_mut(client_ch).write(s, MSG).unwrap();
    pair.drive_client(); // send data to server
    pair.server.inbound.clear(); // Lose it

    // Send FIN
    pair.client_conn_mut(client_ch).finish(s).unwrap();
    pair.drive_client();
    // Process FIN
    pair.drive_server();
    // Receive FIN ack, but no data ack
    pair.drive_client();
    // Check for premature finish from FIN ack
    assert_matches!(pair.client_conn_mut(client_ch).poll(), None);
    // Recover
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Stream(StreamEvent::Finished { id })) if id == s
    );

    assert_matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );

    assert_matches!(pair.server_conn_mut(server_ch).accept(Dir::Uni), Some(stream) if stream == s);
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(Some((ref data, 0))) if data == MSG
    );
    assert_matches!(
        pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
        Ok(None)
    );
}

/// Ensures that exchanging data on a client-initiated bidirectional stream works past the initial
/// stream window.
#[test]
fn repeated_request_response() {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_bidi_streams: 1u32.into(),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    const REQUEST: &[u8] = b"hello";
    const RESPONSE: &[u8] = b"world";
    for _ in 0..3 {
        let s = pair.client_conn_mut(client_ch).open(Dir::Bi).unwrap();

        pair.client_conn_mut(client_ch).write(s, REQUEST).unwrap();
        pair.client_conn_mut(client_ch).finish(s).unwrap();

        pair.drive();

        assert_eq!(pair.server_conn_mut(server_ch).accept(Dir::Bi), Some(s));
        assert_matches!(
            pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
            Ok(Some((ref data, 0))) if data == REQUEST
        );
        assert_matches!(
            pair.server_conn_mut(server_ch).read(s, usize::MAX, false),
            Ok(None)
        );
        pair.server_conn_mut(server_ch).write(s, RESPONSE).unwrap();
        pair.server_conn_mut(server_ch).finish(s).unwrap();

        pair.drive();

        assert_matches!(
            pair.client_conn_mut(client_ch).read(s, usize::MAX, false),
            Ok(Some((ref data, 0))) if data == RESPONSE
        );
        assert_matches!(
            pair.client_conn_mut(client_ch).read(s, usize::MAX, false),
            Ok(None)
        );
    }
}

#[test]
fn read_chunks() {
    let _guard = subscribe();
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_bidi_streams: 3u32.into(),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(Default::default(), server);
    let (client_ch, server_ch) = pair.connect();
    let mut empty = vec![];
    let mut chunks = vec![Bytes::new(), Bytes::new()];
    const ONE: &[u8] = b"ONE";
    const TWO: &[u8] = b"TWO";
    const THREE: &[u8] = b"THREE";
    for _ in 0..3 {
        let s = pair.client_conn_mut(client_ch).open(Dir::Bi).unwrap();

        pair.client_conn_mut(client_ch).write(s, ONE).unwrap();
        pair.drive();
        pair.client_conn_mut(client_ch).write(s, TWO).unwrap();
        pair.drive();
        pair.client_conn_mut(client_ch).write(s, THREE).unwrap();

        pair.drive();

        assert_eq!(pair.server_conn_mut(server_ch).accept(Dir::Bi), Some(s));

        // Read into an empty slice can't do much you, but doesn't crash
        assert_eq!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut empty),
            Ok(Some(0))
        );

        // Read until `chunks` is filled
        assert_eq!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut chunks),
            Ok(Some(2))
        );
        assert_eq!(&chunks, &[ONE, TWO]);

        // Read the rest
        assert_eq!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut chunks),
            Ok(Some(1))
        );
        assert_eq!(&chunks[..1], &[THREE]);

        // We've read everything, stream is now blocked
        assert_eq!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut chunks),
            Err(ReadError::Blocked)
        );

        // Read a new chunk after we've been blocked
        pair.client_conn_mut(client_ch).write(s, ONE).unwrap();
        pair.drive();
        assert_eq!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut chunks),
            Ok(Some(1))
        );
        assert_eq!(&chunks[..1], &[ONE]);

        // Stream finishes by yeilding `Ok(None)`
        pair.client_conn_mut(client_ch).finish(s).unwrap();
        pair.drive();
        assert_matches!(
            pair.server_conn_mut(server_ch).read_chunks(s, &mut chunks),
            Ok(None)
        );

        pair.drive();
    }
}
