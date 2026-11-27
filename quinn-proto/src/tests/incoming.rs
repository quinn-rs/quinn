//! Tests for connection attempts that haven't been accepted yet

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::{
    crypto::{Keys, UnsupportedVersion},
    packet::{Header, InitialHeader, PacketNumber},
    token::{Token, TokenPayload},
};

#[test]
fn retry_and_ignore_derive_no_initial_keys() {
    let _guard = subscribe();
    let now = Instant::now();
    let mut config = server_config();
    let derivations = count_initial_keys(&mut config);
    let mut endpoint = Endpoint::new(Default::default(), Some(Arc::new(config)), true);
    let dst_cid = ConnectionId::new(&[1; 8]);

    for token in [&[][..], &[7; 80]] {
        let mut buf = Vec::new();
        let incoming = new_incoming(&mut endpoint, now, initial_packet(dst_cid, token));
        assert!(!incoming.remote_address_validated());
        let _ = endpoint.retry(incoming, &mut buf).unwrap();
        assert!(!buf.is_empty());

        let incoming = new_incoming(&mut endpoint, now, initial_packet(dst_cid, token));
        endpoint.ignore(incoming);
    }

    assert_eq!(derivations.load(Ordering::Relaxed), 0);
}

#[test]
fn accept_derives_initial_keys_once() {
    let _guard = subscribe();
    let mut config = server_config();
    let derivations = count_initial_keys(&mut config);
    let mut pair = Pair::new(Default::default(), config);
    pair.connect();
    assert_eq!(derivations.load(Ordering::Relaxed), 1);
}

/// An `Incoming` exists before its first packet is known to be a valid Initial
#[test]
fn accept_of_invalid_initial_fails_silently() {
    let _guard = subscribe();
    let now = Instant::now();
    let dst_cid = ConnectionId::new(&[1; 8]);
    let mut config = server_config();
    config.max_incoming(1);
    let config = Arc::new(config);

    let corruptions: [fn(&mut BytesMut); 2] = [
        // Reserved bits, which are under header protection
        |packet| packet[0] ^= 0x04,
        // Payload
        |packet| *packet.last_mut().unwrap() ^= 1,
    ];
    for corrupt in corruptions {
        let mut endpoint = Endpoint::new(Default::default(), Some(config.clone()), true);
        let mut buf = Vec::new();
        let mut packet = initial_packet(dst_cid, &[]);
        corrupt(&mut packet);
        let incoming = new_incoming(&mut endpoint, now, packet);

        // The attempt occupies the only slot until the application deals with it
        let other = initial_packet(ConnectionId::new(&[2; 8]), &[]);
        assert!(
            endpoint
                .handle(now, CLIENT, None, None, other, &mut buf)
                .is_none()
        );

        let error = endpoint.accept(incoming, now, &mut buf, None).unwrap_err();
        assert_matches!(error.cause, ConnectionError::TransportError(_));
        assert!(error.response.is_none());
        assert!(buf.is_empty());
        assert_eq!(endpoint.known_connections(), 0);
        assert_eq!(endpoint.known_cids(), 0);

        let incoming = new_incoming(&mut endpoint, now, initial_packet(dst_cid, &[]));
        endpoint.ignore(incoming);
    }
}

#[test]
fn decrypt_ahead_of_accept() {
    let _guard = subscribe();
    let now = Instant::now();
    let config = Arc::new(server_config());

    let mut client = Endpoint::new(Default::default(), None, true);
    let (_, mut conn) = client
        .connect(now, client_config(), CLIENT, "localhost")
        .unwrap();
    let mut packet = Vec::new();
    let _ = conn.poll_transmit(now, 1, &mut packet).unwrap();
    let mut endpoint = Endpoint::new(Default::default(), Some(config.clone()), true);
    let mut incoming = new_incoming(&mut endpoint, now, packet.as_slice().into());
    assert!(incoming.decrypt());
    assert!(incoming.decrypt());
    let mut buf = Vec::new();
    assert!(endpoint.accept(incoming, now, &mut buf, None).is_ok());
    assert_eq!(endpoint.known_connections(), 1);

    let mut endpoint = Endpoint::new(Default::default(), Some(config), true);
    let mut packet = initial_packet(ConnectionId::new(&[1; 8]), &[]);
    *packet.last_mut().unwrap() ^= 1;
    let mut incoming = new_incoming(&mut endpoint, now, packet);
    assert!(!incoming.decrypt());
    assert!(!incoming.decrypt());
    let mut buf = Vec::new();
    let error = endpoint.accept(incoming, now, &mut buf, None).unwrap_err();
    assert!(error.response.is_none());
    assert_eq!(endpoint.known_connections(), 0);
}

/// Refusing doesn't need the first packet to be valid, only its header to be readable
#[test]
fn refuse_of_invalid_initial() {
    let _guard = subscribe();
    let now = Instant::now();
    let dst_cid = ConnectionId::new(&[1; 8]);
    let mut endpoint = Endpoint::new(Default::default(), Some(Arc::new(server_config())), true);
    let mut packet = initial_packet(dst_cid, &[]);
    *packet.last_mut().unwrap() ^= 1;
    let incoming = new_incoming(&mut endpoint, now, packet);

    let mut buf = Vec::new();
    let transmit = endpoint.refuse(incoming, &mut buf);
    assert_eq!(transmit.size, buf.len());
    assert!(!buf.is_empty());
    assert_eq!(endpoint.known_connections(), 0);
}

/// Initials that the endpoint turns down by itself cost it no Initial keys and get no response
#[test]
fn invalid_initials_are_ignored() {
    let _guard = subscribe();
    let now = Instant::now();
    let mut config = server_config();
    let derivations = count_initial_keys(&mut config);
    let config = Arc::new(config);
    let mut endpoint = Endpoint::new(Default::default(), Some(config.clone()), true);

    // A Retry token issued to another address
    let payload = TokenPayload::Retry {
        address: "[::2]:4433".parse().unwrap(),
        orig_dst_cid: ConnectionId::new(&[3; 8]),
        issued: config.time_source.now(),
    };
    let token = Token::new(payload, &mut rand::rng()).encode(&*config.token_key);
    let invalid_token = initial_packet(ConnectionId::new(&[1; 8]), &token);
    // A destination CID shorter than a client may choose
    let short_dst_cid = initial_packet(ConnectionId::new(&[1; 7]), &[]);

    for packet in [invalid_token, short_dst_cid] {
        let mut buf = Vec::new();
        assert!(
            endpoint
                .handle(now, CLIENT, None, None, packet, &mut buf)
                .is_none()
        );
        assert!(buf.is_empty());
    }
    assert_eq!(endpoint.open_connections(), 0);
    assert_eq!(derivations.load(Ordering::Relaxed), 0);
}

const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433);

/// Feed `packet` to `endpoint`, expecting it to start a connection attempt
fn new_incoming(endpoint: &mut Endpoint, now: Instant, packet: BytesMut) -> Incoming {
    let mut buf = Vec::new();
    match endpoint.handle(now, CLIENT, None, None, packet, &mut buf) {
        Some(DatagramEvent::NewConnection(incoming)) => incoming,
        _ => panic!("expected a connection attempt"),
    }
}

/// Encode a protected, padded client Initial carrying no frames other than padding
fn initial_packet(dst_cid: ConnectionId, token: &[u8]) -> BytesMut {
    let mut buf = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid,
        src_cid: ConnectionId::new(&[2; 8]),
        token: Bytes::copy_from_slice(token),
        number: PacketNumber::U8(0),
        version: 1,
    })
    .encode(&mut buf);
    buf.resize(MIN_INITIAL_SIZE.into(), 0);
    let keys = crypto::ServerConfig::initial_keys(&server_crypto(), 1, dst_cid).unwrap();
    encode.finish(
        &mut buf,
        &*keys.header.remote,
        Some((0, &*keys.packet.remote)),
    );
    buf.as_slice().into()
}

/// Make `config` count how often Initial keys are derived for a connection attempt
fn count_initial_keys(config: &mut ServerConfig) -> Arc<AtomicUsize> {
    let derivations = Arc::new(AtomicUsize::new(0));
    config.crypto = Arc::new(CountingCrypto {
        inner: config.crypto.clone(),
        derivations: derivations.clone(),
    });
    derivations
}

struct CountingCrypto {
    inner: Arc<dyn crypto::ServerConfig>,
    derivations: Arc<AtomicUsize>,
}

impl crypto::ServerConfig for CountingCrypto {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        self.derivations.fetch_add(1, Ordering::Relaxed);
        self.inner.initial_keys(version, dst_cid)
    }

    fn supports_version(&self, version: u32) -> bool {
        self.inner.supports_version(version)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        self.inner.clone().start_session(version, params)
    }
}
