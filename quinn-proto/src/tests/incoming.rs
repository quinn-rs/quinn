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

/// A Retry token that's invalid for the sender is answered only if the packet is an Initial
#[test]
fn invalid_retry_token_in_invalid_initial() {
    let _guard = subscribe();
    let now = Instant::now();
    let dst_cid = ConnectionId::new(&[1; 8]);
    let config = Arc::new(server_config());
    let payload = TokenPayload::Retry {
        address: "[::2]:4433".parse().unwrap(),
        orig_dst_cid: ConnectionId::new(&[3; 8]),
        issued: config.time_source.now(),
    };
    let token = Token::new(payload, &mut rand::rng()).encode(&*config.token_key);
    let mut endpoint = Endpoint::new(Default::default(), Some(config), true);

    let mut buf = Vec::new();
    let packet = initial_packet(dst_cid, &token);
    assert!(matches!(
        endpoint.handle(now, CLIENT, None, None, packet, &mut buf),
        Some(DatagramEvent::Response(_))
    ));

    let mut buf = Vec::new();
    let mut packet = initial_packet(dst_cid, &token);
    packet[0] ^= 0x04;
    assert!(
        endpoint
            .handle(now, CLIENT, None, None, packet, &mut buf)
            .is_none()
    );
    assert!(buf.is_empty());
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
