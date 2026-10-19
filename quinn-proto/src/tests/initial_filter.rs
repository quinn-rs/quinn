//! Admission ordering and fast Retry regressions
use super::*;
use crate::{
    crypto::{HandshakeTokenKey, Keys, UnsupportedVersion},
    token::{Token, TokenPayload},
};
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::hkdf;
#[cfg(feature = "ring")]
use ring::hkdf;
use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// `InitialFilter` with a switchable admission gate and a fixed verdict, recording what it saw
struct Policy {
    allow: AtomicBool,
    verdict: InitialDecision,
    seen: Mutex<Vec<(InitialMetadata, TokenCheck)>>,
    gate_calls: AtomicUsize,
}

impl Policy {
    fn new(verdict: InitialDecision) -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
            verdict,
            seen: Mutex::new(Vec::new()),
            gate_calls: AtomicUsize::new(0),
        })
    }

    fn seen(&self) -> Vec<(InitialMetadata, TokenCheck)> {
        self.seen.lock().expect("policy mutex poisoned").clone()
    }
}

impl InitialFilter for Policy {
    fn before_token_check(&self, meta: &InitialMetadata) -> bool {
        assert!(
            meta.datagram_len() >= usize::from(MIN_INITIAL_SIZE),
            "short datagrams must be dropped before the admission gate"
        );
        self.gate_calls.fetch_add(1, Ordering::Relaxed);
        self.allow.load(Ordering::Relaxed)
    }

    fn after_token_check(&self, initial: &InitialMetadata, token: &TokenCheck) -> InitialDecision {
        self.seen
            .lock()
            .expect("policy mutex poisoned")
            .push((*initial, *token));
        self.verdict
    }
}

/// Number of expensive operations performed by the server
#[derive(Default)]
struct Counts {
    initial_keys: AtomicUsize,
    token_aeads: AtomicUsize,
    token_log: AtomicUsize,
}

impl Counts {
    /// `[initial_keys, token_aeads, token_log]`
    fn values(&self) -> [usize; 3] {
        [&self.initial_keys, &self.token_aeads, &self.token_log].map(|v| v.load(Ordering::Relaxed))
    }
}

/// Crypto provider counting Initial-key derivations
///
/// Uses the default `supports_version`, as a custom provider would.
struct SpyCrypto {
    inner: Arc<dyn crypto::ServerConfig>,
    counts: Arc<Counts>,
}

impl crypto::ServerConfig for SpyCrypto {
    fn initial_keys(&self, version: u32, cid: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.counts.initial_keys.fetch_add(1, Ordering::Relaxed);
        self.inner.initial_keys(version, cid)
    }

    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        self.inner.clone().start_session(version, params)
    }
}

/// Fixed token key, so tokens issued before instrumentation stay valid
fn token_key() -> hkdf::Prk {
    hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&[42; 32])
}

/// `server_config()` using [`token_key`]
fn keyed_server_config() -> ServerConfig {
    let mut config = server_config();
    config.token_key(Arc::new(token_key()));
    config
}

/// Token key counting expensive operations
struct SpyToken {
    inner: hkdf::Prk,
    counts: Arc<Counts>,
}

impl HandshakeTokenKey for SpyToken {
    fn aead_from_hkdf(&self, random: &[u8]) -> Box<dyn crypto::AeadKey> {
        self.counts.token_aeads.fetch_add(1, Ordering::Relaxed);
        self.inner.aead_from_hkdf(random)
    }
}

/// Replay log counting checks and rejecting reused nonces
struct SpyLog {
    counts: Arc<Counts>,
    nonces: Mutex<HashSet<u128>>,
}

impl TokenLog for SpyLog {
    fn check_and_insert(
        &self,
        nonce: u128,
        _: SystemTime,
        _: Duration,
    ) -> Result<(), TokenReuseError> {
        self.counts.token_log.fetch_add(1, Ordering::Relaxed);
        match self.nonces.lock().unwrap().insert(nonce) {
            true => Ok(()),
            false => Err(TokenReuseError),
        }
    }
}

/// Count expensive operations of a [`keyed_server_config`]
fn instrument(config: &mut ServerConfig) -> Arc<Counts> {
    let counts = Arc::new(Counts::default());
    config.crypto = Arc::new(SpyCrypto {
        inner: config.crypto.clone(),
        counts: counts.clone(),
    });
    config.token_key(Arc::new(SpyToken {
        inner: token_key(),
        counts: counts.clone(),
    }));
    config.validation_token.log = Arc::new(SpyLog {
        counts: counts.clone(),
        nonces: Mutex::default(),
    });
    counts
}

/// Encode a protected, padded client Initial with the given DCID and token
fn initial_packet(config: &ServerConfig, dst_cid: ConnectionId, token: &[u8]) -> BytesMut {
    let mut buf = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid,
        src_cid: ConnectionId::new(&[2; 8]),
        token: token.to_vec().into(),
        number: PacketNumber::U8(0),
        version: 1,
    })
    .encode(&mut buf);
    buf.resize(MIN_INITIAL_SIZE.into(), 0);
    let keys = config
        .crypto
        .initial_keys(1, dst_cid)
        .expect("QUIC v1 is supported");
    encode.finish(
        &mut buf,
        &*keys.header.remote,
        Some((0, &*keys.packet.remote)),
    );
    buf.as_slice().into()
}

fn server_endpoint(config: ServerConfig) -> Endpoint {
    Endpoint::new(Default::default(), Some(Arc::new(config)), true)
}

fn is_retry(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|byte| byte & 0xf0 == 0xf0)
}

/// A NEW_TOKEN for `addr`
fn validation_token(config: &ServerConfig, addr: SocketAddr) -> Vec<u8> {
    let payload = TokenPayload::Validation {
        ip: addr.ip(),
        issued: config.time_source.now(),
    };
    Token::new(payload, &mut rand::rng()).encode(&*config.token_key)
}

/// A Retry token for `addr`, issued at `issued`
fn retry_token(config: &ServerConfig, addr: SocketAddr, issued: SystemTime) -> Vec<u8> {
    let payload = TokenPayload::Retry {
        address: addr,
        orig_dst_cid: ConnectionId::new(&[1; 8]),
        issued,
    };
    Token::new(payload, &mut rand::rng()).encode(&*config.token_key)
}

#[test]
fn admission_rejects_all_tokens_before_crypto_and_replay_log() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let dst_cid = ConnectionId::new(&[1; 8]);
    let tokens = [
        vec![],
        vec![7; 80],
        retry_token(&config, addr, config.time_source.now()),
        validation_token(&config, addr),
    ];
    let packets: Vec<_> = tokens
        .iter()
        .map(|token| initial_packet(&config, dst_cid, token))
        .collect();
    let counts = instrument(&mut config);
    let policy = Policy::new(InitialDecision::Proceed);
    policy.allow.store(false, Ordering::Relaxed);
    config.initial_filter(policy.clone());
    let mut endpoint = server_endpoint(config);
    for data in &packets {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(event.is_none(), "gate-rejected initial produced an event");
        assert!(out.is_empty(), "gate-rejected initial drew a response");
        assert_eq!(
            endpoint.incoming_buffer_bytes(),
            0,
            "gate rejection buffered data"
        );
    }
    assert_eq!(
        counts.values(),
        [0; 3],
        "gate rejection must precede all crypto and replay-log work"
    );
    assert!(
        policy.seen().is_empty(),
        "after_token_check must not run for gate-rejected initials"
    );

    // Gate rejection never reached the replay log, so the same NEW_TOKEN still validates once
    // admitted
    policy.allow.store(true, Ordering::Relaxed);
    let Some(DatagramEvent::NewConnection(incoming)) = endpoint.handle(
        Instant::now(),
        addr,
        None,
        None,
        packets[3].clone(),
        &mut Vec::new(),
    ) else {
        panic!("expected an Incoming for the admitted NEW_TOKEN initial")
    };
    assert!(
        incoming.remote_address_validated(),
        "NEW_TOKEN used up by the rejected attempt or by a second check"
    );
    assert!(incoming.may_retry(), "NEW_TOKEN peer may still be retried");
    endpoint.ignore(incoming);
    assert_eq!(
        counts.values(),
        [1, 1, 1],
        "Proceed must not decode the token a second time"
    );
}

/// After `Ignore`, the NEW_TOKEN is in the replay log, so a retransmission is unvalidated
#[test]
fn ignored_new_token_is_used_up() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let token = validation_token(&config, addr);
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    instrument(&mut config);
    let policy = Policy::new(InitialDecision::Ignore);
    config.initial_filter(policy.clone());
    let mut endpoint = server_endpoint(config);
    for _ in 0..2 {
        let event = endpoint.handle(
            Instant::now(),
            addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert!(event.is_none());
    }
    let validated: Vec<_> = policy
        .seen()
        .iter()
        .map(|(_, token)| token.remote_address_validated())
        .collect();
    assert_eq!(validated, [true, false]);
}

/// Manual Retry through `Incoming`, and fast Retry through the filter
#[test]
fn filtered_handshake_after_retry() {
    for fast in [false, true] {
        let verdict = match fast {
            true => InitialDecision::Retry,
            false => InitialDecision::Proceed,
        };
        let policy = Policy::new(verdict);
        let mut config = keyed_server_config();
        config.initial_filter(policy.clone());
        let mut pair = Pair::new(Default::default(), config);
        if !fast {
            pair.server.handle_incoming = Box::new(validate_incoming);
        }
        pair.connect();
        let seen = policy.seen();
        assert!(
            seen.iter()
                .all(|(initial, _)| initial.remote_address() == pair.client.addr)
        );
        let checks: Vec<_> = seen
            .iter()
            .map(|(_, token)| (token.remote_address_validated(), token.may_retry()))
            .collect();
        assert_eq!(
            checks,
            [(false, true), (true, false)],
            "a valid Retry token validates the address and forbids another Retry (fast: {fast})"
        );
    }
}

#[test]
fn filtered_handshake_ignore() {
    let _guard = subscribe();
    let policy = Policy::new(InitialDecision::Ignore);
    let mut config = keyed_server_config();
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let client_ch = pair.begin_connect(client_config());
    pair.drive();
    pair.server.assert_no_accept();
    assert_eq!(
        pair.client_conn_mut(client_ch).stats().udp_rx.datagrams,
        0,
        "an ignored initial must not draw any response"
    );
    assert!(!policy.seen().is_empty(), "the filter was not consulted");
}

#[test]
fn post_token_ignore_pays_token_cost_only() {
    let addr = "[::1]:4433".parse().unwrap();
    for validation in [false, true] {
        let mut config = keyed_server_config();
        let token = if validation {
            validation_token(&config, addr)
        } else {
            vec![7; 80]
        };
        let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
        let counts = instrument(&mut config);
        config.initial_filter(Policy::new(InitialDecision::Ignore));
        let mut endpoint = server_endpoint(config);
        let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut Vec::new());
        assert!(event.is_none(), "Ignore must not produce an event");
        assert_eq!(
            counts.values(),
            [0, 1, usize::from(validation)],
            "Ignore must pay only token decoding (validation token: {validation})"
        );
    }
}

/// Malformed headers skip `after_token_check`, but only the gate decides whether they cost a close
#[test]
fn malformed_initial_is_gated() {
    let addr = "[::1]:4433".parse().unwrap();
    // Empty DCID, as in `reject_short_idcid`
    let mut data = BytesMut::from(hex!("c4 00000001 00 00 00 3f").as_ref());
    data.resize(MIN_INITIAL_SIZE.into(), 0);
    for allow in [false, true] {
        let mut config = keyed_server_config();
        let counts = instrument(&mut config);
        let policy = Policy::new(InitialDecision::Ignore);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy.clone());
        let event = server_endpoint(config).handle(
            Instant::now(),
            addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert_eq!(
            matches!(event, Some(DatagramEvent::Response(_))),
            allow,
            "malformed initial answered only when admitted (allow: {allow})"
        );
        assert_eq!(
            counts.values(),
            [usize::from(allow), 0, 0],
            "malformed initial must derive keys only when admitted (allow: {allow})"
        );
        assert!(policy.seen().is_empty());
    }
}

#[test]
fn no_filter_validates_reserved_bits_before_consuming_token() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let token = validation_token(&config, addr);
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    // Flip a protected reserved bit without changing the header protection sample
    data[0] ^= 0x04;
    let counts = instrument(&mut config);
    let event =
        server_endpoint(config).handle(Instant::now(), addr, None, None, data, &mut Vec::new());
    assert!(event.is_none(), "reserved bits violation must be dropped");
    assert_eq!(
        counts.values(),
        [1, 0, 0],
        "without a filter, the token must not be decoded before header validation"
    );
}

/// Invalid Retry tokens skip `after_token_check` and draw INVALID_TOKEN, so only the gate bounds
/// their cost
#[test]
fn invalid_retry_tokens_only_reach_the_gate() {
    let addr: SocketAddr = "[::1]:4433".parse().unwrap();
    for allow in [false, true] {
        let mut config = keyed_server_config();
        let now = config.time_source.now();
        let packets: Vec<_> = [
            retry_token(&config, "[::1]:4434".parse().unwrap(), now),
            retry_token(&config, addr, now - Duration::from_secs(3600)),
        ]
        .iter()
        .map(|token| initial_packet(&config, ConnectionId::new(&[1; 8]), token))
        .collect();
        let counts = instrument(&mut config);
        let policy = Policy::new(InitialDecision::Retry);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy.clone());
        let mut endpoint = server_endpoint(config);
        for data in packets {
            let mut out = Vec::new();
            let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut out);
            assert_eq!(
                matches!(event, Some(DatagramEvent::Response(_))),
                allow,
                "invalid Retry token answered only when admitted (allow: {allow})"
            );
            assert!(
                !is_retry(&out),
                "an invalid Retry token must not draw Retry"
            );
        }
        assert!(
            policy.seen().is_empty(),
            "after_token_check must not run for invalid Retry tokens"
        );
        let n = usize::from(allow);
        assert_eq!(
            counts.values(),
            [2 * n, 2 * n, 0],
            "each admitted invalid Retry token costs Initial keys and token decryption"
        );
    }
}

#[test]
fn existing_connection_bypasses_exhausted_admission() {
    let mut config = keyed_server_config();
    let policy = Policy::new(InitialDecision::Proceed);
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let (client, _) = pair.connect();
    let gate_calls = policy.gate_calls.load(Ordering::Relaxed);
    policy.allow.store(false, Ordering::Relaxed);
    let before = pair.client_conn_mut(client).stats().frame_rx.acks;
    pair.client_conn_mut(client).ping();
    pair.drive();
    assert!(
        pair.client_conn_mut(client).stats().frame_rx.acks > before,
        "established connection must keep working with the gate closed"
    );
    assert_eq!(
        policy.gate_calls.load(Ordering::Relaxed),
        gate_calls,
        "established connection traffic must not reach the gate"
    );
}

/// The default `supports_version` derives Initial keys, but fast Retry still creates no state
#[test]
fn fast_retry_with_default_supports_version() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    let counts = instrument(&mut config);
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint = server_endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(matches!(event, Some(DatagramEvent::Response(_))));
        assert!(is_retry(&out), "expected a Retry");
        assert_eq!(endpoint.open_connections(), 0, "fast Retry opened state");
    }
    // One key derivation per `supports_version`, one token encryption per Retry
    assert_eq!(counts.values(), [3, 3, 0]);
}

/// Provider that overrides `supports_version` and panics if Initial keys or TLS are used
struct NoInitialKeys(Arc<dyn crypto::ServerConfig>);

impl crypto::ServerConfig for NoInitialKeys {
    fn supports_version(&self, version: u32) -> bool {
        self.0.supports_version(version)
    }

    fn initial_keys(&self, _: u32, _: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        panic!("fast Retry derived Initial keys")
    }

    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, cid, packet)
    }

    fn start_session(self: Arc<Self>, _: u32, _: &TransportParameters) -> Box<dyn crypto::Session> {
        panic!("fast Retry started TLS")
    }
}

#[test]
fn fast_retry_needs_no_initial_keys_or_state() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[7; 80]);
    config.crypto = Arc::new(NoInitialKeys(config.crypto.clone()));
    // A leaked `Incoming` would make the next attempt fail
    config.max_incoming = 1;
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint = server_endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(matches!(event, Some(DatagramEvent::Response(_))));
        assert!(is_retry(&out), "expected a Retry");
        assert_eq!(
            endpoint.known_connections(),
            0,
            "fast Retry created a connection"
        );
        assert_eq!(
            endpoint.known_cids(),
            0,
            "fast Retry registered a CID route"
        );
    }
}

/// `EndpointConfig::supported_versions` can't make fast Retry call `retry_tag` for a version
/// the provider doesn't support
#[test]
fn fast_retry_checks_provider_version_support() {
    let addr = "[::1]:4433".parse().unwrap();
    let unknown_version: u32 = 0x12345678;
    let mut config = keyed_server_config();
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data[1..5].copy_from_slice(&unknown_version.to_be_bytes());
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(vec![1, unknown_version]);
    let mut endpoint = Endpoint::new(Arc::new(endpoint_config), Some(Arc::new(config)), true);
    let mut out = Vec::new();
    let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut out);
    assert!(
        event.is_none() && out.is_empty(),
        "unsupported version must be dropped"
    );
}

#[test]
fn coalesced_initials_draw_one_retry() {
    let mut config = keyed_server_config();
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data.extend_from_slice(&data.clone());
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    let event = server_endpoint(config).handle(
        Instant::now(),
        "[::1]:4433".parse().unwrap(),
        None,
        None,
        data,
        &mut out,
    );
    assert!(matches!(event, Some(DatagramEvent::Response(_))));
    assert!(is_retry(&out), "expected a Retry");
    assert_eq!(policy.gate_calls.load(Ordering::Relaxed), 1);
    assert_eq!(policy.seen().len(), 1);
}
