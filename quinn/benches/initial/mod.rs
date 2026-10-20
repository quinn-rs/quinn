//! Server cost of one new Initial. Packet preparation is not measured.
use bencher::{Bencher, benchmark_group};
use proto::{
    DatagramEvent, InitialDecision, InitialFilter, InitialMetadata, TokenCheck, TokenStore,
};
use std::{hint::black_box, sync::Arc, time::Instant};

struct Policy {
    admit: bool,
    verdict: InitialDecision,
}
impl InitialFilter for Policy {
    fn before_token_check(&self, _: &InitialMetadata) -> bool {
        self.admit
    }
    fn after_token_check(&self, _: &InitialMetadata, _: &TokenCheck) -> InitialDecision {
        self.verdict
    }
}

fn run(
    b: &mut Bencher,
    filter: bool,
    admit: bool,
    verdict: InitialDecision,
    token_len: usize,
    valid_return: bool,
) {
    let super::Context {
        mut server_config,
        mut client_config,
    } = super::Context::new();
    let store = Arc::new(proto::TokenMemoryCache::default());
    if token_len > 0 {
        store.insert("localhost", vec![7; token_len].into());
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
    if valid_return {
        let mut seed = proto::Endpoint::new(
            Default::default(),
            Some(Arc::new(server_config.clone())),
            true,
        );
        let mut retry = Vec::new();
        let Some(DatagramEvent::NewConnection(incoming)) =
            seed.handle(now, addr, None, None, packet.as_slice().into(), &mut retry)
        else {
            panic!("expected Incoming")
        };
        let _ = seed.retry(incoming, &mut retry).unwrap();
        let Some(DatagramEvent::ConnectionEvent(_, event)) = client.handle(
            now,
            addr,
            None,
            None,
            retry.as_slice().into(),
            &mut Vec::new(),
        ) else {
            panic!("expected Retry routing")
        };
        connection.handle_event(event);
        packet.clear();
        // The retried Initial may wait for the client's pacing timer
        for _ in 0..10 {
            if connection.poll_transmit(now, 1, &mut packet).is_some() {
                break;
            }
            now = connection
                .poll_timeout()
                .expect("retried Initial must be scheduled");
            connection.handle_timeout(now);
        }
        assert!(
            !packet.is_empty(),
            "client did not emit the retried Initial"
        );
    }
    if filter {
        server_config.initial_filter(Arc::new(Policy { admit, verdict }));
    }
    let mut server = proto::Endpoint::new(Default::default(), Some(Arc::new(server_config)), true);
    b.bytes = packet.len() as u64;
    b.iter(|| {
        let mut out = Vec::new();
        match server.handle(now, addr, None, None, packet.as_slice().into(), &mut out) {
            Some(DatagramEvent::NewConnection(incoming)) => {
                assert!(admit);
                if valid_return {
                    assert!(incoming.remote_address_validated());
                    server.ignore(incoming);
                } else if verdict == InitialDecision::Retry {
                    assert!(!filter);
                    let _ = server.retry(incoming, &mut out).unwrap();
                } else {
                    server.ignore(incoming);
                }
            }
            Some(DatagramEvent::Response(_)) => {
                assert!(filter && admit && verdict == InitialDecision::Retry && !valid_return)
            }
            None => assert!(!admit || verdict == InitialDecision::Ignore),
            _ => panic!("unexpected route"),
        }
        if admit && verdict == InitialDecision::Retry && !valid_return {
            assert_eq!(out[0] & 0xf0, 0xf0);
        } else {
            assert!(out.is_empty());
        }
        black_box(out);
    });
}
macro_rules! case {
    ($name:ident,$filter:expr,$admit:expr,$verdict:ident,$len:expr,$valid:expr) => {
        fn $name(b: &mut Bencher) {
            run(b, $filter, $admit, InitialDecision::$verdict, $len, $valid);
        }
    };
}
case!(fast_retry_manual_empty, false, true, Retry, 0, false);
case!(fast_retry_empty, true, true, Retry, 0, false);
case!(fast_retry_bogus, true, true, Retry, 80, false);
case!(fast_retry_manual_bogus, false, true, Retry, 80, false);
case!(fast_retry_ignore_bogus, true, true, Ignore, 80, false);
case!(fast_retry_ignore_empty, true, true, Ignore, 0, false);
case!(fast_retry_gate_empty, true, false, Retry, 0, false);
case!(fast_retry_gate_bogus, true, false, Retry, 80, false);
case!(fast_retry_gate_long_bogus, true, false, Retry, 1000, false);
case!(fast_retry_gate_valid_return, true, false, Retry, 0, true);
case!(fast_retry_valid_return, true, true, Retry, 0, true);
case!(fast_retry_manual_valid_return, false, true, Retry, 0, true);
case!(fast_retry_proceed, true, true, Proceed, 0, false);
case!(fast_retry_manual_drop_empty, false, true, Ignore, 0, false);
case!(fast_retry_manual_drop_bogus, false, true, Ignore, 80, false);
benchmark_group!(
    benches,
    fast_retry_manual_empty,
    fast_retry_empty,
    fast_retry_bogus,
    fast_retry_manual_bogus,
    fast_retry_ignore_bogus,
    fast_retry_ignore_empty,
    fast_retry_gate_empty,
    fast_retry_gate_bogus,
    fast_retry_gate_long_bogus,
    fast_retry_gate_valid_return,
    fast_retry_valid_return,
    fast_retry_manual_valid_return,
    fast_retry_proceed,
    fast_retry_manual_drop_empty,
    fast_retry_manual_drop_bogus
);
