use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use proptest::{
    collection::vec,
    prelude::{Strategy, any},
    prop_assert,
};
use test_strategy::proptest;

use crate::{
    ConnectionClose, ConnectionError, PathStatus, TransportConfig, TransportErrorCode,
    tests::{
        Pair, RoutingTable,
        random_interaction::{Side, TestOp, run_random_interaction},
        server_config, subscribe,
    },
};

const MAX_PATHS: u32 = 3;

const CLIENT_ADDRS: [SocketAddr; MAX_PATHS as usize] = [
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44433u16),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44434u16),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44435u16),
];
const SERVER_ADDRS: [SocketAddr; MAX_PATHS as usize] = [
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433u16),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4434u16),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4435u16),
];

fn setup_deterministic_with_multipath(
    seed: [u8; 32],
    routes: RoutingTable,
    qlog_prefix: &'static str,
) -> Pair {
    let mut pair = Pair::seeded(seed);

    let mut cfg = server_config();
    let transport = multipath_transport_config(qlog_prefix);
    cfg.transport = Arc::new(transport);
    pair.server.endpoint.set_server_config(Some(Arc::new(cfg)));

    pair.client.addr = routes.client_addr(0).unwrap();
    pair.server.addr = routes.server_addr(0).unwrap();
    pair.routes = Some(routes);
    pair
}

fn multipath_transport_config(qlog_prefix: &'static str) -> TransportConfig {
    let mut cfg = TransportConfig::default();
    // enable multipath
    cfg.max_concurrent_multipath_paths(MAX_PATHS);
    // cfg.mtu_discovery_config(None);
    #[cfg(feature = "qlog")]
    cfg.qlog_from_env(qlog_prefix);
    #[cfg(not(feature = "qlog"))]
    let _ = qlog_prefix;
    cfg
}

#[proptest(cases = 256)]
fn random_interaction(
    #[strategy(any::<[u8; 32]>().no_shrink())] seed: [u8; 32],
    #[strategy(vec(any::<TestOp>(), 0..100))] interactions: Vec<TestOp>,
) {
    let prefix = "random_interaction";
    let mut pair = Pair::seeded(seed);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    prop_assert!(!pair.drive_bounded(1000), "connection never became idle");
    prop_assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    prop_assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[proptest(cases = 256)]
fn random_interaction_with_multipath_simple_routing(
    #[strategy(any::<[u8; 32]>().no_shrink())] seed: [u8; 32],
    #[strategy(vec(any::<TestOp>(), 0..100))] interactions: Vec<TestOp>,
) {
    let prefix = "random_interaction_with_multipath_simple_routing";
    let routes = RoutingTable::simple_symmetric(CLIENT_ADDRS, SERVER_ADDRS);
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    prop_assert!(!pair.drive_bounded(1000), "connection never became idle");
    prop_assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    prop_assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

fn routing_table() -> impl Strategy<Value = RoutingTable> {
    (vec(0..=5usize, 0..=4), vec(0..=5usize, 0..=4)).prop_map(|(client_offsets, server_offsets)| {
        let mut client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44433u16);
        let mut server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433u16);
        let mut client_routes = vec![(client_addr, 0)];
        let mut server_routes = vec![(server_addr, 0)];
        for (idx, &offset) in client_offsets.iter().enumerate() {
            let other_idx = idx.saturating_sub(offset);
            let server_idx = other_idx.clamp(0, server_offsets.len());
            client_routes.push((client_addr, server_idx));
            client_addr.set_port(client_addr.port() + 1);
        }
        for (idx, &offset) in server_offsets.iter().enumerate() {
            let other_idx = idx.saturating_sub(offset);
            let client_idx = other_idx.clamp(0, client_offsets.len());
            server_routes.push((server_addr, client_idx));
            server_addr.set_port(server_addr.port() + 1);
        }

        RoutingTable::from_routes(client_routes, server_routes)
    })
}

#[proptest(cases = 256)]
fn random_interaction_with_multipath_complex_routing(
    #[strategy(any::<[u8; 32]>().no_shrink())] seed: [u8; 32],
    #[strategy(vec(any::<TestOp>(), 0..100))] interactions: Vec<TestOp>,
    #[strategy(routing_table())] routes: RoutingTable,
) {
    let prefix = "random_interaction_with_multipath_complex_routing";
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    prop_assert!(!pair.drive_bounded(1000), "connection never became idle");
    prop_assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    prop_assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

fn old_routing_table() -> RoutingTable {
    let mut routes = RoutingTable::simple_symmetric([CLIENT_ADDRS[0]], [SERVER_ADDRS[0]]);
    for addr in CLIENT_ADDRS.into_iter().skip(1) {
        routes.add_client_route(addr, 0);
    }
    for addr in SERVER_ADDRS.into_iter().skip(1) {
        routes.add_server_route(addr, 0);
    }
    routes
}

fn not_transport_error(err: Option<ConnectionError>) -> bool {
    match err {
        None => true,
        Some(ConnectionError::TransportError(_)) => false,
        Some(ConnectionError::ConnectionClosed(ConnectionClose { error_code, .. })) => {
            error_code != TransportErrorCode::PROTOCOL_VIOLATION
        }
        _ => true,
    }
}

#[test]
fn regression_unset_packet_acked() {
    let prefix = "regression_unset_packet_acked";
    let seed: [u8; 32] = [
        60, 116, 60, 165, 136, 238, 239, 131, 14, 159, 221, 16, 80, 60, 30, 15, 15, 69, 133, 33,
        89, 203, 28, 107, 123, 117, 6, 54, 215, 244, 47, 1,
    ];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Available, 0),
        TestOp::ClosePath(Side::Client, 0, 0),
        TestOp::Drive(Side::Client),
        TestOp::AdvanceTime,
        TestOp::Drive(Side::Server),
        TestOp::DropInbound(Side::Client),
    ];

    let _guard = subscribe();
    let routes = old_routing_table();
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    #[allow(unused_mut)]
    let mut cfg = TransportConfig::default();
    #[cfg(feature = "qlog")]
    cfg.qlog_from_env(prefix);
    let (client_ch, server_ch) = run_random_interaction(&mut pair, interactions, cfg);

    assert!(!pair.drive_bounded(100), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[test]
fn regression_invalid_key() {
    let prefix = "regression_invalid_key";
    let seed = [
        41, 24, 232, 72, 136, 73, 31, 115, 14, 101, 61, 219, 30, 168, 130, 122, 120, 238, 6, 130,
        117, 84, 250, 190, 50, 237, 14, 167, 60, 5, 140, 149,
    ];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Available, 0),
        TestOp::AdvanceTime,
        TestOp::Drive(Side::Client),
        TestOp::OpenPath(Side::Client, PathStatus::Available, 0),
    ];

    let _guard = subscribe();
    let routes = old_routing_table();
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    assert!(!pair.drive_bounded(100), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[test]
fn regression_key_update_error() {
    let prefix = "regression_key_update_error";
    let seed: [u8; 32] = [
        68, 93, 15, 237, 88, 31, 93, 255, 246, 51, 203, 224, 20, 124, 107, 163, 143, 43, 193, 187,
        208, 54, 158, 239, 190, 82, 198, 62, 91, 51, 53, 226,
    ];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Available, 0),
        TestOp::Drive(Side::Client),
        TestOp::ForceKeyUpdate(Side::Server),
    ];

    let _guard = subscribe();
    let routes = old_routing_table();
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    assert!(!pair.drive_bounded(100), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[test]
fn regression_never_idle() {
    let prefix = "regression_never_idle";
    let seed: [u8; 32] = [
        172, 221, 115, 106, 31, 22, 213, 3, 199, 6, 128, 220, 47, 215, 159, 233, 97, 21, 254, 207,
        48, 180, 255, 97, 33, 29, 11, 76, 219, 138, 87, 57,
    ];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Available, 1),
        TestOp::PathSetStatus(Side::Server, 0, PathStatus::Backup),
        TestOp::ClosePath(Side::Client, 0, 0),
    ];

    let _guard = subscribe();
    let routes = old_routing_table();
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    assert!(!pair.drive_bounded(100), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[test]
fn regression_never_idle2() {
    let prefix = "regression_never_idle2";
    let seed: [u8; 32] = [
        201, 119, 56, 156, 173, 104, 243, 75, 174, 248, 232, 226, 240, 106, 118, 59, 226, 245, 138,
        50, 100, 4, 245, 65, 8, 174, 18, 189, 72, 10, 166, 160,
    ];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Backup, 1),
        TestOp::ClosePath(Side::Client, 0, 0),
        TestOp::Drive(Side::Client),
        TestOp::DropInbound(Side::Server),
        TestOp::PathSetStatus(Side::Client, 0, PathStatus::Available),
    ];

    let _guard = subscribe();
    let routes = old_routing_table();
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    // We needed to increase the bounds. It eventually times out.
    assert!(!pair.drive_bounded(1000), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}

#[test]
fn regression_packet_number_space_missing() {
    let prefix = "regression_packet_number_space_missing";
    let seed = [0u8; 32];
    let interactions = vec![
        TestOp::OpenPath(Side::Client, PathStatus::Backup, 0),
        TestOp::OpenPath(Side::Client, PathStatus::Backup, 0),
        TestOp::Drive(Side::Client),
        TestOp::DropInbound(Side::Server),
        TestOp::ClosePath(Side::Client, 0, 0),
    ];

    let _guard = subscribe();
    let routes = RoutingTable::simple_symmetric([CLIENT_ADDRS[0]], [SERVER_ADDRS[0]]);
    let mut pair = setup_deterministic_with_multipath(seed, routes, prefix);
    let (client_ch, server_ch) =
        run_random_interaction(&mut pair, interactions, multipath_transport_config(prefix));

    assert!(!pair.drive_bounded(100), "connection never became idle");
    assert!(not_transport_error(
        pair.client_conn_mut(client_ch).state().take_error(),
    ));
    assert!(not_transport_error(
        pair.server_conn_mut(server_ch).state().take_error(),
    ));
}
