//! Tests for multipath

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use tracing::info;

use crate::tests::util::{CLIENT_PORTS, SERVER_PORTS};
use crate::{
    ClientConfig, ClosePathError, ConnectionHandle, ConnectionId, ConnectionIdGenerator, Endpoint,
    EndpointConfig, Instant, LOC_CID_COUNT, PathId, PathStatus, RandomConnectionIdGenerator,
    ServerConfig, TransportConfig, cid_queue::CidQueue,
};
use crate::{Event, PathError, PathEvent};

use super::util::{min_opt, subscribe};
use super::{Pair, client_config, server_config};

const MAX_PATHS: u32 = 3;

/// Returns a connected client-server pair with multipath enabled
fn multipath_pair() -> (Pair, ConnectionHandle, ConnectionHandle) {
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let server_cfg = Arc::new(ServerConfig {
        transport: multipath_transport_cfg.clone(),
        ..server_config()
    });
    let server = Endpoint::new(Default::default(), Some(server_cfg), true, None);
    let client = Endpoint::new(Default::default(), None, true, None);

    let mut pair = Pair::new_from_endpoint(client, server);
    let client_cfg = ClientConfig {
        transport: multipath_transport_cfg,
        ..client_config()
    };
    let (client_ch, server_ch) = pair.connect_with(client_cfg);
    pair.drive();
    info!("connected");
    (pair, client_ch, server_ch)
}

#[test]
fn non_zero_length_cids() {
    let _guard = subscribe();
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(3 as _),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let server_cfg = Arc::new(ServerConfig {
        transport: multipath_transport_cfg.clone(),
        ..server_config()
    });
    let server = Endpoint::new(Default::default(), Some(server_cfg), true, None);

    struct ZeroLenCidGenerator;

    impl ConnectionIdGenerator for ZeroLenCidGenerator {
        fn generate_cid(&mut self) -> ConnectionId {
            ConnectionId::new(&[])
        }

        fn cid_len(&self) -> usize {
            0
        }

        fn cid_lifetime(&self) -> Option<std::time::Duration> {
            None
        }
    }

    let mut ep_config = EndpointConfig::default();
    ep_config.cid_generator(|| Box::new(ZeroLenCidGenerator));
    let client = Endpoint::new(Arc::new(ep_config), None, true, None);

    let mut pair = Pair::new_from_endpoint(client, server);
    let client_cfg = ClientConfig {
        transport: multipath_transport_cfg,
        ..client_config()
    };
    pair.begin_connect(client_cfg);
    pair.drive();
    let accept_err = pair
        .server
        .accepted
        .take()
        .expect("server didn't try connecting")
        .expect_err("server did not raise error for connection");
    match accept_err {
        crate::ConnectionError::TransportError(error) => {
            assert_eq!(error.code, crate::TransportErrorCode::PROTOCOL_VIOLATION);
        }
        _ => panic!("Not a TransportError"),
    }
}

#[test]
fn path_acks() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let client_conn = pair.client_conn_mut(client_ch);
    assert!(client_conn.stats().frame_rx.path_acks > 0);
    assert!(client_conn.stats().frame_tx.path_acks > 0);
}

#[test]
fn path_status() {
    let _guard = subscribe();
    let (mut pair, client_ch, server_ch) = multipath_pair();

    let client_conn = pair.client_conn_mut(client_ch);
    let prev_status = client_conn
        .set_path_status(PathId::ZERO, PathStatus::Backup)
        .unwrap();
    assert_eq!(prev_status, PathStatus::Available);

    // Send the frame to the server
    pair.drive();

    let server_conn = pair.server_conn_mut(server_ch);
    assert_eq!(
        server_conn.remote_path_status(PathId::ZERO).unwrap(),
        PathStatus::Backup
    );

    let client_stats = pair.client_conn_mut(client_ch).stats();
    assert_eq!(client_stats.frame_tx.path_available, 0);
    assert_eq!(client_stats.frame_tx.path_backup, 1);
    assert_eq!(client_stats.frame_rx.path_available, 0);
    assert_eq!(client_stats.frame_rx.path_backup, 0);

    let server_stats = pair.server_conn_mut(server_ch).stats();
    assert_eq!(server_stats.frame_tx.path_available, 0);
    assert_eq!(server_stats.frame_tx.path_backup, 0);
    assert_eq!(server_stats.frame_rx.path_available, 0);
    assert_eq!(server_stats.frame_rx.path_backup, 1);
}

#[test]
fn path_close_last_path() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let client_conn = pair.client_conn_mut(client_ch);
    let err = client_conn
        .close_path(Instant::now(), PathId::ZERO, 0u8.into())
        .err()
        .unwrap();
    assert!(matches!(err, ClosePathError::LastOpenPath));
}

#[test]
fn cid_issued_multipath() {
    let _guard = subscribe();
    const ACTIVE_CID_LIMIT: u64 = crate::cid_queue::CidQueue::LEN as _;
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let client_stats = pair.client_conn_mut(client_ch).stats();
    dbg!(&client_stats);

    // The client does not send NEW_CONNECTION_ID frames when multipath is enabled as they
    // are all sent after the handshake is completed.
    assert_eq!(client_stats.frame_tx.new_connection_id, 0);
    assert_eq!(
        client_stats.frame_tx.path_new_connection_id,
        MAX_PATHS as u64 * ACTIVE_CID_LIMIT
    );

    // The server sends NEW_CONNECTION_ID frames before the handshake is completed.
    // Multipath is only enabled *after* the handshake completes.  The first server-CID is
    // not issued but assigned by the client and changed by the server.
    assert_eq!(
        client_stats.frame_rx.new_connection_id,
        ACTIVE_CID_LIMIT - 1
    );
    assert_eq!(
        client_stats.frame_rx.path_new_connection_id,
        (MAX_PATHS - 1) as u64 * ACTIVE_CID_LIMIT
    );
}

#[test]
fn multipath_cid_rotation() {
    let _guard = subscribe();
    const CID_TIMEOUT: Duration = Duration::from_secs(2);

    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(*RandomConnectionIdGenerator::new(8).set_lifetime(CID_TIMEOUT));

    // Only test cid rotation on server side to have a clear output trace
    let server_cfg = ServerConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
            // Assume a low-latency connection so pacing doesn't interfere with the test
            initial_rtt: Duration::from_millis(10),
            ..TransportConfig::default()
        }),
        ..server_config()
    };

    let server = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..EndpointConfig::default()
        }),
        Some(Arc::new(server_cfg)),
        true,
        None,
    );
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    let mut pair = Pair::new_from_endpoint(client, server);
    let client_cfg = ClientConfig {
        transport: Arc::new(TransportConfig {
            max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
            // Assume a low-latency connection so pacing doesn't interfere with the test
            initial_rtt: Duration::from_millis(10),
            ..TransportConfig::default()
        }),
        ..client_config()
    };

    let (_, server_ch) = pair.connect_with(client_cfg);

    let mut round: u64 = 1;
    let mut stop = pair.time;
    let end = pair.time + 5 * CID_TIMEOUT;

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
        for path_id in 0..MAX_PATHS {
            assert_matches!(
                pair.server_conn_mut(server_ch)
                    .active_local_path_cid_seq(path_id),
                _bound
            );
        }
        round += 1;
        left_bound += active_cid_num;
        right_bound += active_cid_num;
        pair.drive_server();
    }

    let stats = pair.server_conn_mut(server_ch).stats();

    // Server sends CIDs for PathId::ZERO before multipath is negotiated.
    assert_eq!(stats.frame_tx.new_connection_id, (CidQueue::LEN - 1) as u64);

    // For the first batch the PathId::ZERO CIDs have already been sent.
    let initial_batch: u64 = (MAX_PATHS - 1) as u64 * CidQueue::LEN as u64;
    // Each round expires all CIDs, so they all get re-issued.
    let each_round: u64 = MAX_PATHS as u64 * CidQueue::LEN as u64;
    // The final round only pushes one set of CIDs with expires_before, the round is not run
    // to completion to wait for the expiry messages from the client.
    let final_round: u64 = MAX_PATHS as u64;
    let path_new_cids = initial_batch + (round - 2) * each_round + final_round;
    debug_assert_eq!(path_new_cids, 73);
    assert_eq!(stats.frame_tx.path_new_connection_id, path_new_cids);

    // We don't retire any CIDs before multipath is negotiated.
    assert_eq!(stats.frame_tx.retire_connection_id, 0);

    // Server expires the CID of the initial sent by the client.
    assert_eq!(stats.frame_tx.path_retire_connection_id, 1);

    // Client only sends CIDs after multipath is negotiated.
    assert_eq!(stats.frame_rx.new_connection_id, 0);

    // Client does not expire CIDs, only the initial set for all the paths.
    assert_eq!(
        stats.frame_rx.path_new_connection_id,
        MAX_PATHS as u64 * CidQueue::LEN as u64
    );
    assert_eq!(stats.frame_rx.retire_connection_id, 0);

    // Test stops before last batch of retirements is sent.
    let path_retire_cids = MAX_PATHS as u64 * CidQueue::LEN as u64 * (round - 2);
    debug_assert_eq!(path_retire_cids, 60);
    assert_eq!(stats.frame_rx.path_retire_connection_id, path_retire_cids);
}

#[test]
fn issue_max_path_id() {
    let _guard = subscribe();

    // We enable multipath but initially do not allow any paths to be opened.
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(1),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let server_cfg = Arc::new(ServerConfig {
        transport: multipath_transport_cfg.clone(),
        ..server_config()
    });
    let server = Endpoint::new(Default::default(), Some(server_cfg), true, None);
    let client = Endpoint::new(Default::default(), None, true, None);

    let mut pair = Pair::new_from_endpoint(client, server);

    // The client is allowed to create more paths immediately.
    let client_multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let client_cfg = ClientConfig {
        transport: client_multipath_transport_cfg,
        ..client_config()
    };
    let (_client_ch, server_ch) = pair.connect_with(client_cfg);
    pair.drive();
    info!("connected");

    // Server should only have sent NEW_CONNECTION_ID frames for now.
    let server_new_cids = CidQueue::LEN as u64 - 1;
    let mut server_path_new_cids = 0;
    let stats = pair.server_conn_mut(server_ch).stats();
    assert_eq!(stats.frame_tx.max_path_id, 0);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent PATH_NEW_CONNECTION_ID frames for PathId::ZERO.
    let client_new_cids = 0;
    let mut client_path_new_cids = CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    // Server increases MAX_PATH_ID.
    pair.server_conn_mut(server_ch)
        .set_max_concurrent_paths(Instant::now(), NonZeroU32::new(MAX_PATHS).unwrap())
        .unwrap();
    pair.drive();
    let stats = pair.server_conn_mut(server_ch).stats();

    // Server should have sent MAX_PATH_ID and new CIDs
    server_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_tx.max_path_id, 1);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent CIDs for new paths
    client_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);
}

/// A copy of [`issue_max_path_id`], but reordering the `MAX_PATH_ID` frame
/// that's sent from the server to the client, so that some `NEW_CONNECTION_ID`
/// frames arrive with higher path IDs than the most recently received
/// `MAX_PATH_ID` frame on the client side.
#[test]
fn issue_max_path_id_reordered() {
    let _guard = subscribe();

    // We enable multipath but initially do not allow any paths to be opened.
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(1),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let server_cfg = Arc::new(ServerConfig {
        transport: multipath_transport_cfg.clone(),
        ..server_config()
    });
    let server = Endpoint::new(Default::default(), Some(server_cfg), true, None);
    let client = Endpoint::new(Default::default(), None, true, None);

    let mut pair = Pair::new_from_endpoint(client, server);

    // The client is allowed to create more paths immediately.
    let client_multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let client_cfg = ClientConfig {
        transport: client_multipath_transport_cfg,
        ..client_config()
    };
    let (_client_ch, server_ch) = pair.connect_with(client_cfg);
    pair.drive();
    info!("connected");

    // Server should only have sent NEW_CONNECTION_ID frames for now.
    let server_new_cids = CidQueue::LEN as u64 - 1;
    let mut server_path_new_cids = 0;
    let stats = pair.server_conn_mut(server_ch).stats();
    assert_eq!(stats.frame_tx.max_path_id, 0);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent PATH_NEW_CONNECTION_ID frames for PathId::ZERO.
    let client_new_cids = 0;
    let mut client_path_new_cids = CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    // Server increases MAX_PATH_ID, but we reorder the frame
    pair.server_conn_mut(server_ch)
        .set_max_concurrent_paths(Instant::now(), NonZeroU32::new(MAX_PATHS).unwrap())
        .unwrap();
    pair.drive_server();
    // reorder the frames on the incoming side
    let p = pair.client.inbound.pop_front().unwrap();
    pair.client.inbound.push_back(p);
    pair.drive();
    let stats = pair.server_conn_mut(server_ch).stats();

    // Server should have sent MAX_PATH_ID and new CIDs
    server_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_tx.max_path_id, 1);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent CIDs for new paths
    client_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);
}

#[test]
fn open_path() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let server_addr = pair.server.addr;
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(server_addr, PathStatus::Available, Instant::now())
        .unwrap();
    pair.drive();
    let client_conn = pair.client_conn_mut(client_ch);
    assert_matches!(
        client_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::Opened { id  }) if id == path_id
    );

    let server_conn = pair.server_conn_mut(client_ch);
    assert_matches!(
        server_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::Opened { id  }) if id == path_id
    );
}

#[test]
fn open_path_key_update() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let server_addr = pair.server.addr;
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(server_addr, PathStatus::Available, Instant::now())
        .unwrap();

    // Do a key-update at the same time as opening the new path.
    pair.client_conn_mut(client_ch).force_key_update();

    pair.drive();
    let client_conn = pair.client_conn_mut(client_ch);
    assert_matches!(
        client_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::Opened { id  }) if id == path_id
    );

    let server_conn = pair.server_conn_mut(client_ch);
    assert_matches!(
        server_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::Opened { id  }) if id == path_id
    );
}

/// Client starts opening a path but the server fails to validate the path
///
/// The client should receive an event closing the path.
#[test]
fn open_path_validation_fails_server_side() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let different_addr = SocketAddr::new(
        [9, 8, 7, 6].into(),
        SERVER_PORTS.lock().unwrap().next().unwrap(),
    );
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(different_addr, PathStatus::Available, Instant::now())
        .unwrap();

    // block the server from receiving anything
    while pair.blackhole_step(true, false) {}
    let client_conn = pair.client_conn_mut(client_ch);
    assert_matches!(
        client_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::LocallyClosed { id, error: PathError::ValidationFailed  }) if id == path_id
    );

    let server_conn = pair.server_conn_mut(client_ch);
    assert!(server_conn.poll().is_none());
}

/// Client starts opening a path but the client fails to validate the path
///
/// The server should receive an event close the path
#[test]
fn open_path_validation_fails_client_side() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    // make sure the new path cannot be validated using the existing path
    pair.client.addr = SocketAddr::new(
        [9, 8, 7, 6].into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );

    let addr = pair.server.addr;
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(addr, PathStatus::Available, Instant::now())
        .unwrap();

    // block the client from receiving anything
    while pair.blackhole_step(false, true) {}

    let server_conn = pair.server_conn_mut(client_ch);
    assert_matches!(server_conn.poll().unwrap(),
        Event::Path(crate::PathEvent::LocallyClosed { id, error: PathError::ValidationFailed  }) if id == path_id
    );
}

#[test]
fn close_path() {
    let _guard = subscribe();
    let (mut pair, client_ch, _server_ch) = multipath_pair();

    let server_addr = pair.server.addr;
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(server_addr, PathStatus::Available, Instant::now())
        .unwrap();
    pair.drive();
    assert_ne!(path_id, PathId::ZERO);

    let stats0 = pair.client_conn_mut(client_ch).stats();
    assert_eq!(stats0.frame_tx.path_abandon, 0);
    assert_eq!(stats0.frame_rx.path_abandon, 0);
    assert_eq!(stats0.frame_tx.max_path_id, 0);
    assert_eq!(stats0.frame_rx.max_path_id, 0);

    info!("closing path 0");
    pair.client_conn_mut(client_ch)
        .close_path(Instant::now(), PathId::ZERO, 0u8.into())
        .unwrap();
    pair.drive();

    let stats1 = pair.client_conn_mut(client_ch).stats();
    assert_eq!(stats1.frame_tx.path_abandon, 1);
    assert_eq!(stats1.frame_rx.path_abandon, 1);
    assert_eq!(stats1.frame_tx.max_path_id, 1);
    assert_eq!(stats1.frame_rx.max_path_id, 1);
    assert!(stats1.frame_tx.path_new_connection_id > stats0.frame_tx.path_new_connection_id);
    assert!(stats1.frame_rx.path_new_connection_id > stats0.frame_rx.path_new_connection_id);
}

#[test]
fn close_last_path() {
    let _guard = subscribe();
    let (mut pair, client_ch, server_ch) = multipath_pair();

    let server_addr = pair.server.addr;
    let path_id = pair
        .client_conn_mut(client_ch)
        .open_path(server_addr, PathStatus::Available, Instant::now())
        .unwrap();
    pair.drive();
    assert_ne!(path_id, PathId::ZERO);

    info!("client closes path 0");
    pair.client_conn_mut(client_ch)
        .close_path(Instant::now(), PathId::ZERO, 0u8.into())
        .unwrap();

    info!("server closes path 1");
    pair.server_conn_mut(server_ch)
        .close_path(Instant::now(), PathId(1), 0u8.into())
        .unwrap();

    pair.drive();

    assert!(pair.server_conn_mut(server_ch).is_closed());
    assert!(pair.client_conn_mut(client_ch).is_closed());
}

#[test]
fn per_path_observed_address() {
    let _guard = subscribe();
    // create the endpoint pair with both address discovery and multipath enabled
    let (mut pair, client_ch, server_ch) = {
        let transport_cfg = Arc::new(TransportConfig {
            max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
            address_discovery_role: crate::address_discovery::Role::Both,
            ..TransportConfig::default()
        });
        let server_cfg = Arc::new(ServerConfig {
            transport: transport_cfg.clone(),
            ..server_config()
        });
        let server = Endpoint::new(Default::default(), Some(server_cfg), true, None);
        let client = Endpoint::new(Default::default(), None, true, None);

        let mut pair = Pair::new_from_endpoint(client, server);
        let client_cfg = ClientConfig {
            transport: transport_cfg,
            ..client_config()
        };
        let (client_ch, server_ch) = pair.connect_with(client_cfg);
        pair.drive();
        info!("connected");
        (pair, client_ch, server_ch)
    };

    // check that the client received the correct address
    let expected_addr = pair.client.addr;
    let conn = pair.client_conn_mut(client_ch);
    assert_matches!(conn.poll(), Some(Event::Path(PathEvent::ObservedAddr{id: PathId::ZERO, addr})) if addr == expected_addr);
    assert_matches!(conn.poll(), None);

    // check that the server received the correct address
    let expected_addr = pair.server.addr;
    let conn = pair.server_conn_mut(server_ch);
    assert_matches!(conn.poll(), Some(Event::Path(PathEvent::ObservedAddr{id: PathId::ZERO, addr})) if addr == expected_addr);
    assert_matches!(conn.poll(), None);

    // simulate a rebind on the client
    pair.client_conn_mut(client_ch).local_address_changed();
    pair.client
        .addr
        .set_port(pair.client.addr.port().overflowing_add(1).0);
    let our_addr = pair.client.addr;

    // open a second path
    let remote = pair.server.addr;
    let conn = pair.client_conn_mut(client_ch);
    let _new_path_id = conn
        .open_path(remote, PathStatus::Available, Instant::now())
        .unwrap();

    pair.drive();
    let conn = pair.client_conn_mut(client_ch);
    // check the migration related event
    assert_matches!(conn.poll(), Some(Event::Path(PathEvent::ObservedAddr{id: PathId::ZERO, addr})) if addr == our_addr);
    // wait for the open event
    let mut opened = false;
    while let Some(ev) = conn.poll() {
        if matches!(ev, Event::Path(PathEvent::Opened { id: PathId(1) })) {
            opened = true;
            break;
        }
    }
    assert!(opened);
    assert_matches!(conn.poll(), Some(Event::Path(PathEvent::ObservedAddr{id: PathId(1), addr})) if addr == our_addr);
}
