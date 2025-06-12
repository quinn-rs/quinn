//! Tests for multipath

use std::num::NonZeroU32;
use std::sync::Arc;

use tracing::info;

use crate::{
    ClientConfig, ConnectionHandle, ConnectionId, ConnectionIdGenerator, Endpoint, EndpointConfig,
    PathId, PathStatus, ServerConfig, TransportConfig,
};

use super::util::subscribe;
use super::{Pair, client_config, server_config};

#[test]
fn non_zero_length_cids() {
    let _guard = subscribe();
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(3 as _),
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

/// Returns a connected client-server pair with multipath enabled
fn multipath_pair() -> (Pair, ConnectionHandle, ConnectionHandle) {
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(3 as _),
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
fn path_status() {
    let _guard = subscribe();
    let (mut pair, client_ch, server_ch) = multipath_pair();

    info!("client sets PATH_BACKUP");
    let client_conn = pair.client_conn_mut(client_ch);
    let prev_status = client_conn
        .set_path_status(PathId::ZERO, PathStatus::Backup)
        .unwrap();
    assert_eq!(prev_status, PathStatus::Available);

    // Send the frame to the server
    pair.drive();

    let server_conn = pair.server_conn_mut(server_ch);
    assert_eq!(
        server_conn.path_status(PathId::ZERO).unwrap(),
        PathStatus::Backup
    );

    info!("server sets PATH_AVAILABLE");
    server_conn
        .set_path_status(PathId::ZERO, PathStatus::Available)
        .unwrap();

    // Send the frame to the client
    pair.drive()
}
