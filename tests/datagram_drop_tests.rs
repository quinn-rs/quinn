// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Integration tests for datagram dropping behavior.
//!
//! These tests verify that:
//! 1. Datagrams are properly dropped when the receive buffer is full
//! 2. Applications are notified about drops via events/logs
//! 3. The connection remains functional after drops

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ant_quic::{
    TransportConfig, VarInt,
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn small_buffer_transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    // Use a very small buffer to make testing easier (1KB instead of default ~1.25MB)
    transport.datagram_receive_buffer_size(Some(1024));
    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    Arc::new(transport)
}

/// Test that sending many datagrams without reading causes drops
#[tokio::test]
async fn test_datagram_buffer_overflow_causes_drop() {
    // Server setup with small datagram buffer
    let (chain, key) = gen_self_signed_cert();
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(small_buffer_transport_config());

    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let server_addr: SocketAddr = server.local_addr().unwrap();

    // Client setup
    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).unwrap();
    }
    let mut client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_cfg.transport_config(small_buffer_transport_config());

    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);

    // Accept in background
    let accept_handle = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept failed");
        timeout(Duration::from_secs(10), inc)
            .await
            .expect("handshake timeout")
            .expect("handshake failed")
    });

    // Connect
    let connecting = client
        .connect(server_addr, "localhost")
        .expect("start connect");
    let client_conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("connect timeout")
        .expect("connect failed");

    let server_conn = accept_handle.await.expect("accept task failed");

    // Send many datagrams from client without reading them on server
    // Buffer is 1024 bytes, so sending 2500 bytes should cause drops
    let datagram_size = 100;
    let num_datagrams = 25; // 2500 bytes total

    for i in 0..num_datagrams {
        let data = Bytes::from(vec![i as u8; datagram_size]);
        // Allow some sends to block or fail - that's expected
        let _ = client_conn.send_datagram(data);
    }

    // Give time for datagrams to arrive and fill the buffer
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Wait for an explicit drop notification
    let drop_event = timeout(Duration::from_secs(1), server_conn.on_datagram_drop())
        .await
        .expect("drop notification not observed")
        .expect("drop future failed");
    assert!(
        drop_event.datagrams > 0,
        "expected at least one datagram to be dropped"
    );

    // Now read datagrams - we should get some but not all
    let mut received_count = 0;
    while let Ok(result) = timeout(Duration::from_millis(100), server_conn.read_datagram()).await {
        if result.is_ok() {
            received_count += 1;
        } else {
            break;
        }
    }

    // Buffer is 1024 bytes, so we can hold at most ~10 datagrams of 100 bytes each
    // Some should have been dropped
    assert!(
        received_count < num_datagrams,
        "Expected some datagrams to be dropped, but received all {}",
        num_datagrams
    );
    assert!(
        received_count > 0,
        "Expected to receive at least some datagrams"
    );
    let stats = server_conn.stats();
    assert!(
        stats.datagram_drops.datagrams >= drop_event.datagrams,
        "stats should account for dropped datagrams (stats={}, event={})",
        stats.datagram_drops.datagrams,
        drop_event.datagrams
    );

    // Connection should still be functional after drops
    assert!(
        client_conn.close_reason().is_none(),
        "Client should still be connected"
    );
    assert!(
        server_conn.close_reason().is_none(),
        "Server should still be connected"
    );

    // Verify we can still send/receive after drops
    let final_data = Bytes::from(vec![255u8; 50]);
    client_conn
        .send_datagram(final_data.clone())
        .expect("final send");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let received = timeout(Duration::from_millis(100), server_conn.read_datagram())
        .await
        .expect("final receive timeout")
        .expect("final receive failed");
    assert_eq!(
        received, final_data,
        "Should receive final datagram correctly"
    );

    // Close gracefully
    client_conn.close(VarInt::from_u32(0), b"done");
}

/// Test that datagrams work normally when buffer isn't exceeded
#[tokio::test]
async fn test_datagram_no_drop_when_reading() {
    // Server setup with small buffer
    let (chain, key) = gen_self_signed_cert();
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(small_buffer_transport_config());

    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let server_addr: SocketAddr = server.local_addr().unwrap();

    // Client setup
    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).unwrap();
    }
    let mut client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_cfg.transport_config(small_buffer_transport_config());

    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);

    // Accept in background
    let accept_handle = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept failed");
        timeout(Duration::from_secs(10), inc)
            .await
            .expect("handshake timeout")
            .expect("handshake failed")
    });

    // Connect
    let connecting = client
        .connect(server_addr, "localhost")
        .expect("start connect");
    let client_conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("connect timeout")
        .expect("connect failed");

    let server_conn = accept_handle.await.expect("accept task failed");

    // Send and immediately read datagrams - should not cause drops
    let num_datagrams = 20;
    let datagram_size = 50;
    let mut received_count = 0;

    for i in 0..num_datagrams {
        let data = Bytes::from(vec![i as u8; datagram_size]);
        client_conn.send_datagram(data).expect("send datagram");

        // Give a little time for the datagram to arrive
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Read immediately to prevent buffer overflow
        if let Ok(result) = timeout(Duration::from_millis(100), server_conn.read_datagram()).await {
            if result.is_ok() {
                received_count += 1;
            }
        }
    }

    // Should receive most or all datagrams when reading immediately
    assert!(
        received_count >= num_datagrams - 2, // Allow small margin for timing
        "Expected to receive most datagrams when reading immediately, got {}/{}",
        received_count,
        num_datagrams
    );

    // Ensure no drop notifications fire when the application reads promptly
    assert!(
        timeout(Duration::from_millis(200), server_conn.on_datagram_drop())
            .await
            .is_err(),
        "unexpected datagram drop notification"
    );

    // Close gracefully
    client_conn.close(VarInt::from_u32(0), b"done");
}
