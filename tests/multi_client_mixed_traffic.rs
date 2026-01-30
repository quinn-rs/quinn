// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Integration test covering the mixed datagram/stream workload reported in issue #128.
//!
//! The scenario spins up a relay-style server that accepts multiple concurrent peers.
//! Each peer immediately floods the server with unordered datagrams, opens a
//! bidirectional stream, and waits for a server-initiated unidirectional stream.
//! The test verifies that no datagrams are lost when the application actively
//! drains the buffer and that both directions of reliable streams continue to work.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    TransportConfig, VarInt,
    config::{ClientConfig, ServerConfig},
    high_level::{Connection, Endpoint, RecvStream, SendStream},
};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

const CLIENT_COUNT: usize = 3;
const DATAGRAMS_PER_CLIENT: usize = 8;
const DATAGRAM_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_MESSAGES_PER_CLIENT: usize = 4;
const SELECT_LOOP_SPIN_DELAY: Duration = Duration::from_millis(1);
const ACCEPT_CANCELLATIONS_PER_STREAM: usize = 5;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn pqc_transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.enable_pqc(true);
    Arc::new(transport)
}

async fn make_server() -> (Endpoint, SocketAddr, Vec<CertificateDer<'static>>) {
    ensure_crypto_provider();
    let (chain, key) = gen_self_signed_cert();
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(pqc_transport_config());
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr = server.local_addr().expect("server addr");
    (server, addr, chain)
}

fn client_config(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in chain.iter().cloned() {
        roots.add(cert).expect("add root");
    }
    let mut cfg = ClientConfig::with_root_certificates(Arc::new(roots)).expect("client cfg");
    cfg.transport_config(pqc_transport_config());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_client_mixed_traffic_no_datagram_loss() {
    let (server, server_addr, chain) = make_server().await;
    let chain = Arc::new(chain);

    let server_task = tokio::spawn(async move {
        run_server(server).await;
    });

    let mut client_tasks = Vec::new();
    for client_idx in 0..CLIENT_COUNT {
        let chain_clone = Arc::clone(&chain);
        client_tasks.push(tokio::spawn(run_client(
            client_idx as u8,
            server_addr,
            chain_clone,
        )));
    }

    for task in client_tasks {
        task.await.expect("client task panicked");
    }

    server_task.await.expect("server task panicked");
}

async fn run_server(endpoint: Endpoint) {
    let mut handlers = Vec::new();
    for _ in 0..CLIENT_COUNT {
        let incoming = timeout(HANDSHAKE_TIMEOUT, endpoint.accept())
            .await
            .expect("server accept timeout")
            .expect("incoming connection");
        let connection = timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .expect("server handshake timeout")
            .expect("server handshake failed");
        handlers.push(tokio::spawn(async move {
            handle_server_connection(connection).await;
        }));
    }

    for handle in handlers {
        handle.await.expect("server handler panicked");
    }

    // Allow CONNECTION_CLOSE frames to flush
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn handle_server_connection(conn: Connection) {
    let mut sequences = HashSet::new();
    let mut client_marker = None;

    while sequences.len() < DATAGRAMS_PER_CLIENT {
        let datagram = timeout(DATAGRAM_TIMEOUT, conn.read_datagram())
            .await
            .expect("server datagram wait timed out")
            .expect("server datagram read failed");
        assert!(datagram.len() >= 2, "datagram missing marker/sequence");
        let marker = datagram[0];
        let seq = datagram[1];
        if let Some(existing) = client_marker {
            assert_eq!(
                existing, marker,
                "mixed client markers on single connection"
            );
        } else {
            client_marker = Some(marker);
        }
        sequences.insert(seq);
    }

    let client_marker = client_marker.expect("no datagrams observed for connection");
    assert_eq!(
        sequences.len(),
        DATAGRAMS_PER_CLIENT,
        "expected to receive all datagrams before continuing",
    );

    let (mut send, mut recv) = timeout(DATAGRAM_TIMEOUT, conn.accept_bi())
        .await
        .expect("server accept_bi timeout")
        .expect("server accept_bi failed");
    let mut buf = [0u8; 128];
    let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
        .await
        .expect("server stream read timeout")
        .expect("server stream read failed")
        .expect("client closed stream prematurely");
    let msg = std::str::from_utf8(&buf[..len]).expect("valid utf8");
    assert!(
        msg.contains(&format!("client-{client_marker}-bi")),
        "unexpected stream payload: {msg}",
    );

    let response = format!("server-ack-{client_marker}");
    timeout(DATAGRAM_TIMEOUT, send.write_all(response.as_bytes()))
        .await
        .expect("server write timeout")
        .expect("server write failed");
    send.finish().expect("server finish stream");

    let mut uni = conn.open_uni().await.expect("server open_uni");
    let broadcast = format!("broadcast-{client_marker}");
    timeout(DATAGRAM_TIMEOUT, uni.write_all(broadcast.as_bytes()))
        .await
        .expect("server uni write timeout")
        .expect("server uni write failed");
    uni.finish().expect("server uni finish");

    let stats = conn.stats();
    assert_eq!(
        stats.datagram_drops.datagrams, 0,
        "server should not drop datagrams"
    );

    // Wait for the peer to close the connection to avoid racing its reads.
    let _ = conn.closed().await;
}

async fn run_client(
    client_marker: u8,
    server_addr: SocketAddr,
    chain: Arc<Vec<CertificateDer<'static>>>,
) {
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_config(chain.as_slice()));

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("start connect");
    let conn = timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .expect("client connect timeout")
        .expect("client connect failed");

    send_client_datagrams(&conn, client_marker);

    let (mut send, mut recv) = conn.open_bi().await.expect("client open_bi");
    let payload = format!("client-{client_marker}-bi");
    timeout(DATAGRAM_TIMEOUT, send.write_all(payload.as_bytes()))
        .await
        .expect("client write timeout")
        .expect("client write failed");
    send.finish().expect("client finish stream");

    let mut buf = [0u8; 64];
    let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
        .await
        .expect("client read timeout")
        .expect("client read failed")
        .expect("server closed stream early");
    let response = std::str::from_utf8(&buf[..len]).expect("valid utf8");
    assert_eq!(response, format!("server-ack-{client_marker}"));

    let mut uni = timeout(DATAGRAM_TIMEOUT, conn.accept_uni())
        .await
        .expect("client accept_uni timeout")
        .expect("client accept_uni failed");
    let len = timeout(DATAGRAM_TIMEOUT, uni.read(&mut buf))
        .await
        .expect("client uni read timeout")
        .expect("client uni read failed")
        .expect("server uni closed early");
    let uni_payload = std::str::from_utf8(&buf[..len]).expect("valid utf8");
    assert_eq!(uni_payload, format!("broadcast-{client_marker}"));

    let stats = conn.stats();
    assert_eq!(
        stats.datagram_drops.datagrams, 0,
        "client should not observe datagram drops"
    );

    conn.close(VarInt::from_u32(0), b"done");
}

fn send_client_datagrams(conn: &Connection, client_marker: u8) {
    for seq in 0..DATAGRAMS_PER_CLIENT {
        let mut payload = Vec::with_capacity(2 + 16);
        payload.push(client_marker);
        payload.push(seq as u8);
        payload.extend_from_slice(format!("payload-{client_marker}-{seq}").as_bytes());
        conn.send_datagram(Bytes::from(payload))
            .expect("client send_datagram");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_client_select_loop_integrity() {
    let (server, server_addr, chain) = make_server().await;
    let chain = Arc::new(chain);

    let server_task = tokio::spawn(async move {
        run_server_select_loop(server).await;
    });

    let mut client_tasks = Vec::new();
    for client_idx in 0..CLIENT_COUNT {
        let chain_clone = Arc::clone(&chain);
        client_tasks.push(tokio::spawn(run_select_loop_client(
            client_idx as u8,
            server_addr,
            chain_clone,
        )));
    }

    for task in client_tasks {
        task.await.expect("select client task panicked");
    }

    server_task.await.expect("select server task panicked");
}

async fn run_server_select_loop(endpoint: Endpoint) {
    let mut handlers = Vec::new();
    for _ in 0..CLIENT_COUNT {
        let incoming = timeout(HANDSHAKE_TIMEOUT, endpoint.accept())
            .await
            .expect("select server accept timeout")
            .expect("select incoming connection");
        let connection = timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .expect("select server handshake timeout")
            .expect("select server handshake failed");
        handlers.push(tokio::spawn(async move {
            handle_select_loop_connection(connection).await;
        }));
    }

    for handle in handlers {
        handle.await.expect("select handler panicked");
    }
}

async fn handle_select_loop_connection(conn: Connection) {
    let mut datagram_sequences = HashSet::new();
    let mut stream_sequences = HashSet::new();
    let mut client_marker = None;

    while datagram_sequences.len() < DATAGRAMS_PER_CLIENT
        || stream_sequences.len() < STREAM_MESSAGES_PER_CLIENT
    {
        tokio::select! {
            biased;
            datagram = conn.read_datagram() => {
                let bytes = datagram.expect("select server datagram read failed");
                assert!(bytes.len() >= 2, "select server datagram missing metadata");
                let marker = bytes[0];
                let seq = bytes[1];
                if let Some(existing) = client_marker {
                    assert_eq!(existing, marker, "mixed client markers per connection");
                } else {
                    client_marker = Some(marker);
                }
                datagram_sequences.insert(seq);
            }
            stream = conn.accept_bi() => {
                let (mut send, mut recv) = stream.expect("select server accept_bi failed");
                let mut buf = [0u8; 256];
                let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
                    .await
                    .expect("select server stream read timeout")
                    .expect("select server stream read failed")
                    .expect("select server stream closed");
                let message = std::str::from_utf8(&buf[..len]).expect("valid UTF-8 stream message");
                let parts: Vec<_> = message.split('-').collect();
                assert!(
                    parts.len() >= 4,
                    "unexpected stream payload format: {message}"
                );
                let marker = parts[1].parse::<u8>().expect("stream marker parse");
                let seq = parts[3].parse::<u8>().expect("stream seq parse");
                if let Some(existing) = client_marker {
                    assert_eq!(existing, marker, "stream marker mismatch");
                } else {
                    client_marker = Some(marker);
                }
                stream_sequences.insert(seq);

                let response = format!("server-ack-{marker}-{seq}");
                timeout(DATAGRAM_TIMEOUT, send.write_all(response.as_bytes()))
                    .await
                    .expect("select server stream write timeout")
                    .expect("select server stream write failed");
                send.finish().expect("select server finish stream");
            }
            _ = sleep(SELECT_LOOP_SPIN_DELAY) => {
                // allow cancellation to mimic tokio::select! usage in user code
            }
        }
    }

    assert_eq!(
        datagram_sequences.len(),
        DATAGRAMS_PER_CLIENT,
        "select loop server should observe all datagrams"
    );
    assert_eq!(
        stream_sequences.len(),
        STREAM_MESSAGES_PER_CLIENT,
        "select loop server should observe all stream RPCs"
    );

    let stats = conn.stats();
    assert_eq!(
        stats.datagram_drops.datagrams, 0,
        "select loop server should not drop datagrams"
    );

    // Keep the connection alive until the peer closes to avoid aborting in-flight streams.
    let _ = conn.closed().await;
}

async fn run_select_loop_client(
    client_marker: u8,
    server_addr: SocketAddr,
    chain: Arc<Vec<CertificateDer<'static>>>,
) {
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("select client ep");
    client.set_default_client_config(client_config(chain.as_slice()));

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("select client start connect");
    let conn = timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .expect("select client connect timeout")
        .expect("select client connect failed");

    send_client_datagrams(&conn, client_marker);

    for seq in 0..STREAM_MESSAGES_PER_CLIENT {
        let (mut send, mut recv) = conn.open_bi().await.expect("select client open_bi");
        let payload = format!("client-{client_marker}-stream-{seq}");
        timeout(DATAGRAM_TIMEOUT, send.write_all(payload.as_bytes()))
            .await
            .expect("select client stream write timeout")
            .expect("select client stream write failed");
        send.finish().expect("select client finish stream");

        let mut buf = [0u8; 64];
        let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
            .await
            .expect("select client stream read timeout")
            .expect("select client stream read failed")
            .expect("select client stream closed early");
        let response = std::str::from_utf8(&buf[..len]).expect("valid UTF-8 response");
        assert_eq!(
            response,
            format!("server-ack-{client_marker}-{seq}"),
            "select client received mismatched ack"
        );
    }

    let stats = conn.stats();
    assert_eq!(
        stats.datagram_drops.datagrams, 0,
        "select client should not see datagram drops"
    );

    conn.close(VarInt::from_u32(0), b"done-select");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_bi_cancellation_is_safe() {
    let (server, server_addr, chain) = make_server().await;
    let chain = Arc::new(chain);

    let server_task = tokio::spawn(async move {
        run_server_with_cancellable_accept(server).await;
    });

    run_cancellation_client(server_addr, chain).await;

    server_task.await.expect("cancellation server panicked");
}

async fn run_server_with_cancellable_accept(endpoint: Endpoint) {
    let incoming = timeout(HANDSHAKE_TIMEOUT, endpoint.accept())
        .await
        .expect("cancellation server accept timeout")
        .expect("cancellation incoming connection");
    let conn = timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .expect("cancellation server handshake timeout")
        .expect("cancellation server handshake failed");

    handle_cancellable_accept_connection(conn).await;
}

async fn handle_cancellable_accept_connection(conn: Connection) {
    for seq in 0..STREAM_MESSAGES_PER_CLIENT {
        let (mut send, mut recv) = accept_with_cancellations(&conn).await;

        let mut buf = [0u8; 128];
        let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
            .await
            .expect("cancellation server stream read timeout")
            .expect("cancellation server stream read failed")
            .expect("cancellation server stream closed");
        let message = std::str::from_utf8(&buf[..len]).expect("valid UTF-8 message");
        assert!(
            message.contains(&format!("cancel-client-stream-{seq}")),
            "unexpected cancellation stream payload: {message}"
        );

        let response = format!("cancel-server-ack-{seq}");
        timeout(DATAGRAM_TIMEOUT, send.write_all(response.as_bytes()))
            .await
            .expect("cancellation server write timeout")
            .expect("cancellation server write failed");
        send.finish().expect("cancellation server finish stream");
    }

    let _ = conn.closed().await;
}

async fn accept_with_cancellations(conn: &Connection) -> (SendStream, RecvStream) {
    let mut cancellations = 0;
    loop {
        let fut = conn.accept_bi();
        tokio::pin!(fut);
        tokio::select! {
            res = &mut fut => {
                return res.expect("cancellation accept_bi result");
            }
            _ = sleep(SELECT_LOOP_SPIN_DELAY) => {
                cancellations += 1;
                if cancellations >= ACCEPT_CANCELLATIONS_PER_STREAM {
                    return conn.accept_bi().await.expect("accept after cancellations");
                }
            }
        }
    }
}

async fn run_cancellation_client(
    server_addr: SocketAddr,
    chain: Arc<Vec<CertificateDer<'static>>>,
) {
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("cancellation client ep");
    client.set_default_client_config(client_config(chain.as_slice()));

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("cancellation start connect");
    let conn = timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .expect("cancellation client connect timeout")
        .expect("cancellation client connect failed");

    for seq in 0..STREAM_MESSAGES_PER_CLIENT {
        sleep(Duration::from_millis(2)).await;
        let (mut send, mut recv) = conn.open_bi().await.expect("cancellation client open_bi");
        let payload = format!("cancel-client-stream-{seq}");
        timeout(DATAGRAM_TIMEOUT, send.write_all(payload.as_bytes()))
            .await
            .expect("cancellation client stream write timeout")
            .expect("cancellation client stream write failed");
        send.finish().expect("cancellation client finish stream");

        let mut buf = [0u8; 64];
        let len = timeout(DATAGRAM_TIMEOUT, recv.read(&mut buf))
            .await
            .expect("cancellation client read timeout")
            .expect("cancellation client read failed")
            .expect("cancellation client stream closed");
        let response = std::str::from_utf8(&buf[..len]).expect("valid UTF-8 cancel response");
        assert_eq!(
            response,
            format!("cancel-server-ack-{seq}"),
            "unexpected cancellation ack"
        );
    }

    conn.close(VarInt::from_u32(0), b"done-cancel-client");
}
