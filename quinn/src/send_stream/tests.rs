use std::{
    net::UdpSocket,
    sync::{Arc, Barrier},
    task::Waker,
    thread,
    time::Duration,
};

use super::*;
use crate::{ClientConfig, Connection, Endpoint, EndpointConfig, Runtime, ServerConfig};

async fn pair() -> (Endpoint, Connection, Connection) {
    pair_with_runtime(Arc::new(crate::runtime::TokioRuntime)).await
}

async fn pair_with_runtime(runtime: Arc<dyn Runtime>) -> (Endpoint, Connection, Connection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let server = ServerConfig::with_single_cert(vec![cert.cert.der().clone()], key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        runtime,
    )
    .unwrap();
    endpoint
        .set_default_client_config(ClientConfig::with_root_certificates(Arc::new(roots)).unwrap());
    let (client, server) = tokio::join!(
        endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { endpoint.accept().await.unwrap().await }
    );
    (endpoint, client.unwrap(), server.unwrap())
}

#[tokio::test]
async fn cancelled_stopped_does_not_retain_notifications() {
    let (_endpoint, connection, _peer) = pair().await;
    cancel_stopped_repeatedly(&connection).await;
}

async fn cancel_stopped_repeatedly(connection: &Connection) {
    for _ in 0..64 {
        let mut send = connection.open_uni().await.unwrap();
        let mut stopped = Box::pin(send.stopped());
        assert!(
            stopped
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(send.conn.state.lock("test").stopped.len(), 1);
        send.reset(0u32.into()).unwrap();
        drop(stopped);
        assert!(send.conn.state.lock("test").stopped.is_empty());
    }
}

#[cfg(feature = "runtime-smol")]
#[test]
fn cancelled_stopped_on_smol() {
    smol::block_on(async {
        let (_endpoint, connection, peer) = pair_with_runtime(Arc::new(crate::SmolRuntime)).await;
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(b"request").await.unwrap();
        let mut recv = peer.accept_uni().await.unwrap();
        let mut stopped = Box::pin(send.stopped());
        assert!(
            stopped
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        recv.stop(42u32.into()).unwrap();
        let result = smol::future::or(stopped, async {
            smol::Timer::after(Duration::from_secs(5)).await;
            panic!("stopped waiter was not woken on smol");
        })
        .await;
        assert_eq!(result.unwrap(), Some(42u32.into()));
        assert!(send.conn.state.lock("test").stopped.is_empty());
        smol::future::or(
            race_cancellation_with_registration(&connection, &peer),
            async {
                smol::Timer::after(Duration::from_secs(5)).await;
                panic!("notification was lost after racing registration on smol");
            },
        )
        .await;
        cancel_stopped_repeatedly(&connection).await;
        cancel_stopped_concurrently(&connection).await;
    });
}

#[tokio::test]
async fn repeated_wakeup_does_not_duplicate_registration() {
    let (_endpoint, connection, _peer) = pair().await;
    let send = connection.open_uni().await.unwrap();
    let mut stopped = Box::pin(send.stopped());
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16 {
        assert!(stopped.as_mut().poll(&mut cx).is_pending());
        let state = send.conn.state.lock("test");
        assert_eq!(Arc::strong_count(&state.stopped[&send.stream]), 2);
        state.stopped[&send.stream].notify_waiters();
    }
    drop(stopped);
    assert!(send.conn.state.lock("test").stopped.is_empty());
}

#[tokio::test]
async fn cancelling_one_stopped_waiter_preserves_another() {
    let (_endpoint, connection, peer) = pair().await;
    let mut send = connection.open_uni().await.unwrap();
    send.write_all(b"request").await.unwrap();
    let mut recv = peer.accept_uni().await.unwrap();
    let mut first = Box::pin(send.stopped());
    let mut second = Box::pin(send.stopped());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    drop(first);
    assert_eq!(send.conn.state.lock("test").stopped.len(), 1);
    recv.stop(42u32.into()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap(),
        Some(42u32.into())
    );
    assert!(send.conn.state.lock("test").stopped.is_empty());
}

#[tokio::test]
async fn concurrent_cancellations_remove_last_notification() {
    let (_endpoint, connection, _peer) = pair().await;
    cancel_stopped_concurrently(&connection).await;
}

async fn cancel_stopped_concurrently(connection: &Connection) {
    for _ in 0..32 {
        let send = connection.open_uni().await.unwrap();
        let mut first = Box::pin(send.stopped());
        let mut second = Box::pin(send.stopped());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            Arc::strong_count(&send.conn.state.lock("test").stopped[&send.stream]),
            3
        );

        let start = Barrier::new(3);
        thread::scope(|scope| {
            for waiter in [first, second] {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    drop(waiter);
                });
            }
            start.wait();
        });
        assert!(send.conn.state.lock("test").stopped.is_empty());
    }
}

#[tokio::test]
async fn cancellation_racing_registration_preserves_notification() {
    let (_endpoint, connection, peer) = pair().await;
    tokio::time::timeout(
        Duration::from_secs(5),
        race_cancellation_with_registration(&connection, &peer),
    )
    .await
    .unwrap();
}

async fn race_cancellation_with_registration(connection: &Connection, peer: &Connection) {
    let mut send = connection.open_uni().await.unwrap();
    send.write_all(b"request").await.unwrap();
    let mut recv = peer.accept_uni().await.unwrap();
    let mut stopped = Box::pin(send.stopped());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(stopped.as_mut().poll(&mut cx).is_pending());

    for _ in 0..32 {
        let previous = stopped;
        let mut replacement = Box::pin(send.stopped());
        let start = Barrier::new(2);
        thread::scope(|scope| {
            let start = &start;
            scope.spawn(move || {
                start.wait();
                drop(previous);
            });
            start.wait();
            assert!(replacement.as_mut().poll(&mut cx).is_pending());
        });
        assert_eq!(
            Arc::strong_count(&send.conn.state.lock("test").stopped[&send.stream]),
            2
        );
        stopped = replacement;
    }

    recv.stop(42u32.into()).unwrap();
    assert_eq!(stopped.await.unwrap(), Some(42u32.into()));
    assert!(send.conn.state.lock("test").stopped.is_empty());
}

#[tokio::test]
async fn old_stopped_registration_does_not_remove_replacement() {
    let (_endpoint, connection, _peer) = pair().await;
    let send = connection.open_uni().await.unwrap();
    let mut old = Box::pin(send.stopped());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(old.as_mut().poll(&mut cx).is_pending());
    // Model event delivery removing an entry before its old waiter is dropped.
    // A new registration must have independent ownership, even for the same ID.
    send.conn.state.lock("test").stopped.clear();
    let mut replacement = Box::pin(send.stopped());
    assert!(replacement.as_mut().poll(&mut cx).is_pending());
    drop(old);
    assert_eq!(send.conn.state.lock("test").stopped.len(), 1);
    drop(replacement);
    assert!(send.conn.state.lock("test").stopped.is_empty());
}

#[tokio::test]
async fn stopped_can_register_and_cancel_after_stream_is_dropped() {
    let (_endpoint, connection, _peer) = pair().await;
    let send = connection.open_uni().await.unwrap();
    let conn = send.conn.clone();
    let mut stopped = Box::pin(send.stopped());
    drop(send);
    assert!(
        stopped
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(conn.state.lock("test").stopped.len(), 1);
    drop(stopped);
    assert!(conn.state.lock("test").stopped.is_empty());
}

#[tokio::test]
async fn unpolled_stopped_does_not_register() {
    let (_endpoint, connection, _peer) = pair().await;
    let send = connection.open_uni().await.unwrap();
    let stopped = send.stopped();
    assert!(send.conn.state.lock("test").stopped.is_empty());
    drop(stopped);
    assert!(send.conn.state.lock("test").stopped.is_empty());
}
