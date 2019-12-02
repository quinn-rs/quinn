use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
    sync::Arc,
};

use futures::{future, FutureExt, StreamExt, TryFutureExt};
use tokio::{
    runtime::{Builder, Runtime},
    time::{Duration, Instant},
};
use tracing::{info, info_span};
use tracing_futures::Instrument as _;

use super::{
    ClientConfigBuilder, Endpoint, EndpointDriver, Incoming, NewConnection, RecvStream, SendStream,
    ServerConfigBuilder,
};

#[test]
fn handshake_timeout() {
    let _guard = subscribe();
    let mut runtime = rt_threaded();
    let (client_driver, client, _) = runtime.enter(|| {
        Endpoint::builder()
            .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap()
    });

    runtime.spawn(client_driver.unwrap_or_else(|e| panic!("client endpoint driver failed: {}", e)));

    let mut client_config = crate::ClientConfig::default();
    const IDLE_TIMEOUT: u64 = 500;
    client_config.transport = Arc::new(crate::TransportConfig {
        idle_timeout: IDLE_TIMEOUT,
        initial_rtt: 10_000, // Ensure initial PTO doesn't influence the timeout significantly
        ..Default::default()
    });

    let start = Instant::now();
    runtime.block_on(async move {
        match client
            .connect_with(
                client_config,
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                "localhost",
            )
            .unwrap()
            .await
        {
            Err(crate::ConnectionError::TimedOut) => {}
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => panic!("unexpected success"),
        }
    });
    let dt = start.elapsed();
    assert!(
        dt > Duration::from_millis(IDLE_TIMEOUT) && dt < 2 * Duration::from_millis(IDLE_TIMEOUT)
    );
}

#[test]
fn drop_endpoint() {
    let _guard = subscribe();
    let mut runtime = rt_basic();
    let (driver, endpoint, _) = runtime.enter(|| {
        Endpoint::builder()
            .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap()
    });

    let handle = runtime.spawn(
        endpoint
            .connect(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                "localhost",
            )
            .unwrap()
            .map(|x| match x {
                Err(crate::ConnectionError::TransportError(proto::TransportError {
                    code: proto::TransportErrorCode::INTERNAL_ERROR,
                    ..
                })) => {}
                Err(e) => panic!("unexpected error: {}", e),
                Ok(_) => {
                    panic!("unexpected success");
                }
            }),
    );

    drop((driver, endpoint));
    runtime.block_on(handle).unwrap();
}

#[test]
fn drop_endpoint_driver() {
    let _guard = subscribe();
    let endpoint = Endpoint::builder();
    let runtime = rt_basic();
    let (_, endpoint, _) = runtime.enter(|| {
        endpoint
            .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap()
    });

    assert!(endpoint
        .connect(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .is_err());
}

#[test]
fn close_endpoint() {
    let _guard = subscribe();
    let endpoint = Endpoint::builder();
    let mut runtime = rt_basic();
    let (_driver, endpoint, incoming) = runtime.enter(|| {
        endpoint
            .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap()
    });

    let handle = runtime.spawn(incoming.for_each(|_| future::ready(())));
    let handle = future::join(
        handle,
        runtime.spawn(
            endpoint
                .connect(
                    &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                    "localhost",
                )
                .unwrap()
                .map(|x| match x {
                    Err(crate::ConnectionError::LocallyClosed) => (),
                    Err(e) => panic!("unexpected error: {}", e),
                    Ok(_) => {
                        panic!("unexpected success");
                    }
                }),
        ),
    );
    endpoint.close(0u32.into(), &[]);
    let (r1, r2) = runtime.block_on(handle);
    r1.unwrap();
    r2.unwrap();
}

#[test]
fn local_addr() {
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let runtime = rt_basic();
    let (_, ep, _) = runtime.enter(|| Endpoint::builder().with_socket(socket).unwrap());
    assert_eq!(
        addr,
        ep.local_addr()
            .expect("Could not obtain our local endpoint")
    );
}

#[test]
fn read_after_close() {
    let _guard = subscribe();
    let mut runtime = rt_basic();
    let (driver, endpoint, mut incoming) = runtime.enter(|| endpoint());
    runtime.spawn(driver.unwrap_or_else(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(async move {
        let new_conn = incoming
            .next()
            .await
            .expect("endpoint")
            .await
            .expect("connection");
        tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let mut s = new_conn.connection.open_uni().await.unwrap();
        s.write_all(MSG).await.unwrap();
        s.finish().await.unwrap();
    });
    runtime.block_on(async move {
        let mut new_conn = endpoint
            .connect(&endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("connect");
        tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        tokio::time::delay_until(Instant::now() + Duration::from_millis(100)).await;
        let stream = new_conn
            .uni_streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream");
        let msg = stream
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
    });
}

/// Construct an endpoint suitable for connecting to itself
fn endpoint() -> (EndpointDriver, Endpoint, Incoming) {
    let mut endpoint = Endpoint::builder();

    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = crate::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
    let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.certificate(cert_chain, key).unwrap();
    endpoint.listen(server_config.build());

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    endpoint.default_client_config(client_config.build());

    let (x, y, z) = endpoint
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    (x, y, z)
}

#[test]
fn zero_rtt() {
    let _guard = subscribe();
    let mut runtime = rt_basic();
    let (driver, endpoint, incoming) = runtime.enter(|| endpoint());

    runtime.spawn(driver.unwrap_or_else(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(incoming.take(2).for_each(|incoming| {
        async {
            let NewConnection {
                driver,
                mut uni_streams,
                connection,
                ..
            } = incoming.into_0rtt().unwrap_or_else(|_| unreachable!()).0;
            tokio::spawn(driver.unwrap_or_else(|_| ()));
            tokio::spawn(async move {
                while let Some(Ok(x)) = uni_streams.next().await {
                    let msg = x.read_to_end(usize::max_value()).await.unwrap();
                    assert_eq!(msg, MSG);
                }
            });
            let mut s = connection.open_uni().await.expect("open_uni");
            s.write_all(MSG).await.expect("write");
            s.finish().await.expect("finish");
        }
    }));
    runtime.block_on(async {
        let NewConnection {
            driver,
            mut uni_streams,
            ..
        } = endpoint
            .connect(&endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .into_0rtt()
            .err()
            .expect("0-RTT succeeded without keys")
            .await
            .expect("connect");

        tokio::spawn(async move {
            // Buy time for the driver to process the server's NewSessionTicket
            tokio::time::delay_until(Instant::now() + Duration::from_millis(100)).await;
            let stream = uni_streams
                .next()
                .await
                .expect("incoming streams")
                .expect("missing stream");
            let msg = stream
                .read_to_end(usize::max_value())
                .await
                .expect("read_to_end");
            assert_eq!(msg, MSG);
        });
        driver.unwrap_or_else(|_| ()).await
    });
    info!("initial connection complete");
    let (
        NewConnection {
            connection,
            driver,
            mut uni_streams,
            ..
        },
        zero_rtt,
    ) = endpoint
        .connect(&endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .ok()
        .expect("missing 0-RTT keys");
    // Send something before the driver starts to ensure it's 0-RTT
    runtime.spawn(async move {
        let mut s = connection.open_uni().await.expect("0-RTT open uni");
        s.write_all(MSG).await.expect("0-RTT write");
        s.finish().await.expect("0-RTT finish");
    });
    let handle = runtime.spawn(driver.unwrap_or_else(|_| ()));
    runtime.block_on(async move {
        let stream = uni_streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream");
        let msg = stream
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
        assert_eq!(zero_rtt.await, true);
    });

    // The endpoint driver won't finish if we could still create new connections
    drop(endpoint);

    runtime.block_on(handle).unwrap();
}

#[test]
fn echo_v6() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    );
}

#[test]
fn echo_v4() {
    run_echo(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))] // Dual-stack sockets aren't the default anywhere else.
fn echo_dualstack() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

fn run_echo(client_addr: SocketAddr, server_addr: SocketAddr) {
    let _guard = subscribe();
    let mut runtime = rt_basic();
    let handle = {
        // We don't use the `endpoint` helper here because we want two different endpoints with
        // different addresses.
        let mut server_config = ServerConfigBuilder::default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
        let cert = crate::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
        let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
        server_config.certificate(cert_chain, key).unwrap();

        let mut server = Endpoint::builder();
        server.listen(server_config.build());
        let server_sock = UdpSocket::bind(server_addr).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let (server_driver, _, mut server_incoming) =
            runtime.enter(|| server.with_socket(server_sock).unwrap());

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();
        client_config.enable_keylog();
        let mut client = Endpoint::builder();
        client.default_client_config(client_config.build());
        let (client_driver, client, _) = runtime.enter(|| client.bind(&client_addr).unwrap());

        let handle = runtime.spawn(
            server_driver
                .unwrap_or_else(|e| panic!("server driver failed: {}", e))
                .instrument(info_span!("server endpoint")),
        );
        let handle = future::join(
            handle,
            runtime.spawn(
                client_driver
                    .unwrap_or_else(|e| panic!("client driver failed: {}", e))
                    .instrument(info_span!("client endpoint")),
            ),
        );
        let handle = future::join(
            handle,
            runtime.spawn(async move {
                let incoming = server_incoming.next().await.unwrap();
                let new_conn = incoming.instrument(info_span!("server")).await.unwrap();
                tokio::spawn(
                    new_conn
                        .bi_streams
                        .take_while(|x| future::ready(x.is_ok()))
                        .for_each(|s| echo(s.unwrap())),
                );
                new_conn
                    .driver
                    .unwrap_or_else(|_| ())
                    .instrument(info_span!("server"))
                    .await
            }),
        );

        info!("connecting from {} to {}", client_addr, server_addr);
        runtime.block_on(async move {
            let new_conn = client
                .connect(&server_addr, "localhost")
                .unwrap()
                .instrument(info_span!("client"))
                .await
                .expect("connect");
            tokio::spawn(
                new_conn
                    .driver
                    .unwrap_or_else(|e| eprintln!("outgoing connection lost: {}", e))
                    .instrument(info_span!("client")),
            );
            let (mut send, recv) = new_conn.connection.open_bi().await.expect("stream open");
            send.write_all(b"foo").await.expect("write");
            send.finish().await.expect("finish");
            let data = recv.read_to_end(usize::max_value()).await.expect("read");
            assert_eq!(&data[..], b"foo");
            new_conn.connection.close(0u32.into(), b"done");
        });
        handle
    };
    let ((r1, r2), r3) = runtime.block_on(handle);
    r1.unwrap();
    r2.unwrap();
    r3.unwrap();
}

async fn echo((mut send, recv): (SendStream, RecvStream)) {
    let data = recv
        .read_to_end(usize::max_value())
        .await
        .expect("read_to_end");
    send.write_all(&data).await.expect("send");
    let _ = send.finish().await;
}

pub fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter("quinn=trace")
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

fn rt_basic() -> Runtime {
    Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap()
}

fn rt_threaded() -> Runtime {
    Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap()
}
