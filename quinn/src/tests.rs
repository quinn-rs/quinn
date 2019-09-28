use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, str};

use futures::{future, FutureExt, StreamExt, TryFutureExt, TryStreamExt};
use slog::{o, Drain, Logger, KV};
use tokio;

use super::{
    ClientConfigBuilder, Endpoint, EndpointDriver, Incoming, NewConnection, NewStream,
    ServerConfigBuilder,
};

#[test]
fn handshake_timeout() {
    let mut client = Endpoint::builder();
    client.logger(logger());
    let (client_driver, client, _) = client
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
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
    let endpoint = Endpoint::builder();
    let (driver, endpoint, _) = endpoint
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(
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
    runtime.run().unwrap();
}

#[test]
fn drop_endpoint_driver() {
    let endpoint = Endpoint::builder();
    let (_, endpoint, _) = endpoint
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    assert!(endpoint
        .connect(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .is_err());
}

#[test]
fn close_endpoint() {
    let endpoint = Endpoint::builder();
    let (_driver, endpoint, incoming) = endpoint
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(incoming.for_each(|_| future::ready(())));
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
    );
    endpoint.close(0u32.into(), &[]);
    runtime.run().unwrap();
}

#[test]
fn local_addr() {
    let port = 56987;
    let (_, ep, _) = Endpoint::builder()
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .expect("Could not bind to localhost");
    assert_eq!(
        port,
        ep.local_addr()
            .expect("Could not obtain our local endpoint")
            .port()
    );
}

#[test]
fn read_after_close() {
    let (_, driver, endpoint, mut incoming) = endpoint();
    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(driver.unwrap_or_else(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(async move {
        let new_conn = incoming
            .next()
            .await
            .expect("endpoint")
            .await
            .expect("connection");
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let mut s = new_conn.connection.open_uni().await.unwrap();
        s.write_all(MSG).await.unwrap();
        s.finish().await.unwrap();
    });
    runtime.spawn(async move {
        let mut new_conn = endpoint
            .connect(&endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("connect");
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        tokio::timer::delay(Instant::now() + Duration::from_millis(100)).await;
        let stream = new_conn
            .streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream");
        let msg = stream
            .unwrap_uni()
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
    });

    runtime.run().unwrap();
}

/// Construct an endpoint suitable for connecting to itself
fn endpoint() -> (Logger, EndpointDriver, Endpoint, Incoming) {
    let mut endpoint = Endpoint::builder();

    let log = logger();
    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = crate::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
    let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.certificate(cert_chain, key).unwrap();
    endpoint.listen(server_config.build());

    let mut client_config = ClientConfigBuilder::default();
    client_config.logger(log.new(o!("side" => "Client")));
    client_config.add_certificate_authority(cert).unwrap();
    endpoint.default_client_config(client_config.build());
    endpoint.logger(log.new(o!("side" => "Server")));

    let (x, y, z) = endpoint
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    (log, x, y, z)
}

#[test]
fn zero_rtt() {
    let (log, driver, endpoint, incoming) = endpoint();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(driver.unwrap_or_else(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(incoming.take(2).for_each(|incoming| {
        let new_conn = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        tokio::runtime::current_thread::spawn(
            new_conn
                .streams
                .map_err(|_| ())
                .try_for_each(|x| {
                    x.unwrap_uni()
                        .read_to_end(usize::max_value())
                        .map_err(|_| ())
                        .map_ok(|msg| {
                            assert_eq!(msg, MSG);
                        })
                })
                .unwrap_or_else(|_| ()),
        );
        new_conn
            .connection
            .open_uni()
            .unwrap_or_else(|e| panic!("open_uni: {}", e))
            .then(|mut s| {
                async move {
                    s.write_all(MSG).await.expect("write");
                    s.finish().await.expect("finish");
                }
            })
    }));
    runtime.block_on(async {
        let NewConnection {
            driver,
            mut streams,
            ..
        } = endpoint
            .connect(&endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .into_0rtt()
            .err()
            .expect("0-RTT succeeded without keys")
            .await
            .expect("connect");

        tokio::runtime::current_thread::spawn(async move {
            // Buy time for the driver to process the server's NewSessionTicket
            tokio::timer::delay(Instant::now() + Duration::from_millis(100)).await;
            let stream = streams
                .next()
                .await
                .expect("incoming streams")
                .expect("missing stream")
                .unwrap_uni();
            let msg = stream
                .read_to_end(usize::max_value())
                .await
                .expect("read_to_end");
            assert_eq!(msg, MSG);
        });
        driver.unwrap_or_else(|_| ()).await
    });
    info!(log, "initial connection complete");
    let NewConnection {
        connection,
        driver,
        mut streams,
        ..
    } = endpoint
        .connect(&endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .ok()
        .expect("missing 0-RTT keys");
    runtime.spawn(
        connection
            .open_uni()
            .unwrap_or_else(|e| panic!("0-RTT open_uni: {}", e))
            .then(|mut s| {
                async move {
                    s.write_all(MSG).await.expect("0-RTT write");
                    s.finish().await.expect("0-RTT finish");
                }
            }),
    );
    // The connection won't implicitly close if we could still open new streams
    drop(connection);
    runtime.spawn(driver.unwrap_or_else(|_| ()));
    runtime.block_on(async move {
        let stream = streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream")
            .unwrap_uni();
        let msg = stream
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
    });

    // The endpoint driver won't finish if we could still create new connections
    drop(endpoint);

    runtime.run().unwrap();
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
    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    {
        // We don't use the `endpoint` helper here because we want two different endpoints with
        // different addresses.
        let log = logger();
        let mut server_config = ServerConfigBuilder::default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
        let cert = crate::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
        let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
        server_config.certificate(cert_chain, key).unwrap();

        let mut server = Endpoint::builder();
        server.logger(log.new(o!("side" => "Server")));
        server.listen(server_config.build());
        let server_sock = UdpSocket::bind(server_addr).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let (server_driver, _, mut server_incoming) = server.with_socket(server_sock).unwrap();

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();
        client_config.enable_keylog();
        let mut client = Endpoint::builder();
        client.logger(log.new(o!("side" => "Client")));
        client.default_client_config(client_config.build());
        let (client_driver, client, _) = client.bind(&client_addr).unwrap();

        runtime.spawn(server_driver.unwrap_or_else(|e| panic!("server driver failed: {}", e)));
        runtime.spawn(client_driver.unwrap_or_else(|e| panic!("client driver failed: {}", e)));
        runtime.spawn(async move {
            let incoming = server_incoming.next().await.unwrap();
            let new_conn = incoming.await.unwrap();
            tokio::spawn(
                new_conn
                    .streams
                    .take_while(|x| future::ready(x.is_ok()))
                    .for_each(|s| echo(s.unwrap())),
            );
            new_conn.driver.unwrap_or_else(|_| ()).await
        });

        info!(log, "connecting from {} to {}", client_addr, server_addr);
        runtime.block_on(async move {
            let new_conn = client
                .connect(&server_addr, "localhost")
                .unwrap()
                .await
                .expect("connect");
            tokio::spawn(
                new_conn
                    .driver
                    .unwrap_or_else(|e| eprintln!("outgoing connection lost: {}", e)),
            );
            let (mut send, recv) = new_conn.connection.open_bi().await.expect("stream open");
            send.write_all(b"foo").await.expect("write");
            send.finish().await.expect("finish");
            let data = recv.read_to_end(usize::max_value()).await.expect("read");
            assert_eq!(&data[..], b"foo");
            new_conn.connection.close(0u32.into(), b"done");
        });
    }
    runtime.run().unwrap();
}

async fn echo(stream: NewStream) {
    let (mut send, recv) = stream.unwrap_bi();
    let data = recv
        .read_to_end(usize::max_value())
        .await
        .expect("read_to_end");
    send.write_all(&data).await.expect("send");
    let _ = send.finish().await;
}

fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

struct TestDrain;

impl Drain for TestDrain {
    type Ok = ();
    type Err = io::Error;
    fn log(&self, record: &slog::Record<'_>, values: &slog::OwnedKVList) -> Result<(), io::Error> {
        let mut vals = Vec::new();
        values.serialize(&record, &mut TestSerializer(&mut vals))?;
        record
            .kv()
            .serialize(&record, &mut TestSerializer(&mut vals))?;
        println!(
            "{} {}{}",
            record.level(),
            record.msg(),
            str::from_utf8(&vals).unwrap()
        );
        Ok(())
    }
}

struct TestSerializer<'a, W>(&'a mut W);

impl<'a, W> slog::Serializer for TestSerializer<'a, W>
where
    W: io::Write + 'a,
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        write!(self.0, ", {}: {}", key, val).unwrap();
        Ok(())
    }
}
