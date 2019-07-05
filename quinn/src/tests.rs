use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, str};

use futures::{Future, Stream};
use slog::{o, Drain, Logger, KV};
use tokio;

use super::{
    ClientConfigBuilder, Endpoint, EndpointDriver, Incoming, NewStream, ServerConfigBuilder,
};

#[test]
fn handshake_timeout() {
    let client = Endpoint::builder();
    let (client_driver, client, _) = client
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.spawn(client_driver.map_err(|e| panic!("client endpoint driver failed: {}", e)));

    let mut client_config = crate::ClientConfig::default();
    const IDLE_TIMEOUT: u64 = 1_000;
    client_config.transport = Arc::new(crate::TransportConfig {
        idle_timeout: IDLE_TIMEOUT,
        ..Default::default()
    });

    let start = Instant::now();
    runtime
        .block_on(
            client
                .connect_with(
                    client_config,
                    &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                    "localhost",
                )
                .unwrap()
                .then(|x| -> Result<(), ()> {
                    match x {
                        Err(crate::ConnectionError::TimedOut) => {}
                        Err(e) => panic!("unexpected error: {:?}", e),
                        Ok(_) => panic!("unexpected success"),
                    }
                    Ok(())
                }),
        )
        .unwrap();
    let dt = start.elapsed();
    assert!(
        dt > Duration::from_millis(IDLE_TIMEOUT) && dt < 2 * Duration::from_millis(IDLE_TIMEOUT)
    );
}

#[test]
fn drop_endpoint() {
    let endpoint = Endpoint::builder();
    let (driver, endpoint, _) = endpoint
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(
        endpoint
            .connect(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                "localhost",
            )
            .unwrap()
            .then(|x| match x {
                Err(crate::ConnectionError::TransportError(proto::TransportError {
                    code: proto::TransportErrorCode::INTERNAL_ERROR,
                    ..
                })) => Ok(()),
                Err(e) => panic!("unexpected error: {}", e),
                Ok(_) => {
                    panic!("unexpected success");
                }
            }),
    );

    let _ = (endpoint, driver);
    runtime.run().unwrap();
}

#[test]
fn drop_endpoint_driver() {
    let endpoint = Endpoint::builder();
    let (_, endpoint, _) = endpoint
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
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
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(incoming.for_each(|_| Ok(())).map_err(|_| ()));
    runtime.spawn(
        endpoint
            .connect(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                "localhost",
            )
            .unwrap()
            .then(|x| match x {
                Err(crate::ConnectionError::LocallyClosed) => Ok(()),
                Err(e) => panic!("unexpected error: {}", e),
                Ok(_) => {
                    panic!("unexpected success");
                }
            }),
    );
    endpoint.close(0, &[]);
    runtime.run().unwrap();
}

#[test]
fn local_addr() {
    let port = 56987;
    let (_, ep, _) = Endpoint::builder()
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
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
    let (_, driver, endpoint, incoming) = endpoint();
    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(driver.map_err(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(
        incoming
            .take(1)
            .and_then(|incoming| incoming.map_err(|_| ()))
            .for_each(|(driver, conn, _)| {
                tokio::runtime::current_thread::spawn(driver.map_err(|_| ()));
                conn.open_uni()
                    .map_err(|e| panic!("open_uni: {}", e))
                    .and_then(|s| {
                        tokio::io::write_all(s, MSG.to_vec())
                            .map_err(|e| panic!("write: {}", e))
                            .and_then(|(s, _)| s.finish().map_err(|e| panic!("finish: {}", e)))
                    })
            }),
    );
    runtime.spawn(
        endpoint
            .connect(&endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .map_err(|e| panic!("connect: {}", e))
            .and_then(|(driver, _, streams)| {
                tokio::runtime::current_thread::spawn(driver.map_err(|_| ()));
                tokio::timer::Delay::new(Instant::now() + Duration::from_millis(100))
                    .map_err(|_| unreachable!())
                    .and_then(move |()| {
                        streams
                            .into_future()
                            .map_err(|(e, _)| panic!("incoming streams: {}", e))
                            .and_then(|(stream, _)| {
                                stream
                                    .expect("missing stream")
                                    .unwrap_uni()
                                    .read_to_end(usize::max_value())
                                    .map_err(|e| panic!("read_to_end: {}", e))
                                    .map(|msg| {
                                        assert_eq!(msg, MSG);
                                    })
                            })
                    })
            }),
    );
    // The endpoint driver won't finish if we could still create new connections
    drop(endpoint);

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
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    (log, x, y, z)
}

#[test]
fn zero_rtt() {
    let (log, driver, endpoint, incoming) = endpoint();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(driver.map_err(|e| panic!("{}", e)));
    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(incoming.take(2).for_each(|incoming| {
        let (driver, conn, streams) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
        tokio::runtime::current_thread::spawn(driver.map_err(|_| ()));
        tokio::runtime::current_thread::spawn(streams.map_err(|_| ()).for_each(|x| {
            x.unwrap_uni()
                .read_to_end(usize::max_value())
                .map_err(|_| ())
                .map(|msg| {
                    assert_eq!(msg, MSG);
                })
        }));
        conn.open_uni()
            .map_err(|e| panic!("open_uni: {}", e))
            .and_then(|s| {
                tokio::io::write_all(s, MSG.to_vec())
                    .map_err(|e| panic!("write: {}", e))
                    .and_then(|(s, _)| s.finish().map_err(|e| panic!("finish: {}", e)))
            })
    }));
    runtime
        .block_on(
            endpoint
                .connect(&endpoint.local_addr().unwrap(), "localhost")
                .unwrap()
                .into_0rtt()
                .err()
                .expect("0-RTT succeeded without keys")
                .map_err(|e| panic!("connect: {}", e))
                .and_then(|(driver, _, streams)| {
                    tokio::runtime::current_thread::spawn(
                        // Buy time for the driver to process the server's NewSessionTicket
                        tokio::timer::Delay::new(Instant::now() + Duration::from_millis(100))
                            .map_err(|_| unreachable!())
                            .and_then(|()| {
                                streams
                                    .into_future()
                                    .map_err(|(e, _)| panic!("incoming streams: {}", e))
                                    .and_then(|(stream, _)| {
                                        stream
                                            .expect("missing stream")
                                            .unwrap_uni()
                                            .read_to_end(usize::max_value())
                                            .map_err(|e| panic!("read_to_end: {}", e))
                                            .map(|msg| {
                                                assert_eq!(msg, MSG);
                                            })
                                    })
                            }),
                    );
                    driver.then(|_| Ok(()))
                }),
        )
        .unwrap();
    info!(log, "initial connection complete");
    let (driver, conn, streams) = endpoint
        .connect(&endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .ok()
        .expect("missing 0-RTT keys");
    runtime.spawn(
        conn.open_uni()
            .map_err(|e| panic!("0-RTT open_uni: {}", e))
            .and_then(|s| {
                tokio::io::write_all(s, MSG.to_vec())
                    .map_err(|e| panic!("0-RTT write: {}", e))
                    .and_then(|(s, _)| s.finish().map_err(|e| panic!("0-RTT finish: {}", e)))
            }),
    );
    // The connection won't implicitly close if we could still open new streams
    drop(conn);
    runtime.spawn(driver.map_err(|_| ()));
    runtime
        .block_on(
            streams
                .into_future()
                .map_err(|(e, _)| panic!("incoming streams: {}", e))
                .and_then(|(stream, _)| {
                    stream
                        .expect("missing stream")
                        .unwrap_uni()
                        .read_to_end(usize::max_value())
                        .map_err(|e| panic!("read_to_end: {}", e))
                        .map(|msg| {
                            assert_eq!(msg, MSG);
                        })
                }),
        )
        .unwrap();

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
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
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
        let (server_driver, _, server_incoming) = server.with_socket(server_sock).unwrap();

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();
        client_config.enable_keylog();
        let mut client = Endpoint::builder();
        client.logger(log.new(o!("side" => "Client")));
        client.default_client_config(client_config.build());
        let (client_driver, client, _) = client.bind(client_addr).unwrap();

        runtime.spawn(server_driver.map_err(|e| panic!("server driver failed: {}", e)));
        runtime.spawn(client_driver.map_err(|e| panic!("client driver failed: {}", e)));
        runtime.spawn(
            server_incoming
                .and_then(|connect| connect.map_err(|_| ()))
                .into_future()
                .map_err(|_| ())
                .map(move |(conn, _)| {
                    let (conn_driver, _, incoming_streams) = conn.unwrap();
                    tokio::spawn(conn_driver.map_err(|_| ()));
                    tokio::spawn(incoming_streams.map_err(|_| ()).for_each(echo));
                }),
        );

        info!(log, "connecting from {} to {}", client_addr, server_addr);
        runtime
            .block_on(
                client
                    .connect(&server_addr, "localhost")
                    .unwrap()
                    .map_err(|e| panic!("connection failed: {}", e))
                    .and_then(move |(conn_driver, conn, _)| {
                        tokio::spawn(
                            conn_driver.map_err(|e| eprintln!("outgoing connection lost: {}", e)),
                        );
                        let stream = conn.open_bi();
                        stream
                            .map_err(|_| ())
                            .and_then(move |(send, recv)| {
                                tokio::io::write_all(send, b"foo".to_vec())
                                    .map_err(|e| panic!("write: {}", e))
                                    .and_then(move |_| {
                                        // Rely on send being implicitly finished when we drop it
                                        recv.read_to_end(usize::max_value())
                                            .map_err(|e| panic!("read: {}", e))
                                    })
                            })
                            .map(move |data| {
                                assert_eq!(&data[..], b"foo");
                                conn.close(0, b"done");
                            })
                    }),
            )
            .unwrap();
    }
    runtime.shutdown_on_idle().wait().unwrap();
}

fn echo(stream: NewStream) -> impl Future<Item = (), Error = ()> {
    let (send, recv) = stream.unwrap_bi();
    tokio::io::copy(recv, send)
        .and_then(|(_, _, send)| tokio::io::shutdown(send))
        .map_err(|_| ())
        .map(|_| ())
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
