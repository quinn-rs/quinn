use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, io, str};

use futures::{Future, Stream};
use slog::{o, Drain, Logger, KV};
use tokio;

use super::{read_to_end, ClientConfigBuilder, Endpoint, NewStream, ServerConfigBuilder};

#[test]
fn handshake_timeout() {
    let client = Endpoint::new();
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
                    &client_config,
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
    let endpoint = Endpoint::new();
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
                Err(crate::ConnectionError::TransportError(quinn_proto::TransportError {
                    code: quinn_proto::TransportErrorCode::INTERNAL_ERROR,
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
fn close_endpoint() {
    let endpoint = Endpoint::new();
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
    let (_, ep, _) = Endpoint::new()
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
#[cfg(any(target_os = "linux"))] // Dual-stack sockets aren't the default anywhere else.
fn echo_dualstack() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

fn run_echo(client_addr: SocketAddr, server_addr: SocketAddr) {
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    {
        let log = logger();
        let mut server_config = ServerConfigBuilder::default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
        let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
        let cert = crate::Certificate::from_der(&cert.serialize_der()).unwrap();
        let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
        server_config.certificate(cert_chain, key).unwrap();

        let mut server = Endpoint::new();
        server.logger(log.new(o!("side" => "Server")));
        server.listen(server_config.build());
        let server_sock = UdpSocket::bind(server_addr).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let (server_driver, _, server_incoming) = server.from_socket(server_sock).unwrap();

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();
        client_config.enable_keylog();
        let mut client = Endpoint::new();
        client.logger(log.new(o!("side" => "Client")));
        client.default_client_config(client_config.build());
        let (client_driver, client, _) = client.bind(client_addr).unwrap();

        runtime.spawn(server_driver.map_err(|e| panic!("server driver failed: {}", e)));
        runtime.spawn(client_driver.map_err(|e| panic!("client driver failed: {}", e)));
        runtime.spawn(
            server_incoming
                .into_future()
                .map(move |(conn, _)| {
                    let (conn_driver, _, incoming_streams) = conn.unwrap();
                    tokio::spawn(conn_driver.map_err(|_| ()));
                    tokio::spawn(incoming_streams.map_err(|_| ()).for_each(echo));
                })
                .map_err(|_| ()),
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
                            .and_then(move |stream| {
                                tokio::io::write_all(stream, b"foo".to_vec())
                                    .map_err(|e| panic!("write: {}", e))
                            })
                            .and_then(|(stream, _)| {
                                tokio::io::shutdown(stream).map_err(|e| panic!("finish: {}", e))
                            })
                            .and_then(move |stream| {
                                read_to_end(stream, usize::max_value())
                                    .map_err(|e| panic!("read: {}", e))
                            })
                            .map(move |(_, data)| {
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
    match stream {
        NewStream::Bi(stream) => tokio::io::read_to_end(stream, Vec::new())
            .and_then(|(stream, data)| tokio::io::write_all(stream, data))
            .and_then(|(stream, _)| tokio::io::shutdown(stream))
            .map_err(|_| ())
            .map(|_| ()),
        _ => panic!("only bidi streams allowed"),
    }
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
