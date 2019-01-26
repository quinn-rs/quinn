use super::{read_to_end, ClientConfigBuilder, Endpoint, NewStream, ServerConfigBuilder};
use futures::{Future, Stream};
use slog::{Drain, Logger, KV};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
};
use tokio;

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
#[cfg(target_os = "linux")] // Dual-stack sockets aren't the default anywhere else.
fn echo_dualstack() {
    run_echo(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
}

fn run_echo(client_addr: SocketAddr, server_addr: SocketAddr) {
    let log = logger();
    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
    let key = crate::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = crate::Certificate::from_der(&cert.serialize_der()).unwrap();
    let cert_chain = crate::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.certificate(cert_chain, key).unwrap();

    let mut server = Endpoint::new();
    server.logger(log.clone());
    server.listen(server_config.build());
    let server_sock = UdpSocket::bind(server_addr).unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let (_, server_driver, server_incoming) = server.from_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    let mut client = Endpoint::new();
    client.logger(log.clone());
    client.default_client_config(client_config.build());
    let (client, client_driver, _) = client.bind(client_addr).unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(server_driver.map_err(|e| panic!("server driver failed: {}", e)));
    runtime.spawn(client_driver.map_err(|e| panic!("client driver failed: {}", e)));
    runtime.spawn(server_incoming.for_each(move |conn| {
        tokio_current_thread::spawn(conn.incoming.map_err(|_| ()).for_each(echo));
        Ok(())
    }));

    info!(log, "connecting from {} to {}", client_addr, server_addr);
    runtime
        .block_on(
            client
                .connect(&server_addr, "localhost")
                .unwrap()
                .map_err(|e| panic!("connection failed: {}", e))
                .and_then(move |conn| {
                    let conn = conn.connection;
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
                        .and_then(move |(_, data)| {
                            assert_eq!(&data[..], b"foo");
                            conn.close(0, b"done").map_err(|_| unreachable!())
                        })
                }),
        )
        .unwrap();
}

fn echo(stream: NewStream) -> Box<dyn Future<Item = (), Error = ()>> {
    match stream {
        NewStream::Bi(stream) => Box::new(
            tokio::io::read_to_end(stream, Vec::new())
                .and_then(|(stream, data)| tokio::io::write_all(stream, data))
                .and_then(|(stream, _)| tokio::io::shutdown(stream))
                .map_err(|_| ())
                .map(|_| ()),
        ),
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
