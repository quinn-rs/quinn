use super::{ClientConfigBuilder, Endpoint, NewStream, ServerConfigBuilder};
use futures::{FutureExt, StreamExt, TryFutureExt};
use slog::{Drain, Logger, KV};
use std::{
    fmt, io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
};
use tokio::runtime::current_thread::Runtime;

#[test]
fn drop_driver() {
    let mut runtime = Runtime::new().unwrap();
    let (_client, _streams) = pair(&mut runtime);
    mem::drop(runtime);
}

#[test]
fn drop_server() {
    let mut runtime = Runtime::new().unwrap();
    let (client, streams) = pair(&mut runtime);
    mem::drop(streams);
    match runtime.block_on(
        async {
            let mut stream =
                await!(client.open_uni()).map_err(crate::FinishError::ConnectionLost)?;
            await!(stream.finish())
        }
            .boxed()
            .compat(),
    ) {
        Ok(_) => panic!("unexpected success"),
        Err(crate::FinishError::ConnectionLost(crate::ConnectionError::ApplicationClosed {
            ..
        })) => {}
        Err(e) => panic!("{}", e),
    }
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
    let mut runtime = Runtime::new().unwrap();
    let (client, mut streams) = pair_bound_to(&mut runtime, client_addr, server_addr);
    runtime.spawn(
        async move {
            while let Some(stream) = await!(streams.next()) {
                await!(echo(stream));
            }
            Ok(())
        }
            .boxed()
            .compat(),
    );

    runtime
        .block_on(
            async {
                let mut stream = await!(client.open_bi()).expect("connection lost");
                await!(stream.send.write_all(b"foo")).expect("write error");
                await!(stream.send.finish()).expect("connection lost");
                let reply =
                    await!(stream.recv.read_to_end(usize::max_value())).expect("read error");
                assert_eq!(&reply[..], b"foo");
                await!(client.close(0, b"done"));
                let result: Result<(), ()> = Ok(());
                result
            }
                .boxed()
                .compat(),
        )
        .unwrap();
}

fn pair(runtime: &mut Runtime) -> (crate::Connection, crate::IncomingStreams) {
    pair_bound_to(
        runtime,
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    )
}

fn pair_bound_to(
    runtime: &mut Runtime,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> (crate::Connection, crate::IncomingStreams) {
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
    let (_, server_driver, mut server_incoming) = server.from_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    let mut client = Endpoint::new();
    client.logger(log.clone());
    client.default_client_config(client_config.build());
    let (client, client_driver, _) = client.bind(client_addr).unwrap();

    runtime.spawn(
        server_driver
            .map_err(|e| panic!("server driver failed: {}", e))
            .compat(),
    );
    runtime.spawn(
        client_driver
            .map_err(|e| panic!("client driver failed: {}", e))
            .compat(),
    );
    runtime
        .block_on(
            async {
                let client_hs = client.connect(&server_addr, "localhost").unwrap();
                let (client, _) = await!(client_hs.establish()).unwrap();
                let server_hs = await!(server_incoming.next()).unwrap();
                let (_, streams) = await!(server_hs.establish()).unwrap();
                let result: Result<_, ()> = Ok((client, streams));
                result
            }
                .boxed()
                .compat(),
        )
        .unwrap()
}

async fn echo(stream: NewStream) {
    match stream {
        NewStream::Bi(mut stream) => {
            let data = await!(stream.recv.read_to_end(usize::max_value())).unwrap();
            await!(stream.send.write_all(&data)).unwrap();
            await!(stream.send.finish()).unwrap();
        }
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
