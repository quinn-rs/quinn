#![feature(await_macro, async_await, futures_api)]

use criterion::{criterion_group, criterion_main, BatchSize, Benchmark, Criterion, Throughput};
use futures::{FutureExt, StreamExt, TryFutureExt};
use quinn::{ClientConfigBuilder, Endpoint, NewStream, ServerConfigBuilder};
use std::cell::RefCell;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::rc::Rc;
use tokio;

criterion_group!(benches, throughput);
criterion_main!(benches);

fn throughput(c: &mut Criterion) {
    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
    let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = quinn::Certificate::from_der(&cert.serialize_der()).unwrap();
    let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.certificate(cert_chain, key).unwrap();

    let mut server = Endpoint::new();
    server.listen(server_config.build());
    let server_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let (_, server_driver, mut server_incoming) = server.from_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    let mut client = Endpoint::new();
    client.default_client_config(client_config.build());
    let (client, client_driver, _) = client
        .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
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

    runtime.spawn(
        async move {
            let conn = await!(server_incoming.next()).unwrap();
            let (_, mut incoming) = await!(conn.establish()).unwrap();
            let mut buf = [0; 4096];
            while let Some(stream) = await!(incoming.next()) {
                let mut stream = if let NewStream::Uni(recv) = stream {
                    recv
                } else {
                    unreachable!("only benchmarking uni streams")
                };
                loop {
                    match await!(stream.read(&mut buf)) {
                        Ok(_) => {}
                        Err(quinn::ReadError::Finished) => {
                            break;
                        }
                        Err(e) => unreachable!(e),
                    }
                }
            }
            Ok(())
        }
            .boxed()
            .compat(),
    );

    let (conn, _) = runtime
        .block_on(
            async {
                let conn = client.connect(&server_addr, "localhost").unwrap();
                await!(conn.establish())
            }
                .boxed()
                .compat(),
        )
        .unwrap();

    const DATA: &[u8] = &[0xAB; 128 * 1024];
    let runtime = Rc::new(RefCell::new(runtime));
    c.bench(
        "throughput",
        Benchmark::new("128k", move |b| {
            b.iter_batched(
                || {
                    runtime
                        .borrow_mut()
                        .block_on(conn.open_uni().boxed().compat())
                        .unwrap()
                },
                |mut stream| {
                    runtime
                        .borrow_mut()
                        .block_on(
                            async {
                                await!(stream.write_all(DATA)).unwrap();
                                await!(stream.finish()).unwrap();
                                let result: Result<(), ()> = Ok(());
                                result
                            }
                                .boxed()
                                .compat(),
                        )
                        .unwrap()
                },
                BatchSize::PerIteration,
            )
        })
        .throughput(Throughput::Bytes(DATA.len() as u32)),
    );
}
