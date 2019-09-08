use std::cell::RefCell;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::rc::Rc;

use criterion::{criterion_group, criterion_main, BatchSize, Benchmark, Criterion, Throughput};
use futures::{StreamExt, TryFutureExt};
use tokio;

use quinn::{ClientConfigBuilder, Endpoint, ReadError, RecvStream, ServerConfigBuilder};

criterion_group!(benches, throughput);
criterion_main!(benches);

fn throughput(c: &mut Criterion) {
    let mut server_config = ServerConfigBuilder::default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
    let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);
    server_config.certificate(cert_chain, key).unwrap();

    let mut server = Endpoint::builder();
    server.listen(server_config.build());
    let server_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let (server_driver, _, mut server_incoming) = server.with_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    client_config.enable_keylog();
    let mut client = Endpoint::builder();
    client.default_client_config(client_config.build());
    let (client_driver, client, _) = client
        .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(server_driver.unwrap_or_else(|e| panic!("server driver failed: {}", e)));
    runtime.spawn(client_driver.unwrap_or_else(|e| panic!("client driver failed: {}", e)));

    let runtime = Rc::new(RefCell::new(runtime));
    runtime.borrow_mut().spawn(async move {
        while let Some(connecting) = server_incoming.next().await {
            let mut new_conn = connecting.await.unwrap();
            tokio::runtime::current_thread::spawn(
                new_conn
                    .driver
                    .unwrap_or_else(|e| ignore_timeout("server connection driver", e)),
            );
            while let Some(Ok(stream)) = new_conn.uni_streams.next().await {
                read_all(stream).await.unwrap();
            }
        }
    });

    let new_conn = runtime
        .borrow_mut()
        .block_on(client.connect(&server_addr, "localhost").unwrap())
        .unwrap();
    let driver = new_conn.driver;
    let connection = new_conn.connection;

    runtime
        .borrow_mut()
        .spawn(driver.unwrap_or_else(|e| ignore_timeout("client connection driver", e)));

    {
        const DATA: &[u8] = &[0xAB; 128 * 1024];
        let runtime = runtime.clone();
        c.bench(
            "throughput",
            Benchmark::new("128kB", move |b| {
                b.iter_batched(
                    || {
                        runtime
                            .borrow_mut()
                            .block_on(connection.open_uni())
                            .expect("failed opening stream")
                    },
                    |mut stream| {
                        runtime.borrow_mut().block_on(async move {
                            stream.write_all(DATA).await.expect("write failed");
                            stream.finish().await.unwrap();
                        })
                    },
                    BatchSize::PerIteration,
                )
            })
            .throughput(Throughput::Bytes(DATA.len() as u64)),
        );
    }

    /*
        let (driver, connection, _) = runtime
            .borrow_mut()
            .block_on(client.connect(&server_addr, "localhost").unwrap())
            .unwrap();

        runtime
            .borrow_mut()
            .spawn(driver.map_err(|e| ignore_timeout("client connection driver", e)));

        {
            const DATA: &[u8] = &[0xAB; 32];
            let runtime = runtime.clone();
            c.bench(
                "throughput",
                Benchmark::new("32B", move |b| {
                    b.iter_batched(
                        || {
                            runtime
                                .borrow_mut()
                                .block_on(connection.open_uni())
                                .expect("failed opening stream")
                        },
                        |stream| {
                            runtime
                                .borrow_mut()
                                .block_on(
                                    tokio::io::write_all(stream, DATA)
                                        .map_err(|e| panic!("write to stream failed: {}", e))
                                        .and_then(|(stream, _)| {
                                            tokio::io::shutdown(stream).map_err(|e| {
                                                panic!("send stream shutdown failed: {}", e)
                                            })
                                        }),
                                )
                                .expect("failed writing data")
                        },
                        BatchSize::PerIteration,
                    )
                })
                .throughput(Throughput::Bytes(DATA.len() as u32)),
            );
        }
    */
}

fn ignore_timeout(ty: &'static str, e: quinn::ConnectionError) {
    use quinn::ConnectionError::*;
    match e {
        TimedOut => (),
        e => panic!("{} failed: {:?}", ty, e),
    }
}

async fn read_all(mut stream: RecvStream) -> Result<(), ReadError> {
    while let Some(_) = stream.read_unordered().await? {}
    Ok(())
}
