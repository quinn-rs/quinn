use std::cell::RefCell;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::rc::Rc;

use criterion::{criterion_group, criterion_main, BatchSize, Benchmark, Criterion, Throughput};
use futures::{try_ready, Async, Future, Poll, Stream};
use tokio;

use quinn::{ClientConfigBuilder, Endpoint, NewStream, ReadError, RecvStream, ServerConfigBuilder};

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
    let (server_driver, _, server_incoming) = server.with_socket(server_sock).unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config.add_certificate_authority(cert).unwrap();
    client_config.enable_keylog();
    let mut client = Endpoint::builder();
    client.default_client_config(client_config.build());
    let (client_driver, client, _) = client
        .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(server_driver.map_err(|e| panic!("server driver failed: {}", e)));
    runtime.spawn(client_driver.map_err(|e| panic!("client driver failed: {}", e)));

    let runtime = Rc::new(RefCell::new(runtime));
    runtime
        .borrow_mut()
        .spawn(server_incoming.for_each(move |connecting| {
            connecting
                .and_then(|new_conn| {
                    tokio::runtime::current_thread::spawn(
                        new_conn
                            .driver
                            .map_err(|e| ignore_timeout("server connection driver", e)),
                    );
                    new_conn.streams.for_each(|stream| {
                        if let NewStream::Uni(recv) = stream {
                            ReadAllUnordered { stream: recv }.map_err(|e| panic!(e))
                        } else {
                            unreachable!("only benchmarking uni streams")
                        }
                    })
                })
                .map_err(|e| panic!("server connection establishment failed: {}", e))
        }));

    let new_conn = runtime
        .borrow_mut()
        .block_on(client.connect(&server_addr, "localhost").unwrap())
        .unwrap();
    let driver = new_conn.driver;
    let connection = new_conn.connection;

    runtime
        .borrow_mut()
        .spawn(driver.map_err(|e| ignore_timeout("client connection driver", e)));

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

struct ReadAllUnordered {
    stream: RecvStream,
}

impl Future for ReadAllUnordered {
    type Item = ();
    type Error = ReadError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match try_ready!(self.stream.poll_read_unordered()) {
                Some(_) => {}
                None => {
                    return Ok(Async::Ready(()));
                }
            }
        }
    }
}
