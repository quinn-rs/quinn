use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use futures::StreamExt;
use slog::Drain;
use tokio::runtime::current_thread::Runtime;

use quinn::{ClientConfigBuilder, Endpoint, ServerConfigBuilder};

criterion_group!(benches, throughput);
criterion_main!(benches);

fn throughput(c: &mut Criterion) {
    let ctx = Context::new();
    let mut group = c.benchmark_group("throughput");
    {
        let (addr, thread) = ctx.spawn_server();
        let (client, mut runtime) = ctx.make_client(addr);
        const DATA: &[u8] = &[0xAB; 128 * 1024];
        group.throughput(Throughput::Bytes(DATA.len() as u64));
        group.bench_function("large streams", |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let mut stream = client.open_uni().await.unwrap();
                    stream.write_all(DATA).await.unwrap();
                    stream.finish().await.unwrap();
                });
            })
        });
        drop(client);
        runtime.run().unwrap();
        thread.join().unwrap();
    }

    {
        let (addr, thread) = ctx.spawn_server();
        let (client, mut runtime) = ctx.make_client(addr);
        const DATA: &[u8] = &[0xAB; 32];
        group.throughput(Throughput::Elements(1));
        group.bench_function("small streams", |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let mut stream = client.open_uni().await.unwrap();
                    stream.write_all(DATA).await.unwrap();
                    stream.finish().await.unwrap();
                });
            })
        });
        drop(client);
        runtime.run().unwrap();
        thread.join().unwrap();
    }

    {
        let (addr, thread) = ctx.spawn_server();
        let (client, mut runtime) = ctx.make_client(addr);
        let data = Bytes::from(&[0xAB; 32][..]);
        group.throughput(Throughput::Elements(1));
        group.bench_function("small datagrams", |b| {
            b.iter(|| {
                runtime.block_on(async {
                    client.send_datagram(data.clone()).await.unwrap();
                });
            })
        });
        drop(client);
        runtime.run().unwrap();
        thread.join().unwrap();
    }

    group.finish();
}

struct Context {
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
    log: slog::Logger,
}

impl Context {
    fn new() -> Self {
        let decorator = slog_term::TermDecorator::new().stderr().build();
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        let drain = std::sync::Mutex::new(drain).fuse();
        let log = slog::Logger::root(drain, slog::o!());

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
        let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);

        let server_config = quinn::ServerConfig {
            transport: Arc::new(quinn::TransportConfig {
                stream_window_uni: 1024,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut server_config = ServerConfigBuilder::new(server_config);
        server_config.certificate(cert_chain, key).unwrap();

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();

        Self {
            server_config: server_config.build(),
            client_config: client_config.build(),
            log,
        }
    }

    pub fn spawn_server(&self) -> (SocketAddr, thread::JoinHandle<()>) {
        let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
        let addr = sock.local_addr().unwrap();
        let config = self.server_config.clone();
        let log = self.log.new(slog::o!("side" => "Server"));
        let handle = thread::spawn(move || {
            let mut endpoint = Endpoint::builder();
            endpoint.logger(log);
            endpoint.listen(config);
            let (driver, _, mut incoming) = endpoint.with_socket(sock).unwrap();
            let mut runtime = Runtime::new().unwrap();
            runtime.spawn(async { driver.await.unwrap() });
            runtime.spawn(async move {
                let quinn::NewConnection {
                    driver,
                    mut uni_streams,
                    ..
                } = incoming.next().await.unwrap().await.unwrap();
                tokio::spawn(async move {
                    match driver.await {
                        Ok(()) => panic!("unexpected success"),
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {}
                        Err(e) => panic!("{}", e),
                    }
                });
                while let Some(Ok(mut stream)) = uni_streams.next().await {
                    while let Some(_) = stream.read_unordered().await.unwrap() {}
                }
            });
            runtime.run().unwrap();
        });
        (addr, handle)
    }

    pub fn make_client(&self, server_addr: SocketAddr) -> (quinn::Connection, Runtime) {
        let mut endpoint = Endpoint::builder();
        endpoint.logger(self.log.new(slog::o!("side" => "Client")));
        let (endpoint_driver, endpoint, _) = endpoint
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .unwrap();
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(async move {
            endpoint_driver.await.unwrap();
        });
        let quinn::NewConnection {
            driver, connection, ..
        } = runtime
            .block_on(
                endpoint
                    .connect_with(self.client_config.clone(), &server_addr, "localhost")
                    .unwrap(),
            )
            .unwrap();
        runtime.spawn(async move {
            driver.await.unwrap();
        });
        (connection, runtime)
    }
}
