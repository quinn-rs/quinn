use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    thread,
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use futures::StreamExt;
use http::{Request, Response, StatusCode};
use tokio::{
    io::AsyncWriteExt as _,
    runtime::{Builder, Runtime},
};
use tracing::{debug, error_span, span, Level};
use tracing_futures::Instrument as _;

use quinn::{ClientConfigBuilder, ServerConfigBuilder};
use quinn_h3::{self, client, server};

criterion_group!(benches_h3, throughput);
criterion_main!(benches_h3);

fn throughput(c: &mut Criterion) {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let ctx = Context::new();
    let mut group = c.benchmark_group("throughput");

    let (addr, _) = ctx.spawn_server();
    let (client, mut runtime) = ctx.make_client(addr);
    let total_size = 10 * 1024 * 1024;

    group.sample_size(10);
    group.throughput(Throughput::Bytes(total_size as u64));

    for frame_size in [1024, 65535 / 2, 65535, 128 * 1024, 1024 * 1024].iter() {
        group.bench_function(
            format!("download: {} by frames of {} ", total_size, frame_size),
            |b| {
                b.iter(|| {
                    runtime.block_on(async { download(&client, *frame_size, total_size).await })
                })
            },
        );
    }

    group.finish();
}

async fn download(client: &client::Connection, frame_size: usize, total_size: usize) {
    let (recv_resp, _) = client
        .send_request(
            Request::get("https://localhost/")
                .header("frame_size", format!("{}", frame_size))
                .header("total_size", format!("{}", total_size))
                .body(())
                .unwrap(),
        )
        .await
        .expect("request");
    let (_, mut body_reader) = recv_resp.await.expect("recv_resp");
    while let Some(Ok(_)) = body_reader.data().await {}
}

struct Context {
    server_config: server::Builder,
    client_config: client::Builder,
}

impl Context {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
        let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);

        let mut transport = quinn::TransportConfig::default();
        transport.stream_window_bidi(102_400);
        let mut server_config = quinn::ServerConfig::default();
        server_config.transport = Arc::new(transport);
        let mut server_config = ServerConfigBuilder::new(server_config);
        server_config.certificate(cert_chain, key).unwrap();

        let mut client_config = ClientConfigBuilder::default();
        client_config.add_certificate_authority(cert).unwrap();
        client_config.protocols(&[quinn_h3::ALPN]);

        Self {
            server_config: server::Builder::with_quic_config(server_config),
            client_config: client::Builder::with_quic_config(client_config),
        }
    }

    pub fn spawn_server(&self) -> (SocketAddr, thread::JoinHandle<()>) {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433);
        let server = self.server_config.clone();
        debug!("server bind");
        let handle = thread::spawn(move || {
            let my_span = span!(Level::TRACE, "server");
            let _enter = my_span.enter();
            let mut runtime = rt();
            let handle = runtime.spawn(
                async move {
                    let (_, mut incoming) = server.build().unwrap();
                    let mut incoming_req = incoming
                        .next()
                        .await
                        .expect("accept")
                        .await
                        .expect("connect");
                    debug!("recv incoming");
                    while let Some(recv_req) = incoming_req.next().await {
                        let (request, mut body_reader, sender) = recv_req.await.expect("recv_req");
                        while let Some(_) = body_reader.data().await {}

                        let mut body_writer = sender
                            .send_response(
                                Response::builder().status(StatusCode::OK).body(()).unwrap(),
                            )
                            .await
                            .expect("send_response");

                        let frame_size = request
                            .headers()
                            .get("frame_size")
                            .map(|x| x.to_str().unwrap().parse().expect("parse frame size"))
                            .expect("no frame size");
                        let mut remaining = request
                            .headers()
                            .get("total_size")
                            .map(|x| x.to_str().unwrap().parse().expect("parse total size"))
                            .expect("no total size");

                        let data = "a".repeat(frame_size);
                        while remaining > 0 {
                            let size = std::cmp::min(frame_size, remaining);
                            body_writer
                                .write_all(&data.as_bytes()[..size])
                                .await
                                .expect("body write");
                            remaining -= size;
                        }
                    }
                }
                .instrument(error_span!("server")),
            );
            runtime.block_on(handle).unwrap();
        });

        (addr, handle)
    }

    pub fn make_client(&self, server_addr: SocketAddr) -> (client::Connection, Runtime) {
        let mut runtime = rt();
        let my_span = span!(Level::TRACE, "client");
        let _enter = my_span.enter();
        let connection = runtime.block_on(async {
            self.client_config
                .clone()
                .build()
                .expect("client build")
                .connect(&server_addr, "localhost")
                .expect("connect build")
                .await
                .expect("connecting")
        });
        (connection, runtime)
    }
}

fn rt() -> Runtime {
    Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap()
}
