use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ops::RangeFrom,
    sync::{Arc, Mutex},
    thread,
};

use bencher::{benchmark_group, benchmark_main, Bencher};
use futures::StreamExt;
use http::{Request, Response, StatusCode};
use lazy_static::lazy_static;
use tokio::{
    io::AsyncWriteExt as _,
    runtime::{Builder, Runtime},
};
use tracing::{debug, error_span, span, Level};
use tracing_futures::Instrument as _;

use quinn::{ClientConfigBuilder, ServerConfigBuilder};
use quinn_h3::{self, client, server};

benchmark_group!(
    benches,
    throughput_1k,
    throughput_32k,
    throughput_64k,
    throughput_128k,
    throughput_1m
);
benchmark_main!(benches);

fn throughput_1k(bench: &mut Bencher) {
    throughput(bench, 1024)
}

fn throughput_32k(bench: &mut Bencher) {
    throughput(bench, 32 * 1024)
}

fn throughput_64k(bench: &mut Bencher) {
    throughput(bench, 64 * 1024)
}

fn throughput_128k(bench: &mut Bencher) {
    throughput(bench, 128 * 1024)
}

fn throughput_1m(bench: &mut Bencher) {
    throughput(bench, 1024 * 1024)
}

fn throughput(bench: &mut Bencher, frame_size: usize) {
    let _ = tracing_subscriber::fmt::try_init();

    let ctx = Context::new();

    let (addr, _) = ctx.spawn_server();
    let (client, mut runtime) = ctx.make_client(addr);
    let total_size = 10 * 1024 * 1024;

    bench.bytes = total_size as u64;

    bench.iter(|| {
        runtime.block_on(async { download(&client, frame_size, total_size).await });
    });
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
        // TODO: Let the OS choose a free port for us
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            PORTS.lock().unwrap().next().unwrap(),
        );
        let mut server = self.server_config.clone();
        server.listen(addr);
        debug!("server bind");
        let handle = thread::spawn(move || {
            let my_span = span!(Level::TRACE, "server");
            let _enter = my_span.enter();
            let mut runtime = rt();
            let handle = runtime.spawn(
                async move {
                    let mut incoming = server.build().unwrap();
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

lazy_static! {
    pub static ref PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
}
