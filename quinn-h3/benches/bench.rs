use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    thread,
};

use bencher::{benchmark_group, benchmark_main, Bencher};
use futures::{channel::oneshot, StreamExt};
use http::{Request, Response, StatusCode};
use tokio::{
    io::AsyncWriteExt as _,
    runtime::{Builder, Runtime},
    select,
};
use tracing::{error_span, span, Level};
use tracing_futures::Instrument as _;

use quinn::{ClientConfigBuilder, ServerConfigBuilder};
use quinn_h3::{
    self, client,
    server::{self, IncomingConnection},
    BodyWriter,
};

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

    let mut ctx = Context::new();

    let (addr, server) = ctx.spawn_server();
    let (client, mut runtime) = ctx.make_client(addr);
    let total_size = 10 * 1024 * 1024;

    bench.bytes = total_size as u64;

    bench.iter(|| {
        runtime.block_on(async {
            download(&client, frame_size, total_size)
                .instrument(error_span!("client"))
                .await
        });
    });
    client.close();
    ctx.stop_server();
    server.join().expect("server");
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
    stop_server: Option<oneshot::Sender<()>>,
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
            stop_server: None,
        }
    }

    pub fn spawn_server(&mut self) -> (SocketAddr, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        let server = self.server_config.clone();

        let (stop_server, stop_recv) = oneshot::channel::<()>();
        self.stop_server = Some(stop_server);

        let handle = thread::spawn(move || {
            let mut runtime = rt();
            runtime.block_on(async {
                let incoming_conn = server.with_socket(socket).unwrap();
                handle_connection(incoming_conn, stop_recv)
                    .instrument(error_span!("server"))
                    .await
            });
        });

        (addr, handle)
    }

    pub fn stop_server(&mut self) {
        if let Some(send) = self.stop_server.take() {
            send.send(()).expect("stop server");
        }
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

async fn handle_connection(
    mut incoming_conn: IncomingConnection,
    mut stop_recv: oneshot::Receiver<()>,
) {
    let mut incoming_req = incoming_conn
        .next()
        .await
        .expect("accept")
        .await
        .expect("connect");
    loop {
        select! {
            _ = &mut stop_recv => break,
            Some(recv_req) = incoming_req.next() => {
                let (request, _, sender) = recv_req.await.expect("recv_req");
                let body_writer = sender
                    .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
                    .await
                    .expect("send_response");

                let frame_size = request
                    .headers()
                    .get("frame_size")
                    .map(|x| x.to_str().unwrap().parse().expect("parse frame size"))
                    .expect("no frame size");
                let total_size = request
                    .headers()
                    .get("total_size")
                    .map(|x| x.to_str().unwrap().parse().expect("parse total size"))
                    .expect("no total size");
                send_body(body_writer, frame_size, total_size).await;
            },
        }
    }
}

async fn send_body(mut body_writer: BodyWriter, frame_size: usize, mut total_size: usize) {
    let data = "a".repeat(frame_size);
    while total_size > 0 {
        let size = std::cmp::min(frame_size, total_size);
        body_writer
            .write_all(&data.as_bytes()[..size])
            .await
            .expect("body write");
        total_size -= size;
    }
}

fn rt() -> Runtime {
    Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap()
}
