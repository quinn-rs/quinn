#![allow(dead_code)]
use std::{
    cmp,
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread,
};

use futures::{channel::oneshot, Future};
use tokio::runtime::{Builder, Runtime};
use tracing::{error_span, span, Level};
use tracing_futures::Instrument as _;

use bytes::Bytes;
use http::HeaderMap;
use http_body::Body as HttpBody;
use quinn::{ClientConfigBuilder, ServerConfigBuilder};
use quinn_h3::{
    self, client,
    server::{self, IncomingConnection},
    Error, Settings,
};

pub struct Bench {
    server_config: server::Builder,
    client_config: client::Builder,
    stop_server: Option<oneshot::Sender<()>>,
}

impl Default for Bench {
    fn default() -> Self {
        Self::with_settings(Settings::new())
    }
}

impl Bench {
    pub fn with_settings(settings: Settings) -> Self {
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

        let mut server_config = server::Builder::with_quic_config(server_config);
        server_config.settings(settings.clone());
        let mut client_config = client::Builder::with_quic_config(client_config);
        client_config.settings(settings);

        Self {
            server_config,
            client_config,
            stop_server: None,
        }
    }

    pub fn spawn_server<Fut>(
        &mut self,
        service: fn(IncomingConnection, oneshot::Receiver<()>) -> Fut,
    ) -> (SocketAddr, thread::JoinHandle<()>)
    where
        Fut: Future<Output = ()> + 'static,
    {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        let server = self.server_config.clone();

        let (stop_server, stop_recv) = oneshot::channel::<()>();
        self.stop_server = Some(stop_server);

        let handle = thread::spawn(move || {
            let mut runtime = rt();
            runtime.block_on(async {
                let incoming_conn = server.with_socket(socket).unwrap();
                service(incoming_conn, stop_recv)
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

pub fn rt() -> Runtime {
    Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap()
}

pub struct BenchBody {
    frame_len: usize,
    total_len: usize,
    buf: Bytes,
}

impl BenchBody {
    pub fn new(frame_len: usize, total_len: usize) -> Self {
        Self {
            total_len,
            frame_len,
            buf: "b".repeat(frame_len).into(),
        }
    }
}

impl HttpBody for BenchBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_data(
        mut self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        if self.total_len == 0 {
            return Poll::Ready(None);
        }

        let size = cmp::min(self.total_len, self.frame_len);
        self.total_len -= size;

        Poll::Ready(Some(Ok(self.buf.slice(..size))))
    }
    fn poll_trailers(
        self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }
}
