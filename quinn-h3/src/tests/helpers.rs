use std::{
    fs, io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use futures::{future::poll_fn, stream::StreamExt};
use http::{request, Request};
use quinn::{Certificate, CertificateChain, PrivateKey, SendStream, WriteError};
use tokio::time::timeout;

use crate::{
    body::Body,
    client::{self, Client},
    connection::ConnectionRef,
    data::{write_headers_frame, RecvData},
    frame::{Error as FrameError, FrameDecoder, FrameStream},
    proto::frame::HttpFrame,
    proto::headers::Header,
    server::{self, IncomingConnection},
    SendData, ZeroRttAccepted,
};
use quinn_proto::StreamId;

pub fn get(path: &str) -> Request<Body> {
    Request::get(format!("https://localhost{}", path))
        .body(Body::from(()))
        .expect("request")
}

pub fn post<T: Into<Body>>(path: &str, body: T) -> Request<Body> {
    Request::post(format!("https://localhost{}", path))
        .body(body.into())
        .expect("request")
}

static PORT_COUNT: AtomicU16 = AtomicU16::new(1024);

pub struct Helper {
    server: server::Builder,
    client: client::Builder,
    client_endpoint: quinn::Endpoint,
    port: u16,
    got_0rtt: bool,
}

impl Helper {
    pub fn new() -> Self {
        let _ = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter("quinn=trace,quinn-h3=trace")
            .with_writer(|| TestWriter)
            .try_init();

        let port = PORT_COUNT.fetch_add(1, Ordering::SeqCst);

        let Certs { chain, key, cert } = CERTS.clone();
        let mut server = server::Builder::default();
        server.certificate(chain, key).expect("server certs");
        server.listen(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));

        let mut client = client::Builder::default();
        client.add_certificate_authority(cert.clone()).unwrap();

        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config
            .protocols(&[crate::ALPN])
            .enable_keylog()
            .add_certificate_authority(cert)
            .expect("client cert");
        client_config.enable_0rtt();
        let client_config = client_config.build();
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.default_client_config(client_config);
        let (client_endpoint, _) = endpoint_builder
            .bind(&"[::]:0".parse().unwrap())
            .expect("bind client endpoint");

        Self {
            server,
            client,
            port,
            client_endpoint,
            got_0rtt: false,
        }
    }

    pub fn make_server(&self) -> IncomingConnection {
        self.server.clone().build().expect("server build")
    }

    pub fn make_client(&self) -> Client {
        self.client.clone().endpoint(self.client_endpoint.clone())
    }

    pub async fn make_connection(&self) -> client::Connection {
        self.make_client()
            .connect(
                &SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port),
                "localhost",
            )
            .expect("connect")
            .await
            .expect("connecting")
    }

    pub async fn make_fake(&mut self) -> FakeConnection {
        FakeConnection(self.make_connection().await)
    }

    pub async fn make_fake_0rtt(&mut self) -> (FakeConnection, ZeroRttAccepted) {
        let (conn, z) = self.make_0rtt().await;
        (FakeConnection(conn), z)
    }

    pub async fn make_0rtt(&mut self) -> (client::Connection, ZeroRttAccepted) {
        if !self.got_0rtt {
            let conn = self.make_connection().await;
            let (req, resp) = conn.send_request(get("/"));
            req.await.expect("request");
            resp.await.expect("response");
            conn.close();
            self.got_0rtt = true;
        }
        self.make_client()
            .connect(
                &SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port),
                "localhost",
            )
            .expect("connect")
            .into_0rtt()
            .map_err(|_| ())
            .expect("no 0rtt")
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port)
    }
}

pub struct FakeConnection(pub client::Connection);

impl FakeConnection {
    pub async fn blank(&mut self) -> FakeRequest {
        let (send, recv) = self.0.inner().quic.open_bi().await.expect("open bi");
        FakeRequest {
            stream_id: send.id(),
            send: Some(send),
            recv: FrameDecoder::stream(recv),
            conn: self.0.inner().clone(),
        }
    }

    pub async fn post(&mut self) -> FakeRequest {
        let (request, _) = Request::post("https://localhost")
            .body(())
            .unwrap()
            .into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            ..
        } = request;
        let (mut send, recv) = self.0.inner().quic.open_bi().await.expect("open bi");

        let header = Header::request(method, uri, headers);
        let mut write =
            write_headers_frame(header, send.id(), &self.0.inner().clone()).expect("bad headers");
        poll_fn(|cx| write.poll_send(&mut send, cx))
            .await
            .expect("send header");

        FakeRequest {
            stream_id: send.id(),
            send: Some(send),
            conn: self.0.inner().clone(),
            recv: FrameDecoder::stream(recv),
        }
    }
}

pub struct FakeRequest {
    pub send: Option<SendStream>,
    stream_id: StreamId,
    recv: FrameStream,
    pub(crate) conn: ConnectionRef,
}

impl FakeRequest {
    pub async fn read(&mut self) -> Option<Result<HttpFrame, FrameError>> {
        self.recv.next().await
    }

    pub fn into_recv_data(self) -> RecvData {
        RecvData::new(self.recv, self.conn.clone(), self.stream_id)
    }

    pub async fn write<F>(&mut self, mut encode: F) -> Result<(), WriteError>
    where
        F: FnMut(&mut Vec<u8>),
    {
        let mut buf = Vec::with_capacity(20 * 1024);
        encode(&mut buf);
        self.send
            .as_mut()
            .unwrap()
            .write_all(&buf)
            .await
            .map(|_| ())
    }

    pub async fn send_get(&mut self) -> Result<()> {
        let (request, body) = Request::get("https://localhost")
            .body(Body::from(()))
            .unwrap()
            .into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            ..
        } = request;

        let send = self.send.take().expect("send stream");
        SendData::new(
            send,
            self.conn.clone(),
            Header::request(method, uri, headers),
            body,
            false,
        )
        .await?;

        Ok(())
    }
}

#[derive(Clone)]
struct Certs {
    chain: CertificateChain,
    cert: Certificate,
    key: PrivateKey,
}

lazy_static! {
    static ref CERTS: Certs = build_certs().expect("build certs");
}

fn build_certs() -> Result<Certs> {
    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            fs::create_dir_all(&path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };
    let key = quinn::PrivateKey::from_der(&key)?;
    let cert = quinn::Certificate::from_der(&cert)?;
    Ok(Certs {
        chain: quinn::CertificateChain::from_certs(vec![cert.clone()]),
        cert,
        key,
    })
}

pub async fn timeout_join<T>(handle: tokio::task::JoinHandle<T>) -> T {
    timeout(Duration::from_millis(500), handle)
        .await
        .map_err(|e| panic!("IncomingRequest did not resolve, {:?}", e))
        .expect("server panic")
        .unwrap()
}

struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}
