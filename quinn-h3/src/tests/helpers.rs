use std::{
    fs, io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use bytes::BufMut;
use futures::stream::StreamExt;
use http::{request, Request};
use quinn::{Certificate, CertificateChain, PrivateKey, SendStream, WriteError};
use tokio::time::timeout;

use crate::{
    body::Body,
    client::{self, Client},
    frame::{Error as FrameError, FrameDecoder, FrameStream},
    headers::SendHeaders,
    proto::frame::HttpFrame,
    proto::headers::Header,
    server::{self, IncomingConnection},
    ZeroRttAccepted,
};

pub fn get(path: &str) -> Request<()> {
    Request::get(format!("https://localhost{}", path))
        .body(())
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
        let port = PORT_COUNT.fetch_add(1, Ordering::SeqCst);

        let Certs { chain, key, cert } = CERTS.clone();
        let mut server = server::Builder::default();
        server.certificate(chain, key).expect("server certs");
        server.listen(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));

        let mut client = client::Builder::default();
        client.add_certificate_authority(cert.clone()).unwrap();

        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config
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

    pub async fn make_fake_0rtt(&mut self) -> (FakeConnection, ZeroRttAccepted) {
        let (conn, z) = self.make_0rtt().await;
        (FakeConnection(conn), z)
    }

    pub async fn make_0rtt(&mut self) -> (client::Connection, ZeroRttAccepted) {
        if !self.got_0rtt {
            let conn = self.make_connection().await;
            let resp = conn
                .send_request(get("/"))
                .await
                .expect("request")
                .0
                .await
                .expect("response");
            println!("got response {:?}", resp.0);
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
        let (send, recv) = self.0.inner().quic.open_bi().await.expect("open bi");

        let stream_id = send.id();
        let send = SendHeaders::new(
            Header::request(method, uri, headers),
            &self.0.inner().clone(),
            send,
            stream_id,
        )
        .expect("bad headers")
        .await
        .expect("send header");
        FakeRequest {
            send,
            recv: FrameDecoder::stream(recv),
        }
    }
}

pub struct FakeRequest {
    send: SendStream,
    recv: FrameStream,
}

impl FakeRequest {
    pub async fn read(&mut self) -> Option<Result<HttpFrame, FrameError>> {
        self.recv.next().await
    }
    pub async fn write<F>(&mut self, mut encode: F) -> Result<(), WriteError>
    where
        F: FnMut(&mut dyn BufMut),
    {
        let mut buf = Vec::with_capacity(20 * 1024);
        encode(&mut buf);
        self.send.write_all(&buf).await.map(|_| ())
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
    let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
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
