use std::{
    fs, io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use quinn::{Certificate, CertificateChain, PrivateKey};
use tokio::time::timeout;

use crate::{
    client::{self, Client},
    server::{self, IncomingConnection, Server},
};

#[macro_export]
macro_rules! get {
    () => {
        Request::get("https://localhost/")
            .body(())
            .expect("request")
    };
    ($path:expr) => {
        Request::get(format!("https://localhost/{}", path))
            .body(())
            .expect("request")
    };
}

#[macro_export]
macro_rules! post {
    () => {
        Request::post("https://localhost/")
            .body(())
            .expect("request")
    };
    ($body:expr) => {
        Request::post("https://localhost/")
            .body($body)
            .expect("request")
    };
}

static PORT_COUNT: AtomicU16 = AtomicU16::new(1024);

pub struct Helper {
    server: server::Builder,
    client: client::Builder,
    port: u16,
}

impl Helper {
    pub fn new() -> Self {
        let port = PORT_COUNT.fetch_add(1, Ordering::SeqCst);

        let Certs { chain, key, cert } = CERTS.clone();
        let mut server = server::Builder::default();
        server.certificate(chain, key).expect("server certs");
        server
            .listen(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
            .unwrap();

        let mut client = client::Builder::default();
        client.add_certificate_authority(cert).unwrap();

        Self {
            server,
            client,
            port,
        }
    }

    pub fn make_server(&self) -> (Server, IncomingConnection) {
        self.server.clone().build().expect("server build")
    }

    pub fn make_client(&self) -> Client {
        self.client.clone().build().expect("client build")
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
