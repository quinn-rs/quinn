use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures::{future, TryFutureExt};
use lazy_static::lazy_static;
use structopt::StructOpt;
use tokio::io::AsyncReadExt;
use tracing::{error, info, warn};

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: Option<String>,
    #[structopt(default_value = "4433")]
    port: u16,
    #[structopt(default_value = "4434")]
    retry_port: u16,
    #[structopt(long)]
    h3: bool,
    #[structopt(long)]
    hq: bool,
    /// Enable key logging
    #[structopt(long = "keylog")]
    keylog: bool,
}

#[derive(Clone)]
enum Alpn {
    Hq,
    H3,
    HqH3,
}

impl From<&Alpn> for Vec<Vec<u8>> {
    fn from(alpn: &Alpn) -> Vec<Vec<u8>> {
        match alpn {
            Alpn::H3 => vec![quinn_h3::ALPN.into()],
            Alpn::Hq => vec![b"hq-24"[..].into()],
            Alpn::HqH3 => vec![b"hq-24"[..].into(), quinn_h3::ALPN.into()],
        }
    }
}

#[derive(Clone)]
struct Peer {
    name: String,
    host: String,
    port: u16,
    retry_port: u16,
    alpn: Alpn,
}

impl Peer {
    fn new<T: Into<String>>(host: T) -> Self {
        let host_str = host.into();
        Self {
            name: host_str.clone(),
            host: host_str,
            port: 4433,
            retry_port: 4434,
            alpn: Alpn::HqH3,
        }
    }

    fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = name.into();
        self
    }

    fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    fn retry_port(mut self, port: u16) -> Self {
        self.retry_port = port;
        self
    }

    fn h3(mut self) -> Self {
        self.alpn = Alpn::H3;
        self
    }

    fn hq(mut self) -> Self {
        self.alpn = Alpn::Hq;
        self
    }
}

lazy_static! {
    static ref PEERS: Vec<Peer> = vec![
        Peer::new("quant.eggert.org").name("quant").hq(),
        Peer::new("nghttp2.org").name("nghttp2").h3(),
        Peer::new("fb.mvfst.net").name("mvfst").h3(),
        Peer::new("test.privateoctopus.com").name("picoquic"),
        Peer::new("quic.westus.cloudapp.azure.com")
            .name("msquic")
            .h3()
            .port(443),
        Peer::new("quic.westus.cloudapp.azure.com")
            .name("msquic-hq")
            .hq(),
        Peer::new("f5quic.com").name("f5"),
        Peer::new("quic.ogre.com").name("ATS"),
        Peer::new("quic.tech").name("quiche-http/0.9").hq(),
        Peer::new("quic.tech")
            .name("quiche")
            .h3()
            .port(8443)
            .retry_port(8444),
        Peer::new("http3-test.litespeedtech.com")
            .name("lsquic")
            .h3(),
        Peer::new("cloudflare-quic.com")
            .name("ngx_quic")
            .h3()
            .port(443),
        Peer::new("quic.aiortc.org").name("aioquic"),
        Peer::new("quic.rocks").name("gQuic"),
    ];
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let mut code = 0;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let peers = if let Some(host) = opt.host {
        vec![Peer {
            name: host.clone(),
            host,
            port: opt.port,
            retry_port: opt.retry_port,
            alpn: match (opt.h3, opt.hq) {
                (false, true) => Alpn::Hq,
                (true, false) => Alpn::H3,
                _ => Alpn::HqH3,
            },
        }]
    } else {
        Vec::from(&PEERS[..])
    };

    for peer in peers.into_iter() {
        let name = peer.name.clone();
        if let Err(e) = run(peer, opt.keylog).await {
            eprintln!("ERROR: {}: {}", name, e);
            code = 1;
        }
    }
    ::std::process::exit(code);
}

struct State {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    remote: SocketAddr,
    host: String,
    peer: Peer,
}

impl State {
    async fn core(&self) -> Result<InteropResult> {
        let mut result = InteropResult::default();
        let new_conn = self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        result.handshake = true;
        let close_handle = tokio::spawn(tokio::time::timeout(
            Duration::from_secs(2),
            new_conn.driver,
        ));
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream)
            .await
            .map_err(|e| anyhow!("simple request failed: {}", e))?;
        result.stream_data = true;
        new_conn.connection.close(0u32.into(), b"done");

        result.saw_cert = false;
        let conn = match self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .into_0rtt()
        {
            Ok((new_conn, _)) => {
                tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                let stream = new_conn
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| anyhow!("failed to open 0-RTT stream: {}", e))?;
                get(stream)
                    .await
                    .map_err(|e| anyhow!("0-RTT request failed: {}", e))?;
                result.zero_rtt;
                new_conn.connection
            }
            Err(conn) => {
                info!("0-RTT unsupported");
                let new_conn = conn
                    .await
                    .map_err(|e| anyhow!("failed to connect: {}", e))?;
                tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                new_conn.connection
            }
        };
        result.resumption = !result.saw_cert;
        conn.close(0u32.into(), b"done");

        result.close = close_handle.await.is_ok();

        Ok(result)
    }

    async fn key_update(&self) -> Result<()> {
        let new_conn = self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let conn = new_conn.connection;
        // Make sure some traffic has gone both ways before the key update
        let stream = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream).await?;
        conn.force_key_update();
        let stream = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream).await?;
        conn.close(0u32.into(), b"done");
        Ok(())
    }

    async fn retry(&self) -> Result<()> {
        let mut remote = self.remote;
        remote.set_port(self.peer.retry_port);

        let new_conn = self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream).await?;
        new_conn.connection.close(0u32.into(), b"done");
        Ok(())
    }

    async fn rebind(&self) -> Result<()> {
        let (endpoint_driver, endpoint, _) =
            quinn::Endpoint::builder().bind(&"[::]:0".parse().unwrap())?;
        tokio::spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));

        let new_conn = endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        tokio::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        endpoint.rebind(socket)?;
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream).await?;
        new_conn.connection.close(0u32.into(), b"done");
        Ok(())
    }

    async fn h3(&self) -> Result<()> {
        let h3_client = quinn_h3::client::Builder::default().endpoint(self.endpoint.clone());
        let (quic_driver, h3_driver, conn) = h3_client
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;

        tokio::spawn(h3_driver.unwrap_or_else(|_| ()));
        tokio::spawn(quic_driver.unwrap_or_else(|_| ()));

        h3_get(&conn)
            .await
            .map_err(|e| anyhow!("h3 request failed: {}", e))?;
        conn.close();
        Ok(())
    }
}

#[derive(Default)]
struct InteropResult {
    saw_cert: bool,
    handshake: bool,
    stream_data: bool,
    close: bool,
    resumption: bool,
    key_update: bool,
    rebinding: bool,
    zero_rtt: bool,
    retry: bool,
    h3: bool,
}

impl InteropResult {
    fn format(&self) -> String {
        let mut string = String::with_capacity(10);
        if self.handshake {
            string.push_str("VH");
        }
        if self.stream_data {
            string.push_str("D");
        }
        if self.close {
            string.push_str("C");
        }
        if self.resumption {
            string.push_str("R");
        }
        if self.zero_rtt {
            string.push_str("Z");
        }
        if self.retry {
            string.push_str("S");
        }
        if self.rebinding {
            string.push_str("B");
        }
        if self.key_update {
            string.push_str("U");
        }
        if self.h3 {
            string.push_str("3");
        }
        string
    }
}

async fn run(peer: Peer, keylog: bool) -> Result<()> {
    let remote = format!("{}:{}", peer.host, peer.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let host = if webpki::DNSNameRef::try_from_ascii_str(&peer.host).is_ok() {
        &peer.host
    } else {
        warn!("invalid hostname, using \"example.com\"");
        "example.com"
    };

    let results = Arc::new(Mutex::new(InteropResult::default()));

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config.enable_early_data = true;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(results.clone())));
    tls_config.alpn_protocols = (&peer.alpn).into();
    if keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        crypto: Arc::new(tls_config),
        transport: Arc::new(quinn::TransportConfig {
            idle_timeout: 1_000,
            ..Default::default()
        }),
    };

    let (endpoint_driver, endpoint, _) =
        quinn::Endpoint::builder().bind(&"[::]:0".parse().unwrap())?;
    tokio::spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));

    let state = Arc::new(State {
        host: host.into(),
        peer: peer.clone(),
        endpoint,
        client_config,
        remote,
    });

    let (core, key_update, rebind, retry, h3) = future::join5(
        state.core(),
        state.key_update(),
        state.rebind(),
        state.retry(),
        state.h3(),
    )
    .await;
    let mut result = core.unwrap_or_else(|e| {
        error!("core functionality failed: {}", e);
        InteropResult::default()
    });
    match key_update {
        Ok(_) => result.key_update = true,
        Err(e) => error!("key update failed: {}", e),
    };
    match rebind {
        Ok(_) => result.rebinding = true,
        Err(e) => error!("rebinding failed: {}", e),
    }
    match retry {
        Ok(_) => result.retry = true,
        Err(e) => error!("retry failed: {}", e),
    }
    match h3 {
        Ok(_) => result.h3 = true,
        Err(e) => error!("retry failed: {}", e),
    }

    println!("{}: {}", peer.name, results.lock().unwrap().format());

    Ok(())
}

async fn h3_get(conn: &quinn_h3::client::Connection) -> Result<()> {
    let (response, _) = conn
        .send_request(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("/")
                .body(())?,
        )
        .await?;

    let (_, mut recv_body) = response.await?;

    let mut body = Vec::with_capacity(1024);
    recv_body.read_to_end(&mut body).await?;
    Ok(())
}

async fn get(stream: (quinn::SendStream, quinn::RecvStream)) -> Result<Vec<u8>> {
    let (mut send, recv) = stream;
    send.write_all(b"GET /index.html\r\n")
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    let response = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    Ok(response)
}

struct InteropVerifier(Arc<Mutex<InteropResult>>);
impl rustls::ServerCertVerifier for InteropVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        self.0.lock().unwrap().saw_cert = true;
        Ok(rustls::ServerCertVerified::assertion())
    }
}
