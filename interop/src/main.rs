#![allow(clippy::mutex_atomic)]

use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures::future;
use lazy_static::lazy_static;
use quinn_h3::Settings;
use structopt::StructOpt;
use tokio::io::AsyncReadExt;
use tracing::{error, info, warn};

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: Option<String>,
    #[structopt(short, long)]
    name: Option<String>,
    #[structopt(long)]
    port: Option<u16>,
    #[structopt(long)]
    retry_port: Option<u16>,
    #[structopt(long)]
    h3: bool,
    #[structopt(long)]
    hq: bool,
    #[structopt(long)]
    seq: bool,
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
    sequential: bool,
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
            sequential: false,
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

    fn uri(&self, path: &str) -> http::Uri {
        http::Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(path)
            .build()
            .expect("invalid uri")
    }
}

lazy_static! {
    static ref PEERS: Vec<Peer> = vec![
        Peer::new("quant.eggert.org").name("quant").hq(),
        Peer::new("nghttp2.org").name("nghttp2").h3(),
        Peer::new("fb.mvfst.net").name("mvfst").h3(),
        Peer::new("test.privateoctopus.com").name("picoquic").h3(),
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
            port: opt.port.unwrap_or(4433),
            retry_port: opt.retry_port.unwrap_or(4434),
            sequential: opt.seq,
            alpn: match (opt.h3, opt.hq) {
                (false, true) => Alpn::Hq,
                (true, false) => Alpn::H3,
                _ => Alpn::HqH3,
            },
        }]
    } else if opt.name.is_some() {
        let name = opt.name.as_ref().unwrap();
        let mut peers: Vec<Peer> = PEERS[..]
            .iter()
            .filter(|p| &p.name == name)
            .cloned()
            .collect();

        peers.iter_mut().for_each(|mut x| {
            match (opt.h3, opt.hq) {
                (false, true) => x.alpn = Alpn::Hq,
                (true, false) => x.alpn = Alpn::H3,
                _ => (),
            }
            if let Some(port) = opt.port {
                x.port = port;
            }
            if let Some(retry_port) = opt.retry_port {
                x.retry_port = retry_port;
            }
            x.sequential = opt.seq;
        });
        peers
    } else {
        Vec::from(&PEERS[..])
    };

    let keylog = opt.keylog;
    let results = future::join_all(peers.into_iter().map(|peer| async move {
        let result = run(&peer, keylog).await;
        (peer, result)
    }));
    for (peer, result) in results.await {
        match result {
            Ok(r) => println!("{}: {}", peer.name, r),
            Err(e) => {
                println!("ERROR: {}: {}", peer.name, e);
                code = 1;
            }
        }
    }
    ::std::process::exit(code);
}

async fn run(peer: &Peer, keylog: bool) -> Result<String> {
    let state = State::try_new(&peer, keylog)?;
    let result = match peer.alpn {
        Alpn::Hq => state.run_hq().await?,
        _ => state.run_h3().await?,
    };
    Ok(result.format())
}

struct State {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    remote: SocketAddr,
    host: String,
    peer: Peer,
    h3_client: Option<quinn_h3::client::Client>,
}

impl State {
    async fn run_hq(self) -> Result<InteropResult> {
        if self.peer.sequential {
            Ok(build_result(
                self.core().await,
                self.key_update().await,
                self.rebind().await,
                self.retry().await,
                None,
            ))
        } else {
            let (core, key_update, rebind, retry) =
                future::join4(self.core(), self.key_update(), self.rebind(), self.retry()).await;
            Ok(build_result(core, key_update, rebind, retry, None))
        }
    }

    async fn run_h3(self) -> Result<InteropResult> {
        if self.peer.sequential {
            Ok(build_result(
                self.core_h3().await,
                self.key_update_h3().await,
                self.rebind_h3().await,
                self.retry_h3().await,
                Some(self.h3().await),
            ))
        } else {
            let (core, key_update, rebind, retry, h3) = future::join5(
                self.core_h3(),
                self.key_update_h3(),
                self.rebind_h3(),
                self.retry_h3(),
                self.h3(),
            )
            .await;
            Ok(build_result(core, key_update, rebind, retry, Some(h3)))
        }
    }

    fn try_new(peer: &Peer, keylog: bool) -> Result<Self> {
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

        let mut tls_config = rustls::ClientConfig::new();
        tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        tls_config.enable_early_data = true;
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InteropVerifier(Arc::new(Mutex::new(false)))));
        tls_config.alpn_protocols = (&peer.alpn).into();
        if keylog {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        let mut transport = quinn::TransportConfig::default();
        transport
            .idle_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let client_config = quinn::ClientConfig {
            crypto: Arc::new(tls_config),
            transport: Arc::new(transport),
        };

        let mut endpoint = quinn::Endpoint::builder();
        endpoint.default_client_config(client_config.clone());

        let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

        let h3_client = match peer.alpn {
            Alpn::Hq => None,
            _ => {
                let mut h3_client = quinn_h3::client::Builder::default();
                h3_client.settings(Settings {
                    qpack_max_table_capacity: 0,
                    qpack_blocked_streams: 0,
                    ..Settings::default()
                });
                Some(h3_client.endpoint(endpoint.clone()))
            }
        };
        Ok(State {
            h3_client,
            host: host.into(),
            peer: peer.clone(),
            client_config,
            endpoint,
            remote,
        })
    }

    async fn core(&self) -> Result<InteropResult> {
        let mut result = InteropResult::default();
        let new_conn = self
            .endpoint
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        result.handshake = true;
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

        let saw_cert = Arc::new(Mutex::new(false));
        let quinn::ClientConfig {
            mut crypto,
            transport,
        } = self.client_config.clone();
        Arc::make_mut(&mut crypto)
            .dangerous()
            .set_certificate_verifier(Arc::new(InteropVerifier(saw_cert.clone())));
        let client_config = quinn::ClientConfig { crypto, transport };

        let conn = match self
            .endpoint
            .connect_with(client_config, &self.remote, &self.host)?
            .into_0rtt()
        {
            Ok((new_conn, _)) => {
                let stream = new_conn
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| anyhow!("failed to open 0-RTT stream: {}", e))?;
                get(stream)
                    .await
                    .map_err(|e| anyhow!("0-RTT request failed: {}", e))?;
                result.zero_rtt = true;
                new_conn.connection
            }
            Err(conn) => {
                info!("0-RTT unsupported");
                let new_conn = conn
                    .await
                    .map_err(|e| anyhow!("failed to connect: {}", e))?;
                new_conn.connection
            }
        };
        result.resumption = !*saw_cert.lock().unwrap();
        conn.close(0u32.into(), b"done");

        self.endpoint.wait_idle().await;

        Ok(result)
    }

    async fn key_update(&self) -> Result<()> {
        let new_conn = self
            .endpoint
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
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
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
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
        let mut endpoint = quinn::Endpoint::builder();
        endpoint.default_client_config(self.client_config.clone());
        let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

        let new_conn = endpoint
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
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
        if let Alpn::Hq = self.peer.alpn {
            return Err(anyhow!("H3 not implemented on this peer"));
        }
        let conn = self
            .h3_client
            .as_ref()
            .unwrap()
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;

        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("h3 request failed: {}", e))?;
        conn.close();
        Ok(())
    }

    async fn core_h3(&self) -> Result<InteropResult> {
        let mut result = InteropResult::default();

        let conn = self
            .h3_client
            .as_ref()
            .unwrap()
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;
        result.handshake = true;
        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("simple request failed: {}", e))?;
        result.stream_data = true;
        conn.close();

        let saw_cert = Arc::new(Mutex::new(false));
        let quinn::ClientConfig {
            mut crypto,
            transport,
        } = self.client_config.clone();
        Arc::make_mut(&mut crypto)
            .dangerous()
            .set_certificate_verifier(Arc::new(InteropVerifier(saw_cert.clone())));
        let client_config = quinn::ClientConfig { crypto, transport };

        let conn = match self
            .h3_client
            .as_ref()
            .unwrap()
            .connect_with(client_config, &self.remote, &self.host)?
            .into_0rtt()
        {
            Ok((conn, _)) => {
                h3_get(&conn, &self.peer.uri("/"))
                    .await
                    .map_err(|e| anyhow!("0-RTT request failed: {}", e))?;
                result.zero_rtt = true;
                conn
            }
            Err(connecting) => {
                info!("0-RTT unsupported");
                connecting
                    .await
                    .map_err(|e| anyhow!("failed to connect: {}", e))?
            }
        };
        result.resumption = !*saw_cert.lock().unwrap();
        conn.close();

        self.endpoint.wait_idle().await;

        result.close = true;

        Ok(result)
    }

    async fn key_update_h3(&self) -> Result<()> {
        let conn = self
            .h3_client
            .as_ref()
            .unwrap()
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;
        // Make sure some traffic has gone both ways before the key update
        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("request failed before key update: {}", e))?;
        conn.force_key_update();
        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("request failed after key update: {}", e))?;
        conn.close();
        Ok(())
    }

    async fn retry_h3(&self) -> Result<()> {
        let mut remote = self.remote;
        remote.set_port(self.peer.retry_port);

        let conn = self
            .h3_client
            .as_ref()
            .unwrap()
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;
        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("request failed on retry port: {}", e))?;
        conn.close();
        Ok(())
    }

    async fn rebind_h3(&self) -> Result<()> {
        let (endpoint, _) = quinn::Endpoint::builder().bind(&"[::]:0".parse().unwrap())?;

        let h3_client = quinn_h3::client::Builder::default().endpoint(self.endpoint.clone());
        let conn = h3_client
            .connect(&self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("h3 failed to connect: {}", e))?;
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        endpoint.rebind(socket)?;
        h3_get(&conn, &self.peer.uri("/"))
            .await
            .map_err(|e| anyhow!("request failed on retry port: {}", e))?;
        conn.close();
        Ok(())
    }
}

#[derive(Default)]
struct InteropResult {
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

fn build_result(
    core: Result<InteropResult>,
    key_update: Result<()>,
    rebind: Result<()>,
    retry: Result<()>,
    h3: Option<Result<()>>,
) -> InteropResult {
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
        Some(Ok(_)) => result.h3 = true,
        Some(Err(e)) => error!("retry failed: {}", e),
        None => (),
    }
    result
}

async fn h3_get(conn: &quinn_h3::client::Connection, uri: &http::Uri) -> Result<()> {
    let (response, _) = conn.send_request(http::Request::get(uri).body(())?).await?;

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

struct InteropVerifier(Arc<Mutex<bool>>);
impl rustls::ServerCertVerifier for InteropVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        *self.0.lock().unwrap() = true;
        Ok(rustls::ServerCertVerified::assertion())
    }
}
