use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Error, Result};
use futures::TryFutureExt;
use structopt::StructOpt;
use tokio::runtime::Builder;
use tracing::{info, warn};

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: String,
    #[structopt(default_value = "4433")]
    port: u16,
    #[structopt(default_value = "4434")]
    retry_port: u16,

    /// Enable key logging
    #[structopt(long = "keylog")]
    keylog: bool,
}

fn main() {
    let opt = Opt::from_args();
    let code = {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .finish(),
        )
        .unwrap();
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

struct State {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    remote: SocketAddr,
    host: String,
    options: Opt,
    results: Arc<Mutex<Results>>,
}

impl State {
    async fn core(self: Arc<Self>) -> Result<()> {
        let new_conn = self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;
        self.results.lock().unwrap().handshake = true;
        let results = self.results.clone();
        tokio::spawn(
            new_conn
                .driver
                .map_ok(move |()| {
                    results.lock().unwrap().close = true;
                })
                .unwrap_or_else(|_| ()),
        );
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        get(stream)
            .await
            .map_err(|e| anyhow!("simple request failed: {}", e))?;
        self.results.lock().unwrap().stream_data = true;
        new_conn.connection.close(0u32.into(), b"done");

        self.results.lock().unwrap().saw_cert = false;
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
                self.results.lock().unwrap().zero_rtt = true;
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
        {
            let mut results = self.results.lock().unwrap();
            results.resumption = !results.saw_cert;
        }
        conn.close(0u32.into(), b"done");

        Ok(())
    }

    async fn key_update(self: Arc<Self>) -> Result<()> {
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
        self.results.lock().unwrap().key_update = true;
        conn.close(0u32.into(), b"done");
        Ok(())
    }

    async fn retry(self: Arc<Self>) -> Result<()> {
        let mut remote = self.remote;
        remote.set_port(self.options.retry_port);

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
        self.results.lock().unwrap().retry = true;
        new_conn.connection.close(0u32.into(), b"done");
        Ok(())
    }

    async fn rebind(self: Arc<Self>) -> Result<()> {
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
        self.results.lock().unwrap().rebinding = true;
        new_conn.connection.close(0u32.into(), b"done");
        Ok(())
    }

    async fn h3(self: Arc<Self>) -> Result<()> {
        let h3_client = quinn_h3::client::Builder::new().endpoint(self.endpoint.clone());
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

        self.results.lock().unwrap().h3 = true;

        Ok(())
    }
}

#[derive(Default)]
struct Results {
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

fn run(options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let host = if webpki::DNSNameRef::try_from_ascii_str(&options.host).is_ok() {
        &options.host
    } else {
        warn!("invalid hostname, using \"example.com\"");
        "example.com"
    };

    let mut runtime = Builder::new().basic_scheduler().enable_all().build()?;

    let results = Arc::new(Mutex::new(Results::default()));
    let protocols = vec![b"hq-24"[..].into(), quinn_h3::ALPN.into()];

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config.enable_early_data = true;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(results.clone())));
    tls_config.alpn_protocols = protocols.clone();
    if options.keylog {
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
        runtime.enter(|| quinn::Endpoint::builder().bind(&"[::]:0".parse().unwrap()))?;
    runtime.spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));

    let state = Arc::new(State {
        endpoint,
        client_config,
        remote,
        host: host.into(),
        options,
        results,
    });

    runtime.spawn(
        state
            .clone()
            .core()
            .unwrap_or_else(|e: Error| eprintln!("core functionality failed: {}", e)),
    );

    runtime.spawn(
        state
            .clone()
            .key_update()
            .unwrap_or_else(|e: Error| eprintln!("key update failed: {}", e)),
    );

    runtime.spawn(
        state
            .clone()
            .rebind()
            .unwrap_or_else(|e: Error| eprintln!("rebinding failed: {}", e)),
    );

    runtime.spawn(
        state
            .clone()
            .retry()
            .unwrap_or_else(|e: Error| eprintln!("retry failed: {}", e)),
    );

    let handle = runtime.spawn(
        state
            .clone()
            .h3()
            .unwrap_or_else(|e: Error| eprintln!("retry failed: {}", e)),
    );

    let results = state.results.clone();
    drop(state); // Ensure the drivers will shut down once idle
    runtime.block_on(handle).unwrap();

    let r = results.lock().unwrap();
    if r.handshake {
        print!("VH");
    }
    if r.stream_data {
        print!("D");
    }
    if r.close {
        print!("C");
    }
    if r.resumption {
        print!("R");
    }
    if r.zero_rtt {
        print!("Z");
    }
    if r.retry {
        print!("S");
    }
    if r.rebinding {
        print!("B");
    }
    if r.key_update {
        print!("U");
    }
    if r.h3 {
        print!("3");
    }

    println!();

    Ok(())
}
const H3_INITIAL_CAPACITY: usize = 256;
const H3_MAX_LEN: usize = 256 * 1024;

async fn h3_get(conn: &quinn_h3::client::Connection) -> Result<()> {
    let (_, body) = conn
        .request(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("/")
                .body(())?,
        )
        .send()
        .await?
        .into_parts();

    body.read_to_end(H3_INITIAL_CAPACITY, H3_MAX_LEN).await?;
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

struct InteropVerifier(Arc<Mutex<Results>>);
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
