use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use futures::TryFutureExt;
// use quinn_h3::qpack;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

// use bytes::{Bytes, BytesMut};
use failure::{format_err, Error};
use slog::{info, o, warn, Drain, Logger};

type Result<T> = std::result::Result<T, Error>;

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
        let decorator = slog_term::TermDecorator::new().stderr().build();
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        // We use a mutex-protected drain for simplicity; this tool is single-threaded anyway.
        let drain = std::sync::Mutex::new(drain).fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
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
    log: Logger,
    options: Opt,
    results: Arc<Mutex<Results>>,
}

impl State {
    async fn core(self: Arc<Self>) -> Result<()> {
        let new_conn = self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| format_err!("failed to connect: {}", e))?;
        self.results.lock().unwrap().handshake = true;
        let results = self.results.clone();
        tokio::runtime::current_thread::spawn(
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
            .map_err(|e| format_err!("failed to open stream: {}", e))?;
        get(stream)
            .await
            .map_err(|e| format_err!("simple request failed: {}", e))?;
        self.results.lock().unwrap().stream_data = true;
        new_conn.connection.close(0u32.into(), b"done");

        self.results.lock().unwrap().saw_cert = false;
        let conn = match self
            .endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .into_0rtt()
        {
            Ok((new_conn, _)) => {
                tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                let stream = new_conn
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| format_err!("failed to open 0-RTT stream: {}", e))?;
                get(stream)
                    .await
                    .map_err(|e| format_err!("0-RTT request failed: {}", e))?;
                self.results.lock().unwrap().zero_rtt = true;
                new_conn.connection
            }
            Err(conn) => {
                info!(self.log, "0-RTT unsupported");
                let new_conn = conn
                    .await
                    .map_err(|e| format_err!("failed to connect: {}", e))?;
                tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
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
            .map_err(|e| format_err!("failed to connect: {}", e))?;
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let conn = new_conn.connection;
        // Make sure some traffic has gone both ways before the key update
        let stream = conn
            .open_bi()
            .await
            .map_err(|e| format_err!("failed to open stream: {}", e))?;
        get(stream).await?;
        conn.force_key_update();
        let stream = conn
            .open_bi()
            .await
            .map_err(|e| format_err!("failed to open stream: {}", e))?;
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
            .map_err(|e| format_err!("failed to connect: {}", e))?;
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| format_err!("failed to open stream: {}", e))?;
        get(stream).await?;
        self.results.lock().unwrap().retry = true;
        new_conn.connection.close(0u32.into(), b"done");
        Ok(())
    }

    async fn rebind(self: Arc<Self>) -> Result<()> {
        let mut builder = quinn::Endpoint::builder();
        builder.logger(self.log.clone());
        let (endpoint_driver, endpoint, _) = builder.bind(&"[::]:0".parse().unwrap())?;
        tokio::runtime::current_thread::spawn(
            endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)),
        );

        let new_conn = endpoint
            .connect_with(self.client_config.clone(), &self.remote, &self.host)?
            .await
            .map_err(|e| format_err!("failed to connect: {}", e))?;
        tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        endpoint.rebind(socket, &tokio_net::driver::Handle::default())?;
        let stream = new_conn
            .connection
            .open_bi()
            .await
            .map_err(|e| format_err!("failed to open stream: {}", e))?;
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
            .map_err(|e| format_err!("h3 failed to connect: {}", e))?;

        tokio::runtime::current_thread::spawn(h3_driver.unwrap_or_else(|_| ()));
        tokio::runtime::current_thread::spawn(quic_driver.unwrap_or_else(|_| ()));

        h3_get(&conn)
            .await
            .map_err(|e| format_err!("h3 request failed: {}", e))?;
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

fn run(log: Logger, options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format_err!("couldn't resolve to an address"))?;
    let host = if webpki::DNSNameRef::try_from_ascii_str(&options.host).is_ok() {
        &options.host
    } else {
        warn!(log, "invalid hostname, using \"example.com\"");
        "example.com"
    };

    let mut runtime = Runtime::new()?;

    let results = Arc::new(Mutex::new(Results::default()));
    let protocols = vec![b"hq-23"[..].into(), quinn_h3::ALPN.into()];

    let mut builder = quinn::Endpoint::builder();
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
        crypto: quinn::crypto::rustls::ClientConfig::new(tls_config),
        transport: Arc::new(quinn::TransportConfig {
            idle_timeout: 1_000,
            ..Default::default()
        }),
        ..Default::default()
    };

    builder.logger(log.clone());
    let (endpoint_driver, endpoint, _) = builder.bind(&"[::]:0".parse().unwrap())?;
    runtime.spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));

    let state = Arc::new(State {
        endpoint,
        client_config,
        remote,
        host: host.into(),
        log,
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

    runtime.spawn(
        state
            .clone()
            .h3()
            .unwrap_or_else(|e: Error| eprintln!("retry failed: {}", e)),
    );

    let results = state.results.clone();
    drop(state); // Ensure the drivers will shut down once idle
    runtime.run().unwrap();

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
        .map_err(|e| format_err!("failed to send request: {}", e))?;
    send.finish()
        .await
        .map_err(|e| format_err!("failed to shutdown stream: {}", e))?;
    let response = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| format_err!("failed to read response: {}", e))?;
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
