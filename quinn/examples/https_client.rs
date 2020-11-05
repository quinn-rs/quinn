use std::{
    fs,
    io::{self, Write},
    net::ToSocketAddrs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use structopt::StructOpt;
use tracing::{error, info};
use url::Url;
use quinn::{NewConnection, Connection, Endpoint};

mod common;

#[derive(StructOpt, Debug)]
#[structopt(name = "client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[structopt(long = "keylog")]
    keylog: bool,

    url: Url,

    /// Override hostname used for certificate verification
    #[structopt(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[structopt(parse(from_os_str), long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[structopt(long = "rebind")]
    rebind: bool,
}

fn main() {
    // Setup logger with environment arguments.
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    // Read command line arguments.
    let opt = Opt::from_args();

    // Setup main loop and catch error if any.
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };

    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let url = options.url.clone();
    let mut endpoint = initialize_endpoint(&options)?;

    let quinn::NewConnection {
        connection: mut conn, ..
    } = initialize_connection(&options, &endpoint, url.clone()).await?;

    if options.rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        eprintln!("rebinding to {}", addr);
        endpoint.rebind(socket).expect("rebind failed");
    }

    // Perform a GET request with the filename.
    perform_request(url, &mut conn).await;

    // Clean up some resources.
    conn.close(0u32.into(), b"done");

    Ok(())
}

/// Initializes the client configuration.
fn initialize_client_configuration(options: &Opt) -> Result<quinn::ClientConfig> {
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(common::ALPN_QUIC_HTTP);

    if options.keylog {
        client_config.enable_keylog();
    }

    // If the user entered a certificate authority path, use it, otherwise search for an certificate in the project folder.
    if let Some(ref ca_path) = &options.ca {
        client_config
            .add_certificate_authority(quinn::Certificate::from_der(&fs::read(&ca_path)?)?)?;
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();

        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }

    Ok(client_config.build())
}

// Initializes an endpoint with the commandline arguments.
fn initialize_endpoint(options: &Opt) -> Result<Endpoint> {
    let mut endpoint = quinn::Endpoint::builder();
    endpoint.default_client_config(initialize_client_configuration(options)?);
    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;
    Ok(endpoint)
}

/// Initializes a connection and connects with the given endpoint.
async fn initialize_connection(options: &Opt, endpoint: &Endpoint, url: Url) -> Result<NewConnection> {
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let start = Instant::now();

    // Try get server host address.
    let host = options
        .host
        .as_ref()
        .map_or_else(|| url.host_str(), |x| Some(&x))
        .ok_or_else(|| anyhow!("no hostname specified"))?;

    // Connect to the server.
    let new_conn = endpoint
        .connect(&remote, &host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    eprintln!("connected at {:?}", start.elapsed());

    Ok(new_conn)
}

/// Opens up an bidirectional stream to the server, requests a file, waits for the response, and print it to the terminal.
async fn perform_request(url: Url, conn: &mut Connection) -> Result<()> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    let request = format!("GET {}\r\n", url.path());

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;

    let response_start = Instant::now();
    eprintln!("request sent at {:?}", response_start);

    // Wait for server file response.
    let response = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;

    // Print response to the terminal.
    let duration = response_start.elapsed();

    eprintln!(
        "response received in {:?} - {} KiB/s",
        duration,
        response.len() as f32 / (duration_secs(&duration) * 1024.0)
    );

    io::stdout().write_all(&response).unwrap();
    io::stdout().flush().unwrap();

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
