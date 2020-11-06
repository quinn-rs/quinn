use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use futures::{StreamExt, TryFutureExt};
use rustls::internal::msgs::handshake::ServerExtension::RenegotiationInfo;
use structopt::{self, StructOpt};
use tracing::{error, info, info_span};
use tracing_futures::Instrument as _;

use quinn::{Certificate, CertificateChain, ParseError, PrivateKey, ServerConfig, ServerConfigBuilder, TransportConfig};
use quinn::crypto::KeyPair;

mod common;

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[structopt(long = "keylog")]
    keylog: bool,
    /// directory to serve files from
    #[structopt(parse(from_os_str))]
    root: PathBuf,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[structopt(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[structopt(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
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

    // Close program with given exit code.
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> anyhow::Result<()> {
    let server_config = initialize_configuration(&options)?;

    // Setup endpoint and initialize it to the configuration listening settings.
    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config);

    // Check if root path exists.
    let root = Arc::<Path>::from(options.root.clone());
    if !root.exists() {
        bail!("root path does not exist");
    }

    // Bind to the endpoint and start listening.
    let (endpoint, mut incoming) = endpoint.bind(&options.listen)?;
    info!("listening on {}", endpoint.local_addr()?);
    drop(endpoint);

    // Wait for incoming connections.
    while let Some(conn) = incoming.next().await {
        info!("connection incoming");
        tokio::spawn(
            // Spawn a tokio process to handle the new connection.
            handle_connection(root.clone(), conn).unwrap_or_else(move |e| {
                error!("connection failed: {reason}", reason = e.to_string())
            }),
        );
    }

    Ok(())
}

/// Try to find certificate files in the given paths.
fn certificate_from_path(key_path: &PathBuf, cert_path: &PathBuf) -> anyhow::Result<(CertificateChain, quinn::PrivateKey)> {
    let key = fs::read(key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
    } else {
        quinn::CertificateChain::from_pem(&cert_chain)?
    };

    Ok((cert_chain, key))
}

/// Try to find certificate files in the directory.
/// A self-signed certificate will be auto-generated if they do not exist in the project folder.
fn try_find_certificate_in_project_directory() -> anyhow::Result<(Certificate, quinn::PrivateKey)> {
    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");

    // If certificates do not exist, create a self-signed certificate.
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("generating self-signed certificate");
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

    Ok((cert, key))
}

/// Initializes the server based on the commandline arguments.
fn initialize_configuration(options: &Opt) -> Result<ServerConfig> {
    // First, setup the configuration builder.
    let mut transport_config = TransportConfig::default();
    transport_config.stream_window_uni(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = ServerConfigBuilder::new(server_config);
    server_config.protocols(common::ALPN_QUIC_HTTP);

    // If the user entered a custom path use that, otherwise look in the project directory for certificate files.
    if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let (cert_chain, key) = certificate_from_path(&key_path, &cert_path)?;
        server_config.certificate(cert_chain, key)?;
    } else {
        let (cert, key) = try_find_certificate_in_project_directory()?;
        server_config.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
    }

    if options.keylog {
        server_config.enable_keylog();
    }

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    Ok(server_config.build())
}

/// Handles incoming connection and starts to receive client file requests.
async fn handle_connection(root: Arc<Path>, conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );

    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            // Spawn tokio process to handle the request.
            tokio::spawn(
                handle_request(root.clone(), stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string()))
                    .instrument(info_span!("request")),
            );
        }
        Ok(())
    }
        .instrument(span)
        .await?;
    Ok(())
}

/// Handles the file requests and sends the file as respond.
async fn handle_request(
    root: Arc<Path>,
    (mut send, buffer): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let request = buffer
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;

    let mut escaped = String::new();
    for &x in &request[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }

    info!(content = %escaped);

    // Handle the file request
    let request_handler = GetFileRequestHandler { request: &request };

    let resp = request_handler.process_get(&root).unwrap_or_else(|e| {
        error!("failed: {}", e);
        format!("failed to process request: {}\n", e).into_bytes()
    });

    // Write the response
    send.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;

    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    info!("complete");

    Ok(())
}

/// Simple struct to handle the file GET request.
struct GetFileRequestHandler<'a> {
    request: &'a [u8]
}

impl<'a> GetFileRequestHandler<'a> {
    /// Processes a file requests.
    ///
    /// - Checks if request is a GET request and valid.
    /// - Checks if file path is valid.
    /// - Reads the file and returns the file bytes.
    fn process_get(&self, root: &Path) -> Result<Vec<u8>> {
        // Validate if GET request.
        if !self.is_get_request() {
            bail!("missing GET");
        }

        // Validate if line endings are correct.
        if !self.contains_line_ending() {
            bail!("missing \\r\\n");
        }

        let path = self.read_file_path()?;

        let mut real_path = PathBuf::from(root);
        let mut components = path.components();

        // Check if the path is absolute.
        match components.next() {
            Some(path::Component::RootDir) => {}
            _ => {
                bail!("path must be absolute");
            }
        }

        // Check whether there are illegal components in the path.
        for c in components {
            match c {
                path::Component::Normal(x) => {
                    real_path.push(x);
                }
                x => {
                    bail!("illegal component in path: {:?}", x);
                }
            }
        }

        println!("{:?}", real_path);
        // Read file from path.
        let data = fs::read(&real_path).context("failed reading file")?;

        Ok(data)
    }

    /// Returns whether this request is a GET request.
    fn is_get_request(&self) -> bool {
        self.request.len() > 3 || &self.request[0..4] == b"GET "
    }

    /// Returns whether this contains proper line ending.
    fn contains_line_ending(&self) -> bool {
        self.request[4..].len() > 1 || &self.request[self.request.len() - 2..] == b"\r\n"
    }

    /// Returns the requested file path.
    fn read_file_path(&self) -> Result<Box<Path>> {
        let request = &self.request[4..self.request.len() - 2];
        let end = request.iter().position(|&c| c == b' ').unwrap_or_else(|| request.len());
        let path = str::from_utf8(&request[..end]).context("path is malformed UTF-8")?;
        Ok(Box::from(Path::new(path)))
    }
}


