#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use std::net::SocketAddr;
use std::path::{self, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::{ascii, fmt, fs, io, str};

use failure::{Error, Fail, ResultExt};
use futures::{Future, Stream};
use slog::{Drain, Logger};
use structopt::{self, StructOpt};
use tokio::runtime::current_thread::Runtime;

type Result<T> = std::result::Result<T, Error>;

pub struct PrettyErr<'a>(&'a dyn Fail);
impl<'a> fmt::Display for PrettyErr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)?;
        let mut x: &dyn Fail = self.0;
        while let Some(cause) = x.cause() {
            f.write_str(": ")?;
            fmt::Display::fmt(&cause, f)?;
            x = cause;
        }
        Ok(())
    }
}

pub trait ErrorExt {
    fn pretty(&self) -> PrettyErr<'_>;
}

impl ErrorExt for Error {
    fn pretty(&self) -> PrettyErr<'_> {
        PrettyErr(self.as_fail())
    }
}

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
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e.pretty());
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

fn run(log: Logger, options: Opt) -> Result<()> {
    let server_config = quinn::ServerConfig {
        transport_config: Arc::new(quinn::TransportConfig {
            stream_window_uni: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(&[quinn::ALPN_QUIC_HTTP]);

    if options.keylog {
        server_config.enable_keylog();
    }

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    if let (Some(ref key_path), Some(ref cert_path)) = (options.key, options.cert) {
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
        server_config.certificate(cert_chain, key)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!(log, "generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der();
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
        server_config.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
    }

    let mut endpoint = quinn::Endpoint::new();
    endpoint.logger(log.clone());
    endpoint.listen(server_config.build());

    let root = Rc::new(options.root);
    if !root.exists() {
        bail!("root path does not exist");
    }

    let (_, driver, incoming) = endpoint.bind(options.listen)?;
    let mut runtime = Runtime::new()?;
    runtime.spawn(incoming.for_each(move |conn| {
        handle_connection(&root, &log, conn);
        Ok(())
    }));
    runtime.block_on(driver)?;

    Ok(())
}

fn handle_connection(root: &PathBuf, log: &Logger, conn: quinn::NewConnection) {
    let quinn::NewConnection {
        driver,
        incoming,
        connection,
    } = conn;
    let log = log.clone();
    info!(log, "got connection";
          "remote_id" => %connection.remote_id(),
          "address" => %connection.remote_address(),
          "protocol" => connection.protocol().map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned()));
    let log2 = log.clone();
    let root = root.clone();

    tokio_current_thread::spawn(driver.map_err(|e| panic!(e)));

    // Each stream initiated by the client constitutes a new request.
    tokio_current_thread::spawn(
        incoming
            .map_err(move |e| info!(log2, "connection terminated"; "reason" => %e))
            .for_each(move |stream| {
                handle_request(&root, &log, stream);
                Ok(())
            }),
    );
}

fn handle_request(root: &PathBuf, log: &Logger, stream: quinn::NewStream) {
    let stream = match stream {
        quinn::NewStream::Bi(stream) => stream,
        quinn::NewStream::Uni(_) => unreachable!("disabled by endpoint configuration"),
    };
    let root = root.clone();
    let log = log.clone();
    let log2 = log.clone();
    let log3 = log.clone();

    tokio_current_thread::spawn(
        quinn::read_to_end(stream, 64 * 1024) // Read the request, which must be at most 64KiB
            .map_err(|e| format_err!("failed reading request: {}", e))
            .and_then(move |(stream, req)| {
                let mut escaped = String::new();
                for &x in &req[..] {
                    let part = ascii::escape_default(x).collect::<Vec<_>>();
                    escaped.push_str(str::from_utf8(&part).unwrap());
                }
                info!(log, "got request"; "content" => escaped);
                // Execute the request
                let resp = process_get(&root, &req).unwrap_or_else(move |e| {
                    error!(log, "failed to process request"; "reason" => %e.pretty());
                    format!("failed to process request: {}\n", e.pretty())
                        .into_bytes()
                        .into()
                });
                // Write the response
                tokio::io::write_all(stream, resp)
                    .map_err(|e| format_err!("failed to send response: {}", e))
            })
            // Gracefully terminate the stream
            .and_then(|(stream, _)| {
                tokio::io::shutdown(stream)
                    .map_err(|e| format_err!("failed to shutdown stream: {}", e))
            })
            .map(move |_| info!(log3, "request complete"))
            .map_err(move |e| error!(log2, "request failed"; "reason" => %e.pretty())),
    )
}

fn process_get(root: &Path, x: &[u8]) -> Result<Box<[u8]>> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let path = str::from_utf8(&x[4..x.len() - 2]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);
    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
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
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data.into())
}
