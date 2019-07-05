#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use std::fs;
use std::io::{self, Write};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use failure::Error;
use futures::Future;
use slog::{Drain, Logger};
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use url::Url;

mod common;

type Result<T> = std::result::Result<T, Error>;

/// HTTP/0.9 over QUIC client
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
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::TermDecorator::new().stderr().build();
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        // We use a mutex-protected drain for simplicity; this example is single-threaded anyway.
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

fn run(log: Logger, options: Opt) -> Result<()> {
    let url = options.url;
    let remote = url
        .with_default_port(|_| Ok(4433))?
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(&[common::ALPN_QUIC_HTTP]);
    endpoint.logger(log.clone());
    if options.keylog {
        client_config.enable_keylog();
    }
    if let Some(ca_path) = options.ca {
        client_config
            .add_certificate_authority(quinn::Certificate::from_der(&fs::read(&ca_path)?)?)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!(log, "local server certificate not found");
            }
            Err(e) => {
                error!(log, "failed to open local server certificate: {}", e);
            }
        }
    }

    endpoint.default_client_config(client_config.build());

    let (endpoint_driver, endpoint, _) = endpoint.bind("[::]:0")?;
    let mut runtime = Runtime::new()?;
    runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    let rebind = options.rebind;
    let host = options
        .host
        .as_ref()
        .map_or_else(|| url.host_str(), |x| Some(&x))
        .ok_or(format_err!("no hostname specified"))?;
    runtime.block_on(
        endpoint
            .connect(&remote, &host)?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(move |(conn_driver, conn, _)| {
                eprintln!("connected at {:?}", start.elapsed());
                tokio_current_thread::spawn(
                    conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
                );
                let stream = conn.open_bi();
                stream
                    .map_err(|e| format_err!("failed to open stream: {}", e))
                    .and_then(move |(send, recv)| {
                        if rebind {
                            let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
                            let addr = socket.local_addr().unwrap();
                            eprintln!("rebinding to {}", addr);
                            endpoint
                                .rebind(socket, &tokio_reactor::Handle::default())
                                .expect("rebind failed");
                        }

                        tokio::io::write_all(send, request.as_bytes().to_owned())
                            .map_err(|e| format_err!("failed to send request: {}", e))
                            .and_then(|(send, _)| {
                                send.finish()
                                    .map_err(|e| format_err!("failed to shutdown stream: {}", e))
                            })
                            .and_then(move |_| {
                                let response_start = Instant::now();
                                eprintln!("request sent at {:?}", response_start - start);
                                recv.read_to_end(usize::max_value())
                                    .map_err(|e| format_err!("failed to read response: {}", e))
                                    .map(move |x| (x, response_start))
                            })
                    })
                    .map(move |(data, response_start)| {
                        let duration = response_start.elapsed();
                        eprintln!(
                            "response received in {:?} - {} KiB/s",
                            duration,
                            data.len() as f32 / (duration_secs(&duration) * 1024.0)
                        );
                        io::stdout().write_all(&data).unwrap();
                        io::stdout().flush().unwrap();
                        conn.close(0, b"done");
                    })
                    .map(|()| eprintln!("drained"))
            }),
    )?;

    // Let the connection to finish closing gracefully
    runtime.run()?;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
