#![feature(await_macro, async_await, futures_api)]
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
use futures::{FutureExt, TryFutureExt};
use slog::{Drain, Logger};
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use url::Url;

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
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
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

    let mut endpoint = quinn::Endpoint::new();
    let mut client_config = quinn::ClientConfigBuilder::new();
    client_config.protocols(&[quinn::ALPN_QUIC_HTTP]);
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

    let (endpoint, driver, _) = endpoint.bind("[::]:0")?;
    let mut runtime = Runtime::new()?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)).compat());

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    let rebind = options.rebind;
    let host = options
        .host
        .as_ref()
        .map_or_else(|| url.host_str(), |x| Some(&x))
        .ok_or(format_err!("no hostname specified"))?;
    runtime.block_on(
        async move {
            let hs = endpoint.connect(&remote, &host)?;
            let (conn, _) = await!(hs.establish())?;
            eprintln!("connected at {:?}", start.elapsed());
            let mut stream = await!(conn.open_bi())?;
            if rebind {
                let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
                let addr = socket.local_addr().unwrap();
                eprintln!("rebinding to {}", addr);
                endpoint
                    .rebind(socket, &tokio_reactor::Handle::default())
                    .expect("rebind failed");
            }
            await!(stream.send.write_all(request.as_bytes()))?;
            await!(stream.send.finish())?;
            let response_start = Instant::now();
            eprintln!("request sent at {:?}", response_start - start);
            let response = await!(stream.recv.read_to_end(usize::max_value()))?;
            let duration = response_start.elapsed();
            eprintln!(
                "response received in {:?} - {} KiB/s",
                duration,
                response.len() as f32 / (duration_secs(&duration) * 1024.0)
            );
            io::stdout().write_all(&response).unwrap();
            io::stdout().flush().unwrap();
            await!(conn.close(0, b"done"));
            std::result::Result::<(), Error>::Ok(())
        }
            .boxed()
            .compat(),
    )?;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
