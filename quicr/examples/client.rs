extern crate tokio;
extern crate quicr;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate futures;
extern crate url;
#[macro_use]
extern crate structopt;

use std::net::ToSocketAddrs;
use std::io::{self, Write};
use std::time::{Instant, Duration};
use std::path::PathBuf;
use std::fs;

use futures::Future;
use tokio::runtime::current_thread::Runtime;
use url::Url;
use structopt::StructOpt;

use slog::{Logger, Drain};
use failure::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(StructOpt, Debug)]
#[structopt(name = "client")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[structopt(parse(from_os_str), long = "keylog")]
    keylog: Option<PathBuf>,

    url: Url,

    /// whether to accept invalid (e.g. self-signed) TLS certificates
    #[structopt(long = "accept-insecure-certs")]
    accept_insecure_certs: bool,

    /// file to read/write session tickets to
    #[structopt(long = "session-cache", parse(from_os_str))]
    session_cache: Option<PathBuf>,
}

fn main() {
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e);
            1
        } else { 0 }
    };
    ::std::process::exit(code);
}

fn run(log: Logger, mut options: Opt) -> Result<()> {
    let url = options.url;
    let remote = url.with_default_port(|_| Ok(4433))?.to_socket_addrs()?.next().ok_or(format_err!("couldn't resolve to an address"))?;

    let mut runtime = Runtime::new()?;

    let mut config = quicr::Config {
        protocols: vec![b"hq-11"[..].into()],
        keylog: options.keylog,
        ..quicr::Config::default()
    };

    let ticket;
    if let Some(path) = options.session_cache.take() {
        ticket = match fs::read(&path) {
            Ok(x) => Some(x),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => { return Err(e.into()); }
        };
        let log = log.clone();
        config.session_cache = Some(Box::new(move |_, _, data| {
            fs::write(&path, data).unwrap();
            info!(log, "wrote {bytes}B session", bytes=data.len());
        }));
    } else {
        ticket = None;
    }

    let mut builder = quicr::Endpoint::new();
    builder.logger(log.clone())
        .config(config);
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    let request = format!("GET {}\r\n", url.path());
    let start = Instant::now();
    runtime.block_on(
        endpoint.connect(&remote,
                         quicr::ClientConfig {
                             server_name: Some(url.host_str().ok_or(format_err!("URL missing host"))?),
                             accept_insecure_certs: options.accept_insecure_certs,
                             session_ticket: ticket.as_ref().map(|x| &x[..]),
                             ..quicr::ClientConfig::default()
                         })?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(move |(conn, _)| {
                eprintln!("connected at {}", duration_secs(&start.elapsed()));
                let stream = conn.open_bi();
                stream.map_err(|e| format_err!("failed to open stream: {}", e))
                    .and_then(move |stream| {
                        eprintln!("stream opened at {}", duration_secs(&start.elapsed()));
                        tokio::io::write_all(stream, request.as_bytes().to_owned()).map_err(|e| format_err!("failed to send request: {}", e))
                    })
                    .and_then(|(stream, _)| tokio::io::shutdown(stream).map_err(|e| format_err!("failed to shutdown stream: {}", e)))
                    .and_then(move |stream| {
                        let response_start = Instant::now();
                        eprintln!("request sent at {}", duration_secs(&(response_start - start)));
                        quicr::read_to_end(stream, usize::max_value()).map_err(|e| format_err!("failed to read response: {}", e))
                            .map(move |x| (x, response_start))
                    })
                    .and_then(move |((_, data), response_start)| {
                        let seconds = duration_secs(&response_start.elapsed());
                        eprintln!("response received in {} - {} KiB/s", seconds, data.len() as f32 / (seconds * 1024.0));
                        io::stdout().write_all(&data).unwrap();
                        io::stdout().flush().unwrap();
                        conn.close(0, b"done").map_err(|_| unreachable!())
                    })
                    .map(|()| eprintln!("drained"))
            })
    )?;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 { x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9 }
