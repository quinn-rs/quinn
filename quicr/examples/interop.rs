extern crate tokio;
extern crate quicr;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate futures;
#[macro_use]
extern crate structopt;

use std::net::ToSocketAddrs;
use std::path::PathBuf;

use futures::{Future, Stream};
use tokio::runtime::current_thread::Runtime;
use structopt::StructOpt;

use slog::{Logger, Drain};
use failure::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: String,
    #[structopt(default_value = "4433")]
    port: u16,
    retry_port: Option<u16>,

    /// file to log TLS keys to for debugging
    #[structopt(parse(from_os_str), long = "keylog")]
    keylog: Option<PathBuf>,
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

fn run(log: Logger, options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port).to_socket_addrs()?.next().ok_or(format_err!("couldn't resolve to an address"))?;

    let mut runtime = Runtime::new()?;

    let config = quicr::Config {
        protocols: vec![b"hq-11"[..].into()],
        keylog: options.keylog,
        ..quicr::Config::default()
    };

    let mut builder = quicr::Endpoint::new();
    builder.logger(log.clone())
        .config(config);
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut ticket = None;
    let result = runtime.block_on(
        endpoint.connect(&remote,
                         quicr::ClientConfig {
                             server_name: Some(&options.host),
                             accept_insecure_certs: true,
                             ..quicr::ClientConfig::default()
                         })?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(|conn| {
                println!("connected");
                handshake = true;
                let tickets = conn.session_tickets;
                let conn = conn.connection;
                let stream = conn.open_bi();
                stream.map_err(|e| format_err!("failed to open stream: {}", e))
                    .and_then(move |stream| {
                        tokio::io::write_all(stream, b"GET /index.html\r\n".to_owned()).map_err(|e| format_err!("failed to send request: {}", e))
                    })
                    .and_then(|(stream, _)| tokio::io::shutdown(stream).map_err(|e| format_err!("failed to shutdown stream: {}", e)))
                    .and_then(move |stream| {
                        quicr::read_to_end(stream, usize::max_value()).map_err(|e| format_err!("failed to read response: {}", e))
                    })
                    .and_then(|(_, data)| {
                        println!("read {} bytes, closing", data.len());
                        stream_data = true;
                        conn.close(0, b"done").map_err(|_| unreachable!())
                    })
                    .map(|()| { close = true; })
                    .and_then(|()| tickets.into_future().map_err(|(e, _)| e.into())
                              .map(|(x, _)| if let Some(x) = x { ticket = Some(x); }))
            })
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    let mut retry = false;
    if let Some(port) = options.retry_port {
        println!("connecting to retry port");
        let remote = format!("{}:{}", options.host, port).to_socket_addrs()?.next().ok_or(format_err!("couldn't resolve to an address"))?;
        let result = runtime.block_on(endpoint.connect(&remote,
                                                       quicr::ClientConfig {
                                                           server_name: Some(&options.host),
                                                           accept_insecure_certs: true,
                                                           ..quicr::ClientConfig::default()
                                                       })?
                                      .and_then(|conn| {
                                          retry = true;
                                          conn.connection.close(0, b"done").map_err(|_| unreachable!())
                                      }));
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }

    let mut resumption = false;
    if let Some(ticket) = ticket {
        println!("attempting resumption");
        let result = runtime.block_on(endpoint.connect(&remote,
                                                       quicr::ClientConfig {
                                                           server_name: Some(&options.host),
                                                           accept_insecure_certs: true,
                                                           session_ticket: Some(&ticket),
                                                           ..quicr::ClientConfig::default()
                                                       })?
                                      .and_then(|conn| {
                                          resumption = conn.connection.session_resumed();
                                          conn.connection.close(0, b"done").map_err(|_| unreachable!())
                                      }));
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }

    if handshake {
        print!("VH");
    }
    if stream_data {
        print!("D");
    }
    if close {
        print!("C");
    }
    if resumption {
        print!("R");
    }
    if retry {
        print!("S");
    }

    println!("");

    Ok(())
}
