extern crate quinn;
extern crate tokio;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate futures;
extern crate slog_term;
#[macro_use]
extern crate structopt;

use std::net::ToSocketAddrs;

use futures::{Future, Stream};
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

use failure::Error;
use slog::{Drain, Logger};

type Result<T> = std::result::Result<T, Error>;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: String,
    #[structopt(default_value = "4433")]
    port: u16,
    retry_port: Option<u16>,

    /// Enable key logging
    #[structopt(long = "keylog")]
    keylog: bool,
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
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    let mut runtime = Runtime::new()?;

    let mut builder = quinn::Endpoint::new();
    let mut client_config = quinn::ClientConfigBuilder::new();
    client_config.accept_insecure_certs(); // Various interop test servers use self-signed certs
    builder.logger(log.clone());
    if options.keylog {
        client_config.enable_keylog();
    }
    let client_config = client_config.build();
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut ticket = None;
    let result = runtime.block_on(
        endpoint
            .connect_with(&client_config, &remote, &options.host)?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(|conn| {
                println!("connected");
                handshake = true;
                let tickets = conn.session_tickets;
                let conn = conn.connection;
                let stream = conn.open_bi();
                let stream_data = &mut stream_data;
                stream
                    .map_err(|e| format_err!("failed to open stream: {}", e))
                    .and_then(move |stream| get(stream))
                    .and_then(move |data| {
                        println!("read {} bytes, closing", data.len());
                        *stream_data = true;
                        conn.close(0, b"done").map_err(|_| unreachable!())
                    })
                    .map(|()| {
                        close = true;
                    })
                    .and_then(|()| {
                        tickets
                            .into_future()
                            .map_err(|(e, _)| e.into())
                            .map(|(x, _)| {
                                if let Some(x) = x {
                                    ticket = Some(x);
                                }
                            })
                    })
            }),
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    let mut retry = false;
    if let Some(port) = options.retry_port {
        println!("connecting to retry port");
        let remote = format!("{}:{}", options.host, port)
            .to_socket_addrs()?
            .next()
            .ok_or(format_err!("couldn't resolve to an address"))?;
        let result = runtime.block_on(
            endpoint
                .connect_with(&client_config, &remote, &options.host)?
                .and_then(|conn| {
                    retry = true;
                    conn.connection
                        .close(0, b"done")
                        .map_err(|_| unreachable!())
                }),
        );
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }

    let resumption = false;
    /*
    if let Some(ticket) = ticket {
        println!("attempting 0-RTT");
        let (conn, established) = endpoint.connect_zero_rtt(
            &remote,
            &options.host,
        )?;
        let conn = conn.connection;
        let request = conn
            .open_bi()
            .map_err(|e| format_err!("failed to open stream: {}", e))
            .and_then(|stream| get(stream))
            .and_then(|data| {
                println!("read {} bytes, closing", data.len());
                resumption = conn.session_resumed();
                conn.close(0, b"done").map_err(|_| unreachable!())
            });
        let result = runtime.block_on(
            established
                .map_err(|e| format_err!("failed to connect: {}", e))
                .join(request),
        );
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }
    */

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

fn get(stream: quinn::BiStream) -> impl Future<Item = Box<[u8]>, Error = Error> {
    tokio::io::write_all(stream, b"GET /index.html\r\n".to_owned())
        .map_err(|e| format_err!("failed to send request: {}", e))
        .and_then(|(stream, _)| {
            tokio::io::shutdown(stream).map_err(|e| format_err!("failed to shutdown stream: {}", e))
        })
        .and_then(move |stream| {
            quinn::read_to_end(stream, usize::max_value())
                .map_err(|e| format_err!("failed to read response: {}", e))
        })
        .map(|(_, data)| data)
}
