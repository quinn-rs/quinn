extern crate quinn;
extern crate tokio;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate futures;
extern crate rustls;
extern crate slog_term;
extern crate structopt;

use std::net::ToSocketAddrs;
use std::str;
use std::sync::{Arc, Mutex};

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
    #[structopt(default_value = "4434")]
    retry_port: u16,

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

struct State {
    saw_cert: bool,
}

fn run(log: Logger, options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    let mut runtime = Runtime::new()?;

    let state = Arc::new(Mutex::new(State { saw_cert: false }));

    let mut builder = quinn::Endpoint::new();
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    tls_config.alpn_protocols = vec![str::from_utf8(quinn::ALPN_QUIC_HTTP).unwrap().into()];
    if options.keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        tls_config: Arc::new(tls_config),
    };

    builder.logger(log.clone());
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut ticket = None;
    let mut resumption = false;
    let mut key_update = false;
    let result = runtime.block_on(
        endpoint
            .connect_with(&client_config, &remote, &options.host)?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(|conn| {
                println!("connected");
                assert!(state.lock().unwrap().saw_cert);
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
            })
            .and_then(|_| {
                println!("attempting resumption");
                state.lock().unwrap().saw_cert = false;
                endpoint
                    .connect_with(&client_config, &remote, &options.host)
                    .unwrap()
                    .map_err(|e| format_err!("failed to connect: {}", e))
                    .and_then(|conn| {
                        resumption = !state.lock().unwrap().saw_cert;
                        let conn = conn.connection;
                        conn.force_key_update();
                        let stream = conn.open_bi();
                        stream
                            .map_err(|e| format_err!("failed to open stream: {}", e))
                            .and_then(move |stream| get(stream))
                            .inspect(|_| {
                                key_update = true;
                            })
                            .and_then(move |_| conn.close(0, b"done").map_err(|_| unreachable!()))
                    })
            }),
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    let mut retry = false;
    {
        println!("connecting to retry port");
        let remote = format!("{}:{}", options.host, options.retry_port)
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
    if key_update {
        print!("U");
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

struct InteropVerifier(Arc<Mutex<State>>);
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
