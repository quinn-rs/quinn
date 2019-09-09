use std::net::SocketAddr;
use std::path::PathBuf;

use failure::{format_err, Error};
use futures::{Future, Stream};
use http::{header::HeaderValue, HeaderMap, Request, Response, StatusCode};
use structopt::{self, StructOpt};
use tokio::runtime::current_thread::{self, Runtime};

use quinn::ConnectionDriver as QuicDriver;
use quinn_h3::{
    self,
    body::RecvBody,
    connection::ConnectionDriver,
    server::{Builder as ServerBuilder, IncomingRequest, Sender},
};
use quinn_proto::crypto::rustls::{CertificateChain, PrivateKey};

mod shared;
use shared::{build_certs, logger, Result};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_server")]
struct Opt {
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    /// Address to listen on
    #[structopt(long = "listen", default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
}

fn main() {
    let opt = Opt::from_args();
    let log = logger("server".into());
    let certs = build_certs(log, &opt.key, &opt.cert).expect("failed to build certs");

    let mut runtime = Runtime::new().expect("runtime failed");
    let server = server(
        opt.clone(),
        &mut runtime,
        (certs.0.clone(), certs.2.clone()),
    )
    .expect("server failed");

    runtime
        .block_on(
            server
                .and_then(|_| {
                    println!("server finished");
                    futures::future::ok(())
                })
                .map_err(|e| println!("client failed: {:?}", e)),
        )
        .expect("block on server failed");
    ::std::process::exit(0);
}

fn server(
    options: Opt,
    runtime: &mut Runtime,
    certs: (CertificateChain, PrivateKey),
) -> Result<quinn::EndpointDriver> {
    let mut server_config = quinn::ServerConfigBuilder::new(quinn::ServerConfig::default());
    server_config.protocols(&[quinn_h3::ALPN]);
    server_config.certificate(certs.0, certs.1)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let server = ServerBuilder::new(endpoint);

    let (endpoint_driver, incoming) = {
        let (driver, _server, incoming) = server.bind(options.listen)?;
        println!("server listening");
        (driver, incoming)
    };

    runtime.spawn(incoming.for_each(|connecting| {
        println!("server received connection");
        connecting
            .map_err(|e| eprintln!("connecting failed: {}", e))
            .and_then(|connection| {
                println!("received connection");
                handle_connection(connection).map_err(|e| eprintln!("connecting failed: {}", e))
            })
    }));
    Ok(endpoint_driver)
}

fn handle_connection(
    conn: (QuicDriver, ConnectionDriver, IncomingRequest),
) -> impl Future<Item = (), Error = Error> {
    let (quic_driver, driver, incoming) = conn;

    current_thread::spawn(
        incoming
            .map_err(|e| format_err!("incoming error: {}", e))
            .for_each(|request| {
                request
                    .map_err(|e| format_err!("recv request: {}", e))
                    .and_then(|(req, send)| handle_request(req, send))
            })
            .map_err(|e| eprintln!("server error: {}", e)),
    );

    current_thread::spawn(quic_driver.map_err(|e| eprintln!("quic server error: {}", e)));
    current_thread::spawn(driver.map_err(|e| eprintln!("h3 server error: {}", e)));
    futures::future::ok(())
}

const INITIAL_CAPACITY: usize = 256;
const MAX_LEN: usize = 256;

fn handle_request(
    request: Request<RecvBody>,
    sender: Sender,
) -> impl Future<Item = (), Error = Error> {
    println!("received request: {:?}", request);

    let (_, body) = request.into_parts();

    body.read_to_end(INITIAL_CAPACITY, MAX_LEN)
        .map_err(|e| format_err!("failed to send response headers: {:?}", e))
        .and_then(move |(content, trailers)| {
            if let Some(content) = content {
                println!("received body: {}", String::from_utf8_lossy(&content));
            }

            if let Some(trailers) = trailers {
                println!("received trailers: {:?}", trailers);
            }

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("response", "header")
                .body("response body")
                .expect("failed to build response");

            let mut trailer = HeaderMap::with_capacity(2);
            trailer.append(
                "response",
                HeaderValue::from_str("trailer").expect("trailer value"),
            );

            sender
                .response(response)
                .trailers(trailer)
                .send()
                .map_err(|e| format_err!("failed to send response: {:?}", e))
                .and_then(|_| futures::future::ok(()))
        })
}
