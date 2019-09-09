use std::net::ToSocketAddrs;
use std::path::PathBuf;
use structopt::{self, StructOpt};

use failure::{format_err, Error};
use futures::Future;
use http::{header::HeaderValue, method::Method, HeaderMap, Request};
use slog::{o, Logger};
use tokio::runtime::current_thread::{self, Runtime};
use url::Url;

use quinn_h3::{self, client::Builder as ClientBuilder};
use quinn_proto::crypto::rustls::Certificate;

mod shared;
use shared::{build_certs, logger, Result};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_client")]
struct Opt {
    #[structopt(default_value = "http://127.0.0.1:4433/Cargo.toml")]
    url: Url,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
}

fn main() {
    let opt = Opt::from_args();
    let log = logger("h3".into());
    let certs = build_certs(log.clone(), &opt.key, &opt.cert).expect("failed to build certs");

    let mut runtime = Runtime::new().expect("runtime failed");

    let (driver, client) =
        client(log.new(o!("client" => "")), opt, certs.1).expect("client failed");

    runtime.spawn(driver.map_err(|_| println!("client driver failed:")));
    runtime
        .block_on(
            client
                .and_then(|_| futures::future::ok(()))
                .map_err(|e| println!("client failed: {:?}", e)),
        )
        .expect("block on server failed");

    runtime.run().expect("connection close failed");

    ::std::process::exit(0);
}

const INITIAL_CAPACITY: usize = 256;
const MAX_LEN: usize = 256 * 1024;

fn client(
    log: Logger,
    options: Opt,
    cert: Certificate,
) -> Result<(quinn::EndpointDriver, impl Future<Item = (), Error = Error>)> {
    let url = options.url;
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(&[quinn_h3::ALPN]);
    endpoint.logger(log.clone());

    client_config.add_certificate_authority(cert)?;
    endpoint.default_client_config(client_config.build());
    let builder = ClientBuilder::new(endpoint);

    let (endpoint_driver, client) = builder.bind("[::]:0")?;

    let fut = client
        .connect(&remote, "localhost")?
        .map_err(|e| format_err!("failed to connect: {}", e))
        .and_then(move |(quic_driver, driver, conn)| {
            current_thread::spawn(quic_driver.map_err(|e| eprintln!("quic server error: {}", e)));
            current_thread::spawn(driver.map_err(|e| eprintln!("h3 server error: {}", e)));

            let request = Request::builder()
                .method(Method::POST)
                .uri("/hello")
                .header("foo", "bar")
                .body("request body")
                .expect("failed to build request");

            let mut trailer = HeaderMap::with_capacity(2);
            trailer.append(
                "request",
                HeaderValue::from_str("trailer").expect("trailer value"),
            );

            conn.request(request)
                .trailers(trailer)
                .send()
                .map_err(|e| format_err!("send request failed: {}", e))
                .and_then(|response| {
                    let (response, body) = response.into_parts();
                    println!("received response: {:?}", response);

                    body.read_to_end(INITIAL_CAPACITY, MAX_LEN)
                        .map_err(|e| format_err!("receive body failed: {}", e))
                        .and_then(move |(content, trailers)| {
                            if let Some(content) = content {
                                println!("received body: {}", String::from_utf8_lossy(&content));
                            }

                            if let Some(trailers) = trailers {
                                println!("received trailers: {:?}", trailers);
                            }
                            futures::future::ok(())
                        })
                })
                .and_then(move |_| {
                    conn.close(0x100, b"Closing");
                    futures::future::ok(())
                })
        });

    Ok((endpoint_driver, Box::new(fut)))
}
