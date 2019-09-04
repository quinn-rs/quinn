use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;
use std::{fmt, fs, io};

use failure::{bail, format_err, Error, Fail, ResultExt};
use futures::{future::Either, Future, Stream};
use http::{header::HeaderValue, method::Method, HeaderMap, Request, Response, StatusCode};
use slog::{info, o, Drain, Logger};
use structopt::{self, StructOpt};
use tokio::runtime::current_thread::{self, Runtime};
use url::Url;

use quinn::ConnectionDriver as QuicDriver;
use quinn_h3::{
    self,
    body::RecvBody,
    client::Builder as ClientBuilder,
    connection::ConnectionDriver,
    server::{Builder as ServerBuilder, IncomingRequest, Sender},
};
use quinn_proto::crypto::rustls::{Certificate, CertificateChain, PrivateKey};

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

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3")]
struct Opt {
    #[structopt(short = "s", long = "server")]
    server: bool,
    #[structopt(default_value = "http://127.0.0.1:4433/Cargo.toml")]
    url: Url,
    /// directory to serve files from
    #[structopt(parse(from_os_str), default_value = ".")]
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
    #[structopt(long = "listen", default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    /// Custom certificate authority to trust, in DER format
    #[structopt(parse(from_os_str), long = "ca")]
    ca: Option<PathBuf>,
    /// Simulate NAT rebinding after connecting
    #[structopt(long = "rebind")]
    rebind: bool,
}

fn main() {
    let opt = Opt::from_args();
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
    let drain = slog_term::FullFormat::new(decorator)
        .use_original_order()
        .build()
        .fuse();
    let log = Logger::root(drain, o!("h3" => ""));

    let certs = build_certs(log.clone(), opt.clone()).expect("failed to build certs");

    let mut runtime = Runtime::new().expect("runtime failed");
    let server = server(
        log.new(o!("server" => "")),
        opt.clone(),
        &mut runtime,
        (certs.0.clone(), certs.2.clone()),
    )
    .expect("server failed");

    let (driver, client) =
        client(log.new(o!("client" => "")), opt, certs.1).expect("client failed");

    runtime.spawn(driver.map_err(|_| println!("client driver failed:")));
    runtime.spawn(server.map_err(|e| println!("server driver failed: {:?}", e)));
    runtime
        .block_on(
            client
                .and_then(|_| {
                    println!("client finished");
                    futures::future::ok(())
                })
                .map_err(|e| println!("client failed: {:?}", e)),
        )
        .expect("block on server failed");
    ::std::process::exit(0);
}

fn server(
    log: Logger,
    options: Opt,
    runtime: &mut Runtime,
    certs: (CertificateChain, PrivateKey),
) -> Result<quinn::EndpointDriver> {
    let server_config = quinn::ServerConfig {
        transport: Arc::new(quinn::TransportConfig {
            stream_window_uni: 513,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(&[quinn_h3::ALPN]);

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }
    server_config.certificate(certs.0, certs.1)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.logger(log.clone());
    endpoint.listen(server_config.build());

    let root = Rc::new(options.root);
    if !root.exists() {
        bail!("root path does not exist");
    }

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

fn handle_request(
    request: Request<RecvBody>,
    sender: Sender,
) -> impl Future<Item = (), Error = Error> {
    println!("received request: {:?}", request);
    let (_, body) = request.into_parts();
    let content = Vec::with_capacity(1024);
    tokio::io::read_to_end(body.into_reader(), content)
        .map_err(|e| format_err!("failed to receive response body: {:?}", e))
        .and_then(move |(reader, content)| {
            println!("server received body len: {:?}", content.len());

            match reader.trailers() {
                None => Either::A(futures::future::ok(())),
                Some(decode_trailers) => Either::B(
                    decode_trailers
                        .map_err(|e| format_err!("decode trailers failed: {}", e))
                        .and_then(move |trailers| {
                            println!("received trailers: {:?}", trailers.into_fields());
                            futures::future::ok(())
                        }),
                ),
            }
        })
        .and_then(move |_| {
            let response = Response::builder()
                .status(StatusCode::OK)
                .body("first part of body")
                .expect("failed to build response");

            let mut trailer = HeaderMap::with_capacity(2);
            trailer.append(
                "response",
                HeaderValue::from_str("trailer").expect("trailer value"),
            );

            sender
                .response(response)
                .trailers(trailer)
                .stream()
                .map_err(|e| format_err!("failed to send response headers: {:?}", e))
                .and_then(|writer| {
                    let body = "r".repeat(1024);
                    tokio::io::write_all(writer, body)
                        .map_err(|e| format_err!("failed to send response body: {:?}", e))
                })
                .and_then(|(writer, _size)| {
                    writer
                        .close()
                        .map_err(|e| format_err!("failed to send response body: {:?}", e))
                })
                .and_then(|_| futures::future::ok(()))
        })
}

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

    let start = Instant::now();
    let fut = client
        .connect(&remote, "localhost")?
        .map_err(|e| format_err!("failed to connect: {}", e))
        .and_then(move |(quic_driver, driver, conn)| {
            eprintln!("client connected at {:?}", start.elapsed());

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
                .stream()
                .map_err(|e| format_err!("send request failed: {}", e))
                .and_then(|(send_body, response)| {
                    let response_fut = response
                        .map_err(|e| format_err!("receive response failed: {}", e))
                        .and_then(|response| {
                            println!("received response: {:?}", response);

                            let (_, body) = response.into_parts();

                            let buf = Vec::with_capacity(1024 * 10); // 10K
                            tokio_io::io::read_to_end(body.into_reader(), buf)
                                .map_err(|e| format_err!("receive body failed: {}", e))
                                .and_then(|(reader, data)| {
                                    println!("received body len = {}", data.len());
                                    if let Some(decode_trailers) = reader.trailers() {
                                        return Either::A(
                                            decode_trailers
                                                .map_err(|e| {
                                                    format_err!("decode trailers failed: {}", e)
                                                })
                                                .and_then(|trailers| {
                                                    println!(
                                                        "received trailers: {:?}",
                                                        trailers.into_fields()
                                                    );
                                                    futures::future::ok(())
                                                }),
                                        );
                                    }
                                    Either::B(futures::future::ok(()))
                                })
                        });

                    let body = "r".repeat(1024);
                    let send_body_fut = tokio::io::write_all(send_body, body)
                        .map_err(|e| format_err!("failed to send response body: {:?}", e))
                        .and_then(|(writer, _size)| {
                            writer
                                .close()
                                .map_err(|e| format_err!("failed to send response body: {:?}", e))
                        });

                    send_body_fut.join(response_fut).map(|_| ())
                })
        });

    Ok((endpoint_driver, Box::new(fut)))
}

fn build_certs(log: Logger, options: Opt) -> Result<(CertificateChain, Certificate, PrivateKey)> {
    if let (Some(ref key_path), Some(ref cert_path)) = (options.key, options.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert = quinn::Certificate::from_der(&cert_chain)?;
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);
        Ok((cert_chain, cert, key))
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!(log, "generating self-signed certificate");
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
        Ok((
            quinn::CertificateChain::from_certs(vec![cert.clone()]),
            cert,
            key,
        ))
    }
}
