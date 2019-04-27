#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{fmt, fs, io};

use bytes::{BytesMut, Buf};
use failure::{Error, Fail, ResultExt};
use futures::{Async, Future, Poll, Stream, try_ready};
use slog::{Drain, Logger};
use structopt::{self, StructOpt};
use tokio::runtime::current_thread::Runtime;
use url::Url;

use quinn::RecvStream;
use quinn_h3::{frame::{ SettingsFrame, HttpFrame}, Connection, StreamType};

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
    let sdecorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
    let cdecorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
    let sdrain = slog_term::FullFormat::new(sdecorator)
        .use_original_order()
        .build()
        .fuse();
    let cdrain = slog_term::FullFormat::new(cdecorator)
        .use_original_order()
        .build()
        .fuse();

    let mut runtime = Runtime::new().expect("runtime failed");
    let server = server(
        Logger::root(sdrain, o!("server" => "")),
        opt.clone(),
        &mut runtime,
    )
    .expect("server failed");

    let client =
        client(Logger::root(cdrain, o!("client" => "")), opt, &mut runtime).expect("client failed");

    runtime.spawn(client.map_err(|_| println!("client failed:")));
    runtime.block_on(server).expect("block on server failed");
    ::std::process::exit(0);
}

fn server(log: Logger, options: Opt, runtime: &mut Runtime) -> Result<quinn::EndpointDriver> {
    let server_config = quinn::ServerConfig {
        transport: Arc::new(quinn::TransportConfig {
            stream_window_uni: 513,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(&[quinn::ALPN_QUIC_H3]);

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

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.logger(log.clone());
    endpoint.listen(server_config.build());

    let root = Rc::new(options.root);
    if !root.exists() {
        bail!("root path does not exist");
    }

    let server = ServerBuilder::with_endpoint(endpoint);

    let (endpoint_driver, incoming) = {
        let (driver, _server, incoming) = server.bind(options.listen)?;
        // info!(log, "listening on {}", endpoint.local_addr()?);
        (driver, incoming)
    };

    runtime.spawn(incoming.for_each(move |conn| {
        info!(log, "listenning");
        handle_connection(&log, conn);
        Ok(())
    }));
    Ok(endpoint_driver)
}

fn handle_connection(log: &Logger, conn: (H3ConnectionDriver, H3Connection, H3IncomingRequests)) {
    let (conn_driver, _conn, _incoming_streams) = conn;
    let log = log.clone();
    info!(log, "got connection");

    // We ignore errors from the driver because they'll be reported by the `incoming` handler anyway.
    tokio_current_thread::spawn(conn_driver.map_err(|_| ()));
}

//===================== THE MESS =====================================

struct ServerBuilder<'a> {
    endpoint: quinn::EndpointBuilder<'a>,
}

struct Server;

impl<'a> ServerBuilder<'a> {
    fn with_endpoint(endpoint: quinn::EndpointBuilder<'a>) -> Self {
        Self { endpoint: endpoint }
    }

    fn bind<T: ToSocketAddrs>(
        self,
        addr: T,
    ) -> Result<(quinn::EndpointDriver, Server, H3Incoming)> {
        let (endpoint_driver, _endpoint, incoming) = self.endpoint.bind(addr)?;
        println!("Server driver");
        Ok((endpoint_driver, Server, H3Incoming { incoming }))
    }
}

struct H3Incoming {
    incoming: quinn::Incoming,
}

impl Stream for H3Incoming {
    type Item = (H3ConnectionDriver, H3Connection, H3IncomingRequests);
    type Error = (); // FIXME: Infallible
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.incoming.poll() {
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
            Ok(Async::Ready(Some((driver, conn, incoming)))) => {
                tokio_current_thread::spawn(
                    driver.map_err(|e| eprintln!("connection lost: {}", e)),
                );
                let h3_conn = H3ConnectionRef(Arc::new(Mutex::new(quinn_h3::Connection::new())));
                Ok(Async::Ready(Some((
                    H3ConnectionDriver {
                        conn: h3_conn.clone(),
                        incoming: incoming,
                        streams: Vec::new(),
                        control: None,
                    },
                    H3Connection {
                        quic: conn,
                        conn: h3_conn.clone(),
                    },
                    H3IncomingRequests(h3_conn),
                ))))
            }
        }
    }
}

#[derive(Clone)]
struct H3ConnectionRef(Arc<Mutex<Connection>>);

struct H3ConnectionDriver {
    conn: H3ConnectionRef,
    incoming: quinn::IncomingStreams,
    streams: Vec<NewUniStream>,
    control: Option<ControlStream>,
}

impl Future for H3ConnectionDriver {
    type Item = ();
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        println!("H3 drive Connection");

        match self.incoming.poll() {
            Err(e) => {
                println!("Err: {}", e);
                return Err(e)?;
            }
            Ok(Async::NotReady) => println!("TODO: Incoming stream not ready..."),
            Ok(Async::Ready(None)) => {
                println!("Ready None");
            }
            Ok(Async::Ready(Some(stream))) => {
                println!("Recv stream");
                match stream {
                    quinn::NewStream::Uni(s) => {
                        self.streams.push(NewUniStream {
                            stream: s,
                            buf: BytesMut::with_capacity(20),
                        });
                    }
                    quinn::NewStream::Bi(_send, _recv) => {
                        println!("Bi stream");
                    }
                }
            }
        };

        let ready = self
            .streams
            .iter_mut()
            .enumerate()
            .filter_map(
                |(idx, stream)| match stream.poll().expect("stream poll failed") {
                    Async::NotReady => None,
                    Async::Ready(ty) => Some((idx, ty)),
                },
            )
            .collect::<Vec<(usize, StreamType)>>();

        if !ready.is_empty() {
            let conn = &mut self.conn.0.lock().unwrap();
            for (idx, ty) in ready.into_iter() {
                let new_uni = self.streams.remove(idx);
                match conn.on_recv_stream(ty) {
                    Ok(()) => {
                        self.control = Some(ControlStream::new(new_uni, self.conn.clone()));
                    }
                    _ => {
                        self.streams.remove(idx);
                    },
                }
            }
        }

        if let Some(ref mut control) = self.control {
            control.poll().ok();
        }

        Ok(Async::NotReady)
    }
}

struct NewUniStream {
    stream: RecvStream,
    buf: BytesMut,
}

impl Future for NewUniStream {
    type Item = StreamType;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        println!("Managed stream: poll");

        let mut buf = [0u8; 8];
        let size = try_ready!(self.stream.poll_read(&mut buf));

        println!("Managed stream: read {}", size);
        self.buf.extend(&buf[..size]);
        let mut cur = io::Cursor::new(&self.buf[..]);
        match StreamType::decode(&mut cur) {
            Err(_) => Ok(Async::NotReady),
            Ok(ty) => {
                self.buf.advance(cur.position() as usize);
                Ok(Async::Ready(ty))
            }
        }
    }
}

pub struct EncoderStream;
pub struct DecoderStream;

pub struct ControlStream {
    stream: RecvStream,
    buf: BytesMut,
    pending: Vec<HttpFrame>,
    conn: H3ConnectionRef,
}

impl ControlStream {
    fn on_read(&mut self) -> bool {
        let mut cur = io::Cursor::new(&self.buf[..]);
        while let Ok(frame) = HttpFrame::decode(&mut cur) {
            self.pending.push(frame);
        }
        self.buf.advance(cur.position() as usize);
        !self.pending.is_empty()
    }

    pub fn on_frame(&mut self) {
        println!("send frame");
        let conn = &mut self.conn.0.lock().unwrap();
        for frame in self.pending.iter() {
            conn.on_recv_control(frame);
        }
        self.pending.clear();
    }
}

impl ControlStream {
    fn new(new_uni: NewUniStream, conn: H3ConnectionRef) -> ControlStream {
        let mut this = Self {
            conn,
            stream: new_uni.stream,
            buf: new_uni.buf,
            pending: Vec::new(),
        };
        this.on_read();
        this
    }
}

impl Future for ControlStream {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        println!("controll polled");
        if !self.pending.is_empty() {
            self.on_frame();
        }

        let mut buf = [0u8, 64];
        let size = try_ready!(self.stream.poll_read(&mut buf));
        self.buf.extend(&buf[..size]);
        if self.on_read() {
            self.on_frame();
        }
        Ok(Async::NotReady)
    }
}

struct H3Connection {
    quic: quinn::Connection,
    conn: H3ConnectionRef,
}

struct H3IncomingRequests(H3ConnectionRef);

//===================== /THE MESS =====================================

fn client(
    log: Logger,
    options: Opt,
    runtime: &mut Runtime,
) -> Result<impl Future<Item = (), Error = Error>> {
    let url = options.url;
    let remote = url
        .with_default_port(|_| Ok(4433))?
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    dbg!(remote);

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(&[quinn::ALPN_QUIC_H3]);
    endpoint.logger(log.clone());
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

    let (endpoint_driver, endpoint, _incoming) = endpoint.bind("[::]:0")?;
    runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));

    let start = Instant::now();
    let fut = endpoint
        .connect(&remote, "localhost")?
        .map_err(|e| format_err!("failed to connect: {}", e))
        .and_then(move |(conn_driver, conn, _)| {
            eprintln!("connected at {:?}", start.elapsed());
            tokio_current_thread::spawn(
                conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
            );
            let stream = conn.open_uni();
            stream
                .map_err(|e| format_err!("failed to open stream: {}", e))
                .and_then(move |send| {
                    let mut buf = vec![0x0];
                    SettingsFrame::default().encode(&mut buf);
                    tokio::io::write_all(send, buf)
                        .map_err(|e| format_err!("failed to send request: {}", e))
                })
                .and_then(move |(send, _wrote)| {
                    tokio::io::shutdown(send)
                        .map_err(|e| format_err!("failed to shutdown stream: {}", e))
                })
                .and_then(move |_| {
                    conn.open_bi()
                        .map_err(|e| format_err!("failed to send request: {}", e))
                        .and_then(move |(s, r)| {
                            let mut buf = vec![];
                            quinn_h3::frame::SettingsFrame::default().encode(&mut buf);
                            tokio::io::write_all(s, buf)
                                .map_err(|e| format_err!("failed to send request: {}", e))
                                .and_then(move |(send, _wrote)| {
                                    tokio::io::shutdown(send).map_err(|e| {
                                        format_err!("failed to shutdown stream: {}", e)
                                    })
                                })
                                .and_then(move |_| {
                                    tokio::io::read_to_end(r, Vec::new())
                                        .map_err(|e| {
                                            format_err!("failed to shutdown stream: {}", e)
                                        })
                                        .and_then(|(_, data)| {
                                            println!("data: {:?}", data);
                                            Ok(())
                                        })
                                })
                        })
                })
                .map(|_| eprintln!("drained"))
        });

    Ok(Box::new(fut))
}
