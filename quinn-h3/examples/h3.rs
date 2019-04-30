#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{fmt, fs, io};

use bytes::{Buf, BytesMut};
use failure::{Error, Fail, ResultExt};
use futures::task::{self, Task};
use futures::{try_ready, Async, Future, Poll, Stream};
use slog::{Drain, Logger};
use structopt::{self, StructOpt};
use tokio::io::AsyncRead;
use tokio::runtime::current_thread::Runtime;
use url::Url;

use quinn::{OpenBi, OpenUni, RecvStream, SendStream};
use quinn_h3::{
    frame::{Error as FrameError, HeadersFrame, HttpFrame, SettingsFrame},
    Connection, StreamType,
};

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
    let server_log = Logger::root(sdrain, o!("server" => ""));

    let certs = build_certs(server_log.clone(), opt.clone()).expect("failed to build certs");

    let mut runtime = Runtime::new().expect("runtime failed");
    let server = server(
        server_log,
        opt.clone(),
        &mut runtime,
        (certs.0.clone(), certs.2.clone()),
    )
    .expect("server failed");

    let client = client(
        Logger::root(cdrain, o!("client" => "")),
        opt,
        &mut runtime,
        certs.1,
    )
    .expect("client failed");

    runtime.spawn(client.map_err(|_| println!("client failed:")));
    runtime.block_on(server).expect("block on server failed");
    ::std::process::exit(0);
}

fn server(
    log: Logger,
    options: Opt,
    runtime: &mut Runtime,
    certs: (quinn::tls::CertificateChain, quinn::tls::PrivateKey),
) -> Result<quinn::EndpointDriver> {
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

    server_config.certificate(certs.0, certs.1)?;

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
    let (conn_driver, _conn, incoming_streams) = conn;
    let log = log.clone();
    info!(log, "got connection");

    let incoming = incoming_streams.for_each(|req| {
        println!("incoming yeild");
        req.map_err(|_| format_err!("recv request failed"))
            .and_then(|_| {
                println!("received an exciting request !");
                futures::future::ok(())
            })
    });

    tokio_current_thread::spawn(incoming.map_err(|e| println!("Server Incoming error: {}", e)));

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
                let h3_conn = H3ConnectionRef::new();
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
                    H3IncomingRequests { inner: h3_conn },
                ))))
            }
        }
    }
}

struct H3ConnectionInner {
    inner: Connection,
    requests: VecDeque<RecvRequest>,
    request_task: Option<Task>,
}

#[derive(Clone)]
struct H3ConnectionRef(Arc<Mutex<H3ConnectionInner>>);

impl H3ConnectionRef {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(H3ConnectionInner {
            inner: quinn_h3::Connection::new(),
            requests: VecDeque::new(),
            request_task: None,
        })))
    }
}

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
                    quinn::NewStream::Bi(send, recv) => {
                        println!("New request pushed");
                        let conn = &mut self.conn.0.lock().unwrap();
                        conn.requests
                            .push_back(RecvRequest::new(recv, send, self.conn.clone()));
                        if let Some(ref mut incoming_task) = conn.request_task {
                            incoming_task.notify();
                        }
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
                match conn.inner.on_recv_stream(ty) {
                    Ok(()) => {
                        self.control = Some(ControlStream::new(new_uni, self.conn.clone()));
                    }
                    _ => {
                        self.streams.remove(idx);
                    }
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
            conn.inner.on_recv_control(frame);
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

enum RecvRequestState {
    Receiving(FrameStream<RecvStream>, SendStream),
}

struct RecvRequest {
    state: Option<RecvRequestState>,
    conn: H3ConnectionRef,
}

impl RecvRequest {
    fn new(recv: RecvStream, send: SendStream, conn: H3ConnectionRef) -> Self {
        Self {
            conn,
            state: Some(RecvRequestState::Receiving(FrameStream::with(recv), send)),
        }
    }
}

impl Future for RecvRequest {
    type Item = RecvRequest;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        println!("RecvRequest polled");
        // let state = if let Some(state) = self.state {
        //     std::mem::replace(&mut self.state, None)
        // };
        // match state {
        //     RecvRequestState::Receiving(frames, send) => {
        //         let frames = try_ready!(frames.poll());

        //     }
        // }
        Ok(Async::NotReady)
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

// struct RecvRequest {
//     conn: H3ConnectionRef,
//     send: SendStream,
//     buf: BytesMut,
// }

// impl Future for RecvRequest {
//     type Item = Request;
//     type Error = Error;

//     fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//     }
// }

struct H3Connection {
    quic: quinn::Connection,
    conn: H3ConnectionRef,
}

struct H3IncomingRequests {
    inner: H3ConnectionRef,
}

impl Stream for H3IncomingRequests {
    type Item = RecvRequest;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        println!("H3IncomingRequests poll");
        let mut conn = self.inner.0.lock().unwrap();
        if !conn.requests.is_empty() {
            return Ok(Async::Ready(conn.requests.pop_front()));
        }
        conn.request_task = Some(task::current());
        Ok(Async::NotReady)
    }
}

struct ClientBuilder<'a> {
    endpoint: quinn::EndpointBuilder<'a>,
}

struct ClientConnection {
    quic: quinn::Connection,
    conn: H3ConnectionRef,
}

impl ClientConnection {
    fn send_request(&mut self, req: Request) -> SendRequest {
        SendRequest::new(self.quic.open_bi_h3(), self.conn.clone())
    }
}

struct FrameStream<R> {
    recv: R,
    buf: BytesMut,
}

impl<R> FrameStream<R> {
    fn with(recv: R) -> Self {
        Self {
            recv,
            buf: BytesMut::with_capacity(1024 * 10),
        }
    }
}

impl<R> Stream for FrameStream<R>
where
    R: AsyncRead,
{
    type Item = HttpFrame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let len = self.buf.len();
        println!("FrameStream: polling frame");
        try_ready!(self.recv.poll_read(&mut self.buf[len..]));

        let (pos, decoded) = {
            let mut cur = io::Cursor::new(&mut self.buf);
            let decoded = HttpFrame::decode(&mut cur);
            (cur.position() as usize, decoded)
        };

        return match decoded {
            Err(FrameError::UnexpectedEnd) => Ok(Async::NotReady),
            Err(e) => Err(format_err!("error decoding frame: {:?}", e)), // TODO should impl failure
            Ok(f) => {
                self.buf.advance(pos);
                Ok(Async::Ready(Some(f)))
            }
        };
    }
}

struct Request {
    headers: Vec<(String, String)>,
}

enum SendRequestState {
    Opening(OpenBi),
    Sending(tokio::io::WriteAll<SendStream, Vec<u8>>),
    Sent(tokio::io::Shutdown<SendStream>),
    Recving(FrameStream<RecvStream>),
    Ready(HeadersFrame),
    Finished,
}

struct SendRequest {
    state: SendRequestState,
    conn: H3ConnectionRef,
    recv: Option<FrameStream<RecvStream>>,
}

impl SendRequest {
    fn new(open_bi: OpenBi, conn: H3ConnectionRef) -> Self {
        Self {
            conn,
            state: SendRequestState::Opening(open_bi),
            recv: None,
        }
    }
}

impl Future for SendRequest {
    type Item = RecvResponse;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let new_state = match &mut self.state {
            SendRequestState::Opening(ref mut o) => {
                println!("SendRequest opening streams");
                let (send, recv) = try_ready!(o.poll());
                self.recv = Some(FrameStream::with(recv));

                let mut encoded_header = vec![];
                HeadersFrame {
                    encoded: b"blah"[..].into(),
                }
                .encode(&mut encoded_header);

                let send = tokio::io::write_all(send, encoded_header);
                SendRequestState::Sending(send)
            }
            SendRequestState::Sending(ref mut send) => {
                println!("SendRequest sending");
                let (send, _) = try_ready!(send.poll());
                let shut = tokio::io::shutdown(send);
                SendRequestState::Sent(shut)
            }
            SendRequestState::Sent(ref mut shut) => {
                println!("SendRequest sent");
                try_ready!(shut.poll());
                SendRequestState::Recving(mem::replace(&mut self.recv, None).unwrap()) // TODO return Err
            }
            SendRequestState::Recving(ref mut frames) => {
                println!("recieving response");
                match try_ready!(frames.poll()) {
                    None => return Err(format_err!("recieved an empty response")),
                    Some(f) => match f {
                        HttpFrame::Headers(headers) => SendRequestState::Ready(headers),
                        _ => return Err(format_err!("first stream is not headers")),
                    },
                }
            }
            _ => SendRequestState::Finished,
        };

        if let SendRequestState::Ready(headers) = new_state {
            match mem::replace(&mut self.state, SendRequestState::Finished) {
                SendRequestState::Recving(frames) => {
                    return Ok(Async::Ready(RecvResponse { headers, frames }))
                }
                _ => unreachable!("ready shall always come after recieve"),
            }
        }

        Ok(Async::NotReady)
    }
}

struct RecvResponse {
    headers: HeadersFrame,
    frames: FrameStream<RecvStream>,
}

fn client(
    log: Logger,
    options: Opt,
    runtime: &mut Runtime,
    cert: quinn::tls::Certificate,
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

    client_config.add_certificate_authority(cert)?;
    endpoint.default_client_config(client_config.build());

    let (endpoint_driver, endpoint, _incoming) = endpoint.bind("[::]:0")?;
    runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));

    let start = Instant::now();
    let fut = endpoint
        .connect(&remote, "localhost")?
        .map_err(|e| format_err!("failed to connect: {}", e))
        .and_then(move |(conn_driver, conn, incoming)| {
            eprintln!("connected at {:?}", start.elapsed());
            tokio_current_thread::spawn(
                conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
            );

            let h3_conn = H3ConnectionRef::new();

            let h3_driver = H3ConnectionDriver {
                conn: h3_conn.clone(),
                incoming: incoming,
                streams: Vec::new(),
                control: None,
            };

            tokio_current_thread::spawn(
                h3_driver.map_err(|e| eprintln!("H3 connection error: {}", e)),
            );

            let mut client_conn = ClientConnection {
                quic: conn,
                conn: h3_conn,
            };

            client_conn
                .send_request(Request {
                    headers: Vec::new(),
                })
                .map_err(|e| format_err!("client recv response failed: {}", e))
                .map(|resp| {
                    println!("resp: {:?}", resp.headers);
                })

            // let stream = conn.open_uni();
            // stream
            //     .map_err(|e| format_err!("failed to open stream: {}", e))
            //     .and_then(move |send| {
            //         let mut buf = vec![0x0];
            //         SettingsFrame::default().encode(&mut buf);
            //         tokio::io::write_all(send, buf)
            //             .map_err(|e| format_err!("failed to send request: {}", e))
            //     })
            //     // .and_then(move |(send, _wrote)| {
            //     //     tokio::io::shutdown(send)
            //     //         .map_err(|e| format_err!("failed to shutdown stream: {}", e))
            //     // })
            //     .and_then(move |send| {
            //         conn.open_bi()
            //             .map_err(|e| format_err!("failed to send request: {}", e))
            //             .and_then(move |(s, r)| {
            //                 let mut buf = vec![];
            //                 quinn_h3::frame::SettingsFrame::default().encode(&mut buf);
            //                 tokio::io::write_all(s, buf)
            //                     .map_err(|e| format_err!("failed to send request: {}", e))
            //                     .and_then(move |(send, _wrote)| {
            //                         tokio::io::shutdown(send).map_err(|e| {
            //                             format_err!("failed to shutdown stream: {}", e)
            //                         })
            //                     })
            //                     .and_then(move |_| {
            //                         tokio::io::read_to_end(r, Vec::new())
            //                             .map_err(|e| {
            //                                 format_err!("failed to shutdown stream: {}", e)
            //                             })
            //                             .and_then(|(_, data)| {
            //                                 println!("data: {:?}", data);
            //                                 Ok(())
            //                             })
            //                     })
            //             })
            //     })
            //     .map(|_| eprintln!("drained"))
        });

    Ok(Box::new(fut))
}

//===================== /THE MESS =====================================

fn build_certs(
    log: Logger,
    options: Opt,
) -> Result<(
    quinn::tls::CertificateChain,
    quinn::tls::Certificate,
    quinn::tls::PrivateKey,
)> {
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
        Ok((
            quinn::CertificateChain::from_certs(vec![cert.clone()]),
            cert,
            key,
        ))
    }
}
