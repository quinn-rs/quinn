#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

use std::io::{self, Write};
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Error;
use quinn_proto::{self as quinn, Config, Directionality, Endpoint, Event, Io, ReadError, Timer};
use rustls::ProtocolVersion;
use slog::{Drain, Logger};

fn main() {
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        if let Err(e) = run(Logger::root(drain, o!())) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

fn normalize(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

type Result<T> = ::std::result::Result<T, Error>;

fn run(log: Logger) -> Result<()> {
    let remote = ::std::env::args()
        .nth(1)
        .ok_or(format_err!("missing address argument"))?;
    let mut ctx = Context::new(log, remote)?;
    ctx.run()?;
    Ok(())
}

struct Context {
    log: Logger,
    socket: UdpSocket,
    client: Endpoint,
    remote_host: String,
    remote: SocketAddrV6,
    loss_timer: Option<u64>,
    close_timer: Option<u64>,
    idle_timer: Option<u64>,
}

impl Context {
    fn new(log: Logger, mut remote_host: String) -> Result<Self> {
        let socket = UdpSocket::bind("[::]:0")?;
        let remote = normalize(
            remote_host
                .to_socket_addrs()?
                .next()
                .ok_or(format_err!("couldn't resolve to an address"))?,
        );
        if let Some(x) = remote_host.rfind(':') {
            remote_host.truncate(x);
        }

        let config = Config::default();
        Ok(Self {
            socket,
            client: Endpoint::new(log.clone(), config, None)?,
            log,
            remote_host,
            remote,
            loss_timer: None,
            close_timer: None,
            idle_timer: None,
        })
    }

    fn run(&mut self) -> Result<()> {
        let epoch = Instant::now();
        let mut config = quinn::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.versions = vec![ProtocolVersion::TLSv1_3];
        let config = Arc::new(config);
        let c = self
            .client
            .connect(self.remote, &config, &self.remote_host)?;
        let mut time = 0;
        let mut buf = Vec::new();
        let mut sent = 0;
        let mut recvd = 0;
        loop {
            while let Some((connection, e)) = self.client.poll() {
                match e {
                    Event::Connected { protocol, .. } => {
                        info!(self.log, "connected, submitting request"; "protocol" => protocol);
                        let s = self
                            .client
                            .open(c, Directionality::Bi)
                            .ok_or(format_err!("no streams available"))?;
                        self.client
                            .write(c, s, b"GET /index.html\r\n"[..].into())
                            .unwrap();
                        self.client.finish(c, s);
                    }
                    Event::ConnectionLost { reason, .. } => {
                        self.client.close(time, c, 0, b""[..].into());
                        bail!("connection lost: {}", reason);
                    }
                    Event::StreamReadable { stream, .. } => {
                        assert_eq!(c, connection);
                        loop {
                            match self.client.read_unordered(connection, stream) {
                                Ok((data, offset)) => {
                                    let len = buf.len().max(offset as usize + data.len());
                                    buf.resize(len, 0);
                                    buf[offset as usize..offset as usize + data.len()]
                                        .copy_from_slice(&data);
                                }
                                Err(ReadError::Finished) => {
                                    info!(self.log, "done, closing");
                                    io::stdout().write_all(&buf)?;
                                    io::stdout().flush()?;
                                    self.client.close(time, c, 0, b"finished"[..].into());
                                    break;
                                }
                                Err(ReadError::Blocked) => {
                                    break;
                                }
                                Err(e) => {
                                    error!(self.log, "read error"; "error" => %e);
                                    self.client
                                        .close(time, c, 1, b"unexpected error"[..].into());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            while let Some(io) = self.client.poll_io(time) {
                match io {
                    Io::Transmit {
                        destination,
                        packet,
                        ..
                    } => {
                        sent += 1;
                        self.socket.send_to(&packet, destination)?;
                    }
                    Io::TimerStart {
                        timer: Timer::LossDetection,
                        time,
                        ..
                    } => {
                        self.loss_timer = Some(time);
                    }
                    Io::TimerStart {
                        timer: Timer::Close,
                        time,
                        ..
                    } => {
                        self.close_timer = Some(time);
                    }
                    Io::TimerStart {
                        timer: Timer::Idle,
                        time,
                        ..
                    } => {
                        self.idle_timer = Some(time);
                    }
                    Io::TimerStop {
                        timer: Timer::LossDetection,
                        ..
                    } => {
                        self.loss_timer = None;
                    }
                    Io::TimerStop {
                        timer: Timer::Close,
                        ..
                    } => {
                        self.close_timer = None;
                    }
                    Io::TimerStop {
                        timer: Timer::Idle, ..
                    } => unreachable!(),
                }
            }
            let mut buf = [0; 2048];
            let (timeout, timer) = (
                self.loss_timer.unwrap_or(u64::max_value()),
                Timer::LossDetection,
            )
                .min((self.close_timer.unwrap_or(u64::max_value()), Timer::Close))
                .min((self.idle_timer.unwrap_or(u64::max_value()), Timer::Idle));
            if timeout != u64::max_value() {
                trace!(self.log, "setting timeout"; "type" => ?timer, "time" => time);
                let dt = timeout - time;
                let seconds = dt / (1000 * 1000);
                self.socket.set_read_timeout(Some(Duration::new(
                    seconds,
                    (dt - (seconds * 1000 * 1000)) as u32 * 1000,
                )))?;
            } else {
                self.socket.set_read_timeout(None)?;
            }
            let r = self.socket.recv_from(&mut buf);
            let dt = Instant::now() - epoch;
            time = dt.subsec_nanos() as u64 / 1000 + dt.as_secs() * 1000 * 1000;
            match r {
                Ok((n, addr)) => {
                    recvd += 1;
                    self.client
                        .handle(time, normalize(addr), None, (&buf[0..n]).into());
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(self.log, "timeout"; "type" => ?timer);
                    self.client.timeout(time, c, timer);
                    match timer {
                        Timer::LossDetection => self.loss_timer = None,
                        Timer::Idle => self.idle_timer = None,
                        Timer::Close => {
                            self.close_timer = None;
                            info!(self.log, "done"; "sent packets" => sent, "received packets" => recvd);
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
}
