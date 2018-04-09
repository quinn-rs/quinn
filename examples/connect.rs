extern crate quicr;
extern crate rand;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate slog_term;

use std::net::{UdpSocket, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::time::{Instant, Duration};
use std::io::{self, Write};

use failure::Error;
use quicr::{Endpoint, Config, Io, Timer, Event, Directionality};
use slog::{Logger, Drain};

fn main() {
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
        if let Err(e) = run(Logger::root(drain, o!())) {
            eprintln!("ERROR: {}", e);
            1
        } else { 0 }
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
    let remote = ::std::env::args().nth(1).ok_or(format_err!("missing address argument"))?;
    let remote = normalize(remote.to_socket_addrs()?.next().ok_or(format_err!("couldn't resolve to an address"))?);
    let mut ctx = Context::new(log, remote)?;
    ctx.run()?;
    Ok(())
}

struct Context {
    log: Logger,
    socket: UdpSocket,
    client: Endpoint,
    local: SocketAddrV6,
    remote: SocketAddrV6,
    loss_timer: Option<u64>,
    close_timer: Option<u64>,
    idle_timer: Option<u64>,
}

impl Context {
    fn new(log: Logger, remote: SocketAddrV6) -> Result<Self> {
        let socket = UdpSocket::bind("[::]:0")?;
        let local = normalize(socket.local_addr()?);
        Ok(Self {
            socket, local,
            client: Endpoint::new(log.clone(), Config::default(), rand::random(), None)?,
            log, remote,
            loss_timer: None,
            close_timer: None,
            idle_timer: None,
        })
    }

    fn run(&mut self) -> Result<()> {
        let epoch = Instant::now();
        let c = self.client.connect(0, self.local, self.remote)?;
        let mut time = 0;
        loop {
            while let Some(e) = self.client.poll() { match e {
                Event::Connected(_) => {
                    let s = self.client.open(c, Directionality::Bi).ok_or(format_err!("no streams available"))?;
                    self.client.write(time, c, s, b"GET /index.html\r\n"[..].into());
                    self.client.write(time, c, s, b""[..].into());
                }
                Event::ConnectionLost { reason, .. } => { return Err(reason.into()); }
                Event::Recv(frame) => {
                    io::stdout().write_all(&frame.data)?;
                    io::stdout().flush()?;
                }
            }}
            while let Some(io) = self.client.poll_io() { match io {
                Io::Transmit { destination, packet } => { self.socket.send_to(&packet, destination)?; }
                Io::TimerStart { timer: Timer::LossDetection, time, .. } => { self.loss_timer = Some(time); }
                Io::TimerStart { timer: Timer::Close, time, .. } => { self.close_timer = Some(time); }
                Io::TimerStart { timer: Timer::Idle, time, .. } => { self.idle_timer = Some(time); }
                Io::TimerStop { timer: Timer::LossDetection, .. } => { self.loss_timer = None; }
                Io::TimerStop { timer: Timer::Close, .. } => { self.close_timer = None; }
                Io::TimerStop { timer: Timer::Idle, .. } => { unreachable!() }
            }}
            let mut buf = [0; 2048];
            let (timeout, timer) = (self.loss_timer.unwrap_or(u64::max_value()), Timer::LossDetection)
                .min((self.close_timer.unwrap_or(u64::max_value()), Timer::Close))
                .min((self.idle_timer.unwrap_or(u64::max_value()), Timer::Idle));
            if timeout != u64::max_value() {
                let dt = timeout - time;
                trace!(self.log, "setting timeout"; "dt" => dt);
                let seconds = dt / (1000 * 1000);
                self.socket.set_read_timeout(Some(Duration::new(seconds, (dt - (seconds * 1000 * 1000)) as u32 * 1000)))?;
            } else {
                self.socket.set_read_timeout(None)?;
            }
            let r = self.socket.recv_from(&mut buf);
            let dt = Instant::now() - epoch;
            time = dt.subsec_nanos() as u64 / 1000 + dt.as_secs() * 1000 * 1000;
            match r {
                Ok((n, addr)) => {
                    self.client.handle(time, normalize(addr), self.local, (&buf[0..n]).into());
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.client.timeout(time, c, timer);
                    match timer {
                        Timer::LossDetection => self.loss_timer = None,
                        Timer::Close => self.close_timer = None,
                        Timer::Idle => self.idle_timer = None,
                    }
                }
                Err(e) => { return Err(e.into()); }
            }
        }
    }
}
