extern crate tokio;
extern crate tokio_timer;
extern crate quicr_tokio as quicr;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate futures;
extern crate rand;

use std::net::{UdpSocket, ToSocketAddrs};
use std::io::{self, Write};

use futures::Future;
use tokio::executor::current_thread::CurrentThread;

use slog::{Logger, Drain};
use failure::Error;

type Result<T> = std::result::Result<T, Error>;

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

fn run(log: Logger) -> Result<()> {
    let mut remote_host = ::std::env::args().nth(1).ok_or(format_err!("missing address argument"))?;
    let remote = remote_host.to_socket_addrs()?.next().ok_or(format_err!("couldn't resolve to an address"))?;
    if let Some(x) = remote_host.rfind(':') { remote_host.truncate(x); }

    let socket = UdpSocket::bind("[::]:0")?;
    let mut protocols = Vec::new();
    const PROTO: &[u8] = b"hq-11";
    protocols.push(PROTO.len() as u8);
    protocols.extend_from_slice(PROTO);
    let config = quicr::Config {
        protocols,
        ..quicr::Config::default()
    };

    let reactor = tokio::reactor::Reactor::new()?;
    let timer = tokio_timer::Timer::new(reactor);
    
    let (endpoint, driver, _) = quicr::Endpoint::from_std(&tokio::reactor::Handle::current(), timer.handle(), socket, log.clone(), config, rand::random(), None)?;
    let mut executor = CurrentThread::new_with_park(timer);

    executor.spawn(
        endpoint.connect(&remote, Some(remote_host.as_bytes()))
            .map_err(|e| eprintln!("failed to connect: {}", e))
            .and_then(|(conn, _)| {
                println!("connected!");
                conn.open(quicr::Directionality::Bi).map_err(|e| eprintln!("failed to open stream: {}", e))
            })
            .and_then(|stream| {
                println!("opened a stream");
                tokio::io::write_all(stream, b"GET /index.html\r\n").map_err(|e| eprintln!("failed to send request: {}", e))
            })
            .and_then(|(stream, _)| tokio::io::shutdown(stream).map_err(|e| eprintln!("failed to shutdown stream: {}", e)))
            .and_then(|stream| stream.read_to_end(usize::max_value()).map_err(|e| eprintln!("failed to read response: {}", e)))
            .map(|data| {
                io::stdout().write_all(&data).unwrap();
                io::stdout().flush().unwrap();
                println!("done")
            })
    );
    executor.block_on(driver).map_err(|e| e.into_inner().unwrap())?;

    Ok(())
}
