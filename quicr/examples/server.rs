extern crate tokio;
extern crate tokio_timer;
extern crate quicr;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate futures;
extern crate rand;
extern crate openssl;

use std::net::UdpSocket;
use std::fs::File;
use std::io::Read;
use std::fmt;
use std::path::{self, Path, PathBuf};
use std::str;
use std::rc::Rc;

use futures::{Future, Stream};
use tokio::executor::current_thread::{self, CurrentThread};
use failure::{ResultExt, Fail};

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

use slog::{Logger, Drain};
use failure::Error;

type Result<T> = std::result::Result<T, Error>;

pub struct PrettyErr<'a>(&'a Fail);
impl<'a> fmt::Display for PrettyErr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)?;
        let mut x: &Fail = self.0;
        while let Some(cause) = x.cause() {
            f.write_str(": ")?;
            fmt::Display::fmt(&cause, f)?;
            x = cause;
        }
        Ok(())
    }
}

pub trait ErrorExt {
    fn pretty(&self) -> PrettyErr;
}

impl ErrorExt for Error {
    fn pretty(&self) -> PrettyErr { PrettyErr(self.cause()) }
}

fn main() {
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
        if let Err(e) = run(Logger::root(drain, o!())) {
            eprintln!("ERROR: {}", e.pretty());
            1
        } else { 0 }
    };
    ::std::process::exit(code);
}

fn run(log: Logger) -> Result<()> {
    let root = ::std::env::args().nth(1).ok_or(format_err!("missing root argument"))?;
    let root = Rc::new(Path::new(&root).to_owned());
    if !root.exists() { bail!("root path does not exist"); }

    let socket = UdpSocket::bind("[::]:4433")?;
    let mut protocols = Vec::new();
    const PROTO: &[u8] = b"hq-11";
    protocols.push(PROTO.len() as u8);
    protocols.extend_from_slice(PROTO);
    let config = quicr::Config {
        protocols,
        max_remote_bi_streams: 64,
        ..quicr::Config::default()
    };

    let reactor = tokio::reactor::Reactor::new()?;
    let handle = reactor.handle();
    let timer = tokio_timer::Timer::new(reactor);

    let key;
    let cert;
    {
        let mut key_file = File::open("key.der").context("failed to open key.der")?;
        let mut data = Vec::new();
        key_file.read_to_end(&mut data).context("failed reading key.der")?;
        key = PKey::<Private>::private_key_from_der(&data).context("failed to load key.der")?;
        data.clear();

        let mut cert_file = File::open("cert.der").context("failed to open cert.der")?;
        cert_file.read_to_end(&mut data).context("failed reading cert.der")?;
        cert = X509::from_der(&data).context("failed to load cert.der")?;
    }

    let (_, driver, incoming) = quicr::Endpoint::from_std(
        &handle, timer.handle(), socket,
        log.clone(), config, Some(quicr::ListenConfig { private_key: &key, cert: &cert, state: rand::random() }))?;
    let mut executor = CurrentThread::new_with_park(timer);

    executor.spawn(incoming.for_each(move |conn| {
        let quicr::NewConnection { incoming, address, .. } = conn;
        info!(log, "got connection"; "remote" => %address);
        let root = root.clone();
        let log = log.clone();
        let log2 = log.clone();
        current_thread::spawn(
            incoming
                .map_err(move |e| info!(log2, "connection terminated"; "remote" => %address, "reason" => %e))
                .and_then(|stream| { match stream {
                    quicr::NewStream::Bi(send, recv) => Ok((send, recv)),
                    quicr::NewStream::Uni(_) => unreachable!(),
                }})
                .for_each(move |(send, recv)| {
                    let root = root.clone();
                    let log = log.clone();
                    let log2 = log.clone();
                    let log3 = log.clone();
                    current_thread::spawn(
                        recv.read_to_end(64 * 1024)
                            .map_err(|e| format_err!("failed reading request: {}", e))
                            .map(move |data| (send, data))
                            .and_then(move |(send, req)| {
                                info!(log, "got request"; "remote" => %address);
                                let resp = process_request(&root, &req).unwrap_or_else(move |e| {
                                    error!(log, "failed to process request"; "reaosn" => %e.pretty());
                                    format!("failed to process request: {}\n", e.pretty()).into_bytes().into()
                                });
                                tokio::io::write_all(send, resp).map_err(|e| format_err!("failed to send response: {}", e))
                            })
                            .and_then(|(send, _)| tokio::io::shutdown(send).map_err(|e| format_err!("failed to shutdown stream: {}", e)))
                            .map(move |_| info!(log3, "request complete"; "remote" => %address))
                            .map_err(move |e| error!(log2, "request failed"; "reason" => %e.pretty()))
                    );
                    Ok(())
                })
        );
        Ok(())
    }));

    executor.block_on(driver).map_err(|e| e.into_inner().unwrap())?;

    Ok(())
}

fn process_request(root: &Path, x: &[u8]) -> Result<Box<[u8]>> {
    if x.len() < 4 || &x[0..4] != b"GET " { bail!("missing GET"); }
    if x[4..].len() < 2 || &x[x.len()-2..] != b"\r\n" { bail!("missing \\r\\n"); }
    let path = str::from_utf8(&x[4..x.len()-2]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);
    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => { bail!("path must be absolute"); }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => { real_path.push(x); }
            x => { bail!("illegal component in path: {:?}", x); }
        }
    }
    let mut file = File::open(real_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).context("failed reading file")?;
    Ok(data.into())
}
