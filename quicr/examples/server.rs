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

use futures::{Future, Stream};
use tokio::executor::current_thread::CurrentThread;
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

    let (endpoint, driver, incoming) = quicr::Endpoint::from_std(&tokio::reactor::Handle::current(), timer.handle(), socket,
                                                                 log.clone(), config, rand::random(),
                                                                 Some(quicr::ListenConfig { private_key: &key, cert: &cert }))?;
    let mut executor = CurrentThread::new_with_park(timer);

    executor.spawn(incoming.for_each(move |conn| {
        info!(log, "got connection");
        let log = log.clone();
        
        Ok(())
    }));

    executor.block_on(driver).map_err(|e| e.into_inner().unwrap())?;

    Ok(())
}
