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
#[macro_use]
extern crate structopt;

use std::fs::File;
use std::io::Read;
use std::fmt;
use std::path::{self, Path, PathBuf};
use std::str;
use std::rc::Rc;
use std::ascii;

use futures::{Future, Stream};
use tokio::executor::current_thread::{self, CurrentThread};
use failure::{ResultExt, Fail};
use structopt::StructOpt;

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

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[structopt(parse(from_os_str), long = "keylog")]
    keylog: Option<PathBuf>,
    /// directory to serve files from
    #[structopt(parse(from_os_str))]
    root: PathBuf,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), long = "key", default_value = "key.pem")]
    key: PathBuf,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), long = "cert", default_value = "cert.pem")]
    cert: PathBuf,
}

fn main() {
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator).use_original_order().build().fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e.pretty());
            1
        } else { 0 }
    };
    ::std::process::exit(code);
}

fn run(log: Logger, options: Opt) -> Result<()> {
    let root = Rc::new(options.root);
    if !root.exists() { bail!("root path does not exist"); }

    let mut protocols = Vec::new();
    const PROTO: &[u8] = b"hq-11";
    protocols.push(PROTO.len() as u8);
    protocols.extend_from_slice(PROTO);

    let reactor = tokio::reactor::Reactor::new()?;
    let handle = reactor.handle();
    let timer = tokio_timer::Timer::new(reactor);

    let key;
    let cert;
    {
        let mut key_file = File::open(options.key).context("failed to open key")?;
        let mut data = Vec::new();
        key_file.read_to_end(&mut data).context("failed reading key")?;
        key = PKey::<Private>::private_key_from_pem(&data).context("failed to load key")?;
        data.clear();

        let mut cert_file = File::open(options.cert).context("failed to open cert")?;
        cert_file.read_to_end(&mut data).context("failed reading cert")?;
        cert = X509::from_pem(&data).context("failed to load cert")?;
    }

    let (_, driver, incoming) = quicr::Endpoint::new()
        .reactor(&handle)
        .timer(timer.handle())
        .logger(log.clone())
        .config(quicr::Config {
            protocols,
            max_remote_bi_streams: 64,
            keylog: options.keylog,
            ..quicr::Config::default()
        })
        .listen(quicr::ListenConfig { private_key: &key, cert: &cert, state: rand::random() })
        .bind("[::]:4433")?;
    let mut executor = CurrentThread::new_with_park(timer);

    executor.spawn(incoming.for_each(move |conn| {
        let quicr::NewConnection { incoming, protocol, connection } = conn;
        let address = connection.remote_address();
        let local_id = connection.local_id();
        let remote_id = connection.remote_id();
        let log = log.new(o!("local_id" => format!("{}", local_id)));
        info!(log, "got connection";
              "remote_id" => %remote_id,
              "address" => %address,
              "protocol" => protocol.map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned()));
        let log2 = log.clone();
        let root = root.clone();
        current_thread::spawn(
            incoming
                .map_err(move |e| info!(log2, "connection terminated"; "reason" => %e))
                .for_each(move |stream| {
                    let stream = match stream {
                        quicr::NewStream::Bi(stream) => stream,
                        quicr::NewStream::Uni(_) => {
                            error!(log, "client opened unidirectional stream");
                            return Ok(());
                        }
                    };
                    let root = root.clone();
                    let log = log.clone();
                    let log2 = log.clone();
                    let log3 = log.clone();
                    current_thread::spawn(
                        quicr::read_to_end(stream, 64 * 1024)
                            .map_err(|e| format_err!("failed reading request: {}", e))
                            .and_then(move |(stream, req)| {
                                let mut escaped = String::new();
                                for &x in &req[..] {
                                    let part = ascii::escape_default(x).collect::<Vec<_>>();
                                    escaped.push_str(str::from_utf8(&part).unwrap());
                                }
                                info!(log, "got request"; "content" => escaped);
                                let resp = process_request(&root, &req).unwrap_or_else(move |e| {
                                    error!(log, "failed to process request"; "reason" => %e.pretty());
                                    format!("failed to process request: {}\n", e.pretty()).into_bytes().into()
                                });
                                tokio::io::write_all(stream, resp).map_err(|e| format_err!("failed to send response: {}", e))
                            })
                            .and_then(|(stream, _)| tokio::io::shutdown(stream).map_err(|e| format_err!("failed to shutdown stream: {}", e)))
                            .map(move |_| info!(log3, "request complete"))
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
