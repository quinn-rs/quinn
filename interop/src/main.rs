#![feature(await_macro, async_await, futures_api)]
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use futures::{FutureExt, TryFutureExt};
use quinn_h3::qpack;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

use bytes::BytesMut;
use err_ctx::ResultExt;
use quinn_h3::frame::{HeadersFrame, HttpFrame, SettingsFrame};
use quinn_h3::StreamType;
use slog::{o, warn, Drain, Logger};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: String,
    #[structopt(default_value = "4433")]
    port: u16,
    #[structopt(default_value = "4434")]
    retry_port: u16,

    /// Enable key logging
    #[structopt(long = "keylog")]
    keylog: bool,
}

fn main() {
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

struct State {
    saw_cert: bool,
}

fn run(log: Logger, options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or("couldn't resolve to an address")?;
    let host = if webpki::DNSNameRef::try_from_ascii_str(&options.host).is_ok() {
        &options.host
    } else {
        warn!(log, "invalid hostname, using \"example.com\"");
        "example.com"
    };

    let mut runtime = Runtime::new()?;

    let state = Arc::new(Mutex::new(State { saw_cert: false }));

    let mut builder = quinn::Endpoint::new();
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    tls_config.alpn_protocols = vec![quinn::ALPN_QUIC_HTTP.into()];
    tls_config.enable_early_data = true;
    if options.keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        tls_config: Arc::new(tls_config),
        transport: Arc::new(quinn::TransportConfig {
            idle_timeout: 2,
            ..Default::default()
        }),
    };

    builder.logger(log.clone());
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)).compat());

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut resumption = false;
    let mut key_update = false;
    let mut rebinding = false;
    let mut zero_rtt = false;
    let result: Result<()> = runtime.block_on(
        async {
            let conn = endpoint.connect_with(&client_config, &remote, host)?;
            let (conn, _) = await!(conn.establish()).ctx("failed to connect")?;
            println!("connected");
            assert!(state.lock().unwrap().saw_cert);
            handshake = true;
            let stream = await!(conn.open_bi()).ctx("failed to open stream")?;
            let data = await!(get(stream)).ctx("request failed")?;
            println!("read {} bytes, closing", data.len());
            stream_data = true;
            await!(conn.close(0, b"done"));
            close = true;

            println!("attempting resumption");
            state.lock().unwrap().saw_cert = false;
            let conn = endpoint.connect_with(&client_config, &remote, &host)?;
            let conn = match conn.into_zero_rtt() {
                Ok((conn, _)) => {
                    let stream = await!(conn.open_bi()).ctx("failed to open 0-RTT stream")?;
                    if !conn.is_handshaking() {
                        println!("0-RTT stream budget too low");
                    } else if let Err(e) = await!(get(stream)) {
                        println!("0-RTT failed: {}", e);
                    } else {
                        zero_rtt = true;
                    }
                    conn
                }
                Err(conn) => {
                    println!("0-RTT not offered");
                    await!(conn.establish()).ctx("failed to connect")?.0
                }
            };
            resumption = !state.lock().unwrap().saw_cert;
            println!("updating keys");
            let result: Result<()> = await!(
                async {
                    conn.force_key_update();
                    let stream = await!(conn.open_bi()).ctx("failed to open stream")?;
                    await!(get(stream)).ctx("request failed")?;
                    key_update = true;
                    await!(conn.close(0, b"done"));
                    Ok(())
                }
            );
            if let Err(e) = result {
                println!("key update failure: {}", e);
            }

            let result: Result<()> = await!(
                async {
                    let (conn, _) = await!(endpoint
                        .connect_with(&client_config, &remote, host)?
                        .establish())
                    .ctx("establishing initial connection")?;
                    await!(get(await!(conn.open_bi())?)).ctx("request failed")?;
                    let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
                    let addr = socket.local_addr().unwrap();
                    println!("rebinding to {}", addr);
                    endpoint
                        .rebind(socket, &tokio_reactor::Handle::default())
                        .expect("rebind failed");
                    let stream = await!(conn.open_bi()).ctx("failed to open stream")?;
                    await!(get(stream)).ctx("request failed")?;
                    rebinding = true;
                    await!(conn.close(0, b"done"));
                    Ok(())
                }
            );
            if let Err(e) = result {
                println!("rebind failure: {}", e);
            }

            Ok(())
        }
            .boxed()
            .compat(),
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    let mut retry = false;
    {
        println!("connecting to retry port");
        let remote = format!("{}:{}", options.host, options.retry_port)
            .to_socket_addrs()?
            .next()
            .ok_or("couldn't resolve to an address")?;
        let result: Result<()> = runtime.block_on(
            async {
                let conn = endpoint.connect_with(&client_config, &remote, host)?;
                let (conn, _) = await!(conn.establish()).ctx("failed to connect")?;
                retry = true;
                await!(conn.close(0, b"done"));
                Ok(())
            }
                .boxed()
                .compat(),
        );
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }

    let mut h3_tls_config = rustls::ClientConfig::new();
    h3_tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    h3_tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    h3_tls_config.alpn_protocols = vec![quinn::ALPN_QUIC_H3.into()];
    let h3_client_config = quinn::ClientConfig {
        tls_config: Arc::new(h3_tls_config),
        transport: Default::default(),
    };

    let mut h3 = false;
    let result: Result<()> = runtime.block_on(
        async {
            let conn = endpoint.connect_with(&h3_client_config, &remote, host)?;
            let (conn, _) = await!(conn.establish()).ctx("failed to connect")?;
            let mut control_stream =
                await!(conn.open_uni()).ctx("failed to open control stream")?;
            let mut buf = BytesMut::new();
            StreamType::CONTROL.encode(&mut buf);
            HttpFrame::Settings(SettingsFrame {
                max_header_list_size: 4096,
                num_placeholders: 0,
            })
            .encode(&mut buf);
            await!(control_stream.write_all(&buf)).ctx("failed to send Settings frame")?;

            let req_stream = await!(conn.open_bi()).ctx("failed to open request stream")?;
            let data = await!(h3_get(req_stream))?;
            println!(
                "read {} bytes: \n\n{}\n\n closing",
                data.len(),
                String::from_utf8_lossy(&data)
            );
            await!(conn.close(0, b"done"));
            h3 = true;
            Ok(())
        }
            .boxed()
            .compat(),
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    if handshake {
        print!("VH");
    }
    if stream_data {
        print!("D");
    }
    if close {
        print!("C");
    }
    if resumption {
        print!("R");
    }
    if zero_rtt {
        print!("Z");
    }
    if retry {
        print!("S");
    }
    if rebinding {
        print!("B");
    }
    if key_update {
        print!("U");
    }
    if h3 {
        print!("3");
    }

    println!("");

    Ok(())
}

async fn h3_get(mut stream: quinn::BiStream) -> Result<Box<[u8]>> {
    let header = [
        (":method", "GET"),
        (":path", "/"),
        ("user-agent", "quinn interop tool"),
    ]
    .iter()
    .map(|(k, v)| qpack::HeaderField::new(*k, *v))
    .collect::<Vec<_>>();

    let mut table = qpack::DynamicTable::new();
    table
        .inserter()
        .set_max_mem_size(0)
        .expect("set dynamic table size");

    let mut block = BytesMut::new();
    let mut enc = BytesMut::new();
    qpack::encode(&mut table.encoder(0), &mut block, &mut enc, &header).expect("encoder failed");

    let mut buf = BytesMut::new();
    HttpFrame::Headers(HeadersFrame {
        encoded: block.into(),
    })
    .encode(&mut buf);

    await!(stream.send.write_all(&buf))?;
    let data = await!(stream.recv.read_to_end(usize::max_value()))?;
    h3_resp(&table, data)
}

fn h3_resp(table: &qpack::DynamicTable, data: Box<[u8]>) -> Result<Box<[u8]>> {
    let mut cur = std::io::Cursor::new(data);
    match HttpFrame::decode(&mut cur) {
        Ok(HttpFrame::Headers(text)) => {
            let mut resp_block = std::io::Cursor::new(&text.encoded);
            match qpack::decode_header(table, &mut resp_block) {
                Ok(_) => (),
                Err(e) => return Err(format!("failed to decode response header {}", e).into()),
            }
        }
        Ok(f) => {
            return Err(format!("response frame bad type {:?}", f).into());
        }
        Err(e) => return Err(format!("failed to decode response frame {:?}", e).into()),
    }

    match HttpFrame::decode(&mut cur) {
        Ok(HttpFrame::Data(text)) => Ok(Box::from(text.payload.as_ref())),
        Ok(f) => Err(format!("response frame bad type {:?}", f).into()),
        Err(e) => Err(format!("failed to decode response frame {:?}", e).into()),
    }
}

async fn get(mut stream: quinn::BiStream) -> Result<Box<[u8]>> {
    await!(stream.send.write_all(REQUEST)).ctx("writing request")?;
    await!(stream.send.finish()).ctx("finishing stream")?;
    Ok(await!(stream.recv.read_to_end(usize::max_value())).ctx("reading response")?)
}

const REQUEST: &[u8] = b"GET /index.html\r\n";

struct InteropVerifier(Arc<Mutex<State>>);
impl rustls::ServerCertVerifier for InteropVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        self.0.lock().unwrap().saw_cert = true;
        Ok(rustls::ServerCertVerified::assertion())
    }
}
