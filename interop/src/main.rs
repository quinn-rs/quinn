use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use futures::Future;
use quinn_h3::qpack;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

use bytes::{Bytes, BytesMut};
use failure::{format_err, Error};
use quinn_h3::proto::{
    frame::{HeadersFrame, HttpFrame, SettingsFrame},
    StreamType,
};
use slog::{o, warn, Drain, Logger};

type Result<T> = std::result::Result<T, Error>;

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
        .ok_or_else(|| format_err!("couldn't resolve to an address"))?;
    let host = if webpki::DNSNameRef::try_from_ascii_str(&options.host).is_ok() {
        &options.host
    } else {
        warn!(log, "invalid hostname, using \"example.com\"");
        "example.com"
    };

    let mut runtime = Runtime::new()?;

    let state = Arc::new(Mutex::new(State { saw_cert: false }));

    let mut builder = quinn::Endpoint::builder();
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config.enable_early_data = true;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    tls_config.alpn_protocols = vec![quinn::ALPN_QUIC_HTTP.into()];
    if options.keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        crypto: Arc::new(tls_config),
        transport: Arc::new(quinn::TransportConfig {
            idle_timeout: 1_000,
            ..Default::default()
        }),
        ..Default::default()
    };

    builder.logger(log.clone());
    let (endpoint_driver, endpoint, _) = builder.bind("[::]:0")?;
    runtime.spawn(endpoint_driver.map_err(|e| eprintln!("IO error: {}", e)));

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut resumption = false;
    let mut key_update = false;
    let mut rebinding = false;
    let mut zero_rtt = false;
    let endpoint = &endpoint;
    let result = runtime.block_on(
        endpoint
            .connect_with(client_config.clone(), &remote, host)?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(|(conn_driver, conn, _)| {
                println!("connected");
                tokio_current_thread::spawn(
                    conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
                );
                assert!(state.lock().unwrap().saw_cert);
                handshake = true;
                let stream = conn.open_bi();
                let stream_data = &mut stream_data;

                stream
                    .map_err(|e| format_err!("failed to open stream: {}", e))
                    .and_then(move |(send, recv)| get(send, recv))
                    .map(move |data| {
                        println!("read {} bytes, closing", data.len());
                        *stream_data = true;
                        conn.close(0, b"done");
                    })
                    .and_then(|_| {
                        println!("attempting resumption");
                        state.lock().unwrap().saw_cert = false;
                        endpoint
                            .connect_with(client_config.clone(), &remote, host)
                            .unwrap()
                            .map_err(|e| format_err!("failed to connect: {}", e))
                            .and_then(|(conn_driver, conn, _)| {
                                tokio_current_thread::spawn(
                                    conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
                                );
                                resumption = !state.lock().unwrap().saw_cert;
                                conn.force_key_update();
                                let stream = conn.open_bi();
                                let stream2 = conn.open_bi();
                                let rebinding = &mut rebinding;
                                stream
                                    .map_err(|e| format_err!("failed to open stream: {}", e))
                                    .and_then(move |(send, recv)| get(send, recv))
                                    .inspect(|_| {
                                        key_update = true;
                                    })
                                    .and_then(move |_| {
                                        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
                                        let addr = socket.local_addr().unwrap();
                                        println!("rebinding to {}", addr);
                                        endpoint
                                            .rebind(socket, &tokio_reactor::Handle::default())
                                            .expect("rebind failed");
                                        stream2
                                            .map_err(|e| {
                                                format_err!("failed to open stream: {}", e)
                                            })
                                            .and_then(move |(send, recv)| get(send, recv))
                                    })
                                    .map(move |_| {
                                        *rebinding = true;
                                        conn.close(0, b"done");
                                    })
                            })
                    })
                    .and_then(|_| {
                        println!("attempting 0-RTT");
                        let (conn_driver, conn, _) = endpoint
                            .connect_with(client_config.clone(), &remote, host)
                            .unwrap()
                            .into_0rtt()
                            .map_err(|_| format_err!("0-RTT unsupported by server"))?;
                        tokio_current_thread::spawn(
                            conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
                        );
                        Ok(conn)
                    })
                    .and_then(|conn| {
                        conn.open_bi()
                            .map_err(|e| format_err!("failed to open 0-RTT stream: {}", e))
                    })
                    .and_then(|(send, recv)| get(send, recv))
                    .map(|_| {
                        zero_rtt = true;
                    })
            }),
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
            .ok_or_else(|| format_err!("couldn't resolve to an address"))?;
        let result = runtime.block_on(
            endpoint
                .connect_with(client_config.clone(), &remote, host)?
                .and_then(|(conn_driver, conn, _)| {
                    retry = true;
                    conn.close(0, b"done");
                    conn_driver
                })
                .map(|()| {
                    close = true;
                }),
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
        crypto: Arc::new(h3_tls_config),
        transport: client_config.transport.clone(),
        ..Default::default()
    };

    let mut h3 = false;
    println!("trying h3");
    let result = runtime.block_on(
        endpoint
            .connect_with(h3_client_config, &remote, host)?
            .map_err(|e| format_err!("failed to connect: {}", e))
            .and_then(|(conn_driver, conn, _)| {
                tokio_current_thread::spawn(
                    conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
                );
                let control_stream = conn.open_uni();
                let control_fut = control_stream
                    .map_err(|e| format_err!("failed to open control stream: {}", e))
                    .and_then(move |stream| {
                        let mut buf = BytesMut::new();
                        StreamType::CONTROL.encode(&mut buf);
                        HttpFrame::Settings(SettingsFrame::default()).encode(&mut buf);
                        tokio::io::write_all(stream, buf)
                            .map_err(|e| format_err!("failed to send Settings frame: {}", e))
                            .and_then(move |(_, _)| futures::future::ok(()))
                    });

                let req_stream = conn.open_bi();
                let req_fut = req_stream
                    .map_err(|e| format_err!("failed to open request stream: {}", e))
                    .and_then(|(req_send, req_recv)| h3_get(req_send, req_recv))
                    .map(move |data| {
                        println!(
                            "read {} bytes: \n\n{}\n\n closing",
                            data.len(),
                            String::from_utf8_lossy(&data)
                        );
                        conn.close(0, b"done");
                    });
                control_fut.and_then(|_| req_fut).map(|_| h3 = true)
            }),
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

    println!();

    Ok(())
}

fn h3_get(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> impl Future<Item = Bytes, Error = Error> {
    let header = [
        (":method", "GET"),
        (":path", "/"),
        ("user-agent", "quinn interop tool"),
    ]
    .iter()
    .map(|(k, v)| qpack::HeaderField::new(*k, *v));

    let mut table = qpack::DynamicTable::new();
    table
        .inserter()
        .set_max_mem_size(0)
        .expect("set dynamic table size");

    let mut block = BytesMut::new();
    let mut enc = BytesMut::new();
    qpack::encode(&mut table.encoder(0), &mut block, &mut enc, header).expect("encoder failed");

    let mut buf = BytesMut::new();
    HttpFrame::Headers(HeadersFrame {
        encoded: block.into(),
    })
    .encode(&mut buf);

    tokio::io::write_all(send, buf)
        .map_err(|e| format_err!("failed to send Request frame: {}", e))
        .and_then(|(_, _)| {
            recv.read_to_end(usize::max_value())
                .unwrap()
                .map_err(|e| format_err!("failed to send Request frame: {}", e))
        })
        .and_then(move |data| h3_resp(&table, data))
}

fn h3_resp(table: &qpack::DynamicTable, data: Vec<u8>) -> Result<Bytes> {
    let mut cur = std::io::Cursor::new(data);
    match HttpFrame::decode(&mut cur) {
        Ok(HttpFrame::Headers(text)) => {
            let mut resp_block = std::io::Cursor::new(&text.encoded);
            match qpack::decode_header(table, &mut resp_block) {
                Ok(_) => (),
                Err(e) => return Err(format_err!("failed to decode response header {}", e)),
            }
        }
        Ok(f) => {
            return Err(format_err!("response frame bad type {:?}", f));
        }
        Err(e) => return Err(format_err!("failed to decode response frame {:?}", e)),
    }

    match HttpFrame::decode(&mut cur) {
        Ok(HttpFrame::Data(text)) => Ok(text.payload),
        Ok(f) => Err(format_err!("response frame bad type {:?}", f)),
        Err(e) => Err(format_err!("failed to decode response frame {:?}", e)),
    }
}

fn get(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> impl Future<Item = Vec<u8>, Error = Error> {
    tokio::io::write_all(send, b"GET /index.html\r\n".to_owned())
        .map_err(|e| format_err!("failed to send request: {}", e))
        .and_then(|(send, _)| {
            send.finish()
                .map_err(|e| format_err!("failed to shutdown stream: {}", e))
        })
        .and_then(move |_| {
            recv.read_to_end(usize::max_value())
                .unwrap()
                .map_err(|e| format_err!("failed to read response: {}", e))
        })
        .map(|data| data)
}

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
