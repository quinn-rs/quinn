use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use futures::TryFutureExt;
// use quinn_h3::qpack;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

// use bytes::{Bytes, BytesMut};
use failure::{format_err, Error};
// use quinn_h3::proto::{
//     frame::{HeadersFrame, HttpFrame, SettingsFrame},
//     StreamType,
// };
use slog::{info, o, warn, Drain, Logger};

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
        let decorator = slog_term::TermDecorator::new().stderr().build();
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        // We use a mutex-protected drain for simplicity; this tool is single-threaded anyway.
        let drain = std::sync::Mutex::new(drain).fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[derive(Default)]
struct State {
    saw_cert: bool,
    handshake: bool,
    stream_data: bool,
    close: bool,
    resumption: bool,
    key_update: bool,
    rebinding: bool,
    zero_rtt: bool,
    retry: bool,
    h3: bool,
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
    let host: Arc<str> = Arc::from(host);

    let mut runtime = Runtime::new()?;

    let state = Arc::new(Mutex::new(State::default()));
    let protocols = vec![b"hq-20"[..].into(), b"hq-22"[..].into()];

    let mut builder = quinn::Endpoint::builder();
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config.enable_early_data = true;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    tls_config.alpn_protocols = protocols.clone();
    if options.keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        crypto: quinn::crypto::rustls::ClientConfig::new(tls_config),
        transport: Arc::new(quinn::TransportConfig {
            idle_timeout: 1_000,
            ..Default::default()
        }),
        ..Default::default()
    };

    builder.logger(log.clone());
    let (endpoint_driver, endpoint, _) = builder.bind("[::]:0")?;
    runtime.spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));

    runtime.spawn({
        let endpoint = endpoint.clone();
        let state = state.clone();
        let config = client_config.clone();
        let host = host.clone();
        let log = log.clone();
        async move {
            let new_conn = endpoint
                .connect_with(config.clone(), &remote, &host)?
                .await
                .map_err(|e| format_err!("failed to connect: {}", e))?;
            state.lock().unwrap().handshake = true;
            let state2 = state.clone();
            tokio::runtime::current_thread::spawn(
                new_conn
                    .driver
                    .map_ok(move |()| {
                        state2.lock().unwrap().close = true;
                    })
                    .unwrap_or_else(|_| ()),
            );
            let stream = new_conn
                .connection
                .open_bi()
                .await
                .map_err(|e| format_err!("failed to open stream: {}", e))?;
            get(stream)
                .await
                .map_err(|e| format_err!("simple request failed: {}", e))?;
            state.lock().unwrap().stream_data = true;
            new_conn.connection.close(0u32.into(), b"done");

            state.lock().unwrap().saw_cert = false;
            let conn = match endpoint.connect_with(config, &remote, &host)?.into_0rtt() {
                Ok(new_conn) => {
                    tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                    let stream = new_conn
                        .connection
                        .open_bi()
                        .await
                        .map_err(|e| format_err!("failed to open 0-RTT stream: {}", e))?;
                    get(stream)
                        .await
                        .map_err(|e| format_err!("0-RTT request failed: {}", e))?;
                    state.lock().unwrap().zero_rtt = true;
                    new_conn.connection
                }
                Err(conn) => {
                    info!(log, "0-RTT unsupported");
                    let new_conn = conn
                        .await
                        .map_err(|e| format_err!("failed to connect: {}", e))?;
                    tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                    new_conn.connection
                }
            };
            {
                let mut state = state.lock().unwrap();
                state.resumption = !state.saw_cert;
            }
            conn.close(0u32.into(), b"done");

            Ok(())
        }
            .unwrap_or_else(|e: Error| eprintln!("{}", e))
    });

    runtime.spawn({
        let endpoint = endpoint.clone();
        let state = state.clone();
        let config = client_config.clone();
        let host = host.clone();
        async move {
            let new_conn = endpoint
                .connect_with(config.clone(), &remote, &host)?
                .await
                .map_err(|e| format_err!("failed to connect: {}", e))?;
            tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
            let conn = new_conn.connection;
            // Make sure some traffic has gone both ways before the key update
            let stream = conn
                .open_bi()
                .await
                .map_err(|e| format_err!("failed to open stream: {}", e))?;
            get(stream).await?;
            conn.force_key_update();
            let stream = conn
                .open_bi()
                .await
                .map_err(|e| format_err!("failed to open stream: {}", e))?;
            get(stream).await?;
            state.lock().unwrap().key_update = true;
            conn.close(0u32.into(), b"done");
            Ok(())
        }
            .unwrap_or_else(|e: Error| eprintln!("key update failed: {}", e))
    });

    {
        // Dedicated endpoint so rebinding doesn't interfere with other connections' handshakes
        let mut builder = quinn::Endpoint::builder();
        builder.logger(log.clone());
        let (endpoint_driver, endpoint, _) = builder.bind("[::]:0")?;
        runtime.spawn(endpoint_driver.unwrap_or_else(|e| eprintln!("IO error: {}", e)));
        runtime.spawn({
            let state = state.clone();
            let config = client_config.clone();
            let host = host.clone();
            async move {
                let new_conn = endpoint
                    .connect_with(config.clone(), &remote, &host)?
                    .await
                    .map_err(|e| format_err!("failed to connect: {}", e))?;
                tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
                let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
                endpoint.rebind(socket, &tokio_net::driver::Handle::default())?;
                let stream = new_conn
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| format_err!("failed to open stream: {}", e))?;
                get(stream).await?;
                state.lock().unwrap().rebinding = true;
                new_conn.connection.close(0u32.into(), b"done");
                Ok(())
            }
                .unwrap_or_else(|e: Error| eprintln!("rebinding failed: {}", e))
        });
    }

    runtime.spawn({
        let endpoint = endpoint.clone();
        let state = state.clone();
        let config = client_config.clone();
        let remote = format!("{}:{}", options.host, options.retry_port)
            .to_socket_addrs()?
            .next()
            .unwrap();
        let host = host.clone();

        async move {
            let new_conn = endpoint
                .connect_with(config.clone(), &remote, &host)?
                .await
                .map_err(|e| format_err!("failed to connect: {}", e))?;
            tokio::runtime::current_thread::spawn(new_conn.driver.unwrap_or_else(|_| ()));
            let stream = new_conn
                .connection
                .open_bi()
                .await
                .map_err(|e| format_err!("failed to open stream: {}", e))?;
            get(stream).await?;
            state.lock().unwrap().retry = true;
            new_conn.connection.close(0u32.into(), b"done");
            Ok(())
        }
            .unwrap_or_else(|e: Error| eprintln!("retry failed: {}", e))
    });

    // let mut h3_tls_config = rustls::ClientConfig::new();
    // h3_tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    // h3_tls_config
    //     .dangerous()
    //     .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    // h3_tls_config.alpn_protocols = protocols;
    // let h3_client_config = quinn::ClientConfig {
    //     crypto: quinn::crypto::rustls::ClientConfig::new(h3_tls_config),
    //     transport: client_config.transport.clone(),
    //     ..Default::default()
    // };

    // let mut h3 = false;
    // println!("trying h3");
    // let result = runtime.block_on(
    //     endpoint
    //         .connect_with(h3_client_config, &remote, host)?
    //         .map_err(|e| format_err!("failed to connect: {}", e))
    //         .and_then(|(conn_driver, conn, _)| {
    //             tokio_current_thread::spawn(
    //                 conn_driver.map_err(|e| eprintln!("connection lost: {}", e)),
    //             );
    //             let control_stream = conn.open_uni();
    //             let control_fut = control_stream
    //                 .map_err(|e| format_err!("failed to open control stream: {}", e))
    //                 .and_then(move |stream| {
    //                     let mut buf = BytesMut::new();
    //                     StreamType::CONTROL.encode(&mut buf);
    //                     HttpFrame::Settings(SettingsFrame::default()).encode(&mut buf);
    //                     tokio::io::write_all(stream, buf)
    //                         .map_err(|e| format_err!("failed to send Settings frame: {}", e))
    //                         .and_then(move |(_, _)| futures::future::ok(()))
    //                 });

    //             let req_stream = conn.open_bi();
    //             let req_fut = req_stream
    //                 .map_err(|e| format_err!("failed to open request stream: {}", e))
    //                 .and_then(|(req_send, req_recv)| h3_get(req_send, req_recv))
    //                 .map(move |data| {
    //                     println!(
    //                         "read {} bytes: \n\n{}\n\n closing",
    //                         data.len(),
    //                         String::from_utf8_lossy(&data)
    //                     );
    //                     conn.close(0, b"done");
    //                 });
    //             control_fut.and_then(|_| req_fut).map(|_| h3 = true)
    //         }),
    // );
    // if let Err(e) = result {
    //     println!("failure: {}", e);
    // }

    drop(endpoint);
    runtime.run().unwrap();
    let state = state.lock().unwrap();

    if state.handshake {
        print!("VH");
    }
    if state.stream_data {
        print!("D");
    }
    if state.close {
        print!("C");
    }
    if state.resumption {
        print!("R");
    }
    if state.zero_rtt {
        print!("Z");
    }
    if state.retry {
        print!("S");
    }
    if state.rebinding {
        print!("B");
    }
    if state.key_update {
        print!("U");
    }
    if state.h3 {
        print!("3");
    }

    println!();

    Ok(())
}

// fn h3_get(
//     send: quinn::SendStream,
//     recv: quinn::RecvStream,
// ) -> impl Future<Item = Bytes, Error = Error> {
//     let header = [
//         (":method", "GET"),
//         (":path", "/"),
//         ("user-agent", "quinn interop tool"),
//     ]
//     .iter()
//     .map(|(k, v)| qpack::HeaderField::new(*k, *v));

//     let mut table = qpack::DynamicTable::new();
//     table
//         .inserter()
//         .set_max_mem_size(0)
//         .expect("set dynamic table size");

//     let mut block = BytesMut::new();
//     let mut enc = BytesMut::new();
//     qpack::encode(&mut table.encoder(0), &mut block, &mut enc, header).expect("encoder failed");

//     let mut buf = BytesMut::new();
//     HttpFrame::Headers(HeadersFrame {
//         encoded: block.into(),
//     })
//     .encode(&mut buf);

//     tokio::io::write_all(send, buf)
//         .map_err(|e| format_err!("failed to send Request frame: {}", e))
//         .and_then(|(_, _)| {
//             recv.read_to_end(usize::max_value())
//                 .map_err(|e| format_err!("failed to send Request frame: {}", e))
//         })
//         .and_then(move |data| h3_resp(&table, data))
// }

// fn h3_resp(table: &qpack::DynamicTable, data: Vec<u8>) -> Result<Bytes> {
//     let mut cur = std::io::Cursor::new(data);
//     match HttpFrame::decode(&mut cur) {
//         Ok(HttpFrame::Headers(text)) => {
//             let mut resp_block = std::io::Cursor::new(&text.encoded);
//             match qpack::decode_header(table, &mut resp_block) {
//                 Ok(_) => (),
//                 Err(e) => return Err(format_err!("failed to decode response header {}", e)),
//             }
//         }
//         Ok(f) => {
//             return Err(format_err!("response frame bad type {:?}", f));
//         }
//         Err(e) => return Err(format_err!("failed to decode response frame {:?}", e)),
//     }

//     match HttpFrame::decode(&mut cur) {
//         Ok(HttpFrame::Data(text)) => Ok(text.payload),
//         Ok(f) => Err(format_err!("response frame bad type {:?}", f)),
//         Err(e) => Err(format_err!("failed to decode response frame {:?}", e)),
//     }
// }

async fn get(stream: (quinn::SendStream, quinn::RecvStream)) -> Result<Vec<u8>> {
    let (mut send, recv) = stream;
    send.write_all(b"GET /index.html\r\n")
        .await
        .map_err(|e| format_err!("failed to send request: {}", e))?;
    send.finish()
        .await
        .map_err(|e| format_err!("failed to shutdown stream: {}", e))?;
    let response = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| format_err!("failed to read response: {}", e))?;
    Ok(response)
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
