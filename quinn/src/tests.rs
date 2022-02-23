#![cfg(feature = "rustls")]

use std::{
    convert::TryInto,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str,
    sync::Arc,
};

use bytes::Bytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tokio::{
    runtime::{Builder, Runtime},
    time::{Duration, Instant},
};
use tracing::{info, info_span};
use tracing_futures::Instrument as _;
use tracing_subscriber::EnvFilter;

use super::{
    ClientConfig, Endpoint, Incoming, NewConnection, RecvStream, SendStream, TransportConfig,
};

#[test]
fn handshake_timeout() {
    let _guard = subscribe();
    let runtime = rt_threaded();
    let client = {
        let _guard = runtime.enter();
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap()
    };

    let mut client_config =
        crate::ClientConfig::with_root_certificates(rustls::RootCertStore::empty());
    const IDLE_TIMEOUT: Duration = Duration::from_millis(500);
    let mut transport_config = crate::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()))
        .initial_rtt(Duration::from_millis(10));
    client_config.transport_config(Arc::new(transport_config));

    let start = Instant::now();
    runtime.block_on(async move {
        match client
            .connect_with(
                client_config,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                "localhost",
            )
            .unwrap()
            .await
        {
            Err(crate::ConnectionError::TimedOut) => {}
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => panic!("unexpected success"),
        }
    });
    let dt = start.elapsed();
    assert!(dt > IDLE_TIMEOUT && dt < 2 * IDLE_TIMEOUT);
}

#[tokio::test]
async fn close_endpoint() {
    let _guard = subscribe();
    let mut endpoint =
        Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    endpoint.set_default_client_config(ClientConfig::with_root_certificates(
        rustls::RootCertStore::empty(),
    ));

    let conn = endpoint
        .connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .unwrap();

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let conn = endpoint
        .connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            "localhost",
        )
        .unwrap();
    endpoint.close(0u32.into(), &[]);
    match conn.await {
        Err(crate::ConnectionError::LocallyClosed) => (),
        Err(e) => panic!("unexpected error: {}", e),
        Ok(_) => {
            panic!("unexpected success");
        }
    }
}

#[test]
fn local_addr() {
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let runtime = rt_basic();
    let (ep, _) = {
        let _guard = runtime.enter();
        Endpoint::new(Default::default(), None, socket).unwrap()
    };
    assert_eq!(
        addr,
        ep.local_addr()
            .expect("Could not obtain our local endpoint")
    );
}

#[test]
fn read_after_close() {
    let _guard = subscribe();
    let runtime = rt_basic();
    let (endpoint, mut incoming) = {
        let _guard = runtime.enter();
        endpoint()
    };

    const MSG: &[u8] = b"goodbye!";
    runtime.spawn(async move {
        let new_conn = incoming
            .next()
            .await
            .expect("endpoint")
            .await
            .expect("connection");
        let mut s = new_conn.connection.open_uni().await.unwrap();
        s.write_all(MSG).await.unwrap();
        s.finish().await.unwrap();
    });
    runtime.block_on(async move {
        let mut new_conn = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("connect");
        tokio::time::sleep_until(Instant::now() + Duration::from_millis(100)).await;
        let stream = new_conn
            .uni_streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream");
        let msg = stream
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
    });
}

#[test]
fn export_keying_material() {
    let _guard = subscribe();
    let runtime = rt_basic();
    let (endpoint, mut incoming) = {
        let _guard = runtime.enter();
        endpoint()
    };

    runtime.block_on(async move {
        let outgoing_conn = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("connect");
        let incoming_conn = incoming
            .next()
            .await
            .expect("endpoint")
            .await
            .expect("connection");
        let mut i_buf = [0u8; 64];
        incoming_conn
            .connection
            .export_keying_material(&mut i_buf, b"asdf", b"qwer")
            .unwrap();
        let mut o_buf = [0u8; 64];
        outgoing_conn
            .connection
            .export_keying_material(&mut o_buf, b"asdf", b"qwer")
            .unwrap();
        assert_eq!(&i_buf[..], &o_buf[..]);
    });
}

#[tokio::test]
async fn accept_after_close() {
    let _guard = subscribe();
    let (endpoint, mut incoming) = endpoint();

    const MSG: &[u8] = b"goodbye!";

    let sender = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .await
        .expect("connect")
        .connection;
    let mut s = sender.open_uni().await.unwrap();
    s.write_all(MSG).await.unwrap();
    s.finish().await.unwrap();
    sender.close(0u32.into(), b"");

    // Allow some time for the close to be sent and processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Despite the connection having closed, we should be able to accept it...
    let mut receiver = incoming
        .next()
        .await
        .expect("endpoint")
        .await
        .expect("connection");

    // ...and read what was sent.
    let stream = receiver
        .uni_streams
        .next()
        .await
        .expect("incoming streams")
        .expect("missing stream");
    let msg = stream
        .read_to_end(usize::max_value())
        .await
        .expect("read_to_end");
    assert_eq!(msg, MSG);

    // But it's still definitely closed.
    assert!(receiver.connection.open_uni().await.is_err());
}

/// Construct an endpoint suitable for connecting to itself
fn endpoint() -> (Endpoint, Incoming) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());
    let server_config = crate::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(&cert).unwrap();
    let (mut endpoint, incoming) = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let client_config = ClientConfig::with_root_certificates(roots);
    endpoint.set_default_client_config(client_config);

    (endpoint, incoming)
}

#[tokio::test]
async fn zero_rtt() {
    let _guard = subscribe();
    let (endpoint, mut incoming) = endpoint();

    const MSG: &[u8] = b"goodbye!";
    tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = incoming.next().await.unwrap();
            let NewConnection {
                mut uni_streams,
                connection,
                ..
            } = incoming.into_0rtt().unwrap_or_else(|_| unreachable!()).0;
            tokio::spawn(async move {
                while let Some(Ok(x)) = uni_streams.next().await {
                    let msg = x.read_to_end(usize::max_value()).await.unwrap();
                    assert_eq!(msg, MSG);
                }
            });
            let mut s = connection.open_uni().await.expect("open_uni");
            s.write_all(MSG).await.expect("write");
            s.finish().await.expect("finish");
        }
    });

    let NewConnection {
        mut uni_streams, ..
    } = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .err()
        .expect("0-RTT succeeded without keys")
        .await
        .expect("connect");

    tokio::spawn(async move {
        // Buy time for the driver to process the server's NewSessionTicket
        tokio::time::sleep_until(Instant::now() + Duration::from_millis(100)).await;
        let stream = uni_streams
            .next()
            .await
            .expect("incoming streams")
            .expect("missing stream");
        let msg = stream
            .read_to_end(usize::max_value())
            .await
            .expect("read_to_end");
        assert_eq!(msg, MSG);
    });
    endpoint.wait_idle().await;

    info!("initial connection complete");

    let (
        NewConnection {
            connection,
            mut uni_streams,
            ..
        },
        zero_rtt,
    ) = endpoint
        .connect(endpoint.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("missing 0-RTT keys"));
    // Send something ASAP to use 0-RTT
    tokio::spawn(async move {
        let mut s = connection.open_uni().await.expect("0-RTT open uni");
        s.write_all(MSG).await.expect("0-RTT write");
        s.finish().await.expect("0-RTT finish");
    });

    let stream = uni_streams
        .next()
        .await
        .expect("incoming streams")
        .expect("missing stream");
    let msg = stream
        .read_to_end(usize::max_value())
        .await
        .expect("read_to_end");
    assert_eq!(msg, MSG);
    assert!(zero_rtt.await);

    drop(uni_streams);

    endpoint.wait_idle().await;
}

#[test]
fn echo_v6() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
fn echo_v4() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))] // Dual-stack sockets aren't the default anywhere else.
fn echo_dualstack() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 1,
        stream_size: 10 * 1024,
        receive_window: None,
        stream_receive_window: None,
    });
}

#[test]
#[cfg(not(tarpaulin))]
fn stress_receive_window() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 50,
        stream_size: 25 * 1024 + 11,
        receive_window: Some(37),
        stream_receive_window: Some(100 * 1024 * 1024),
    });
}

#[test]
#[cfg(not(tarpaulin))]
fn stress_stream_receive_window() {
    // Note that there is no point in runnning this with too many streams,
    // since the window is only active within a stream
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 2,
        stream_size: 250 * 1024 + 11,
        receive_window: Some(100 * 1024 * 1024),
        stream_receive_window: Some(37),
    });
}

#[test]
#[cfg(not(tarpaulin))]
fn stress_both_windows() {
    run_echo(EchoArgs {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        nr_streams: 50,
        stream_size: 25 * 1024 + 11,
        receive_window: Some(37),
        stream_receive_window: Some(37),
    });
}

fn run_echo(args: EchoArgs) {
    let _guard = subscribe();
    let runtime = rt_basic();
    let handle = {
        // Use small receive windows
        let mut transport_config = TransportConfig::default();
        if let Some(receive_window) = args.receive_window {
            transport_config.receive_window(receive_window.try_into().unwrap());
        }
        if let Some(stream_receive_window) = args.stream_receive_window {
            transport_config.stream_receive_window(stream_receive_window.try_into().unwrap());
        }
        transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.max_concurrent_uni_streams(1_u8.into());
        let transport_config = Arc::new(transport_config);

        // We don't use the `endpoint` helper here because we want two different endpoints with
        // different addresses.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::PrivateKey(cert.serialize_private_key_der());
        let cert_der = cert.serialize_der().unwrap();
        let cert = rustls::Certificate(cert_der);
        let mut server_config =
            crate::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();

        server_config.transport = transport_config.clone();
        let server_sock = UdpSocket::bind(args.server_addr).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let (server, mut server_incoming) = {
            let _guard = runtime.enter();
            Endpoint::new(Default::default(), Some(server_config), server_sock).unwrap()
        };

        let mut roots = rustls::RootCertStore::empty();
        roots.add(&cert).unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

        let mut client = {
            let _guard = runtime.enter();
            Endpoint::client(args.client_addr).unwrap()
        };
        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        client_config.transport_config(transport_config);
        client.set_default_client_config(client_config);

        let handle = runtime.spawn(async move {
            let incoming = server_incoming.next().await.unwrap();

            // Note for anyone modifying the platform support in this test:
            // If `local_ip` gets available on additional platforms - which
            // requires modifying this test - please update the list of supported
            // platforms in the doc comments of the various `local_ip` functions.
            if cfg!(target_os = "linux") {
                let local_ip = incoming.local_ip().expect("Local IP must be available");
                assert!(local_ip.is_loopback());
            } else {
                assert_eq!(None, incoming.local_ip());
            }

            let mut new_conn = incoming.instrument(info_span!("server")).await.unwrap();
            tokio::spawn(async move {
                while let Some(stream) = new_conn.bi_streams.next().await {
                    tokio::spawn(echo(stream.unwrap()));
                }
            });
            server.wait_idle().await;
        });

        info!(
            "connecting from {} to {}",
            args.client_addr, args.server_addr
        );
        runtime.block_on(async move {
            let new_conn = client
                .connect(server_addr, "localhost")
                .unwrap()
                .instrument(info_span!("client"))
                .await
                .expect("connect");

            /// This is just an arbitrary number to generate deterministic test data
            const SEED: u64 = 0x12345678;

            for i in 0..args.nr_streams {
                println!("Opening stream {}", i);
                let (mut send, recv) = new_conn.connection.open_bi().await.expect("stream open");
                let msg = gen_data(args.stream_size, SEED);

                let send_task = async {
                    send.write_all(&msg).await.expect("write");
                    send.finish().await.expect("finish");
                };
                let recv_task = async { recv.read_to_end(usize::max_value()).await.expect("read") };

                let (_, data) = tokio::join!(send_task, recv_task);

                assert_eq!(data[..], msg[..], "Data mismatch");
            }
            new_conn.connection.close(0u32.into(), b"done");
            client.wait_idle().await;
        });
        handle
    };
    runtime.block_on(handle).unwrap();
}

struct EchoArgs {
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    nr_streams: usize,
    stream_size: usize,
    receive_window: Option<u64>,
    stream_receive_window: Option<u64>,
}

async fn echo((mut send, mut recv): (SendStream, RecvStream)) {
    loop {
        // These are 32 buffers, for reading approximately 32kB at once
        #[rustfmt::skip]
        let mut bufs = [
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        ];

        match recv.read_chunks(&mut bufs).await.expect("read chunks") {
            Some(n) => {
                send.write_all_chunks(&mut bufs[..n])
                    .await
                    .expect("write chunks");
            }
            None => break,
        }
    }

    let _ = send.finish().await;
}

fn gen_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
    let mut buf = vec![0; size];
    rng.fill_bytes(&mut buf);
    buf
}

pub fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

fn rt_basic() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn rt_threaded() -> Runtime {
    Builder::new_multi_thread().enable_all().build().unwrap()
}

#[tokio::test]
async fn rebind_recv() {
    let _guard = subscribe();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(&cert).unwrap();

    let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let mut client_config = ClientConfig::new(Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    client_config.transport_config(Arc::new({
        let mut cfg = TransportConfig::default();
        cfg.max_concurrent_uni_streams(1u32.into());
        cfg
    }));
    client.set_default_client_config(client_config);

    let server_config = crate::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
    let (server, mut incoming) = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();

    const MSG: &[u8; 5] = b"hello";

    let write_send = Arc::new(tokio::sync::Notify::new());
    let write_recv = write_send.clone();
    let connected_send = Arc::new(tokio::sync::Notify::new());
    let connected_recv = connected_send.clone();
    let server = tokio::spawn(async move {
        let NewConnection { connection, .. } = incoming.next().await.unwrap().await.unwrap();
        info!("got conn");
        connected_send.notify_one();
        write_recv.notified().await;
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(MSG).await.unwrap();
        stream.finish().await.unwrap();
    });

    let NewConnection {
        mut uni_streams, ..
    } = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    info!("connected");
    connected_recv.notified().await;
    client
        .rebind(UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap())
        .unwrap();
    info!("rebound");
    write_send.notify_one();
    let stream = uni_streams.next().await.unwrap().unwrap();
    assert_eq!(stream.read_to_end(MSG.len()).await.unwrap(), MSG);
    server.await.unwrap();
}
