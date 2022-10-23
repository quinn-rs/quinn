use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::TokioRuntime;
use tracing::{debug, error, info};

use perf::{bind_socket, noprotection::NoProtectionServerConfig};

#[derive(Parser)]
#[clap(name = "server")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// TLS private key in DER format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Send buffer size in bytes
    #[clap(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[clap(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Whether to print connection statistics
    #[clap(long)]
    conn_stats: bool,
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,
    /// UDP payload size that the network must be capable of carrying
    #[clap(long, default_value = "1200")]
    initial_mtu: u16,
    /// Disable packet encryption/decryption (for debugging purpose)
    #[clap(long = "no-protection")]
    no_protection: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (Some(key), Some(cert)) => {
            let key = fs::read(key).context("reading key")?;
            let cert = fs::read(cert).expect("reading cert");

            let mut certs = Vec::new();
            for cert in rustls_pemfile::certs(&mut cert.as_ref()).context("parsing cert")? {
                certs.push(rustls::Certificate(cert));
            }

            (rustls::PrivateKey(key), certs)
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                rustls::PrivateKey(cert.serialize_private_key_der()),
                vec![rustls::Certificate(cert.serialize_der().unwrap())],
            )
        }
    };

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(perf::PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if opt.keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(opt.initial_mtu);

    let mut server_config = if opt.no_protection {
        quinn::ServerConfig::with_crypto(Arc::new(NoProtectionServerConfig::new(Arc::new(crypto))))
    } else {
        quinn::ServerConfig::with_crypto(Arc::new(crypto))
    };
    server_config.transport_config(Arc::new(transport));

    let socket = bind_socket(opt.listen, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::Endpoint::new(
        Default::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )
    .context("creating endpoint")?;

    info!("listening on {}", endpoint.local_addr().unwrap());

    let opt = Arc::new(opt);

    while let Some(handshake) = endpoint.accept().await {
        let opt = opt.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(handshake, opt).await {
                error!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn handle(handshake: quinn::Connecting, opt: Arc<Opt>) -> Result<()> {
    let connection = handshake.await.context("handshake failed")?;
    debug!("{} connected", connection.remote_address());
    tokio::try_join!(
        drive_uni(connection.clone()),
        drive_bi(connection.clone()),
        conn_stats(connection, opt)
    )?;
    Ok(())
}

async fn conn_stats(connection: quinn::Connection, opt: Arc<Opt>) -> Result<()> {
    if opt.conn_stats {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("{:?}\n", connection.stats());
        }
    }

    Ok(())
}

async fn drive_uni(connection: quinn::Connection) -> Result<()> {
    while let Ok(stream) = connection.accept_uni().await {
        let connection = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_uni(connection, stream).await {
                error!("request failed: {:#}", e);
            }
        });
    }
    Ok(())
}

async fn handle_uni(connection: quinn::Connection, stream: quinn::RecvStream) -> Result<()> {
    let bytes = read_req(stream).await?;
    let response = connection.open_uni().await?;
    respond(bytes, response).await?;
    Ok(())
}

async fn drive_bi(connection: quinn::Connection) -> Result<()> {
    while let Ok((send, recv)) = connection.accept_bi().await {
        tokio::spawn(async move {
            if let Err(e) = handle_bi(send, recv).await {
                error!("request failed: {:#}", e);
            }
        });
    }
    Ok(())
}

async fn handle_bi(send: quinn::SendStream, recv: quinn::RecvStream) -> Result<()> {
    let bytes = read_req(recv).await?;
    respond(bytes, send).await?;
    Ok(())
}

async fn read_req(mut stream: quinn::RecvStream) -> Result<u64> {
    let mut buf = [0; 8];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading request")?;
    let n = u64::from_be_bytes(buf);
    debug!("got req for {} bytes on {}", n, stream.id());
    drain_stream(stream).await?;
    Ok(n)
}

async fn drain_stream(mut stream: quinn::RecvStream) -> Result<()> {
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
    while stream.read_chunks(&mut bufs[..]).await?.is_some() {}
    debug!("finished reading {}", stream.id());
    Ok(())
}

async fn respond(mut bytes: u64, mut stream: quinn::SendStream) -> Result<()> {
    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];

    while bytes > 0 {
        let chunk_len = bytes.min(DATA.len() as u64);
        stream
            .write_chunk(Bytes::from_static(&DATA[..chunk_len as usize]))
            .await
            .context("sending response")?;
        bytes -= chunk_len;
    }
    debug!("finished responding on {}", stream.id());
    Ok(())
}
