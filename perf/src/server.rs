use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use structopt::StructOpt;
use tracing::{debug, error, info, trace};

#[derive(StructOpt)]
#[structopt(name = "server")]
struct Opt {
    /// Address to listen on
    #[structopt(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::from_args();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (&Some(ref key), &Some(ref cert)) => {
            let key = fs::read(key).context("reading key")?;
            let cert = fs::read(cert).expect("reading cert");
            (
                quinn::PrivateKey::from_pem(&key).context("parsing key")?,
                quinn::CertificateChain::from_pem(&cert).context("parsing cert")?,
            )
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap(),
                quinn::CertificateChain::from_certs(vec![quinn::Certificate::from_der(
                    &cert.serialize_der().unwrap(),
                )
                .unwrap()]),
            )
        }
    };

    let mut server_config = quinn::ServerConfigBuilder::default();
    server_config.certificate(cert, key).unwrap();
    server_config.protocols(&[b"perf"]);

    let mut server_config = server_config.build();

    // Configure cipher suites for efficiency
    let tls_config = Arc::get_mut(&mut server_config.crypto).unwrap();
    tls_config.ciphersuites.clear();
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_128_GCM_SHA256);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_256_GCM_SHA384);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256);

    let mut endpoint = quinn::EndpointBuilder::default();
    endpoint.listen(server_config);

    let (endpoint, mut incoming) = endpoint.bind(&opt.listen).context("binding endpoint")?;

    info!("listening on {}", endpoint.local_addr().unwrap());

    while let Some(handshake) = incoming.next().await {
        tokio::spawn(async move {
            if let Err(e) = handle(handshake).await {
                error!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn handle(handshake: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        uni_streams,
        bi_streams,
        connection,
        ..
    } = handshake.await.context("handshake failed")?;
    debug!("{} connected", connection.remote_address());
    tokio::try_join!(drive_uni(connection, uni_streams), drive_bi(bi_streams))?;
    Ok(())
}

async fn drive_uni(
    connection: quinn::Connection,
    mut streams: quinn::IncomingUniStreams,
) -> Result<()> {
    while let Some(stream) = streams.next().await {
        let stream = stream?;
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

async fn drive_bi(mut streams: quinn::IncomingBiStreams) -> Result<()> {
    while let Some(stream) = streams.next().await {
        let (send, recv) = stream?;
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
    trace!("got req for {} bytes on {}", n, stream.id());
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
    trace!("finished reading {}", stream.id());
    Ok(())
}

async fn respond(mut bytes: u64, mut stream: quinn::SendStream) -> Result<()> {
    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];
    while bytes > 0 {
        let n = stream
            .write(&DATA[..bytes.min(DATA.len() as u64) as usize])
            .await
            .context("sending response")?;
        bytes -= n as u64;
    }
    trace!("finished responding on {}", stream.id());
    Ok(())
}
