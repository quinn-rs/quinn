use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{TokioRuntime, crypto::rustls::QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tracing::{debug, error, info};

use crate::{CommonOpt, PERF_CIPHER_SUITES, noprotection::NoProtectionServerConfig};

#[derive(Parser)]
#[clap(name = "server")]
pub struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// TLS private key in DER format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Common options
    #[command(flatten)]
    common: CommonOpt,
}

pub async fn run(opt: Opt) -> Result<()> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (Some(key), Some(cert)) => (
            PrivateKeyDer::from_pem_file(key).context("reading private key")?,
            CertificateDer::pem_file_iter(cert)
                .context("reading certificate chain file")?
                .collect::<Result<_, _>>()
                .context("reading certificate chain")?,
        ),
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
                vec![CertificateDer::from(cert.cert)],
            )
        }
    };

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: PERF_CIPHER_SUITES.into(),
        ..default_provider
    };

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if opt.common.keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let transport = opt.common.build_transport_config(
        #[cfg(feature = "qlog")]
        "perf-server",
    )?;

    let crypto = Arc::new(QuicServerConfig::try_from(crypto)?);
    let mut config = quinn::ServerConfig::with_crypto(match opt.common.no_protection {
        true => Arc::new(NoProtectionServerConfig::new(crypto)),
        false => crypto,
    });
    config.transport_config(Arc::new(transport));

    let socket = opt.common.bind_socket(opt.listen)?;

    let mut endpoint_cfg = quinn::EndpointConfig::default();
    endpoint_cfg.max_udp_payload_size(opt.common.max_udp_payload_size)?;

    let endpoint = quinn::Endpoint::new(endpoint_cfg, Some(config), socket, Arc::new(TokioRuntime))
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

async fn handle(handshake: quinn::Incoming, opt: Arc<Opt>) -> Result<()> {
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
    if opt.common.conn_stats {
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
    static DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];

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
