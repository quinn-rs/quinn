use std::{fs, io, net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use http::{Response, StatusCode};
use quinn::{CertificateChain, PrivateKey};
use structopt::{self, StructOpt};
use tracing::{error, info};
use tracing_subscriber::filter::LevelFilter;

use quinn_h3::{
    self,
    server::{self, RecvRequest},
    Body,
};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_server")]
struct Opt {
    /// TLS private key in DER format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in DER format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Address to listen on
    #[structopt(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(LevelFilter::INFO.into()),
            )
            .finish(),
    )?;
    let opt = Opt::from_args();
    let (cert, key) = build_certs(&opt.key, &opt.cert).expect("failed to build certs");

    // Configure a server endpoint
    let mut server = server::Builder::default();
    server
        .listen(opt.listen)
        .certificate(cert, key)
        .expect("failed to add cert");

    // Build it, get a stream of incoming connections
    let mut incoming = server.build().expect("bind failed");

    info!("server listening on {}", opt.listen);

    // Handle each connection concurrently, spawning a new task for each of one them
    while let Some(connecting) = incoming.next().await {
        tokio::spawn(async move {
            // Wait for the handshake to complete, get a stream of incoming requests
            let mut incoming_request = match connecting.await {
                Ok(incoming_request) => incoming_request,
                Err(e) => {
                    error!("handshake failed: {:?}", e);
                    return;
                }
            };

            // Handle each request concurently
            while let Some(request) = incoming_request.next().await {
                tokio::spawn(async move {
                    if let Err(e) = handle_request(request).await {
                        error!("request failed: {:?}", e);
                    };
                });
            }
        });
    }

    Ok(())
}

async fn handle_request(recv_request: RecvRequest) -> Result<()> {
    // Receive the request's headers
    let (request, mut sender) = recv_request.await?;
    info!("received request: {:?}", request);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("response", "header")
        .body(Body::from("Greetings over HTTP/3"))?;

    sender.send_response(response).await?;

    Ok(())
}

pub fn build_certs(
    key: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> Result<(CertificateChain, PrivateKey)> {
    if let (Some(ref key_path), Some(ref cert_path)) = (key, cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert = quinn::Certificate::from_der(&cert_chain)?;
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert]);
        Ok((cert_chain, key))
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(&path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, &key).context("failed to write private key")?;
                (cert, key)
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert = quinn::Certificate::from_der(&cert)?;
        Ok((quinn::CertificateChain::from_certs(vec![cert]), key))
    }
}
