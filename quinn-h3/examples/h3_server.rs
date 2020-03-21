use std::{net::SocketAddr, path::PathBuf};

use anyhow::{anyhow, Result};
use futures::{AsyncReadExt, StreamExt};
use http::{Response, StatusCode};
use structopt::{self, StructOpt};
use tracing::error;

use quinn_h3::{
    self,
    server::{Builder as ServerBuilder, IncomingRequest, RecvRequest},
};

mod shared;
use shared::build_certs;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_server")]
struct Opt {
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    /// Address to listen on
    #[structopt(long = "listen", default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::from_args();
    let certs = build_certs(&opt.key, &opt.cert).expect("failed to build certs");

    let mut server = ServerBuilder::default();
    server
        .certificate(certs.0, certs.2)
        .expect("failed to add cert");

    let mut incoming = server.build().expect("bind failed");

    println!("server listening");
    while let Some(connecting) = incoming.next().await {
        println!("server received connection");
        match connecting.await {
            Err(e) => error!("accept failed: {:?}", e),
            Ok(connection) => {
                let _ = tokio::spawn(async move {
                    if let Err(e) = handle_connection(connection).await {
                        error!("handling connection failed: {:?}", e);
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_connection(mut incoming: IncomingRequest) -> Result<()> {
    while let Some(request) = incoming.next().await {
        tokio::spawn(async move {
            if let Err(e) = handle_request(request).await {
                eprintln!("request error: {}", e)
            }
        });
    }

    Ok(())
}

async fn handle_request(recv_request: RecvRequest) -> Result<()> {
    let (request, mut recv_body, sender) = recv_request.await?;
    println!("received request: {:?}", request);

    let mut body = Vec::with_capacity(1024);
    recv_body
        .read_to_end(&mut body)
        .await
        .map_err(|e| anyhow!("failed to send response headers: {:?}", e))?;

    println!("received body: {}", String::from_utf8_lossy(&body));
    if let Some(trailers) = recv_body.trailers().await {
        println!("received trailers: {:?}", trailers);
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("response", "header")
        .body("response body")
        .expect("failed to build response");

    sender
        .send_response(response)
        .await
        .map_err(|e| anyhow!("failed to send response: {:?}", e))?;

    Ok(())
}
