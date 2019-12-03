use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};
use futures::{AsyncReadExt, StreamExt};
use http::{Response, StatusCode};
use structopt::{self, StructOpt};

use quinn::ConnectionDriver as QuicDriver;
use quinn_h3::{
    self,
    connection::ConnectionDriver,
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

    let server_config = quinn::ServerConfig {
        transport: Arc::new(quinn::TransportConfig {
            stream_window_uni: 513,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(&[quinn_h3::ALPN]);
    server_config
        .certificate(certs.0, certs.2)
        .expect("failed to add cert");

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let server = ServerBuilder::new(endpoint);

    let (endpoint_driver, mut incoming) = {
        let (driver, _server, incoming) = server.bind(&opt.listen).expect("bind failed");
        (driver, incoming)
    };

    tokio::spawn(async move {
        if let Err(e) = endpoint_driver.await {
            eprintln!("h3 server error: {}", e)
        }
    });

    println!("server listening");
    while let Some(connecting) = incoming.next().await {
        println!("server received connection");
        let connection = connecting
            .await
            .map_err(|e| anyhow!("accept failed: {:?}", e))
            .expect("server failed");

        handle_connection(connection)
            .await
            .expect("handling connection failed")
    }

    Ok(())
}

async fn handle_connection(conn: (QuicDriver, ConnectionDriver, IncomingRequest)) -> Result<()> {
    let (quic_driver, h3_driver, mut incoming) = conn;

    tokio::spawn(async move {
        if let Err(e) = h3_driver.await {
            eprintln!("quic connection driver error: {}", e)
        }
    });

    tokio::spawn(async move {
        while let Some(request) = incoming.next().await {
            tokio::spawn(async move {
                if let Err(e) = handle_request(request).await {
                    eprintln!("request error: {}", e)
                }
            });
        }
    });

    if let Err(e) = quic_driver.await {
        eprintln!("quic connection driver error: {}", e)
    }

    Ok(())
}

async fn handle_request(recv_request: RecvRequest) -> Result<()> {
    let (request, mut recv_body, sender) = recv_request.await.expect("recv request failed");
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
