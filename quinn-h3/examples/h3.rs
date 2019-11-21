use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Result};
use futures::{StreamExt, TryFutureExt};
use http::{header::HeaderValue, method::Method, HeaderMap, Request, Response, StatusCode};
use structopt::{self, StructOpt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use quinn::{Certificate, CertificateChain, ConnectionDriver as QuicDriver, PrivateKey};
use quinn_h3::{
    self,
    body::RecvBody,
    client::{Builder as ClientBuilder, Client},
    connection::ConnectionDriver,
    server::{Builder as ServerBuilder, IncomingRequest, Sender},
};

mod shared;
use shared::build_certs;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3")]
struct Opt {
    #[structopt(default_value = "http://127.0.0.1:4433/Cargo.toml")]
    url: Url,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
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

    let server =
        server(opt.clone(), (certs.0.clone(), certs.2.clone())).expect("init server failed");

    let (client, client_driver) = build_client(certs.1).expect("build client failed");

    tokio::spawn(async move {
        println!("server running");
        if let Err(e) = server.await {
            eprintln!("h3 server error: {}", e)
        }
        println!("server finished");
    });

    tokio::spawn(async move {
        if let Err(e) = client_driver.await {
            eprintln!("h3 client dirver error: {}", e)
        }
    });

    let remote = (opt.url.host_str().unwrap(), opt.url.port().unwrap_or(4433))
        .to_socket_addrs()
        .expect("invalid address")
        .next()
        .expect("couldn't resolve to an address");

    match client_request(client, &remote).await {
        Ok(_) => println!("client finished"),
        Err(e) => println!("client failed: {:?}", e),
    }

    ::std::process::exit(0);
}

fn server(options: Opt, certs: (CertificateChain, PrivateKey)) -> Result<quinn::EndpointDriver> {
    let server_config = quinn::ServerConfig {
        transport: Arc::new(quinn::TransportConfig {
            stream_window_uni: 513,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(&[quinn_h3::ALPN]);
    server_config.certificate(certs.0, certs.1)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let server = ServerBuilder::new(endpoint);

    let (endpoint_driver, mut incoming) = {
        let (driver, _server, incoming) = server.bind(&options.listen)?;
        (driver, incoming)
    };

    tokio::spawn(async move {
        println!("server listening");
        while let Some(connecting) = incoming.next().await {
            println!("server received connection");
            let connection = connecting
                .await
                .map_err(|e| anyhow!("accept failed: {:?}", e))
                .expect("server failed");
            println!("received connection");
            handle_connection(connection).await
        }
    });

    Ok(endpoint_driver)
}

async fn handle_connection(conn: (QuicDriver, ConnectionDriver, IncomingRequest)) {
    let (quic_driver, h3_driver, mut incoming) = conn;
    tokio::spawn(async move {
        if let Err(e) = h3_driver.await {
            eprintln!("h3 server error: {}", e)
        }
    });

    tokio::spawn(async move {
        while let Some(request) = incoming.next().await {
            let (req, send) = request.await.expect("receiving request failed");
            handle_request(req, send)
                .await
                .expect("handling request failed");
        }
    });

    if let Err(e) = quic_driver.await {
        eprintln!("quic server error: {}", e)
    }
}

async fn handle_request(request: Request<RecvBody>, sender: Sender) -> Result<()> {
    println!("received request: {:?}", request);
    let (_, body) = request.into_parts();
    let (content, trailers) = body
        .read_to_end(1024, 10 * 1024)
        .await
        .map_err(|e| anyhow!("receive body failed: {:?}", e))?;

    if let Some(content) = content {
        println!("server received body len: {:?}", content.len());
    }
    if let Some(trailers) = trailers {
        println!("received trailers: {:?}", trailers);
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("failed to build response");

    let mut trailer = HeaderMap::with_capacity(2);
    trailer.append(
        "response",
        HeaderValue::from_str("trailer").expect("trailer value"),
    );

    let mut writer = sender
        .response(response)
        .trailers(trailer)
        .stream()
        .await
        .map_err(|e| anyhow!("receive response failed: {:?}", e))?;

    let response_body = "r".repeat(1024);
    println!("sending body");
    writer.write_all(response_body.as_bytes()).await?;
    println!("sent body");
    writer
        .close()
        .map_err(|e| anyhow!("close failed: {:?}", e))
        .await?;
    Ok(())
}

fn build_client(cert: Certificate) -> Result<(Client, quinn::EndpointDriver)> {
    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(&[quinn_h3::ALPN]);

    client_config.add_certificate_authority(cert)?;
    endpoint.default_client_config(client_config.build());

    let (endpoint_driver, endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;
    Ok((
        ClientBuilder::new().endpoint(endpoint.clone()),
        endpoint_driver,
    ))
}

async fn client_request(client: Client, remote: &SocketAddr) -> Result<()> {
    let start = Instant::now();
    let (quic_driver, h3_driver, conn) = client
        .connect(&remote, "localhost")?
        .await
        .map_err(|e| anyhow!("failed ot connect: {:?}", e))?;
    eprintln!("client connected at {:?}", start.elapsed());

    tokio::spawn(async move {
        if let Err(e) = h3_driver.await {
            eprintln!("h3 client error: {}", e)
        }
    });

    tokio::spawn(async move {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/hello")
            .header("foo", "bar")
            .body("request body")
            .expect("failed to build request");

        let mut trailer = HeaderMap::with_capacity(2);
        trailer.append(
            "request",
            HeaderValue::from_str("trailer").expect("trailer value"),
        );

        let (mut send_body, response) = conn
            .request(request)
            .stream()
            .await
            .expect("send request failed");

        let request_body = "c".repeat(1024);
        send_body
            .write_all(request_body.as_bytes())
            .await
            .expect("failed to send body");
        send_body
            .trailers(trailer)
            .await
            .expect("failed end request");

        let (response, body) = response
            .await
            .expect("receive response failed")
            .into_parts();
        println!("client received response: {:?}", response);

        let mut data = Vec::with_capacity(1024);
        let mut reader = body.into_reader();
        reader
            .read_to_end(&mut data)
            .await
            .expect("read body failed");
        println!("client received body len = {}", data.len());

        if let Some(decode_trailers) = reader.trailers() {
            let trailers = decode_trailers.await.expect("decode trailers failed");
            println!("client received trailers: {:?}", trailers.into_fields());
        }

        conn.close();
    });

    if let Err(e) = quic_driver.await {
        eprintln!("quic client error: {}", e)
    }
    Ok(())
}
