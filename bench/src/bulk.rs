use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use tracing::trace;

#[tokio::main]
async fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();

    let mut server_config = quinn::ServerConfigBuilder::default();
    server_config
        .certificate(quinn::CertificateChain::from_certs(vec![cert.clone()]), key)
        .unwrap();
    let mut endpoint = quinn::EndpointBuilder::default();
    endpoint.listen(server_config.build());
    let (driver, endpoint, incoming) = endpoint
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    drop(endpoint); // Ensure server shuts down when finished
    let thread = tokio::spawn(async {
        let driver = tokio::spawn(async {
            driver.await.expect("server endpoint driver");
        });
        if let Err(e) = tokio::spawn(server(incoming)).await {
            eprintln!("server failed: {:#}", e);
        }
        driver.await.expect("server run");
    });

    if let Err(e) = tokio::spawn(client(server_addr, cert)).await {
        eprintln!("client failed: {:#}", e);
    }

    thread.await.expect("server thread");
}

async fn server(mut incoming: quinn::Incoming) -> Result<()> {
    let handshake = incoming.next().await.unwrap();
    let quinn::NewConnection {
        driver,
        mut uni_streams,
        ..
    } = handshake.await.context("handshake failed")?;
    tokio::spawn(async {
        driver.await.expect("server conn driver");
    });
    let mut stream = uni_streams
        .next()
        .await
        .ok_or(anyhow!("accepting stream failed"))??;
    trace!("stream established");
    let start = Instant::now();
    let mut n = 0;
    while let Some((data, offset)) = stream.read_unordered().await? {
        n = n.max(offset + data.len() as u64);
    }
    println!("recvd {} bytes in {:?}", n, start.elapsed());
    Ok(())
}

async fn client(server_addr: SocketAddr, server_cert: quinn::Certificate) -> Result<()> {
    let (driver, endpoint, _) = quinn::EndpointBuilder::default()
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();
    tokio::spawn(async {
        driver.await.expect("client endpoint driver");
    });

    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config
        .add_certificate_authority(server_cert)
        .unwrap();
    let quinn::NewConnection {
        driver, connection, ..
    } = endpoint
        .connect_with(client_config.build(), &server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;
    tokio::spawn(async {
        let _ = driver.await;
    });
    trace!("connected");

    let mut stream = connection
        .open_uni()
        .await
        .context("failed to open stream")?;
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let start = Instant::now();
    for _ in 0..1024 {
        stream
            .write_all(DATA)
            .await
            .context("failed sending data")?;
    }
    stream.finish().await.context("failed finishing stream")?;
    println!("sent {} bytes in {:?}", 1024 * DATA.len(), start.elapsed());
    Ok(())
}
