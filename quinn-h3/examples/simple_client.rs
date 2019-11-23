use std::{fs, io, net::ToSocketAddrs, path::PathBuf};
use structopt::{self, StructOpt};

use anyhow::{anyhow, Result};
use http::{header::HeaderValue, method::Method, HeaderMap, Request};
use tracing::{error, info};
use url::Url;

use quinn_h3::{
    self,
    client::{Builder as ClientBuilder, Client},
};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_client")]
struct Opt {
    #[structopt(default_value = "http://localhost:4433/Cargo.toml")]
    url: Url,

    /// Custom certificate authority to trust, in DER format
    #[structopt(parse(from_os_str), long = "ca")]
    ca: Option<PathBuf>,
}

const INITIAL_CAPACITY: usize = 256;
const MAX_LEN: usize = 256 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let options = Opt::from_args();

    let mut client = ClientBuilder::default();
    if let Some(ca_path) = options.ca {
        client.add_certificate_authority(quinn::Certificate::from_der(&fs::read(&ca_path)?)?)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                client.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }

    let (endpoint_driver, client) = client.build()?;
    tokio::spawn(async move {
        if let Err(e) = endpoint_driver.await {
            eprintln!("quic driver error: {}", e)
        }
    });

    match request(client, &options.url).await {
        Ok(_) => println!("client finished"),
        Err(e) => println!("client failed: {:?}", e),
    }

    Ok(())
}

async fn request(client: Client, url: &Url) -> Result<()> {
    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("couldn't resolve to an address"))?;
    let (quic_driver, h3_driver, conn) = client
        .connect(&remote, url.host_str().unwrap_or("localhost"))?
        .await
        .map_err(|e| anyhow!("failed ot connect: {:?}", e))?;

    tokio::spawn(async move {
        if let Err(e) = h3_driver.await {
            eprintln!("h3 client error: {}", e)
        }
    });

    tokio::spawn(async move {
        if let Err(e) = quic_driver.await {
            eprintln!("h3 client error: {}", e)
        }
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri(url.path())
        .header("client", "quinn-h3:0.0.1")
        .body(())
        .expect("failed to build request");

    let mut trailer = HeaderMap::with_capacity(2);
    trailer.append(
        "request",
        HeaderValue::from_str("trailer").expect("trailer value"),
    );

    let (response, body) = conn
        .request(request)
        .send()
        .await
        .expect("send request failed: {:?}")
        .into_parts();

    println!("received response: {:?}", response);

    let (content, trailers) = body
        .read_to_end(INITIAL_CAPACITY, MAX_LEN)
        .await
        .expect("read body");

    if let Some(content) = content {
        println!("received body: {}", String::from_utf8_lossy(&content));
    }
    if let Some(trailers) = trailers {
        println!("received trailers: {:?}", trailers);
    }
    conn.close();

    Ok(())
}
