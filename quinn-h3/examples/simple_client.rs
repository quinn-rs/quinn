use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use structopt::{self, StructOpt};

use failure::{format_err, Error};
use http::{header::HeaderValue, method::Method, HeaderMap, Request};
use url::Url;

use quinn_h3::{self, client::Builder as ClientBuilder, client::Client};

mod shared;
use shared::{build_certs, logger};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_client")]
struct Opt {
    #[structopt(default_value = "http://127.0.0.1:4433/Cargo.toml")]
    url: Url,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
}

const INITIAL_CAPACITY: usize = 256;
const MAX_LEN: usize = 256 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let log = logger("h3".into());
    let certs = build_certs(log.clone(), &opt.key, &opt.cert).expect("failed to build certs");

    let remote = (opt.url.host_str().unwrap(), opt.url.port().unwrap_or(4433))
        .to_socket_addrs()
        .expect("invalid address")
        .next()
        .expect("couldn't resolve to an address");

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    endpoint.logger(log.clone());

    client_config.protocols(&[quinn_h3::ALPN]);
    client_config
        .add_certificate_authority(certs.1)
        .expect("failed to ad cert");
    endpoint.default_client_config(client_config.build());

    let (endpoint_driver, endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;
    tokio::spawn(async move {
        if let Err(e) = endpoint_driver.await {
            eprintln!("quic client error: {}", e)
        }
    });

    match request(ClientBuilder::new().endpoint(endpoint), &remote).await {
        Ok(_) => println!("client finished"),
        Err(e) => println!("client failed: {:?}", e),
    }

    Ok(())
}

async fn request(client: Client, remote: &SocketAddr) -> Result<(), Error> {
    let (quic_driver, h3_driver, conn) = client
        .connect(&remote, "localhost")?
        .await
        .map_err(|e| format_err!("failed ot connect: {:?}", e))?;

    tokio::spawn(async move {
        if let Err(e) = h3_driver.await {
            eprintln!("h3 client error: {}", e)
        }
    });

    tokio::spawn(async move {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/hello")
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
    });

    if let Err(e) = quic_driver.await {
        eprintln!("h3 client error: {}", e)
    }

    Ok(())
}
