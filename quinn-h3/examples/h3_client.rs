use std::{fs, io, net::ToSocketAddrs, path::PathBuf};
use structopt::{self, StructOpt};

use anyhow::Result;
use http::{Request, Uri};
use tracing::{error, info};
use tracing_subscriber::filter::LevelFilter;

use quinn_h3::{client, Body};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_client")]
struct Opt {
    #[structopt(default_value = "http://localhost:4433/Cargo.toml")]
    uri: Uri,

    /// Custom certificate authority to trust, in DER format
    #[structopt(parse(from_os_str), long = "ca")]
    ca: Option<PathBuf>,
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
    let Opt { uri, ca } = Opt::from_args();
    let socket_addr = (uri.host().unwrap(), uri.port_u16().unwrap_or(443))
        .to_socket_addrs()?
        .next()
        .expect("socket addr");

    // Configure the client and build it
    let mut client_builder = client::Builder::default();
    if let Some(cert) = read_cert(&ca) {
        client_builder.add_certificate_authority(cert)?;
    }
    let mut client = client_builder.build()?;

    // Connect and wait for handshake completion
    let conn = client
        .connect(&socket_addr, uri.host().unwrap_or("localhost"))?
        .await?;

    let request = Request::get(uri)
        .header("client", "quinn-h3:0.0.1")
        .body(Body::from(()))?;

    // Send the request
    let (send_data, recv_response) = conn.send_request(request);
    send_data.await?;
    // Wait for the response
    let mut response = recv_response.await?;

    info!("received response: {:?}", response);

    // Stream the response body into a vec
    let body = response.body_mut().read_to_end().await?;
    info!("received body: {}", String::from_utf8_lossy(&body));

    // Get the trailers if any
    if let Some(trailers) = response.body_mut().trailers().await? {
        info!("received trailers: {:?}", trailers);
    }

    // Send a connection_close(NO_ERROR) to the server
    conn.close();
    // Make sure the server receives the closure frame
    client.wait_idle().await;

    Ok(())
}

fn read_cert(ca: &Option<PathBuf>) -> Option<quinn::Certificate> {
    if let Some(ca_path) = ca {
        return Some(quinn::Certificate::from_der(&fs::read(&ca_path).ok()?).ok()?);
    }

    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    match fs::read(dirs.data_local_dir().join("cert.der")) {
        Ok(cert) => return Some(quinn::Certificate::from_der(&cert).ok()?),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("local server certificate not found");
        }
        Err(e) => {
            error!("failed to open local server certificate: {}", e);
        }
    }
    None
}
