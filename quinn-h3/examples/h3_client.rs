use std::{fs, io, net::ToSocketAddrs, path::PathBuf};
use structopt::{self, StructOpt};

use anyhow::{anyhow, Result};
use futures::AsyncReadExt;
use http::{Request, Uri};
use tracing::{error, info};

use quinn_h3::{
    self,
    client::{Builder as ClientBuilder, Client},
};

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

    let client = client.build()?;

    match request(client, &options.uri).await {
        Ok(_) => println!("client finished"),
        Err(e) => println!("client failed: {:?}", e),
    }

    Ok(())
}

async fn request(client: Client, uri: &Uri) -> Result<()> {
    let remote = (uri.host().unwrap(), uri.port_u16().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let conn = client
        .connect(&remote, uri.host().unwrap_or("localhost"))?
        .await
        .map_err(|e| anyhow!("failed ot connect: {:?}", e))?;

    let request = Request::get(uri)
        .header("client", "quinn-h3:0.0.1")
        .body(())
        .expect("failed to build request");

    let (recv_response, _) = conn.send_request(request).await?;
    let (response, mut recv_body) = recv_response.await?;

    println!("received response: {:?}", response);

    let mut body = Vec::with_capacity(1024);
    recv_body.read_to_end(&mut body).await?;

    println!("received body: {}", String::from_utf8_lossy(&body));

    if let Some(trailers) = recv_body.trailers().await {
        println!("received trailers: {:?}", trailers);
    }
    conn.close();

    Ok(())
}
