use std::{cmp, fs, net::SocketAddr, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use http::{Response, StatusCode};
use structopt::{self, StructOpt};
use tracing::error;

use quinn_h3::{
    self,
    server::{Builder as ServerBuilder, Connecting, RecvRequest},
};

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_server")]
struct Opt {
    /// TLS private key in PEM format
    #[structopt(
        parse(from_os_str),
        short = "k",
        long = "key",
        requires = "cert",
        default_value = "key.der"
    )]
    key: PathBuf,
    /// TLS certificate in PEM format
    #[structopt(
        parse(from_os_str),
        short = "c",
        long = "cert",
        requires = "key",
        default_value = "cert.der"
    )]
    cert: PathBuf,
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

    let key = fs::read(opt.key).context("failed to read private key")?;
    let key = quinn::PrivateKey::from_der(&key[..])?;
    let cert_chain = fs::read(opt.cert).context("failed to read certificate chain")?;
    let cert_chain =
        quinn::CertificateChain::from_certs(vec![quinn::Certificate::from_der(&cert_chain)?]);

    let mut server = ServerBuilder::default();
    server
        .certificate(cert_chain, key)
        .expect("failed to add cert");

    let (_, mut incoming) = server.build().expect("bind failed");

    println!("server listening");
    while let Some(connecting) = incoming.next().await {
        tokio::spawn(async move {
            if let Err(e) = handle_connection(connecting).await {
                error!("handling connection failed: {:?}", e)
            }
        });
    }

    Ok(())
}

async fn handle_connection(connecting: Connecting) -> Result<()> {
    println!("server received connection");
    let mut incoming = connecting.await.context("accept failed")?;

    tokio::spawn(async move {
        while let Some(request) = incoming.next().await {
            tokio::spawn(async move {
                if let Err(e) = handle_request(request).await {
                    eprintln!("request error: {}", e)
                }
            });
        }
    });

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

    match request.uri().path() {
        "/" => home(sender).await?,
        x if !x.is_empty() => match parse_size(&x[1..]) {
            Ok(n) => payload(sender, n).await?,
            Err(_) => home(sender).await?,
        },
        _ => home(sender).await?,
    };

    Ok(())
}

async fn home(sender: quinn_h3::server::Sender) -> Result<()> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(HOME)
        .expect("failed to build response");
    sender
        .send_response(response)
        .await
        .map_err(|e| anyhow!("failed to send response: {:?}", e))?;
    Ok(())
}

async fn payload(sender: quinn_h3::server::Sender, len: usize) -> Result<()> {
    if len > 1_000_000_000 {
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Bytes::from(format!("requested {}: too large", len)))
            .expect("failed to build response");
        sender.send_response(response).await?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("failed to build response");

    let mut body_writer = sender
        .send_response(response)
        .await
        .map_err(|e| anyhow!("failed to send response: {:?}", e))?;

    let mut remaining = len;
    while remaining > 0 {
        let size = cmp::min(remaining, TEXT.len());
        body_writer.write_all(&TEXT[..size]).await?;
        remaining -= size;
    }
    body_writer.flush().await?;
    body_writer.close().await?;

    Ok(())
}

fn parse_size(literal: &str) -> Result<usize> {
    let pos = literal
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or_else(|| literal.len());
    let num: usize = literal[..pos]
        .parse()
        .map_err(|_| anyhow!("parse failed"))?;
    let scale = match literal[pos..].to_uppercase().as_str() {
        "K" => 1000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        _ => 1,
    };
    Ok(num * scale)
}

const TEXT: &[u8] =
    b"It would be different if we could not step back and reflect on the process,\n\
    but were merely led from impulse to impulse without self- consciousness. But human\n\
    beings do not act solely on impulse. They are prudent, they reflect, they weigh\n\
    consequences, they ask whether what they are doing is worth while. Not only are their\n\
    lives full of particular choices that hang together in larger activities with temporal\n\
    structure: they also decide in the broadest terms what to pursue and what to avoid, what\n\
    the priorities among their various aims should be, and what kind of people they want to\n\
    be or become. Some men are faced with such choices by the large decisions they make from\n\
    time to time; some merely by reflection on the course their lives are taking as the product\n\
    of countless small decisions. They decide whom to marry, what profession to follow, whether\n\
    to join the Country Club, or the Resistance; or they may just wonder why they go on being\n\
    salesmen or academics or taxi drivers, and then stop thinking about it after a certain period\n\
    of inconclusive reflection.";

const HOME: &str = r##"
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
    <title>Quinn H3 interop server</title>
  </head>
  <body>
    <h1>Welcome to the quinn-h3 interop server.</h1>
    <p>
      <strong>Draft version:</strong> draft-24<br/>
      <strong>Available tests:</strong> VHDCRZSBU3
    </p>
    <p>
      Use '/{n}' to get <i>n</i> bytes of deep thoughts.<br/>
      For example <a href="/1000000">/1000000</a>
      to get 1MB. Limit: 1GB
    </p>
    <p>Checkout our project's <a href="https://github.com/djc/quinn">repository</a>.</p>
    <p>Say hi on quickdev slack workspace at `quinn`.</p>
  </body>
</html>
"##;
