use std::{
    ascii, cmp, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str,
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt, TryFutureExt};
use http::{Response, StatusCode};
use structopt::{self, StructOpt};
use tracing::{error, info, info_span};
use tracing_futures::Instrument as _;

use quinn::SendStream;
use quinn_h3::{self, server::RecvRequest};

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

    let mut server_config = quinn::ServerConfigBuilder::default();
    server_config.certificate(cert_chain, key)?;
    server_config.protocols(&[quinn_h3::ALPN, b"hq-27"]);

    let main = server(server_config.clone(), 4433);
    let other = server(server_config.clone(), 443);

    server_config.use_stateless_retry(true);
    let retry = server(server_config.clone(), 4434);

    tokio::try_join!(main, other, retry)?;

    Ok(())
}

async fn server(server_config: quinn::ServerConfigBuilder, port: u16) -> Result<()> {
    let mut endpoint_builder = quinn::Endpoint::builder();
    endpoint_builder.listen(server_config.build());
    let (_, mut incoming) =
        endpoint_builder.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))?;

    println!("server listening on {}", port);
    while let Some(connecting) = incoming.next().await {
        tokio::spawn(async move {
            let protos = connecting.authentication_data().protocol.unwrap();
            println!("server received connection");

            if protos == b"h3-27" {
                if let Err(e) = h3_handle_connection(connecting).await {
                    error!("handling connection failed: {:?}", e)
                }
            } else if protos == b"hq-27" {
                if let Err(e) = hq_handle_connection(connecting).await {
                    error!("handling connection failed: {:?}", e)
                }
            }
        });
    }
    Ok(())
}

async fn h3_handle_connection(connecting: quinn::Connecting) -> Result<()> {
    let connecting = quinn_h3::server::Connecting::from(connecting);
    let mut incoming = connecting.await.context("accept failed")?;
    tokio::spawn(async move {
        while let Some(request) = incoming.next().await {
            tokio::spawn(async move {
                if let Err(e) = h3_handle_request(request).await {
                    eprintln!("request error: {}", e)
                }
            });
        }
    });

    Ok(())
}

async fn h3_handle_request(recv_request: RecvRequest) -> Result<()> {
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
        "/" => h3_home(sender).await?,
        path => match parse_size(path) {
            Ok(n) => h3_payload(sender, n).await?,
            Err(_) => h3_home(sender).await?,
        },
    };

    Ok(())
}

async fn h3_home(sender: quinn_h3::server::Sender) -> Result<()> {
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

async fn h3_payload(sender: quinn_h3::server::Sender, len: usize) -> Result<()> {
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

async fn hq_handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .authentication_data()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                hq_handle_request(stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string()))
                    .instrument(info_span!("request")),
            );
        }
        Ok(())
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn hq_handle_request((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!(content = %escaped);
    // Execute the request
    hq_process_get(send, &req).await?;
    Ok(())
}

async fn hq_process_get(mut send: SendStream, x: &[u8]) -> Result<()> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or_else(|| x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;

    // Write the response
    match parse_size(path) {
        Ok(n) if n <= 1_000_000_000 => {
            let mut remaining = n;
            while remaining > 0 {
                let size = cmp::min(remaining, TEXT.len());
                send.write_all(&TEXT[..size])
                    .await
                    .map_err(|e| anyhow!("failed to send response: {}", e))?;
                remaining -= size;
            }
        }
        Ok(_) | Err(_) => {
            send.write_all(&HOME.as_bytes())
                .await
                .map_err(|e| anyhow!("failed to send response: {}", e))?;
        }
    }

    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;

    Ok(())
}

fn parse_size(literal: &str) -> Result<usize> {
    if literal.is_empty() {
        return Err(anyhow!("path empty"));
    }
    let pos = literal[1..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|p| p + 1)
        .unwrap_or_else(|| literal.len());
    let num: usize = literal[1..pos]
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
