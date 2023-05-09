use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser;
use quinn::TokioRuntime;
use tracing::{debug, error, info};

use perf::{bind_socket, drain_stream, get_server_config, get_server_crypto, get_transport_config};

#[derive(Parser)]
#[clap(name = "datagram_server")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// TLS private key in DER format
    #[clap(parse(from_os_str), short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(parse(from_os_str), short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Send buffer size in bytes
    #[clap(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[clap(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Transfer the data using a stream instead of datagrams (useful to compare performance between
    /// the two)
    #[clap(long)]
    use_stream: bool,
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,
    /// UDP payload size that the network must be capable of carrying
    #[clap(long, default_value = "1200")]
    initial_mtu: u16,
    /// Disable packet encryption/decryption (for debugging purpose)
    #[clap(long = "no-protection")]
    no_protection: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let crypto = get_server_crypto(opt.key.as_deref(), opt.cert.as_deref(), opt.keylog)?;
    let mut transport_config = get_transport_config(opt.initial_mtu);
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024 * 10));
    let server_config = get_server_config(transport_config, crypto, opt.no_protection);
    let socket = bind_socket(opt.listen, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::Endpoint::new(
        Default::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )
    .context("creating endpoint")?;

    info!("listening on {}", endpoint.local_addr().unwrap());

    let use_stream = opt.use_stream;
    while let Some(handshake) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle(handshake, use_stream).await {
                error!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn handle(handshake: quinn::Connecting, use_stream: bool) -> Result<()> {
    let connection = handshake.await.context("handshake failed")?;
    debug!("{} connected", connection.remote_address());

    // The first 8 bytes represent the amount of data that we want to transfer
    let (mut send_stream, mut recv_stream) =
        connection.accept_bi().await.context("accept_bi failed")?;
    let mut buf = [0; 8];
    recv_stream
        .read_exact(&mut buf)
        .await
        .context("unable to read data length")?;
    let data_length = u64::from_le_bytes(buf);

    let received = if use_stream {
        // The data will be transferred in an unidirectional stream
        receive_stream(connection).await.context("receive_stream")?;
        data_length
    } else {
        // The data will be transferred in datagrams
        receive_datagrams(connection, data_length as usize)
            .await
            .context("receive_datagrams")?
    };

    // We are done! Now let the client know
    send_stream
        .write_all(&u64::to_le_bytes(received))
        .await
        .context("unable to write to signal we are done")?;
    send_stream.finish().await?;

    Ok(())
}

async fn receive_stream(connection: quinn::Connection) -> Result<()> {
    // No need to explicitly keep track of received bytes, because streams are reliable
    let stream = connection
        .accept_uni()
        .await
        .context("unable to receive data through stream")?;
    drain_stream(stream).await?;
    Ok(())
}

async fn receive_datagrams(connection: quinn::Connection, data_length: usize) -> Result<u64> {
    // Need to explicitly keep track of received bytes, because datagrams are unreliable
    let mut received = 0;
    while received < data_length {
        let datagram = connection
            .read_datagram()
            .await
            .context("unable to read datagram")?;
        received += datagram.len();
    }

    Ok(received as u64)
}
