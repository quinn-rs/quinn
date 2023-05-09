use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{RecvStream, TokioRuntime};

use tracing::{debug, error, info};

use perf::{
    bind_socket, get_client_config, get_client_crypto, get_local_addr, get_transport_config,
    lookup_host,
};

/// Connects to a QUIC perf datagram server and maintains a specified pattern of requests until interrupted
#[derive(Parser)]
#[clap(name = "datagram_client")]
struct Opt {
    /// Host to connect to
    #[clap(default_value = "localhost:4433")]
    host: String,
    /// Override DNS resolution for host
    #[clap(long)]
    ip: Option<IpAddr>,
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
    /// Specify the local socket address
    #[clap(long)]
    local_addr: Option<SocketAddr>,
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
    let (host_name, addr) = lookup_host(&opt.host, opt.ip).await?;
    info!("connecting to {} at {}", host_name, addr);

    let bind_addr = get_local_addr(addr, opt.local_addr);
    info!("local addr {:?}", bind_addr);

    let socket = bind_socket(bind_addr, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime))?;

    let crypto = get_client_crypto(opt.keylog)?;
    let mut transport = get_transport_config(opt.initial_mtu);

    transport.datagram_send_buffer_size(1024 * 1024 * 100);

    let cfg = get_client_config(transport, crypto, opt.no_protection);

    let connection = endpoint
        .connect_with(cfg, addr, host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let data_len = 1024 * 1024 * 1024 * 2; // 2 GiB
    let data_len_buf = u64::to_le_bytes(data_len);

    let datagram_size = connection.max_datagram_size().unwrap();

    // The length of the data to send
    let (mut data_len_send, recv_done) = connection.open_bi().await?;
    data_len_send.write_all(&data_len_buf).await?;

    let start = Instant::now();

    let total_received_by_server = if opt.use_stream {
        send_stream(&connection, data_len as usize).await?;
        receive_total_bytes_read(recv_done).await?
    } else {
        tokio::select! {
            Ok(()) = send_datagrams(&connection, datagram_size) => {
                unreachable!("send_datagrams never stops by itself")
            }
            Ok(total_received) = receive_total_bytes_read(recv_done) => {
                total_received
            }
        }
    };

    assert!(total_received_by_server >= data_len);

    let finish = Instant::now();
    let diff = finish - start;

    println!(
        "Transferred {total_received_by_server} bytes in {} ms ({:.2} MiB/s)",
        diff.as_millis(),
        total_received_by_server as f64 / 1024.0 / 1024.0 / diff.as_secs_f64()
    );

    let bytes_lost = if opt.use_stream {
        connection.stats().path.lost_bytes
    } else {
        let total_sent = connection.stats().frame_tx.datagram * datagram_size as u64;
        total_sent - total_received_by_server
    };

    println!(
        "Bytes lost {bytes_lost} ({:.2} MiB)",
        bytes_lost as f64 / 1024.0 / 1024.0
    );

    println!(
        "Congestion events: {}",
        connection.stats().path.congestion_events
    );
    println!("Congestion window: {}", connection.stats().path.cwnd);

    endpoint.wait_idle().await;

    Ok(())
}

async fn send_stream(connection: &quinn::Connection, data_len: usize) -> Result<()> {
    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];

    let mut send = connection.open_uni().await?;
    let mut upload = data_len;

    while upload > 0 {
        let chunk_len = upload.min(DATA.len());
        send.write_chunk(Bytes::from_static(&DATA[..chunk_len]))
            .await
            .context("sending stream chunk")?;
        upload -= chunk_len;
    }

    send.finish().await?;

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn send_datagrams(connection: &quinn::Connection, datagram_size: usize) -> Result<()> {
    // Since all datagrams contain the same data, they can all use the same shared buffer
    let data = Bytes::from(vec![42; datagram_size]);
    let total_buffer_space = connection.datagram_send_buffer_space();
    let mut first_iteration = true;

    loop {
        // Make sure the outgoing datagram buffer is always full, so we are sending at the maximum
        // possible rate allowed by congestion control
        let buffer_space = connection.datagram_send_buffer_space();
        if !first_iteration && buffer_space == total_buffer_space {
            anyhow::bail!("No datagrams were pending! Increase datagram send buffer space so the connection is always busy");
        }

        if first_iteration {
            first_iteration = false;
        }

        let mut sent = 0;
        while sent + datagram_size <= buffer_space {
            sent += datagram_size;
            connection
                .send_datagram(data.clone())
                .context("send_datagram")?;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn receive_total_bytes_read(mut recv: RecvStream) -> Result<u64> {
    let mut buf = [0; 8];
    recv.read_exact(&mut buf)
        .await
        .context("receive_total_bytes_read")?;
    Ok(u64::from_le_bytes(buf))
}
