use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use structopt::StructOpt;
use tracing::{info, trace};

use bench::{
    configure_tracing_subscriber, connect_client, drain_stream, rt, server_endpoint,
    stats::{throughput_bps, Stats, TransferResult},
    Opt,
};

fn main() {
    let opt = Opt::from_args();
    configure_tracing_subscriber();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();

    let runtime = rt();
    let (server_addr, incoming) = server_endpoint(&runtime, cert.clone(), key, &opt);

    let thread = std::thread::spawn(move || {
        if let Err(e) = runtime.block_on(server(incoming, opt)) {
            eprintln!("server failed: {:#}", e);
        }
    });

    let runtime = rt();
    if let Err(e) = runtime.block_on(client(server_addr, cert, opt)) {
        eprintln!("client failed: {:#}", e);
    }

    thread.join().expect("server thread");
}

async fn server(mut incoming: quinn::Incoming, opt: Opt) -> Result<()> {
    let handshake = incoming.next().await.unwrap();
    let quinn::NewConnection {
        mut uni_streams,
        connection,
        ..
    } = handshake.await.context("handshake failed")?;

    let mut result = Ok(());

    loop {
        let mut stream = match uni_streams.next().await {
            None => break,
            Some(Err(quinn::ConnectionError::ApplicationClosed(_))) => break,
            Some(Err(e)) => {
                result = Err(e).context("accepting stream failed");
                break;
            }
            Some(Ok(stream)) => stream,
        };
        trace!("stream established");

        let _: tokio::task::JoinHandle<Result<usize>> =
            tokio::spawn(async move { drain_stream(&mut stream, opt.read_unordered).await });
    }

    if opt.stats {
        println!("\nServer connection stats:\n{:#?}", connection.stats());
    }

    result
}

async fn client(server_addr: SocketAddr, server_cert: quinn::Certificate, opt: Opt) -> Result<()> {
    let (endpoint, connection) = connect_client(server_addr, server_cert, opt).await?;

    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut ops = futures_util::stream::iter((0..opt.streams).map(|_| {
        let connection = connection.clone();
        async move { send_data_on_stream(connection, opt.stream_size_mb).await }
    }))
    .buffer_unordered(opt.max_streams);

    let mut stats = Stats::default();

    let mut result = Ok(());

    while let Some(stream_result) = ops.next().await {
        info!("stream finished: {:?}", stream_result);
        match stream_result {
            Ok(stream_result) => {
                stats.stream_finished(stream_result);
            }
            Err(e) => {
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
    }

    stats.total_duration = start.elapsed();
    stats.print("upload");

    // Explicit close of the connection, since handles can still be around due
    // to `Arc`ing them
    connection.close(0u32.into(), b"Benchmark done");

    endpoint.wait_idle().await;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    result
}

async fn send_data_on_stream(
    connection: Arc<quinn::Connection>,
    stream_size_mb: usize,
) -> Result<TransferResult> {
    let start = Instant::now();

    let mut stream = connection
        .open_uni()
        .await
        .context("failed to open stream")?;

    bench::send_data_on_stream(&mut stream, stream_size_mb).await?;

    let duration = start.elapsed();
    let size = 1024 * 1024 * stream_size_mb;
    let throughput = throughput_bps(duration, size as u64);

    Ok(TransferResult {
        duration,
        size,
        throughput,
    })
}
