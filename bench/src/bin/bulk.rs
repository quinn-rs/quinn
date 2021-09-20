use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use structopt::StructOpt;
use tracing::{info, trace};

use bench::{
    configure_tracing_subscriber, connect_client, drain_stream, rt, send_data_on_stream,
    server_endpoint,
    stats::{Stats, TransferResult},
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
        mut bi_streams,
        connection,
        ..
    } = handshake.await.context("handshake failed")?;

    let mut result = Ok(());

    loop {
        let (mut send_stream, mut recv_stream) = match bi_streams.next().await {
            None => break,
            Some(Err(quinn::ConnectionError::ApplicationClosed(_))) => break,
            Some(Err(e)) => {
                result = Err(e).context("accepting stream failed");
                break;
            }
            Some(Ok(stream)) => stream,
        };
        trace!("stream established");

        let _: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            drain_stream(&mut recv_stream, opt.read_unordered).await?;
            send_data_on_stream(&mut send_stream, opt.download_size).await?;
            Ok(())
        });
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

    let mut ops =
        futures_util::stream::iter(
            (0..opt.streams).map(|_| {
                let connection = connection.clone();
                async move {
                    handle_client_stream(connection, opt.upload_size, opt.read_unordered).await
                }
            }),
        )
        .buffer_unordered(opt.max_streams);

    let mut upload_stats = Stats::default();
    let mut download_stats = Stats::default();

    let mut result = Ok(());

    while let Some(stream_result) = ops.next().await {
        info!("stream finished: {:?}", stream_result);
        match stream_result {
            Ok((upload_result, download_result)) => {
                upload_stats.stream_finished(upload_result);
                download_stats.stream_finished(download_result);
            }
            Err(e) => {
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
    }

    upload_stats.total_duration = start.elapsed();
    download_stats.total_duration = start.elapsed();
    if upload_stats.total_size != 0 {
        upload_stats.print("upload");
    }
    if download_stats.total_size != 0 {
        download_stats.print("download");
    }

    // Explicit close of the connection, since handles can still be around due
    // to `Arc`ing them
    connection.close(0u32.into(), b"Benchmark done");

    endpoint.wait_idle().await;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    result
}

async fn handle_client_stream(
    connection: Arc<quinn::Connection>,
    upload_size: usize,
    read_unordered: bool,
) -> Result<(TransferResult, TransferResult)> {
    let start = Instant::now();

    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .context("failed to open stream")?;

    send_data_on_stream(&mut send_stream, upload_size).await?;

    let upload_result = TransferResult::new(start.elapsed(), upload_size);

    let start = Instant::now();
    let size = drain_stream(&mut recv_stream, read_unordered).await?;
    let download_result = TransferResult::new(start.elapsed(), size);

    Ok((upload_result, download_result))
}
