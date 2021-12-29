use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use structopt::StructOpt;
use tokio::sync::Semaphore;
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
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());

    let runtime = rt();
    let (server_addr, incoming) = server_endpoint(&runtime, cert.clone(), key, &opt);

    let server_thread = std::thread::spawn(move || {
        if let Err(e) = runtime.block_on(server(incoming, opt)) {
            eprintln!("server failed: {:#}", e);
        }
    });

    let mut handles = Vec::new();
    for _ in 0..opt.clients {
        let cert = cert.clone();
        handles.push(std::thread::spawn(move || {
            let runtime = rt();
            match runtime.block_on(client(server_addr, cert, opt)) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    eprintln!("client failed: {:#}", e);
                    Err(e)
                }
            }
        }));
    }

    for (id, handle) in handles.into_iter().enumerate() {
        // We print all stats at the end of the test sequentially to avoid
        // them being garbled due to being printed concurrently
        if let Ok(stats) = handle.join().expect("client thread") {
            stats.print(id);
        }
    }

    server_thread.join().expect("server thread");
}

async fn server(mut incoming: quinn::Incoming, opt: Opt) -> Result<()> {
    let mut server_tasks = Vec::new();

    // Handle only the expected amount of clients
    for _ in 0..opt.clients {
        let handshake = incoming.next().await.unwrap();
        let quinn::NewConnection {
            mut bi_streams,
            connection,
            ..
        } = handshake.await.context("handshake failed")?;

        server_tasks.push(tokio::spawn(async move {
            loop {
                let (mut send_stream, mut recv_stream) = match bi_streams.next().await {
                    None => break,
                    Some(Err(quinn::ConnectionError::ApplicationClosed(_))) => break,
                    Some(Err(e)) => {
                        eprintln!("accepting stream failed: {:?}", e);
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
        }));
    }

    // Await all the tasks. We have to do this to prevent the runtime getting dropped
    // and all server tasks to be cancelled
    for handle in server_tasks {
        if let Err(e) = handle.await {
            eprintln!("Server task error: {:?}", e);
        };
    }

    Ok(())
}

async fn client(
    server_addr: SocketAddr,
    server_cert: rustls::Certificate,
    opt: Opt,
) -> Result<ClientStats> {
    let (endpoint, connection) = connect_client(server_addr, server_cert, opt).await?;

    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut stats = ClientStats::default();
    let mut first_error = None;

    let sem = Arc::new(Semaphore::new(opt.max_streams));
    let results = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..opt.streams {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let results = results.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let result =
                handle_client_stream(connection, opt.upload_size, opt.read_unordered).await;
            info!("stream finished: {:?}", result);
            results.lock().unwrap().push(result);
            drop(permit);
        });
    }

    // Wait for remaining streams to finish
    let _ = sem.acquire_many(opt.max_streams as u32).await.unwrap();

    for result in results.lock().unwrap().drain(..) {
        match result {
            Ok((upload_result, download_result)) => {
                stats.upload_stats.stream_finished(upload_result);
                stats.download_stats.stream_finished(download_result);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    stats.upload_stats.total_duration = start.elapsed();
    stats.download_stats.total_duration = start.elapsed();

    // Explicit close of the connection, since handles can still be around due
    // to `Arc`ing them
    connection.close(0u32.into(), b"Benchmark done");

    endpoint.wait_idle().await;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    match first_error {
        None => Ok(stats),
        Some(e) => Err(e),
    }
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

#[derive(Default)]
struct ClientStats {
    upload_stats: Stats,
    download_stats: Stats,
}

impl ClientStats {
    pub fn print(&self, client_id: usize) {
        println!();
        println!("Client {} stats:", client_id);

        if self.upload_stats.total_size != 0 {
            self.upload_stats.print("upload");
        }

        if self.download_stats.total_size != 0 {
            self.download_stats.print("download");
        }
    }
}
