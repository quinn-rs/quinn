use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::StreamExt;
use hdrhistogram::Histogram;
use structopt::StructOpt;
use tokio::runtime::{Builder, Runtime};
use tracing::{info, trace};

fn main() {
    let opt = Opt::from_args();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = quinn::PrivateKey::from_der(&cert.serialize_private_key_der()).unwrap();
    let cert = quinn::Certificate::from_der(&cert.serialize_der().unwrap()).unwrap();

    let mut server_config = quinn::ServerConfigBuilder::default();
    server_config
        .certificate(quinn::CertificateChain::from_certs(vec![cert.clone()]), key)
        .unwrap();

    let mut server_config = server_config.build();
    server_config.transport = Arc::new(transport_config());

    let mut endpoint = quinn::EndpointBuilder::default();
    endpoint.listen(server_config);
    let mut runtime = rt();
    let (endpoint, incoming) = runtime.enter(|| {
        endpoint
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .unwrap()
    });
    let server_addr = endpoint.local_addr().unwrap();
    drop(endpoint); // Ensure server shuts down when finished
    let thread = std::thread::spawn(move || {
        if let Err(e) = runtime.block_on(server(incoming, opt)) {
            eprintln!("server failed: {:#}", e);
        }
    });

    let mut runtime = rt();
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

        let _: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            while stream.read_unordered().await?.is_some() {}

            Ok(())
        });
    }

    if opt.stats {
        println!("\nServer connection stats:\n{:#?}", connection.stats());
    }

    result
}

async fn client(server_addr: SocketAddr, server_cert: quinn::Certificate, opt: Opt) -> Result<()> {
    let (endpoint, _) = quinn::EndpointBuilder::default()
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config
        .add_certificate_authority(server_cert)
        .unwrap();
    let mut client_config = client_config.build();
    client_config.transport = Arc::new(transport_config());

    let quinn::NewConnection { connection, .. } = endpoint
        .connect_with(client_config, &server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;
    trace!("connected");

    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut ops = futures::stream::iter((0..opt.streams).map(|_| {
        let connection = connection.clone();
        async move { send_data_on_stream(connection, opt.stream_size_mb).await }
    }))
    .buffer_unordered(opt.max_streams);

    let mut total_size = 0;
    let mut duration_hist = Histogram::<u64>::new(3).unwrap();
    let mut throughput_hist = Histogram::<u64>::new(3).unwrap();

    let mut result = Ok(());

    while let Some(stream_result) = ops.next().await {
        info!("stream finished: {:?}", stream_result);
        match stream_result {
            Ok(stream_result) => {
                total_size += stream_result.size;

                duration_hist
                    .record(stream_result.duration.as_millis() as u64)
                    .unwrap();
                throughput_hist
                    .record(stream_result.throughput as u64)
                    .unwrap();
            }
            Err(e) => {
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
    }

    let dt = start.elapsed();
    println!("Overall stats:\n");
    println!(
        "Sent {} bytes on {} streams in {:4.2?} ({:.2} MiB/s)\n",
        total_size,
        opt.streams,
        dt,
        throughput_bps(dt, total_size as u64) / 1024.0 / 1024.0
    );

    println!("Stream metrics:\n");

    println!("      │  Throughput   │ Duration ");
    println!("──────┼───────────────┼──────────");

    let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
        println!(
            " {} │ {:7.2} MiB/s │ {:>9}",
            label,
            get_metric(&throughput_hist) as f64 / 1024.0 / 1024.0,
            format!("{:.2?}", Duration::from_millis(get_metric(&duration_hist)))
        );
    };

    print_metric("AVG ", |hist| hist.mean() as u64);
    print_metric("P0  ", |hist| hist.value_at_quantile(0.00));
    print_metric("P10 ", |hist| hist.value_at_quantile(0.10));
    print_metric("P50 ", |hist| hist.value_at_quantile(0.50));
    print_metric("P90 ", |hist| hist.value_at_quantile(0.90));
    print_metric("P100", |hist| hist.value_at_quantile(1.00));

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
) -> Result<SendResult> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];

    let start = Instant::now();

    let mut stream = connection
        .open_uni()
        .await
        .context("failed to open stream")?;

    for _ in 0..stream_size_mb {
        stream
            .write_all(DATA)
            .await
            .context("failed sending data")?;
    }

    stream.finish().await.context("failed finishing stream")?;

    let duration = start.elapsed();
    let size = DATA.len() * stream_size_mb;
    let throughput = throughput_bps(duration, size as u64);

    Ok(SendResult {
        duration,
        size,
        throughput,
    })
}

#[derive(Debug)]
struct SendResult {
    duration: Duration,
    size: usize,
    throughput: f64,
}

fn throughput_bps(duration: Duration, size: u64) -> f64 {
    (size as f64) / (duration.as_secs_f64())
}

fn rt() -> Runtime {
    Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap()
}

fn transport_config() -> quinn::TransportConfig {
    // High stream windows are chosen because the amount of concurrent streams
    // is configurable as a parameter.
    let mut config = quinn::TransportConfig::default();
    config.stream_window_uni(1024).unwrap();
    config
}

#[derive(StructOpt, Debug, Clone, Copy)]
#[structopt(name = "bulk")]
struct Opt {
    /// The total number of streams which should be created
    #[structopt(long = "streams", short = "n", default_value = "1")]
    streams: usize,
    /// The amount of concurrent streams which should be used
    #[structopt(long = "max_streams", short = "m", default_value = "1")]
    max_streams: usize,
    /// The amount of data to transfer on a stream in megabytes
    #[structopt(long = "stream_size", default_value = "1024")]
    stream_size_mb: usize,
    /// Show connection stats the at the end of the benchmark
    #[structopt(long = "stats")]
    stats: bool,
}
