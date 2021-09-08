mod bulk_stream;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use hdrhistogram::Histogram;
use structopt::StructOpt;
use tokio::runtime::{Builder, Runtime};
use tracing::{info, trace};

fn main() {
    let opt = Opt::from_args();
    let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel();

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
    server_config.transport = Arc::new(transport_config(&opt));

    let mut endpoint = quinn::EndpointBuilder::default();
    endpoint.listen(server_config);
    let runtime = rt();
    let (endpoint, incoming) = {
        let _guard = runtime.enter();
        endpoint
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .unwrap()
    };
    let server_addr = endpoint.local_addr().unwrap();
    drop(endpoint); // Ensure server shuts down when finished
    let thread = std::thread::spawn(move || {
        if let Err(e) = runtime.block_on(server(incoming, opt, server_done_tx)) {
            eprintln!("server failed: {:#}", e);
        }
    });

    let runtime = rt();
    if let Err(e) = runtime.block_on(client(server_addr, cert, opt, server_done_rx)) {
        eprintln!("client failed: {:#}", e);
    }

    thread.join().expect("server thread");
}

async fn server(
    mut incoming: quinn::Incoming,
    opt: Opt,
    server_done_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let handshake = incoming.next().await.unwrap();
    let quinn::NewConnection {
        mut datagrams,
        connection,
        ..
    } = handshake.await.context("handshake failed")?;

    let mut count = 0;

    while let Some(res) = datagrams.next().await {
        //println!("SERVER RECV {}", count);
        let _ = res?;
        count += 1;
        if count == opt.num_packets - 1 {
            server_done_tx.send(()).unwrap();
            break;
        }
    }

    if opt.stats {
        println!("\nServer connection stats:\n{:#?}", connection.stats());
    }

    Ok(())
}

async fn client(
    server_addr: SocketAddr,
    server_cert: quinn::Certificate,
    opt: Opt,
    server_done_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    let (endpoint, _) = quinn::EndpointBuilder::default()
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .unwrap();

    let mut config = quinn::ClientConfig::default();
    let crypto_config = Arc::get_mut(&mut config.crypto).unwrap();

    crypto_config.ciphersuites.clear();
    crypto_config.ciphersuites.push(opt.cipher.as_rustls());

    let mut client_config = quinn::ClientConfigBuilder::new(config);
    client_config
        .add_certificate_authority(server_cert)
        .unwrap();
    let mut client_config = client_config.build();
    client_config.transport = Arc::new(transport_config(&opt));

    let quinn::NewConnection { connection, .. } = endpoint
        .connect_with(client_config, &server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;
    trace!("connected");

    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut total_size = 0;
    let mut duration_hist = Histogram::<u64>::new(3).unwrap();
    let mut throughput_hist = Histogram::<u64>::new(3).unwrap();

    let mut result = Ok(());

    let stream_result =
        send_data_on_stream(connection.clone(), opt.num_packets, server_done_rx).await;
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
            println!("Client ERR: {:?}", e.to_string());
            if result.is_ok() {
                result = Err(e);
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
    //connection.close(0u32.into(), b"Benchmark done");

    //endpoint.wait_idle().await;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    result
}

async fn send_data_on_stream(
    connection: Arc<quinn::Connection>,
    num_packets: usize,
    server_done_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<SendResult> {
    const DATA: &[u8] = &[0xAB; 256];
    let bytes_data = Bytes::from_static(DATA);

    let start = Instant::now();

    for _ in 0..num_packets {
        connection
            .send_datagram(bytes_data.clone())
            .context("failed sending data")?;
    }

    println!("Client awaiting server packet ...");
    server_done_rx.await?;

    let duration = start.elapsed();
    let size = DATA.len() * num_packets;
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
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn transport_config(opt: &Opt) -> quinn::TransportConfig {
    // High stream windows are chosen because the amount of concurrent streams
    // is configurable as a parameter.
    let mut config = quinn::TransportConfig::default();

    config
        .max_concurrent_uni_streams(opt.max_streams as u64)
        .unwrap()
        .datagram_receive_buffer_size(Some(1024 * 1024 * 10))
        .datagram_send_buffer_size(1024 * 1024 * 10)
        .crypto_buffer_size(1024 * 1024 * 10);

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
    #[structopt(long = "num_packets", short = "p", default_value = "4096")]
    num_packets: usize,
    /// Show connection stats the at the end of the benchmark
    #[structopt(long = "stats")]
    stats: bool,
    /// Whether to use the unordered read API
    #[structopt(long = "unordered")]
    read_unordered: bool,
    /// Allows to configure the desired cipher suite
    ///
    /// Valid options are: aes128, aes256, chacha20
    #[structopt(long = "cipher", default_value = "aes128")]
    cipher: CipherSuite,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CipherSuite {
    Aes128,
    Aes256,
    Chacha20,
}

impl CipherSuite {
    fn as_rustls(self) -> &'static rustls::SupportedCipherSuite {
        match self {
            CipherSuite::Aes128 => &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::Aes256 => &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::Chacha20 => &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
        }
    }
}

impl FromStr for CipherSuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes128" => Ok(CipherSuite::Aes128),
            "aes256" => Ok(CipherSuite::Aes256),
            "chacha20" => Ok(CipherSuite::Chacha20),
            _ => Err(anyhow::anyhow!("Unknown cipher suite {}", s)),
        }
    }
}
