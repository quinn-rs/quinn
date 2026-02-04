//! Example that compares congestion control algorithms by sending data from client to server
//! in the same process for 5 seconds and measuring throughput, loss ratio, and delay.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::Parser;
use proto::{TransportConfig, congestion};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{net::UdpSocket, sync::oneshot, time::sleep};
use tracing::{error, info};

#[derive(Debug, Clone)]
struct Scenario {
    cc: String,
    proxy: bool,
    ecn: bool,
    delay_ms: u64,
    loss_percent: u8,
}

#[derive(Debug)]
struct ScenarioResult {
    scenario: Scenario,
    data_transferred: u64,
    loss_ratio: f64,
    rtt: Duration,
    transfer_duration: Duration,
}

#[derive(Parser, Debug)]
#[clap(name = "congestion_comparison")]
struct Opt {
    /// Run demo with multiple scenarios
    #[clap(long)]
    demo: bool,
    /// Congestion control algorithm: cubic or quicdc (for single run)
    #[clap(long = "cc", default_value = "cubic")]
    congestion_control: String,
    /// Enable UDP proxy to simulate network conditions (for single run)
    #[clap(long)]
    proxy: bool,
    /// Delay in milliseconds for proxy to forward packets (for single run)
    #[clap(long, default_value = "1")]
    delay_ms: u64,
    /// Packet loss percentage for proxy (0-100) (for single run)
    #[clap(long, default_value = "0")]
    loss_percent: u8,
    /// Enable ECN-capable proxy (for single run)
    #[clap(long)]
    ecn: bool,
}

async fn run_proxy(
    server_addr: SocketAddr,
    delay: Duration,
    loss_percent: u8,
    ecn: bool,
) -> Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let proxy_addr = socket.local_addr()?;
    if ecn {
        println!("Proxy listening on {} (ECN simulated)", proxy_addr);
    } else {
        println!("Proxy listening on {}", proxy_addr);
    }

    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut client_addr: Option<SocketAddr> = None;

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let packet = &buf[..len];

                    let dst = if Some(src) == client_addr {
                        server_addr
                    } else {
                        if client_addr.is_none() {
                            client_addr = Some(src);
                        }
                        client_addr.unwrap()
                    };

                    if loss_percent > 0 {
                        let mut rng = rand::rng();
                        if rng.random_range(0..100) < loss_percent {
                            continue;
                        }
                    }

                    if !delay.is_zero() {
                        sleep(delay).await;
                    }

                    if let Err(e) = socket.send_to(packet, dst).await {
                        eprintln!("Proxy send error: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Proxy recv error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(proxy_addr)
}

async fn run_scenario(scenario: &Scenario) -> Result<ScenarioResult> {
    let congestion_factory: Arc<dyn congestion::ControllerFactory + Send + Sync> =
        match scenario.cc.as_str() {
            "cubic" => Arc::new(congestion::CubicConfig::default()),
            "quicdc" => Arc::new(congestion::QuicDcConfig::default()),
            _ => panic!("Unknown cc"),
        };

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));

    let server_port = if scenario.proxy { 9998 } else { 9999 };
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();

    let (tx, rx) = oneshot::channel::<(u64, f64, Duration, Duration, Duration)>();

    // Spawn server
    let server_handle = {
        let mut transport_config = TransportConfig::default();
        transport_config.congestion_controller_factory(congestion_factory.clone());
        let transport_config = Arc::new(transport_config);
        let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], priv_key)?;
        server_config.transport_config(transport_config);
        let server_endpoint = Endpoint::server(server_config, server_addr)?;

        tokio::spawn(async move {
            let conn = server_endpoint.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = conn.accept_bi().await.unwrap();
            let received = match recv.read_to_end(usize::MAX).await {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Server read error: {}", e);
                    return;
                }
            };

            // Generate expected data
            let mut rng = StdRng::from_seed([123u8; 32]);
            let mut expected = vec![0u8; received.len()];
            rng.fill_bytes(&mut expected);

            if received == expected {
                println!("Server: data matches");
            } else {
                println!("Server: data mismatch");
            }

            let total_bytes = received.len() as u64;

            let stats = conn.stats();
            let loss_ratio = if stats.path.sent_packets > 0 {
                stats.path.lost_packets as f64 / stats.path.sent_packets as f64
            } else {
                0.0
            };

            let controller = conn.congestion_state();
            let metrics = controller.metrics();
            let queuing_delay = if let Some(min_rtt) = metrics.min_rtt {
                stats.path.rtt.saturating_sub(min_rtt)
            } else {
                Duration::ZERO
            };

            // For now, transfer_duration is not measured on server, set to ZERO
            let transfer_duration = Duration::ZERO;

            let _ = tx.send((
                total_bytes,
                loss_ratio,
                stats.path.rtt,
                queuing_delay,
                transfer_duration,
            ));
        })
    };

    // Run proxy if needed
    let client_target_addr = if scenario.proxy {
        run_proxy(
            server_addr,
            Duration::from_millis(scenario.delay_ms),
            scenario.loss_percent,
            scenario.ecn,
        )
        .await?
    } else {
        server_addr
    };

    // Client
    let mut transport_config = TransportConfig::default();
    transport_config.congestion_controller_factory(congestion_factory);
    let transport_config = Arc::new(transport_config);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))?;
    client_config.transport_config(transport_config);
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    client_endpoint.set_default_client_config(client_config);

    let conn = client_endpoint
        .connect(client_target_addr, "localhost")?
        .await?;
    let (mut send, _recv) = conn.open_bi().await?;
    let mut rng = StdRng::from_seed([123u8; 32]);
    let mut data = vec![0u8; 1024 * 1024]; // 1MB
    rng.fill_bytes(&mut data);
    let transfer_start = Instant::now();
    send.write_all(&data).await?;
    let transfer_duration = transfer_start.elapsed();
    send.finish()?;

    // Wait for result
    let (data_transferred, loss_ratio, rtt, _queuing_delay, transfer_duration) = rx.await?;

    // Clean up
    client_endpoint.wait_idle().await;
    server_handle.await?;

    Ok(ScenarioResult {
        scenario: scenario.clone(),
        data_transferred,
        loss_ratio,
        rtt,
        transfer_duration,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let opt = Opt::parse();

    if opt.demo {
        let scenarios = vec![
            Scenario {
                cc: "cubic".to_string(),
                proxy: false,
                ecn: false,
                delay_ms: 0,
                loss_percent: 0,
            },
            Scenario {
                cc: "quicdc".to_string(),
                proxy: false,
                ecn: false,
                delay_ms: 0,
                loss_percent: 0,
            },
            Scenario {
                cc: "cubic".to_string(),
                proxy: true,
                ecn: false,
                delay_ms: 1,
                loss_percent: 0,
            },
            Scenario {
                cc: "quicdc".to_string(),
                proxy: true,
                ecn: false,
                delay_ms: 1,
                loss_percent: 0,
            },
            Scenario {
                cc: "cubic".to_string(),
                proxy: true,
                ecn: true,
                delay_ms: 1,
                loss_percent: 0,
            },
            Scenario {
                cc: "quicdc".to_string(),
                proxy: true,
                ecn: true,
                delay_ms: 1,
                loss_percent: 0,
            },
        ];

        let mut results = Vec::new();
        for scenario in &scenarios {
            println!("Running scenario: {:?}", scenario);
            match run_scenario(scenario).await {
                Ok(result) => results.push(result),
                Err(e) => eprintln!("Error in scenario {:?}: {}", scenario, e),
            }
            tokio::time::sleep(Duration::from_millis(500)).await; // Wait for ports to be released
        }

        // Print preformatted table
        println!("\nResults Table:");
        #[rustfmt::skip]
        println!("| CC     | Proxy | ECN | Delay | Loss | Data Transferred | Loss Ratio | RTT       | Transfer Duration |");
        #[rustfmt::skip]
        println!("|--------|-------|-----|-------|------|------------------|------------|-----------|-------------------|");
        for result in &results {
            let proxy_type = if result.scenario.proxy {
                if result.scenario.ecn { "ECN" } else { "Basic" }
            } else {
                "None"
            };
            println!(
                "| {:<6} | {:<5} | {:<3} | {:<5} | {:<4} | {:<16} | {:<10.4} | {:<9} | {:<17} |",
                result.scenario.cc,
                proxy_type,
                if result.scenario.ecn { "Yes" } else { "No" },
                result.scenario.delay_ms,
                result.scenario.loss_percent,
                result.data_transferred,
                result.loss_ratio,
                format!("{:.2}ms", result.rtt.as_secs_f64() * 1000.0),
                format!("{:.2}ms", result.transfer_duration.as_secs_f64() * 1000.0),
            );
        }
    } else {
        // Single run
        let scenario = Scenario {
            cc: opt.congestion_control,
            proxy: opt.proxy,
            ecn: opt.ecn,
            delay_ms: opt.delay_ms,
            loss_percent: opt.loss_percent,
        };
        let result = run_scenario(&scenario).await?;
        println!("Results:");
        println!("  Data transferred: {} bytes", result.data_transferred);
        println!("  Loss ratio: {:.4}", result.loss_ratio);
        println!("  Average RTT: {:?}", result.rtt);
        println!("  Transfer duration: {:?}", result.transfer_duration);
    }

    Ok(())
}
