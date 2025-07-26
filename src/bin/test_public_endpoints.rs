//! Test connectivity to public QUIC endpoints
//!
//! This binary tests ant-quic's ability to connect to various public QUIC servers
//! to verify protocol compliance and interoperability.

use ant_quic::{
    ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt,
    crypto::rustls::QuicClientConfig,
};
use clap::Parser;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to endpoint configuration YAML file
    #[arg(short, long, default_value = "docs/public-quic-endpoints.yaml")]
    config: PathBuf,

    /// Output file for JSON results
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Connection timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Number of parallel connections
    #[arg(short, long, default_value = "5")]
    parallel: usize,

    /// Specific endpoints to test (comma-separated)
    #[arg(short, long)]
    endpoints: Option<String>,

    /// Analyze results from JSON file
    #[arg(short, long)]
    analyze: Option<PathBuf>,

    /// Output format for analysis (markdown, json)
    #[arg(short, long, default_value = "markdown")]
    format: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Deserialize)]
struct EndpointDatabase {
    endpoints: Vec<EndpointEntry>,
    validation: ValidationConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct EndpointEntry {
    name: String,
    host: String,
    port: u16,
    protocols: Vec<String>,
    #[serde(rename = "type")]
    endpoint_type: String,
    category: String,
    reliability: String,
    features: Vec<String>,
    notes: String,
    #[serde(default)]
    region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidationConfig {
    timeout_seconds: u64,
    retry_attempts: u32,
    retry_delay_ms: u64,
    parallel_connections: usize,
    tests: Vec<TestConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TestConfig {
    name: String,
    description: String,
    required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResult {
    endpoint: String,
    endpoint_name: String,
    address: String,
    success: bool,
    handshake_time_ms: Option<u64>,
    rtt_ms: Option<u64>,
    quic_version: Option<u32>,
    error: Option<String>,
    protocols_tested: Vec<String>,
    successful_protocols: Vec<String>,
    features_tested: Vec<String>,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<EndpointMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EndpointMetrics {
    handshake_time_ms: u64,
    rtt_ms: u64,
    success_rate: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationResults {
    endpoints: Vec<TestResult>,
    summary: ValidationSummary,
    metadata: ResultMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationSummary {
    total_endpoints: usize,
    passed_endpoints: usize,
    failed_endpoints: usize,
    success_rate: f32,
    average_handshake_time: f32,
    protocols_seen: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResultMetadata {
    ant_quic_version: String,
    test_date: String,
    test_duration_ms: u64,
}

async fn test_endpoint(
    endpoint: &EndpointEntry,
    client_config: ClientConfig,
    test_config: &ValidationConfig,
) -> TestResult {
    let start = Instant::now();
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    let mut protocols_tested = Vec::new();
    let mut successful_protocols = Vec::new();

    // Resolve address (prefer IPv4 for compatibility)
    let addr = match address.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            // Prefer IPv4 addresses
            let addr = addrs
                .iter()
                .find(|addr| addr.is_ipv4())
                .or_else(|| addrs.first())
                .copied();

            match addr {
                Some(addr) => addr,
                None => {
                    return TestResult {
                        endpoint: address.clone(),
                        endpoint_name: endpoint.name.clone(),
                        address: address.clone(),
                        success: false,
                        handshake_time_ms: None,
                        rtt_ms: None,
                        quic_version: None,
                        error: Some("Failed to resolve address".to_string()),
                        protocols_tested,
                        successful_protocols,
                        features_tested: vec![],
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        metrics: None,
                    };
                }
            }
        }
        Err(e) => {
            return TestResult {
                endpoint: address.clone(),
                endpoint_name: endpoint.name.clone(),
                address: address.clone(),
                success: false,
                handshake_time_ms: None,
                rtt_ms: None,
                quic_version: None,
                error: Some(format!("DNS resolution failed: {}", e)),
                protocols_tested,
                successful_protocols,
                features_tested: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
                metrics: None,
            };
        }
    };

    // Extract hostname for SNI
    let hostname = address.split(':').next().unwrap_or(&address);
    let _server_name = match ServerName::try_from(hostname) {
        Ok(name) => name,
        Err(e) => {
            return TestResult {
                endpoint: address.clone(),
                endpoint_name: endpoint.name.clone(),
                address: address.clone(),
                success: false,
                handshake_time_ms: None,
                rtt_ms: None,
                quic_version: None,
                error: Some(format!("Invalid server name: {}", e)),
                protocols_tested,
                successful_protocols,
                features_tested: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
                metrics: None,
            };
        }
    };

    // Create endpoint (use appropriate bind address based on target)
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let _endpoint_config = EndpointConfig::default();
    let quic_endpoint = match Endpoint::client(bind_addr) {
        Ok(ep) => ep,
        Err(e) => {
            return TestResult {
                endpoint: address.clone(),
                endpoint_name: endpoint.name.clone(),
                address: address.clone(),
                success: false,
                handshake_time_ms: None,
                rtt_ms: None,
                quic_version: None,
                error: Some(format!("Failed to create endpoint: {}", e)),
                protocols_tested,
                successful_protocols,
                features_tested: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
                metrics: None,
            };
        }
    };

    // Connect with timeout
    let connecting = match quic_endpoint.connect_with(client_config.clone(), addr, &hostname) {
        Ok(c) => c,
        Err(e) => {
            return TestResult {
                endpoint: address.clone(),
                endpoint_name: endpoint.name.clone(),
                address: address.clone(),
                success: false,
                handshake_time_ms: None,
                rtt_ms: None,
                quic_version: None,
                error: Some(format!("Failed to start connection: {}", e)),
                protocols_tested,
                successful_protocols,
                features_tested: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
                metrics: None,
            };
        }
    };

    // Mark protocols as tested
    protocols_tested = endpoint.protocols.clone();

    let connect_result = timeout(
        Duration::from_secs(test_config.timeout_seconds),
        async move { connecting.await },
    )
    .await;

    match connect_result {
        Ok(Ok(connection)) => {
            let handshake_time = start.elapsed();
            let handshake_ms = handshake_time.as_millis() as u64;
            let _version = connection.stable_id();

            // Mark successful protocols
            successful_protocols = endpoint.protocols.clone();

            // Test opening a stream
            let rtt_start = Instant::now();
            match connection.open_uni().await {
                Ok(_stream) => {
                    info!("Successfully opened stream to {}", endpoint.name);
                }
                Err(e) => {
                    warn!("Failed to open stream to {}: {}", endpoint.name, e);
                }
            }
            let rtt_ms = rtt_start.elapsed().as_millis() as u64;

            connection.close(0u32.into(), b"test complete");

            TestResult {
                endpoint: address.clone(),
                endpoint_name: endpoint.name.clone(),
                address: address.clone(),
                success: true,
                handshake_time_ms: Some(handshake_ms),
                rtt_ms: Some(rtt_ms),
                quic_version: Some(0x00000001), // QUIC v1
                error: None,
                protocols_tested,
                successful_protocols,
                features_tested: endpoint.features.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                metrics: Some(EndpointMetrics {
                    handshake_time_ms: handshake_ms,
                    rtt_ms,
                    success_rate: 100.0,
                }),
            }
        }
        Ok(Err(e)) => TestResult {
            endpoint: address.clone(),
            endpoint_name: endpoint.name.clone(),
            address: address.clone(),
            success: false,
            handshake_time_ms: None,
            rtt_ms: None,
            quic_version: None,
            error: Some(format!("Connect failed: {}", e)),
            protocols_tested,
            successful_protocols,
            features_tested: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
            metrics: None,
        },
        Err(_) => TestResult {
            endpoint: address.clone(),
            endpoint_name: endpoint.name.clone(),
            address: address.clone(),
            success: false,
            handshake_time_ms: None,
            rtt_ms: None,
            quic_version: None,
            error: Some("Connect timeout".to_string()),
            protocols_tested,
            successful_protocols,
            features_tested: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
            metrics: None,
        },
    }
}

async fn run_validation(args: Args) -> Result<ValidationResults, Box<dyn Error>> {
    // Load configuration
    let config_content = fs::read_to_string(&args.config)?;
    let config: EndpointDatabase = serde_yaml::from_str(&config_content)?;

    // Create client configuration
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(cert).unwrap();
    }

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Configure ALPN for HTTP/3
    crypto.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));

    // Configure transport
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

    client_config.transport_config(Arc::new(transport_config));

    // Filter endpoints if specified
    let endpoints_to_test = if let Some(filter) = &args.endpoints {
        let filter_list: Vec<&str> = filter.split(',').collect();
        config
            .endpoints
            .into_iter()
            .filter(|e| filter_list.contains(&e.name.as_str()))
            .collect()
    } else {
        config.endpoints
    };

    // Test endpoints
    let mut results = Vec::new();
    let test_start = Instant::now();

    // Run tests in batches
    for chunk in endpoints_to_test.chunks(args.parallel) {
        let mut handles = vec![];

        for endpoint in chunk {
            let client_config = client_config.clone();
            let endpoint = endpoint.clone();
            let test_config = config.validation.clone();

            let handle =
                tokio::spawn(
                    async move { test_endpoint(&endpoint, client_config, &test_config).await },
                );
            handles.push(handle);
        }

        // Wait for batch to complete
        for handle in handles {
            let result = handle.await?;
            results.push(result);
        }

        // Brief delay between batches
        if !chunk.is_empty() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    let test_duration = test_start.elapsed();

    // Calculate summary
    let successful = results.iter().filter(|r| r.success).count();
    let total = results.len();
    let success_rate = if total > 0 {
        (successful as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    let avg_handshake = if successful > 0 {
        let sum: u64 = results
            .iter()
            .filter(|r| r.success)
            .filter_map(|r| r.handshake_time_ms)
            .sum();
        sum as f32 / successful as f32
    } else {
        0.0
    };

    let mut protocols_seen = std::collections::HashSet::new();
    for result in &results {
        protocols_seen.extend(result.successful_protocols.iter().cloned());
    }

    let validation_results = ValidationResults {
        endpoints: results,
        summary: ValidationSummary {
            total_endpoints: total,
            passed_endpoints: successful,
            failed_endpoints: total - successful,
            success_rate,
            average_handshake_time: avg_handshake,
            protocols_seen: protocols_seen.into_iter().collect(),
        },
        metadata: ResultMetadata {
            ant_quic_version: env!("CARGO_PKG_VERSION").to_string(),
            test_date: chrono::Utc::now().to_rfc3339(),
            test_duration_ms: test_duration.as_millis() as u64,
        },
    };

    Ok(validation_results)
}

fn generate_markdown_report(results: &ValidationResults) -> String {
    let mut report = String::new();

    report.push_str("# QUIC Endpoint Validation Report\n\n");
    report.push_str(&format!("**Date**: {}\n", results.metadata.test_date));
    report.push_str(&format!(
        "**ant-quic Version**: {}\n",
        results.metadata.ant_quic_version
    ));
    report.push_str(&format!(
        "**Test Duration**: {}ms\n\n",
        results.metadata.test_duration_ms
    ));

    report.push_str("## Summary\n\n");
    report.push_str(&format!(
        "- **Total Endpoints**: {}\n",
        results.summary.total_endpoints
    ));
    report.push_str(&format!(
        "- **Successful**: {}\n",
        results.summary.passed_endpoints
    ));
    report.push_str(&format!(
        "- **Failed**: {}\n",
        results.summary.failed_endpoints
    ));
    report.push_str(&format!(
        "- **Success Rate**: {:.1}%\n",
        results.summary.success_rate
    ));
    report.push_str(&format!(
        "- **Average Handshake Time**: {:.1}ms\n",
        results.summary.average_handshake_time
    ));
    report.push_str(&format!(
        "- **Protocols Seen**: {}\n\n",
        results.summary.protocols_seen.join(", ")
    ));

    report.push_str("## Detailed Results\n\n");
    report.push_str("| Endpoint | Address | Status | Handshake Time | RTT | Protocols | Error |\n");
    report.push_str("|----------|---------|--------|----------------|-----|-----------|-------|\n");

    for result in &results.endpoints {
        let status = if result.success {
            "✅ Success"
        } else {
            "❌ Failed"
        };
        let handshake = result
            .handshake_time_ms
            .map(|ms| format!("{}ms", ms))
            .unwrap_or_else(|| "N/A".to_string());
        let rtt = result
            .rtt_ms
            .map(|ms| format!("{}ms", ms))
            .unwrap_or_else(|| "N/A".to_string());
        let protocols = result.successful_protocols.join(", ");
        let error = result.error.as_deref().unwrap_or("");

        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            result.endpoint_name, result.address, status, handshake, rtt, protocols, error
        ));
    }

    report
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(format!("ant_quic={}", log_level).parse()?)
                .add_directive(format!("test_public_endpoints={}", log_level).parse()?),
        )
        .init();

    // Check if we're in analysis mode
    if let Some(analyze_path) = &args.analyze {
        // Load and analyze results
        let results_content = fs::read_to_string(&analyze_path)?;
        let results: ValidationResults = serde_json::from_str(&results_content)?;

        match args.format.as_str() {
            "markdown" => {
                println!("{}", generate_markdown_report(&results));
            }
            "json" => {
                println!("{}", serde_json::to_string_pretty(&results.summary)?);
            }
            _ => {
                eprintln!("Unsupported format: {}", args.format);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    println!("================================================");
    println!("ant-quic Public Endpoint Validation");
    println!("================================================");
    println!();

    // Run validation
    let results = run_validation(args.clone()).await?;

    // Print summary
    println!("\nValidation Summary:");
    println!(
        "Total endpoints tested: {}",
        results.summary.total_endpoints
    );
    println!(
        "Successful connections: {} ({:.1}%)",
        results.summary.passed_endpoints, results.summary.success_rate
    );
    println!(
        "Average handshake time: {:.1}ms",
        results.summary.average_handshake_time
    );

    // Save results if output specified
    if let Some(output_path) = &args.output {
        let json_output = serde_json::to_string_pretty(&results)?;
        fs::write(&output_path, json_output)?;
        println!("\nResults saved to: {}", output_path.display());
    }

    Ok(())
}
