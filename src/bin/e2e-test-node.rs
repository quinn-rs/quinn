// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! E2E Test Node - Enhanced P2P node with metrics push and data verification
//!
//! This binary extends ant-quic with capabilities for comprehensive E2E testing:
//! - Metrics push to central dashboard (HTTP POST)
//! - Data generation and verification with SHA-256 checksums
//! - Progress reporting for heavy throughput testing
//! - Support for local and remote node deployment
//!
//! # Usage Examples
//!
//! Start a test node with metrics reporting:
//! ```bash
//! e2e-test-node --listen 0.0.0.0:9000 --metrics-server http://dashboard:8080
//! ```
//!
//! Run heavy throughput test (1 GB):
//! ```bash
//! e2e-test-node --listen 0.0.0.0:9000 --generate-data 1073741824 --verify-data
//! ```

#![allow(clippy::unwrap_used)] // Test binary - panics are acceptable
#![allow(clippy::expect_used)] // Test binary - panics are acceptable

use ant_quic::{
    MtuConfig, P2pConfig, P2pEndpoint, P2pEvent, PeerId, TraversalPhase, auth::AuthConfig,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// E2E Test Node - Enhanced P2P node for comprehensive testing
#[derive(Parser, Debug)]
#[command(name = "e2e-test-node")]
#[command(
    author,
    version,
    about = "E2E test node with metrics push and data verification"
)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,

    /// Known peer addresses to connect to (comma-separated)
    #[arg(short = 'k', long, value_delimiter = ',')]
    known_peers: Vec<SocketAddr>,

    /// Dashboard/metrics server URL for pushing metrics
    #[arg(long)]
    metrics_server: Option<String>,

    /// Metrics push interval in seconds
    #[arg(long, default_value = "5")]
    metrics_interval: u64,

    /// Amount of data to generate and send (bytes)
    #[arg(long, default_value = "0")]
    generate_data: u64,

    /// Enable data integrity verification with SHA-256
    #[arg(long)]
    verify_data: bool,

    /// Unique node identifier
    #[arg(long)]
    node_id: Option<String>,

    /// Node location (e.g., "local", "do-nyc1", "do-sfo1")
    #[arg(long, default_value = "local")]
    node_location: String,

    /// Chunk size for data transfers (bytes)
    #[arg(long, default_value = "65536")]
    chunk_size: usize,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Run duration in seconds (0 = indefinite)
    #[arg(long, default_value = "0")]
    duration: u64,

    /// Enable PQC-optimized MTU settings
    #[arg(long)]
    pqc_mtu: bool,

    /// JSON output for machine parsing
    #[arg(long)]
    json: bool,

    /// Accept data from peers and echo it back
    #[arg(long)]
    echo: bool,

    /// Show progress updates during data transfer
    #[arg(long)]
    show_progress: bool,

    /// Disable peer authentication (for local testing)
    #[arg(long)]
    no_auth: bool,
}

/// Peer connection information for metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub remote_addr: String,
    pub connected_at: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_type: String, // "direct", "nat_traversed", "relayed"
}

/// Node metrics report pushed to dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetricsReport {
    pub node_id: String,
    pub location: String,
    pub timestamp: u64,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub bytes_sent_total: u64,
    pub bytes_received_total: u64,
    pub current_throughput_mbps: f64,
    pub nat_traversal_successes: u64,
    pub nat_traversal_failures: u64,
    pub direct_connections: u64,
    pub relayed_connections: u64,
    pub data_chunks_sent: u64,
    pub data_chunks_verified: u64,
    pub data_verification_failures: u64,
    pub external_addresses: Vec<String>,
    pub connected_peers: Vec<PeerInfo>,
    pub local_addr: String,
}

/// Data chunk with integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedDataChunk {
    pub sequence: u64,
    pub data: Vec<u8>,
    pub checksum: String,
    pub timestamp: u64,
}

impl VerifiedDataChunk {
    /// Create a new verified data chunk with SHA-256 checksum
    pub fn new(sequence: u64, data: Vec<u8>) -> Self {
        let checksum = compute_sha256(&data);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            sequence,
            data,
            checksum,
            timestamp,
        }
    }

    /// Verify the data integrity
    pub fn verify(&self) -> bool {
        compute_sha256(&self.data) == self.checksum
    }
}

/// Runtime statistics with atomic counters
#[derive(Debug, Default)]
struct RuntimeStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    connections_accepted: AtomicU64,
    connections_initiated: AtomicU64,
    nat_traversals_completed: AtomicU64,
    nat_traversals_failed: AtomicU64,
    external_addresses_discovered: AtomicU64,
    direct_connections: AtomicU64,
    relayed_connections: AtomicU64,
    data_chunks_sent: AtomicU64,
    data_chunks_verified: AtomicU64,
    data_verification_failures: AtomicU64,
}

/// Peer state tracking
#[derive(Debug, Clone)]
struct PeerState {
    peer_id: PeerId,
    remote_addr: SocketAddr,
    connected_at: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    connection_type: String,
}

/// Compute SHA-256 checksum of data
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate random test data with verification
fn generate_test_data(size: u64, chunk_size: usize) -> Vec<VerifiedDataChunk> {
    let mut chunks = Vec::new();
    let mut remaining = size;
    let mut sequence = 0u64;

    while remaining > 0 {
        let this_chunk = std::cmp::min(remaining, chunk_size as u64) as usize;
        let data: Vec<u8> = (0..this_chunk)
            .map(|i| ((sequence + i as u64) % 256) as u8)
            .collect();
        chunks.push(VerifiedDataChunk::new(sequence, data));
        remaining -= this_chunk as u64;
        sequence += 1;
    }

    chunks
}

/// Format bytes in human readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format peer ID as short hex string
fn format_peer_id(peer_id: &PeerId) -> String {
    hex::encode(&peer_id.0[..8])
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ant_quic={log_level},e2e_test_node={log_level}"))
        .init();

    info!("E2E Test Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting in {} mode...", args.node_location);

    // Build configuration
    let mut builder = P2pConfig::builder().bind_addr(args.listen);

    for addr in &args.known_peers {
        builder = builder.known_peer(*addr);
    }

    if args.pqc_mtu {
        builder = builder.mtu(MtuConfig::pqc_optimized());
        info!("Using PQC-optimized MTU settings");
    }

    // Disable authentication if requested (for local testing)
    if args.no_auth {
        builder = builder.auth(AuthConfig {
            require_authentication: false,
            ..Default::default()
        });
        info!("Authentication DISABLED - for local testing only");
    }

    let config = builder.build()?;

    // Create endpoint
    info!("Creating P2P endpoint...");
    let endpoint = P2pEndpoint::new(config).await?;

    // Generate node ID if not provided
    let node_id = args.node_id.unwrap_or_else(|| {
        let peer_id = endpoint.peer_id();
        format!("node-{}", hex::encode(&peer_id.0[..4]))
    });

    let peer_id = endpoint.peer_id();
    let public_key = endpoint.public_key_bytes();

    info!("═══════════════════════════════════════════════════════════════");
    info!("                    E2E TEST NODE");
    info!("═══════════════════════════════════════════════════════════════");
    info!("Node ID: {}", node_id);
    info!("Location: {}", args.node_location);
    info!("Peer ID: {}", format_peer_id(&peer_id));
    info!("Public Key: {}", hex::encode(public_key));

    if let Some(addr) = endpoint.local_addr() {
        info!("Local Address: {}", addr);
    }

    if let Some(ref server) = args.metrics_server {
        info!("Metrics Server: {}", server);
    }

    if args.generate_data > 0 {
        info!(
            "Data Generation: {} ({} chunks)",
            format_bytes(args.generate_data),
            (args.generate_data + args.chunk_size as u64 - 1) / args.chunk_size as u64
        );
    }

    info!("═══════════════════════════════════════════════════════════════");

    // Setup state
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let stats = Arc::new(RuntimeStats::default());
    let peers: Arc<RwLock<HashMap<PeerId, PeerState>>> = Arc::new(RwLock::new(HashMap::new()));
    let external_addrs: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));
    let start_time = Instant::now();

    // Shutdown signal handler
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for ctrl-c: {}", e);
        }
        info!("Shutdown signal received");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    // Event handler task
    let endpoint_events = endpoint.clone();
    let shutdown_events = shutdown.clone();
    let stats_events = stats.clone();
    let peers_events = peers.clone();
    let external_addrs_events = external_addrs.clone();
    let json_output = args.json;

    let event_handle = tokio::spawn(async move {
        let mut events = endpoint_events.subscribe();
        while !shutdown_events.load(Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Ok(event)) => {
                    handle_event(
                        &event,
                        &stats_events,
                        &peers_events,
                        &external_addrs_events,
                        json_output,
                    )
                    .await;
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    });

    // Metrics push task
    let metrics_handle = if let Some(ref server) = args.metrics_server {
        let server = server.clone();
        let endpoint_metrics = endpoint.clone();
        let shutdown_metrics = shutdown.clone();
        let stats_metrics = stats.clone();
        let peers_metrics = peers.clone();
        let external_addrs_metrics = external_addrs.clone();
        let node_id_metrics = node_id.clone();
        let location = args.node_location.clone();
        let interval = args.metrics_interval;

        Some(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval));

            while !shutdown_metrics.load(Ordering::SeqCst) {
                interval_timer.tick().await;

                let report = build_metrics_report(
                    &node_id_metrics,
                    &location,
                    &endpoint_metrics,
                    &stats_metrics,
                    &peers_metrics,
                    &external_addrs_metrics,
                    start_time,
                )
                .await;

                match client
                    .post(format!("{}/api/metrics", server))
                    .json(&report)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("Metrics pushed successfully");
                    }
                    Ok(resp) => {
                        warn!("Metrics push returned {}", resp.status());
                    }
                    Err(e) => {
                        debug!("Failed to push metrics: {}", e);
                    }
                }
            }
        }))
    } else {
        None
    };

    // Data receiver/echo task
    let endpoint_recv = endpoint.clone();
    let shutdown_recv = shutdown.clone();
    let stats_recv = stats.clone();
    let verify_data = args.verify_data;
    let echo_enabled = args.echo;
    let json = args.json;

    let recv_handle = tokio::spawn(async move {
        while !shutdown_recv.load(Ordering::SeqCst) {
            match endpoint_recv.recv(Duration::from_millis(100)).await {
                Ok((peer_id, data)) => {
                    stats_recv
                        .bytes_received
                        .fetch_add(data.len() as u64, Ordering::SeqCst);

                    // Try to deserialize as verified chunk
                    if verify_data {
                        if let Ok(chunk) = serde_json::from_slice::<VerifiedDataChunk>(&data) {
                            if chunk.verify() {
                                stats_recv
                                    .data_chunks_verified
                                    .fetch_add(1, Ordering::SeqCst);
                                if json {
                                    println!(
                                        r#"{{"event":"chunk_verified","sequence":{},"peer":"{}","size":{}}}"#,
                                        chunk.sequence,
                                        format_peer_id(&peer_id),
                                        chunk.data.len()
                                    );
                                } else {
                                    debug!(
                                        "Verified chunk {} from {} ({} bytes)",
                                        chunk.sequence,
                                        format_peer_id(&peer_id),
                                        chunk.data.len()
                                    );
                                }
                            } else {
                                stats_recv
                                    .data_verification_failures
                                    .fetch_add(1, Ordering::SeqCst);
                                error!(
                                    "Verification FAILED for chunk {} from {}",
                                    chunk.sequence,
                                    format_peer_id(&peer_id)
                                );
                            }
                        }
                    } else if json {
                        println!(
                            r#"{{"event":"data_received","bytes":{},"peer":"{}"}}"#,
                            data.len(),
                            format_peer_id(&peer_id)
                        );
                    } else {
                        debug!(
                            "Received {} bytes from {}",
                            data.len(),
                            format_peer_id(&peer_id)
                        );
                    }

                    // Echo back if enabled
                    if echo_enabled {
                        if let Err(e) = endpoint_recv.send(&peer_id, &data).await {
                            debug!("Failed to echo: {}", e);
                        } else {
                            stats_recv
                                .bytes_sent
                                .fetch_add(data.len() as u64, Ordering::SeqCst);
                        }
                    }
                }
                Err(_) => {
                    // Timeout or error
                }
            }
        }
    });

    // Connect to known peers
    if !args.known_peers.is_empty() {
        info!("Connecting to {} known peer(s)...", args.known_peers.len());
        for peer_addr in &args.known_peers {
            info!("Connecting to peer at {}...", peer_addr);
            match endpoint.connect(*peer_addr).await {
                Ok(peer) => {
                    info!(
                        "Connected to peer: {} at {}",
                        format_peer_id(&peer.peer_id),
                        peer_addr
                    );
                    stats.connections_initiated.fetch_add(1, Ordering::SeqCst);

                    // Track peer
                    let mut peers_guard = peers.write().await;
                    peers_guard.insert(
                        peer.peer_id.clone(),
                        PeerState {
                            peer_id: peer.peer_id,
                            remote_addr: *peer_addr,
                            connected_at: Instant::now(),
                            bytes_sent: 0,
                            bytes_received: 0,
                            connection_type: "direct".to_string(),
                        },
                    );
                }
                Err(e) => {
                    error!("Failed to connect to {}: {}", peer_addr, e);
                }
            }
        }
    }

    // Data generation and sending task
    let data_handle = if args.generate_data > 0 {
        let endpoint_data = endpoint.clone();
        let shutdown_data = shutdown.clone();
        let stats_data = stats.clone();
        let peers_data = peers.clone();
        let data_size = args.generate_data;
        let chunk_size = args.chunk_size;
        let show_progress = args.show_progress;
        let json = args.json;

        Some(tokio::spawn(async move {
            // Wait for connections
            tokio::time::sleep(Duration::from_secs(2)).await;

            let chunks = generate_test_data(data_size, chunk_size);
            let total_chunks = chunks.len();
            info!(
                "Generated {} chunks ({} total)",
                total_chunks,
                format_bytes(data_size)
            );

            let connected_peers: Vec<PeerId> = peers_data.read().await.keys().cloned().collect();

            if connected_peers.is_empty() {
                warn!("No connected peers to send data to");
                return;
            }

            info!("Sending data to {} peer(s)...", connected_peers.len());

            let send_start = Instant::now();
            let mut chunks_sent = 0u64;
            let mut last_progress = Instant::now();

            for (idx, chunk) in chunks.iter().enumerate() {
                if shutdown_data.load(Ordering::SeqCst) {
                    break;
                }

                let chunk_bytes = serde_json::to_vec(&chunk).expect("Failed to serialize chunk");

                for peer_id in &connected_peers {
                    match endpoint_data.send(peer_id, &chunk_bytes).await {
                        Ok(()) => {
                            stats_data
                                .bytes_sent
                                .fetch_add(chunk_bytes.len() as u64, Ordering::SeqCst);
                            stats_data.data_chunks_sent.fetch_add(1, Ordering::SeqCst);
                            chunks_sent += 1;
                        }
                        Err(e) => {
                            debug!(
                                "Failed to send chunk {} to {}: {}",
                                idx,
                                format_peer_id(peer_id),
                                e
                            );
                        }
                    }
                }

                // Progress reporting
                if show_progress && last_progress.elapsed() > Duration::from_secs(1) {
                    let progress = (idx + 1) as f64 / total_chunks as f64 * 100.0;
                    let elapsed = send_start.elapsed().as_secs_f64();
                    let bytes_sent = stats_data.bytes_sent.load(Ordering::SeqCst);
                    let throughput_mbps = (bytes_sent as f64 * 8.0) / (elapsed * 1_000_000.0);

                    if json {
                        println!(
                            r#"{{"event":"progress","percent":{:.1},"chunks_sent":{},"throughput_mbps":{:.2}}}"#,
                            progress, chunks_sent, throughput_mbps
                        );
                    } else {
                        info!(
                            "Progress: {:.1}% ({}/{} chunks, {:.2} Mbps)",
                            progress,
                            idx + 1,
                            total_chunks,
                            throughput_mbps
                        );
                    }
                    last_progress = Instant::now();
                }
            }

            let elapsed = send_start.elapsed();
            let throughput_mbps = (data_size as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);

            if json {
                println!(
                    r#"{{"event":"data_transfer_complete","chunks_sent":{},"bytes":{},"duration_secs":{:.2},"throughput_mbps":{:.2}}}"#,
                    chunks_sent,
                    data_size,
                    elapsed.as_secs_f64(),
                    throughput_mbps
                );
            } else {
                info!("═══════════════════════════════════════════════════════════════");
                info!("                DATA TRANSFER COMPLETE");
                info!("═══════════════════════════════════════════════════════════════");
                info!("  Chunks sent: {}", chunks_sent);
                info!("  Total data: {}", format_bytes(data_size));
                info!("  Duration: {:.2}s", elapsed.as_secs_f64());
                info!("  Throughput: {:.2} Mbps", throughput_mbps);
                info!("═══════════════════════════════════════════════════════════════");
            }
        }))
    } else {
        None
    };

    // Main accept loop
    let duration = if args.duration > 0 {
        Some(Duration::from_secs(args.duration))
    } else {
        None
    };

    info!("Ready. Press Ctrl+C to shutdown.");

    while !shutdown.load(Ordering::SeqCst) {
        if let Some(max_duration) = duration {
            if start_time.elapsed() > max_duration {
                info!("Duration limit reached");
                break;
            }
        }

        match tokio::time::timeout(Duration::from_millis(100), endpoint.accept()).await {
            Ok(Some(peer)) => {
                info!(
                    "Accepted connection from: {} at {}",
                    format_peer_id(&peer.peer_id),
                    peer.remote_addr
                );
                stats.connections_accepted.fetch_add(1, Ordering::SeqCst);

                let mut peers_guard = peers.write().await;
                peers_guard.insert(
                    peer.peer_id.clone(),
                    PeerState {
                        peer_id: peer.peer_id,
                        remote_addr: peer.remote_addr,
                        connected_at: Instant::now(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        connection_type: "direct".to_string(),
                    },
                );
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    // Shutdown
    info!("Shutting down...");
    shutdown.store(true, Ordering::SeqCst);

    endpoint.shutdown().await;
    event_handle.abort();
    recv_handle.abort();

    if let Some(h) = metrics_handle {
        h.abort();
    }
    if let Some(h) = data_handle {
        let _ = h.await;
    }

    // Print final statistics
    print_final_stats(&node_id, &stats, start_time.elapsed(), args.json);

    info!("Goodbye!");
    Ok(())
}

async fn handle_event(
    event: &P2pEvent,
    stats: &RuntimeStats,
    peers: &RwLock<HashMap<PeerId, PeerState>>,
    external_addrs: &RwLock<Vec<SocketAddr>>,
    json: bool,
) {
    match event {
        P2pEvent::PeerConnected { peer_id, addr } => {
            if json {
                println!(
                    r#"{{"event":"peer_connected","peer_id":"{}","addr":"{}"}}"#,
                    format_peer_id(peer_id),
                    addr
                );
            } else {
                info!("Peer connected: {} at {}", format_peer_id(peer_id), addr);
            }
        }
        P2pEvent::PeerDisconnected { peer_id, reason } => {
            peers.write().await.remove(peer_id);
            if json {
                println!(
                    r#"{{"event":"peer_disconnected","peer_id":"{}","reason":"{:?}"}}"#,
                    format_peer_id(peer_id),
                    reason
                );
            } else {
                info!(
                    "Peer disconnected: {} ({:?})",
                    format_peer_id(peer_id),
                    reason
                );
            }
        }
        P2pEvent::ExternalAddressDiscovered { addr } => {
            stats
                .external_addresses_discovered
                .fetch_add(1, Ordering::SeqCst);
            external_addrs.write().await.push(*addr);
            if json {
                println!(
                    r#"{{"event":"external_address_discovered","addr":"{}"}}"#,
                    addr
                );
            } else {
                info!("External address discovered: {}", addr);
            }
        }
        P2pEvent::NatTraversalProgress { peer_id, phase } => {
            match phase {
                TraversalPhase::Connected => {
                    stats
                        .nat_traversals_completed
                        .fetch_add(1, Ordering::SeqCst);
                }
                TraversalPhase::Failed => {
                    stats.nat_traversals_failed.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            if json {
                println!(
                    r#"{{"event":"nat_traversal_progress","peer_id":"{}","phase":"{:?}"}}"#,
                    format_peer_id(peer_id),
                    phase
                );
            } else {
                debug!(
                    "NAT traversal progress: {} - {:?}",
                    format_peer_id(peer_id),
                    phase
                );
            }
        }
        P2pEvent::DataReceived { peer_id, bytes } => {
            stats
                .bytes_received
                .fetch_add(*bytes as u64, Ordering::SeqCst);
            debug!(
                "Data received: {} bytes from {}",
                bytes,
                format_peer_id(peer_id)
            );
        }
        _ => {
            debug!("Event: {:?}", event);
        }
    }
}

async fn build_metrics_report(
    node_id: &str,
    location: &str,
    endpoint: &P2pEndpoint,
    stats: &RuntimeStats,
    peers: &RwLock<HashMap<PeerId, PeerState>>,
    external_addrs: &RwLock<Vec<SocketAddr>>,
    start_time: Instant,
) -> NodeMetricsReport {
    let uptime = start_time.elapsed();
    let bytes_sent = stats.bytes_sent.load(Ordering::SeqCst);
    let bytes_received = stats.bytes_received.load(Ordering::SeqCst);

    // Calculate throughput (bits per second to Mbps)
    let total_bytes = bytes_sent + bytes_received;
    let throughput_mbps = if uptime.as_secs() > 0 {
        (total_bytes as f64 * 8.0) / (uptime.as_secs_f64() * 1_000_000.0)
    } else {
        0.0
    };

    let peers_guard = peers.read().await;
    let connected_peers: Vec<PeerInfo> = peers_guard
        .values()
        .map(|p| PeerInfo {
            peer_id: format_peer_id(&p.peer_id),
            remote_addr: p.remote_addr.to_string(),
            connected_at: p.connected_at.elapsed().as_secs(),
            bytes_sent: p.bytes_sent,
            bytes_received: p.bytes_received,
            connection_type: p.connection_type.clone(),
        })
        .collect();

    let external_addresses: Vec<String> = external_addrs
        .read()
        .await
        .iter()
        .map(|a| a.to_string())
        .collect();

    let local_addr = endpoint
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    NodeMetricsReport {
        node_id: node_id.to_string(),
        location: location.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        uptime_secs: uptime.as_secs(),
        active_connections: connected_peers.len(),
        bytes_sent_total: bytes_sent,
        bytes_received_total: bytes_received,
        current_throughput_mbps: throughput_mbps,
        nat_traversal_successes: stats.nat_traversals_completed.load(Ordering::SeqCst),
        nat_traversal_failures: stats.nat_traversals_failed.load(Ordering::SeqCst),
        direct_connections: stats.direct_connections.load(Ordering::SeqCst),
        relayed_connections: stats.relayed_connections.load(Ordering::SeqCst),
        data_chunks_sent: stats.data_chunks_sent.load(Ordering::SeqCst),
        data_chunks_verified: stats.data_chunks_verified.load(Ordering::SeqCst),
        data_verification_failures: stats.data_verification_failures.load(Ordering::SeqCst),
        external_addresses,
        connected_peers,
        local_addr,
    }
}

fn print_final_stats(node_id: &str, stats: &RuntimeStats, duration: Duration, json: bool) {
    let bytes_sent = stats.bytes_sent.load(Ordering::SeqCst);
    let bytes_received = stats.bytes_received.load(Ordering::SeqCst);
    let secs = duration.as_secs_f64();

    if json {
        println!(
            r#"{{"type":"final_stats","node_id":"{}","duration_secs":{:.2},"bytes_sent":{},"bytes_received":{},"connections_accepted":{},"connections_initiated":{},"nat_traversals_completed":{},"nat_traversals_failed":{},"chunks_sent":{},"chunks_verified":{},"verification_failures":{}}}"#,
            node_id,
            secs,
            bytes_sent,
            bytes_received,
            stats.connections_accepted.load(Ordering::SeqCst),
            stats.connections_initiated.load(Ordering::SeqCst),
            stats.nat_traversals_completed.load(Ordering::SeqCst),
            stats.nat_traversals_failed.load(Ordering::SeqCst),
            stats.data_chunks_sent.load(Ordering::SeqCst),
            stats.data_chunks_verified.load(Ordering::SeqCst),
            stats.data_verification_failures.load(Ordering::SeqCst),
        );
    } else {
        info!("═══════════════════════════════════════════════════════════════");
        info!("                    FINAL STATISTICS");
        info!("═══════════════════════════════════════════════════════════════");
        info!("  Node ID: {}", node_id);
        info!("  Duration: {:.2}s", secs);
        info!(
            "  Connections accepted: {}",
            stats.connections_accepted.load(Ordering::SeqCst)
        );
        info!(
            "  Connections initiated: {}",
            stats.connections_initiated.load(Ordering::SeqCst)
        );
        info!(
            "  NAT traversals completed: {}",
            stats.nat_traversals_completed.load(Ordering::SeqCst)
        );
        info!(
            "  NAT traversals failed: {}",
            stats.nat_traversals_failed.load(Ordering::SeqCst)
        );
        info!("  Bytes sent: {}", format_bytes(bytes_sent));
        info!("  Bytes received: {}", format_bytes(bytes_received));
        info!(
            "  Data chunks sent: {}",
            stats.data_chunks_sent.load(Ordering::SeqCst)
        );
        info!(
            "  Data chunks verified: {}",
            stats.data_chunks_verified.load(Ordering::SeqCst)
        );
        info!(
            "  Verification failures: {}",
            stats.data_verification_failures.load(Ordering::SeqCst)
        );

        if secs > 0.0 {
            let total_bytes = bytes_sent + bytes_received;
            let throughput_mbps = (total_bytes as f64 * 8.0) / (secs * 1_000_000.0);
            info!("  Throughput: {:.2} Mbps", throughput_mbps);
        }
        info!("═══════════════════════════════════════════════════════════════");
    }
}
