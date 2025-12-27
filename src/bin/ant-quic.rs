// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ant-quic - P2P QUIC networking with NAT traversal
//!
//! This binary provides a command-line interface for running symmetric P2P nodes.
//! All nodes are identical - they can connect to and accept connections from other nodes,
//! and coordinate NAT traversal for peers.
//!
//! # Usage Examples
//!
//! Start a node listening on port 9000:
//! ```bash
//! ant-quic --listen 0.0.0.0:9000
//! ```
//!
//! Start a node and connect to known peers:
//! ```bash
//! ant-quic --known-peers 1.2.3.4:9000,5.6.7.8:9000
//! ```
//!
//! Run throughput test:
//! ```bash
//! ant-quic --known-peers 1.2.3.4:9000 --connect 5.6.7.8:9001 --throughput-test
//! ```

use ant_quic::host_identity::{HostIdentity, auto_storage};
use ant_quic::{
    ConnectionMethod, MtuConfig, P2pConfig, P2pEndpoint, P2pEvent, PeerId, TraversalPhase,
};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Default bootstrap nodes operated by Saorsa Labs
///
/// These nodes are available for initial network discovery. They run the same
/// ant-quic software as any other node and provide:
/// - Initial peer discovery
/// - NAT traversal coordination
/// - External address observation (OBSERVED_ADDRESS frames)
const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    "saorsa-1.saorsalabs.com:9000",
    "saorsa-2.saorsalabs.com:9000",
];

/// ant-quic P2P node
///
/// A symmetric P2P node that can both connect to and accept connections from
/// other nodes. All nodes are functionally identical - there is no client/server
/// distinction.
#[derive(Parser, Debug)]
#[command(name = "ant-quic")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Subcommand to run
    #[command(subcommand)]
    command: Option<Command>,

    /// Address to listen on (dual-stack: binds IPv6 and IPv4)
    #[arg(short, long, default_value = "[::]:0")]
    listen: SocketAddr,

    /// Known peer addresses to connect to (comma-separated)
    #[arg(short = 'k', long, value_delimiter = ',')]
    known_peers: Vec<SocketAddr>,

    /// Bootstrap node addresses (alias for --known-peers)
    #[arg(short, long, value_delimiter = ',')]
    bootstrap: Vec<SocketAddr>,

    /// Peer address to connect to directly
    #[arg(short, long)]
    connect: Option<SocketAddr>,

    /// Use fallback strategy: IPv4 → IPv6 → HolePunch → Relay
    #[arg(long)]
    connect_fallback: bool,

    /// IPv6 address for fallback connection
    #[arg(long)]
    connect_ipv6: Option<SocketAddr>,

    /// Run throughput test after connecting
    #[arg(long)]
    throughput_test: bool,

    /// Run counter test - send incrementing counters to connected peers
    #[arg(long)]
    counter_test: bool,

    /// Counter interval in milliseconds
    #[arg(long, default_value = "1000")]
    counter_interval: u64,

    /// Enable echo mode - echo received data back to sender
    #[arg(long)]
    echo: bool,

    /// Data size for throughput test (bytes)
    #[arg(long, default_value = "1048576")]
    test_size: usize,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Show real-time statistics
    #[arg(long)]
    stats: bool,

    /// Stats update interval in seconds
    #[arg(long, default_value = "5")]
    stats_interval: u64,

    /// Run duration in seconds (0 = indefinite)
    #[arg(long, default_value = "0")]
    duration: u64,

    /// Enable PQC-optimized MTU settings
    #[arg(long)]
    pqc_mtu: bool,

    /// JSON output for machine parsing
    #[arg(long)]
    json: bool,

    /// Show full public key (not just first 8 bytes)
    #[arg(long)]
    full_key: bool,

    // === Metrics Reporting ===
    /// Dashboard server URL for metrics reporting (e.g., http://saorsa-1.saorsalabs.com:8080)
    #[arg(long)]
    metrics_server: Option<String>,

    /// Metrics reporting interval in seconds
    #[arg(long, default_value = "5")]
    metrics_interval: u64,

    /// Node location identifier (e.g., "hetzner-eu", "do-nyc")
    #[arg(long, default_value = "unknown")]
    node_location: String,

    /// Node identifier (defaults to first 8 bytes of peer ID)
    #[arg(long)]
    node_id: Option<String>,

    // === Data Testing ===
    /// Generate test data with SHA-256 checksums (size in bytes)
    #[arg(long)]
    generate_data: Option<u64>,

    /// Verify received data integrity
    #[arg(long)]
    verify_data: bool,

    /// Chunk size for data generation/verification (bytes)
    #[arg(long, default_value = "65536")]
    chunk_size: usize,
}

/// CLI subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Identity management commands
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// Bootstrap cache management commands
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Run diagnostic checks
    Doctor,
}

/// Identity management actions
#[derive(Subcommand, Debug)]
enum IdentityAction {
    /// Show the current host identity fingerprint and endpoint IDs
    Show {
        /// Show all network endpoint IDs
        #[arg(long)]
        all_networks: bool,

        /// Data directory for stored identities
        #[arg(long, default_value = "~/.ant-quic")]
        data_dir: PathBuf,
    },

    /// Wipe the host identity and all derived data (DANGEROUS)
    Wipe {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,

        /// Data directory for stored identities
        #[arg(long, default_value = "~/.ant-quic")]
        data_dir: PathBuf,
    },

    /// Export identity fingerprint for sharing
    Fingerprint,
}

/// Cache management actions
#[derive(Subcommand, Debug)]
enum CacheAction {
    /// Show bootstrap cache statistics
    Stats {
        /// Data directory containing the cache
        #[arg(long, default_value = "~/.ant-quic")]
        data_dir: PathBuf,
    },

    /// Clear the bootstrap cache
    Clear {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,

        /// Data directory containing the cache
        #[arg(long, default_value = "~/.ant-quic")]
        data_dir: PathBuf,
    },
}

// v0.13.0: Mode enum removed - all nodes are symmetric P2P nodes

/// Runtime statistics
#[derive(Debug, Default)]
struct RuntimeStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    connections_accepted: AtomicU64,
    connections_initiated: AtomicU64,
    nat_traversals_completed: AtomicU64,
    nat_traversals_failed: AtomicU64,
    external_addresses_discovered: AtomicU64,
    counters_sent: AtomicU64,
    counters_received: AtomicU64,
    echoes_sent: AtomicU64,
    // Data verification stats
    data_chunks_sent: AtomicU64,
    data_chunks_verified: AtomicU64,
    data_verification_failures: AtomicU64,
    direct_connections: AtomicU64,
    relayed_connections: AtomicU64,
}

/// Information about a connected peer for metrics reporting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub remote_addr: String,
    pub connected_at: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_type: String, // "direct", "nat_traversed", "relayed"
}

/// Metrics report sent to dashboard
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Track per-peer state for metrics
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields tracked for future use in detailed metrics
struct PeerState {
    peer_id: PeerId,
    remote_addr: SocketAddr,
    connected_at: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    connection_type: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ant_quic={log_level},ant_quic={log_level}"))
        .init();

    // Handle subcommands first
    if let Some(command) = args.command {
        return handle_command(command).await;
    }

    info!("ant-quic v{}", env!("CARGO_PKG_VERSION"));
    info!("Symmetric P2P node starting...");

    // Combine known_peers and bootstrap (bootstrap is an alias for backwards compat)
    let mut all_peers: Vec<SocketAddr> = args
        .known_peers
        .iter()
        .chain(args.bootstrap.iter())
        .copied()
        .collect();

    // Use default bootstrap nodes if no peers were specified
    if all_peers.is_empty() {
        info!("No peers specified, using default Saorsa Labs bootstrap nodes");
        for addr_str in DEFAULT_BOOTSTRAP_NODES {
            match tokio::net::lookup_host(addr_str).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        all_peers.push(addr);
                        info!("  - {} -> {}", addr_str, addr);
                    }
                }
                Err(e) => {
                    warn!("Failed to resolve {}: {}", addr_str, e);
                }
            }
        }
    }

    // Build configuration
    let mut builder = P2pConfig::builder().bind_addr(args.listen);

    // Add known peers
    for addr in &all_peers {
        builder = builder.known_peer(*addr);
    }

    // Configure MTU
    if args.pqc_mtu {
        builder = builder.mtu(MtuConfig::pqc_optimized());
        info!("Using PQC-optimized MTU settings");
    }
    // v0.13.0: No mode-based NAT config - all nodes are symmetric

    let config = builder.build()?;

    // Create endpoint
    info!("Creating P2P endpoint...");
    let endpoint = P2pEndpoint::new(config).await?;

    // Show local info
    let peer_id = endpoint.peer_id();
    let public_key = endpoint.public_key_bytes();

    info!("═══════════════════════════════════════════════════════════════");
    info!("                    NODE IDENTITY");
    info!("═══════════════════════════════════════════════════════════════");
    if args.full_key {
        info!("Peer ID (full): {}", hex::encode(peer_id.0));
    } else {
        info!("Peer ID: {}", format_peer_id(&peer_id));
    }
    info!("Public Key (ML-DSA-65): {}", hex::encode(public_key));

    if let Some(addr) = endpoint.local_addr() {
        info!("Local Address: {}", addr);
    }
    info!("═══════════════════════════════════════════════════════════════");

    // Setup shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for ctrl-c: {}", e);
        }
        info!("Shutdown signal received");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    // Setup statistics
    let stats = Arc::new(RuntimeStats::default());
    let stats_clone = stats.clone();

    // Track peer state for metrics
    let peer_states: Arc<RwLock<HashMap<PeerId, PeerState>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Track discovered external addresses
    let external_addrs: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));

    // Event handler
    let endpoint_clone = endpoint.clone();
    let shutdown_events = shutdown.clone();
    let json_output = args.json;
    let peer_states_events = peer_states.clone();
    let external_addrs_events = external_addrs.clone();

    let event_handle = tokio::spawn(async move {
        let mut events = endpoint_clone.subscribe();
        while !shutdown_events.load(Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Ok(event)) => {
                    handle_event_with_state(
                        &event,
                        &stats_clone,
                        &peer_states_events,
                        &external_addrs_events,
                        json_output,
                    )
                    .await;
                }
                Ok(Err(_)) => break, // Channel closed
                Err(_) => continue,  // Timeout, check shutdown
            }
        }
    });

    // Stats reporter
    let stats_clone2 = stats.clone();
    let shutdown_stats = shutdown.clone();
    let stats_handle = if args.stats {
        let endpoint_stats = endpoint.clone();
        let interval = args.stats_interval;
        let json = args.json;

        Some(tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval));
            while !shutdown_stats.load(Ordering::SeqCst) {
                interval_timer.tick().await;
                print_stats(&endpoint_stats, &stats_clone2, json).await;
            }
        }))
    } else {
        None
    };

    // Metrics push task
    let metrics_handle = if let Some(ref server) = args.metrics_server {
        let endpoint_metrics = endpoint.clone();
        let shutdown_metrics = shutdown.clone();
        let stats_metrics = stats.clone();
        let peer_states_metrics = peer_states.clone();
        let external_addrs_metrics = external_addrs.clone();
        let interval_secs = args.metrics_interval;
        let server_url = server.clone();
        let node_id = args
            .node_id
            .clone()
            .unwrap_or_else(|| format_peer_id(&peer_id));
        let location = args.node_location.clone();
        let start_time = Instant::now();

        info!(
            "Metrics reporting enabled: {} every {}s",
            server_url, interval_secs
        );

        Some(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            let mut prev_bytes: u64 = 0;
            let mut prev_time = Instant::now();

            while !shutdown_metrics.load(Ordering::SeqCst) {
                interval.tick().await;

                let report = build_metrics_report(
                    &node_id,
                    &location,
                    start_time,
                    &endpoint_metrics,
                    &stats_metrics,
                    &peer_states_metrics,
                    &external_addrs_metrics,
                    &mut prev_bytes,
                    &mut prev_time,
                )
                .await;

                let url = format!("{}/api/metrics", server_url);
                match client.post(&url).json(&report).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!("Metrics sent successfully to {}", url);
                        } else {
                            warn!(
                                "Metrics server returned status {}: {}",
                                response.status(),
                                url
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to send metrics to {}: {}", url, e);
                    }
                }
            }
        }))
    } else {
        None
    };

    // Counter test task
    let counter_handle = if args.counter_test {
        let endpoint_counter = endpoint.clone();
        let shutdown_counter = shutdown.clone();
        let interval_ms = args.counter_interval;
        let stats_counter = stats.clone();
        let json = args.json;

        Some(tokio::spawn(async move {
            let mut counter: u64 = 0;
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

            while !shutdown_counter.load(Ordering::SeqCst) {
                interval.tick().await;
                counter += 1;

                let peers = endpoint_counter.connected_peers().await;
                for peer in peers {
                    let data = counter.to_be_bytes();
                    match endpoint_counter.send(&peer.peer_id, &data).await {
                        Ok(()) => {
                            stats_counter.counters_sent.fetch_add(1, Ordering::SeqCst);
                            stats_counter
                                .bytes_sent
                                .fetch_add(data.len() as u64, Ordering::SeqCst);
                            if json {
                                println!(
                                    r#"{{"event":"counter_sent","counter":{},"peer":"{}"}}"#,
                                    counter,
                                    hex::encode(&peer.peer_id.0[..8])
                                );
                            } else {
                                info!(
                                    "Sent counter {} to peer {}",
                                    counter,
                                    hex::encode(&peer.peer_id.0[..8])
                                );
                            }
                        }
                        Err(e) => {
                            debug!("Failed to send counter: {}", e);
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    // Echo and receive handler task
    let echo_handle = {
        let endpoint_echo = endpoint.clone();
        let shutdown_echo = shutdown.clone();
        let echo_enabled = args.echo;
        let stats_echo = stats.clone();
        let json = args.json;

        tokio::spawn(async move {
            while !shutdown_echo.load(Ordering::SeqCst) {
                match endpoint_echo.recv(Duration::from_millis(100)).await {
                    Ok((peer_id, data)) => {
                        stats_echo
                            .bytes_received
                            .fetch_add(data.len() as u64, Ordering::SeqCst);

                        // Try to parse as counter
                        if data.len() == 8 {
                            if let Ok(bytes) = data[..8].try_into() {
                                let counter = u64::from_be_bytes(bytes);
                                stats_echo.counters_received.fetch_add(1, Ordering::SeqCst);
                                if json {
                                    println!(
                                        r#"{{"event":"counter_received","counter":{},"peer":"{}"}}"#,
                                        counter,
                                        hex::encode(&peer_id.0[..8])
                                    );
                                } else {
                                    info!(
                                        "Received counter {} from peer {}",
                                        counter,
                                        hex::encode(&peer_id.0[..8])
                                    );
                                }
                            }
                        } else if json {
                            println!(
                                r#"{{"event":"data_received","bytes":{},"peer":"{}"}}"#,
                                data.len(),
                                hex::encode(&peer_id.0[..8])
                            );
                        } else {
                            info!(
                                "Received {} bytes from peer {}",
                                data.len(),
                                hex::encode(&peer_id.0[..8])
                            );
                        }

                        // Echo back if enabled
                        if echo_enabled {
                            if let Err(e) = endpoint_echo.send(&peer_id, &data).await {
                                debug!("Failed to echo: {}", e);
                            } else {
                                stats_echo.echoes_sent.fetch_add(1, Ordering::SeqCst);
                                stats_echo
                                    .bytes_sent
                                    .fetch_add(data.len() as u64, Ordering::SeqCst);
                            }
                        }
                    }
                    Err(_) => {
                        // Timeout or error, continue
                    }
                }
            }
        })
    };

    // Connect to known peers (bootstrap nodes)
    if !all_peers.is_empty() {
        info!("Connecting to {} known peer(s)...", all_peers.len());
        for peer_addr in &all_peers {
            info!("Connecting to known peer at {}...", peer_addr);
            match endpoint.connect(*peer_addr).await {
                Ok(peer) => {
                    info!(
                        "Connected to known peer: {} at {}",
                        format_peer_id(&peer.peer_id),
                        peer_addr
                    );
                    stats.connections_initiated.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    error!("Failed to connect to known peer {}: {}", peer_addr, e);
                }
            }
        }
    }

    // Connect to specific peer if specified
    if let Some(peer_addr) = args.connect {
        if args.connect_fallback {
            // Use progressive fallback: IPv4 → IPv6 → HolePunch → Relay
            info!(
                "Connecting to peer with fallback strategy: IPv4={}, IPv6={:?}",
                peer_addr, args.connect_ipv6
            );
            match endpoint
                .connect_with_fallback(Some(peer_addr), args.connect_ipv6, None)
                .await
            {
                Ok((peer, method)) => {
                    let method: ConnectionMethod = method;
                    info!(
                        "✓ Connected to peer {} via {}",
                        format_peer_id(&peer.peer_id),
                        method
                    );
                    stats.connections_initiated.fetch_add(1, Ordering::SeqCst);

                    // Run throughput test if requested
                    if args.throughput_test {
                        run_throughput_test(&endpoint, &peer.peer_id, args.test_size).await?;
                    }
                }
                Err(e) => {
                    error!("Failed to connect with fallback: {}", e);
                }
            }
        } else {
            // Direct connection (original behavior)
            info!("Connecting to peer at {}...", peer_addr);
            match endpoint.connect(peer_addr).await {
                Ok(peer) => {
                    info!("Connected to peer: {}", format_peer_id(&peer.peer_id));
                    stats.connections_initiated.fetch_add(1, Ordering::SeqCst);

                    // Run throughput test if requested
                    if args.throughput_test {
                        run_throughput_test(&endpoint, &peer.peer_id, args.test_size).await?;
                    }
                }
                Err(e) => {
                    error!("Failed to connect to peer: {}", e);
                }
            }
        }
    }

    // Main loop - accept connections
    let start_time = Instant::now();
    let duration = if args.duration > 0 {
        Some(Duration::from_secs(args.duration))
    } else {
        None
    };

    info!("Ready. Press Ctrl+C to shutdown.");

    // All nodes are symmetric - accept connections while running
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
                    "Accepted connection from peer: {} at {}",
                    format_peer_id(&peer.peer_id),
                    peer.remote_addr
                );
                stats.connections_accepted.fetch_add(1, Ordering::SeqCst);
            }
            Ok(None) => {
                // No connection available
            }
            Err(_) => {
                // Timeout
            }
        }
    }

    // Shutdown
    info!("Shutting down...");
    shutdown.store(true, Ordering::SeqCst);

    endpoint.shutdown().await;
    event_handle.abort();
    echo_handle.abort();
    if let Some(h) = stats_handle {
        h.abort();
    }
    if let Some(h) = counter_handle {
        h.abort();
    }
    if let Some(h) = metrics_handle {
        h.abort();
    }

    // Final stats
    print_final_stats(&stats, start_time.elapsed(), args.json);

    info!("Goodbye!");
    Ok(())
}

async fn handle_event_with_state(
    event: &P2pEvent,
    stats: &RuntimeStats,
    peer_states: &RwLock<HashMap<PeerId, PeerState>>,
    external_addrs: &RwLock<Vec<SocketAddr>>,
    json: bool,
) {
    match event {
        P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
        } => {
            // Track peer state with connection direction
            let connection_type = if side.is_client() {
                "outbound" // We connected to them
            } else {
                "inbound" // They connected to us
            };
            let state = PeerState {
                peer_id: *peer_id,
                remote_addr: *addr,
                connected_at: Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
                connection_type: connection_type.to_string(),
            };
            peer_states.write().await.insert(*peer_id, state);
            stats.direct_connections.fetch_add(1, Ordering::SeqCst);

            if json {
                println!(
                    r#"{{"event":"peer_connected","peer_id":"{}","addr":"{}","direction":"{}"}}"#,
                    format_peer_id(peer_id),
                    addr,
                    connection_type
                );
            } else {
                info!("Peer connected: {} at {}", format_peer_id(peer_id), addr);
            }
        }
        P2pEvent::PeerDisconnected { peer_id, reason } => {
            // Remove peer state
            peer_states.write().await.remove(peer_id);

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

            // Track the discovered address
            let mut addrs = external_addrs.write().await;
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }

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
            if matches!(phase, TraversalPhase::Connected) {
                stats
                    .nat_traversals_completed
                    .fetch_add(1, Ordering::SeqCst);

                // Update connection type to nat_traversed
                if let Some(state) = peer_states.write().await.get_mut(peer_id) {
                    state.connection_type = "nat_traversed".to_string();
                }
            }
            if json {
                println!(
                    r#"{{"event":"nat_traversal_progress","peer_id":"{}","phase":"{:?}"}}"#,
                    format_peer_id(peer_id),
                    phase
                );
            } else {
                info!(
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

            // Update peer bytes received
            if let Some(state) = peer_states.write().await.get_mut(peer_id) {
                state.bytes_received += *bytes as u64;
            }

            debug!("Received {} bytes from {}", bytes, format_peer_id(peer_id));
        }
        _ => {
            debug!("Event: {:?}", event);
        }
    }
}

async fn print_stats(endpoint: &P2pEndpoint, runtime_stats: &RuntimeStats, json: bool) {
    let stats = endpoint.stats().await;

    if json {
        println!(
            r#"{{"type":"stats","active_connections":{},"successful_connections":{},"failed_connections":{},"nat_traversals":{},"bytes_sent":{},"bytes_received":{},"external_addresses":{}}}"#,
            stats.active_connections,
            stats.successful_connections,
            stats.failed_connections,
            runtime_stats
                .nat_traversals_completed
                .load(Ordering::SeqCst),
            runtime_stats.bytes_sent.load(Ordering::SeqCst),
            runtime_stats.bytes_received.load(Ordering::SeqCst),
            runtime_stats
                .external_addresses_discovered
                .load(Ordering::SeqCst),
        );
    } else {
        info!("=== Statistics ===");
        info!("  Active connections: {}", stats.active_connections);
        info!("  Successful connections: {}", stats.successful_connections);
        info!("  Failed connections: {}", stats.failed_connections);
        info!(
            "  NAT traversals completed: {}",
            runtime_stats
                .nat_traversals_completed
                .load(Ordering::SeqCst)
        );
        info!(
            "  External addresses discovered: {}",
            runtime_stats
                .external_addresses_discovered
                .load(Ordering::SeqCst)
        );
        info!(
            "  Bytes sent: {}",
            format_bytes(runtime_stats.bytes_sent.load(Ordering::SeqCst))
        );
        info!(
            "  Bytes received: {}",
            format_bytes(runtime_stats.bytes_received.load(Ordering::SeqCst))
        );
    }
}

fn print_final_stats(stats: &RuntimeStats, duration: Duration, json: bool) {
    let bytes_sent = stats.bytes_sent.load(Ordering::SeqCst);
    let bytes_received = stats.bytes_received.load(Ordering::SeqCst);
    let counters_sent = stats.counters_sent.load(Ordering::SeqCst);
    let counters_received = stats.counters_received.load(Ordering::SeqCst);
    let echoes_sent = stats.echoes_sent.load(Ordering::SeqCst);
    let secs = duration.as_secs_f64();

    if json {
        println!(
            r#"{{"type":"final_stats","duration_secs":{:.2},"bytes_sent":{},"bytes_received":{},"connections_accepted":{},"connections_initiated":{},"nat_traversals":{},"external_addresses":{},"counters_sent":{},"counters_received":{},"echoes_sent":{}}}"#,
            secs,
            bytes_sent,
            bytes_received,
            stats.connections_accepted.load(Ordering::SeqCst),
            stats.connections_initiated.load(Ordering::SeqCst),
            stats.nat_traversals_completed.load(Ordering::SeqCst),
            stats.external_addresses_discovered.load(Ordering::SeqCst),
            counters_sent,
            counters_received,
            echoes_sent,
        );
    } else {
        info!("═══════════════════════════════════════════════════════════════");
        info!("                    FINAL STATISTICS");
        info!("═══════════════════════════════════════════════════════════════");
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
            "  NAT traversals: {}",
            stats.nat_traversals_completed.load(Ordering::SeqCst)
        );
        info!(
            "  External addresses: {}",
            stats.external_addresses_discovered.load(Ordering::SeqCst)
        );
        info!("  Bytes sent: {}", format_bytes(bytes_sent));
        info!("  Bytes received: {}", format_bytes(bytes_received));
        if counters_sent > 0 || counters_received > 0 {
            info!("  Counters sent: {}", counters_sent);
            info!("  Counters received: {}", counters_received);
        }
        if echoes_sent > 0 {
            info!("  Echoes sent: {}", echoes_sent);
        }

        if secs > 0.0 {
            let total_bytes = bytes_sent + bytes_received;
            let throughput = total_bytes as f64 / secs;
            info!("  Throughput: {}/s", format_bytes(throughput as u64));
        }
        info!("═══════════════════════════════════════════════════════════════");
    }
}

async fn run_throughput_test(
    endpoint: &P2pEndpoint,
    peer_id: &PeerId,
    data_size: usize,
) -> anyhow::Result<()> {
    info!("Starting throughput test ({} bytes)...", data_size);

    let data = vec![0xABu8; data_size];
    let start = Instant::now();

    match endpoint.send(peer_id, &data).await {
        Ok(()) => {
            let elapsed = start.elapsed();
            let throughput = data_size as f64 / elapsed.as_secs_f64();
            info!(
                "Throughput test complete: {} in {:.2}ms ({}/s)",
                format_bytes(data_size as u64),
                elapsed.as_secs_f64() * 1000.0,
                format_bytes(throughput as u64)
            );
        }
        Err(e) => {
            error!("Throughput test failed: {}", e);
        }
    }

    Ok(())
}

fn format_peer_id(peer_id: &PeerId) -> String {
    let bytes = &peer_id.0;
    hex::encode(&bytes[..8])
}

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

// === Data Verification Functions ===

/// Compute SHA-256 hash of data
#[allow(dead_code)] // Will be used when data generation features are wired up
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verified data chunk with embedded checksum
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used when data generation features are wired up
pub struct VerifiedDataChunk {
    /// Sequence number
    pub sequence: u64,
    /// The actual data
    pub data: Vec<u8>,
    /// SHA-256 hash of the data
    pub checksum: [u8; 32],
}

#[allow(dead_code)] // Will be used when data generation features are wired up
impl VerifiedDataChunk {
    /// Create a new verified chunk with random data
    fn generate(sequence: u64, size: usize) -> Self {
        let data: Vec<u8> = (0..size)
            .map(|i| ((sequence + i as u64) % 256) as u8)
            .collect();
        let checksum = compute_sha256(&data);
        Self {
            sequence,
            data,
            checksum,
        }
    }

    /// Serialize chunk to bytes: [sequence(8)] [checksum(32)] [data]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 32 + self.data.len());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.checksum);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize chunk from bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let sequence = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[8..40]);
        let data = bytes[40..].to_vec();
        Some(Self {
            sequence,
            data,
            checksum,
        })
    }

    /// Verify the checksum matches the data
    fn verify(&self) -> bool {
        let computed = compute_sha256(&self.data);
        computed == self.checksum
    }
}

// === Metrics Functions ===

/// Build a metrics report from current state
async fn build_metrics_report(
    node_id: &str,
    location: &str,
    start_time: Instant,
    endpoint: &P2pEndpoint,
    stats: &RuntimeStats,
    peer_states: &RwLock<HashMap<PeerId, PeerState>>,
    external_addrs: &RwLock<Vec<SocketAddr>>,
    prev_bytes: &mut u64,
    prev_time: &mut Instant,
) -> NodeMetricsReport {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let bytes_sent = stats.bytes_sent.load(Ordering::SeqCst);
    let bytes_received = stats.bytes_received.load(Ordering::SeqCst);
    let total_bytes = bytes_sent + bytes_received;

    // Calculate throughput
    let elapsed = prev_time.elapsed().as_secs_f64();
    let throughput_mbps = if elapsed > 0.0 {
        let bytes_diff = total_bytes.saturating_sub(*prev_bytes);
        (bytes_diff as f64 * 8.0) / (elapsed * 1_000_000.0) // bits per second / 1M
    } else {
        0.0
    };
    *prev_bytes = total_bytes;
    *prev_time = Instant::now();

    // Get connected peers
    let endpoint_stats = endpoint.stats().await;
    let peers = endpoint.connected_peers().await;

    // Build peer info from tracked state
    let peer_states_read = peer_states.read().await;
    let connected_peers: Vec<PeerInfo> = peers
        .iter()
        .map(|p| {
            let state = peer_states_read.get(&p.peer_id);
            PeerInfo {
                peer_id: hex::encode(&p.peer_id.0[..8]),
                remote_addr: p.remote_addr.to_string(),
                connected_at: state
                    .map(|s| s.connected_at.elapsed().as_secs())
                    .unwrap_or(0),
                bytes_sent: state.map(|s| s.bytes_sent).unwrap_or(0),
                bytes_received: state.map(|s| s.bytes_received).unwrap_or(0),
                connection_type: state
                    .map(|s| s.connection_type.clone())
                    .unwrap_or_else(|| "direct".to_string()),
            }
        })
        .collect();

    // Get external addresses from tracked state
    let external_addresses: Vec<String> = external_addrs
        .read()
        .await
        .iter()
        .map(|a| a.to_string())
        .collect();

    let local_addr = endpoint
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    NodeMetricsReport {
        node_id: node_id.to_string(),
        location: location.to_string(),
        timestamp: now_secs,
        uptime_secs: start_time.elapsed().as_secs(),
        active_connections: endpoint_stats.active_connections,
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

// =============================================================================
// CLI Subcommand Handlers
// =============================================================================

/// Handle CLI subcommands
async fn handle_command(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Identity { action } => handle_identity_command(action).await,
        Command::Cache { action } => handle_cache_command(action).await,
        Command::Doctor => handle_doctor_command().await,
    }
}

/// Expand tilde to home directory
fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}

/// Handle identity subcommands
async fn handle_identity_command(action: IdentityAction) -> anyhow::Result<()> {
    match action {
        IdentityAction::Show {
            all_networks,
            data_dir,
        } => {
            let data_dir = expand_tilde(&data_dir);

            println!("═══════════════════════════════════════════════════════════════");
            println!("                    HOST IDENTITY");
            println!("═══════════════════════════════════════════════════════════════");

            // Try to load existing host identity
            let storage_selection = auto_storage()?;
            match storage_selection.storage.load() {
                Ok(secret) => {
                    let host = HostIdentity::from_secret(secret);
                    println!("Fingerprint: {}", host.fingerprint());
                    println!("Policy: {:?}", host.policy());
                    println!("Storage: {}", storage_selection.storage.backend_name());
                    println!("Security: {:?}", storage_selection.security_level);
                    if let Some(warning) = storage_selection.security_level.warning_message() {
                        println!();
                        println!("{}", warning);
                    }
                    println!("Data Directory: {}", data_dir.display());

                    if all_networks {
                        // List all network keypair files in data directory
                        println!();
                        println!("Stored Endpoint Keypairs:");
                        if data_dir.exists() {
                            let mut found = false;
                            if let Ok(entries) = std::fs::read_dir(&data_dir) {
                                for entry in entries.flatten() {
                                    let name = entry.file_name();
                                    let name_str = name.to_string_lossy();
                                    if name_str.ends_with("_keypair.enc") {
                                        let network_id_hex =
                                            name_str.trim_end_matches("_keypair.enc");
                                        println!("  - Network: {}", network_id_hex);
                                        found = true;
                                    }
                                }
                            }
                            if !found {
                                println!("  (none)");
                            }
                        } else {
                            println!("  (data directory not found)");
                        }
                    }
                }
                Err(e) => {
                    println!("No host identity found.");
                    println!("Error: {}", e);
                    println!();
                    println!("A new identity will be created when you first run the node.");
                }
            }
            println!("═══════════════════════════════════════════════════════════════");
        }

        IdentityAction::Wipe { force, data_dir } => {
            let data_dir = expand_tilde(&data_dir);

            if !force {
                println!(
                    "WARNING: This will permanently delete your host identity and all derived keys!"
                );
                println!("All stored endpoint keypairs will be lost.");
                println!();
                print!("Type 'DELETE' to confirm: ");
                use std::io::Write;
                std::io::stdout().flush()?;

                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim() != "DELETE" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Delete host key from storage
            let storage_selection = auto_storage()?;
            if storage_selection.storage.exists() {
                storage_selection.storage.delete()?;
                println!("Host identity deleted from secure storage.");
            } else {
                println!("No host identity found in secure storage.");
            }

            // Delete keypair files
            if data_dir.exists() {
                let mut deleted = 0;
                if let Ok(entries) = std::fs::read_dir(&data_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.ends_with("_keypair.enc")
                            && std::fs::remove_file(entry.path()).is_ok()
                        {
                            deleted += 1;
                        }
                    }
                }
                println!("Deleted {} encrypted keypair file(s).", deleted);
            }

            println!("Identity wiped. A new identity will be created on next run.");
        }

        IdentityAction::Fingerprint => {
            let storage_selection = auto_storage()?;
            match storage_selection.storage.load() {
                Ok(secret) => {
                    let host = HostIdentity::from_secret(secret);
                    println!("{}", host.fingerprint());
                }
                Err(_) => {
                    eprintln!("No host identity found.");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

/// Handle cache subcommands
async fn handle_cache_command(action: CacheAction) -> anyhow::Result<()> {
    match action {
        CacheAction::Stats { data_dir } => {
            let data_dir = expand_tilde(&data_dir);
            let cache_file = data_dir.join("bootstrap_cache.enc");

            println!("═══════════════════════════════════════════════════════════════");
            println!("                    BOOTSTRAP CACHE STATS");
            println!("═══════════════════════════════════════════════════════════════");
            println!("Cache file: {}", cache_file.display());

            if cache_file.exists() {
                let metadata = std::fs::metadata(&cache_file)?;
                println!("File size: {} bytes", metadata.len());

                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        let secs = elapsed.as_secs();
                        if secs < 60 {
                            println!("Last modified: {}s ago", secs);
                        } else if secs < 3600 {
                            println!("Last modified: {}m ago", secs / 60);
                        } else if secs < 86400 {
                            println!("Last modified: {}h ago", secs / 3600);
                        } else {
                            println!("Last modified: {}d ago", secs / 86400);
                        }
                    }
                }

                println!();
                println!("Note: Cache is encrypted. Detailed stats require decryption");
                println!("which needs a running node with host identity.");
            } else {
                println!("Cache file not found.");
                println!();
                println!("A new cache will be created when you run the node.");
            }
            println!("═══════════════════════════════════════════════════════════════");
        }

        CacheAction::Clear { force, data_dir } => {
            let data_dir = expand_tilde(&data_dir);
            let cache_file = data_dir.join("bootstrap_cache.enc");

            if !cache_file.exists() {
                println!("No cache file found at {}", cache_file.display());
                return Ok(());
            }

            if !force {
                println!("WARNING: This will delete your bootstrap cache.");
                println!("You will need to rediscover peers on next run.");
                println!();
                print!("Type 'CLEAR' to confirm: ");
                use std::io::Write;
                std::io::stdout().flush()?;

                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim() != "CLEAR" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            std::fs::remove_file(&cache_file)?;
            println!("Bootstrap cache cleared.");
        }
    }
    Ok(())
}

/// Handle doctor diagnostic command
async fn handle_doctor_command() -> anyhow::Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("                    ANT-QUIC DOCTOR");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    let mut issues: Vec<String> = Vec::new();
    let mut passed = 0;

    // Check 1: Host identity storage
    print!("Checking host identity storage... ");
    let storage_selection = match auto_storage() {
        Ok(s) => {
            println!("{} ({:?})", s.storage.backend_name(), s.security_level);
            if let Some(warning) = s.security_level.warning_message() {
                println!();
                println!("{}", warning);
                println!();
            }
            passed += 1;
            s
        }
        Err(e) => {
            println!("FAILED: {}", e);
            issues.push("Cannot access host identity storage.".to_string());
            // Create a fallback for the remaining checks
            return Ok(());
        }
    };

    // Check 2: Host identity exists
    print!("Checking host identity... ");
    match storage_selection.storage.load() {
        Ok(secret) => {
            let host = HostIdentity::from_secret(secret);
            println!("OK (fingerprint: {})", host.fingerprint());
            passed += 1;
        }
        Err(_) => {
            println!("NOT FOUND");
            issues.push("No host identity found. One will be created on first run.".to_string());
        }
    }

    // Check 3: Data directory
    print!("Checking data directory... ");
    let data_dir = dirs::home_dir()
        .map(|h| h.join(".ant-quic"))
        .unwrap_or_else(|| PathBuf::from(".ant-quic"));
    if data_dir.exists() {
        println!("OK ({})", data_dir.display());
        passed += 1;
    } else {
        println!("NOT FOUND");
        issues.push("Data directory not found. It will be created on first run.".to_string());
    }

    // Check 4: Bootstrap cache
    print!("Checking bootstrap cache... ");
    let cache_file = data_dir.join("bootstrap_cache.enc");
    if cache_file.exists() {
        let size = std::fs::metadata(&cache_file).map(|m| m.len()).unwrap_or(0);
        println!("OK ({} bytes)", size);
        passed += 1;
    } else {
        println!("NOT FOUND");
        issues.push("No bootstrap cache. Peers will be discovered on first run.".to_string());
    }

    // Check 5: Network connectivity (basic check)
    print!("Checking network... ");
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(socket) => {
            let addr = socket
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)));
            println!("OK (can bind UDP on {})", addr);
            passed += 1;
        }
        Err(e) => {
            println!("FAILED");
            issues.push(format!("Cannot bind UDP socket: {}", e));
        }
    }

    // Check 6: DNS resolution for bootstrap nodes
    print!("Checking DNS resolution... ");
    let mut dns_ok = 0;
    for node in DEFAULT_BOOTSTRAP_NODES {
        if tokio::net::lookup_host(node).await.is_ok() {
            dns_ok += 1;
        }
    }
    if dns_ok == DEFAULT_BOOTSTRAP_NODES.len() {
        println!("OK ({} nodes resolved)", dns_ok);
        passed += 1;
    } else if dns_ok > 0 {
        println!(
            "PARTIAL ({}/{} nodes resolved)",
            dns_ok,
            DEFAULT_BOOTSTRAP_NODES.len()
        );
        passed += 1;
    } else {
        println!("FAILED");
        issues.push("Cannot resolve any bootstrap nodes. Check your DNS settings.".to_string());
    }

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                         SUMMARY");
    println!("═══════════════════════════════════════════════════════════════");
    println!("Checks passed: {}/6", passed);

    if issues.is_empty() {
        println!();
        println!("All checks passed! Your system is ready to run ant-quic.");
    } else {
        println!();
        println!("Issues found:");
        for issue in &issues {
            println!("  ! {}", issue);
        }
    }
    println!("═══════════════════════════════════════════════════════════════");

    Ok(())
}
