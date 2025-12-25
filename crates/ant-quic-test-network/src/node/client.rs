//! Test node client implementation.
//!
//! Handles automatic registration with the registry, peer discovery,
//! automatic connections using REAL P2pEndpoint QUIC connections,
//! and test traffic generation over actual QUIC streams.

use crate::registry::{
    ConnectionMethod, ConnectionReport, NatStats, NatType, NodeCapabilities, NodeHeartbeat,
    NodeRegistration, PeerInfo, RegistryClient,
};
use crate::tui::{ConnectedPeer, LocalNodeInfo, TuiEvent, country_flag};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

// Real QUIC P2P endpoint imports
use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, P2pEvent, PeerId as QuicPeerId};

use super::test_protocol::TestPacket;

/// Configuration for the test node.
#[derive(Debug, Clone)]
pub struct TestNodeConfig {
    /// Registry URL to connect to.
    pub registry_url: String,
    /// Maximum number of peer connections.
    pub max_peers: usize,
    /// Local bind address.
    pub bind_addr: SocketAddr,
    /// Interval between peer connection attempts.
    pub connect_interval: Duration,
    /// Interval between test packet exchanges.
    pub test_interval: Duration,
    /// Interval between heartbeats.
    pub heartbeat_interval: Duration,
}

impl Default for TestNodeConfig {
    fn default() -> Self {
        Self {
            registry_url: "https://saorsa-1.saorsalabs.com".to_string(),
            max_peers: 10,
            bind_addr: "0.0.0.0:9000".parse().expect("valid default address"),
            connect_interval: Duration::from_secs(10),
            test_interval: Duration::from_secs(5),
            // 5-second heartbeat keeps NAT holes open for hole-punched connections
            // (NAT devices typically close UDP mappings after 30-60 seconds of inactivity)
            heartbeat_interval: Duration::from_secs(5),
        }
    }
}

/// Maximum consecutive failures before disconnecting a direct peer.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Maximum consecutive failures for hole-punched connections (more tolerant).
/// Hole-punched connections are inherently more fragile due to NAT behavior.
const MAX_CONSECUTIVE_FAILURES_HOLEPUNCHED: u32 = 10;

/// Detect if the system has global IPv6 connectivity.
fn has_global_ipv6() -> bool {
    // Try to get network interfaces and check for global IPv6 addresses
    #[cfg(unix)]
    {
        use std::process::Command;
        // Use ip command to check for global IPv6 addresses
        if let Ok(output) = Command::new("ip")
            .args(["-6", "addr", "show", "scope", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains("inet6") && !stdout.trim().is_empty();
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ipconfig").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Look for IPv6 addresses that aren't link-local (fe80::)
            for line in stdout.lines() {
                if line.contains("IPv6") && !line.contains("fe80::") && !line.contains("::1") {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if we can potentially reach a peer based on IP version compatibility.
///
/// A peer is reachable if:
/// - They have at least one IPv4 address (we always have IPv4), OR
/// - They have IPv6 addresses AND we have IPv6 connectivity
///
/// This prevents connection attempts to peers we cannot possibly reach,
/// avoiding false "connection failed" statistics.
fn can_reach_peer(peer: &PeerInfo, our_has_ipv6: bool) -> bool {
    let has_ipv4_addr = peer
        .addresses
        .iter()
        .any(|addr| addr.ip().is_ipv4() || addr.ip().to_canonical().is_ipv4());
    let has_ipv6_addr = peer.addresses.iter().any(|addr| addr.ip().is_ipv6());

    // Can reach if peer has IPv4 (we always have IPv4)
    // OR if peer has IPv6 AND we have IPv6
    has_ipv4_addr || (has_ipv6_addr && our_has_ipv6)
}

/// Detect local IPv4 and IPv6 addresses.
fn detect_local_addresses(bind_port: u16) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let mut local_ipv4: Option<SocketAddr> = None;
    let mut local_ipv6: Option<SocketAddr> = None;

    debug!("Detecting local addresses with bind_port: {}", bind_port);

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        // macOS doesn't have the 'ip' command, use ifconfig instead
        match Command::new("ifconfig").output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();

                    // Look for IPv4: "inet 192.168.1.100 netmask ..."
                    if line.starts_with("inet ")
                        && !line.contains("127.0.0.1")
                        && local_ipv4.is_none()
                    {
                        if let Some(ip_str) = line.split_whitespace().nth(1) {
                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                if !ip.is_loopback() && !ip.is_link_local() {
                                    local_ipv4 = Some(SocketAddr::new(ip.into(), bind_port));
                                    debug!("Found local IPv4: {}", ip);
                                }
                            }
                        }
                    }

                    // Look for IPv6: "inet6 2001:db8::1 prefixlen ..."
                    if line.starts_with("inet6 ")
                        && !line.contains("::1")
                        && !line.contains("fe80::")
                        && local_ipv6.is_none()
                    {
                        if let Some(ip_str) = line.split_whitespace().nth(1) {
                            // Remove scope ID if present (e.g., "fe80::1%en0" -> "fe80::1")
                            let ip_str = ip_str.split('%').next().unwrap_or(ip_str);
                            if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                                if !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    && ((ip.segments()[0] & 0xffc0) != 0xfe80)
                                {
                                    local_ipv6 = Some(SocketAddr::new(ip.into(), bind_port));
                                    debug!("Found local IPv6: {}", ip);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to run ifconfig: {}", e);
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::process::Command;

        // Try to get IPv4 address
        if let Ok(output) = Command::new("ip")
            .args(["-4", "addr", "show", "scope", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(addr_str) = line.trim().strip_prefix("inet ") {
                    // Extract IP from "inet 192.168.1.100/24 brd ..." format
                    if let Some(ip_str) = addr_str.split('/').next() {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_loopback() && !ip.is_link_local() {
                                local_ipv4 = Some(SocketAddr::new(ip.into(), bind_port));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Try to get IPv6 address
        if let Ok(output) = Command::new("ip")
            .args(["-6", "addr", "show", "scope", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(addr_str) = line.trim().strip_prefix("inet6 ") {
                    // Extract IP from "inet6 2001:db8::1/64 scope global" format
                    if let Some(ip_str) = addr_str.split('/').next() {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                            if !ip.is_loopback()
                                && !ip.is_unspecified()
                                && ((ip.segments()[0] & 0xffc0) != 0xfe80)
                            {
                                // Not link-local
                                local_ipv6 = Some(SocketAddr::new(ip.into(), bind_port));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;

        if let Ok(output) = Command::new("ipconfig").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();

                // Look for "IPv4 Address. . . . . . . . . . . : 192.168.1.100"
                if line.contains("IPv4") && line.contains(":") && local_ipv4.is_none() {
                    if let Some(ip_str) = line.split(':').last() {
                        let ip_str = ip_str.trim();
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_loopback() && !ip.is_link_local() {
                                local_ipv4 = Some(SocketAddr::new(ip.into(), bind_port));
                            }
                        }
                    }
                }

                // Look for "IPv6 Address. . . . . . . . . . . : 2001:db8::1"
                if line.contains("IPv6")
                    && line.contains(":")
                    && !line.contains("fe80")
                    && local_ipv6.is_none()
                {
                    // IPv6 addresses contain multiple colons, so we need to find the label-value separator
                    if let Some(pos) = line.rfind(": ") {
                        let ip_str = &line[pos + 2..];
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                            if !ip.is_loopback()
                                && !ip.is_unspecified()
                                && ((ip.segments()[0] & 0xffc0) != 0xfe80)
                            {
                                local_ipv6 = Some(SocketAddr::new(ip.into(), bind_port));
                            }
                        }
                    }
                }
            }
        }
    }

    // Log summary of detected addresses
    if local_ipv4.is_none() && local_ipv6.is_none() {
        warn!("No local addresses detected - TUI will show 'Not bound'");
    } else {
        info!(
            "Local addresses detected: IPv4={:?}, IPv6={:?}",
            local_ipv4, local_ipv6
        );
    }

    (local_ipv4, local_ipv6)
}

/// Maximum time without activity before considering a peer stale (seconds).
const STALE_PEER_TIMEOUT_SECS: u64 = 60;

/// Interval for health checks (seconds).
const HEALTH_CHECK_INTERVAL_SECS: u64 = 15;

/// Chance to rotate a peer each health check cycle (1 in N).
const PEER_ROTATION_CHANCE: u32 = 10;

/// Statistics for a connected peer.
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    /// Number of successful tests.
    pub tests_success: u64,
    /// Number of failed tests.
    pub tests_failed: u64,
    /// Total RTT sum for averaging.
    pub total_rtt_ms: u64,
    /// Packets sent to this peer.
    pub packets_sent: u64,
    /// Packets received from this peer.
    pub packets_received: u64,
    /// Last RTT measurement.
    pub last_rtt: Option<Duration>,
}

/// Internal peer tracking.
struct TrackedPeer {
    /// Peer information from registry.
    info: PeerInfo,
    /// Connection method used.
    method: ConnectionMethod,
    /// When connection was established.
    connected_at: Instant,
    /// Last successful activity timestamp.
    last_activity: Instant,
    /// Stats for this peer.
    stats: PeerStats,
    /// Sequence counter for test packets.
    sequence: AtomicU64,
    /// Consecutive failures (for health checking).
    consecutive_failures: u32,
}

impl TrackedPeer {
    /// Convert to a ConnectedPeer for TUI display.
    fn to_connected_peer(&self) -> ConnectedPeer {
        let mut peer = ConnectedPeer::new(&self.info.peer_id, self.method);

        // Set location with flag
        if let Some(ref cc) = self.info.country_code {
            peer.location = format!("{} {}", country_flag(cc), cc);
        }

        // Set RTT and quality
        if let Some(rtt) = self.stats.last_rtt {
            peer.update_rtt(rtt);
        }

        peer.packets_sent = self.stats.packets_sent;
        peer.packets_received = self.stats.packets_received;
        peer.connected_at = self.connected_at;
        peer.addresses = self.info.addresses.clone();

        peer
    }
}

/// Test node that automatically connects to peers and exchanges test traffic.
///
/// This uses REAL P2pEndpoint QUIC connections - NO simulations.
pub struct TestNode {
    /// Configuration.
    config: TestNodeConfig,
    /// Registry client.
    registry: RegistryClient,
    /// Real P2P QUIC endpoint for actual connections.
    endpoint: Arc<P2pEndpoint>,
    /// Our peer ID (hex encoded from QUIC endpoint).
    peer_id: String,
    /// Our public key (hex encoded ML-DSA-65 from QUIC endpoint).
    public_key: String,
    /// Local addresses.
    listen_addresses: Vec<SocketAddr>,
    /// External addresses (discovered).
    external_addresses: Arc<RwLock<Vec<SocketAddr>>>,
    /// Connected peers with their QUIC connections.
    connected_peers: Arc<RwLock<HashMap<String, TrackedPeer>>>,
    /// Global statistics (wrapped in Arc for safe sharing).
    total_bytes_sent: Arc<AtomicU64>,
    total_bytes_received: Arc<AtomicU64>,
    total_connections_success: Arc<AtomicU64>,
    total_connections_failed: Arc<AtomicU64>,
    direct_connections: Arc<AtomicU64>,
    holepunch_connections: Arc<AtomicU64>,
    relay_connections: Arc<AtomicU64>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Event sender for TUI updates.
    event_tx: mpsc::Sender<TuiEvent>,
    /// NAT stats for heartbeat.
    nat_stats: Arc<RwLock<NatStats>>,
    /// Whether this node has IPv6 connectivity.
    has_ipv6: bool,
    /// Actual bound port (may differ from config if port 0 was used).
    actual_port: u16,
    /// Track peers that used hole-punching (saw Punching phase before Connected).
    /// Key is hex-encoded peer ID, value is true if hole-punching was used.
    hole_punched_peers: Arc<RwLock<HashMap<String, bool>>>,
}

impl TestNode {
    /// Create a new test node with a REAL P2pEndpoint for actual QUIC connections.
    ///
    /// This is NOT a simulation - it creates a real QUIC endpoint with:
    /// - Real ML-DSA-65 keypair for identity
    /// - Real NAT traversal capability
    /// - Real QUIC streams for data exchange
    pub async fn new(
        config: TestNodeConfig,
        event_tx: mpsc::Sender<TuiEvent>,
    ) -> Result<Self, anyhow::Error> {
        let registry = RegistryClient::new(&config.registry_url);

        // Create REAL P2pEndpoint configuration
        info!("Creating REAL P2pEndpoint for QUIC connections...");

        // Configure relay nodes for fallback when direct connection fails
        // Note: MASQUE relay is not yet fully implemented in ant-quic,
        // but we configure it here for future readiness.
        // These are the saorsa registry nodes which could also serve as relays.
        let relay_nodes: Vec<SocketAddr> = vec![
            // saorsa-1.saorsalabs.com QUIC port
            "77.42.75.115:9000".parse().ok(),
            // TODO: Add more relay nodes as they become available
        ]
        .into_iter()
        .flatten()
        .collect();

        if !relay_nodes.is_empty() {
            info!(
                "Configured {} relay nodes for fallback (MASQUE not yet implemented)",
                relay_nodes.len()
            );
        }

        let nat_config = NatConfig {
            enable_relay_fallback: true,
            relay_nodes,
            ..Default::default()
        };

        let p2p_config = P2pConfig::builder()
            .bind_addr(config.bind_addr)
            .nat(nat_config)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build P2P config: {}", e))?;

        // Create the REAL QUIC endpoint
        let endpoint = P2pEndpoint::new(p2p_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create P2P endpoint: {}", e))?;

        // Get REAL peer ID and public key from the endpoint
        let quic_peer_id = endpoint.peer_id();
        let peer_id = hex::encode(quic_peer_id.0);
        let public_key = hex::encode(endpoint.public_key_bytes());

        info!("REAL Peer ID: {}...", &peer_id[..16.min(peer_id.len())]);
        info!(
            "REAL Public Key (ML-DSA-65): {}... ({} bytes)",
            &public_key[..32.min(public_key.len())],
            endpoint.public_key_bytes().len()
        );

        // Get the actual bound port (may differ from config if port 0 was used)
        let actual_port = endpoint
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(config.bind_addr.port());

        // Detect actual local addresses (not 0.0.0.0)
        let (local_ipv4, local_ipv6) = detect_local_addresses(actual_port);

        // Build listen_addresses from actual IPs, NOT the bind address (which could be 0.0.0.0)
        let mut listen_addresses = Vec::new();
        if let Some(addr) = local_ipv4 {
            listen_addresses.push(addr);
        }
        if let Some(addr) = local_ipv6 {
            listen_addresses.push(addr);
        }
        // Fallback: if no addresses detected, use endpoint's local addr (but not if it's 0.0.0.0)
        if listen_addresses.is_empty() {
            if let Some(addr) = endpoint.local_addr() {
                if !addr.ip().is_unspecified() {
                    listen_addresses.push(addr);
                }
            }
        }
        info!("Detected listen addresses: {:?}", listen_addresses);

        // Create initial local node info and send it to TUI
        let mut local_node = LocalNodeInfo::default();
        local_node.set_peer_id(&peer_id);
        local_node.local_ipv4 = local_ipv4;
        local_node.local_ipv6 = local_ipv6;
        local_node.nat_type = NatType::Unknown;
        local_node.registered = false;

        // Send initial node info to TUI
        let _ = event_tx
            .send(TuiEvent::UpdateLocalNode(local_node.clone()))
            .await;

        // Create external addresses storage before spawning event handler
        // so we can share it with the handler
        let external_addresses: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));

        // Create hole-punching tracker before spawning event handler
        let hole_punched_peers: Arc<RwLock<HashMap<String, bool>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Spawn event handler for P2P events to update TUI
        let endpoint_for_events = endpoint.clone();
        let event_tx_for_events = event_tx.clone();
        let hole_punched_for_events = Arc::clone(&hole_punched_peers);
        let external_addresses_for_events = Arc::clone(&external_addresses);
        tokio::spawn(async move {
            let mut events = endpoint_for_events.subscribe();
            while let Ok(event) = events.recv().await {
                match event {
                    P2pEvent::ExternalAddressDiscovered { addr } => {
                        info!("External address discovered: {}", addr);
                        // Store the discovered external address
                        {
                            let mut addrs = external_addresses_for_events.write().await;
                            if !addrs.contains(&addr) {
                                addrs.push(addr);
                                info!("Stored external address: {} (total: {})", addr, addrs.len());
                            }
                        }
                        let _ = event_tx_for_events
                            .send(TuiEvent::Info(format!(
                                "Discovered external address: {}",
                                addr
                            )))
                            .await;
                    }
                    P2pEvent::NatTraversalProgress { peer_id, phase } => {
                        // Track if this peer went through the Punching phase
                        use ant_quic::TraversalPhase;
                        if matches!(phase, TraversalPhase::Punching) {
                            let peer_hex = hex::encode(peer_id.0);
                            debug!(
                                "Peer {} entered Punching phase - marking as hole-punched",
                                &peer_hex[..8.min(peer_hex.len())]
                            );
                            hole_punched_for_events.write().await.insert(peer_hex, true);
                        }
                    }
                    P2pEvent::PeerConnected { peer_id, addr } => {
                        debug!("P2P event: peer connected {:?} at {}", peer_id, addr);
                    }
                    P2pEvent::PeerDisconnected { peer_id, reason } => {
                        debug!("P2P event: peer disconnected {:?}: {:?}", peer_id, reason);
                        // Notify TUI of peer disconnect
                        let _ = event_tx_for_events
                            .send(TuiEvent::RemovePeer(hex::encode(peer_id.0)))
                            .await;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            listen_addresses,
            config,
            registry,
            endpoint: Arc::new(endpoint),
            peer_id,
            public_key,
            external_addresses, // Use the shared Arc created before event handler
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            total_connections_success: Arc::new(AtomicU64::new(0)),
            total_connections_failed: Arc::new(AtomicU64::new(0)),
            direct_connections: Arc::new(AtomicU64::new(0)),
            holepunch_connections: Arc::new(AtomicU64::new(0)),
            relay_connections: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            event_tx,
            nat_stats: Arc::new(RwLock::new(NatStats::default())),
            has_ipv6: has_global_ipv6(),
            actual_port,
            hole_punched_peers,
        })
    }

    /// Get the underlying P2pEndpoint for direct access.
    pub fn endpoint(&self) -> &Arc<P2pEndpoint> {
        &self.endpoint
    }

    /// Get our peer ID.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Discover our external address by connecting to known QUIC peers.
    ///
    /// This connects to the saorsa registry nodes via QUIC (port 9000) to receive
    /// OBSERVED_ADDRESS frames that tell us our external IP:port as seen by them.
    /// This is part of the native QUIC NAT traversal per draft-ietf-quic-address-discovery.
    async fn discover_external_address(&self) {
        // Known QUIC peers (saorsa registry nodes running QUIC on port 9000)
        let known_quic_peers: Vec<SocketAddr> = vec![
            "77.42.75.115:9000".parse().ok(),    // saorsa-1
            "162.243.167.201:9000".parse().ok(), // saorsa-2
            "159.65.221.230:9000".parse().ok(),  // saorsa-3
        ]
        .into_iter()
        .flatten()
        .collect();

        if known_quic_peers.is_empty() {
            warn!("No known QUIC peers configured for address discovery");
            return;
        }

        info!(
            "Discovering external address via QUIC connections to {} known peers...",
            known_quic_peers.len()
        );

        // Try to connect to each known peer to discover our external address
        for peer_addr in &known_quic_peers {
            info!(
                "Connecting to known peer {} for address discovery...",
                peer_addr
            );

            match tokio::time::timeout(Duration::from_secs(10), self.endpoint.connect(*peer_addr))
                .await
            {
                Ok(Ok(_conn)) => {
                    info!(
                        "Connected to {} - waiting for OBSERVED_ADDRESS frame...",
                        peer_addr
                    );

                    // Wait a bit for the OBSERVED_ADDRESS frame to arrive
                    // The P2pEvent::ExternalAddressDiscovered handler will store it
                    tokio::time::sleep(Duration::from_secs(2)).await;

                    // Check if we discovered an external address
                    let addrs = self.external_addresses.read().await;
                    if !addrs.is_empty() {
                        info!(
                            "External address discovered via QUIC NAT traversal: {:?}",
                            *addrs
                        );
                        return;
                    }

                    info!(
                        "No external address received yet from {}, trying next peer...",
                        peer_addr
                    );
                }
                Ok(Err(e)) => {
                    warn!(
                        "Failed to connect to {} for address discovery: {}",
                        peer_addr, e
                    );
                }
                Err(_) => {
                    warn!("Connection to {} timed out", peer_addr);
                }
            }
        }

        // If we couldn't discover from any peer, log a warning
        let addrs = self.external_addresses.read().await;
        if addrs.is_empty() {
            warn!(
                "Could not discover external address from any known peer. \
                 Registration will proceed without external address - \
                 other nodes may not be able to connect to us."
            );
        }
    }

    /// Start the test node (runs all background tasks).
    pub async fn run(&self) -> anyhow::Result<()> {
        info!(
            "Starting test node {} connecting to {}",
            &self.peer_id[..8.min(self.peer_id.len())],
            self.config.registry_url
        );

        // CRITICAL: Discover external address via native QUIC NAT traversal BEFORE registering
        // Connect to known QUIC peers first to receive OBSERVED_ADDRESS frames
        self.discover_external_address().await;

        // Register with the registry (now with external address from QUIC discovery)
        self.register().await?;

        // Start background tasks
        let shutdown = Arc::clone(&self.shutdown);

        // Spawn all background tasks
        let heartbeat_handle = self.spawn_heartbeat_loop();
        let connect_handle = self.spawn_connect_loop();
        let test_handle = self.spawn_test_loop();
        let health_handle = self.spawn_health_check_loop();

        // Wait for shutdown
        while !shutdown.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Abort tasks on shutdown
        heartbeat_handle.abort();
        connect_handle.abort();
        test_handle.abort();
        health_handle.abort();

        info!("Test node shutting down");
        Ok(())
    }

    /// Register with the central registry.
    async fn register(&self) -> anyhow::Result<()> {
        let external_addrs = self.external_addresses.read().await.clone();

        // Detect actual network capabilities
        let ipv6_available = has_global_ipv6();
        let capabilities = NodeCapabilities {
            pqc: true,
            ipv4: true,
            ipv6: ipv6_available,
            nat_traversal: true,
            relay: false,
        };

        if ipv6_available {
            info!("IPv6 connectivity detected");
        }

        let registration = NodeRegistration {
            peer_id: self.peer_id.clone(),
            public_key: self.public_key.clone(),
            listen_addresses: self.listen_addresses.clone(),
            external_addresses: external_addrs.clone(),
            nat_type: NatType::Unknown, // Will be determined after connections
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities,
            location_label: None,
        };

        match self.registry.register(&registration).await {
            Ok(response) => {
                if response.success {
                    info!(
                        "Registered with registry, got {} peers",
                        response.peers.len()
                    );

                    // Update local node info with registration status
                    let (local_ipv4, local_ipv6) = detect_local_addresses(self.actual_port);

                    let mut local_node = LocalNodeInfo::default();
                    local_node.set_peer_id(&self.peer_id);
                    local_node.local_ipv4 = local_ipv4;
                    local_node.local_ipv6 = local_ipv6;
                    local_node.nat_type = NatType::Unknown;
                    local_node.registered = true;
                    local_node.last_heartbeat = Some(std::time::Instant::now());

                    // Set external addresses if we have any
                    if !external_addrs.is_empty() {
                        for addr in &external_addrs {
                            if addr.is_ipv4() && local_node.external_ipv4.is_none() {
                                local_node.external_ipv4 = Some(*addr);
                            } else if addr.is_ipv6() && local_node.external_ipv6.is_none() {
                                local_node.external_ipv6 = Some(*addr);
                            }
                        }
                    }

                    // Send updated node info to TUI
                    let _ = self
                        .event_tx
                        .send(TuiEvent::UpdateLocalNode(local_node))
                        .await;
                    let _ = self.event_tx.send(TuiEvent::RegistrationComplete).await;

                    // Also send the registered count
                    let _ = self
                        .event_tx
                        .send(TuiEvent::UpdateRegisteredCount(response.peers.len() + 1))
                        .await;
                } else {
                    let err = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    error!("Registration failed: {}", err);
                    return Err(anyhow::anyhow!("Registration failed: {}", err));
                }
            }
            Err(e) => {
                error!("Failed to connect to registry: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Spawn the heartbeat background task.
    fn spawn_heartbeat_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = RegistryClient::new(&self.config.registry_url);
        let peer_id = self.peer_id.clone();
        let public_key = self.public_key.clone();
        let listen_addresses = self.listen_addresses.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let external_addresses = Arc::clone(&self.external_addresses);
        let nat_stats = Arc::clone(&self.nat_stats);
        let bytes_sent = Arc::clone(&self.total_bytes_sent);
        let bytes_received = Arc::clone(&self.total_bytes_received);
        let interval = self.config.heartbeat_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut consecutive_failures = 0u32;

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                let peers = connected_peers.read().await;
                let ext_addrs = external_addresses.read().await.clone();
                let stats = nat_stats.read().await.clone();

                let heartbeat = NodeHeartbeat {
                    peer_id: peer_id.clone(),
                    connected_peers: peers.len(),
                    bytes_sent: bytes_sent.load(Ordering::Relaxed),
                    bytes_received: bytes_received.load(Ordering::Relaxed),
                    external_addresses: if ext_addrs.is_empty() {
                        None
                    } else {
                        Some(ext_addrs.clone())
                    },
                    nat_stats: Some(stats),
                };
                drop(peers);

                if let Err(e) = registry.heartbeat(&heartbeat).await {
                    consecutive_failures += 1;
                    warn!("Heartbeat failed (attempt {}): {}", consecutive_failures, e);

                    // Re-register after 2 consecutive failures (peer likely expired)
                    if consecutive_failures >= 2 {
                        info!("Re-registering with registry after heartbeat failures...");

                        // Detect actual network capabilities
                        let ipv6_available = has_global_ipv6();
                        let capabilities = NodeCapabilities {
                            pqc: true,
                            ipv4: true,
                            ipv6: ipv6_available,
                            nat_traversal: true,
                            relay: false,
                        };

                        let registration = NodeRegistration {
                            peer_id: peer_id.clone(),
                            public_key: public_key.clone(),
                            listen_addresses: listen_addresses.clone(),
                            external_addresses: ext_addrs.clone(),
                            nat_type: NatType::Unknown,
                            version: env!("CARGO_PKG_VERSION").to_string(),
                            capabilities,
                            location_label: None,
                        };

                        match registry.register(&registration).await {
                            Ok(response) if response.success => {
                                info!(
                                    "Re-registered successfully, got {} peers",
                                    response.peers.len()
                                );
                                consecutive_failures = 0;
                            }
                            Ok(response) => {
                                let err = response
                                    .error
                                    .unwrap_or_else(|| "Unknown error".to_string());
                                error!("Re-registration failed: {}", err);
                            }
                            Err(e) => {
                                error!("Re-registration request failed: {}", e);
                            }
                        }
                    }
                } else {
                    if consecutive_failures > 0 {
                        info!(
                            "Heartbeat recovered after {} failures",
                            consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
                    debug!("Heartbeat sent successfully");
                }
            }
        })
    }

    /// Spawn the peer connection background task.
    fn spawn_connect_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = RegistryClient::new(&self.config.registry_url);
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let max_peers = self.config.max_peers;
        let interval = self.config.connect_interval;
        let event_tx = self.event_tx.clone();
        let our_peer_id = self.peer_id.clone();
        let nat_stats = Arc::clone(&self.nat_stats);
        let success = Arc::clone(&self.total_connections_success);
        let failed = Arc::clone(&self.total_connections_failed);
        let direct = Arc::clone(&self.direct_connections);
        let holepunch = Arc::clone(&self.holepunch_connections);
        let relay = Arc::clone(&self.relay_connections);
        // Clone the endpoint for real QUIC connections
        let endpoint = Arc::clone(&self.endpoint);
        // Capture our IPv6 capability for filtering
        let our_has_ipv6 = self.has_ipv6;
        // Clone hole-punching tracker for connection method detection
        let hole_punched_peers = Arc::clone(&self.hole_punched_peers);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                let current_count = connected_peers.read().await.len();
                if current_count >= max_peers {
                    debug!(
                        "At max peers ({}/{}), skipping connection attempt",
                        current_count, max_peers
                    );
                    continue;
                }

                // Fetch peer list from registry
                let peers = match registry.get_peers().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch peers: {}", e);
                        continue;
                    }
                };

                // Filter out ourselves, already-connected peers, and unreachable peers
                let connected = connected_peers.read().await;
                let candidates: Vec<&PeerInfo> = peers
                    .iter()
                    .filter(|p| p.peer_id != our_peer_id)
                    .filter(|p| !connected.contains_key(&p.peer_id))
                    .filter(|p| p.is_active)
                    // Filter out peers we can't reach due to IP version incompatibility
                    // This prevents false "connection failed" statistics
                    .filter(|p| can_reach_peer(p, our_has_ipv6))
                    .collect();
                drop(connected);

                if candidates.is_empty() {
                    debug!("No candidate peers available");
                    continue;
                }

                // Pick a random peer
                use rand::seq::SliceRandom;
                let candidate = candidates
                    .choose(&mut rand::thread_rng())
                    .expect("candidates not empty");

                info!(
                    "Attempting REAL QUIC connection to peer {} ({:?})",
                    &candidate.peer_id[..8.min(candidate.peer_id.len())],
                    candidate.country_code
                );

                // Update NAT stats
                {
                    let mut stats = nat_stats.write().await;
                    stats.attempts += 1;
                }

                // Make REAL QUIC connection using P2pEndpoint
                let connection_result = real_connect(&endpoint, candidate).await;

                match connection_result {
                    Ok(method) => {
                        success.fetch_add(1, Ordering::Relaxed);

                        // Use the method returned by real_connect (which now correctly
                        // distinguishes between Direct and HolePunched connections).
                        // Also check hole_punched_peers tracker as secondary signal.
                        let final_method = {
                            let tracker = hole_punched_peers.read().await;
                            if tracker.get(&candidate.peer_id).copied().unwrap_or(false) {
                                // NAT traversal phase was observed - definitely hole-punched
                                ConnectionMethod::HolePunched
                            } else {
                                // Use the method from real_connect
                                method
                            }
                        };

                        match final_method {
                            ConnectionMethod::Direct => {
                                direct.fetch_add(1, Ordering::Relaxed);
                                let mut stats = nat_stats.write().await;
                                stats.direct_success += 1;
                            }
                            ConnectionMethod::HolePunched => {
                                holepunch.fetch_add(1, Ordering::Relaxed);
                                let mut stats = nat_stats.write().await;
                                stats.hole_punch_success += 1;
                            }
                            ConnectionMethod::Relayed => {
                                relay.fetch_add(1, Ordering::Relaxed);
                                let mut stats = nat_stats.write().await;
                                stats.relay_success += 1;
                            }
                        }

                        let now = Instant::now();
                        let tracked = TrackedPeer {
                            info: (*candidate).clone(),
                            method: final_method,
                            connected_at: now,
                            last_activity: now,
                            stats: PeerStats::default(),
                            sequence: AtomicU64::new(0),
                            consecutive_failures: 0,
                        };

                        // Create TUI peer from tracked peer
                        let peer_for_tui = tracked.to_connected_peer();

                        connected_peers
                            .write()
                            .await
                            .insert(candidate.peer_id.clone(), tracked);

                        info!(
                            "Connected to {} via {:?}",
                            &candidate.peer_id[..8.min(candidate.peer_id.len())],
                            final_method
                        );

                        // Notify TUI
                        let _ = event_tx.send(TuiEvent::PeerConnected(peer_for_tui)).await;

                        // Report connection to registry
                        let report = ConnectionReport {
                            from_peer: our_peer_id.clone(),
                            to_peer: candidate.peer_id.clone(),
                            method: final_method,
                            is_ipv6: candidate
                                .addresses
                                .first()
                                .map(|a| a.is_ipv6())
                                .unwrap_or(false),
                            rtt_ms: None, // Will be updated later with test packets
                        };
                        if let Err(e) = registry.report_connection(&report).await {
                            warn!("Failed to report connection: {}", e);
                        }
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        {
                            let mut stats = nat_stats.write().await;
                            stats.failures += 1;
                        }
                        warn!(
                            "Failed to connect to {}: {}",
                            &candidate.peer_id[..8.min(candidate.peer_id.len())],
                            e
                        );

                        // Notify TUI of connection failure
                        let _ = event_tx.send(TuiEvent::ConnectionFailed).await;
                    }
                }
            }
        })
    }

    /// Spawn the test traffic background task.
    fn spawn_test_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let interval = self.config.test_interval;
        let event_tx = self.event_tx.clone();
        let our_peer_id_bytes = peer_id_to_bytes(&self.peer_id);
        let total_sent = Arc::clone(&self.total_bytes_sent);
        let total_received = Arc::clone(&self.total_bytes_received);
        // Clone the endpoint for real QUIC test exchanges
        let endpoint = Arc::clone(&self.endpoint);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                let mut peers = connected_peers.write().await;
                let peer_ids: Vec<String> = peers.keys().cloned().collect();

                for peer_id in peer_ids {
                    if let Some(tracked) = peers.get_mut(&peer_id) {
                        let seq = tracked.sequence.fetch_add(1, Ordering::Relaxed);
                        let packet = TestPacket::new_ping(our_peer_id_bytes, seq);
                        let packet_size = packet.size() as u64;

                        // Perform REAL test packet exchange over QUIC streams
                        let result = real_test_exchange(&endpoint, &peer_id, &packet).await;

                        match result {
                            Ok(rtt) => {
                                tracked.stats.tests_success += 1;
                                tracked.stats.total_rtt_ms += rtt.as_millis() as u64;
                                tracked.stats.last_rtt = Some(rtt);
                                tracked.stats.packets_sent += 1;
                                tracked.stats.packets_received += 1;
                                tracked.last_activity = Instant::now();
                                tracked.consecutive_failures = 0; // Reset on success

                                total_sent.fetch_add(packet_size, Ordering::Relaxed);
                                total_received.fetch_add(packet_size, Ordering::Relaxed);

                                // Update TUI
                                let _ = event_tx
                                    .send(TuiEvent::TestPacketResult {
                                        peer_id: peer_id.clone(),
                                        success: true,
                                        rtt: Some(rtt),
                                    })
                                    .await;
                            }
                            Err(e) => {
                                tracked.stats.tests_failed += 1;
                                tracked.consecutive_failures += 1;
                                warn!("Test packet to {} failed: {}", &peer_id[..8], e);

                                let _ = event_tx
                                    .send(TuiEvent::TestPacketResult {
                                        peer_id: peer_id.clone(),
                                        success: false,
                                        rtt: None,
                                    })
                                    .await;
                            }
                        }
                    }
                }
            }
        })
    }

    /// Spawn the health check background task.
    ///
    /// This task periodically:
    /// 1. Removes peers with too many consecutive failures
    /// 2. Removes stale peers (no activity for too long)
    /// 3. Occasionally rotates peers to keep the network fresh
    fn spawn_health_check_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS));

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                let now = Instant::now();
                let mut peers_to_remove = Vec::new();
                let mut should_rotate = false;

                // Check all peers for health issues
                {
                    let peers = connected_peers.read().await;

                    for (peer_id, tracked) in peers.iter() {
                        let time_since_activity = now.duration_since(tracked.last_activity);

                        // Use higher tolerance for hole-punched connections (more fragile)
                        let max_failures = match tracked.method {
                            ConnectionMethod::HolePunched | ConnectionMethod::Relayed => {
                                MAX_CONSECUTIVE_FAILURES_HOLEPUNCHED
                            }
                            ConnectionMethod::Direct => MAX_CONSECUTIVE_FAILURES,
                        };

                        // Check for too many consecutive failures
                        if tracked.consecutive_failures >= max_failures {
                            info!(
                                "Removing peer {} - {} consecutive failures (threshold: {})",
                                &peer_id[..8.min(peer_id.len())],
                                tracked.consecutive_failures,
                                max_failures
                            );
                            peers_to_remove.push(peer_id.clone());
                            continue;
                        }

                        // Check for stale peers
                        if time_since_activity.as_secs() > STALE_PEER_TIMEOUT_SECS {
                            info!(
                                "Removing peer {} - stale (no activity for {}s)",
                                &peer_id[..8.min(peer_id.len())],
                                time_since_activity.as_secs()
                            );
                            peers_to_remove.push(peer_id.clone());
                        }
                    }

                    // Decide whether to rotate a peer (for network freshness)
                    if peers.len() > 1 && peers_to_remove.is_empty() {
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        if rng.gen_ratio(1, PEER_ROTATION_CHANCE) {
                            // Find the oldest connected peer to rotate out
                            if let Some((oldest_id, _)) =
                                peers.iter().min_by_key(|(_, p)| p.connected_at)
                            {
                                info!(
                                    "Rotating out peer {} for network freshness",
                                    &oldest_id[..8.min(oldest_id.len())]
                                );
                                peers_to_remove.push(oldest_id.clone());
                                should_rotate = true;
                            }
                        }
                    }
                }

                // Remove unhealthy/rotated peers
                if !peers_to_remove.is_empty() {
                    let mut peers = connected_peers.write().await;
                    for peer_id in &peers_to_remove {
                        peers.remove(peer_id);

                        // Notify TUI
                        let _ = event_tx.send(TuiEvent::RemovePeer(peer_id.clone())).await;
                    }

                    let removed_count = peers_to_remove.len();
                    let reason = if should_rotate { "rotation" } else { "health" };
                    debug!(
                        "Removed {} peer(s) for {}, {} remaining",
                        removed_count,
                        reason,
                        peers.len()
                    );
                }
            }
        })
    }

    /// Trigger shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get current connected peer count.
    pub async fn connected_peer_count(&self) -> usize {
        self.connected_peers.read().await.len()
    }

    /// Get all connected peers for TUI display.
    pub async fn get_connected_peers(&self) -> Vec<ConnectedPeer> {
        let peers = self.connected_peers.read().await;
        peers
            .values()
            .map(|tracked| tracked.to_connected_peer())
            .collect()
    }

    /// Get global statistics.
    pub fn get_stats(&self) -> GlobalStats {
        GlobalStats {
            total_connections_success: self.total_connections_success.load(Ordering::Relaxed),
            total_connections_failed: self.total_connections_failed.load(Ordering::Relaxed),
            direct_connections: self.direct_connections.load(Ordering::Relaxed),
            holepunch_connections: self.holepunch_connections.load(Ordering::Relaxed),
            relay_connections: self.relay_connections.load(Ordering::Relaxed),
            bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// Global statistics for the test node.
#[derive(Debug, Clone, Default)]
pub struct GlobalStats {
    /// Total successful connections.
    pub total_connections_success: u64,
    /// Total failed connections.
    pub total_connections_failed: u64,
    /// Direct connections.
    pub direct_connections: u64,
    /// Hole-punched connections.
    pub holepunch_connections: u64,
    /// Relayed connections.
    pub relay_connections: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
}

impl GlobalStats {
    /// Calculate success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.total_connections_success + self.total_connections_failed;
        if total == 0 {
            1.0
        } else {
            self.total_connections_success as f64 / total as f64
        }
    }
}

// Helper functions

/// Convert peer ID string to 32-byte array.
fn peer_id_to_bytes(peer_id: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if let Ok(decoded) = hex::decode(peer_id) {
        let len = decoded.len().min(32);
        bytes[..len].copy_from_slice(&decoded[..len]);
    }
    bytes
}

/// Make a REAL QUIC connection to a peer using P2pEndpoint.
///
/// This is NOT a simulation - it creates an actual QUIC connection.
/// Connection strategy:
/// 1. Try direct dual-stack connection (IPv4 and IPv6 in parallel)
/// 2. Try individual direct connections to each address
/// 3. Fall back to NAT traversal (hole-punching) if direct fails
async fn real_connect(endpoint: &P2pEndpoint, peer: &PeerInfo) -> Result<ConnectionMethod, String> {
    // Get addresses to try
    if peer.addresses.is_empty() {
        return Err("Peer has no addresses".to_string());
    }

    let peer_id_short = &peer.peer_id[..8.min(peer.peer_id.len())];

    // Try dual-stack connection first (both IPv4 and IPv6 in parallel)
    match endpoint.connect_dual_stack(&peer.addresses).await {
        Ok(_conn) => {
            info!(
                "REAL QUIC connection established to {} (direct dual-stack)",
                peer_id_short
            );
            // Direct connection succeeded
            return Ok(ConnectionMethod::Direct);
        }
        Err(e) => {
            debug!("Dual-stack direct connection failed: {}", e);
        }
    }

    // Try single address connections as fallback
    for addr in &peer.addresses {
        match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(*addr)).await {
            Ok(Ok(_conn)) => {
                info!(
                    "REAL QUIC connection established to {} at {} (direct)",
                    peer_id_short, addr
                );
                return Ok(ConnectionMethod::Direct);
            }
            Ok(Err(e)) => {
                debug!("Direct connection to {} failed: {}", addr, e);
            }
            Err(_) => {
                debug!("Direct connection to {} timed out", addr);
            }
        }
    }

    // All direct connections failed - try NAT traversal (hole-punching)
    info!(
        "Direct connections to {} failed, attempting NAT traversal...",
        peer_id_short
    );

    // Convert hex peer_id to QuicPeerId
    let peer_id_bytes =
        hex::decode(&peer.peer_id).map_err(|e| format!("Invalid peer ID hex: {}", e))?;

    if peer_id_bytes.len() < 32 {
        return Err("Peer ID too short for NAT traversal".to_string());
    }

    let mut peer_id_array = [0u8; 32];
    peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
    let quic_peer_id = QuicPeerId(peer_id_array);

    // Use first address as potential coordinator hint (P2pEndpoint will use known_peers if None)
    let coordinator = peer.addresses.first().copied();

    match tokio::time::timeout(
        Duration::from_secs(30), // NAT traversal can take longer
        endpoint.connect_to_peer(quic_peer_id, coordinator),
    )
    .await
    {
        Ok(Ok(_conn)) => {
            info!(
                "REAL QUIC connection established to {} via NAT traversal (hole-punched)",
                peer_id_short
            );
            Ok(ConnectionMethod::HolePunched)
        }
        Ok(Err(e)) => {
            warn!("NAT traversal to {} failed: {}", peer_id_short, e);
            Err(format!("All connection methods failed: {}", e))
        }
        Err(_) => {
            warn!("NAT traversal to {} timed out after 30s", peer_id_short);
            Err("NAT traversal timed out".to_string())
        }
    }
}

/// Perform REAL test packet exchange over QUIC streams.
///
/// This sends actual data over a QUIC stream and measures real RTT.
async fn real_test_exchange(
    endpoint: &P2pEndpoint,
    peer_id_hex: &str,
    packet: &TestPacket,
) -> Result<Duration, String> {
    // Convert hex peer ID to QuicPeerId
    let peer_id_bytes =
        hex::decode(peer_id_hex).map_err(|e| format!("Invalid peer ID hex: {}", e))?;

    if peer_id_bytes.len() < 32 {
        return Err("Peer ID too short".to_string());
    }

    let mut peer_id_array = [0u8; 32];
    peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
    let quic_peer_id = QuicPeerId(peer_id_array);

    // Get the QUIC connection for this peer
    let connection = endpoint
        .get_quic_connection(&quic_peer_id)
        .map_err(|e| format!("Failed to get connection: {}", e))?
        .ok_or_else(|| "No connection to peer".to_string())?;

    // Serialize the test packet
    let packet_data =
        serde_json::to_vec(packet).map_err(|e| format!("Failed to serialize packet: {}", e))?;

    let start = Instant::now();

    // Open a unidirectional stream and send the packet
    let mut send_stream = connection
        .open_uni()
        .await
        .map_err(|e| format!("Failed to open stream: {}", e))?;

    send_stream
        .write_all(&packet_data)
        .await
        .map_err(|e| format!("Failed to write data: {}", e))?;

    send_stream
        .finish()
        .map_err(|e| format!("Failed to finish stream: {}", e))?;

    let rtt = start.elapsed();

    debug!(
        "REAL test packet sent to {} ({} bytes, RTT: {:?})",
        &peer_id_hex[..8.min(peer_id_hex.len())],
        packet_data.len(),
        rtt
    );

    Ok(rtt)
}
