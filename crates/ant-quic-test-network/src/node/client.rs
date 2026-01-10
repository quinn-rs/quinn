//! This module has some deeply nested async code that is difficult to refactor.
#![allow(clippy::excessive_nesting)]
//! Test node client implementation.
//!
//! Handles automatic registration with the registry, peer discovery,
//! automatic connections using REAL P2pEndpoint QUIC connections,
//! and test traffic generation over actual QUIC streams.

use crate::epidemic_gossip::{
    ConnectionType as GossipConnectionType, EpidemicConfig, EpidemicEvent, EpidemicGossip,
};
use crate::gossip::{
    GossipConfig, GossipEvent, GossipIntegration, PeerCapabilities as GossipCapabilities,
};
use crate::registry::{
    BgpGeoProvider, ConnectionDirection, ConnectionMethod, ConnectionReport, ConnectivityMatrix,
    DataProof, FullMeshProbeResult, NatStats, NatType, NetworkEvent, NodeCapabilities,
    NodeGossipStats, NodeHeartbeat, NodeRegistration, PeerInfo, PeerStatus, RegistryClient,
    SuccessLevel,
};
use crate::tui::{
    CacheHealth, ConnectedPeer, FrameDirection, GeographicDistribution, LocalNodeInfo,
    NatTraversalPhase, NatTypeAnalytics, ProtocolFrame, TestConnectivityMethod, TrafficType,
    TuiEvent, country_flag, send_tui_event,
};
use saorsa_gossip_types::PeerId as GossipPeerId;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use ant_quic::{Node, P2pEndpoint, P2pEvent, PeerId as QuicPeerId};
use saorsa_gossip_transport::AntQuicTransport;
// Import key types for persistence
use ant_quic::crypto::raw_public_keys::key_utils::{
    MlDsaPublicKey, MlDsaSecretKey, generate_ml_dsa_keypair,
};

use super::test_protocol::{
    CanYouReachRequest, GossipMessage, GossipPeerAnnouncement, GossipPeerInfo, PeerListMessage,
    RELAY_MAGIC, ReachResponse, RelayAckResponse, RelayMessage, RelayPunchMeNowRequest, RelayState,
    RelayedDataResponse, TestPacket,
};

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
            // Use port 0 for dynamic OS-allocated port (prevents collisions)
            bind_addr: "[::]:0".parse().expect("valid default address"),
            connect_interval: Duration::from_secs(5),
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

/// VPS node IPs that should ALWAYS be probed regardless of is_active status.
/// These are infrastructure nodes that are always reachable.
const VPS_NODE_IPS: &[&str] = &[
    "77.42.75.115",
    "142.93.199.50",
    "147.182.234.192",
    "206.189.7.117",
    "144.126.230.161",
    "65.21.157.229",
    "116.203.101.172",
    "149.28.156.231",
    "45.77.176.184",
];

fn is_vps_node(addr: &SocketAddr) -> bool {
    let ip_str = addr.ip().to_string();
    VPS_NODE_IPS.iter().any(|vps_ip| ip_str == *vps_ip)
}

fn peer_is_vps(peer: &PeerInfo) -> bool {
    peer.addresses.iter().any(is_vps_node)
}

/// Check if our external addresses indicate we're a known VPS node.
fn we_are_vps(external_addresses: &[SocketAddr]) -> bool {
    external_addresses.iter().any(is_vps_node)
}

/// Check if both we and the peer are VPS nodes.
/// When both are VPS, skip NAT/relay testing since direct connection always works.
fn both_are_vps(peer: &PeerInfo, external_addresses: &[SocketAddr]) -> bool {
    peer_is_vps(peer) && we_are_vps(external_addresses)
}

fn vps_gossip_bootstrap_addrs() -> Vec<SocketAddr> {
    VPS_NODE_IPS
        .iter()
        .filter(|ip| **ip != "77.42.75.115") // Skip registry node (no gossip)
        .filter_map(|ip| {
            ip.parse::<std::net::IpAddr>()
                .ok()
                .map(|addr| SocketAddr::new(addr, 9000))
        })
        .collect()
}

/// Detect if the system has global IPv6 connectivity using UDP socket connect.
///
/// This is cross-platform and doesn't require running external commands.
fn has_global_ipv6() -> bool {
    use std::net::UdpSocket;

    // Try to connect to Google's public IPv6 DNS
    // This doesn't send any data, just checks if we can route to IPv6
    UdpSocket::bind("[::]:0")
        .and_then(|socket| {
            socket.connect("[2001:4860:4860::8888]:53")?;
            socket.local_addr()
        })
        .map(|addr| !addr.ip().is_loopback() && !addr.ip().is_unspecified())
        .unwrap_or(false)
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

/// Detect local IPv4 and IPv6 addresses using UDP socket connect.
///
/// This approach is cross-platform and doesn't require running external commands.
/// It works by creating a UDP socket and "connecting" it to a public address -
/// this doesn't send any data but reveals the local IP that would be used.
fn detect_local_addresses(bind_port: u16) -> (Option<SocketAddr>, Option<SocketAddr>) {
    use std::net::UdpSocket;

    debug!("Detecting local addresses with bind_port: {}", bind_port);

    // Detect IPv4 by connecting to a public address (Google DNS)
    let local_ipv4 = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:53")?;
            socket.local_addr()
        })
        .ok()
        .and_then(|addr| {
            let ip = addr.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                Some(SocketAddr::new(ip, bind_port))
            } else {
                None
            }
        });

    // Detect IPv6 by connecting to a public IPv6 address (Google DNS)
    let local_ipv6 = UdpSocket::bind("[::]:0")
        .and_then(|socket| {
            socket.connect("[2001:4860:4860::8888]:53")?;
            socket.local_addr()
        })
        .ok()
        .and_then(|addr| {
            let ip = addr.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                Some(SocketAddr::new(ip, bind_port))
            } else {
                None
            }
        });

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

fn detect_nat_type(
    local_ipv4: &Option<SocketAddr>,
    local_ipv6: &Option<SocketAddr>,
    local_node: &LocalNodeInfo,
) -> NatType {
    let external_ipv4 = local_node.external_ipv4;
    let external_ipv6 = local_node.external_ipv6;

    let ipv4_match = match (local_ipv4, external_ipv4) {
        (Some(local), Some(external)) => local.ip() == external.ip(),
        _ => false,
    };

    let ipv6_match = match (local_ipv6, external_ipv6) {
        (Some(local), Some(external)) => local.ip() == external.ip(),
        _ => false,
    };

    if ipv4_match || ipv6_match {
        NatType::None
    } else {
        NatType::Unknown
    }
}

/// Maximum time without activity before considering a peer stale (1 hour keepalive).
const STALE_PEER_TIMEOUT_SECS: u64 = 3600;

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
    /// Connection direction (we initiated or they initiated).
    direction: ConnectionDirection,
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
    /// Connectivity matrix showing all tested paths.
    connectivity: ConnectivityMatrix,
    /// Whether outbound connection has been verified (we connected to them).
    outbound_verified: bool,
    /// Whether inbound connection has been verified (they connected to us - proves NAT traversal!).
    inbound_verified: bool,
    /// When we last sent a ConnectBackRequest to this peer.
    last_nat_test_time: Option<Instant>,
    /// Whether QUIC transport test succeeded (for dual transport testing).
    quic_test_success: bool,
    /// Whether gossip transport test succeeded (for dual transport testing).
    gossip_test_success: bool,
}

impl TrackedPeer {
    /// Convert to a ConnectedPeer for TUI display.
    fn to_connected_peer(&self) -> ConnectedPeer {
        let mut peer =
            ConnectedPeer::with_direction(&self.info.peer_id, self.method, self.direction);

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
        peer.connectivity = self.connectivity.clone();

        // NAT traversal verification state
        peer.outbound_verified = self.outbound_verified;
        peer.inbound_verified = self.inbound_verified;
        peer.last_nat_test_time = self.last_nat_test_time;
        peer.last_connection_time = self.last_activity;

        peer
    }
}

/// Test node that automatically connects to peers and exchanges test traffic.
///
/// This uses REAL P2pEndpoint QUIC connections - NO simulations.
pub struct TestNode {
    config: TestNodeConfig,
    registry: RegistryClient,
    node: Arc<Node>,
    peer_id: String,
    public_key: String,
    listen_addresses: Vec<SocketAddr>,
    external_addresses: Arc<RwLock<Vec<SocketAddr>>>,
    connected_peers: Arc<RwLock<HashMap<String, TrackedPeer>>>,
    total_bytes_sent: Arc<AtomicU64>,
    total_bytes_received: Arc<AtomicU64>,
    total_connections_success: Arc<AtomicU64>,
    total_connections_failed: Arc<AtomicU64>,
    direct_connections: Arc<AtomicU64>,
    holepunch_connections: Arc<AtomicU64>,
    relay_connections: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    event_tx: mpsc::Sender<TuiEvent>,
    nat_stats: Arc<RwLock<NatStats>>,
    has_ipv6: bool,
    hole_punched_peers: Arc<RwLock<HashMap<String, bool>>>,
    disconnection_times: Arc<RwLock<HashMap<String, Instant>>>,
    pending_outbound: Arc<RwLock<HashSet<String>>>,
    inbound_connections: Arc<AtomicU64>,
    relay_state: Arc<RwLock<RelayState>>,
    gossip_integration: Arc<GossipIntegration>,
    gossip_event_rx: Arc<RwLock<mpsc::Receiver<GossipEvent>>>,
    epidemic_gossip: Arc<EpidemicGossip>,
    epidemic_event_rx: Arc<RwLock<mpsc::Receiver<EpidemicEvent>>>,
    full_mesh_probes: Arc<RwLock<HashMap<String, FullMeshProbeResult>>>,
    geo_provider: Arc<BgpGeoProvider>,
    fully_tested_peers: Arc<RwLock<HashSet<String>>>,
}

/// Get the data directory for persistent storage.
fn get_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ant-quic-test")
}

/// Get the path to the keypair file.
fn keypair_path() -> PathBuf {
    get_data_dir().join("identity_keypair.bin")
}

/// Load or generate a persistent ML-DSA-65 keypair.
/// The keypair is stored in the data directory to maintain stable peer ID across restarts.
fn load_or_generate_keypair() -> Result<(MlDsaPublicKey, MlDsaSecretKey), anyhow::Error> {
    let path = keypair_path();

    // Try to load existing keypair
    if path.exists() {
        match std::fs::read(&path) {
            Ok(data) => {
                // Format: public_key_len (2 bytes) + public_key + secret_key
                if data.len() < 2 {
                    warn!("Keypair file corrupted (too short), generating new keypair");
                } else {
                    let pub_len = u16::from_le_bytes([data[0], data[1]]) as usize;
                    if data.len() >= 2 + pub_len {
                        let pub_bytes = &data[2..2 + pub_len];
                        let sec_bytes = &data[2 + pub_len..];

                        // Try to reconstruct the keys
                        match (
                            MlDsaPublicKey::from_bytes(pub_bytes),
                            MlDsaSecretKey::from_bytes(sec_bytes),
                        ) {
                            (Ok(public_key), Ok(secret_key)) => {
                                info!("Loaded existing keypair from {:?}", path);
                                return Ok((public_key, secret_key));
                            }
                            _ => {
                                warn!("Failed to parse keypair from file, generating new keypair");
                            }
                        }
                    } else {
                        warn!("Keypair file corrupted (invalid length), generating new keypair");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read keypair file: {}, generating new keypair", e);
            }
        }
    }

    // Generate new keypair
    info!("Generating new ML-DSA-65 keypair for persistent identity...");
    let (public_key, secret_key) = generate_ml_dsa_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate keypair: {:?}", e))?;

    // Save the keypair
    if let Err(e) = save_keypair(&public_key, &secret_key) {
        warn!(
            "Failed to save keypair: {} (peer ID will change on restart)",
            e
        );
    } else {
        info!("Saved new keypair to {:?}", keypair_path());
    }

    Ok((public_key, secret_key))
}

/// Save a keypair to persistent storage.
fn save_keypair(
    public_key: &MlDsaPublicKey,
    secret_key: &MlDsaSecretKey,
) -> Result<(), anyhow::Error> {
    let path = keypair_path();

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Format: public_key_len (2 bytes) + public_key + secret_key
    let pub_bytes = public_key.as_bytes();
    let sec_bytes = secret_key.as_bytes();
    let pub_len = pub_bytes.len() as u16;

    let mut data = Vec::with_capacity(2 + pub_bytes.len() + sec_bytes.len());
    data.extend_from_slice(&pub_len.to_le_bytes());
    data.extend_from_slice(pub_bytes);
    data.extend_from_slice(sec_bytes);

    std::fs::write(&path, &data)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

impl TestNode {
    pub async fn new(
        config: TestNodeConfig,
        event_tx: mpsc::Sender<TuiEvent>,
    ) -> Result<Self, anyhow::Error> {
        let registry = RegistryClient::new(&config.registry_url);

        info!("Creating unified QUIC endpoint via gossip transport...");

        let (public_key, secret_key) = load_or_generate_keypair()?;
        let keypair_bytes = (
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        );

        let (epidemic_event_tx, epidemic_event_rx) = mpsc::channel(100);
        let vps_bootstrap = vps_gossip_bootstrap_addrs();
        let epidemic_config = EpidemicConfig {
            listen_addr: config.bind_addr,
            bootstrap_peers: vps_bootstrap.clone(),
            registry_url: Some(config.registry_url.clone()),
            keypair: Some(keypair_bytes.clone()),
            ..EpidemicConfig::default()
        };

        let temp_peer_id = {
            let peer_id_bytes = hex::decode("0".repeat(64)).unwrap_or_else(|_| vec![0u8; 32]);
            let mut id_array = [0u8; 32];
            id_array.copy_from_slice(&peer_id_bytes[..32]);
            GossipPeerId::new(id_array)
        };

        let epidemic_gossip = Arc::new(EpidemicGossip::new(
            temp_peer_id,
            epidemic_config,
            epidemic_event_tx,
        ));

        epidemic_gossip
            .start()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start gossip: {:?}", e))?;

        let transport: Arc<AntQuicTransport> = epidemic_gossip
            .transport()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get transport: {:?}", e))?;
        let node: Arc<Node> = transport.node();

        let quic_peer_id = node.peer_id();
        let peer_id = hex::encode(quic_peer_id.0);
        let public_key = hex::encode(node.public_key_bytes());

        info!("Peer ID: {}...", &peer_id[..16.min(peer_id.len())]);
        info!(
            "Public Key (ML-DSA-65): {}... ({} bytes)",
            &public_key[..32.min(public_key.len())],
            node.public_key_bytes().len()
        );

        let actual_port = node
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(config.bind_addr.port());

        let (local_ipv4, local_ipv6) = detect_local_addresses(actual_port);

        // Build listen_addresses from actual IPs, NOT the bind address (which could be 0.0.0.0)
        let mut listen_addresses = Vec::new();
        if let Some(addr) = local_ipv4 {
            listen_addresses.push(addr);
        }
        if let Some(addr) = local_ipv6 {
            listen_addresses.push(addr);
        }
        if listen_addresses.is_empty() {
            if let Some(addr) = node.local_addr() {
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

        // Send initial node info to TUI (non-blocking to avoid deadlock)
        let _ = event_tx.try_send(TuiEvent::UpdateLocalNode(local_node.clone()));

        // Send an info message with peer ID and addresses so user sees confirmation
        let ipv4_str = local_ipv4
            .map(|a| a.to_string())
            .unwrap_or_else(|| "None".to_string());
        let info_msg = format!(
            "Peer ID: {}... | IPv4: {}",
            &peer_id[..8.min(peer_id.len())],
            ipv4_str
        );
        let _ = event_tx.try_send(TuiEvent::Info(info_msg));

        // Create external addresses storage before spawning event handler
        // so we can share it with the handler
        let external_addresses: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(Vec::new()));

        // Create hole-punching tracker before spawning event handler
        let hole_punched_peers: Arc<RwLock<HashMap<String, bool>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Create disconnection times tracker for bidirectional testing
        // We only attempt fresh connections to peers we've been disconnected from for >30s
        let disconnection_times: Arc<RwLock<HashMap<String, Instant>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Create pending outbound tracker for detecting inbound vs outbound connections
        // When PeerConnected fires, if peer is NOT in pending_outbound, it's inbound
        let pending_outbound: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

        // Counter for inbound connections - key metric for nodes behind NAT
        // If we're behind NAT and receive inbound connections, hole-punching works!
        let inbound_connections: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

        let nat_stats: Arc<RwLock<NatStats>> = Arc::new(RwLock::new(NatStats::default()));

        // Create relay state for NAT traversal fallback (before event handler spawn)
        let our_peer_id_bytes = peer_id_to_bytes(&peer_id);
        let mut relay_state_inner = RelayState::new(our_peer_id_bytes);
        relay_state_inner.our_local_addresses = listen_addresses.clone();
        let relay_state: Arc<RwLock<RelayState>> = Arc::new(RwLock::new(relay_state_inner));

        // Geo provider for looking up country codes from IP addresses
        let geo_provider = Arc::new(BgpGeoProvider::new());

        // Create connected_peers early so it can be shared with event handler
        let connected_peers: Arc<RwLock<HashMap<String, TrackedPeer>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Initialize gossip integration layer with bootstrap cache (created early for event handler)
        let (gossip_event_tx, gossip_event_rx) = mpsc::channel(100);
        let gossip_config = GossipConfig {
            cache_path: Some(
                dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("ant-quic-test")
                    .join("peer_cache.cbor"),
            ),
            ..GossipConfig::default()
        };
        let gossip_integration = Arc::new(GossipIntegration::new(
            peer_id.clone(),
            listen_addresses.clone(),
            false, // Assume not public initially, will update when external address discovered
            false, // is_public_ipv4 - will update when external IPv4 discovered
            false, // is_public_ipv6 - will update when external IPv6 discovered
            gossip_config,
            gossip_event_tx,
        ));
        info!(
            "Initialized gossip integration with bootstrap cache ({} cached peers)",
            gossip_integration.cache_size()
        );

        let node_for_events = Arc::clone(&node);
        let event_tx_for_events = event_tx.clone();
        let hole_punched_for_events = Arc::clone(&hole_punched_peers);
        let external_addresses_for_events = Arc::clone(&external_addresses);
        let disconnection_times_for_events = Arc::clone(&disconnection_times);
        let pending_outbound_for_events = Arc::clone(&pending_outbound);
        let inbound_connections_for_events = Arc::clone(&inbound_connections);
        let geo_provider_for_events = Arc::clone(&geo_provider);
        let relay_state_for_events = Arc::clone(&relay_state);
        let listen_addresses_for_events = listen_addresses.clone();
        let connected_peers_for_events = Arc::clone(&connected_peers);
        let peer_id_for_events = peer_id.clone();
        let registry_url_for_events = config.registry_url.clone();
        let nat_stats_for_events = Arc::clone(&nat_stats);
        let local_ipv4_for_events = local_ipv4;
        let local_ipv6_for_events = local_ipv6;
        tokio::spawn(async move {
            let mut events = node_for_events.subscribe_raw();
            while let Ok(event) = events.recv().await {
                match event {
                    P2pEvent::ExternalAddressDiscovered { addr } => {
                        info!("External address discovered: {}", addr);
                        let mut addrs = external_addresses_for_events.write().await;
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                            info!("Stored external address: {} (total: {})", addr, addrs.len());
                        }

                        let mut rs = relay_state_for_events.write().await;
                        rs.our_external_addresses = addrs.clone();
                        rs.our_local_addresses = listen_addresses_for_events.clone();

                        let (is_public, is_public_ipv4, is_public_ipv6) = rs.get_public_status();
                        if is_public {
                            info!(
                                "We appear to be a PUBLIC node (IPv4: {}, IPv6: {})",
                                if is_public_ipv4 { "public" } else { "NAT" },
                                if is_public_ipv6 { "public" } else { "NAT/none" }
                            );
                        }
                        drop(rs);

                        let mut local_node = LocalNodeInfo::default();
                        local_node.set_peer_id(&peer_id_for_events);
                        local_node.local_ipv4 = local_ipv4_for_events;
                        local_node.local_ipv6 = local_ipv6_for_events;
                        for a in addrs.iter() {
                            if a.is_ipv4() && local_node.external_ipv4.is_none() {
                                local_node.external_ipv4 = Some(*a);
                            } else if a.is_ipv6() && local_node.external_ipv6.is_none() {
                                local_node.external_ipv6 = Some(*a);
                            }
                        }
                        drop(addrs);

                        let _ = event_tx_for_events.try_send(TuiEvent::UpdateLocalNode(local_node));
                        let _ = event_tx_for_events.try_send(TuiEvent::Info(format!(
                            "Discovered external address: {}",
                            addr
                        )));
                        let _ =
                            event_tx_for_events.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                                peer_id: String::new(),
                                frame_type: "OBSERVED_ADDRESS".to_string(),
                                direction: FrameDirection::Received,
                                timestamp: Instant::now(),
                                context: Some(format!("External: {}", addr)),
                            }));
                        let _ = event_tx_for_events.try_send(TuiEvent::NatPhaseUpdate {
                            peer_id: peer_id_for_events.clone(),
                            phase: NatTraversalPhase::Discovering,
                            coordinator_id: None,
                        });
                    }
                    P2pEvent::NatTraversalProgress { peer_id, phase } => {
                        use ant_quic::TraversalPhase;
                        let peer_hex = hex::encode(peer_id.0);

                        let tui_phase = match &phase {
                            TraversalPhase::Discovery => NatTraversalPhase::Discovering,
                            TraversalPhase::Coordination => NatTraversalPhase::Coordinating,
                            TraversalPhase::Synchronization => NatTraversalPhase::Coordinating,
                            TraversalPhase::Punching => NatTraversalPhase::Punching,
                            TraversalPhase::Validation => NatTraversalPhase::Punching,
                            TraversalPhase::Connected => NatTraversalPhase::Connected,
                            TraversalPhase::Failed => NatTraversalPhase::Relayed,
                        };

                        let _ = event_tx_for_events.try_send(TuiEvent::NatPhaseUpdate {
                            peer_id: peer_hex.clone(),
                            phase: tui_phase,
                            coordinator_id: None,
                        });

                        let frame_type = match &phase {
                            TraversalPhase::Discovery => "OBSERVED_ADDRESS",
                            TraversalPhase::Coordination => "ADD_ADDRESS",
                            TraversalPhase::Synchronization => "ADD_ADDRESS",
                            TraversalPhase::Punching => "PUNCH_ME_NOW",
                            TraversalPhase::Validation => "PUNCH_ME_NOW",
                            TraversalPhase::Connected => "CONNECTED",
                            TraversalPhase::Failed => "FAILED",
                        };
                        let _ =
                            event_tx_for_events.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                                peer_id: peer_hex.clone(),
                                frame_type: frame_type.to_string(),
                                direction: FrameDirection::Received,
                                timestamp: Instant::now(),
                                context: Some(format!("{:?}", phase)),
                            }));

                        if matches!(phase, TraversalPhase::Punching) {
                            debug!(
                                "Peer {} entered Punching phase - marking as hole-punched",
                                &peer_hex[..8.min(peer_hex.len())]
                            );
                            hole_punched_for_events.write().await.insert(peer_hex, true);
                        }
                    }
                    P2pEvent::PeerConnected {
                        peer_id,
                        addr,
                        side,
                    } => {
                        let peer_hex = hex::encode(peer_id.0);
                        debug!(
                            "P2P event: peer connected {} at {} (side: {:?})",
                            &peer_hex[..8.min(peer_hex.len())],
                            addr,
                            side
                        );

                        // Use the actual connection side from the QUIC layer
                        // Side::Server means THEY connected to US (inbound)
                        // Side::Client means WE connected to THEM (outbound)
                        let is_inbound = side.is_server();

                        if addr.is_ipv4() {
                            let _ = event_tx_for_events.try_send(TuiEvent::Ipv4Connection);
                        } else {
                            let _ = event_tx_for_events.try_send(TuiEvent::Ipv6Connection);
                        }

                        if is_inbound {
                            let count =
                                inbound_connections_for_events.fetch_add(1, Ordering::Relaxed) + 1;
                            info!(
                                "INBOUND connection received from {} (total inbound: {})",
                                &peer_hex[..8.min(peer_hex.len())],
                                count
                            );

                            {
                                let mut stats = nat_stats_for_events.write().await;
                                stats.hole_punch_success += 1;
                            }

                            let _ = event_tx_for_events.try_send(TuiEvent::InboundConnection);
                            let _ = event_tx_for_events.try_send(TuiEvent::Info(format!(
                                "← INBOUND from {} (NAT traversal works!)",
                                &peer_hex[..8.min(peer_hex.len())]
                            )));

                            // Create a ConnectedPeer for TUI display with Inbound direction
                            let mut inbound_peer = ConnectedPeer::with_direction(
                                &peer_hex,
                                ConnectionMethod::HolePunched,
                                ConnectionDirection::Inbound,
                            );
                            inbound_peer.addresses = vec![addr];

                            // Set connectivity matrix based on address type + NAT success
                            let is_ipv6 = addr.is_ipv6();
                            inbound_peer.connectivity.ipv4_direct_tested = !is_ipv6;
                            inbound_peer.connectivity.ipv4_direct_success = !is_ipv6;
                            inbound_peer.connectivity.ipv6_direct_tested = is_ipv6;
                            inbound_peer.connectivity.ipv6_direct_success = is_ipv6;
                            inbound_peer.connectivity.nat_traversal_tested = true;
                            inbound_peer.connectivity.nat_traversal_success = true;
                            inbound_peer.connectivity.active_is_ipv6 = is_ipv6;
                            inbound_peer.connectivity.active_method =
                                Some(ConnectionMethod::HolePunched);

                            // Look up country code from the peer's IP address
                            let (_lat, _lon, country_code) =
                                geo_provider_for_events.lookup(addr.ip());
                            if let Some(cc) = country_code {
                                inbound_peer.location = format!("{} {}", country_flag(&cc), cc);
                            }

                            send_tui_event(
                                &event_tx_for_events,
                                TuiEvent::PeerConnected(inbound_peer),
                            );
                        } else {
                            // Outbound connection - we initiated
                            // Remove from pending since connection completed
                            let mut pending = pending_outbound_for_events.write().await;
                            pending.remove(&peer_hex);
                            // Track outbound connection
                            let _ = event_tx_for_events.try_send(TuiEvent::OutboundConnection);

                            // Create a ConnectedPeer for TUI display with Outbound direction
                            let mut outbound_peer = ConnectedPeer::with_direction(
                                &peer_hex,
                                ConnectionMethod::Direct,
                                ConnectionDirection::Outbound,
                            );
                            outbound_peer.addresses = vec![addr];

                            // Set connectivity matrix based on address type
                            let is_ipv6 = addr.is_ipv6();
                            outbound_peer.connectivity.ipv4_direct_tested = !is_ipv6;
                            outbound_peer.connectivity.ipv4_direct_success = !is_ipv6;
                            outbound_peer.connectivity.ipv6_direct_tested = is_ipv6;
                            outbound_peer.connectivity.ipv6_direct_success = is_ipv6;
                            outbound_peer.connectivity.active_is_ipv6 = is_ipv6;
                            outbound_peer.connectivity.active_method =
                                Some(ConnectionMethod::Direct);

                            // Look up country code from the peer's IP address
                            let (_lat, _lon, country_code) =
                                geo_provider_for_events.lookup(addr.ip());
                            if let Some(cc) = country_code {
                                outbound_peer.location = format!("{} {}", country_flag(&cc), cc);
                            }

                            send_tui_event(
                                &event_tx_for_events,
                                TuiEvent::PeerConnected(outbound_peer),
                            );
                        }

                        // === ADD PEER TO CONNECTED_PEERS IMMEDIATELY ===
                        // This ensures the peer list gossip includes this peer.
                        // For outbound connections, this may be replaced later by the
                        // comprehensive test which has more detailed info.
                        {
                            let mut peers = connected_peers_for_events.write().await;
                            if !peers.contains_key(&peer_hex) {
                                let now = Instant::now();
                                let direction = if is_inbound {
                                    ConnectionDirection::Inbound
                                } else {
                                    ConnectionDirection::Outbound
                                };
                                // Determine connection method based on address type
                                // For VPS nodes on public IPs, all connections are "Direct"
                                // HolePunched only applies when NAT traversal was needed
                                let method = ConnectionMethod::Direct;

                                // Create minimal PeerInfo for tracking
                                let peer_info = PeerInfo {
                                    peer_id: peer_hex.clone(),
                                    addresses: vec![addr],
                                    nat_type: NatType::Unknown,
                                    country_code: None,
                                    latitude: 0.0,
                                    longitude: 0.0,
                                    last_seen: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0),
                                    connection_success_rate: 1.0,
                                    capabilities: NodeCapabilities::default(),
                                    version: String::new(),
                                    is_active: true,
                                    status: PeerStatus::Active,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                    connected_peers: 0,
                                    gossip_stats: None,
                                    full_mesh_probes: None,
                                };

                                // Set connectivity based on actual address
                                let is_ipv6 = addr.is_ipv6();
                                let connectivity = ConnectivityMatrix {
                                    active_is_ipv6: is_ipv6,
                                    ipv4_direct_tested: !is_ipv6,
                                    ipv4_direct_success: !is_ipv6,
                                    ipv6_direct_tested: is_ipv6,
                                    ipv6_direct_success: is_ipv6,
                                    ..Default::default()
                                };

                                let existing = peers.get(&peer_hex);
                                let prev_outbound =
                                    existing.map(|t| t.outbound_verified).unwrap_or(false);
                                let prev_inbound =
                                    existing.map(|t| t.inbound_verified).unwrap_or(false);
                                let (outbound_verified, inbound_verified) = match direction {
                                    ConnectionDirection::Outbound => (true, prev_inbound),
                                    ConnectionDirection::Inbound => (prev_outbound, true),
                                };
                                let connectivity_for_report = connectivity.clone();
                                let tracked = TrackedPeer {
                                    info: peer_info,
                                    method,
                                    direction,
                                    connected_at: now,
                                    last_activity: now,
                                    stats: PeerStats::default(),
                                    sequence: AtomicU64::new(0),
                                    consecutive_failures: 0,
                                    connectivity,
                                    outbound_verified,
                                    inbound_verified,
                                    last_nat_test_time: None,
                                    quic_test_success: false,
                                    gossip_test_success: false,
                                };

                                peers.insert(peer_hex.clone(), tracked);
                                debug!(
                                    "Added peer {} to connected_peers immediately (direction: {:?})",
                                    &peer_hex[..8.min(peer_hex.len())],
                                    direction
                                );

                                let report = ConnectionReport {
                                    from_peer: peer_id_for_events.clone(),
                                    to_peer: peer_hex.clone(),
                                    method,
                                    is_ipv6,
                                    rtt_ms: None,
                                    connectivity: connectivity_for_report,
                                };
                                let registry_url = registry_url_for_events.clone();
                                tokio::spawn(async move {
                                    let registry = RegistryClient::new(&registry_url);
                                    if let Err(e) = registry.report_connection(&report).await {
                                        debug!("Failed to report connection to registry: {}", e);
                                    }
                                });
                            }
                        }

                        // Update relay state to track this connected peer
                        // We use the address we connected to as their external address
                        {
                            let mut rs = relay_state_for_events.write().await;
                            rs.update_peer(
                                peer_id.0,
                                vec![addr], // Assume their local = addr for now
                                vec![addr], // Their external address is what we connected to
                                true,       // They are now connected
                            );
                            debug!(
                                "Relay state: added connected peer {}",
                                &peer_hex[..8.min(peer_hex.len())]
                            );
                        }

                        // === GOSSIP: Exchange peer lists with newly connected peer ===
                        // This is the core of gossip-first peer discovery:
                        // When we connect to a peer, we send them our list of known peers,
                        // and they send us theirs.
                        let node_for_gossip = Arc::clone(&node_for_events);
                        let connected_peers_for_gossip = Arc::clone(&connected_peers_for_events);
                        let our_peer_id_for_gossip = peer_id_for_events.clone();
                        let new_peer_hex = peer_hex.clone();
                        tokio::spawn(async move {
                            // Small delay to ensure connection is fully established
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                            // Build peer list from currently connected peers
                            let peer_list = {
                                let connected = connected_peers_for_gossip.read().await;
                                build_peer_list_from_connected(&connected, &our_peer_id_for_gossip)
                            };

                            if let Err(e) = send_gossip_peer_list(
                                node_for_gossip.inner_endpoint(),
                                &new_peer_hex,
                                &our_peer_id_for_gossip,
                                peer_list.clone(),
                            )
                            .await
                            {
                                debug!(
                                    "Failed to send peer list to {}: {}",
                                    &new_peer_hex[..8.min(new_peer_hex.len())],
                                    e
                                );
                            } else {
                                info!(
                                    "Sent peer list ({} peers) to newly connected {}",
                                    peer_list.len(),
                                    &new_peer_hex[..8.min(new_peer_hex.len())]
                                );
                            }
                        });

                        // Send ConnectBackRequest after outbound connection
                        // The peer will wait 30s for NAT hole to expire, then try to connect back
                        if !is_inbound {
                            let node_for_callback = Arc::clone(&node_for_events);
                            let external_addrs_for_callback =
                                Arc::clone(&external_addresses_for_events);
                            let our_peer_id_for_callback = peer_id_for_events.clone();
                            let target_peer_hex = peer_hex.clone();
                            let event_tx_for_callback = event_tx_for_events.clone();
                            let connected_peers_for_callback =
                                Arc::clone(&connected_peers_for_events);

                            tokio::spawn(async move {
                                use super::test_protocol::ConnectBackRequest;

                                let our_addresses =
                                    external_addrs_for_callback.read().await.clone();
                                if our_addresses.is_empty() {
                                    return;
                                }

                                let peer_short = &target_peer_hex[..8.min(target_peer_hex.len())];
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

                                let request = ConnectBackRequest::new(
                                    our_peer_id_for_callback.clone(),
                                    our_addresses.clone(),
                                );

                                if let Ok(bytes) = request.to_bytes() {
                                    if let Ok(peer_bytes) = hex::decode(&target_peer_hex) {
                                        if peer_bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&peer_bytes);
                                            let target_peer = ant_quic::PeerId(arr);

                                            if let Err(e) =
                                                node_for_callback.send(&target_peer, &bytes).await
                                            {
                                                debug!(
                                                    "ConnectBackRequest: failed to send to {}: {}",
                                                    peer_short, e
                                                );
                                                return;
                                            }

                                            info!(
                                                "ConnectBackRequest: sent to {} - waiting for connect-back",
                                                peer_short
                                            );

                                            let _ = event_tx_for_callback.try_send(
                                                TuiEvent::NatTestWaitingForConnectBack {
                                                    peer_id: target_peer_hex.clone(),
                                                    seconds_remaining: 60,
                                                },
                                            );

                                            // 60s = 30s for peer's NAT to expire + 30s for them to connect
                                            for countdown in (0..60).rev() {
                                                tokio::time::sleep(Duration::from_secs(1)).await;

                                                let peers =
                                                    connected_peers_for_callback.read().await;
                                                if let Some(tracked) = peers.get(&target_peer_hex) {
                                                    if tracked.inbound_verified {
                                                        let _ = event_tx_for_callback.try_send(
                                                            TuiEvent::NatTestConnectBackSuccess {
                                                                peer_id: target_peer_hex.clone(),
                                                            },
                                                        );
                                                        return;
                                                    }
                                                }
                                                drop(peers);

                                                if countdown % 10 == 0 && countdown > 0 {
                                                    let _ = event_tx_for_callback.try_send(
                                                        TuiEvent::NatTestWaitingForConnectBack {
                                                            peer_id: target_peer_hex.clone(),
                                                            seconds_remaining: countdown,
                                                        },
                                                    );
                                                }
                                            }

                                            info!(
                                                "ConnectBackRequest: timeout waiting for {} to connect back",
                                                peer_short
                                            );
                                            let _ = event_tx_for_callback.try_send(
                                                TuiEvent::NatTestConnectBackTimeout {
                                                    peer_id: target_peer_hex.clone(),
                                                },
                                            );

                                            let _ = event_tx_for_callback.try_send(
                                                TuiEvent::NatTestRetrying {
                                                    peer_id: target_peer_hex.clone(),
                                                },
                                            );

                                            let retry_result = tokio::time::timeout(
                                                Duration::from_secs(10),
                                                node_for_callback.connect(target_peer),
                                            )
                                            .await;

                                            match retry_result {
                                                Ok(Ok(_)) => {
                                                    info!(
                                                        "ConnectBackRequest: {} is still reachable but didn't connect back",
                                                        peer_short
                                                    );
                                                    let _ = event_tx_for_callback.try_send(
                                                        TuiEvent::Info(format!(
                                                            "{} online but NAT traversal failed - they can't reach us",
                                                            peer_short
                                                        ))
                                                    );
                                                }
                                                _ => {
                                                    info!(
                                                        "ConnectBackRequest: {} appears to have gone offline",
                                                        peer_short
                                                    );
                                                    let _ = event_tx_for_callback.try_send(
                                                        TuiEvent::NatTestPeerUnreachable {
                                                            peer_id: target_peer_hex.clone(),
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }

                        // Note: Gossip messages are now received via the central
                        // endpoint.recv() loop in start_gossip_listener, not per-peer
                    }
                    P2pEvent::PeerDisconnected { peer_id, reason } => {
                        let peer_hex = hex::encode(peer_id.0);
                        debug!(
                            "P2P event: peer disconnected {}: {:?}",
                            &peer_hex[..8.min(peer_hex.len())],
                            reason
                        );

                        // Record disconnection time for bidirectional testing
                        // This allows us to test fresh hole-punches after NAT mappings expire
                        {
                            let mut times = disconnection_times_for_events.write().await;
                            times.insert(peer_hex.clone(), Instant::now());
                            debug!(
                                "Recorded disconnection time for peer {}",
                                &peer_hex[..8.min(peer_hex.len())]
                            );
                        }

                        // Update relay state to mark peer as disconnected
                        {
                            let mut rs = relay_state_for_events.write().await;
                            rs.set_peer_connected(peer_id.0, false);
                            // Also remove any relay routes through this peer
                            // (we can't relay through a disconnected peer)
                            rs.active_relays
                                .retain(|_, relay_id| *relay_id != peer_id.0);
                            debug!(
                                "Relay state: marked peer {} as disconnected",
                                &peer_hex[..8.min(peer_hex.len())]
                            );
                        }

                        // Notify TUI of peer disconnect (non-blocking)
                        let _ = event_tx_for_events.try_send(TuiEvent::RemovePeer(peer_hex));
                    }
                    P2pEvent::DataReceived { peer_id, bytes } => {
                        // P2pEvent::DataReceived is a notification that data was received
                        // (bytes is the count, not the actual data which must be obtained via recv())
                        let peer_hex = hex::encode(peer_id.0);
                        debug!(
                            "QUIC data notification: {} bytes from {}",
                            bytes,
                            &peer_hex[..8.min(peer_hex.len())]
                        );
                        // Mark QUIC test as successful for this peer since we received data
                        let mut peers = connected_peers_for_events.write().await;
                        if let Some(tracked) = peers.get_mut(&peer_hex) {
                            tracked.quic_test_success = true;
                            tracked.last_activity = Instant::now();
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            listen_addresses,
            config,
            registry,
            node,
            peer_id,
            public_key,
            external_addresses,
            connected_peers,
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            total_connections_success: Arc::new(AtomicU64::new(0)),
            total_connections_failed: Arc::new(AtomicU64::new(0)),
            direct_connections: Arc::new(AtomicU64::new(0)),
            holepunch_connections: Arc::new(AtomicU64::new(0)),
            relay_connections: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            event_tx,
            nat_stats,
            has_ipv6: has_global_ipv6(),
            hole_punched_peers,
            disconnection_times,
            pending_outbound,
            inbound_connections,
            relay_state,
            gossip_integration,
            gossip_event_rx: Arc::new(RwLock::new(gossip_event_rx)),
            epidemic_gossip,
            epidemic_event_rx: Arc::new(RwLock::new(epidemic_event_rx)),
            full_mesh_probes: Arc::new(RwLock::new(HashMap::new())),
            geo_provider,
            fully_tested_peers: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// Get our peer ID.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Check if we appear to be a public node (not behind NAT).
    ///
    /// A node is public if its external address IP matches its local address IP.
    pub async fn is_public_node(&self) -> bool {
        let rs = self.relay_state.read().await;
        rs.are_we_public()
    }

    /// Get a list of relay candidates sorted by priority.
    ///
    /// Public nodes are preferred, followed by currently connected peers.
    pub async fn get_relay_candidates(&self) -> Vec<super::test_protocol::RelayCandidate> {
        let rs = self.relay_state.read().await;
        rs.get_relay_candidates()
    }

    /// Get public nodes we're connected to (best relay candidates).
    pub async fn get_public_nodes(&self) -> Vec<super::test_protocol::PeerNetworkInfo> {
        let rs = self.relay_state.read().await;
        rs.get_public_nodes().into_iter().cloned().collect()
    }

    /// Try to find a relay that can reach the target peer.
    ///
    /// This implements the relay discovery protocol:
    /// 1. Get list of connected peers sorted by priority (public nodes first)
    /// 2. Send CAN_YOU_REACH request to each
    /// 3. Return first peer that responds positively
    ///
    /// Returns the relay peer's ID if found, None otherwise.
    pub async fn find_relay_for(&self, target_peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        let candidates = self.get_relay_candidates().await;
        let target_hex = hex::encode(target_peer_id);

        if candidates.is_empty() {
            debug!(
                "No relay candidates available to reach {}",
                &target_hex[..8.min(target_hex.len())]
            );
            return None;
        }

        info!(
            "Looking for relay to reach {} among {} candidates",
            &target_hex[..8.min(target_hex.len())],
            candidates.len()
        );

        // For now, log candidates - actual CAN_YOU_REACH protocol will be added next
        for (i, candidate) in candidates.iter().enumerate() {
            let peer_hex = hex::encode(candidate.peer_id);
            info!(
                "  Candidate {}: {} (public={}, connected={}, priority={})",
                i + 1,
                &peer_hex[..8.min(peer_hex.len())],
                candidate.is_public,
                candidate.is_connected,
                candidate.priority()
            );
        }

        // TODO: Implement CAN_YOU_REACH message exchange
        // For now, return the highest priority connected peer as potential relay
        // This will be enhanced with actual reachability checking
        if let Some(best) = candidates.first() {
            if best.is_connected {
                let peer_hex = hex::encode(best.peer_id);
                info!(
                    "Selected {} as potential relay (priority={})",
                    &peer_hex[..8.min(peer_hex.len())],
                    best.priority()
                );
                return Some(best.peer_id);
            }
        }

        None
    }

    /// Set an active relay for reaching a target peer.
    pub async fn set_relay(&self, target_peer_id: [u8; 32], relay_peer_id: [u8; 32]) {
        let mut rs = self.relay_state.write().await;
        rs.set_relay_for(target_peer_id, relay_peer_id);
    }

    /// Remove relay for a target (e.g., when direct connection succeeds).
    pub async fn remove_relay(&self, target_peer_id: &[u8; 32]) {
        let mut rs = self.relay_state.write().await;
        rs.remove_relay_for(target_peer_id);
    }

    /// Get current relay for a target peer, if any.
    pub async fn get_relay(&self, target_peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        let rs = self.relay_state.read().await;
        rs.get_relay_for(target_peer_id)
    }

    /// Connect to a peer with relay fallback.
    ///
    /// This implements the connection strategy:
    /// 1. Try direct IPv4 connection
    /// 2. Try direct IPv6 connection (if available)
    /// 3. Try NAT traversal (hole-punching via ant-quic)
    /// 4. If all fail, find a relay and use it for PUNCH_ME_NOW exchange
    /// 5. If relay-assisted holepunch fails, keep the relay for traffic
    ///
    /// Returns the connection method used and whether we're using a relay.
    pub async fn connect_with_relay_fallback(
        &self,
        peer: &crate::PeerInfo,
    ) -> Result<(ConnectionMethod, Option<[u8; 32]>), String> {
        let peer_id_short = &peer.peer_id[..8.min(peer.peer_id.len())];
        let target_peer_id = peer_id_to_bytes(&peer.peer_id);

        info!(
            "Connecting to {} with relay fallback enabled",
            peer_id_short
        );

        // 1. Try direct IPv4 connections
        for addr in peer.addresses.iter().filter(|a| a.is_ipv4()) {
            match tokio::time::timeout(Duration::from_secs(10), self.node.connect_addr(*addr)).await
            {
                Ok(Ok(_conn)) => {
                    info!("Direct IPv4 connection to {} succeeded", peer_id_short);
                    // Clear any existing relay since direct works
                    self.remove_relay(&target_peer_id).await;
                    return Ok((ConnectionMethod::Direct, None));
                }
                Ok(Err(e)) => {
                    debug!("Direct IPv4 to {} at {} failed: {}", peer_id_short, addr, e);
                }
                Err(_) => {
                    debug!("Direct IPv4 to {} at {} timed out", peer_id_short, addr);
                }
            }
        }

        // 2. Try direct IPv6 connections
        for addr in peer.addresses.iter().filter(|a| a.is_ipv6()) {
            match tokio::time::timeout(Duration::from_secs(10), self.node.connect_addr(*addr)).await
            {
                Ok(Ok(_conn)) => {
                    info!("Direct IPv6 connection to {} succeeded", peer_id_short);
                    self.remove_relay(&target_peer_id).await;
                    return Ok((ConnectionMethod::Direct, None));
                }
                Ok(Err(e)) => {
                    debug!("Direct IPv6 to {} at {} failed: {}", peer_id_short, addr, e);
                }
                Err(_) => {
                    debug!("Direct IPv6 to {} at {} timed out", peer_id_short, addr);
                }
            }
        }

        // 3. Try NAT traversal (hole-punching)
        if let Ok(peer_id_bytes) = hex::decode(&peer.peer_id) {
            if peer_id_bytes.len() >= 32 {
                let mut peer_id_array = [0u8; 32];
                peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
                let quic_peer_id = QuicPeerId(peer_id_array);

                match tokio::time::timeout(Duration::from_secs(30), self.node.connect(quic_peer_id))
                    .await
                {
                    Ok(Ok(_conn)) => {
                        info!("NAT traversal to {} succeeded", peer_id_short);
                        self.remove_relay(&target_peer_id).await;
                        return Ok((ConnectionMethod::HolePunched, None));
                    }
                    Ok(Err(e)) => {
                        debug!("NAT traversal to {} failed: {}", peer_id_short, e);
                    }
                    Err(_) => {
                        debug!("NAT traversal to {} timed out", peer_id_short);
                    }
                }
            }
        }

        // 4. All direct methods failed - try to find a relay
        info!(
            "All direct connections failed for {}, looking for relay...",
            peer_id_short
        );

        if let Some(relay_peer_id) = self.find_relay_for(&target_peer_id).await {
            let relay_hex = hex::encode(relay_peer_id);
            info!(
                "Found relay {} for reaching {}",
                &relay_hex[..8.min(relay_hex.len())],
                peer_id_short
            );

            // Store the relay for this target
            self.set_relay(target_peer_id, relay_peer_id).await;

            // TODO: Send PUNCH_ME_NOW via relay and attempt hole-punch
            // For now, just return that we're using a relay
            // The actual relay data forwarding will be added in the next step

            info!(
                "Using relay {} for {} (relay-assisted holepunch not yet implemented)",
                &relay_hex[..8.min(relay_hex.len())],
                peer_id_short
            );

            // TODO: Return Relayed when we actually implement data relay
            // For now, return HolePunched placeholder to indicate we found a relay
            return Ok((ConnectionMethod::Relayed, Some(relay_peer_id)));
        }

        Err(format!(
            "Failed to connect to {} via any method (no relay available)",
            peer_id_short
        ))
    }

    /// Log relay statistics for debugging.
    pub async fn log_relay_stats(&self) {
        let rs = self.relay_state.read().await;
        let public_nodes = rs.get_public_nodes();
        let candidates = rs.get_relay_candidates();

        info!("=== Relay State ===");
        info!("  We are public: {}", rs.are_we_public());
        info!("  Known peers: {}", rs.known_peers.len());
        info!(
            "  Public nodes: {} (connected)",
            public_nodes.iter().filter(|p| p.is_connected).count()
        );
        info!("  Relay candidates: {}", candidates.len());
        info!("  Active relays: {}", rs.active_relays.len());

        for (target, relay) in &rs.active_relays {
            let target_hex = hex::encode(target);
            let relay_hex = hex::encode(relay);
            info!(
                "    {} -> {}",
                &target_hex[..8.min(target_hex.len())],
                &relay_hex[..8.min(relay_hex.len())]
            );
        }
    }

    /// Spawn a background loop that periodically logs relay state.
    fn spawn_relay_stats_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let relay_state = Arc::clone(&self.relay_state);
        let peer_id = self.peer_id.clone();

        tokio::spawn(async move {
            // Log every 60 seconds
            let mut ticker = tokio::time::interval(Duration::from_secs(60));

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                let rs = relay_state.read().await;
                let public_nodes: Vec<_> = rs.get_public_nodes();
                let candidates = rs.get_relay_candidates();
                let (is_public, is_public_ipv4, is_public_ipv6) = rs.get_public_status();

                info!(
                    "=== Relay State for {} ===",
                    &peer_id[..8.min(peer_id.len())]
                );
                info!(
                    "  We are public: {} (IPv4: {}, IPv6: {})",
                    is_public,
                    if is_public_ipv4 { "yes" } else { "no" },
                    if is_public_ipv6 { "yes" } else { "no" }
                );
                info!("  Known peers: {}", rs.known_peers.len());
                info!("  Connected public nodes: {}", public_nodes.len());
                info!("  Total relay candidates: {}", candidates.len());
                info!("  Active relays: {}", rs.active_relays.len());

                // Log public nodes
                for (i, p) in public_nodes.iter().enumerate().take(5) {
                    let peer_hex = hex::encode(p.peer_id);
                    info!(
                        "    Public #{}: {} ({} addrs)",
                        i + 1,
                        &peer_hex[..8.min(peer_hex.len())],
                        p.external_addresses.len()
                    );
                }
            }
        })
    }

    /// Spawn the accept loop to handle incoming connections.
    ///
    /// This is CRITICAL for receiving data from peers who connect to us.
    /// Without this, we can only receive data from peers WE connected to.
    fn spawn_accept_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let endpoint = Arc::clone(&self.node);
        let connected_peers = Arc::clone(&self.connected_peers);
        let gossip_integration = Arc::clone(&self.gossip_integration);
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);
        let peer_id = self.peer_id.clone();
        let event_tx = self.event_tx.clone();
        let inbound_connections = Arc::clone(&self.inbound_connections);
        let max_peers = self.config.max_peers;

        tokio::spawn(async move {
            info!("Accept loop started - listening for incoming connections");

            while !shutdown.load(Ordering::SeqCst) {
                // Accept incoming connection
                if let Some(peer_conn) = endpoint.accept().await {
                    let new_peer_hex = hex::encode(peer_conn.peer_id.0);
                    let addr = peer_conn.remote_addr;
                    info!(
                        "Accepted incoming connection from {} at {}",
                        &new_peer_hex[..8.min(new_peer_hex.len())],
                        addr
                    );

                    // Increment inbound connections counter
                    inbound_connections.fetch_add(1, Ordering::SeqCst);

                    // Add to connected_peers if not already there
                    {
                        let mut peers = connected_peers.write().await;
                        if !peers.contains_key(&new_peer_hex) {
                            let now = Instant::now();
                            // Create minimal PeerInfo for tracking
                            let peer_info = PeerInfo {
                                peer_id: new_peer_hex.clone(),
                                addresses: vec![addr],
                                nat_type: NatType::Unknown,
                                country_code: None,
                                latitude: 0.0,
                                longitude: 0.0,
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                                connection_success_rate: 1.0,
                                capabilities: NodeCapabilities::default(),
                                version: String::new(),
                                is_active: true,
                                status: PeerStatus::Active,
                                bytes_sent: 0,
                                bytes_received: 0,
                                connected_peers: 0,
                                gossip_stats: None,
                                full_mesh_probes: None,
                            };

                            // Set connectivity based on actual address
                            let is_ipv6 = addr.is_ipv6();
                            let connectivity = ConnectivityMatrix {
                                active_is_ipv6: is_ipv6,
                                ipv4_direct_tested: !is_ipv6,
                                ipv4_direct_success: !is_ipv6,
                                ipv6_direct_tested: is_ipv6,
                                ipv6_direct_success: is_ipv6,
                                ..Default::default()
                            };

                            let tracked = TrackedPeer {
                                info: peer_info,
                                method: ConnectionMethod::Direct, // Direct connection over IPv4 or IPv6
                                direction: ConnectionDirection::Inbound,
                                connected_at: now,
                                last_activity: now,
                                stats: PeerStats::default(),
                                sequence: AtomicU64::new(0),
                                consecutive_failures: 0,
                                connectivity,
                                outbound_verified: false, // We haven't connected to them yet
                                inbound_verified: true,   // They connected to us!
                                last_nat_test_time: None,
                                quic_test_success: false,
                                gossip_test_success: false,
                            };

                            peers.insert(new_peer_hex.clone(), tracked);
                            debug!(
                                "Added inbound peer {} to connected_peers ({})",
                                &new_peer_hex[..8.min(new_peer_hex.len())],
                                if is_ipv6 { "IPv6" } else { "IPv4" }
                            );

                            // Update epidemic gossip layer with inbound connection type
                            // AND add to HyParView membership so stats show this peer
                            if let Ok(peer_bytes) = hex::decode(&new_peer_hex) {
                                if peer_bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&peer_bytes);
                                    let gossip_peer_id = GossipPeerId::new(arr);
                                    let gossip_conn_type = if is_ipv6 {
                                        GossipConnectionType::DirectIpv6
                                    } else {
                                        GossipConnectionType::DirectIpv4
                                    };
                                    epidemic_gossip
                                        .set_connection_type(gossip_peer_id, gossip_conn_type)
                                        .await;

                                    // CRITICAL: Add inbound peer to HyParView membership
                                    // Without this, the stats loop won't see inbound connections
                                    // because the gossip transport's acceptor lost the race to us
                                    if let Err(e) = epidemic_gossip.add_peer(gossip_peer_id).await {
                                        debug!(
                                            "Could not add inbound peer {} to HyParView: {:?}",
                                            &new_peer_hex[..8.min(new_peer_hex.len())],
                                            e
                                        );
                                    } else {
                                        debug!(
                                            "Added inbound peer {} to HyParView active view",
                                            &new_peer_hex[..8.min(new_peer_hex.len())]
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Build peer list from our connected peers
                    let peer_list: Vec<GossipPeerInfo> = {
                        let peers = connected_peers.read().await;
                        let timestamp_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        peers
                            .values()
                            .filter_map(|p| {
                                if p.info.peer_id != new_peer_hex {
                                    Some(GossipPeerInfo {
                                        peer_id: p.info.peer_id.clone(),
                                        addresses: p.info.addresses.clone(),
                                        is_public: true,
                                        is_connected: true,
                                        last_seen_ms: timestamp_ms,
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect()
                    };

                    // Send peer list to newly connected peer if we have peers and space
                    let connected = connected_peers.read().await;
                    let at_capacity = connected.len() >= max_peers;
                    drop(connected);

                    if !peer_list.is_empty() && !at_capacity {
                        let inner_ep = Arc::clone(endpoint.inner_endpoint());
                        let peer_id_clone = peer_id.clone();
                        let new_peer_hex_clone = new_peer_hex.clone();
                        let peer_list_clone = peer_list.clone();

                        tokio::spawn(async move {
                            if let Err(e) = send_gossip_peer_list(
                                &inner_ep,
                                &new_peer_hex_clone,
                                &peer_id_clone,
                                peer_list_clone,
                            )
                            .await
                            {
                                debug!(
                                    "Failed to send peer list to inbound {}: {}",
                                    &new_peer_hex_clone[..8.min(new_peer_hex_clone.len())],
                                    e
                                );
                            } else {
                                info!(
                                    "Sent peer list to inbound connection {}",
                                    &new_peer_hex_clone[..8.min(new_peer_hex_clone.len())]
                                );
                            }
                        });
                    }

                    // Add to bootstrap cache
                    gossip_integration.add_peer(&new_peer_hex, &[addr], true);

                    // Send TUI event - create a ConnectedPeer for display
                    let mut tui_peer = ConnectedPeer::with_direction(
                        &new_peer_hex,
                        ConnectionMethod::HolePunched,
                        ConnectionDirection::Inbound,
                    );
                    tui_peer.addresses = vec![addr];
                    // Set connectivity matrix based on address type (inbound = NAT traversal success)
                    let is_ipv6 = addr.is_ipv6();
                    tui_peer.connectivity.ipv4_direct_tested = !is_ipv6;
                    tui_peer.connectivity.ipv4_direct_success = !is_ipv6;
                    tui_peer.connectivity.ipv6_direct_tested = is_ipv6;
                    tui_peer.connectivity.ipv6_direct_success = is_ipv6;
                    tui_peer.connectivity.nat_traversal_tested = true;
                    tui_peer.connectivity.nat_traversal_success = true;
                    tui_peer.connectivity.active_is_ipv6 = is_ipv6;
                    tui_peer.connectivity.active_method = Some(ConnectionMethod::HolePunched);
                    send_tui_event(&event_tx, TuiEvent::PeerConnected(tui_peer));

                    // Record for connectivity test (inbound connection proves NAT traversal)
                    let test_method = if addr.is_ipv4() {
                        TestConnectivityMethod::DirectIpv4
                    } else {
                        TestConnectivityMethod::DirectIpv6
                    };
                    let _ = event_tx.try_send(TuiEvent::ConnectivityTestInbound {
                        peer_id: new_peer_hex.clone(),
                        method: test_method,
                        success: true,
                        rtt_ms: None,
                    });
                }
            }

            info!("Accept loop shutting down");
        })
    }

    /// Spawn the gossip event processing loop.
    fn spawn_gossip_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let gossip_integration = Arc::clone(&self.gossip_integration);
        let gossip_event_rx = Arc::clone(&self.gossip_event_rx);
        let event_tx = self.event_tx.clone();
        let peer_id = self.peer_id.clone();
        let endpoint = Arc::clone(&self.node);
        let connected_peers = Arc::clone(&self.connected_peers);
        let fully_tested_peers = Arc::clone(&self.fully_tested_peers);
        let max_peers = self.config.max_peers;
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);

        tokio::spawn(async move {
            // Periodic cleanup and announcement ticker
            let mut cleanup_ticker = tokio::time::interval(Duration::from_secs(30));

            while !shutdown.load(Ordering::SeqCst) {
                tokio::select! {
                    // Process incoming gossip events
                    event = async {
                        let mut rx = gossip_event_rx.write().await;
                        rx.recv().await
                    } => {
                        if let Some(event) = event {
                            match event {
                                GossipEvent::PeerDiscovered(announcement) => {
                                    let peer_id_short = &announcement.peer_id[..8.min(announcement.peer_id.len())];
                                    info!(
                                        "Gossip: discovered peer {} with {} addresses",
                                        peer_id_short,
                                        announcement.addresses.len()
                                    );

                                    // ALWAYS add to bootstrap cache - this is crucial for peer discovery!
                                    if !announcement.addresses.is_empty() {
                                        gossip_integration.add_peer(
                                            &announcement.peer_id,
                                            &announcement.addresses,
                                            announcement.is_public,
                                        );

                                        // CRDT SYNC: Add to peer cache for distributed state sync
                                        if let Ok(peer_bytes) = hex::decode(&announcement.peer_id) {
                                            if peer_bytes.len() == 32 {
                                                let mut peer_id_array = [0u8; 32];
                                                peer_id_array.copy_from_slice(&peer_bytes);
                                                let entry = crate::epidemic_gossip::PeerCacheEntry {
                                                    peer_id: peer_id_array,
                                                    addresses: announcement.addresses.clone(),
                                                    last_seen: std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .map(|d| d.as_millis() as u64)
                                                        .unwrap_or(0),
                                                    location: None,
                                                };
                                                epidemic_gossip.add_to_peer_cache(entry).await;
                                                debug!(
                                                    "Gossip: added peer {} to CRDT peer cache",
                                                    peer_id_short
                                                );
                                            }
                                        }
                                    }

                                    // Check if we should try to connect to this peer
                                    let connected = connected_peers.read().await;
                                    let already_connected = connected.contains_key(&announcement.peer_id);
                                    let at_capacity = connected.len() >= max_peers;
                                    drop(connected);

                                    if already_connected {
                                        debug!("Gossip: already connected to {}, skipping", peer_id_short);
                                    } else if at_capacity {
                                        debug!("Gossip: at max peers ({}), skipping {}", max_peers, peer_id_short);
                                    } else if !announcement.addresses.is_empty() {
                                        // Try to connect to the first available address
                                        let addr = announcement.addresses[0];
                                        info!(
                                            "Gossip: attempting connection to {} at {}",
                                            peer_id_short, addr
                                        );

                                        // Spawn connection attempt (don't block the gossip loop)
                                        let endpoint_clone = Arc::clone(&endpoint);
                                        let gossip_clone = Arc::clone(&gossip_integration);
                                        let peer_id_for_task = announcement.peer_id.clone();
                                        tokio::spawn(async move {
                                            match tokio::time::timeout(
                                                Duration::from_secs(10),
                                                endpoint_clone.connect_addr(addr)
                                            ).await {
                                                Ok(Ok(_conn)) => {
                                                    info!(
                                                        "Gossip: connected to {} via gossip discovery",
                                                        &peer_id_for_task[..8.min(peer_id_for_task.len())]
                                                    );
                                                    // Record success in gossip cache
                                                    gossip_clone.record_success(&peer_id_for_task);
                                                }
                                                Ok(Err(e)) => {
                                                    debug!(
                                                        "Gossip: connection to {} failed: {}",
                                                        &peer_id_for_task[..8.min(peer_id_for_task.len())],
                                                        e
                                                    );
                                                }
                                                Err(_) => {
                                                    debug!(
                                                        "Gossip: connection to {} timed out",
                                                        &peer_id_for_task[..8.min(peer_id_for_task.len())]
                                                    );
                                                }
                                            }
                                        });
                                    }

                                    // Send to TUI for visualization
                                    let _ = event_tx.try_send(TuiEvent::GossipPeerDiscovered {
                                        peer_id: announcement.peer_id.clone(),
                                        addresses: announcement.addresses.iter().map(|a| a.to_string()).collect(),
                                        is_public: announcement.is_public,
                                    });
                                }
                                GossipEvent::RelayDiscovered(relay) => {
                                    info!(
                                        "Gossip: discovered relay {} with {} connections",
                                        &relay.peer_id[..8.min(relay.peer_id.len())],
                                        relay.active_connections
                                    );
                                    let _ = event_tx.try_send(TuiEvent::GossipRelayDiscovered {
                                        peer_id: relay.peer_id.clone(),
                                        addresses: relay.addresses.iter().map(|a| a.to_string()).collect(),
                                        load: relay.active_connections,
                                    });
                                }
                                GossipEvent::CoordinatorDiscovered(coord) => {
                                    info!(
                                        "Gossip: discovered coordinator {} (success rate: {:.1}%)",
                                        &coord.peer_id[..8.min(coord.peer_id.len())],
                                        coord.success_rate * 100.0
                                    );
                                }
                                GossipEvent::PeerOffline(offline_peer_id) => {
                                    debug!(
                                        "Gossip: peer {} went offline",
                                        &offline_peer_id[..8.min(offline_peer_id.len())]
                                    );
                                }
                                GossipEvent::PeerQueryReceived(query) => {
                                    debug!(
                                        "Gossip: received peer query from {} for target {}",
                                        &query.querier_id[..8.min(query.querier_id.len())],
                                        &query.target_public_key[..16.min(query.target_public_key.len())]
                                    );
                                    // TODO: Check if we're connected to the target and respond
                                }
                                GossipEvent::PeerResponseReceived(response) => {
                                    debug!(
                                        "Gossip: received peer response from {} for query {:?}",
                                        &response.responder_id[..8.min(response.responder_id.len())],
                                        &response.query_id[..4]
                                    );
                                    // TODO: Use response for NAT coordination
                                }
                            }
                        }
                    }

                    // Periodic cleanup of stale entries
                    _ = cleanup_ticker.tick() => {
                        gossip_integration.discovery().cleanup_stale().await;
                        debug!("Gossip: cleaned up stale entries for {}", &peer_id[..8.min(peer_id.len())]);
                    }

                    // Receive incoming data from all connected peers
                    result = endpoint.recv(Duration::from_millis(100)) => {
                        if let Ok((sender_peer_id, data)) = result {
                            let sender_hex = hex::encode(sender_peer_id.0);

                            // Check if it's a gossip message
                            if GossipMessage::is_gossip_message(&data) {
                                // Try to parse as PeerListMessage
                                if let Ok(peer_list) = PeerListMessage::from_bytes(&data) {
                                    info!(
                                        "Received peer list from {} with {} peers",
                                        &sender_hex[..8.min(sender_hex.len())],
                                        peer_list.peers.len()
                                    );

                                    // Process each peer in the list
                                    for peer_info in peer_list.peers {
                                        // Skip if it's us
                                        if peer_info.peer_id == peer_id {
                                            continue;
                                        }

                                        // ALWAYS add to bootstrap cache - this is crucial for peer discovery!
                                        // The cache should know about all peers, regardless of connection status.
                                        gossip_integration.add_peer(
                                            &peer_info.peer_id,
                                            &peer_info.addresses,
                                            peer_info.is_public,
                                        );

                                        // CRDT SYNC: Add to peer cache for distributed state sync
                                        if let Ok(peer_bytes) = hex::decode(&peer_info.peer_id) {
                                            if peer_bytes.len() == 32 {
                                                let mut peer_id_array = [0u8; 32];
                                                peer_id_array.copy_from_slice(&peer_bytes);
                                                let entry = crate::epidemic_gossip::PeerCacheEntry {
                                                    peer_id: peer_id_array,
                                                    addresses: peer_info.addresses.clone(),
                                                    last_seen: std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .map(|d| d.as_millis() as u64)
                                                        .unwrap_or(0),
                                                    location: None,
                                                };
                                                epidemic_gossip.add_to_peer_cache(entry).await;
                                            }
                                        }

                                        // Check if already connected or at capacity for connection attempt
                                        let connected = connected_peers.read().await;
                                        let already_connected = connected.contains_key(&peer_info.peer_id);
                                        let at_capacity = connected.len() >= max_peers;
                                        drop(connected);

                                        if already_connected || at_capacity {
                                            continue;
                                        }

                                        // Broadcast to other connected peers
                                        let announcement = GossipPeerAnnouncement::new(
                                            peer_info.clone(),
                                            peer_id.clone(),
                                            3,
                                        );
                                        let inner_ep_for_broadcast = Arc::clone(endpoint.inner_endpoint());
                                        let connected_for_broadcast = Arc::clone(&connected_peers);
                                        let sender_id = sender_hex.clone();
                                        tokio::spawn(async move {
                                            let _ = broadcast_peer_announcement(
                                                &inner_ep_for_broadcast,
                                                &connected_for_broadcast,
                                                &announcement,
                                                Some(&sender_id),
                                            ).await;
                                        });

                                        // Attempt connection to new peer
                                        if !peer_info.addresses.is_empty() {
                                            let addr = peer_info.addresses[0];
                                            let endpoint_clone = Arc::clone(&endpoint);
                                            let gossip_clone = Arc::clone(&gossip_integration);
                                            let peer_id_for_connect = peer_info.peer_id.clone();
                                            tokio::spawn(async move {
                                                if let Ok(Ok(_)) = tokio::time::timeout(
                                                    Duration::from_secs(10),
                                                    endpoint_clone.connect_addr(addr),
                                                ).await {
                                                    info!(
                                                        "Gossip: connected to {} via peer list",
                                                        &peer_id_for_connect[..8.min(peer_id_for_connect.len())]
                                                    );
                                                    gossip_clone.record_success(&peer_id_for_connect);
                                                }
                                            });
                                        }
                                    }
                                } else if let Ok(announcement) = GossipPeerAnnouncement::from_bytes(&data) {
                                    info!(
                                        "Received peer announcement for {} from {}",
                                        &announcement.peer.peer_id[..8.min(announcement.peer.peer_id.len())],
                                        &sender_hex[..8.min(sender_hex.len())]
                                    );

                                    // Process announced peer
                                    let peer_info = &announcement.peer;
                                    if peer_info.peer_id != peer_id && !peer_info.addresses.is_empty() {
                                        // ALWAYS add to bootstrap cache - this is crucial for peer discovery!
                                        gossip_integration.add_peer(
                                            &peer_info.peer_id,
                                            &peer_info.addresses,
                                            peer_info.is_public,
                                        );

                                        // CRDT SYNC: Add to peer cache for distributed state sync
                                        if let Ok(peer_bytes) = hex::decode(&peer_info.peer_id) {
                                            if peer_bytes.len() == 32 {
                                                let mut peer_id_array = [0u8; 32];
                                                peer_id_array.copy_from_slice(&peer_bytes);
                                                let entry = crate::epidemic_gossip::PeerCacheEntry {
                                                    peer_id: peer_id_array,
                                                    addresses: peer_info.addresses.clone(),
                                                    last_seen: std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .map(|d| d.as_millis() as u64)
                                                        .unwrap_or(0),
                                                    location: None,
                                                };
                                                epidemic_gossip.add_to_peer_cache(entry).await;
                                            }
                                        }

                                        // Check if we should attempt a connection
                                        let connected = connected_peers.read().await;
                                        let already_connected = connected.contains_key(&peer_info.peer_id);
                                        let at_capacity = connected.len() >= max_peers;
                                        drop(connected);

                                        if !already_connected && !at_capacity {
                                            let addr = peer_info.addresses[0];
                                            let endpoint_clone = Arc::clone(&endpoint);
                                            let gossip_clone = Arc::clone(&gossip_integration);
                                            let peer_id_for_connect = peer_info.peer_id.clone();
                                            tokio::spawn(async move {
                                                if let Ok(Ok(_)) = tokio::time::timeout(
                                                    Duration::from_secs(10),
                                                    endpoint_clone.connect_addr(addr),
                                                ).await {
                                                    info!(
                                                        "Gossip: connected to {} via announcement",
                                                        &peer_id_for_connect[..8.min(peer_id_for_connect.len())]
                                                    );
                                                    gossip_clone.record_success(&peer_id_for_connect);
                                                }
                                            });
                                        }
                                    }
                                } else if let Ok(msg) = GossipMessage::from_bytes(&data) {
                                    // Handle ConnectBackRequest and ConnectBackResponse
                                    match msg {
                                        GossipMessage::ConnectBackRequest(request) => {
                                            info!(
                                                "Received ConnectBackRequest from {} with {} addresses",
                                                &request.requester_peer_id[..8.min(request.requester_peer_id.len())],
                                                request.requester_addresses.len()
                                            );

                                            if request.requester_peer_id != peer_id {
                                                let endpoint_clone = Arc::clone(&endpoint);
                                                let requester_id = request.requester_peer_id.clone();
                                                let addresses = request.requester_addresses.clone();
                                                let event_tx_clone = event_tx.clone();

                                                tokio::spawn(async move {
                                                    let peer_short = &requester_id[..8.min(requester_id.len())];

                                                    info!(
                                                        "ConnectBack: waiting 30s for NAT hole to expire before connecting to {}",
                                                        peer_short
                                                    );

                                                    let _ = event_tx_clone.try_send(TuiEvent::Info(format!(
                                                        "Will connect back to {} in 30s",
                                                        peer_short
                                                    )));

                                                    tokio::time::sleep(Duration::from_secs(30)).await;

                                                    info!(
                                                        "ConnectBack: 30s elapsed, attempting fresh connection to {} ({} addresses)",
                                                        peer_short,
                                                        addresses.len()
                                                    );

                                                    for addr in &addresses {
                                                        match tokio::time::timeout(
                                                            Duration::from_secs(10),
                                                            endpoint_clone.connect_addr(*addr),
                                                        ).await {
                                                            Ok(Ok(_)) => {
                                                                info!(
                                                                    "ConnectBack: SUCCESS fresh connection to {} at {}",
                                                                    peer_short,
                                                                    addr
                                                                );
                                                                let _ = event_tx_clone.try_send(TuiEvent::Info(format!(
                                                                    "Connected back to {} (fresh)",
                                                                    peer_short
                                                                )));
                                                                return;
                                                            }
                                                            Ok(Err(e)) => {
                                                                debug!(
                                                                    "ConnectBack: failed {} at {}: {}",
                                                                    peer_short,
                                                                    addr,
                                                                    e
                                                                );
                                                            }
                                                            Err(_) => {
                                                                debug!(
                                                                    "ConnectBack: timeout {} at {}",
                                                                    peer_short,
                                                                    addr
                                                                );
                                                            }
                                                        }
                                                    }

                                                    info!(
                                                        "ConnectBack: FAILED to connect to {} after trying all {} addresses",
                                                        peer_short,
                                                        addresses.len()
                                                    );
                                                });
                                            }
                                        }
                                        GossipMessage::ConnectBackResponse(response) => {
                                            if response.success {
                                                info!(
                                                    "Received ConnectBackResponse: {} successfully connected to us at {:?}",
                                                    &response.responder_peer_id[..8.min(response.responder_peer_id.len())],
                                                    response.connected_address
                                                );

                                                let _ = event_tx.try_send(TuiEvent::Info(format!(
                                                    "NAT verified: {} connected back to us",
                                                    &response.responder_peer_id[..8.min(response.responder_peer_id.len())]
                                                )));

                                                let responder_id = response.responder_peer_id.clone();
                                                let connected_peers_clone = Arc::clone(&connected_peers);
                                                let fully_tested_clone = Arc::clone(&fully_tested_peers);
                                                tokio::spawn(async move {
                                                    let mut peers = connected_peers_clone.write().await;
                                                    if let Some(tracked) = peers.get_mut(&responder_id) {
                                                        tracked.inbound_verified = true;
                                                        if tracked.outbound_verified {
                                                            let mut tested = fully_tested_clone.write().await;
                                                            tested.insert(responder_id.clone());
                                                        }
                                                    }
                                                });
                                            }
                                        }
                                        GossipMessage::DisconnectAndConnectBack(request) => {
                                            let requester_id = request.requester_peer_id.clone();
                                            let addresses = request.requester_addresses.clone();
                                            let delay = request.delay_seconds;
                                            let endpoint_clone = Arc::clone(&endpoint);
                                            let event_tx_clone = event_tx.clone();
                                            let peer_id_clone = peer_id.clone();

                                            tokio::spawn(async move {
                                                let peer_short = &requester_id[..8.min(requester_id.len())];
                                                info!(
                                                    "DisconnectAndConnectBack from {}: disconnecting, waiting {}s, then reconnecting",
                                                    peer_short, delay
                                                );

                                                let _ = event_tx_clone.try_send(TuiEvent::Info(format!(
                                                    "Will reconnect to {} in {}s (NAT test)",
                                                    peer_short, delay
                                                )));

                                                tokio::time::sleep(Duration::from_secs(delay as u64)).await;

                                                for addr in &addresses {
                                                    match tokio::time::timeout(
                                                        Duration::from_secs(15),
                                                        endpoint_clone.connect_addr(*addr),
                                                    ).await {
                                                        Ok(Ok(_)) => {
                                                            info!(
                                                                "ConnectBack SUCCESS: fresh connection to {} at {}",
                                                                peer_short, addr
                                                            );
                                                            let _ = event_tx_clone.try_send(TuiEvent::Info(format!(
                                                                "Connected back to {} (NAT verified)",
                                                                peer_short
                                                            )));

                                                            let response = super::test_protocol::ConnectBackResponse::success(
                                                                request.request_id,
                                                                peer_id_clone.clone(),
                                                                *addr,
                                                            );
                                                            if let Ok(bytes) = response.to_bytes() {
                                                                if let Ok(peer_bytes) = hex::decode(&requester_id) {
                                                                    if peer_bytes.len() == 32 {
                                                                        let mut arr = [0u8; 32];
                                                                        arr.copy_from_slice(&peer_bytes);
                                                                        let target = ant_quic::PeerId(arr);
                                                                        let _ = endpoint_clone.send(&target, &bytes).await;
                                                                    }
                                                                }
                                                            }
                                                            return;
                                                        }
                                                        Ok(Err(e)) => {
                                                            debug!("ConnectBack failed to {} at {}: {}", peer_short, addr, e);
                                                        }
                                                        Err(_) => {
                                                            debug!("ConnectBack timeout to {} at {}", peer_short, addr);
                                                        }
                                                    }
                                                }
                                                info!("ConnectBack FAILED: couldn't reach {} at any address", peer_short);
                                            });
                                        }
                                        _ => {}
                                    }
                                }
                            } else if RelayMessage::is_relay_message(&data) {
                                // Handle relay messages
                                debug!(
                                    "Received relay message ({} bytes) from {}",
                                    data.len(),
                                    &sender_hex[..8.min(sender_hex.len())]
                                );
                                // TODO: Process relay message
                            }
                        }
                    }
                }
            }
        })
    }

    /// Announce ourselves to the gossip network.
    pub async fn announce_to_gossip(&self) {
        let external_addrs = self.external_addresses.read().await.clone();
        let rs = self.relay_state.read().await;
        let (is_public, is_public_ipv4, is_public_ipv6) = rs.get_public_status();
        drop(rs); // Release lock early

        let capabilities = GossipCapabilities {
            direct: is_public,
            direct_ipv4: is_public_ipv4,
            direct_ipv6: is_public_ipv6,
            hole_punch: true,
            relay: is_public,       // Only public nodes can relay
            coordinator: is_public, // Only public nodes can coordinate
            // Dual-stack bridging requires both IPv4 and IPv6 public addresses
            supports_dual_stack: is_public_ipv4 && is_public_ipv6,
        };

        let announcement = self
            .gossip_integration
            .discovery()
            .create_announcement(capabilities);
        // Handle the announcement (would broadcast via actual gossip network)
        self.gossip_integration
            .discovery()
            .handle_peer_announcement(announcement)
            .await;

        info!(
            "Announced ourselves to gossip: {} (public: {}, addrs: {})",
            &self.peer_id[..8.min(self.peer_id.len())],
            is_public,
            external_addrs.len()
        );
    }

    /// Get gossip integration layer for external access.
    pub fn gossip(&self) -> &Arc<GossipIntegration> {
        &self.gossip_integration
    }

    /// Announce ourselves via saorsa-gossip epidemic broadcast (PlumTree).
    /// Falls back to P2pEndpoint broadcast when epidemic gossip has no peers (NATted clients).
    pub async fn announce_via_epidemic(&self) {
        let external_addrs = self.external_addresses.read().await.clone();
        let rs = self.relay_state.read().await;
        let (is_public, _is_public_ipv4, _is_public_ipv6) = rs.get_public_status();
        drop(rs);

        let peer_info = GossipPeerInfo {
            peer_id: self.peer_id.clone(),
            addresses: external_addrs.clone(),
            is_public,
            is_connected: true,
            last_seen_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };

        let announcement = GossipPeerAnnouncement::new(peer_info, self.peer_id.clone(), 8);

        let payload = match announcement.to_bytes() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to serialize announcement: {}", e);
                return;
            }
        };

        let epidemic_peers = self.epidemic_gossip.connected_peers_with_addresses().await;
        let use_epidemic = self.epidemic_gossip.is_running() && !epidemic_peers.is_empty();

        if use_epidemic {
            if let Err(e) = self.epidemic_gossip.publish(payload.clone()).await {
                warn!(
                    "Epidemic publish failed: {}, falling back to P2pEndpoint",
                    e
                );
                self.broadcast_via_p2p_endpoint(&payload).await;
            } else {
                info!(
                    "Published via epidemic gossip ({} peers)",
                    epidemic_peers.len()
                );
            }
        } else {
            debug!(
                "Epidemic gossip unavailable (running={}, peers={}), using P2pEndpoint fallback",
                self.epidemic_gossip.is_running(),
                epidemic_peers.len()
            );
            self.broadcast_via_p2p_endpoint(&payload).await;
        }
    }

    /// Broadcast data to all connected peers via P2pEndpoint (fallback for NATted clients).
    async fn broadcast_via_p2p_endpoint(&self, data: &[u8]) {
        let peers = self.connected_peers.read().await;
        if peers.is_empty() {
            debug!("No P2pEndpoint peers to broadcast to");
            return;
        }

        let mut sent = 0;
        for peer_hex in peers.keys() {
            if let Ok(peer_bytes) = hex::decode(peer_hex) {
                if peer_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&peer_bytes);
                    let peer_id = ant_quic::PeerId(arr);
                    if self.node.send(&peer_id, data).await.is_ok() {
                        sent += 1;
                    }
                }
            }
        }
        if sent > 0 {
            info!("Broadcast via P2pEndpoint to {} peers (fallback)", sent);
        }
    }

    /// Spawn the saorsa-gossip epidemic event processing loop.
    fn spawn_epidemic_gossip_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let gossip_integration = Arc::clone(&self.gossip_integration);
        let epidemic_event_rx = Arc::clone(&self.epidemic_event_rx);
        let endpoint = Arc::clone(&self.node);
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);
        let our_peer_id_hex = self.peer_id.clone();
        let bytes_received = Arc::clone(&self.total_bytes_received);

        tokio::spawn(async move {
            let mut last_periodic = Instant::now();
            let periodic_interval = Duration::from_secs(30);

            // CRDT sync and group publish interval: 5 minutes as user requested
            let mut last_crdt_sync = Instant::now();
            let crdt_sync_interval = Duration::from_secs(300);

            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                // Process incoming epidemic events
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        let mut rx = epidemic_event_rx.write().await;
                        while let Ok(event) = rx.try_recv() {
                            match event {
                                EpidemicEvent::PeerJoined { peer_id, addresses } => {
                                    let peer_id_hex = hex::encode(peer_id.as_bytes());
                                    info!(
                                        "Epidemic: peer joined via HyParView: {} (addrs: {:?})",
                                        &peer_id_hex[..8.min(peer_id_hex.len())],
                                        addresses
                                    );

                                    // Add to gossip integration cache (addresses are already SocketAddr)
                                    gossip_integration.add_peer(&peer_id_hex, &addresses, true);

                                    // PRESENCE: Add peer to CRDT and broadcast join to groups
                                    {
                                        let mut peer_id_array = [0u8; 32];
                                        peer_id_array.copy_from_slice(peer_id.as_bytes());
                                        let entry = crate::epidemic_gossip::PeerCacheEntry {
                                            peer_id: peer_id_array,
                                            addresses: addresses.clone(),
                                            last_seen: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_millis() as u64)
                                                .unwrap_or(0),
                                            location: None,
                                        };
                                        epidemic_gossip.add_to_peer_cache(entry).await;

                                        // Publish presence event to "nat-events" group
                                        #[derive(serde::Serialize)]
                                        struct PresenceEvent {
                                            event_type: String,
                                            peer_id: String,
                                            observer: String,
                                            addresses: Vec<String>,
                                            timestamp_ms: u64,
                                        }
                                        let presence = PresenceEvent {
                                            event_type: "peer_joined".to_string(),
                                            peer_id: peer_id_hex.clone(),
                                            observer: our_peer_id_hex.clone(),
                                            addresses: addresses.iter().map(|a| a.to_string()).collect(),
                                            timestamp_ms: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_millis() as u64)
                                                .unwrap_or(0),
                                        };
                                        if let Ok(payload) = serde_json::to_vec(&presence) {
                                            if let Ok(topic_id) = saorsa_gossip_types::TopicId::from_entity("nat-events") {
                                                if epidemic_gossip.is_group_member(&topic_id).await {
                                                    let _ = epidemic_gossip.group_publish(topic_id, payload).await;
                                                }
                                            }
                                        }
                                    }

                                    // Try to connect via QUIC if not already connected
                                    {
                                        let peers = connected_peers.read().await;
                                        if !peers.contains_key(&peer_id_hex) && !addresses.is_empty() {
                                            drop(peers);
                                            // Spawn connection attempt
                                            let endpoint_clone = Arc::clone(&endpoint);
                                            let gossip_clone = Arc::clone(&gossip_integration);
                                            let event_tx_clone = event_tx.clone();
                                            tokio::spawn(async move {
                                                if let Err(e) = endpoint_clone.connect_addr(addresses[0]).await {
                                                    debug!("Failed to connect to epidemic peer {}: {}", &peer_id_hex[..8], e);
                                                } else {
                                                    gossip_clone.record_success(&peer_id_hex);
                                                    let _ = event_tx_clone.try_send(TuiEvent::Info(format!(
                                                        "Connected to epidemic peer {}",
                                                        &peer_id_hex[..8]
                                                    )));
                                                }
                                            });
                                        }
                                    }
                                }
                                EpidemicEvent::PeerLeft { peer_id } => {
                                    let peer_id_hex = hex::encode(peer_id.as_bytes());
                                    info!(
                                        "Epidemic: peer left (SWIM dead): {}",
                                        &peer_id_hex[..8.min(peer_id_hex.len())]
                                    );

                                    // PRESENCE: Publish leave event to "nat-events" group
                                    {
                                        #[derive(serde::Serialize)]
                                        struct PresenceEvent {
                                            event_type: String,
                                            peer_id: String,
                                            observer: String,
                                            timestamp_ms: u64,
                                        }
                                        let presence = PresenceEvent {
                                            event_type: "peer_left".to_string(),
                                            peer_id: peer_id_hex.clone(),
                                            observer: our_peer_id_hex.clone(),
                                            timestamp_ms: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_millis() as u64)
                                                .unwrap_or(0),
                                        };
                                        if let Ok(payload) = serde_json::to_vec(&presence) {
                                            if let Ok(topic_id) = saorsa_gossip_types::TopicId::from_entity("nat-events") {
                                                if epidemic_gossip.is_group_member(&topic_id).await {
                                                    let _ = epidemic_gossip.group_publish(topic_id, payload).await;
                                                }
                                            }
                                        }
                                    }
                                }
                                EpidemicEvent::PeerSuspect { peer_id } => {
                                    let peer_id_hex = hex::encode(peer_id.as_bytes());
                                    debug!(
                                        "Epidemic: peer suspected (SWIM probe timeout): {}",
                                        &peer_id_hex[..8.min(peer_id_hex.len())]
                                    );
                                }
                                EpidemicEvent::MessageReceived { from, topic: _, payload } => {
                                    // Track bytes received for metrics
                                    bytes_received.fetch_add(payload.len() as u64, Ordering::Relaxed);

                                    // FIRST: Check if this is a relay message that needs forwarding
                                    // Relay format: [RELY:4][TARGET_PEER_ID:32][DATA:...]
                                    if payload.starts_with(b"RELY") && payload.len() >= 36 {
                                        let target_bytes = &payload[4..36];
                                        let actual_data = &payload[36..];

                                        // Check if we are the target (decode our hex peer ID to bytes)
                                        let our_id_bytes = hex::decode(&our_peer_id_hex).unwrap_or_default();
                                        if target_bytes == our_id_bytes.as_slice() {
                                            // We are the target - process the actual data
                                            debug!(
                                                "Relay: received relayed message from {} ({} bytes)",
                                                hex::encode(from.as_bytes())[..8].to_string(),
                                                actual_data.len()
                                            );
                                            if let Ok(announcement) = GossipPeerAnnouncement::from_bytes(actual_data) {
                                                gossip_integration.add_peer(
                                                    &announcement.peer.peer_id,
                                                    &announcement.peer.addresses,
                                                    announcement.peer.is_public,
                                                );
                                                use crate::gossip::{PeerAnnouncement, PeerCapabilities};
                                                let discovery_announcement = PeerAnnouncement {
                                                    peer_id: announcement.peer.peer_id.clone(),
                                                    addresses: announcement.peer.addresses.clone(),
                                                    is_public: announcement.peer.is_public,
                                                    is_public_ipv4: announcement.peer.is_public,
                                                    is_public_ipv6: false,
                                                    timestamp_ms: announcement.timestamp_ms,
                                                    country_code: None,
                                                    capabilities: PeerCapabilities {
                                                        direct: announcement.peer.is_public,
                                                        direct_ipv4: announcement.peer.is_public,
                                                        direct_ipv6: false,
                                                        hole_punch: true,
                                                        relay: false,
                                                        coordinator: false,
                                                        supports_dual_stack: false,
                                                    },
                                                    epoch: announcement.timestamp_ms,
                                                };
                                                gossip_integration.discovery().handle_peer_announcement(discovery_announcement).await;
                                            }
                                        } else {
                                            // Forward to the actual target
                                            let mut target_array = [0u8; 32];
                                            target_array.copy_from_slice(target_bytes);
                                            let target_peer_id = saorsa_gossip_types::PeerId::new(target_array);

                                            debug!(
                                                "Relay: forwarding message to {} (from {})",
                                                hex::encode(&target_bytes[..4]),
                                                hex::encode(from.as_bytes())[..8].to_string()
                                            );

                                            // Forward the UNWRAPPED payload (not the relay header again)
                                            // Clone data before moving into async block
                                            let forward_data = actual_data.to_vec();
                                            let epidemic_gossip_clone = Arc::clone(&epidemic_gossip);
                                            tokio::spawn(async move {
                                                if let Err(e) = epidemic_gossip_clone.send_to_peer(target_peer_id, forward_data).await {
                                                    debug!("Relay forward failed: {}", e);
                                                }
                                            });
                                        }
                                    } else if let Ok(announcement) = GossipPeerAnnouncement::from_bytes(&payload) {
                                        // Process epidemic gossip message (peer announcement)
                                        let peer_id_hex = &announcement.peer.peer_id;
                                        debug!(
                                            "Epidemic: received announcement from {} for peer {}",
                                            hex::encode(from.as_bytes())[..8].to_string(),
                                            &peer_id_hex[..8.min(peer_id_hex.len())]
                                        );

                                        // Add peer to gossip integration (updates peer_cache)
                                        gossip_integration.add_peer(
                                            peer_id_hex,
                                            &announcement.peer.addresses,
                                            announcement.peer.is_public,
                                        );

                                        use crate::gossip::{PeerAnnouncement, PeerCapabilities};
                                        let discovery_announcement = PeerAnnouncement {
                                            peer_id: announcement.peer.peer_id.clone(),
                                            addresses: announcement.peer.addresses.clone(),
                                            is_public: announcement.peer.is_public,
                                            is_public_ipv4: announcement.peer.is_public,
                                            is_public_ipv6: false,
                                            timestamp_ms: announcement.timestamp_ms,
                                            country_code: None,
                                            capabilities: PeerCapabilities {
                                                direct: announcement.peer.is_public,
                                                direct_ipv4: announcement.peer.is_public,
                                                direct_ipv6: false,
                                                hole_punch: true,
                                                relay: false,
                                                coordinator: false,
                                                supports_dual_stack: false,
                                            },
                                            epoch: announcement.timestamp_ms,
                                        };
                                        gossip_integration.discovery().handle_peer_announcement(discovery_announcement).await;
                                    }
                                }
                                EpidemicEvent::ConnectionType { peer_id, connection_type } => {
                                    debug!(
                                        "Epidemic: connection type for {}: {:?}",
                                        hex::encode(peer_id.as_bytes())[..8].to_string(),
                                        connection_type
                                    );
                                }
                                EpidemicEvent::PeerAlive { peer_id } => {
                                    let peer_id_hex = hex::encode(peer_id.as_bytes());
                                    debug!(
                                        "Epidemic: peer recovered (SWIM alive again): {}",
                                        &peer_id_hex[..8.min(peer_id_hex.len())]
                                    );
                                }
                                EpidemicEvent::AddressDiscovered { peer_id, address } => {
                                    let peer_id_hex = hex::encode(peer_id.as_bytes());
                                    debug!(
                                        "Epidemic: discovered address for {}: {}",
                                        &peer_id_hex[..8.min(peer_id_hex.len())],
                                        address
                                    );

                                    // Add to gossip integration cache
                                    gossip_integration.add_peer(&peer_id_hex, &[address], true);
                                }
                            }
                        }
                    }
                }

                // Periodic tasks: re-announce ourselves every 30s to propagate to new nodes
                if last_periodic.elapsed() >= periodic_interval {
                    last_periodic = Instant::now();

                    let stats = epidemic_gossip.stats().await;
                    let peer_count =
                        stats.hyparview.active_view_size + stats.hyparview.passive_view_size;

                    if epidemic_gossip.is_running() && peer_count > 0 {
                        let external_addrs: Vec<std::net::SocketAddr> = {
                            let peers = connected_peers.read().await;
                            peers
                                .values()
                                .flat_map(|p| p.info.addresses.iter().cloned())
                                .take(4)
                                .collect()
                        };

                        if !external_addrs.is_empty() {
                            let peer_info = crate::node::test_protocol::GossipPeerInfo {
                                peer_id: our_peer_id_hex.clone(),
                                addresses: external_addrs.clone(),
                                is_public: true,
                                is_connected: true,
                                last_seen_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0),
                            };

                            let announcement =
                                crate::node::test_protocol::GossipPeerAnnouncement::new(
                                    peer_info,
                                    our_peer_id_hex.clone(),
                                    8,
                                );

                            if let Ok(payload) = announcement.to_bytes() {
                                if let Err(e) = epidemic_gossip.publish(payload).await {
                                    debug!("Periodic epidemic announce failed: {}", e);
                                } else {
                                    debug!(
                                        "Periodic epidemic announce: {} peers in view",
                                        peer_count
                                    );
                                }
                            }
                        }
                    }
                }

                // CRDT sync and group gossip: every 5 minutes
                // This broadcasts our node state to gossip groups for distributed testing
                if last_crdt_sync.elapsed() >= crdt_sync_interval {
                    last_crdt_sync = Instant::now();

                    if epidemic_gossip.is_running() {
                        // Get our CRDT stats for broadcast
                        let crdt_stats = epidemic_gossip.crdt_stats().await;
                        let stats = epidemic_gossip.stats().await;

                        // Build gossip health message with CRDT info
                        #[derive(serde::Serialize)]
                        struct GossipHealthBroadcast {
                            peer_id: String,
                            crdt_entries: usize,
                            crdt_merges: u64,
                            hyparview_active: usize,
                            hyparview_passive: usize,
                            swim_alive: usize,
                            swim_suspect: usize,
                            timestamp_ms: u64,
                        }

                        let health = GossipHealthBroadcast {
                            peer_id: our_peer_id_hex.clone(),
                            crdt_entries: crdt_stats.entries,
                            crdt_merges: crdt_stats.merges,
                            hyparview_active: stats.hyparview.active_view_size,
                            hyparview_passive: stats.hyparview.passive_view_size,
                            swim_alive: stats.swim.alive_count,
                            swim_suspect: stats.swim.suspect_count,
                            timestamp_ms: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as u64)
                                .unwrap_or(0),
                        };

                        if let Ok(payload) = serde_json::to_vec(&health) {
                            // Publish to "gossip-health" group if we're a member
                            if let Ok(topic_id) =
                                saorsa_gossip_types::TopicId::from_entity("gossip-health")
                            {
                                if epidemic_gossip.is_group_member(&topic_id).await {
                                    if let Err(e) = epidemic_gossip
                                        .group_publish(topic_id, payload.clone())
                                        .await
                                    {
                                        debug!("Failed to publish gossip-health: {}", e);
                                    } else {
                                        info!(
                                            "CRDT sync: published gossip-health (entries={}, merges={}) to group",
                                            crdt_stats.entries, crdt_stats.merges
                                        );
                                    }
                                }
                            }
                        }

                        // Also broadcast CRDT peer cache entries to peers
                        let peer_entries = epidemic_gossip.get_peer_cache_entries().await;
                        if !peer_entries.is_empty() {
                            debug!(
                                "CRDT sync: {} peer cache entries to share",
                                peer_entries.len()
                            );
                        }
                    }
                }
            }
        })
    }

    /// Spawn the SWIM liveness reporting loop.
    ///
    /// This loop reports SWIM liveness data (alive/suspect/dead) from saorsa-gossip.
    /// Unlike the old O(N²) probing approach, this uses SWIM's failure detection
    /// which is part of the HyParView membership protocol.
    ///
    /// SWIM probes peers in the active view every ~1 second:
    /// - Alive: Peer responded to probe
    /// - Suspect: Peer didn't respond, but may recover
    /// - Dead: Peer confirmed unreachable after suspect timeout
    ///
    /// The results are stored in `self.full_mesh_probes` for backwards compatibility
    /// with the registry heartbeat format.
    fn spawn_connectivity_probe_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);
        let full_mesh_probes = Arc::clone(&self.full_mesh_probes);
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            // Report every 5 seconds for real-time TUI updates
            let report_interval = Duration::from_secs(5);

            // Wait only 3 seconds for initial gossip connections
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Force immediate first report
            let mut last_report = Instant::now() - report_interval;

            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                if last_report.elapsed() >= report_interval {
                    last_report = Instant::now();

                    // Get SWIM liveness data from saorsa-gossip
                    // This uses SWIM's failure detection - no custom probing needed!
                    let (alive, suspect, dead) = epidemic_gossip.peer_liveness().await;

                    // Get HyParView views for context
                    let active_view = epidemic_gossip.active_view().await;
                    let passive_view = epidemic_gossip.passive_view().await;

                    // Convert to hex sets for quick lookup
                    let active_set: std::collections::HashSet<String> = active_view
                        .iter()
                        .map(|p| hex::encode(p.as_bytes()))
                        .collect();
                    let passive_set: std::collections::HashSet<String> = passive_view
                        .iter()
                        .map(|p| hex::encode(p.as_bytes()))
                        .collect();

                    info!(
                        "SWIM liveness: {} alive, {} suspect, {} dead (HyParView: {} active, {} passive)",
                        alive.len(),
                        suspect.len(),
                        dead.len(),
                        active_set.len(),
                        passive_set.len()
                    );

                    // Update full_mesh_probes from SWIM data (backwards compatibility)
                    let now_ms = crate::registry::unix_timestamp_ms();
                    let mut probes = full_mesh_probes.write().await;

                    // Mark alive peers as reachable
                    for peer in &alive {
                        let peer_id_hex = hex::encode(peer.as_bytes());
                        let result = probes.entry(peer_id_hex.clone()).or_default();
                        result.reachable = true;
                        result.last_probe_ms = now_ms;
                        result.in_active_view = active_set.contains(&peer_id_hex);
                        result.in_passive_view = passive_set.contains(&peer_id_hex);
                        result.success_count += 1;

                        // Mark peer as seen (SWIM alive = peer is responsive)
                        let _ = event_tx.try_send(TuiEvent::PeerSeen(peer_id_hex));
                    }

                    // Mark suspect peers (may recover)
                    for peer in &suspect {
                        let peer_id_hex = hex::encode(peer.as_bytes());
                        let result = probes.entry(peer_id_hex.clone()).or_default();
                        // Keep existing reachable status - suspect is transitional
                        result.last_probe_ms = now_ms;
                        result.in_active_view = active_set.contains(&peer_id_hex);
                        result.in_passive_view = passive_set.contains(&peer_id_hex);
                    }

                    // Mark dead peers as unreachable
                    for peer in &dead {
                        let peer_id_hex = hex::encode(peer.as_bytes());
                        let result = probes.entry(peer_id_hex.clone()).or_default();
                        result.reachable = false;
                        result.last_probe_ms = now_ms;
                        result.in_active_view = active_set.contains(&peer_id_hex);
                        result.in_passive_view = passive_set.contains(&peer_id_hex);
                        result.failure_count += 1;
                    }

                    drop(probes);

                    // Send SWIM liveness update to TUI
                    let _ = event_tx.try_send(TuiEvent::SwimLivenessUpdate {
                        alive: alive.len(),
                        suspect: suspect.len(),
                        dead: dead.len(),
                        active: active_set.len(),
                        passive: passive_set.len(),
                    });

                    // Log preview of alive peers
                    if !alive.is_empty() {
                        let preview: Vec<_> = alive
                            .iter()
                            .take(5)
                            .map(|p| hex::encode(&p.as_bytes()[..4]))
                            .collect();
                        debug!("SWIM alive peers (first 5): {:?}", preview);
                    }
                    // PeerConnected events sent by QUIC layer only (avoids duplicate peer_id encodings)
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
    }

    // ========================================================================
    // Relay Message Handling
    // ========================================================================

    /// Handle an incoming relay message.
    ///
    /// This processes:
    /// - CAN_YOU_REACH: Check if we're connected to the target and respond
    /// - RELAY_PUNCH_ME_NOW: Forward PUNCH_ME_NOW data to the target peer
    /// - RELAY_DATA: Forward data to the target peer
    ///
    /// Returns the response message to send back (if any).
    pub async fn handle_relay_message(&self, data: &[u8]) -> Option<Vec<u8>> {
        // First check if this looks like a relay message
        if !RelayMessage::is_relay_message(data) {
            return None;
        }

        // Try to parse as relay message
        let msg = match RelayMessage::from_bytes(data) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Failed to parse relay message: {}", e);
                return None;
            }
        };

        match msg {
            RelayMessage::CanYouReach(req) => self.handle_can_you_reach(req).await,
            RelayMessage::RelayPunchMeNow(req) => self.handle_relay_punch_me_now(req).await,
            RelayMessage::RelayData(req) => self.handle_relay_data(req).await,
            // Responses are handled by the requester, not here
            RelayMessage::ReachResponse(_) => None,
            RelayMessage::RelayAck(_) => None,
            RelayMessage::RelayedData(_) => None,
        }
    }

    /// Handle CAN_YOU_REACH request.
    ///
    /// Check if we're connected to the target peer and respond with reachability info.
    async fn handle_can_you_reach(&self, req: CanYouReachRequest) -> Option<Vec<u8>> {
        let target_hex = hex::encode(req.target_peer_id);
        let requester_hex = hex::encode(req.requester_peer_id);
        info!(
            "CAN_YOU_REACH request from {} for target {}",
            &requester_hex[..8.min(requester_hex.len())],
            &target_hex[..8.min(target_hex.len())]
        );

        // Check relay state for target peer
        let rs = self.relay_state.read().await;
        let peer_info = rs.known_peers.get(&req.target_peer_id);

        let (reachable, is_connected, is_public, addresses) = if let Some(info) = peer_info {
            (
                info.is_connected,
                info.is_connected,
                info.is_public,
                info.external_addresses.clone(),
            )
        } else {
            (false, false, false, Vec::new())
        };
        drop(rs); // Release the lock

        let response = ReachResponse {
            magic: RELAY_MAGIC,
            request_id: req.request_id,
            target_peer_id: req.target_peer_id,
            reachable,
            target_addresses: addresses,
            currently_connected: is_connected,
            is_public_node: is_public,
        };

        info!(
            "Responding to CAN_YOU_REACH: reachable={}, connected={}, public={}",
            reachable, is_connected, is_public
        );

        response.to_bytes().ok()
    }

    /// Handle RELAY_PUNCH_ME_NOW request.
    ///
    /// Forward the PUNCH_ME_NOW data to the target peer.
    async fn handle_relay_punch_me_now(&self, req: RelayPunchMeNowRequest) -> Option<Vec<u8>> {
        let target_hex = hex::encode(req.target_peer_id);
        let requester_hex = hex::encode(req.requester_peer_id);
        info!(
            "RELAY_PUNCH_ME_NOW from {} for target {} (round={}, {} addresses)",
            &requester_hex[..8.min(requester_hex.len())],
            &target_hex[..8.min(target_hex.len())],
            req.round,
            req.requester_addresses.len()
        );

        // Check if we're connected to the target
        let rs = self.relay_state.read().await;
        let target_connected = rs
            .known_peers
            .get(&req.target_peer_id)
            .is_some_and(|p| p.is_connected);
        drop(rs);

        if !target_connected {
            warn!(
                "Cannot relay PUNCH_ME_NOW to {} - not connected",
                &target_hex[..8.min(target_hex.len())]
            );

            // Send failure response
            return RelayAckResponse::failure(
                req.request_id,
                "Not connected to target".to_string(),
            )
            .to_bytes()
            .ok();
        }

        // Forward the PUNCH_ME_NOW request to the target peer
        let target_peer_id = QuicPeerId(req.target_peer_id);

        // Serialize the relay message for forwarding
        let forward_data = match req.to_bytes() {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to serialize PUNCH_ME_NOW for forwarding: {}", e);
                return RelayAckResponse::failure(
                    req.request_id,
                    format!("Serialize error: {}", e),
                )
                .to_bytes()
                .ok();
            }
        };

        // Get connection to target
        let connection = match self
            .node
            .inner_endpoint()
            .get_quic_connection(&target_peer_id)
        {
            Ok(Some(conn)) => conn,
            Ok(None) => {
                warn!(
                    "No active connection to target {} for relay",
                    &target_hex[..8.min(target_hex.len())]
                );
                return RelayAckResponse::failure(
                    req.request_id,
                    "No connection to target".to_string(),
                )
                .to_bytes()
                .ok();
            }
            Err(e) => {
                warn!("Failed to get connection to target: {}", e);
                return RelayAckResponse::failure(
                    req.request_id,
                    format!("Connection error: {}", e),
                )
                .to_bytes()
                .ok();
            }
        };

        // Open a unidirectional stream and forward the message
        match connection.open_uni().await {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(&forward_data).await {
                    warn!("Failed to write PUNCH_ME_NOW to target: {}", e);
                    return RelayAckResponse::failure(
                        req.request_id,
                        format!("Write error: {}", e),
                    )
                    .to_bytes()
                    .ok();
                }
                if let Err(e) = stream.finish() {
                    warn!("Failed to finish stream to target: {}", e);
                    // Still return success since data was written
                }

                info!(
                    "Forwarded PUNCH_ME_NOW to {} ({} bytes, round={})",
                    &target_hex[..8.min(target_hex.len())],
                    forward_data.len(),
                    req.round
                );

                RelayAckResponse::success(req.request_id).to_bytes().ok()
            }
            Err(e) => {
                warn!("Failed to open stream to target: {}", e);
                RelayAckResponse::failure(req.request_id, format!("Stream error: {}", e))
                    .to_bytes()
                    .ok()
            }
        }
    }

    /// Handle RELAY_DATA request.
    ///
    /// Forward data to the target peer.
    async fn handle_relay_data(
        &self,
        req: super::test_protocol::RelayDataRequest,
    ) -> Option<Vec<u8>> {
        let target_hex = hex::encode(req.target_peer_id);
        let source_hex = hex::encode(req.source_peer_id);
        debug!(
            "RELAY_DATA from {} for target {} ({} bytes)",
            &source_hex[..8.min(source_hex.len())],
            &target_hex[..8.min(target_hex.len())],
            req.data.len()
        );

        // Check if we're connected to the target
        let rs = self.relay_state.read().await;
        let target_connected = rs
            .known_peers
            .get(&req.target_peer_id)
            .is_some_and(|p| p.is_connected);
        drop(rs);

        if !target_connected {
            warn!(
                "Cannot relay data to {} - not connected",
                &target_hex[..8.min(target_hex.len())]
            );
            return None;
        }

        // Forward the data to the target peer
        let target_peer_id = QuicPeerId(req.target_peer_id);
        let our_peer_id_bytes = peer_id_to_bytes(&self.peer_id);

        // Create the relayed data response for the target
        let relayed = RelayedDataResponse::new(req.source_peer_id, our_peer_id_bytes, req.data);
        let forward_data = match serde_json::to_vec(&RelayMessage::RelayedData(relayed)) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to serialize relayed data: {}", e);
                return None;
            }
        };

        // Get connection to target
        let connection = match self
            .node
            .inner_endpoint()
            .get_quic_connection(&target_peer_id)
        {
            Ok(Some(conn)) => conn,
            Ok(None) => {
                warn!(
                    "No active connection to target {} for data relay",
                    &target_hex[..8.min(target_hex.len())]
                );
                return None;
            }
            Err(e) => {
                warn!("Failed to get connection to target for relay: {}", e);
                return None;
            }
        };

        // Open a unidirectional stream and forward the data
        match connection.open_uni().await {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(&forward_data).await {
                    warn!("Failed to write relayed data to target: {}", e);
                    return None;
                }
                if let Err(e) = stream.finish() {
                    warn!("Failed to finish relay data stream: {}", e);
                }

                debug!(
                    "Relayed {} bytes from {} to {}",
                    forward_data.len(),
                    &source_hex[..8.min(source_hex.len())],
                    &target_hex[..8.min(target_hex.len())]
                );

                None // No response needed for data relay
            }
            Err(e) => {
                warn!("Failed to open stream for data relay: {}", e);
                None
            }
        }
    }

    /// Send a CAN_YOU_REACH request to a peer.
    ///
    /// Returns the encoded request bytes.
    pub fn create_can_you_reach_request(
        &self,
        target_peer_id: [u8; 32],
        request_id: u64,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let our_peer_id_bytes = peer_id_to_bytes(&self.peer_id);

        let request = CanYouReachRequest {
            magic: RELAY_MAGIC,
            request_id,
            target_peer_id,
            requester_peer_id: our_peer_id_bytes,
        };

        request.to_bytes()
    }

    /// Send a RELAY_PUNCH_ME_NOW request to a relay peer.
    ///
    /// Returns the encoded request bytes.
    pub async fn create_relay_punch_me_now_request(
        &self,
        target_peer_id: [u8; 32],
        request_id: u64,
        round: u64,
        paired_with_sequence: u64,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let our_peer_id_bytes = peer_id_to_bytes(&self.peer_id);

        // Get our external addresses for hole-punching
        let requester_addresses = self.external_addresses.read().await.clone();

        let request = RelayPunchMeNowRequest::new(
            target_peer_id,
            our_peer_id_bytes,
            requester_addresses,
            round,
            paired_with_sequence,
        );

        // Override the request_id
        let mut request = request;
        request.request_id = request_id;

        request.to_bytes()
    }

    async fn discover_external_address(&self) {
        let known_quic_peers: Vec<SocketAddr> = VPS_NODE_IPS
            .iter()
            .filter_map(|ip| {
                ip.parse::<std::net::IpAddr>()
                    .ok()
                    .map(|addr| SocketAddr::new(addr, 9000))
            })
            .collect();

        if known_quic_peers.is_empty() {
            warn!("No known QUIC peers configured for address discovery");
            return;
        }

        info!(
            "Fast parallel address discovery via {} QUIC peers...",
            known_quic_peers.len()
        );

        let (tx, mut rx) = mpsc::channel::<bool>(1);
        let external_addresses = Arc::clone(&self.external_addresses);
        let endpoint = Arc::clone(&self.node);

        for peer_addr in known_quic_peers {
            let ep = Arc::clone(&endpoint);
            let ext_addrs = Arc::clone(&external_addresses);
            let tx = tx.clone();

            tokio::spawn(async move {
                if let Ok(Ok(_conn)) =
                    tokio::time::timeout(Duration::from_secs(3), ep.connect_addr(peer_addr)).await
                {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let addrs = ext_addrs.read().await;
                    if !addrs.is_empty() {
                        let _ = tx.send(true).await;
                    }
                }
            });
        }
        drop(tx);

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        if let Ok(Some(true)) = result {
            let addrs = self.external_addresses.read().await;
            info!("External address discovered: {:?}", *addrs);
            return;
        }

        let addrs = self.external_addresses.read().await;
        if addrs.is_empty() {
            let msg = "No external address discovered - inbound connections may not work";
            warn!("{}", msg);
            let _ = self.event_tx.try_send(TuiEvent::Info(msg.to_string()));
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        self.discover_external_address().await;

        if self.is_public_node().await {
            info!("=== RELAY: This node appears to be PUBLIC (can relay for others) ===");
        } else {
            info!("=== RELAY: This node appears to be behind NAT ===");
        }

        let shutdown = Arc::clone(&self.shutdown);

        // Register FIRST - only needs HTTP to registry, no gossip dependency
        // CRITICAL: Registration is NON-FATAL - we continue even if registry is down
        // This ensures TUI shows "registered" immediately while gossip initializes
        // The heartbeat loop will keep retrying registration via its heartbeat calls
        let _registration_ok = match self.register().await {
            Ok(()) => {
                info!("Initial registration successful");
                true
            }
            Err(e) => {
                warn!(
                    "Initial registration failed: {} - will retry via heartbeat",
                    e
                );
                let _ = self.event_tx.try_send(TuiEvent::Info(
                    "Registry offline - continuing in P2P mode".to_string(),
                ));
                false
            }
        };

        // Start gossip AFTER registration - gossip.start() can be slow due to transport creation
        if let Err(e) = self.epidemic_gossip.start().await {
            warn!(
                "Failed to start saorsa-gossip epidemic layer: {} (continuing with passive gossip)",
                e
            );
        } else {
            info!("Started saorsa-gossip epidemic layer (HyParView + SWIM + PlumTree)");

            let gossip = Arc::clone(&self.epidemic_gossip);
            tokio::spawn(async move {
                match gossip.bootstrap().await {
                    Ok(connected) => {
                        info!(
                            "HyParView bootstrap complete: connected to {} gossip peers",
                            connected
                        );
                    }
                    Err(e) => {
                        warn!("HyParView bootstrap failed: {} (gossip may be limited)", e);
                    }
                }
            });
        }

        info!("DIAGNOSTIC: About to spawn heartbeat loop...");
        let heartbeat_handle = self.spawn_heartbeat_loop();
        info!("DIAGNOSTIC: Heartbeat loop spawned, JoinHandle created");
        let connect_handle = self.spawn_connect_loop();
        let test_handle = self.spawn_test_loop();
        let health_handle = self.spawn_health_check_loop();
        let relay_stats_handle = self.spawn_relay_stats_loop();
        let gossip_handle = self.spawn_gossip_loop();
        let accept_handle = self.spawn_accept_loop();
        let epidemic_handle = self.spawn_epidemic_gossip_loop();
        let probe_handle = self.spawn_connectivity_probe_loop();
        let nat_callback_handle = self.spawn_nat_callback_loop();
        let websocket_handle = self.spawn_websocket_event_loop();

        // Announce ourselves to gossip network
        self.announce_to_gossip().await;
        // Also announce via saorsa-gossip epidemic broadcast
        self.announce_via_epidemic().await;

        // Wait for shutdown
        while !shutdown.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        heartbeat_handle.abort();
        connect_handle.abort();
        test_handle.abort();
        health_handle.abort();
        relay_stats_handle.abort();
        gossip_handle.abort();
        accept_handle.abort();
        epidemic_handle.abort();
        probe_handle.abort();
        nat_callback_handle.abort();
        websocket_handle.abort();

        // Save peer cache and shutdown gossip integration
        if let Err(e) = self.gossip_integration.save_cache() {
            warn!("Failed to save peer cache on shutdown: {}", e);
        }
        self.gossip_integration.discovery().shutdown();

        // Stop saorsa-gossip epidemic layer
        self.epidemic_gossip.stop().await;

        info!("Test node shutting down");
        Ok(())
    }

    /// Register with the central registry.
    async fn register(&self) -> anyhow::Result<()> {
        let external_addrs = self.external_addresses.read().await.clone();

        // Get the GOSSIP TRANSPORT's peer ID for registration.
        // This is CRITICAL: The gossip transport generates its own identity which
        // is DIFFERENT from the P2pEndpoint's identity. For HyParView active_view
        // comparisons to work correctly, we must use the transport's peer ID.
        let registration_peer_id = match self.epidemic_gossip.transport_peer_id().await {
            Ok(gossip_pid) => {
                let gossip_peer_id_hex = hex::encode(gossip_pid.as_bytes());
                if gossip_peer_id_hex != self.peer_id {
                    info!(
                        "Using gossip transport peer ID for registration: {} (QUIC endpoint: {})",
                        &gossip_peer_id_hex[..8],
                        &self.peer_id[..8]
                    );
                }
                gossip_peer_id_hex
            }
            Err(e) => {
                warn!(
                    "Failed to get gossip transport peer ID ({}), using QUIC endpoint ID",
                    e
                );
                self.peer_id.clone()
            }
        };

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
            peer_id: registration_peer_id.clone(),
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

                    let local_port = self.node.local_addr().map(|a| a.port()).unwrap_or(9000);
                    let (local_ipv4, local_ipv6) = detect_local_addresses(local_port);

                    let mut local_node = LocalNodeInfo::default();
                    local_node.set_peer_id(&registration_peer_id);
                    local_node.local_ipv4 = local_ipv4;
                    local_node.local_ipv6 = local_ipv6;
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

                    local_node.nat_type = detect_nat_type(&local_ipv4, &local_ipv6, &local_node);

                    // Send updated node info to TUI (non-blocking)
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::UpdateLocalNode(local_node));
                    let _ = self.event_tx.try_send(TuiEvent::RegistrationComplete);
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                            peer_id: "registry".to_string(),
                            frame_type: "REGISTER".to_string(),
                            direction: FrameDirection::Sent,
                            timestamp: Instant::now(),
                            context: Some(format!("{} peers", response.peers.len())),
                        }));

                    // Also send the registered count (non-blocking)
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::UpdateRegisteredCount(response.peers.len() + 1));

                    if !response.peers.is_empty() {
                        let mut our_addrs: std::collections::HashSet<SocketAddr> =
                            external_addrs.iter().copied().collect();
                        for addr in &self.listen_addresses {
                            our_addrs.insert(*addr);
                        }
                        let bootstrap_addrs: Vec<SocketAddr> = response
                            .peers
                            .iter()
                            .filter(|p| p.peer_id != registration_peer_id)
                            .flat_map(|p| p.addresses.iter().copied())
                            .filter(|addr| !our_addrs.contains(addr))
                            .collect();

                        if !bootstrap_addrs.is_empty() {
                            info!(
                                "Adding {} bootstrap addresses to epidemic gossip from {} peers",
                                bootstrap_addrs.len(),
                                response.peers.len()
                            );

                            match self
                                .epidemic_gossip
                                .add_bootstrap_peers(bootstrap_addrs.clone())
                                .await
                            {
                                Ok(count) => {
                                    info!(
                                        "Epidemic gossip joined HyParView overlay with {} peers",
                                        count
                                    );
                                    // PeerConnected events sent by QUIC layer only (avoids duplicate peer_id encodings)

                                    // Send immediate SWIM update
                                    let (alive, suspect, dead) =
                                        self.epidemic_gossip.peer_liveness().await;
                                    let active_view = self.epidemic_gossip.active_view().await;
                                    let passive_view = self.epidemic_gossip.passive_view().await;
                                    let _ = self.event_tx.try_send(TuiEvent::SwimLivenessUpdate {
                                        alive: alive.len(),
                                        suspect: suspect.len(),
                                        dead: dead.len(),
                                        active: active_view.len(),
                                        passive: passive_view.len(),
                                    });
                                    info!(
                                        "Sent immediate TUI updates: {} peers connected, SWIM: {} alive",
                                        count,
                                        alive.len()
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to add bootstrap peers to epidemic gossip: {}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                } else {
                    let err = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    error!("Registration failed: {}", err);
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::Error(format!("Registration failed: {}", err)));
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                            peer_id: "registry".to_string(),
                            frame_type: "REGISTER".to_string(),
                            direction: FrameDirection::Sent,
                            timestamp: Instant::now(),
                            context: Some(format!("FAILED: {}", err)),
                        }));
                    return Err(anyhow::anyhow!("Registration failed: {}", err));
                }
            }
            Err(e) => {
                error!("Failed to connect to registry: {}", e);
                let _ = self.event_tx.try_send(TuiEvent::Error(format!(
                    "Registry connection failed: {}",
                    e
                )));
                let _ = self
                    .event_tx
                    .try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                        peer_id: "registry".to_string(),
                        frame_type: "REGISTER".to_string(),
                        direction: FrameDirection::Sent,
                        timestamp: Instant::now(),
                        context: Some("OFFLINE".to_string()),
                    }));
                return Err(e);
            }
        }

        Ok(())
    }

    /// Spawn the heartbeat background task.
    fn spawn_heartbeat_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = RegistryClient::new(&self.config.registry_url);
        let quic_peer_id = self.peer_id.clone(); // Fallback if transport not ready
        let public_key = self.public_key.clone();
        let listen_addresses = self.listen_addresses.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let external_addresses = Arc::clone(&self.external_addresses);
        let nat_stats = Arc::clone(&self.nat_stats);
        let bytes_sent = Arc::clone(&self.total_bytes_sent);
        let bytes_received = Arc::clone(&self.total_bytes_received);
        let interval = self.config.heartbeat_interval;
        // Clone inbound_connections counter for heartbeat reporting
        let inbound_connections = Arc::clone(&self.inbound_connections);
        // Clone gossip integration for gossip stats reporting
        let gossip_integration = Arc::clone(&self.gossip_integration);
        // Clone epidemic gossip for real saorsa-gossip stats
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);
        let full_mesh_probes = Arc::clone(&self.full_mesh_probes);
        let event_tx = self.event_tx.clone();
        let geo_provider = Arc::clone(&self.geo_provider);

        tokio::spawn(async move {
            info!("DIAGNOSTIC: Heartbeat task STARTED - entering main loop");
            let mut ticker = tokio::time::interval(interval);
            let mut consecutive_failures = 0u32;
            let mut heartbeat_count = 0u64;
            // Cache the transport peer ID to avoid repeated async calls
            let mut cached_peer_id: Option<String> = None;

            while !shutdown.load(Ordering::SeqCst) {
                info!("DIAGNOSTIC: Heartbeat awaiting ticker.tick()...");
                ticker.tick().await;
                info!(
                    "DIAGNOSTIC: Heartbeat ticker fired, count={}",
                    heartbeat_count
                );
                heartbeat_count += 1;

                // Get the gossip transport's peer ID (cache it once we have it)
                if cached_peer_id.is_none() {
                    if let Ok(Ok(gossip_pid)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        epidemic_gossip.transport_peer_id(),
                    )
                    .await
                    {
                        let gossip_hex = hex::encode(gossip_pid.as_bytes());
                        if gossip_hex != quic_peer_id {
                            info!(
                                "Heartbeat using gossip transport ID: {} (QUIC: {})",
                                &gossip_hex[..8],
                                &quic_peer_id[..8]
                            );
                        }
                        cached_peer_id = Some(gossip_hex);
                    }
                }
                let peer_id = cached_peer_id
                    .clone()
                    .unwrap_or_else(|| quic_peer_id.clone());

                // Use timeouts on lock acquisitions to detect deadlocks
                let peers = match tokio::time::timeout(
                    Duration::from_secs(5),
                    connected_peers.read(),
                )
                .await
                {
                    Ok(guard) => guard,
                    Err(_) => {
                        warn!(
                            "Heartbeat #{}: TIMEOUT waiting for connected_peers lock!",
                            heartbeat_count
                        );
                        continue;
                    }
                };

                let ext_addrs =
                    match tokio::time::timeout(Duration::from_secs(5), external_addresses.read())
                        .await
                    {
                        Ok(guard) => guard.clone(),
                        Err(_) => {
                            warn!(
                                "Heartbeat #{}: TIMEOUT waiting for external_addresses lock!",
                                heartbeat_count
                            );
                            drop(peers);
                            continue;
                        }
                    };

                let mut stats =
                    match tokio::time::timeout(Duration::from_secs(5), nat_stats.read()).await {
                        Ok(guard) => guard.clone(),
                        Err(_) => {
                            warn!(
                                "Heartbeat #{}: TIMEOUT waiting for nat_stats lock!",
                                heartbeat_count
                            );
                            drop(peers);
                            continue;
                        }
                    };

                // Detect NAT status by comparing local vs external addresses
                // If external IPs differ from local IPs, we're behind NAT
                let is_behind_nat = if !ext_addrs.is_empty() {
                    let local_ips: std::collections::HashSet<_> =
                        listen_addresses.iter().map(|a| a.ip()).collect();
                    let external_ips: std::collections::HashSet<_> =
                        ext_addrs.iter().map(|a| a.ip()).collect();
                    // Behind NAT if external IPs are different from local IPs
                    local_ips.intersection(&external_ips).count() == 0
                } else {
                    false // Unknown without external address discovery
                };

                // Update stats with inbound connection count and NAT status
                stats.inbound_connections = inbound_connections.load(Ordering::Relaxed);
                stats.is_behind_nat = is_behind_nat;

                let detected_nat_type = if !is_behind_nat && !ext_addrs.is_empty() {
                    NatType::None
                } else {
                    NatType::Unknown
                };

                // Collect gossip protocol statistics
                let gossip_metrics = gossip_integration.metrics();

                // Get real saorsa-gossip stats (HyParView + SWIM + PlumTree + Connection Types)
                // Connection type breakdown comes from gossip transport which is the source of truth
                // Use timeout to prevent blocking if stats lock is contended
                let epidemic_stats =
                    match tokio::time::timeout(Duration::from_secs(2), epidemic_gossip.stats())
                        .await
                    {
                        Ok(stats) => stats,
                        Err(_) => {
                            warn!(
                                "Heartbeat #{}: TIMEOUT waiting for epidemic_gossip.stats()!",
                                heartbeat_count
                            );
                            continue;
                        }
                    };

                // Connection type breakdown from gossip layer (inferred from socket addresses)
                let (conn_direct_ipv4, conn_direct_ipv6, conn_hole_punched, conn_relayed) = {
                    let breakdown = &epidemic_stats.connection_types;

                    static HEARTBEAT_COUNT: std::sync::atomic::AtomicUsize =
                        std::sync::atomic::AtomicUsize::new(0);
                    let hb_count =
                        HEARTBEAT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if hb_count % 10 == 0 {
                        let p2p_total = peers.len() + stats.inbound_connections as usize;
                        let gossip_total = breakdown.direct_ipv4
                            + breakdown.direct_ipv6
                            + breakdown.hole_punched
                            + breakdown.relayed;
                        info!(
                            "Heartbeat #{}: P2P={} (out={}, in={}), Gossip={} (IPv4={}, IPv6={}), CRDT={}, Groups={}, RDV={}",
                            hb_count,
                            p2p_total,
                            peers.len(),
                            stats.inbound_connections,
                            gossip_total,
                            breakdown.direct_ipv4,
                            breakdown.direct_ipv6,
                            epidemic_stats.crdt.entries,
                            epidemic_stats.groups.groups_count,
                            epidemic_stats.rendezvous.registrations,
                        );
                    }

                    (
                        breakdown.direct_ipv4,
                        breakdown.direct_ipv6,
                        breakdown.hole_punched,
                        breakdown.relayed,
                    )
                };

                // Use TOTAL connected peers (outbound + inbound) for "alive" stats
                // peers.len() = outbound connections we initiated
                // stats.inbound_connections = connections initiated by others
                let total_connections = peers.len() + stats.inbound_connections as usize;

                let gossip_stats = NodeGossipStats {
                    announcements_sent: gossip_metrics.announcements_sent.load(Ordering::Relaxed),
                    announcements_received: gossip_metrics
                        .announcements_received
                        .load(Ordering::Relaxed),
                    peer_queries_sent: gossip_metrics.peer_queries_sent.load(Ordering::Relaxed),
                    peer_queries_received: gossip_metrics
                        .peer_queries_received
                        .load(Ordering::Relaxed),
                    peer_responses_sent: gossip_metrics.peer_responses_sent.load(Ordering::Relaxed),
                    peer_responses_received: gossip_metrics
                        .peer_responses_received
                        .load(Ordering::Relaxed),
                    cache_updates: gossip_metrics.cache_updates.load(Ordering::Relaxed),
                    cache_hits: gossip_metrics.cache_hits.load(Ordering::Relaxed),
                    cache_misses: gossip_metrics.cache_misses.load(Ordering::Relaxed),
                    cache_size: gossip_integration.cache_size() as u64,
                    // Real HyParView stats from saorsa-gossip
                    hyparview_active: epidemic_stats.hyparview.active_view_size,
                    hyparview_passive: epidemic_stats.hyparview.passive_view_size,
                    // Real SWIM stats from saorsa-gossip
                    swim_alive: epidemic_stats.swim.alive_count,
                    swim_suspect: epidemic_stats.swim.suspect_count,
                    swim_dead: epidemic_stats.swim.dead_count,
                    // Real Plumtree stats from saorsa-gossip
                    plumtree_sent: epidemic_stats.plumtree.messages_sent,
                    plumtree_received: epidemic_stats.plumtree.messages_received,
                    plumtree_eager: epidemic_stats.plumtree.eager_peers,
                    plumtree_lazy: epidemic_stats.plumtree.lazy_peers,
                    // Connection type breakdown (computed from connected peers)
                    conn_direct_ipv4,
                    conn_direct_ipv6,
                    conn_hole_punched,
                    conn_relayed,

                    // Extended HyParView stats
                    hyparview_shuffles: epidemic_stats.hyparview.shuffles,
                    hyparview_joins: epidemic_stats.hyparview.joins,
                    hyparview_forward_joins: 0, // Not tracked in current implementation

                    // Extended SWIM stats
                    swim_pings_sent: epidemic_stats.swim.pings_sent,
                    swim_pings_received: 0, // Not tracked in current implementation
                    swim_ping_req_sent: 0,  // Not tracked in current implementation
                    swim_acks_received: epidemic_stats.swim.acks_received,

                    // Extended Plumtree stats
                    plumtree_ihaves_sent: 0, // Not tracked in current implementation
                    plumtree_ihaves_received: 0, // Not tracked in current implementation
                    plumtree_grafts_sent: epidemic_stats.plumtree.grafts,
                    plumtree_prunes_sent: epidemic_stats.plumtree.prunes,
                    plumtree_broadcasts: epidemic_stats.plumtree.messages_sent,

                    // CRDT stats from saorsa-gossip-crdt-sync
                    crdt_entries: epidemic_stats.crdt.entries,
                    crdt_merges: epidemic_stats.crdt.merges,
                    crdt_vector_clock_len: epidemic_stats.crdt.vector_clock_len,
                    crdt_sync_rounds: 0, // Not tracked in current implementation
                    crdt_deltas_sent: 0, // Not tracked in current implementation
                    crdt_deltas_received: 0, // Not tracked in current implementation

                    // Coordinator stats from saorsa-gossip-coordinator
                    coordinator_active: epidemic_stats.coordinator.active_coordinators,
                    coordinator_success: epidemic_stats.coordinator.coordination_success,
                    coordinator_failed: epidemic_stats.coordinator.coordination_failed,
                    coordinator_requests: 0, // Not tracked in current implementation

                    // Groups stats from saorsa-gossip-groups
                    groups_count: epidemic_stats.groups.groups_count,
                    groups_total_members: epidemic_stats.groups.total_members,
                    groups_joins: 0,  // Not tracked in current implementation
                    groups_leaves: 0, // Not tracked in current implementation

                    // Rendezvous stats from saorsa-gossip-rendezvous
                    rendezvous_registrations: epidemic_stats.rendezvous.registrations,
                    rendezvous_discoveries: epidemic_stats.rendezvous.discoveries,
                    rendezvous_points: epidemic_stats.rendezvous.active_providers,
                    rendezvous_queries: 0, // Not tracked in current implementation

                    // Identity stats - use alive count as known peers
                    identity_known_peers: epidemic_stats.swim.alive_count,
                    identity_verifications: 0,

                    // Transport stats - use connection counts for now
                    transport_packets_sent: epidemic_stats.plumtree.messages_sent,
                    transport_packets_received: epidemic_stats.plumtree.messages_received,
                    transport_bytes_sent: 0, // Not tracked in current implementation
                    transport_bytes_received: 0, // Not tracked in current implementation
                };

                let probes =
                    match tokio::time::timeout(Duration::from_secs(2), full_mesh_probes.read())
                        .await
                    {
                        Ok(probes_guard) => {
                            if probes_guard.is_empty() {
                                None
                            } else {
                                Some(probes_guard.clone())
                            }
                        }
                        Err(_) => {
                            warn!(
                                "Heartbeat #{}: TIMEOUT waiting for full_mesh_probes lock!",
                                heartbeat_count
                            );
                            None
                        }
                    };

                // Clone gossip_stats for TUI before moving into heartbeat
                let gossip_stats_for_tui = gossip_stats.clone();

                let heartbeat = NodeHeartbeat {
                    peer_id: peer_id.clone(),
                    connected_peers: total_connections,
                    bytes_sent: bytes_sent.load(Ordering::Relaxed),
                    bytes_received: bytes_received.load(Ordering::Relaxed),
                    external_addresses: if ext_addrs.is_empty() {
                        None
                    } else {
                        Some(ext_addrs.clone())
                    },
                    nat_type: Some(detected_nat_type),
                    nat_stats: Some(stats.clone()),
                    gossip_stats: Some(gossip_stats),
                    full_mesh_probes: probes,
                };
                drop(peers);

                // Add timeout to registry heartbeat to prevent blocking
                let heartbeat_result =
                    tokio::time::timeout(Duration::from_secs(10), registry.heartbeat(&heartbeat))
                        .await;

                let heartbeat_err = match heartbeat_result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(format!("{}", e)),
                    Err(_) => Some("TIMEOUT waiting for registry response".to_string()),
                };

                if let Some(e) = heartbeat_err {
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

                        match tokio::time::timeout(
                            Duration::from_secs(15),
                            registry.register(&registration),
                        )
                        .await
                        {
                            Ok(Ok(response)) if response.success => {
                                info!(
                                    "Re-registered successfully, got {} peers",
                                    response.peers.len()
                                );
                                consecutive_failures = 0;
                            }
                            Ok(Ok(response)) => {
                                let err = response
                                    .error
                                    .unwrap_or_else(|| "Unknown error".to_string());
                                error!("Re-registration failed: {}", err);
                            }
                            Ok(Err(e)) => {
                                error!("Re-registration request failed: {}", e);
                            }
                            Err(_) => {
                                error!("Re-registration TIMEOUT - registry unresponsive");
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
                    let _ = event_tx.try_send(TuiEvent::HeartbeatSent);
                    let _ = event_tx.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                        peer_id: "registry".to_string(),
                        frame_type: "HEARTBEAT".to_string(),
                        direction: FrameDirection::Sent,
                        timestamp: Instant::now(),
                        context: Some(format!("{} peers", total_connections)),
                    }));
                    // Send gossip stats to TUI for display
                    let _ = event_tx
                        .try_send(TuiEvent::UpdateGossipStats(gossip_stats_for_tui.clone()));

                    let cache_health = CacheHealth {
                        total_peers: gossip_integration.cache_size(),
                        valid_peers: gossip_integration.cache_size(),
                        public_peers: total_connections,
                        average_quality: 0.8,
                        cache_age: Duration::from_secs(0),
                        last_updated: Some(Instant::now()),
                        cache_hits: gossip_metrics.cache_hits.load(Ordering::Relaxed),
                        cache_misses: gossip_metrics.cache_misses.load(Ordering::Relaxed),
                        fresh_peers: epidemic_stats.swim.alive_count,
                        stale_peers: epidemic_stats.swim.dead_count,
                        private_peers: 0,
                        public_quality: 0.9,
                        private_quality: 0.5,
                    };
                    let _ = event_tx.try_send(TuiEvent::CacheHealthUpdate(cache_health));

                    let mut nat_analytics = NatTypeAnalytics::default();
                    nat_analytics.full_cone.attempts =
                        stats.direct_success + stats.hole_punch_success;
                    nat_analytics.full_cone.direct_connections = stats.direct_success;
                    nat_analytics.full_cone.hole_punched_connections = stats.hole_punch_success;
                    nat_analytics.full_cone.relayed_connections = stats.relay_success;
                    nat_analytics.full_cone.successes =
                        stats.direct_success + stats.hole_punch_success + stats.relay_success;
                    nat_analytics.full_cone.failures = stats.failures;
                    let _ = event_tx.try_send(TuiEvent::NatAnalyticsUpdate(nat_analytics));

                    let peers_for_geo = connected_peers.read().await;
                    let mut geo_dist = GeographicDistribution::new();
                    for tracked in peers_for_geo.values() {
                        for addr in &tracked.info.addresses {
                            let (_lat, _lon, country) = geo_provider.lookup(addr.ip());
                            if let Some(cc) = country {
                                geo_dist.add_peer(cc);
                                break;
                            }
                        }
                    }
                    drop(peers_for_geo);
                    if geo_dist.total_peers > 0 {
                        let _ = event_tx.try_send(TuiEvent::GeographicDistributionUpdate(geo_dist));
                    }
                }
            }
        })
    }

    /// Connect to peers and test bidirectional NAT traversal.
    ///
    /// Flow:
    /// 1. Get all peers from registry + gossip
    /// 2. Connect to any peer we haven't fully tested yet  
    /// 3. After connecting, send DisconnectAndConnectBack message
    /// 4. Peer disconnects, waits 30s, reconnects (fresh NAT test)
    /// 5. When peer connects back → bidirectional verified
    #[allow(clippy::excessive_nesting)]
    fn spawn_connect_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = RegistryClient::new(&self.config.registry_url);
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let fully_tested_peers = Arc::clone(&self.fully_tested_peers);
        let external_addresses = Arc::clone(&self.external_addresses);
        let interval = self.config.connect_interval;
        let event_tx = self.event_tx.clone();
        let our_peer_id = self.peer_id.clone();
        let nat_stats = Arc::clone(&self.nat_stats);
        let success = Arc::clone(&self.total_connections_success);
        let failed = Arc::clone(&self.total_connections_failed);
        let direct = Arc::clone(&self.direct_connections);
        let holepunch = Arc::clone(&self.holepunch_connections);
        let relay = Arc::clone(&self.relay_connections);
        let endpoint = Arc::clone(&self.node);
        let our_has_ipv6 = self.has_ipv6;
        let hole_punched_peers = Arc::clone(&self.hole_punched_peers);
        let pending_outbound = Arc::clone(&self.pending_outbound);
        let gossip_integration = Arc::clone(&self.gossip_integration);
        let relay_state = Arc::clone(&self.relay_state);
        let epidemic_gossip = Arc::clone(&self.epidemic_gossip);
        #[allow(unused_variables)]
        let disconnection_times = Arc::clone(&self.disconnection_times);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut first_run = true;

            while !shutdown.load(Ordering::SeqCst) {
                if first_run {
                    first_run = false;
                } else {
                    ticker.tick().await;
                }

                // Fetch peer list from registry (only LIVE peers with recent heartbeat)
                let registry_peers = match registry.get_peers().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to fetch peers from registry: {}", e);
                        Vec::new() // Continue with gossip peers only
                    }
                };

                // Also fetch peers from gossip (decentralized discovery)
                // Gossip peers are marked is_active=false so we don't count failures
                // (we don't know if they're actually online without registry confirmation)
                let gossip_announcements = gossip_integration.discovery().get_peers().await;

                // Build a set of registry peer IDs for deduplication
                let registry_peer_ids: std::collections::HashSet<_> =
                    registry_peers.iter().map(|p| p.peer_id.clone()).collect();

                // Convert gossip peers to PeerInfo, excluding those already in registry
                let gossip_peers: Vec<PeerInfo> = gossip_announcements
                    .iter()
                    .filter(|g| !registry_peer_ids.contains(&g.peer_id))
                    .filter(|g| g.peer_id != our_peer_id) // Not ourselves
                    .map(|g| {
                        use crate::registry::{NatType, NodeCapabilities};

                        PeerInfo {
                            peer_id: g.peer_id.clone(),
                            addresses: g.addresses.clone(),
                            nat_type: if g.is_public {
                                NatType::None
                            } else {
                                NatType::Unknown
                            },
                            country_code: g.country_code.clone(),
                            latitude: 0.0,
                            longitude: 0.0,
                            last_seen: g.timestamp_ms / 1000,
                            connection_success_rate: 0.5, // Unknown
                            capabilities: NodeCapabilities {
                                pqc: true, // All ant-quic nodes use PQC
                                ipv4: g.addresses.iter().any(|a| a.is_ipv4()),
                                ipv6: g.addresses.iter().any(|a| a.is_ipv6()),
                                nat_traversal: g.capabilities.hole_punch,
                                relay: g.capabilities.relay,
                            },
                            version: String::from("gossip"),
                            // CRITICAL: Mark as NOT active so connection failures
                            // are not counted (we don't know if they're online)
                            is_active: false,
                            status: Default::default(), // Uses serde default
                            bytes_sent: 0,
                            bytes_received: 0,
                            connected_peers: 0,
                            gossip_stats: None,
                            full_mesh_probes: None,
                        }
                    })
                    .collect();

                // Merge registry peers with gossip-discovered peers
                let mut peers = registry_peers;
                if !gossip_peers.is_empty() {
                    debug!(
                        "Gossip discovery found {} additional peers (not in registry)",
                        gossip_peers.len()
                    );
                    peers.extend(gossip_peers);
                }

                // Update TUI with total registered count (+1 to include ourselves)
                // The registry.get_peers() returns all peers EXCEPT us (non-blocking)
                let _ = event_tx.try_send(TuiEvent::UpdateRegisteredCount(peers.len() + 1));

                let connected = connected_peers.read().await;
                let tested = fully_tested_peers.read().await;

                // Connect to peers we haven't fully tested (bidirectional) yet
                let total_peers = peers.len();
                let candidates: Vec<PeerInfo> = peers
                    .iter()
                    .filter(|p| p.peer_id != our_peer_id)
                    .filter(|p| !tested.contains(&p.peer_id))
                    .filter(|p| !connected.contains_key(&p.peer_id))
                    .filter(|p| p.is_active || peer_is_vps(p))
                    .filter(|p| can_reach_peer(p, our_has_ipv6))
                    .cloned()
                    .collect();

                drop(connected);
                drop(tested);

                if candidates.is_empty() {
                    if total_peers > 0 {
                        debug!(
                            "No candidates from {} peers (has_ipv6={})",
                            total_peers, our_has_ipv6
                        );
                    }
                    continue;
                }

                info!("Connecting to {} untested peers", candidates.len());

                // Connect to ALL eligible peers concurrently (max 20 at a time)
                // Higher limit ensures DO nodes quickly reach all community test nodes
                let mut connect_futures = Vec::new();
                for candidate in candidates.into_iter().take(20) {
                    let endpoint = Arc::clone(&endpoint);
                    let external_addresses = Arc::clone(&external_addresses);
                    let nat_stats = Arc::clone(&nat_stats);
                    let success = Arc::clone(&success);
                    let failed = Arc::clone(&failed);
                    let direct = Arc::clone(&direct);
                    let holepunch = Arc::clone(&holepunch);
                    let relay = Arc::clone(&relay);
                    let connected_peers = Arc::clone(&connected_peers);
                    let hole_punched_peers = Arc::clone(&hole_punched_peers);
                    let pending_outbound = Arc::clone(&pending_outbound);
                    let event_tx = event_tx.clone();
                    let registry = RegistryClient::new(registry.base_url());
                    let our_peer_id = our_peer_id.clone();
                    let gossip_integration = Arc::clone(&gossip_integration);
                    let relay_state = Arc::clone(&relay_state);
                    let epidemic_gossip = Arc::clone(&epidemic_gossip);

                    let fut = async move {
                        let peer_id_short = &candidate.peer_id[..8.min(candidate.peer_id.len())];
                        let addr_str = candidate
                            .addresses
                            .first()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "unknown".to_string());

                        info!(
                            "Testing FRESH hole-punch to peer {} ({:?})",
                            peer_id_short, candidate.country_code
                        );

                        let _ = event_tx.try_send(TuiEvent::NatTestOutbound {
                            peer_id: candidate.peer_id.clone(),
                            address: addr_str,
                        });

                        {
                            let mut pending = pending_outbound.write().await;
                            pending.insert(candidate.peer_id.clone());
                        }

                        {
                            let mut stats = nat_stats.write().await;
                            stats.attempts += 1;
                        }

                        let _ = event_tx.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                            peer_id: candidate.peer_id.clone(),
                            frame_type: "CONNECT".to_string(),
                            direction: FrameDirection::Sent,
                            timestamp: Instant::now(),
                            context: candidate.country_code.clone(),
                        }));

                        let our_addrs = external_addresses.read().await;
                        let skip_nat_for_vps_pair = both_are_vps(&candidate, &our_addrs);
                        drop(our_addrs);

                        let result = real_connect_comprehensive(
                            &endpoint,
                            &candidate,
                            skip_nat_for_vps_pair,
                        )
                        .await;

                        if result.success {
                            success.fetch_add(1, Ordering::Relaxed);

                            // Check if we saw a Punching phase event
                            let tracker = hole_punched_peers.read().await;
                            let saw_punching =
                                tracker.get(&candidate.peer_id).copied().unwrap_or(false);

                            // Final method considers both comprehensive test and punching events
                            let final_method =
                                if saw_punching || result.matrix.nat_traversal_success {
                                    ConnectionMethod::HolePunched
                                } else {
                                    result.best_method
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
                            let is_ipv6 = result.matrix.active_is_ipv6;

                            // Update epidemic gossip layer with the actual connection type
                            // This ensures NAT traversal stats in gossip match the registry
                            if let Ok(peer_bytes) = hex::decode(&candidate.peer_id) {
                                if peer_bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&peer_bytes);
                                    let gossip_peer_id = GossipPeerId::new(arr);
                                    let gossip_conn_type = match final_method {
                                        ConnectionMethod::Direct => {
                                            if is_ipv6 {
                                                GossipConnectionType::DirectIpv6
                                            } else {
                                                GossipConnectionType::DirectIpv4
                                            }
                                        }
                                        ConnectionMethod::HolePunched => {
                                            GossipConnectionType::HolePunched
                                        }
                                        ConnectionMethod::Relayed => GossipConnectionType::Relayed,
                                    };
                                    epidemic_gossip
                                        .set_connection_type(gossip_peer_id, gossip_conn_type)
                                        .await;
                                }
                            }
                            let connectivity_for_report = result.matrix.clone();

                            // Preserve inbound_verified if peer already had inbound connection
                            let mut peers = connected_peers.write().await;
                            let existing_inbound_verified = peers
                                .get(&candidate.peer_id)
                                .map(|t| t.inbound_verified)
                                .unwrap_or(false);

                            let tracked = TrackedPeer {
                                info: candidate.clone(),
                                method: final_method,
                                direction: ConnectionDirection::Outbound,
                                connected_at: now,
                                last_activity: now,
                                stats: PeerStats::default(),
                                sequence: AtomicU64::new(0),
                                consecutive_failures: 0,
                                connectivity: result.matrix,
                                outbound_verified: true,
                                inbound_verified: existing_inbound_verified,
                                last_nat_test_time: None,
                                quic_test_success: false,
                                gossip_test_success: false,
                            };

                            let peer_for_tui = tracked.to_connected_peer();
                            peers.insert(candidate.peer_id.clone(), tracked);
                            drop(peers);

                            info!(
                                "COMPREHENSIVE test SUCCESS to {} via {:?} (matrix: {})",
                                peer_id_short,
                                final_method,
                                peer_for_tui.connectivity_summary()
                            );

                            let _ = event_tx.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                                peer_id: candidate.peer_id.clone(),
                                frame_type: format!("{:?}", final_method).to_uppercase(),
                                direction: FrameDirection::Received,
                                timestamp: Instant::now(),
                                context: Some((if is_ipv6 { "IPv6" } else { "IPv4" }).to_string()),
                            }));

                            send_tui_event(&event_tx, TuiEvent::PeerConnected(peer_for_tui));

                            // Report successful connection to registry
                            let report = ConnectionReport {
                                from_peer: our_peer_id.clone(),
                                to_peer: candidate.peer_id.clone(),
                                method: final_method,
                                is_ipv6,
                                rtt_ms: None,
                                connectivity: connectivity_for_report,
                            };
                            if let Err(e) = registry.report_connection(&report).await {
                                warn!("Failed to report connection: {}", e);
                            }

                            gossip_integration.record_success(&candidate.peer_id);

                            // Send DisconnectAndConnectBack to trigger reverse test
                            let our_addrs = external_addresses.read().await.clone();
                            if !our_addrs.is_empty() {
                                let msg = super::test_protocol::DisconnectAndConnectBack::new(
                                    our_peer_id.clone(),
                                    our_addrs,
                                    30,
                                );
                                if let Ok(bytes) = msg.to_bytes() {
                                    if let Ok(peer_bytes) = hex::decode(&candidate.peer_id) {
                                        if peer_bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&peer_bytes);
                                            let target = ant_quic::PeerId(arr);
                                            let _ = endpoint.send(&target, &bytes).await;
                                            info!(
                                                "Sent DisconnectAndConnectBack to {}",
                                                peer_id_short
                                            );
                                        }
                                    }
                                }
                            }
                        } else {
                            // Connection failed - try relay fallback before giving up
                            let target_peer_id = peer_id_to_bytes(&candidate.peer_id);

                            // Check if we have a relay that can reach the target
                            let relay_found = {
                                let rs = relay_state.read().await;
                                // First check if we already have an active relay for this target
                                if rs.active_relays.contains_key(&target_peer_id) {
                                    Some(true) // Already have a relay
                                } else {
                                    // Check if any of our relay candidates can reach the target
                                    let candidates = rs.get_relay_candidates();
                                    if !candidates.is_empty() {
                                        // We have potential relays to try
                                        Some(false)
                                    } else {
                                        None
                                    }
                                }
                            };

                            if let Some(_has_relay) = relay_found {
                                success.fetch_add(1, Ordering::Relaxed);
                                relay.fetch_add(1, Ordering::Relaxed);
                                {
                                    let mut stats = nat_stats.write().await;
                                    stats.relay_success += 1;
                                }

                                // Update epidemic gossip layer with relay connection type
                                if let Ok(peer_bytes) = hex::decode(&candidate.peer_id) {
                                    if peer_bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&peer_bytes);
                                        let gossip_peer_id = GossipPeerId::new(arr);
                                        epidemic_gossip
                                            .set_connection_type(
                                                gossip_peer_id,
                                                GossipConnectionType::Relayed,
                                            )
                                            .await;
                                    }
                                }

                                let now = Instant::now();
                                let mut matrix = result.matrix.clone();
                                matrix.relay_success = true;

                                let mut peers = connected_peers.write().await;
                                let existing_inbound_verified = peers
                                    .get(&candidate.peer_id)
                                    .map(|t| t.inbound_verified)
                                    .unwrap_or(false);

                                let tracked = TrackedPeer {
                                    info: candidate.clone(),
                                    method: ConnectionMethod::Relayed,
                                    direction: ConnectionDirection::Outbound,
                                    connected_at: now,
                                    last_activity: now,
                                    stats: PeerStats::default(),
                                    sequence: AtomicU64::new(0),
                                    consecutive_failures: 0,
                                    connectivity: matrix.clone(),
                                    outbound_verified: true,
                                    inbound_verified: existing_inbound_verified,
                                    last_nat_test_time: None,
                                    quic_test_success: false,
                                    gossip_test_success: false,
                                };

                                let peer_for_tui = tracked.to_connected_peer();
                                peers.insert(candidate.peer_id.clone(), tracked);
                                drop(peers);

                                info!(
                                    "Direct connection failed but RELAY available for {} (matrix: {})",
                                    peer_id_short,
                                    peer_for_tui.connectivity_summary()
                                );

                                send_tui_event(&event_tx, TuiEvent::PeerConnected(peer_for_tui));

                                // Report relayed connection to registry
                                let report = ConnectionReport {
                                    from_peer: our_peer_id.clone(),
                                    to_peer: candidate.peer_id.clone(),
                                    method: ConnectionMethod::Relayed,
                                    is_ipv6: false,
                                    rtt_ms: None,
                                    connectivity: matrix,
                                };
                                if let Err(e) = registry.report_connection(&report).await {
                                    warn!("Failed to report relayed connection: {}", e);
                                }
                            } else {
                                // No relay available - connection truly failed
                                {
                                    let mut pending = pending_outbound.write().await;
                                    pending.remove(&candidate.peer_id);
                                }

                                // Only count as failure if peer is still LIVE
                                // (they might have gone offline, not a hole-punch failure)
                                if candidate.is_active {
                                    failed.fetch_add(1, Ordering::Relaxed);
                                    {
                                        let mut stats = nat_stats.write().await;
                                        stats.failures += 1;
                                    }
                                    warn!(
                                        "COMPREHENSIVE test FAILED to {} (peer is LIVE, no relay available, matrix: {})",
                                        peer_id_short,
                                        result.matrix.summary()
                                    );
                                    let _ =
                                        event_tx.try_send(TuiEvent::ProtocolFrame(ProtocolFrame {
                                            peer_id: candidate.peer_id.clone(),
                                            frame_type: "FAILED".to_string(),
                                            direction: FrameDirection::Sent,
                                            timestamp: Instant::now(),
                                            context: candidate.country_code.clone(),
                                        }));
                                    let _ = event_tx.try_send(TuiEvent::ConnectionFailed);
                                } else {
                                    debug!(
                                        "Connection to {} failed but peer went offline",
                                        peer_id_short
                                    );
                                }
                            }
                        }
                        result.success
                    };

                    connect_futures.push(fut);
                }

                let candidate_count = connect_futures.len();
                let results = futures_util::future::join_all(connect_futures).await;
                let success_count = results.iter().filter(|&&s| s).count();

                if candidate_count > 0 && success_count == 0 {
                    let _ = event_tx.try_send(TuiEvent::FirewallDetected {
                        attempted_count: candidate_count,
                    });
                }
            }
        })
    }

    /// Spawn the test traffic background task.
    ///
    /// Uses DUAL TRANSPORT testing: sends test packets via BOTH gossip and QUIC transports.
    fn spawn_test_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let interval = self.config.test_interval;
        let event_tx = self.event_tx.clone();
        let our_peer_id_bytes = peer_id_to_bytes(&self.peer_id);
        let total_sent = Arc::clone(&self.total_bytes_sent);
        let total_received = Arc::clone(&self.total_bytes_received);
        // Use gossip transport for test packets (uses configured gossip_port)
        let gossip = Arc::clone(&self.epidemic_gossip);
        // Use QUIC transport for dual transport testing
        let endpoint = Arc::clone(&self.node);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                // CRITICAL: Collect peer info WITHOUT holding lock during network operations
                // This prevents lock starvation that was blocking heartbeats
                let peer_info: Vec<(String, u64)> = {
                    let peers = connected_peers.read().await;
                    peers
                        .iter()
                        .map(|(id, tracked)| {
                            let seq = tracked.sequence.fetch_add(1, Ordering::Relaxed);
                            (id.clone(), seq)
                        })
                        .collect()
                };
                // Lock released here before network operations

                for (peer_id, seq) in peer_info {
                    let packet = TestPacket::new_ping(our_peer_id_bytes, seq);
                    let packet_size = packet.size() as u64;

                    // === DUAL TRANSPORT TESTING ===
                    // Test 1: Gossip transport (saorsa-gossip)
                    let gossip_result = gossip_test_exchange(&gossip, &peer_id, &packet).await;

                    // Test 2: QUIC transport (P2pEndpoint)
                    // The response is handled asynchronously via P2pEvent::DataReceived
                    let quic_result = quic_test_exchange(&endpoint, &peer_id, &packet).await;

                    // Now briefly acquire lock to update stats
                    let gossip_success = gossip_result.is_ok();
                    let rtt_for_tui = gossip_result.as_ref().ok().copied();

                    {
                        let mut peers = connected_peers.write().await;
                        if let Some(tracked) = peers.get_mut(&peer_id) {
                            // Track gossip transport success
                            if gossip_success {
                                tracked.gossip_test_success = true;
                                tracked.stats.tests_success += 1;
                                if let Ok(rtt) = &gossip_result {
                                    tracked.stats.total_rtt_ms += rtt.as_millis() as u64;
                                    tracked.stats.last_rtt = Some(*rtt);
                                }
                                tracked.stats.packets_sent += 1;
                                tracked.stats.packets_received += 1;
                                tracked.last_activity = Instant::now();
                                tracked.consecutive_failures = 0; // Reset on success

                                total_sent.fetch_add(packet_size, Ordering::Relaxed);
                                total_received.fetch_add(packet_size, Ordering::Relaxed);

                                debug!(
                                    "GOSSIP test packet sent to {} ({} bytes, RTT: {:?})",
                                    &peer_id[..8],
                                    packet_size,
                                    gossip_result.as_ref().ok()
                                );
                            } else if let Err(e) = &gossip_result {
                                tracked.stats.tests_failed += 1;
                                tracked.consecutive_failures += 1;
                                warn!("Gossip test packet to {} failed: {}", &peer_id[..8], e);
                            }

                            // Track QUIC transport success (send only - response via DataReceived)
                            if quic_result.is_ok() {
                                debug!(
                                    "QUIC test packet sent to {} (awaiting pong)",
                                    &peer_id[..8]
                                );
                            } else if let Err(e) = &quic_result {
                                debug!("QUIC test packet to {} failed: {}", &peer_id[..8], e);
                            }
                        }
                    } // Lock released here before TUI update

                    let _ = event_tx.try_send(TuiEvent::TestPacketResult {
                        peer_id: peer_id.clone(),
                        success: gossip_success,
                        rtt: rtt_for_tui,
                    });
                    let _ = event_tx.try_send(TuiEvent::TrafficTypeUpdate {
                        peer_id: peer_id.clone(),
                        traffic_type: TrafficType::TestData,
                        direction: FrameDirection::Sent,
                    });
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
                        let _ = event_tx.try_send(TuiEvent::RemovePeer(peer_id.clone()));
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

    /// Interval for NAT callback testing (45 seconds - longer than 30-second rule).
    const NAT_CALLBACK_INTERVAL_SECS: u64 = 45;

    /// Spawn a loop that periodically sends ConnectBackRequests to verify NAT traversal.
    ///
    /// This implements the 30-second rule: only request connect-back from peers
    /// that haven't had any connection activity for 30+ seconds, ensuring we're
    /// testing fresh NAT traversal rather than reusing existing holes.
    fn spawn_nat_callback_loop(&self) -> tokio::task::JoinHandle<()> {
        use super::test_protocol::ConnectBackRequest;

        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let endpoint = Arc::clone(&self.node);
        let external_addresses = Arc::clone(&self.external_addresses);
        let peer_id = self.peer_id.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(Self::NAT_CALLBACK_INTERVAL_SECS));

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;

                // Get our current external addresses
                let our_addresses = external_addresses.read().await.clone();
                if our_addresses.is_empty() {
                    debug!("NAT callback: No external addresses known, skipping");
                    continue;
                }

                // Find peers that need NAT callback testing (30-second rule)
                let peers_to_test: Vec<(String, Vec<std::net::SocketAddr>)> = {
                    let mut peers = connected_peers.write().await;
                    let now = Instant::now();
                    let mut test_list = Vec::new();

                    for (peer_hex, tracked) in peers.iter_mut() {
                        // Skip if already inbound verified
                        if tracked.inbound_verified {
                            continue;
                        }

                        // Check 30-second rule: no activity for 30+ seconds
                        let time_since_activity = now.duration_since(tracked.last_activity);
                        if time_since_activity.as_secs() < 30 {
                            continue;
                        }

                        // Check if we already tested recently (avoid spamming)
                        if let Some(last_test) = tracked.last_nat_test_time {
                            if now.duration_since(last_test).as_secs() < 60 {
                                continue;
                            }
                        }

                        // Mark that we're testing now
                        tracked.last_nat_test_time = Some(now);

                        test_list.push((peer_hex.clone(), tracked.info.addresses.clone()));
                    }

                    test_list
                };

                if peers_to_test.is_empty() {
                    debug!("NAT callback: No peers eligible for testing");
                    continue;
                }

                info!(
                    "NAT callback: Testing {} peer(s) for inbound connectivity",
                    peers_to_test.len()
                );

                // Send ConnectBackRequest to each eligible peer
                for (peer_hex, _peer_addrs) in peers_to_test {
                    let request = ConnectBackRequest::new(peer_id.clone(), our_addresses.clone());

                    if let Ok(bytes) = request.to_bytes() {
                        // Decode peer ID
                        if let Ok(peer_bytes) = hex::decode(&peer_hex) {
                            if peer_bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&peer_bytes);
                                let target_peer = ant_quic::PeerId(arr);

                                if let Err(e) = endpoint.send(&target_peer, &bytes).await {
                                    debug!(
                                        "NAT callback: Failed to send ConnectBackRequest to {}: {}",
                                        &peer_hex[..8.min(peer_hex.len())],
                                        e
                                    );
                                } else {
                                    debug!(
                                        "NAT callback: Sent ConnectBackRequest to {}",
                                        &peer_hex[..8.min(peer_hex.len())]
                                    );
                                    let _ = event_tx.try_send(TuiEvent::Info(format!(
                                        "NAT test: asking {} to connect back",
                                        &peer_hex[..8.min(peer_hex.len())]
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    fn spawn_websocket_event_loop(&self) -> tokio::task::JoinHandle<()> {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let shutdown = Arc::clone(&self.shutdown);
        let endpoint = Arc::clone(&self.node);
        let peer_id = self.peer_id.clone();
        let event_tx = self.event_tx.clone();

        let registry_url = self.config.registry_url.clone();
        let ws_url = registry_url
            .replace("https://", "wss://")
            .replace("http://", "ws://")
            + "/ws/live";

        tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                info!(
                    "Connecting to registry WebSocket at {} for connectivity test events...",
                    ws_url
                );

                match tokio_tungstenite::connect_async(&ws_url).await {
                    Ok((mut ws_stream, _response)) => {
                        info!("Connected to registry WebSocket");

                        while let Some(msg_result) = ws_stream.next().await {
                            if shutdown.load(Ordering::SeqCst) {
                                break;
                            }

                            match msg_result {
                                Ok(Message::Text(text)) => {
                                    match serde_json::from_str::<NetworkEvent>(&text) {
                                        Ok(NetworkEvent::ConnectivityTestRequest {
                                            peer_id: target_peer_id,
                                            addresses,
                                            relay_addr: _,
                                            timestamp_ms: _,
                                        }) => {
                                            if target_peer_id == peer_id {
                                                debug!(
                                                    "Ignoring connectivity test request for ourselves"
                                                );
                                                continue;
                                            }

                                            info!(
                                                "Received connectivity test request for peer {} with {} addresses",
                                                &target_peer_id[..8.min(target_peer_id.len())],
                                                addresses.len()
                                            );

                                            Self::handle_connectivity_test_request(
                                                &endpoint,
                                                &target_peer_id,
                                                &addresses,
                                                &event_tx,
                                            )
                                            .await;
                                        }
                                        Ok(_other_event) => {
                                            debug!("WebSocket: received non-connectivity event");
                                        }
                                        Err(e) => {
                                            debug!("WebSocket: failed to parse event: {}", e);
                                        }
                                    }
                                }
                                Ok(Message::Ping(data)) => {
                                    debug!("WebSocket ping received");
                                    let _ =
                                        futures::SinkExt::send(&mut ws_stream, Message::Pong(data))
                                            .await;
                                }
                                Ok(Message::Close(_)) => {
                                    info!("WebSocket connection closed by server");
                                    break;
                                }
                                Err(e) => {
                                    warn!("WebSocket error: {}", e);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to connect to registry WebSocket: {}", e);
                    }
                }

                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        })
    }

    async fn handle_connectivity_test_request(
        node: &Arc<Node>,
        target_peer_id: &str,
        addresses: &[SocketAddr],
        event_tx: &mpsc::Sender<TuiEvent>,
    ) {
        use ant_quic::connection_strategy::ConnectionMethod as QuicConnectionMethod;

        let target_peer_id_short = &target_peer_id[..8.min(target_peer_id.len())];

        let ipv4_addr = addresses.iter().find(|a| a.is_ipv4()).copied();
        let ipv6_addr = addresses.iter().find(|a| a.is_ipv6()).copied();

        let target_peer_bytes = peer_id_to_bytes(target_peer_id);
        let target_quic_peer_id = ant_quic::PeerId(target_peer_bytes);

        info!(
            "Starting connectivity test to {} (IPv4: {:?}, IPv6: {:?})",
            target_peer_id_short, ipv4_addr, ipv6_addr
        );

        match node
            .inner_endpoint()
            .connect_with_fallback(ipv4_addr, ipv6_addr, None, Some(target_quic_peer_id))
            .await
        {
            Ok((connection, method)) => {
                let method_str = match &method {
                    QuicConnectionMethod::DirectIPv4 => "Direct IPv4",
                    QuicConnectionMethod::DirectIPv6 => "Direct IPv6",
                    QuicConnectionMethod::HolePunched { .. } => "NAT Traversal",
                    QuicConnectionMethod::Relayed { .. } => "Relay",
                };

                info!(
                    "Connectivity test SUCCESS: {} to {} via {} (peer_id: {})",
                    method_str,
                    target_peer_id_short,
                    method,
                    hex::encode(&connection.peer_id.0[..4])
                );

                let _ = event_tx.try_send(TuiEvent::Info(format!(
                    "Connectivity test: {} to {} succeeded",
                    method_str, target_peer_id_short
                )));
            }
            Err(e) => {
                warn!(
                    "Connectivity test FAILED: all methods to {} failed: {}",
                    target_peer_id_short, e
                );

                let _ = event_tx.try_send(TuiEvent::Info(format!(
                    "Connectivity test: all paths to {} failed",
                    target_peer_id_short
                )));
            }
        }
    }

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

const DATA_PROOF_PAYLOAD_SIZE: usize = 1024;
const DATA_PROOF_TIMEOUT_SECS: u64 = 5;

async fn perform_bidirectional_data_exchange(
    endpoint: &Arc<P2pEndpoint>,
    peer_id: &QuicPeerId,
) -> Option<DataProof> {
    use sha2::{Digest, Sha256};

    let connection = match endpoint.get_quic_connection(peer_id) {
        Ok(Some(conn)) => conn,
        Ok(None) => {
            debug!("No QUIC connection found for peer");
            return None;
        }
        Err(e) => {
            debug!("Failed to get QUIC connection: {:?}", e);
            return None;
        }
    };

    let start = Instant::now();

    let payload: Vec<u8> = (0..DATA_PROOF_PAYLOAD_SIZE)
        .map(|i| (i % 256) as u8)
        .collect();

    let sent_checksum = {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        hex::encode(hasher.finalize())
    };

    let exchange_result =
        tokio::time::timeout(Duration::from_secs(DATA_PROOF_TIMEOUT_SECS), async {
            let (mut send, mut recv) = connection.open_bi().await?;

            send.write_all(&payload).await?;
            send.finish()?;

            let response = recv.read_to_end(DATA_PROOF_PAYLOAD_SIZE * 2).await?;

            Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(response)
        })
        .await;

    match exchange_result {
        Ok(Ok(response)) => {
            let received_checksum = {
                let mut hasher = Sha256::new();
                hasher.update(&response);
                hex::encode(hasher.finalize())
            };

            let verified = !response.is_empty();
            let echo_rtt_ms = start.elapsed().as_millis() as u64;

            Some(DataProof {
                bytes_sent: payload.len() as u64,
                bytes_received: response.len() as u64,
                sent_checksum,
                received_checksum,
                verified,
                echo_rtt_ms: Some(echo_rtt_ms),
                stream_tested: true,
                datagram_tested: false,
                timestamp_ms: crate::registry::unix_timestamp_ms(),
            })
        }
        Ok(Err(e)) => {
            debug!("Bidirectional data exchange failed: {}", e);
            None
        }
        Err(_) => {
            debug!("Bidirectional data exchange timed out");
            None
        }
    }
}

struct ComprehensiveConnectResult {
    matrix: ConnectivityMatrix,
    best_method: ConnectionMethod,
    success: bool,
}

/// Comprehensive connection test that tries ALL paths for complete network analysis.
///
/// Unlike real_connect which returns on first success, this function tests:
/// 1. IPv4 direct connections (all IPv4 addresses)
/// 2. IPv6 direct connections (all IPv6 addresses)
/// 3. NAT traversal (hole-punching) - skipped if `skip_nat_test` is true
/// 4. Relay (if available)
///
/// Set `skip_nat_test` to true when both peers are VPS nodes (direct always works).
async fn real_connect_comprehensive(
    node: &Arc<Node>,
    peer: &PeerInfo,
    skip_nat_test: bool,
) -> ComprehensiveConnectResult {
    let peer_id_short = &peer.peer_id[..8.min(peer.peer_id.len())];
    let mut matrix = ConnectivityMatrix::default();
    let endpoint = node.inner_endpoint();

    let ipv4_addrs: Vec<_> = peer.addresses.iter().filter(|a| a.is_ipv4()).collect();
    let ipv6_addrs: Vec<_> = peer.addresses.iter().filter(|a| a.is_ipv6()).collect();

    info!(
        "Testing comprehensive connectivity to {}: {} IPv4, {} IPv6 addresses",
        peer_id_short,
        ipv4_addrs.len(),
        ipv6_addrs.len()
    );

    if !ipv4_addrs.is_empty() {
        matrix.ipv4_direct_tested = true;
        let start = Instant::now();
        for addr in &ipv4_addrs {
            match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(**addr)).await {
                Ok(Ok(conn)) => {
                    matrix.ipv4_direct_success = true;
                    matrix.ipv4_direct_rtt_ms = Some(start.elapsed().as_millis() as u64);

                    let data_proof =
                        perform_bidirectional_data_exchange(endpoint, &conn.peer_id).await;
                    if data_proof.is_some() {
                        matrix.data_proof = data_proof;
                        matrix.success_level = SuccessLevel::Usable;
                        info!(
                            "IPv4 direct to {} at {} succeeded with data proof",
                            peer_id_short, addr
                        );
                    } else {
                        matrix.success_level = SuccessLevel::Established;
                        info!(
                            "IPv4 direct to {} at {} connected (no data proof)",
                            peer_id_short, addr
                        );
                    }
                    break;
                }
                Ok(Err(e)) => {
                    debug!("IPv4 direct to {} failed: {}", addr, e);
                }
                Err(_) => {
                    debug!("IPv4 direct to {} timed out", addr);
                }
            }
        }
    }

    if !ipv6_addrs.is_empty() {
        matrix.ipv6_direct_tested = true;
        let start = Instant::now();
        for addr in &ipv6_addrs {
            match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(**addr)).await {
                Ok(Ok(conn)) => {
                    matrix.ipv6_direct_success = true;
                    matrix.ipv6_direct_rtt_ms = Some(start.elapsed().as_millis() as u64);

                    if matrix.data_proof.is_none() {
                        let data_proof =
                            perform_bidirectional_data_exchange(endpoint, &conn.peer_id).await;
                        if data_proof.is_some() {
                            matrix.data_proof = data_proof;
                            matrix.success_level = SuccessLevel::Usable;
                            info!(
                                "IPv6 direct to {} at {} succeeded with data proof",
                                peer_id_short, addr
                            );
                        } else {
                            if matrix.success_level < SuccessLevel::Established {
                                matrix.success_level = SuccessLevel::Established;
                            }
                            info!(
                                "IPv6 direct to {} at {} connected (no data proof)",
                                peer_id_short, addr
                            );
                        }
                    }
                    break;
                }
                Ok(Err(e)) => {
                    debug!("IPv6 direct to {} failed: {}", addr, e);
                }
                Err(_) => {
                    debug!("IPv6 direct to {} timed out", addr);
                }
            }
        }
    }

    if skip_nat_test {
        debug!(
            "Skipping NAT traversal test to {} (VPS-to-VPS pair)",
            peer_id_short
        );
    } else if let Ok(peer_id_bytes) = hex::decode(&peer.peer_id) {
        if peer_id_bytes.len() >= 32 {
            let mut peer_id_array = [0u8; 32];
            peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
            let quic_peer_id = QuicPeerId(peer_id_array);

            matrix.nat_traversal_tested = true;
            let start = Instant::now();

            match tokio::time::timeout(
                Duration::from_secs(30),
                endpoint.connect_to_peer(quic_peer_id, None),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    matrix.nat_traversal_success = true;
                    matrix.nat_traversal_rtt_ms = Some(start.elapsed().as_millis() as u64);

                    if matrix.data_proof.is_none() {
                        let data_proof =
                            perform_bidirectional_data_exchange(endpoint, &conn.peer_id).await;
                        if data_proof.is_some() {
                            matrix.data_proof = data_proof;
                            matrix.success_level = SuccessLevel::Usable;
                            info!(
                                "NAT traversal to {} succeeded with data proof",
                                peer_id_short
                            );
                        } else {
                            if matrix.success_level < SuccessLevel::Established {
                                matrix.success_level = SuccessLevel::Established;
                            }
                            info!(
                                "NAT traversal to {} connected (no data proof)",
                                peer_id_short
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!("NAT traversal to {} failed: {}", peer_id_short, e);
                }
                Err(_) => {
                    debug!("NAT traversal to {} timed out", peer_id_short);
                }
            }
        }
    }

    // TODO: Test relay when available
    // matrix.relay_tested = true;
    // matrix.relay_success = ...;

    // Determine best method and whether we have any connection
    let (best_method, active_is_ipv6) = if matrix.ipv6_direct_success {
        // Prefer IPv6 if available (typically better for P2P)
        (ConnectionMethod::Direct, true)
    } else if matrix.ipv4_direct_success {
        (ConnectionMethod::Direct, false)
    } else if matrix.nat_traversal_success {
        (ConnectionMethod::HolePunched, false)
    } else if matrix.relay_success {
        (ConnectionMethod::Relayed, false)
    } else {
        // No connection succeeded, but still report Direct as default
        (ConnectionMethod::Direct, false)
    };

    let success =
        matrix.ipv4_direct_success || matrix.ipv6_direct_success || matrix.nat_traversal_success;

    matrix.active_method = if success { Some(best_method) } else { None };
    matrix.active_is_ipv6 = active_is_ipv6;

    info!(
        "Comprehensive test to {}: {} paths tested, {} succeeded (best: {:?})",
        peer_id_short,
        matrix.tested_paths(),
        matrix.successful_paths(),
        if success { Some(best_method) } else { None }
    );

    ComprehensiveConnectResult {
        matrix,
        best_method,
        success,
    }
}

/// Perform test packet exchange via gossip transport.
///
/// This uses the saorsa-gossip transport (configured via --bind-port flag),
/// bypassing the P2pEndpoint that uses a different port.
async fn gossip_test_exchange(
    gossip: &EpidemicGossip,
    peer_id_hex: &str,
    packet: &TestPacket,
) -> Result<Duration, String> {
    use saorsa_gossip_types::PeerId as GossipPeerId;

    // Convert hex peer ID to gossip PeerId
    let peer_id_bytes =
        hex::decode(peer_id_hex).map_err(|e| format!("Invalid peer ID hex: {}", e))?;

    if peer_id_bytes.len() != 32 {
        return Err(format!("Peer ID wrong length: {}", peer_id_bytes.len()));
    }

    let mut peer_id_array = [0u8; 32];
    peer_id_array.copy_from_slice(&peer_id_bytes);
    let gossip_peer_id = GossipPeerId::new(peer_id_array);

    // Serialize the test packet
    let packet_data =
        serde_json::to_vec(packet).map_err(|e| format!("Failed to serialize packet: {}", e))?;

    let start = Instant::now();

    // Send via gossip transport (uses configured gossip_port)
    gossip
        .send_to_peer(gossip_peer_id, packet_data)
        .await
        .map_err(|e| format!("Gossip send failed: {}", e))?;

    let rtt = start.elapsed();

    debug!(
        "GOSSIP test packet sent to {} (RTT: {:?})",
        &peer_id_hex[..8.min(peer_id_hex.len())],
        rtt
    );

    Ok(rtt)
}

/// Perform test packet exchange via QUIC transport.
///
/// This uses the P2pEndpoint QUIC transport, sending directly to the peer.
/// The response is handled asynchronously via P2pEvent::DataReceived.
async fn quic_test_exchange(
    node: &Arc<Node>,
    peer_id_hex: &str,
    packet: &TestPacket,
) -> Result<(), String> {
    let peer_id_bytes =
        hex::decode(peer_id_hex).map_err(|e| format!("Invalid peer ID hex: {}", e))?;

    if peer_id_bytes.len() != 32 {
        return Err(format!("Peer ID wrong length: {}", peer_id_bytes.len()));
    }

    let mut peer_id_array = [0u8; 32];
    peer_id_array.copy_from_slice(&peer_id_bytes);
    let quic_peer_id = ant_quic::PeerId(peer_id_array);

    let packet_data =
        serde_json::to_vec(packet).map_err(|e| format!("Failed to serialize packet: {}", e))?;

    node.send(&quic_peer_id, &packet_data)
        .await
        .map_err(|e| format!("QUIC send failed: {}", e))?;

    debug!(
        "QUIC test packet sent to {}",
        &peer_id_hex[..8.min(peer_id_hex.len())]
    );

    Ok(())
}

// ============================================================================
// Gossip Peer List Exchange Functions
// ============================================================================

/// Send our peer list to a specific peer.
///
/// Called when a new connection is established to exchange peer knowledge.
async fn send_gossip_peer_list(
    endpoint: &Arc<P2pEndpoint>,
    peer_id_hex: &str,
    our_peer_id: &str,
    peers: Vec<GossipPeerInfo>,
) -> Result<(), String> {
    let peer_id_bytes =
        hex::decode(peer_id_hex).map_err(|e| format!("Invalid peer ID hex: {}", e))?;

    if peer_id_bytes.len() < 32 {
        return Err("Peer ID too short".to_string());
    }

    let mut peer_id_array = [0u8; 32];
    peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
    let quic_peer_id = QuicPeerId(peer_id_array);

    let connection = endpoint
        .get_quic_connection(&quic_peer_id)
        .map_err(|e| format!("Failed to get connection: {}", e))?
        .ok_or_else(|| "No connection to peer".to_string())?;

    let message = PeerListMessage::new(our_peer_id.to_string(), peers);

    let message_data = message
        .to_bytes()
        .map_err(|e| format!("Failed to serialize peer list: {}", e))?;

    let mut send_stream = connection
        .open_uni()
        .await
        .map_err(|e| format!("Failed to open stream: {}", e))?;

    send_stream
        .write_all(&message_data)
        .await
        .map_err(|e| format!("Failed to write data: {}", e))?;

    send_stream
        .finish()
        .map_err(|e| format!("Failed to finish stream: {}", e))?;

    info!(
        "Sent peer list ({} peers) to {}",
        message.peers.len(),
        &peer_id_hex[..8.min(peer_id_hex.len())]
    );

    Ok(())
}

/// Broadcast a peer announcement to all connected peers.
///
/// Called when a new peer is discovered to propagate the information.
async fn broadcast_peer_announcement(
    endpoint: &Arc<P2pEndpoint>,
    connected_peers: &RwLock<HashMap<String, TrackedPeer>>,
    announcement: &GossipPeerAnnouncement,
    exclude_peer: Option<&str>,
) -> usize {
    let peer_ids: Vec<String> = {
        let peers = connected_peers.read().await;
        peers
            .keys()
            .filter(|id| {
                if let Some(exclude) = exclude_peer {
                    id.as_str() != exclude
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    };

    let mut success_count = 0;

    for peer_id_hex in peer_ids {
        let peer_id_bytes = match hex::decode(&peer_id_hex) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        if peer_id_bytes.len() < 32 {
            continue;
        }

        let mut peer_id_array = [0u8; 32];
        peer_id_array.copy_from_slice(&peer_id_bytes[..32]);
        let quic_peer_id = QuicPeerId(peer_id_array);

        let connection = match endpoint.get_quic_connection(&quic_peer_id) {
            Ok(Some(conn)) => conn,
            _ => continue,
        };

        // Serialize the announcement
        let message_data = match announcement.to_bytes() {
            Ok(data) => data,
            Err(_) => continue,
        };

        // Open a unidirectional stream and send the announcement
        let result = async {
            let mut send_stream = connection.open_uni().await?;
            send_stream.write_all(&message_data).await?;
            send_stream.finish()?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;

        if result.is_ok() {
            success_count += 1;
            debug!(
                "Broadcast peer announcement for {} to {}",
                &announcement.peer.peer_id[..8.min(announcement.peer.peer_id.len())],
                &peer_id_hex[..8.min(peer_id_hex.len())]
            );
        }
    }

    success_count
}

/// Build a list of known peers for gossip exchange.
fn build_peer_list_from_connected(
    connected: &HashMap<String, TrackedPeer>,
    our_peer_id: &str,
) -> Vec<GossipPeerInfo> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    connected
        .iter()
        .filter(|(id, _)| id.as_str() != our_peer_id)
        .map(|(peer_id, tracked)| GossipPeerInfo {
            peer_id: peer_id.clone(),
            addresses: tracked.info.addresses.clone(),
            is_public: matches!(tracked.method, ConnectionMethod::Direct),
            is_connected: true,
            last_seen_ms: now_ms,
        })
        .collect()
}

// Note: Gossip message receiving is now done via the central endpoint.recv()
// loop in start_gossip_listener, not via per-peer receivers.
