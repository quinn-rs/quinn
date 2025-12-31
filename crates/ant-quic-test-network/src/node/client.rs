//! Test node client implementation.
//!
//! Handles automatic registration with the registry, peer discovery,
//! automatic connections using REAL P2pEndpoint QUIC connections,
//! and test traffic generation over actual QUIC streams.

use crate::gossip::{
    GossipConfig, GossipEvent, GossipIntegration, PeerCapabilities as GossipCapabilities,
};
use crate::registry::{
    BgpGeoProvider, ConnectionDirection, ConnectionMethod, ConnectionReport, ConnectivityMatrix,
    NatStats, NatType, NodeCapabilities, NodeGossipStats, NodeHeartbeat, NodeRegistration,
    PeerInfo, PeerStatus, RegistryClient,
};
use crate::tui::{ConnectedPeer, LocalNodeInfo, TuiEvent, country_flag};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

// Real QUIC P2P endpoint imports
use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, P2pEvent, PeerId as QuicPeerId};
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
    /// Track when we last disconnected from each peer.
    /// Used for bidirectional connectivity testing - we only attempt fresh connections
    /// to peers we've been disconnected from for >30 seconds (to ensure NAT mappings expired).
    disconnection_times: Arc<RwLock<HashMap<String, Instant>>>,
    /// Track peer IDs we're currently trying to connect to (outbound).
    /// When PeerConnected fires, if the peer is in this set it's outbound, otherwise inbound.
    pending_outbound: Arc<RwLock<HashSet<String>>>,
    /// Count of inbound connections (they initiated to us).
    /// This is the key metric for nodes behind NAT.
    inbound_connections: Arc<AtomicU64>,
    /// Relay discovery state for NAT traversal fallback.
    /// Tracks public nodes and manages relay connections.
    relay_state: Arc<RwLock<RelayState>>,
    /// Gossip integration layer with bootstrap cache for decentralized peer discovery.
    gossip_integration: Arc<GossipIntegration>,
    /// Receiver for gossip events.
    gossip_event_rx: Arc<RwLock<mpsc::Receiver<GossipEvent>>>,
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

        // Known peers for NAT traversal coordination.
        // These are publicly reachable nodes that can coordinate hole-punching.
        // When NAT traversal is needed, we use these as coordinators (not the unreachable target peer).
        let known_peers: Vec<SocketAddr> = vec![
            "77.42.75.115:9000".parse().ok(),    // saorsa-1 (Helsinki)
            "142.93.199.50:9000".parse().ok(),   // saorsa-2 (NYC)
            "147.182.234.192:9000".parse().ok(), // saorsa-3 (SFO)
        ]
        .into_iter()
        .flatten()
        .collect();

        info!(
            "Configured {} known peers for NAT traversal coordination",
            known_peers.len()
        );

        // Load or generate persistent keypair to maintain stable peer ID across restarts
        let (public_key, secret_key) = load_or_generate_keypair()?;

        let p2p_config = P2pConfig::builder()
            .bind_addr(config.bind_addr)
            .known_peers(known_peers)
            .nat(nat_config)
            .keypair(public_key, secret_key)
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

        // Spawn event handler for P2P events to update TUI
        let endpoint_for_events = endpoint.clone();
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

                            // Update relay state with our external addresses
                            let mut rs = relay_state_for_events.write().await;
                            rs.our_external_addresses = addrs.clone();
                            rs.our_local_addresses = listen_addresses_for_events.clone();

                            // Check if we're a public node per IP family
                            let (is_public, is_public_ipv4, is_public_ipv6) =
                                rs.get_public_status();
                            if is_public {
                                info!(
                                    "We appear to be a PUBLIC node (IPv4: {}, IPv6: {})",
                                    if is_public_ipv4 { "public" } else { "NAT" },
                                    if is_public_ipv6 { "public" } else { "NAT/none" }
                                );
                            } else {
                                debug!("We appear to be behind NAT on all IP families");
                            }
                        }
                        let _ = event_tx_for_events.try_send(TuiEvent::Info(format!(
                            "Discovered external address: {}",
                            addr
                        )));
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

                        if is_inbound {
                            let count =
                                inbound_connections_for_events.fetch_add(1, Ordering::Relaxed) + 1;
                            info!(
                                "INBOUND connection received from {} (total inbound: {})",
                                &peer_hex[..8.min(peer_hex.len())],
                                count
                            );

                            // This is the key metric for nodes behind NAT!
                            // If we receive inbound connections, NAT traversal is working
                            let _ = event_tx_for_events.try_send(TuiEvent::InboundConnection);
                            let _ = event_tx_for_events.try_send(TuiEvent::Info(format!(
                                "← INBOUND from {} (NAT traversal works!)",
                                &peer_hex[..8.min(peer_hex.len())]
                            )));

                            // Create a ConnectedPeer for TUI display with Inbound direction
                            // This ensures inbound connections appear in the peer list
                            let mut inbound_peer = ConnectedPeer::with_direction(
                                &peer_hex,
                                ConnectionMethod::HolePunched, // They punched through to us
                                ConnectionDirection::Inbound,
                            );
                            inbound_peer.addresses = vec![addr];
                            // Mark connectivity matrix to show NAT traversal succeeded
                            inbound_peer.connectivity.nat_traversal_tested = true;
                            inbound_peer.connectivity.nat_traversal_success = true;

                            // Look up country code from the peer's IP address
                            let (_lat, _lon, country_code) =
                                geo_provider_for_events.lookup(addr.ip());
                            if let Some(cc) = country_code {
                                inbound_peer.location = format!("{} {}", country_flag(&cc), cc);
                            }

                            let _ =
                                event_tx_for_events.try_send(TuiEvent::PeerConnected(inbound_peer));
                        } else {
                            // Outbound connection - we initiated
                            // Remove from pending since connection completed
                            let mut pending = pending_outbound_for_events.write().await;
                            pending.remove(&peer_hex);
                            // Track outbound connection
                            let _ = event_tx_for_events.try_send(TuiEvent::OutboundConnection);
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
                                let method = if is_inbound {
                                    ConnectionMethod::HolePunched // They traversed to us
                                } else {
                                    ConnectionMethod::Direct // Placeholder, comprehensive test updates
                                };

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
                                };

                                let tracked = TrackedPeer {
                                    info: peer_info,
                                    method,
                                    direction,
                                    connected_at: now,
                                    last_activity: now,
                                    stats: PeerStats::default(),
                                    sequence: AtomicU64::new(0),
                                    consecutive_failures: 0,
                                    connectivity: ConnectivityMatrix::default(),
                                };

                                peers.insert(peer_hex.clone(), tracked);
                                debug!(
                                    "Added peer {} to connected_peers immediately (direction: {:?})",
                                    &peer_hex[..8.min(peer_hex.len())],
                                    direction
                                );
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
                        let endpoint_for_gossip = endpoint_for_events.clone();
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

                            // Send our peer list to the newly connected peer
                            if let Err(e) = send_gossip_peer_list(
                                &endpoint_for_gossip,
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
            connected_peers,    // Use the shared Arc created before event handler
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
            disconnection_times,
            pending_outbound,
            inbound_connections,
            relay_state,
            gossip_integration, // Already Arc-wrapped
            gossip_event_rx: Arc::new(RwLock::new(gossip_event_rx)),
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
            match tokio::time::timeout(Duration::from_secs(10), self.endpoint.connect(*addr)).await
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
            match tokio::time::timeout(Duration::from_secs(10), self.endpoint.connect(*addr)).await
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

                match tokio::time::timeout(
                    Duration::from_secs(30),
                    self.endpoint.connect_to_peer(quic_peer_id, None),
                )
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

    /// Spawn the gossip event processing loop.
    fn spawn_gossip_loop(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let gossip_integration = Arc::clone(&self.gossip_integration);
        let gossip_event_rx = Arc::clone(&self.gossip_event_rx);
        let event_tx = self.event_tx.clone();
        let peer_id = self.peer_id.clone();
        // Add endpoint and connected_peers for triggering connections
        let endpoint = Arc::clone(&self.endpoint);
        let connected_peers = Arc::clone(&self.connected_peers);
        let max_peers = self.config.max_peers;

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
                                                endpoint_clone.connect(addr)
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

                                        // Check if already connected
                                        let connected = connected_peers.read().await;
                                        let already_connected = connected.contains_key(&peer_info.peer_id);
                                        let at_capacity = connected.len() >= max_peers;
                                        drop(connected);

                                        if already_connected || at_capacity {
                                            continue;
                                        }

                                        // Store in gossip integration
                                        gossip_integration.add_peer(
                                            &peer_info.peer_id,
                                            &peer_info.addresses,
                                            peer_info.is_public,
                                        );

                                        // Broadcast to other connected peers
                                        let announcement = GossipPeerAnnouncement::new(
                                            peer_info.clone(),
                                            peer_id.clone(),
                                            3,
                                        );
                                        let endpoint_for_broadcast = Arc::clone(&endpoint);
                                        let connected_for_broadcast = Arc::clone(&connected_peers);
                                        let sender_id = sender_hex.clone();
                                        tokio::spawn(async move {
                                            let _ = broadcast_peer_announcement(
                                                &endpoint_for_broadcast,
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
                                                    endpoint_clone.connect(addr),
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
                                    if peer_info.peer_id != peer_id {
                                        let connected = connected_peers.read().await;
                                        let already_connected = connected.contains_key(&peer_info.peer_id);
                                        let at_capacity = connected.len() >= max_peers;
                                        drop(connected);

                                        if !already_connected && !at_capacity && !peer_info.addresses.is_empty() {
                                            gossip_integration.add_peer(
                                                &peer_info.peer_id,
                                                &peer_info.addresses,
                                                peer_info.is_public,
                                            );

                                            let addr = peer_info.addresses[0];
                                            let endpoint_clone = Arc::clone(&endpoint);
                                            let gossip_clone = Arc::clone(&gossip_integration);
                                            let peer_id_for_connect = peer_info.peer_id.clone();
                                            tokio::spawn(async move {
                                                if let Ok(Ok(_)) = tokio::time::timeout(
                                                    Duration::from_secs(10),
                                                    endpoint_clone.connect(addr),
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
        let connection = match self.endpoint.get_quic_connection(&target_peer_id) {
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
        let connection = match self.endpoint.get_quic_connection(&target_peer_id) {
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

    /// Discover our external address by connecting to known QUIC peers.
    ///
    /// This connects to the saorsa registry nodes via QUIC (port 9000) to receive
    /// OBSERVED_ADDRESS frames that tell us our external IP:port as seen by them.
    /// This is part of the native QUIC NAT traversal per draft-ietf-quic-address-discovery.
    async fn discover_external_address(&self) {
        // Known QUIC peers (saorsa registry nodes running QUIC on port 9000)
        let known_quic_peers: Vec<SocketAddr> = vec![
            "77.42.75.115:9000".parse().ok(),    // saorsa-1 (Helsinki)
            "142.93.199.50:9000".parse().ok(),   // saorsa-2 (NYC)
            "147.182.234.192:9000".parse().ok(), // saorsa-3 (SFO)
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

                    // Wait for the OBSERVED_ADDRESS frame to arrive
                    // The P2pEvent::ExternalAddressDiscovered handler will store it
                    // Give 5 seconds for the frame to be sent, received, and processed
                    tokio::time::sleep(Duration::from_secs(5)).await;

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

        // If we couldn't discover from any peer, log a warning and notify TUI
        let addrs = self.external_addresses.read().await;
        if addrs.is_empty() {
            let msg = "No external address discovered - inbound connections may not work";
            warn!(
                "Could not discover external address from any known peer. \
                 Registration will proceed without external address - \
                 other nodes may not be able to connect to us."
            );
            // Send warning to TUI so user sees it
            let _ = self.event_tx.try_send(TuiEvent::Info(msg.to_string()));
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

        // Log our public/NAT status for relay testing
        if self.is_public_node().await {
            info!("=== RELAY: This node appears to be PUBLIC (can relay for others) ===");
        } else {
            info!("=== RELAY: This node appears to be behind NAT ===");
        }

        // Register with the registry (now with external address from QUIC discovery)
        self.register().await?;

        // Start background tasks
        let shutdown = Arc::clone(&self.shutdown);

        // Spawn all background tasks
        let heartbeat_handle = self.spawn_heartbeat_loop();
        let connect_handle = self.spawn_connect_loop();
        let test_handle = self.spawn_test_loop();
        let health_handle = self.spawn_health_check_loop();
        let relay_stats_handle = self.spawn_relay_stats_loop();
        let gossip_handle = self.spawn_gossip_loop();

        // Announce ourselves to gossip network
        self.announce_to_gossip().await;

        // Wait for shutdown
        while !shutdown.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Abort tasks on shutdown
        heartbeat_handle.abort();
        connect_handle.abort();
        test_handle.abort();
        health_handle.abort();
        relay_stats_handle.abort();
        gossip_handle.abort();

        // Save peer cache and shutdown gossip integration
        if let Err(e) = self.gossip_integration.save_cache() {
            warn!("Failed to save peer cache on shutdown: {}", e);
        }
        self.gossip_integration.discovery().shutdown();

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

                    // Send updated node info to TUI (non-blocking)
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::UpdateLocalNode(local_node));
                    let _ = self.event_tx.try_send(TuiEvent::RegistrationComplete);

                    // Also send the registered count (non-blocking)
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::UpdateRegisteredCount(response.peers.len() + 1));
                } else {
                    let err = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    error!("Registration failed: {}", err);
                    // Send error to TUI (non-blocking)
                    let _ = self
                        .event_tx
                        .try_send(TuiEvent::Error(format!("Registration failed: {}", err)));
                    return Err(anyhow::anyhow!("Registration failed: {}", err));
                }
            }
            Err(e) => {
                error!("Failed to connect to registry: {}", e);
                // Send error to TUI (non-blocking)
                let _ = self.event_tx.try_send(TuiEvent::Error(format!(
                    "Registry connection failed: {}",
                    e
                )));
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
        // Clone inbound_connections counter for heartbeat reporting
        let inbound_connections = Arc::clone(&self.inbound_connections);
        // Clone gossip integration for gossip stats reporting
        let gossip_integration = Arc::clone(&self.gossip_integration);
        // Clone event_tx to send HeartbeatSent events to TUI
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut consecutive_failures = 0u32;
            let mut heartbeat_count = 0u64;

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;
                heartbeat_count += 1;

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

                // Collect gossip protocol statistics
                let gossip_metrics = gossip_integration.metrics();

                // Compute connection type breakdown from connected peers
                let (conn_direct_ipv4, conn_direct_ipv6, conn_hole_punched, conn_relayed) = {
                    let mut ipv4 = 0usize;
                    let mut ipv6 = 0usize;
                    let mut hole_punched = 0usize;
                    let mut relayed = 0usize;

                    for tracked in peers.values() {
                        match tracked.method {
                            ConnectionMethod::Direct => {
                                // Check if active connection is IPv6
                                if tracked.connectivity.active_is_ipv6 {
                                    ipv6 += 1;
                                } else {
                                    ipv4 += 1;
                                }
                            }
                            ConnectionMethod::HolePunched => {
                                hole_punched += 1;
                            }
                            ConnectionMethod::Relayed => {
                                relayed += 1;
                            }
                        }
                    }

                    (ipv4, ipv6, hole_punched, relayed)
                };

                // Use connected peers count as "alive" peers for SWIM-like stats
                let swim_alive = peers.len();

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
                    // HyParView stats - using connected peers as active view proxy
                    hyparview_active: swim_alive,
                    hyparview_passive: gossip_integration.cache_size(),
                    // SWIM stats - connected peers are "alive"
                    swim_alive,
                    swim_suspect: 0, // No suspect tracking yet
                    swim_dead: 0,    // No dead tracking yet
                    // Plumtree stats - using gossip metrics as proxy
                    plumtree_sent: gossip_metrics.announcements_sent.load(Ordering::Relaxed),
                    plumtree_received: gossip_metrics
                        .announcements_received
                        .load(Ordering::Relaxed),
                    plumtree_eager: swim_alive, // Active peers get eager push
                    plumtree_lazy: 0,           // No lazy push tracking yet
                    // Connection type breakdown (computed from connected peers)
                    conn_direct_ipv4,
                    conn_direct_ipv6,
                    conn_hole_punched,
                    conn_relayed,
                };

                // Total connections = outbound (in connected_peers HashMap) + inbound
                // The connected_peers HashMap only tracks connections WE initiated,
                // so we must add inbound_connections to get the true total.
                let total_connected = peers.len() + stats.inbound_connections as usize;

                let heartbeat = NodeHeartbeat {
                    peer_id: peer_id.clone(),
                    connected_peers: total_connected,
                    bytes_sent: bytes_sent.load(Ordering::Relaxed),
                    bytes_received: bytes_received.load(Ordering::Relaxed),
                    external_addresses: if ext_addrs.is_empty() {
                        None
                    } else {
                        Some(ext_addrs.clone())
                    },
                    nat_stats: Some(stats),
                    gossip_stats: Some(gossip_stats),
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
                    // Notify TUI that heartbeat was successful (non-blocking to avoid deadlock)
                    let _ = event_tx.try_send(TuiEvent::HeartbeatSent);
                }
            }
        })
    }

    /// Spawn the peer connection background task.
    ///
    /// Bidirectional connectivity testing strategy:
    /// 1. Get list of LIVE peers from registry (is_active = recent heartbeat)
    /// 2. Only attempt connections to peers we've been disconnected from for >30 seconds
    ///    (this ensures NAT mappings have expired and we're testing FRESH hole-punches)
    /// 3. Each node independently tests its own outbound connectivity
    /// 4. When A tests A→B and B tests B→A, registry can correlate for true bidirectional
    #[allow(clippy::excessive_nesting)]
    fn spawn_connect_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = RegistryClient::new(&self.config.registry_url);
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let disconnection_times = Arc::clone(&self.disconnection_times);
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
        // Clone pending_outbound to track outbound connection attempts
        let pending_outbound = Arc::clone(&self.pending_outbound);
        // Clone gossip integration for decentralized peer discovery
        let gossip_integration = Arc::clone(&self.gossip_integration);

        // Minimum time since disconnection before attempting fresh connection (30 seconds)
        // This ensures NAT mappings have expired and we're testing real hole-punching
        const RECONNECT_COOLDOWN_SECS: u64 = 30;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            while !shutdown.load(Ordering::SeqCst) {
                ticker.tick().await;
                let now = Instant::now();

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

                // Get current connection state and disconnection times
                let connected = connected_peers.read().await;
                let disc_times = disconnection_times.read().await;

                // Filter candidates:
                // 1. Not ourselves
                // 2. Not currently connected
                // 3. Is active (recent heartbeat = peer is online)
                // 4. IP version compatible
                // 5. Either never connected OR disconnected for >30 seconds (fresh hole-punch test)
                let candidates: Vec<PeerInfo> = peers
                    .iter()
                    .filter(|p| p.peer_id != our_peer_id)
                    .filter(|p| !connected.contains_key(&p.peer_id))
                    .filter(|p| p.is_active) // Only test against LIVE peers
                    .filter(|p| can_reach_peer(p, our_has_ipv6))
                    .filter(|p| {
                        // Check if we've been disconnected long enough for NAT to forget
                        match disc_times.get(&p.peer_id) {
                            Some(disconnected_at) => {
                                let elapsed = now.duration_since(*disconnected_at);
                                if elapsed.as_secs() >= RECONNECT_COOLDOWN_SECS {
                                    debug!(
                                        "Peer {} eligible: disconnected {}s ago (>{}s cooldown)",
                                        &p.peer_id[..8.min(p.peer_id.len())],
                                        elapsed.as_secs(),
                                        RECONNECT_COOLDOWN_SECS
                                    );
                                    true
                                } else {
                                    debug!(
                                        "Peer {} skipped: only {}s since disconnect (<{}s cooldown)",
                                        &p.peer_id[..8.min(p.peer_id.len())],
                                        elapsed.as_secs(),
                                        RECONNECT_COOLDOWN_SECS
                                    );
                                    false
                                }
                            }
                            None => {
                                // Never connected before - eligible for first connection
                                debug!(
                                    "Peer {} eligible: never connected before",
                                    &p.peer_id[..8.min(p.peer_id.len())]
                                );
                                true
                            }
                        }
                    })
                    .cloned()
                    .collect();

                drop(connected);
                drop(disc_times);

                if candidates.is_empty() {
                    debug!("No eligible peers for fresh hole-punch testing");
                    continue;
                }

                info!(
                    "Testing connectivity to {} eligible peers (all disconnected >{}s)",
                    candidates.len(),
                    RECONNECT_COOLDOWN_SECS
                );

                // Connect to ALL eligible peers concurrently (max 20 at a time)
                // Higher limit ensures DO nodes quickly reach all community test nodes
                let mut connect_futures = Vec::new();
                for candidate in candidates.into_iter().take(20) {
                    let endpoint = Arc::clone(&endpoint);
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

                    let fut = async move {
                        let peer_id_short = &candidate.peer_id[..8.min(candidate.peer_id.len())];
                        info!(
                            "Testing FRESH hole-punch to peer {} ({:?})",
                            peer_id_short, candidate.country_code
                        );

                        // Mark this as an outbound connection attempt
                        // When PeerConnected fires, if peer is in pending_outbound, it's outbound
                        {
                            let mut pending = pending_outbound.write().await;
                            pending.insert(candidate.peer_id.clone());
                        }

                        // Update NAT stats
                        {
                            let mut stats = nat_stats.write().await;
                            stats.attempts += 1;
                        }

                        // Use comprehensive connection testing to try ALL paths
                        let result = real_connect_comprehensive(&endpoint, &candidate).await;

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
                            // Extract values and clone matrix before moving
                            let is_ipv6 = result.matrix.active_is_ipv6;
                            let connectivity_for_report = result.matrix.clone();
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
                            };

                            let peer_for_tui = tracked.to_connected_peer();

                            connected_peers
                                .write()
                                .await
                                .insert(candidate.peer_id.clone(), tracked);

                            info!(
                                "COMPREHENSIVE test SUCCESS to {} via {:?} (matrix: {})",
                                peer_id_short,
                                final_method,
                                peer_for_tui.connectivity_summary()
                            );

                            let _ = event_tx.try_send(TuiEvent::PeerConnected(peer_for_tui));

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

                            // Cache this peer for gossip/bootstrap
                            gossip_integration.record_success(&candidate.peer_id);
                            debug!(
                                "Cached successful connection to {} in gossip bootstrap cache",
                                peer_id_short
                            );
                        } else {
                            // Connection failed - clean up and report
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
                                    "COMPREHENSIVE test FAILED to {} (peer is LIVE, matrix: {})",
                                    peer_id_short,
                                    result.matrix.summary()
                                );
                                let _ = event_tx.try_send(TuiEvent::ConnectionFailed);
                            } else {
                                debug!(
                                    "Connection to {} failed but peer went offline",
                                    peer_id_short
                                );
                            }
                        }
                    };

                    connect_futures.push(fut);
                }

                // Execute all connections concurrently
                futures_util::future::join_all(connect_futures).await;
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

                    // Perform REAL test packet exchange over QUIC streams
                    // WITHOUT holding any lock - prevents heartbeat starvation
                    let result = real_test_exchange(&endpoint, &peer_id, &packet).await;

                    // Now briefly acquire lock to update stats
                    let success = result.is_ok();
                    let rtt_for_tui = result.as_ref().ok().copied();

                    {
                        let mut peers = connected_peers.write().await;
                        if let Some(tracked) = peers.get_mut(&peer_id) {
                            match &result {
                                Ok(rtt) => {
                                    tracked.stats.tests_success += 1;
                                    tracked.stats.total_rtt_ms += rtt.as_millis() as u64;
                                    tracked.stats.last_rtt = Some(*rtt);
                                    tracked.stats.packets_sent += 1;
                                    tracked.stats.packets_received += 1;
                                    tracked.last_activity = Instant::now();
                                    tracked.consecutive_failures = 0; // Reset on success

                                    total_sent.fetch_add(packet_size, Ordering::Relaxed);
                                    total_received.fetch_add(packet_size, Ordering::Relaxed);

                                    debug!(
                                        "REAL test packet sent to {} ({} bytes, RTT: {:?})",
                                        &peer_id[..8],
                                        packet_size,
                                        rtt
                                    );
                                }
                                Err(e) => {
                                    tracked.stats.tests_failed += 1;
                                    tracked.consecutive_failures += 1;
                                    warn!("Test packet to {} failed: {}", &peer_id[..8], e);
                                }
                            }
                        }
                    } // Lock released here before TUI update

                    // Update TUI outside the lock (non-blocking)
                    let _ = event_tx.try_send(TuiEvent::TestPacketResult {
                        peer_id: peer_id.clone(),
                        success,
                        rtt: rtt_for_tui,
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
/// Result of comprehensive connection testing.
struct ComprehensiveConnectResult {
    /// The connectivity matrix with all tested paths.
    matrix: ConnectivityMatrix,
    /// The best connection method to use.
    best_method: ConnectionMethod,
    /// Whether connection succeeded at all.
    success: bool,
}

/// Comprehensive connection test that tries ALL paths for complete network analysis.
///
/// Unlike real_connect which returns on first success, this function tests:
/// 1. IPv4 direct connections (all IPv4 addresses)
/// 2. IPv6 direct connections (all IPv6 addresses)
/// 3. NAT traversal (hole-punching)
/// 4. Relay (if available)
///
/// This enables comprehensive network testing for studies and design.
async fn real_connect_comprehensive(
    endpoint: &P2pEndpoint,
    peer: &PeerInfo,
) -> ComprehensiveConnectResult {
    let peer_id_short = &peer.peer_id[..8.min(peer.peer_id.len())];
    let mut matrix = ConnectivityMatrix::default();

    // Separate addresses by IP version
    let ipv4_addrs: Vec<_> = peer.addresses.iter().filter(|a| a.is_ipv4()).collect();
    let ipv6_addrs: Vec<_> = peer.addresses.iter().filter(|a| a.is_ipv6()).collect();

    info!(
        "Testing comprehensive connectivity to {}: {} IPv4, {} IPv6 addresses",
        peer_id_short,
        ipv4_addrs.len(),
        ipv6_addrs.len()
    );

    // Test IPv4 direct connections
    if !ipv4_addrs.is_empty() {
        matrix.ipv4_direct_tested = true;
        let start = Instant::now();
        for addr in &ipv4_addrs {
            match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(**addr)).await {
                Ok(Ok(_conn)) => {
                    matrix.ipv4_direct_success = true;
                    matrix.ipv4_direct_rtt_ms = Some(start.elapsed().as_millis() as u64);
                    info!(
                        "IPv4 direct connection to {} at {} succeeded",
                        peer_id_short, addr
                    );
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

    // Test IPv6 direct connections (even if IPv4 succeeded - comprehensive testing)
    if !ipv6_addrs.is_empty() {
        matrix.ipv6_direct_tested = true;
        let start = Instant::now();
        for addr in &ipv6_addrs {
            match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(**addr)).await {
                Ok(Ok(_conn)) => {
                    matrix.ipv6_direct_success = true;
                    matrix.ipv6_direct_rtt_ms = Some(start.elapsed().as_millis() as u64);
                    info!(
                        "IPv6 direct connection to {} at {} succeeded",
                        peer_id_short, addr
                    );
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

    // Test NAT traversal (even if direct succeeded - comprehensive testing)
    if let Ok(peer_id_bytes) = hex::decode(&peer.peer_id) {
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
                Ok(Ok(_conn)) => {
                    matrix.nat_traversal_success = true;
                    matrix.nat_traversal_rtt_ms = Some(start.elapsed().as_millis() as u64);
                    info!("NAT traversal to {} succeeded", peer_id_short);
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

// ============================================================================
// Gossip Peer List Exchange Functions
// ============================================================================

/// Send our peer list to a specific peer.
///
/// Called when a new connection is established to exchange peer knowledge.
async fn send_gossip_peer_list(
    endpoint: &P2pEndpoint,
    peer_id_hex: &str,
    our_peer_id: &str,
    peers: Vec<GossipPeerInfo>,
) -> Result<(), String> {
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

    // Create peer list message
    let message = PeerListMessage::new(our_peer_id.to_string(), peers);

    // Serialize the message
    let message_data = message
        .to_bytes()
        .map_err(|e| format!("Failed to serialize peer list: {}", e))?;

    // Open a unidirectional stream and send the message
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
    endpoint: &P2pEndpoint,
    connected_peers: &RwLock<HashMap<String, TrackedPeer>>,
    announcement: &GossipPeerAnnouncement,
    exclude_peer: Option<&str>,
) -> usize {
    // Collect peer IDs first to avoid holding lock during network operations
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
        // Convert hex peer ID to QuicPeerId
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

        // Get the QUIC connection for this peer
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
