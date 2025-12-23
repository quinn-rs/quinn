//! Test node client implementation.
//!
//! Handles automatic registration with the registry, peer discovery,
//! automatic connections, and test traffic generation.

use crate::registry::{
    ConnectionMethod, NatStats, NatType, NodeCapabilities, NodeHeartbeat, NodeRegistration,
    PeerInfo, RegistryClient,
};
use crate::tui::{ConnectedPeer, TuiEvent, country_flag};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

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
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

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
    /// Stats for this peer.
    stats: PeerStats,
    /// Sequence counter for test packets.
    sequence: AtomicU64,
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
pub struct TestNode {
    /// Configuration.
    config: TestNodeConfig,
    /// Registry client.
    registry: RegistryClient,
    /// Our peer ID.
    peer_id: String,
    /// Our public key (hex encoded).
    public_key: String,
    /// Local addresses.
    listen_addresses: Vec<SocketAddr>,
    /// External addresses (discovered).
    external_addresses: Arc<RwLock<Vec<SocketAddr>>>,
    /// Connected peers.
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
}

impl TestNode {
    /// Create a new test node.
    pub fn new(config: TestNodeConfig, event_tx: mpsc::Sender<TuiEvent>) -> Self {
        let registry = RegistryClient::new(&config.registry_url);

        // Generate a temporary peer ID - in real usage this comes from the P2pEndpoint
        let peer_id = generate_temporary_peer_id();
        let public_key = "placeholder_public_key".to_string();

        Self {
            listen_addresses: vec![config.bind_addr],
            config,
            registry,
            peer_id,
            public_key,
            external_addresses: Arc::new(RwLock::new(Vec::new())),
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
        }
    }

    /// Initialize with a real P2pEndpoint.
    pub fn with_endpoint_info(
        mut self,
        peer_id: String,
        public_key: String,
        listen_addresses: Vec<SocketAddr>,
    ) -> Self {
        self.peer_id = peer_id;
        self.public_key = public_key;
        self.listen_addresses = listen_addresses;
        self
    }

    /// Get our peer ID.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Start the test node (runs all background tasks).
    pub async fn run(&self) -> anyhow::Result<()> {
        info!(
            "Starting test node {} connecting to {}",
            &self.peer_id[..8.min(self.peer_id.len())],
            self.config.registry_url
        );

        // Register with the registry
        self.register().await?;

        // Start background tasks
        let shutdown = Arc::clone(&self.shutdown);

        // Spawn all background tasks
        let heartbeat_handle = self.spawn_heartbeat_loop();
        let connect_handle = self.spawn_connect_loop();
        let test_handle = self.spawn_test_loop();

        // Wait for shutdown
        while !shutdown.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Abort tasks on shutdown
        heartbeat_handle.abort();
        connect_handle.abort();
        test_handle.abort();

        info!("Test node shutting down");
        Ok(())
    }

    /// Register with the central registry.
    async fn register(&self) -> anyhow::Result<()> {
        let external_addrs = self.external_addresses.read().await.clone();

        let registration = NodeRegistration {
            peer_id: self.peer_id.clone(),
            public_key: self.public_key.clone(),
            listen_addresses: self.listen_addresses.clone(),
            external_addresses: external_addrs,
            nat_type: NatType::Unknown, // Will be determined after connections
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: NodeCapabilities::default(),
            location_label: None,
        };

        match self.registry.register(&registration).await {
            Ok(response) => {
                if response.success {
                    info!(
                        "Registered with registry, got {} peers",
                        response.peers.len()
                    );
                    // Send registration success to TUI
                    let _ = self.event_tx.send(TuiEvent::RegistrationComplete).await;
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
        let shutdown = Arc::clone(&self.shutdown);
        let connected_peers = Arc::clone(&self.connected_peers);
        let external_addresses = Arc::clone(&self.external_addresses);
        let nat_stats = Arc::clone(&self.nat_stats);
        let bytes_sent = Arc::clone(&self.total_bytes_sent);
        let bytes_received = Arc::clone(&self.total_bytes_received);
        let interval = self.config.heartbeat_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

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
                        Some(ext_addrs)
                    },
                    nat_stats: Some(stats),
                };
                drop(peers);

                if let Err(e) = registry.heartbeat(&heartbeat).await {
                    warn!("Heartbeat failed: {}", e);
                } else {
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

                // Filter out ourselves and already-connected peers
                let connected = connected_peers.read().await;
                let candidates: Vec<&PeerInfo> = peers
                    .iter()
                    .filter(|p| p.peer_id != our_peer_id)
                    .filter(|p| !connected.contains_key(&p.peer_id))
                    .filter(|p| p.is_active)
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
                    "Attempting connection to peer {} ({:?})",
                    &candidate.peer_id[..8.min(candidate.peer_id.len())],
                    candidate.country_code
                );

                // Update NAT stats
                {
                    let mut stats = nat_stats.write().await;
                    stats.attempts += 1;
                }

                // Simulate connection attempt (in real implementation, use P2pEndpoint)
                // For now, we'll simulate success for demonstration
                let connection_result = simulate_connection(candidate).await;

                match connection_result {
                    Ok(method) => {
                        success.fetch_add(1, Ordering::Relaxed);
                        match method {
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

                        let tracked = TrackedPeer {
                            info: (*candidate).clone(),
                            method,
                            connected_at: Instant::now(),
                            stats: PeerStats::default(),
                            sequence: AtomicU64::new(0),
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
                            method
                        );

                        // Notify TUI
                        let _ = event_tx.send(TuiEvent::PeerConnected(peer_for_tui)).await;
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

                        // Simulate test packet exchange
                        let result = simulate_test_exchange(&packet).await;

                        match result {
                            Ok(rtt) => {
                                tracked.stats.tests_success += 1;
                                tracked.stats.total_rtt_ms += rtt.as_millis() as u64;
                                tracked.stats.last_rtt = Some(rtt);
                                tracked.stats.packets_sent += 1;
                                tracked.stats.packets_received += 1;

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

/// Generate a temporary peer ID for testing.
fn generate_temporary_peer_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    hex::encode(bytes)
}

/// Convert peer ID string to 32-byte array.
fn peer_id_to_bytes(peer_id: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if let Ok(decoded) = hex::decode(peer_id) {
        let len = decoded.len().min(32);
        bytes[..len].copy_from_slice(&decoded[..len]);
    }
    bytes
}

/// Simulate a connection attempt (placeholder for real P2pEndpoint integration).
async fn simulate_connection(_peer: &PeerInfo) -> Result<ConnectionMethod, String> {
    use rand::Rng;

    // Generate random values before await point to avoid Send issues
    let (delay, roll): (u64, f64) = {
        let mut rng = rand::thread_rng();
        (100 + rng.gen_range(0..200), rng.r#gen())
    };

    // Simulate network delay
    tokio::time::sleep(Duration::from_millis(delay)).await;

    // Simulate success with realistic distribution
    if roll < 0.05 {
        // 5% failure rate
        Err("Connection timeout".to_string())
    } else if roll < 0.75 {
        // 70% direct
        Ok(ConnectionMethod::Direct)
    } else if roll < 0.95 {
        // 20% hole-punched
        Ok(ConnectionMethod::HolePunched)
    } else {
        // 5% relayed
        Ok(ConnectionMethod::Relayed)
    }
}

/// Simulate test packet exchange (placeholder for real implementation).
async fn simulate_test_exchange(_packet: &TestPacket) -> Result<Duration, String> {
    use rand::Rng;

    // Generate random values before await point to avoid Send issues
    let (rtt_ms, success): (u64, bool) = {
        let mut rng = rand::thread_rng();
        (10 + rng.gen_range(0..200), rng.gen_bool(0.98))
    };

    // Simulate network delay
    tokio::time::sleep(Duration::from_millis(rtt_ms / 2)).await;

    // 98% success rate
    if success {
        Ok(Duration::from_millis(rtt_ms))
    } else {
        Err("Packet lost".to_string())
    }
}
