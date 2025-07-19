//! ant-quic: Advanced QUIC with NAT Traversal for P2P Networks
//!
//! A unified binary for P2P networking with advanced NAT traversal capabilities.
//! Each node can act as:
//! - A P2P client seeking connections through NAT traversal
//! - A coordinator/bootstrap node providing services to other peers (if publicly reachable)
//! - Network simulation for testing NAT traversal scenarios
//!
//! Nodes automatically detect their reachability and enable coordinator services
//! when they can be reached directly, creating a decentralized bootstrap network.

use ant_quic::terminal_ui;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ant_quic::{
    CandidateAddress, CandidateSource, CandidateState, PeerId, derive_peer_id_from_public_key,
    generate_ed25519_keypair, candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig},
};
use clap::Parser;
// use four_word_networking::FourWordAdaptiveEncoder;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{self, Rng};
use std::io;
use terminal_ui::{
    ProgressIndicator, colors, describe_address, format_address, format_address_with_words,
    format_peer_id, print_banner, print_item, print_section, print_status, symbols,
};
use tokio::{
    net::UdpSocket,
    time::{interval, sleep, timeout},
};
use tracing::{debug, error, info, warn};

/// Dual-stack socket manager for IPv4 and IPv6
#[derive(Debug)]
struct DualStackSocket {
    /// IPv4 socket
    ipv4_socket: Option<UdpSocket>,
    /// IPv6 socket
    ipv6_socket: Option<UdpSocket>,
    /// Primary address (the one we bind to)
    primary_addr: SocketAddr,
    /// All bound addresses
    bound_addresses: Vec<SocketAddr>,
}

impl DualStackSocket {
    /// Create a new dual-stack socket binding to the specified address
    async fn bind(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ipv4_socket = None;
        let mut ipv6_socket = None;
        let mut bound_addresses = Vec::new();

        match addr {
            SocketAddr::V4(_) => {
                // Primary is IPv4, try to bind IPv4 first
                if let Ok(socket) = UdpSocket::bind(addr).await {
                    let bound_addr = socket.local_addr()?;
                    bound_addresses.push(bound_addr);
                    ipv4_socket = Some(socket);

                    // Also try to bind IPv6 on same port for dual-stack
                    let ipv6_addr = SocketAddr::new(
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        bound_addr.port(),
                    );
                    if let Ok(socket) = UdpSocket::bind(ipv6_addr).await {
                        let ipv6_bound_addr = socket.local_addr()?;
                        bound_addresses.push(ipv6_bound_addr);
                        ipv6_socket = Some(socket);
                        debug!("Dual-stack: IPv6 socket bound to {}", ipv6_bound_addr);
                    } else {
                        debug!("Dual-stack: Failed to bind IPv6 socket, IPv4 only");
                    }
                } else {
                    return Err("Failed to bind IPv4 socket".into());
                }
            }
            SocketAddr::V6(_) => {
                // Primary is IPv6, try to bind IPv6 first
                if let Ok(socket) = UdpSocket::bind(addr).await {
                    let bound_addr = socket.local_addr()?;
                    bound_addresses.push(bound_addr);
                    ipv6_socket = Some(socket);

                    // Also try to bind IPv4 on same port for dual-stack
                    let ipv4_addr = SocketAddr::new(
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        bound_addr.port(),
                    );
                    if let Ok(socket) = UdpSocket::bind(ipv4_addr).await {
                        let ipv4_bound_addr = socket.local_addr()?;
                        bound_addresses.push(ipv4_bound_addr);
                        ipv4_socket = Some(socket);
                        debug!("Dual-stack: IPv4 socket bound to {}", ipv4_bound_addr);
                    } else {
                        debug!("Dual-stack: Failed to bind IPv4 socket, IPv6 only");
                    }
                } else {
                    return Err("Failed to bind IPv6 socket".into());
                }
            }
        }

        if ipv4_socket.is_none() && ipv6_socket.is_none() {
            return Err("Failed to bind any socket".into());
        }

        Ok(Self {
            ipv4_socket,
            ipv6_socket,
            primary_addr: addr,
            bound_addresses,
        })
    }

    /// Get the primary local address
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        if let Some(ref socket) = self.ipv4_socket {
            socket.local_addr()
        } else if let Some(ref socket) = self.ipv6_socket {
            socket.local_addr()
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No sockets bound",
            ))
        }
    }

    /// Get all bound addresses
    fn bound_addresses(&self) -> &[SocketAddr] {
        &self.bound_addresses
    }

    /// Send data to a specific address using the appropriate socket
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, std::io::Error> {
        match target {
            SocketAddr::V4(_) => {
                if let Some(ref socket) = self.ipv4_socket {
                    socket.send_to(buf, target).await
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "IPv4 socket not available",
                    ))
                }
            }
            SocketAddr::V6(_) => {
                if let Some(ref socket) = self.ipv6_socket {
                    socket.send_to(buf, target).await
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "IPv6 socket not available",
                    ))
                }
            }
        }
    }

    /// Receive data from any bound socket
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        use tokio::select;

        match (&self.ipv4_socket, &self.ipv6_socket) {
            (Some(ipv4), Some(ipv6)) => {
                // Create separate buffer slices to avoid borrow checker issues
                let mut ipv4_buf = [0u8; 1472];
                let mut ipv6_buf = [0u8; 1472];

                select! {
                    result = ipv4.recv_from(&mut ipv4_buf) => {
                        match result {
                            Ok((size, addr)) => {
                                buf[..size].copy_from_slice(&ipv4_buf[..size]);
                                Ok((size, addr))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    result = ipv6.recv_from(&mut ipv6_buf) => {
                        match result {
                            Ok((size, addr)) => {
                                buf[..size].copy_from_slice(&ipv6_buf[..size]);
                                Ok((size, addr))
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            (Some(ipv4), None) => ipv4.recv_from(buf).await,
            (None, Some(ipv6)) => ipv6.recv_from(buf).await,
            (None, None) => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No sockets bound",
            )),
        }
    }

    /// Check if IPv4 is available
    fn has_ipv4(&self) -> bool {
        self.ipv4_socket.is_some()
    }

    /// Check if IPv6 is available
    fn has_ipv6(&self) -> bool {
        self.ipv6_socket.is_some()
    }
}

/// Command line arguments for ant-quic
#[derive(Parser, Debug)]
#[command(name = "ant-quic")]
#[command(about = "Advanced QUIC with NAT Traversal for P2P Networks")]
#[command(long_about = "
ant-quic is a QUIC implementation with advanced NAT traversal capabilities for P2P networks.
It can automatically detect network reachability and operate in multiple modes:

- Client: Connect to peers through NAT traversal
- Coordinator: Provide bootstrap services to other peers  
- Simulation: Test NAT traversal scenarios

Designed for the Autonomi decentralized network ecosystem.
")]
struct Args {
    /// Node's listening address
    #[arg(short, long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,

    /// Bootstrap nodes to connect to (comma separated, supports IP:port or four-word addresses)
    #[arg(short, long)]
    bootstrap: Option<String>,

    /// Connect to specific peer by ID (hex format)
    #[arg(short, long)]
    connect: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Force coordinator mode (don't auto-detect)
    #[arg(long)]
    force_coordinator: bool,

    /// Reachability test timeout in seconds
    #[arg(long, default_value = "5")]
    reachability_timeout: u64,

    /// Statistics reporting interval in seconds
    #[arg(long, default_value = "30")]
    stats_interval: u64,

    /// Run network simulation mode
    #[arg(long)]
    simulate: bool,

    /// Number of nodes in simulation
    #[arg(long, default_value = "10")]
    nodes: usize,

    /// Simulation duration in seconds
    #[arg(long, default_value = "300")]
    duration: u64,
}

/// Node capability based on network reachability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeCapability {
    /// Node is publicly reachable and can serve as coordinator
    PublicCoordinator,
    /// Node is behind NAT but has some limited reachability
    LimitedReachability,
    /// Node is behind restrictive NAT, client-only
    ClientOnly,
}

/// Role the node is currently playing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeRole {
    /// Acting as coordinator/bootstrap node
    Coordinator,
    /// Acting as P2P client
    Client,
    /// Acting as both coordinator and client
    Hybrid,
}

/// Connection attempt with another peer
#[derive(Debug, Clone)]
struct PeerConnection {
    /// Target peer ID
    peer_id: PeerId,
    /// Known addresses for this peer
    known_addresses: Vec<SocketAddr>,
    /// Connection state
    state: ConnectionState,
    /// When connection attempt started
    started_at: Instant,
    /// Last activity
    last_activity: Instant,
    /// Number of attempts made
    attempt_count: u32,
}

/// State of a peer connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// Attempting direct connection
    DirectAttempt,
    /// Discovering address candidates
    CandidateDiscovery,
    /// Coordinating NAT traversal
    Coordination,
    /// Performing hole punching
    HolePunching,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
}

/// Statistics for the unified node
#[derive(Debug, Clone)]
struct NodeStats {
    /// Node's current role
    current_role: NodeRole,
    /// Node's detected capability
    capability: NodeCapability,
    /// When the node started
    start_time: Instant,
    /// Uptime duration
    uptime: Duration,

    // Client stats
    /// Known bootstrap nodes
    bootstrap_nodes: usize,
    /// Active peer connections
    active_connections: usize,
    /// Successful connections made
    successful_connections: u64,
    /// Failed connection attempts
    failed_connections: u64,
    /// Outgoing NAT traversal attempts
    nat_traversal_attempts: u64,

    // Coordinator stats
    /// Clients we're serving as coordinator
    served_clients: usize,
    /// Total discovery requests handled
    discovery_requests_handled: u64,
    /// Total coordination requests handled
    coordination_requests_handled: u64,
    /// Active coordination sessions
    active_coordination_sessions: usize,
    /// Server reflexive discoveries provided
    reflexive_discoveries_provided: u64,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            current_role: NodeRole::Client,
            capability: NodeCapability::ClientOnly,
            start_time: Instant::now(),
            uptime: Duration::ZERO,
            bootstrap_nodes: 0,
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            served_clients: 0,
            discovery_requests_handled: 0,
            coordination_requests_handled: 0,
            active_coordination_sessions: 0,
            reflexive_discoveries_provided: 0,
        }
    }
}

/// Information about a peer we're serving as coordinator
#[derive(Debug, Clone)]
struct ServedPeer {
    /// Peer's ID
    #[allow(dead_code)] // Will be used for peer identification in NAT traversal
    peer_id: PeerId,
    /// Peer's chosen nickname
    nickname: String,
    /// Observed address
    observed_address: SocketAddr,
    /// Local candidates reported by peer
    #[allow(dead_code)] // Will be used for NAT traversal coordination
    local_candidates: Vec<CandidateAddress>,
    /// Last seen timestamp
    last_seen: Instant,
}

/// Active coordination session between two peers
#[derive(Debug, Clone)]
struct CoordinationSession {
    /// Requesting peer
    requester: PeerId,
    /// Target peer
    target: PeerId,
    /// Session start time
    started_at: Instant,
    /// Session timeout
    timeout: Duration,
}

/// Chat message between peers
#[derive(Debug, Clone)]
struct ChatMessage {
    /// Message ID for deduplication
    #[allow(dead_code)] // Will be used for message deduplication
    message_id: u64,
    /// Sender's peer ID
    #[allow(dead_code)] // Will be used for message verification
    from_peer_id: PeerId,
    /// Sender's nickname
    from_nickname: String,
    /// Target peer ID (None for broadcast)
    #[allow(dead_code)] // Will be used for direct messaging
    to_peer_id: Option<PeerId>,
    /// Target nickname (None for broadcast)
    #[allow(dead_code)] // Will be used for direct messaging UI
    to_nickname: Option<String>,
    /// Message content
    content: String,
    /// Timestamp when sent
    timestamp: Instant,
    /// Whether this is a broadcast message
    is_broadcast: bool,
}

/// Chat state management
#[derive(Debug, Clone)]
struct ChatState {
    /// Our own nickname
    our_nickname: String,
    /// Message history
    message_history: Vec<ChatMessage>,
    /// Connected peers with nicknames
    connected_peers: HashMap<PeerId, String>,
    /// Next message ID
    next_message_id: u64,
}

/// Main unified P2P node
struct UnifiedP2PNode {
    /// Node's own peer ID (derived from public key)
    peer_id: PeerId,
    /// Ed25519 private key for this node
    #[allow(dead_code)] // Will be used for signing messages and authentication
    private_key: SigningKey,
    /// Ed25519 public key for this node
    #[allow(dead_code)] // May be used for cryptographic operations in the future
    public_key: VerifyingKey,
    /// Dual-stack socket for IPv4/IPv6 communication
    socket: DualStackSocket,
    /// Primary local address we're bound to
    local_addr: SocketAddr,
    /// All bound addresses (IPv4 and IPv6)
    #[allow(dead_code)] // Kept for potential future use in multi-homed scenarios
    bound_addresses: Vec<SocketAddr>,
    /// Configuration
    config: NodeConfig,

    // Node state
    /// Current node capability
    capability: NodeCapability,
    /// Current node role
    current_role: NodeRole,
    /// Statistics
    stats: Arc<Mutex<NodeStats>>,

    // Client state
    /// Known bootstrap nodes
    bootstrap_nodes: Arc<Mutex<Vec<SocketAddr>>>,
    /// Active peer connections
    peer_connections: Arc<Mutex<HashMap<PeerId, PeerConnection>>>,
    /// Discovered local candidates
    local_candidates: Arc<Mutex<Vec<CandidateAddress>>>,

    // Coordinator state
    /// Peers we're serving as coordinator
    served_peers: Arc<Mutex<HashMap<PeerId, ServedPeer>>>,
    /// Active coordination sessions
    coordination_sessions: Arc<Mutex<HashMap<(PeerId, PeerId), CoordinationSession>>>,

    // Chat state
    /// Chat functionality
    chat_state: Arc<Mutex<ChatState>>,
    /// All known peer addresses for chat (includes both served peers and bootstrap nodes)
    all_peer_addresses: Arc<Mutex<HashMap<SocketAddr, String>>>,
}

/// Configuration for the unified node
#[derive(Debug, Clone)]
struct NodeConfig {
    /// Enable coordinator services
    enable_coordinator: bool,
    /// Force coordinator mode
    force_coordinator: bool,
    /// Reachability test timeout
    reachability_timeout: Duration,
    /// Client registration timeout
    client_timeout: Duration,
    /// Connection attempt timeout
    connection_timeout: Duration,
    /// Maximum coordination sessions
    max_coordination_sessions: usize,
    /// Statistics reporting interval
    stats_interval: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            enable_coordinator: true,
            force_coordinator: false,
            reachability_timeout: Duration::from_secs(5),
            client_timeout: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(30),
            max_coordination_sessions: 100,
            stats_interval: Duration::from_secs(30),
        }
    }
}

/// Generate a random nickname for a peer
fn generate_random_nickname() -> String {
    let adjectives = [
        "Swift",
        "Bright",
        "Clever",
        "Brave",
        "Quick",
        "Wise",
        "Bold",
        "Sharp",
        "Keen",
        "Smart",
        "Agile",
        "Fast",
        "Noble",
        "Kind",
        "Cool",
        "Calm",
        "Strong",
        "Gentle",
        "Witty",
        "Cheerful",
        "Loyal",
        "Honest",
        "Creative",
        "Inventive",
        "Curious",
        "Patient",
        "Friendly",
        "Helpful",
        "Generous",
        "Thoughtful",
    ];

    let animals = [
        "Wolf", "Eagle", "Tiger", "Lion", "Bear", "Fox", "Hawk", "Raven", "Falcon", "Panther",
        "Cheetah", "Dolphin", "Shark", "Whale", "Otter", "Badger", "Lynx", "Jaguar", "Puma",
        "Cobra", "Viper", "Phoenix", "Dragon", "Griffin", "Pegasus", "Unicorn", "Sphinx", "Kraken",
        "Hydra", "Titan",
    ];

    use rand::Rng;
    let mut rng = rand::thread_rng();
    let adjective = adjectives[rng.gen_range(0..adjectives.len())];
    let animal = animals[rng.gen_range(0..animals.len())];
    let number = rng.gen_range(0..1000);

    format!("{}{}{}", adjective, animal, number)
}

impl UnifiedP2PNode {
    /// Create a new unified P2P node
    async fn new(
        listen_addr: SocketAddr,
        config: NodeConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate Ed25519 keypair and derive peer ID from public key
        let (private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);
        debug!("Generated Ed25519 keypair, derived peer ID from public key");

        // Bind dual-stack socket
        let socket = DualStackSocket::bind(listen_addr).await?;
        let local_addr = socket.local_addr()?;
        let bound_addresses = socket.bound_addresses().to_vec();

        // Verify port allocation if random port was requested
        verify_port_allocation(&listen_addr, &local_addr)?;

        debug!("Node {:?} starting on {}", peer_id, local_addr);

        // Generate a random nickname for this node
        let nickname = generate_random_nickname();
        info!("Generated nickname: {}", nickname);

        Ok(Self {
            peer_id,
            private_key,
            public_key,
            socket,
            local_addr,
            bound_addresses,
            config,
            capability: NodeCapability::ClientOnly,
            current_role: NodeRole::Client,
            stats: Arc::new(Mutex::new(NodeStats::default())),
            bootstrap_nodes: Arc::new(Mutex::new(Vec::new())),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            local_candidates: Arc::new(Mutex::new(Vec::new())),
            served_peers: Arc::new(Mutex::new(HashMap::new())),
            coordination_sessions: Arc::new(Mutex::new(HashMap::new())),
            chat_state: Arc::new(Mutex::new(ChatState {
                our_nickname: nickname,
                message_history: Vec::new(),
                connected_peers: HashMap::new(),
                next_message_id: 1,
            })),
            all_peer_addresses: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Start the unified node
    async fn start(
        &mut self,
        bootstrap_addresses: Vec<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting unified P2P node {:?}", self.peer_id);

        // Store bootstrap nodes
        {
            let mut bootstraps = self.bootstrap_nodes.lock().unwrap();
            bootstraps.extend(bootstrap_addresses.clone());
        }

        // Add bootstrap nodes to all_peer_addresses for chat
        {
            let mut all_peers = self.all_peer_addresses.lock().unwrap();
            for addr in &bootstrap_addresses {
                all_peers.insert(*addr, "BootstrapNode".to_string());
            }
        }

        // Smart mode selection based on bootstrap presence
        if bootstrap_addresses.is_empty() {
            // No bootstrap peers - try to be a coordinator
            self.capability = NodeCapability::PublicCoordinator;
            self.current_role = NodeRole::Coordinator;
            debug!("No bootstrap peers - starting as coordinator");
        } else {
            // Have bootstrap peers - detect capability normally
            self.detect_capability().await;
            self.determine_role();

            // Register with bootstrap nodes if we're in client mode
            if matches!(self.current_role, NodeRole::Client | NodeRole::Hybrid) {
                self.register_with_bootstraps().await;
            }
        }

        // Update stats with initial role
        {
            let mut stats = self.stats.lock().unwrap();
            stats.current_role = self.current_role;
            stats.capability = self.capability;
        }

        // Start periodic tasks
        let _stats_task = self.start_stats_task();
        let _cleanup_task = self.start_cleanup_task();
        let _connection_manager_task = self.start_connection_manager_task();

        // Main packet processing loop
        let mut buffer = vec![0u8; 1472];
        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, peer_addr)) => {
                    self.handle_incoming_packet(&buffer[..size], peer_addr)
                        .await;
                }
                Err(e) => {
                    warn!("Error receiving packet: {}", e);
                }
            }

            // Process timeouts and state transitions
            self.process_timeouts().await;

            // Brief sleep to prevent busy waiting
            sleep(Duration::from_millis(1)).await;
        }
    }

    /// Detect node's reachability capability
    async fn detect_capability(&mut self) {
        debug!("Detecting node reachability capability...");

        if self.config.force_coordinator {
            self.capability = NodeCapability::PublicCoordinator;
            debug!("Forced coordinator mode - assuming public reachability");
            return;
        }

        // Try to determine if we're publicly reachable
        // This is a simplified test - in practice, bootstrap nodes observe our public address
        let is_public_ip = match self.local_addr.ip() {
            IpAddr::V4(ip) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unspecified(),
        };

        if is_public_ip {
            self.capability = NodeCapability::PublicCoordinator;
            debug!("Detected public IP - enabling coordinator services");
        } else {
            // Test reachability through bootstrap nodes
            let reachable = self.test_reachability_via_bootstraps().await;
            if reachable {
                self.capability = NodeCapability::LimitedReachability;
                debug!("Limited reachability detected - may provide coordinator services");
            } else {
                self.capability = NodeCapability::ClientOnly;
                debug!("Behind NAT - client-only mode");
            }
        }
    }

    /// Test reachability through bootstrap nodes
    async fn test_reachability_via_bootstraps(&self) -> bool {
        let bootstrap_nodes = self.bootstrap_nodes.lock().unwrap().clone();
        if bootstrap_nodes.is_empty() {
            return false;
        }

        // Send test packets to bootstrap nodes and see if we get responses
        let test_packet = self.create_reachability_test_packet();
        let mut responses = 0;

        for bootstrap_addr in &bootstrap_nodes {
            if let Ok(_) = timeout(
                self.config.reachability_timeout,
                self.socket.send_to(&test_packet, *bootstrap_addr),
            )
            .await
            {
                // Wait for response (simplified)
                responses += 1;
            }
        }

        responses > 0
    }

    /// Create a reachability test packet
    fn create_reachability_test_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0xFF); // Reachability test message type
        packet.extend_from_slice(&self.peer_id.0);
        packet
    }

    /// Determine node role based on capability and configuration
    fn determine_role(&mut self) {
        if !self.config.enable_coordinator {
            self.current_role = NodeRole::Client;
            debug!("Coordinator services disabled - client-only mode");
            return;
        }

        self.current_role = match self.capability {
            NodeCapability::PublicCoordinator => {
                debug!("Enabling full coordinator services");
                NodeRole::Hybrid // Can act as both coordinator and client
            }
            NodeCapability::LimitedReachability => {
                debug!("Enabling limited coordinator services");
                NodeRole::Hybrid
            }
            NodeCapability::ClientOnly => {
                debug!("Client-only mode");
                NodeRole::Client
            }
        };

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.current_role = self.current_role;
            stats.capability = self.capability;
        }
    }

    /// Register with bootstrap nodes
    async fn register_with_bootstraps(&self) {
        let bootstrap_nodes = self.bootstrap_nodes.lock().unwrap().clone();

        for bootstrap_addr in &bootstrap_nodes {
            debug!("Registering with bootstrap node {}", bootstrap_addr);

            let registration_packet = self.create_registration_packet();
            match self
                .socket
                .send_to(&registration_packet, *bootstrap_addr)
                .await
            {
                Ok(_) => {
                    // Show connection progress
                    print_status(
                        symbols::CIRCULAR_ARROWS,
                        &format!(
                            "Registering with {}",
                            format_address_with_words(bootstrap_addr)
                        ),
                        colors::BLUE,
                    );
                }
                Err(e) => {
                    print_status(
                        symbols::CROSS,
                        &format!(
                            "Failed to reach {}: {}",
                            format_address_with_words(bootstrap_addr),
                            e
                        ),
                        colors::RED,
                    );
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.bootstrap_nodes = bootstrap_nodes.len();
        }
    }

    /// Create registration packet
    fn create_registration_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x01); // Client registration
        packet.extend_from_slice(&self.peer_id.0);
        packet
    }

    /// Handle incoming packet
    async fn handle_incoming_packet(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.is_empty() {
            return;
        }

        let message_type = data[0];
        info!(
            "Received message type 0x{:02x} ({} bytes) from {}",
            message_type,
            data.len(),
            peer_addr
        );

        match message_type {
            0x01 => {
                // Client registration (we're acting as coordinator)
                if matches!(self.current_role, NodeRole::Coordinator | NodeRole::Hybrid) {
                    self.handle_client_registration(data, peer_addr).await;
                }
            }
            0x02 => {
                // Candidate discovery request (we're acting as coordinator)
                if matches!(self.current_role, NodeRole::Coordinator | NodeRole::Hybrid) {
                    self.handle_candidate_discovery_request(data, peer_addr)
                        .await;
                }
            }
            0x03 => {
                // Coordination request (we're acting as coordinator)
                if matches!(self.current_role, NodeRole::Coordinator | NodeRole::Hybrid) {
                    self.handle_coordination_request(data, peer_addr).await;
                }
            }
            0x81 => {
                // Registration ACK (we're acting as client)
                self.handle_registration_ack(data, peer_addr).await;
            }
            0x82 => {
                // Candidate discovery response (we're acting as client)
                self.handle_candidate_discovery_response(data, peer_addr)
                    .await;
            }
            0x83 => {
                // Coordination instructions (we're acting as client)
                self.handle_coordination_instructions(data, peer_addr).await;
            }
            0x84 => {
                // Error response
                self.handle_error_response(data, peer_addr).await;
            }
            0x10 => {
                // Hole punch packet
                self.handle_hole_punch_packet(data, peer_addr).await;
            }
            0x11 => {
                // Chat message
                self.handle_chat_message(data, peer_addr).await;
            }
            0x12 => {
                // Punch notification from coordinator
                self.handle_punch_notification(data, peer_addr).await;
            }
            0xFF => {
                // Reachability test
                self.handle_reachability_test(data, peer_addr).await;
            }
            _ => {
                debug!("Unknown message type {} from {}", message_type, peer_addr);
            }
        }
    }

    /// Handle client registration (coordinator role)
    async fn handle_client_registration(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() < 33 {
            return;
        }

        let peer_id_bytes: [u8; 32] = data[1..33].try_into().unwrap();
        let peer_id = PeerId(peer_id_bytes);

        debug!("Client registration from {:?} at {}", peer_id, peer_addr);

        // Show connection with four-word address
        println!();
        print_status(
            symbols::CHECK,
            &format!(
                "New client connected: {} from {}",
                format_peer_id(&peer_id.0),
                format_address_with_words(&peer_addr)
            ),
            colors::GREEN,
        );

        // Register the peer
        {
            let mut served_peers = self.served_peers.lock().unwrap();
            let nickname = generate_random_nickname();
            served_peers.insert(
                peer_id,
                ServedPeer {
                    peer_id,
                    nickname: nickname.clone(),
                    observed_address: peer_addr,
                    local_candidates: Vec::new(),
                    last_seen: Instant::now(),
                },
            );

            // Add to chat state connected peers
            {
                let mut chat_state = self.chat_state.lock().unwrap();
                chat_state.connected_peers.insert(peer_id, nickname.clone());
            }

            // Track peer address for chat
            {
                let mut all_peers = self.all_peer_addresses.lock().unwrap();
                all_peers.insert(peer_addr, nickname.clone());
            }

            info!(
                "Peer {} connected with nickname: {} from {}",
                format_peer_id(&peer_id.0),
                nickname,
                format_address_with_words(&peer_addr)
            );
        }

        // Send registration ACK with server reflexive address
        self.send_registration_ack(peer_id, peer_addr).await;

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.served_clients = self.served_peers.lock().unwrap().len();
        }
    }

    /// Handle candidate discovery request (coordinator role)
    async fn handle_candidate_discovery_request(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() < 33 {
            return;
        }

        let peer_id_bytes: [u8; 32] = data[1..33].try_into().unwrap();
        let peer_id = PeerId(peer_id_bytes);

        debug!("Candidate discovery request from {:?}", peer_id);

        // Update peer info
        {
            let mut served_peers = self.served_peers.lock().unwrap();
            if let Some(peer) = served_peers.get_mut(&peer_id) {
                peer.last_seen = Instant::now();
                peer.observed_address = peer_addr;
            }
        }

        // Send candidate discovery response
        self.send_candidate_discovery_response(peer_id, peer_addr)
            .await;

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.discovery_requests_handled += 1;
            stats.reflexive_discoveries_provided += 1;
        }
    }

    /// Handle coordination request (coordinator role)
    async fn handle_coordination_request(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() < 65 {
            return;
        }

        let requesting_peer_bytes: [u8; 32] = data[1..33].try_into().unwrap();
        let requesting_peer = PeerId(requesting_peer_bytes);

        let target_peer_bytes: [u8; 32] = data[33..65].try_into().unwrap();
        let target_peer = PeerId(target_peer_bytes);

        debug!(
            "Coordination request: {:?} wants to connect to {:?}",
            requesting_peer, target_peer
        );

        // Check if target peer is known
        let target_info = {
            let served_peers = self.served_peers.lock().unwrap();
            served_peers.get(&target_peer).cloned()
        };

        match target_info {
            Some(target_info) => {
                // Show coordination with four-word addresses
                println!();
                print_status(
                    symbols::CIRCULAR_ARROWS,
                    &format!(
                        "Coordinating connection: {} {} wants to reach {} {}",
                        format_peer_id(&requesting_peer.0),
                        format_address_with_words(&peer_addr),
                        format_peer_id(&target_peer.0),
                        format_address_with_words(&target_info.observed_address)
                    ),
                    colors::BLUE,
                );

                // Create coordination session
                {
                    let mut sessions = self.coordination_sessions.lock().unwrap();
                    if sessions.len() < self.config.max_coordination_sessions {
                        sessions.insert(
                            (requesting_peer, target_peer),
                            CoordinationSession {
                                requester: requesting_peer,
                                target: target_peer,
                                started_at: Instant::now(),
                                timeout: Duration::from_secs(30),
                            },
                        );
                    }
                }

                // Send punch notifications to both peers for simultaneous hole punching
                let round = rand::thread_rng().gen_range(0..u32::MAX);

                // Notify requesting peer about target
                self.send_punch_notification(
                    requesting_peer,
                    peer_addr,
                    target_peer,
                    target_info.observed_address,
                    round,
                )
                .await;

                // Notify target peer about requester
                self.send_punch_notification(
                    target_peer,
                    target_info.observed_address,
                    requesting_peer,
                    peer_addr,
                    round,
                )
                .await;

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.coordination_requests_handled += 1;
                    stats.active_coordination_sessions =
                        self.coordination_sessions.lock().unwrap().len();
                }
            }
            None => {
                self.send_coordination_error(requesting_peer, peer_addr, "Target peer not found")
                    .await;
            }
        }
    }

    /// Handle registration ACK (client role)
    async fn handle_registration_ack(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() >= 39 {
            // Extract server reflexive address from response
            let ip_bytes: [u8; 4] = data[33..37].try_into().unwrap();
            let port_bytes: [u8; 2] = data[37..39].try_into().unwrap();
            let port = u16::from_be_bytes(port_bytes);
            let server_reflexive = SocketAddr::from((ip_bytes, port));

            // Print external address discovery with formatting
            println!();
            print_status(
                symbols::CHECK,
                &format!(
                    "External address discovered: {} (observed by {})",
                    format_address_with_words(&server_reflexive),
                    format_address_with_words(&peer_addr)
                ),
                colors::GREEN,
            );

            // Add to local candidates
            {
                let mut candidates = self.local_candidates.lock().unwrap();
                candidates.push(CandidateAddress {
                    address: server_reflexive,
                    priority: 100,
                    source: CandidateSource::Observed { by_node: None },
                    state: CandidateState::Valid,
                });
            }
        }
    }

    /// Handle candidate discovery response (client role)
    async fn handle_candidate_discovery_response(&self, _data: &[u8], peer_addr: SocketAddr) {
        debug!("Received candidate discovery response from {}", peer_addr);
        // Process discovered candidates
        // Implementation would parse candidates and add them to local candidates
    }

    /// Handle coordination instructions (client role)
    async fn handle_coordination_instructions(&self, data: &[u8], _peer_addr: SocketAddr) {
        if data.len() >= 39 {
            let ip_bytes: [u8; 4] = data[33..37].try_into().unwrap();
            let port_bytes: [u8; 2] = data[37..39].try_into().unwrap();
            let port = u16::from_be_bytes(port_bytes);
            let target_addr = SocketAddr::from((ip_bytes, port));

            info!(
                "Received coordination instructions to connect to {}",
                format_address_with_words(&target_addr)
            );

            // Show coordination with four-word address
            println!();
            print_status(
                symbols::ROCKET,
                &format!(
                    "Initiating NAT traversal to peer at {}",
                    format_address_with_words(&target_addr)
                ),
                colors::CYAN,
            );

            // Start hole punching to target address
            self.start_hole_punching(target_addr).await;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.nat_traversal_attempts += 1;
            }
        }
    }

    /// Handle error response
    async fn handle_error_response(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() > 34 {
            let error_len = data[33] as usize;
            if data.len() >= 34 + error_len {
                let error_msg = String::from_utf8_lossy(&data[34..34 + error_len]);
                warn!(
                    "Error from {}: {}",
                    format_address_with_words(&peer_addr),
                    error_msg
                );
            }
        }
    }

    /// Handle reachability test
    async fn handle_reachability_test(&self, _data: &[u8], peer_addr: SocketAddr) {
        debug!("Reachability test from {}", peer_addr);
        // Send simple response
        let response = vec![0xFE]; // Reachability test response
        let _ = self.socket.send_to(&response, peer_addr).await;
    }

    /// Handle hole punch packet for NAT traversal
    async fn handle_hole_punch_packet(&self, data: &[u8], peer_addr: SocketAddr) {
        if data.len() < 37 {
            // 1 + 32 + 4 = minimum size
            debug!("Hole punch packet too short from {}", peer_addr);
            return;
        }

        // Parse packet: [type(1)] [peer_id(32)] [sequence(4)]
        let from_peer_id = PeerId({
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[1..33]);
            bytes
        });

        let sequence = u32::from_be_bytes({
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[33..37]);
            bytes
        });

        info!(
            "Received hole punch {} from peer {} at {}",
            sequence,
            format_peer_id(&from_peer_id.0),
            format_address_with_words(&peer_addr)
        );

        // Track this peer for chat if not already known
        {
            let mut all_peers = self.all_peer_addresses.lock().unwrap();
            if !all_peers.contains_key(&peer_addr) {
                all_peers.insert(
                    peer_addr,
                    format!("Peer_{}", format_peer_id(&from_peer_id.0)),
                );
            }
        }

        // Send hole punch response to establish bidirectional flow
        let response_packet = self.create_punch_response(sequence);
        if let Err(e) = self.socket.send_to(&response_packet, peer_addr).await {
            warn!("Failed to send hole punch response to {}: {}", peer_addr, e);
        } else {
            debug!("Sent hole punch response {} to {}", sequence, peer_addr);

            // Mark connection as successful if this is part of our NAT traversal attempt
            let connections = self.peer_connections.lock().unwrap();
            if connections
                .values()
                .any(|conn| conn.peer_id == from_peer_id)
            {
                print_status(
                    symbols::CHECK,
                    &format!(
                        "NAT traversal successful with {} at {}",
                        format_peer_id(&from_peer_id.0),
                        format_address_with_words(&peer_addr)
                    ),
                    colors::GREEN,
                );

                // Update stats
                let mut stats = self.stats.lock().unwrap();
                stats.successful_connections += 1;
            }
        }
    }

    /// Create a hole punch response packet
    fn create_punch_response(&self, sequence: u32) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x10); // Hole punch message type (same as request)
        packet.extend_from_slice(&self.peer_id.0);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet
    }

    /// Handle incoming chat message
    async fn handle_chat_message(&self, data: &[u8], peer_addr: SocketAddr) {
        info!(
            "Received potential chat message from {} with {} bytes",
            peer_addr,
            data.len()
        );
        if data.len() < 42 {
            // 1 + 32 + 8 + 1 = minimum size
            debug!("Chat message too short from {}", peer_addr);
            return;
        }

        // Parse message: [type(1)] [from_peer_id(32)] [message_id(8)] [nickname_len(1)] [nickname] [content_len(2)] [content]
        let from_peer_id = PeerId({
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[1..33]);
            bytes
        });

        let message_id = u64::from_be_bytes({
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[33..41]);
            bytes
        });

        let nickname_len = data[41] as usize;
        if data.len() < 44 + nickname_len {
            debug!("Chat message malformed (nickname) from {}", peer_addr);
            return;
        }

        let from_nickname = String::from_utf8_lossy(&data[42..42 + nickname_len]).to_string();

        let content_len_start = 42 + nickname_len;
        if data.len() < content_len_start + 2 {
            debug!("Chat message malformed (content length) from {}", peer_addr);
            return;
        }

        let content_len =
            u16::from_be_bytes([data[content_len_start], data[content_len_start + 1]]) as usize;

        let content_start = content_len_start + 2;
        if data.len() < content_start + content_len {
            debug!("Chat message malformed (content) from {}", peer_addr);
            return;
        }

        let content =
            String::from_utf8_lossy(&data[content_start..content_start + content_len]).to_string();

        // Create chat message
        let chat_message = ChatMessage {
            message_id,
            from_peer_id,
            from_nickname: from_nickname.clone(),
            to_peer_id: None, // TODO: parse target peer ID for direct messages
            to_nickname: None,
            content: content.clone(),
            timestamp: Instant::now(),
            is_broadcast: true, // TODO: determine if broadcast or direct
        };

        // Add to message history
        {
            let mut chat_state = self.chat_state.lock().unwrap();
            chat_state.message_history.push(chat_message.clone());

            // Update connected peers list
            chat_state
                .connected_peers
                .insert(from_peer_id, from_nickname.clone());
        }

        // Track this peer's address for future messages
        {
            let mut all_peers = self.all_peer_addresses.lock().unwrap();
            all_peers.insert(peer_addr, from_nickname.clone());
        }

        // Display the message
        self.display_chat_message(&chat_message);

        info!(
            "Successfully processed chat from {}: {}",
            from_nickname, content
        );
    }

    /// Send a chat message
    #[allow(dead_code)] // Will be used when implementing full chat functionality
    async fn send_chat_message(&self, content: String, target_nickname: Option<String>) {
        debug!("Sending chat message: {} to {:?}", content, target_nickname);
        let (our_peer_id, our_nickname, message_id) = {
            let chat_state = self.chat_state.lock().unwrap();
            let message_id = chat_state.next_message_id;
            (self.peer_id, chat_state.our_nickname.clone(), message_id)
        };

        // Increment message ID
        {
            let mut chat_state = self.chat_state.lock().unwrap();
            chat_state.next_message_id += 1;
        }

        // Create chat message
        let chat_message = ChatMessage {
            message_id,
            from_peer_id: our_peer_id,
            from_nickname: our_nickname.clone(),
            to_peer_id: None, // TODO: resolve target peer ID from nickname
            to_nickname: target_nickname.clone(),
            content: content.clone(),
            timestamp: Instant::now(),
            is_broadcast: target_nickname.is_none(),
        };

        // Add to our own message history
        {
            let mut chat_state = self.chat_state.lock().unwrap();
            chat_state.message_history.push(chat_message.clone());
        }

        // Create packet: [type(1)] [from_peer_id(32)] [message_id(8)] [nickname_len(1)] [nickname] [content_len(2)] [content]
        let mut packet = Vec::new();
        packet.push(0x11); // Chat message type
        packet.extend_from_slice(&our_peer_id.0);
        packet.extend_from_slice(&message_id.to_be_bytes());
        packet.push(our_nickname.len() as u8);
        packet.extend_from_slice(our_nickname.as_bytes());
        packet.extend_from_slice(&(content.len() as u16).to_be_bytes());
        packet.extend_from_slice(content.as_bytes());

        // Send to all connected peers
        let all_peers = self.all_peer_addresses.lock().unwrap();

        let target_peers: Vec<(SocketAddr, String)> = if let Some(ref target_nick) = target_nickname
        {
            // Find specific peer by nickname
            all_peers
                .iter()
                .filter(|(_, nick)| *nick == target_nick)
                .map(|(addr, nick)| (*addr, nick.clone()))
                .collect()
        } else {
            // Broadcast to all peers
            all_peers
                .iter()
                .map(|(addr, nick)| (*addr, nick.clone()))
                .collect()
        };

        info!(
            "Sending chat to {} peers (target: {:?})",
            target_peers.len(),
            target_nickname
        );

        for (peer_addr, nickname) in target_peers {
            info!("Sending chat to {} at {}", nickname, peer_addr);
            if let Err(e) = self.socket.send_to(&packet, peer_addr).await {
                warn!(
                    "Failed to send chat message to {}: {}",
                    format_address_with_words(&peer_addr),
                    e
                );
            } else {
                info!("Successfully sent chat message to {}", peer_addr);
            }
        }

        // Display our own message
        self.display_chat_message(&chat_message);
    }

    /// Display a chat message in the terminal
    fn display_chat_message(&self, message: &ChatMessage) {
        let timestamp = terminal_ui::format_timestamp(message.timestamp);
        let prefix = if message.is_broadcast {
            format!(
                "[{}] {}{}:{}",
                timestamp,
                colors::CYAN,
                message.from_nickname,
                colors::RESET
            )
        } else {
            format!(
                "[{}] {}{} → {}{}:{}",
                timestamp,
                colors::CYAN,
                message.from_nickname,
                colors::MAGENTA,
                message
                    .to_nickname
                    .as_ref()
                    .unwrap_or(&"Unknown".to_string()),
                colors::RESET
            )
        };

        println!();
        println!("{} {}", prefix, message.content);
        print!("💬 Chat: ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }

    /// Start hole punching to target address
    async fn start_hole_punching(&self, target_addr: SocketAddr) {
        info!(
            "Starting hole punching to {}",
            format_address_with_words(&target_addr)
        );

        // Send multiple packets to try to open NAT hole
        for i in 0..5 {
            let punch_packet = self.create_punch_packet(i);
            if let Err(e) = self.socket.send_to(&punch_packet, target_addr).await {
                warn!(
                    "Hole punch {} to {} failed: {}",
                    i,
                    format_address_with_words(&target_addr),
                    e
                );
            } else {
                debug!(
                    "Sent hole punch {} to {}",
                    i,
                    format_address_with_words(&target_addr)
                );
            }

            // Brief delay between punches
            sleep(Duration::from_millis(100)).await;
        }

        // Show completion
        println!();
        print_status(
            symbols::CHECK,
            &format!(
                "NAT traversal attempt completed to {}",
                format_address_with_words(&target_addr)
            ),
            colors::GREEN,
        );
    }

    /// Create hole punch packet
    fn create_punch_packet(&self, sequence: u32) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x10); // Hole punch message type
        packet.extend_from_slice(&self.peer_id.0);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet
    }

    /// Connect to a specific peer
    #[allow(dead_code)] // Will be used when implementing peer connection commands
    pub async fn connect_to_peer(&self, target_peer_id: PeerId) {
        info!("Attempting to connect to peer {:?}", target_peer_id);

        // Add to peer connections
        {
            let mut connections = self.peer_connections.lock().unwrap();
            connections.insert(
                target_peer_id,
                PeerConnection {
                    peer_id: target_peer_id,
                    known_addresses: Vec::new(),
                    state: ConnectionState::DirectAttempt,
                    started_at: Instant::now(),
                    last_activity: Instant::now(),
                    attempt_count: 1,
                },
            );
        }

        // Request coordination through bootstrap nodes
        self.request_coordination(target_peer_id).await;

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.active_connections = self.peer_connections.lock().unwrap().len();
        }
    }

    /// Request coordination through bootstrap nodes
    #[allow(dead_code)] // Will be used when implementing NAT traversal coordination
    async fn request_coordination(&self, target_peer_id: PeerId) {
        let bootstrap_nodes = self.bootstrap_nodes.lock().unwrap().clone();

        for bootstrap_addr in &bootstrap_nodes {
            let request_packet = self.create_coordination_request_packet(target_peer_id);
            if let Err(e) = self.socket.send_to(&request_packet, *bootstrap_addr).await {
                warn!(
                    "Failed to request coordination from {}: {}",
                    bootstrap_addr, e
                );
            } else {
                info!(
                    "Requested coordination from {} for peer {:?}",
                    bootstrap_addr, target_peer_id
                );
            }
        }
    }

    /// Create coordination request packet
    #[allow(dead_code)] // Will be used when implementing NAT traversal coordination
    fn create_coordination_request_packet(&self, target_peer_id: PeerId) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x03); // Coordination request
        packet.extend_from_slice(&self.peer_id.0);
        packet.extend_from_slice(&target_peer_id.0);
        packet
    }

    /// Send various response packets (coordinator role methods)
    async fn send_registration_ack(&self, peer_id: PeerId, peer_addr: SocketAddr) {
        let mut response = Vec::new();
        response.push(0x81); // Registration ACK
        response.extend_from_slice(&peer_id.0);

        // Add server reflexive address
        match peer_addr {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                response.extend_from_slice(&[0u8; 6]);
            }
        }

        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send registration ACK to {}: {}", peer_addr, e);
        }
    }

    async fn send_candidate_discovery_response(&self, peer_id: PeerId, peer_addr: SocketAddr) {
        let mut response = Vec::new();
        response.push(0x82); // Candidate discovery response
        response.extend_from_slice(&peer_id.0);
        response.push(1); // Number of candidates

        // Add server reflexive candidate
        match peer_addr {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
                response.extend_from_slice(&100u32.to_be_bytes()); // Priority
            }
            SocketAddr::V6(_) => {
                response[33] = 0; // No candidates for IPv6 in this simple implementation
            }
        }

        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!(
                "Failed to send candidate discovery response to {}: {}",
                peer_addr, e
            );
        }
    }

    async fn send_coordination_error(&self, peer_id: PeerId, peer_addr: SocketAddr, error: &str) {
        let mut response = Vec::new();
        response.push(0x84); // Coordination error
        response.extend_from_slice(&peer_id.0);

        let error_bytes = error.as_bytes();
        response.push(error_bytes.len().min(255) as u8);
        response.extend_from_slice(&error_bytes[..error_bytes.len().min(255)]);

        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send coordination error to {}: {}", peer_addr, e);
        }
    }

    /// Send punch notification to a peer (coordinator role)
    async fn send_punch_notification(
        &self,
        to_peer_id: PeerId,
        to_peer_addr: SocketAddr,
        other_peer_id: PeerId,
        other_peer_addr: SocketAddr,
        round: u32,
    ) {
        let mut packet = Vec::new();
        packet.push(0x12); // Punch notification
        packet.extend_from_slice(&to_peer_id.0);
        packet.extend_from_slice(&other_peer_id.0);

        // Add other peer's address
        match other_peer_addr {
            SocketAddr::V4(addr) => {
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                // Simple IPv4-only implementation for now
                packet.extend_from_slice(&[0u8; 6]);
            }
        }

        // Add round number for coordination
        packet.extend_from_slice(&round.to_be_bytes());

        if let Err(e) = self.socket.send_to(&packet, to_peer_addr).await {
            warn!(
                "Failed to send punch notification to {}: {}",
                to_peer_addr, e
            );
        } else {
            info!(
                "Sent punch notification to {} about {} (round {})",
                format_address_with_words(&to_peer_addr),
                format_address_with_words(&other_peer_addr),
                round
            );
        }
    }

    /// Handle punch notification from coordinator (client role)
    async fn handle_punch_notification(&self, data: &[u8], coordinator_addr: SocketAddr) {
        if data.len() < 73 {
            // 1 + 32 + 32 + 4 + 2 + 4 = minimum size
            debug!("Punch notification too short from {}", coordinator_addr);
            return;
        }

        // Parse: [type(1)] [to_peer_id(32)] [other_peer_id(32)] [ip(4)] [port(2)] [round(4)]
        let other_peer_id = PeerId({
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[33..65]);
            bytes
        });

        let ip_bytes: [u8; 4] = data[65..69].try_into().unwrap();
        let port_bytes: [u8; 2] = data[69..71].try_into().unwrap();
        let port = u16::from_be_bytes(port_bytes);
        let target_addr = SocketAddr::from((ip_bytes, port));

        let round = u32::from_be_bytes({
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[71..75]);
            bytes
        });

        info!(
            "Received punch notification from coordinator: punch to {} at {} (round {})",
            format_peer_id(&other_peer_id.0),
            format_address_with_words(&target_addr),
            round
        );

        // Show coordination with four-word address
        println!();
        print_status(
            symbols::ROCKET,
            &format!(
                "Coordinated NAT traversal to peer {} at {} (round {})",
                format_peer_id(&other_peer_id.0),
                format_address_with_words(&target_addr),
                round
            ),
            colors::CYAN,
        );

        // Start synchronized hole punching
        self.start_synchronized_hole_punching(target_addr, round)
            .await;
    }

    /// Start synchronized hole punching with coordination round
    async fn start_synchronized_hole_punching(&self, target_addr: SocketAddr, round: u32) {
        info!(
            "Starting synchronized hole punching to {} (round {})",
            format_address_with_words(&target_addr),
            round
        );

        // Brief delay to ensure both peers are ready
        sleep(Duration::from_millis(100)).await;

        // Send multiple packets rapidly to maximize success chance
        for i in 0..10 {
            let punch_packet = self.create_punch_packet_with_round(i, round);
            if let Err(e) = self.socket.send_to(&punch_packet, target_addr).await {
                warn!(
                    "Hole punch {} to {} failed: {}",
                    i,
                    format_address_with_words(&target_addr),
                    e
                );
            } else {
                debug!(
                    "Sent synchronized hole punch {} to {} (round {})",
                    i, target_addr, round
                );
            }

            // Very brief delay between punches
            sleep(Duration::from_millis(20)).await;
        }

        // Show completion
        println!();
        print_status(
            symbols::CHECK,
            &format!(
                "Synchronized NAT traversal completed to {} (round {})",
                format_address_with_words(&target_addr),
                round
            ),
            colors::GREEN,
        );

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.nat_traversal_attempts += 1;
        }
    }

    /// Create hole punch packet with round number
    fn create_punch_packet_with_round(&self, sequence: u32, round: u32) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x10); // Hole punch message type
        packet.extend_from_slice(&self.peer_id.0);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&round.to_be_bytes());
        packet
    }

    /// Process various timeouts
    async fn process_timeouts(&self) {
        let now = Instant::now();

        // Process connection timeouts
        {
            let mut connections = self.peer_connections.lock().unwrap();
            let timed_out: Vec<_> = connections
                .iter()
                .filter(|(_, conn)| {
                    now.duration_since(conn.started_at) > self.config.connection_timeout
                })
                .map(|(peer_id, _)| *peer_id)
                .collect();

            for peer_id in timed_out {
                connections.remove(&peer_id);
                warn!("Connection to {:?} timed out", peer_id);

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.failed_connections += 1;
                    stats.active_connections = connections.len();
                }
            }
        }

        // Process coordination session timeouts
        {
            let mut sessions = self.coordination_sessions.lock().unwrap();
            let timed_out: Vec<_> = sessions
                .iter()
                .filter(|(_, session)| now.duration_since(session.started_at) > session.timeout)
                .map(|(key, _)| *key)
                .collect();

            for key in timed_out {
                sessions.remove(&key);
                debug!("Coordination session {:?} timed out", key);
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.active_coordination_sessions = sessions.len();
            }
        }
    }

    /// Start periodic tasks
    fn start_stats_task(&self) -> tokio::task::JoinHandle<()> {
        let stats = Arc::clone(&self.stats);
        let interval_duration = self.config.stats_interval;

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                let stats_snapshot = {
                    let mut stats = stats.lock().unwrap();
                    stats.uptime = stats.start_time.elapsed();
                    stats.clone()
                };

                // Only log detailed stats in debug mode
                debug!(
                    "Node statistics - Role: {:?}, Connections: {}, Uptime: {:?}",
                    stats_snapshot.current_role,
                    stats_snapshot.active_connections,
                    stats_snapshot.uptime
                );
            }
        })
    }

    fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let served_peers = Arc::clone(&self.served_peers);
        let stats: Arc<Mutex<NodeStats>> = Arc::clone(&self.stats);
        let timeout = self.config.client_timeout;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let now = Instant::now();
                let stale_peers: Vec<_> = {
                    let peers = served_peers.lock().unwrap();
                    peers
                        .iter()
                        .filter(|(_, peer)| now.duration_since(peer.last_seen) > timeout)
                        .map(|(peer_id, _)| *peer_id)
                        .collect()
                };

                if !stale_peers.is_empty() {
                    debug!("Cleaning up {} stale served peers", stale_peers.len());

                    let mut peers = served_peers.lock().unwrap();
                    for peer_id in stale_peers {
                        peers.remove(&peer_id);
                    }

                    // Update stats
                    {
                        let mut stats = stats.lock().unwrap();
                        stats.served_clients = peers.len();
                    }
                }
            }
        })
    }

    fn start_connection_manager_task(&self) -> tokio::task::JoinHandle<()> {
        let peer_connections: Arc<Mutex<HashMap<PeerId, PeerConnection>>> =
            Arc::clone(&self.peer_connections);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Process connection state transitions
                let connections = peer_connections.lock().unwrap();
                for (peer_id, connection) in connections.iter() {
                    match connection.state {
                        ConnectionState::DirectAttempt => {
                            // Try direct connection first
                            debug!("Processing direct attempt for {:?}", peer_id);
                        }
                        ConnectionState::CandidateDiscovery => {
                            // Discover candidates
                            debug!("Processing candidate discovery for {:?}", peer_id);
                        }
                        ConnectionState::Coordination => {
                            // Coordinate with bootstrap
                            debug!("Processing coordination for {:?}", peer_id);
                        }
                        ConnectionState::HolePunching => {
                            // Perform hole punching
                            debug!("Processing hole punching for {:?}", peer_id);
                        }
                        _ => {}
                    }
                }
            }
        })
    }

    /// Get current node statistics
    #[allow(dead_code)] // Will be used when implementing status commands
    pub fn get_stats(&self) -> NodeStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Send a chat message using standalone components (for main function)
async fn send_chat_message_standalone(
    content: String,
    target_nickname: Option<String>,
    our_peer_id: PeerId,
    chat_state: &Arc<Mutex<ChatState>>,
    served_peers: &Arc<Mutex<HashMap<PeerId, ServedPeer>>>,
    local_addr: SocketAddr,
) {
    let (our_nickname, message_id) = {
        let mut chat_state = chat_state.lock().unwrap();
        let message_id = chat_state.next_message_id;
        chat_state.next_message_id += 1;
        (chat_state.our_nickname.clone(), message_id)
    };

    // Create chat message
    let chat_message = ChatMessage {
        message_id,
        from_peer_id: our_peer_id,
        from_nickname: our_nickname.clone(),
        to_peer_id: None, // TODO: resolve target peer ID from nickname
        to_nickname: target_nickname.clone(),
        content: content.clone(),
        timestamp: Instant::now(),
        is_broadcast: target_nickname.is_none(),
    };

    // Add to our own message history
    {
        let mut chat_state = chat_state.lock().unwrap();
        chat_state.message_history.push(chat_message.clone());
    }

    // Create packet: [type(1)] [from_peer_id(32)] [message_id(8)] [nickname_len(1)] [nickname] [content_len(2)] [content]
    let mut packet = Vec::new();
    packet.push(0x11); // Chat message type
    packet.extend_from_slice(&our_peer_id.0);
    packet.extend_from_slice(&message_id.to_be_bytes());
    packet.push(our_nickname.len() as u8);
    packet.extend_from_slice(our_nickname.as_bytes());
    packet.extend_from_slice(&(content.len() as u16).to_be_bytes());
    packet.extend_from_slice(content.as_bytes());

    // Send to all connected peers (broadcast) or specific peer
    let peers: Vec<SocketAddr> = {
        let served_peers = served_peers.lock().unwrap();
        if target_nickname.is_some() {
            // Find specific peer by nickname
            served_peers
                .values()
                .filter(|peer| Some(&peer.nickname) == target_nickname.as_ref())
                .map(|peer| peer.observed_address)
                .collect()
        } else {
            // Broadcast to all peers
            served_peers
                .values()
                .map(|peer| peer.observed_address)
                .collect()
        }
    };

    // Create a temporary socket for sending chat messages
    // Use port 0 to let OS assign an available port
    let send_addr = SocketAddr::new(local_addr.ip(), 0);
    if let Ok(socket) = UdpSocket::bind(send_addr).await {
        for peer_addr in peers {
            if let Err(e) = socket.send_to(&packet, peer_addr).await {
                warn!(
                    "Failed to send chat message to {}: {}",
                    format_address_with_words(&peer_addr),
                    e
                );
            }
        }
    } else {
        warn!("Failed to create socket for sending chat message");
    }

    // Display our own message
    display_chat_message_standalone(&chat_message);
}

/// Display a chat message in the terminal (standalone version)
fn display_chat_message_standalone(message: &ChatMessage) {
    let timestamp = terminal_ui::format_timestamp(message.timestamp);
    let prefix = if message.is_broadcast {
        format!(
            "[{}] {}{}:{}",
            timestamp,
            colors::CYAN,
            message.from_nickname,
            colors::RESET
        )
    } else {
        format!(
            "[{}] {}{} → {}{}:{}",
            timestamp,
            colors::CYAN,
            message.from_nickname,
            colors::MAGENTA,
            message
                .to_nickname
                .as_ref()
                .unwrap_or(&"Unknown".to_string()),
            colors::RESET
        )
    };

    println!();
    println!("{} {}", prefix, message.content);
    print!("💬 Chat: ");
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
}

/// Parse peer ID from hex string
fn parse_peer_id(hex_str: &str) -> Result<PeerId, Box<dyn std::error::Error>> {
    if hex_str.len() != 64 {
        return Err("Peer ID must be 64 hex characters".into());
    }

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)?;
    }

    Ok(PeerId(bytes))
}

/// Verify that port allocation works as expected
fn verify_port_allocation(
    requested_addr: &SocketAddr,
    actual_addr: &SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if a random port was requested (port 0)
    if requested_addr.port() == 0 {
        // Ensure the OS actually allocated a port
        if actual_addr.port() == 0 {
            return Err("OS failed to allocate a port automatically".into());
        }

        // Check if the allocated port is in the ephemeral range (typically > 32768)
        let allocated_port = actual_addr.port();
        if allocated_port < 1024 {
            warn!(
                "Allocated port {} is in privileged range - this may indicate a problem",
                allocated_port
            );
        } else if allocated_port > 32768 {
            debug!("Successfully allocated ephemeral port {}", allocated_port);
        } else {
            // Port is in registered range (1024-32767), which is still fine but worth noting
            debug!("Allocated port {} is in registered range", allocated_port);
        }

        // Check for common predictable port patterns
        if is_predictable_port(allocated_port) {
            warn!(
                "Allocated port {} follows a predictable pattern - consider explicit port configuration",
                allocated_port
            );
        }
    } else {
        // Specific port was requested - verify it was honored
        if requested_addr.port() != actual_addr.port() {
            return Err(format!(
                "Requested port {} but got port {}",
                requested_addr.port(),
                actual_addr.port()
            )
            .into());
        }

        // Check if it's a commonly used/guessable port
        if is_common_port(requested_addr.port()) {
            warn!(
                "Using commonly known port {} - consider using a random port for better security",
                requested_addr.port()
            );
        }
    }

    Ok(())
}

/// Check if a port follows predictable patterns
fn is_predictable_port(port: u16) -> bool {
    // Check for some common predictable patterns
    match port {
        // Sequential patterns
        p if p % 1000 == 0 => true, // Round thousands
        p if p % 100 == 0 => true,  // Round hundreds
        p if p
            .to_string()
            .chars()
            .all(|c| c == p.to_string().chars().next().unwrap()) =>
        {
            true
        } // Repeating digits
        // Common dev ports
        3000..=3999 | 8000..=8999 | 9000..=9999 => true,
        _ => false,
    }
}

/// Check if a port is commonly known/used
fn is_common_port(port: u16) -> bool {
    matches!(
        port,
        22 | 23 | 25 | 53 | 80 | 110 | 143 | 443 | 993 | 995 |  // Common protocols
        1080 | 3128 | 8080 | 8443 | 8888 |                     // Common proxy ports
        3000 | 3001 | 4000 | 5000 | 8000 | 8001 | 9000 | 9001 // Common dev ports
    )
}

/// Parse a single address that could be either IP:port or four-word format
fn parse_single_address(addr_str: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr_str = addr_str.trim();

    // First try to parse as normal IP:port
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // If that fails, return error (four-word address support disabled)
    Err(format!(
        "Invalid address format '{}'. Expected IP:port format.",
        addr_str
    )
    .into())
}

/// Parse bootstrap addresses from comma-separated string (supports both IP:port and four-word formats)
fn parse_bootstrap_addresses(
    bootstrap_str: &str,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    bootstrap_str
        .split(',')
        .map(parse_single_address)
        .collect::<Result<Vec<_>, _>>()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging with custom formatter
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ant_quic={}", log_level))
        .with_ansi(true)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact()
        .init();

    // Print startup banner
    print_banner(env!("CARGO_PKG_VERSION"));

    // Parse bootstrap nodes
    let bootstrap_addresses = if let Some(bootstrap_str) = &args.bootstrap {
        parse_bootstrap_addresses(bootstrap_str)?
    } else {
        Vec::new()
    };

    // Create node configuration
    let config = NodeConfig {
        enable_coordinator: true,
        force_coordinator: args.force_coordinator,
        reachability_timeout: Duration::from_secs(args.reachability_timeout),
        stats_interval: Duration::from_secs(args.stats_interval),
        ..Default::default()
    };

    // Create and start the unified node
    let mut progress = ProgressIndicator::new("Initializing node...".to_string());
    progress.tick();

    let node = UnifiedP2PNode::new(args.listen, config).await?;
    let node_peer_id = node.peer_id;
    let actual_addr = node.local_addr;

    progress.finish_success("");

    // Display node information
    println!();
    print_section(
        &format!("Node ID: {}", symbols::KEY),
        &format_peer_id(&node_peer_id.0),
    );

    // Display port allocation information
    display_port_allocation_info(&args.listen, &actual_addr);
    println!();

    // Display network interfaces
    print_section(symbols::NETWORK, "Network Interfaces:");
    display_network_interfaces(actual_addr, &bootstrap_addresses).await;
    println!();

    // Determine and display mode
    if bootstrap_addresses.is_empty() {
        print_section(symbols::GLOBE, "Mode: Bootstrap Coordinator");
        print_status(
            symbols::INFO,
            "No peers specified - running as bootstrap coordinator",
            colors::BLUE,
        );
        print_status(
            symbols::CHECK,
            &format!("Ready to accept connections on port {}", actual_addr.port()),
            colors::GREEN,
        );
    } else {
        print_section(symbols::GLOBE, "Mode: P2P Client");
        print_status(
            symbols::INFO,
            &format!(
                "Connecting to {} bootstrap node(s)",
                bootstrap_addresses.len()
            ),
            colors::BLUE,
        );
    }
    println!();

    // If connect argument provided, initiate connection after startup
    let connect_peer = if let Some(connect_str) = &args.connect {
        Some(parse_peer_id(connect_str)?)
    } else {
        None
    };

    // Get our nickname for chat display
    let our_nickname = {
        let chat_state = node.chat_state.lock().unwrap();
        chat_state.our_nickname.clone()
    };

    // Extract shared state before moving node
    let node_stats = Arc::clone(&node.stats);
    let chat_state_for_input = Arc::clone(&node.chat_state);
    let served_peers_for_chat = Arc::clone(&node.served_peers);
    let local_addr_for_chat = node.local_addr;
    let peer_id_for_chat = node.peer_id;

    let bootstrap_addrs_clone = bootstrap_addresses.clone();

    // Start the node in a separate task
    let mut node_for_start = node;
    let node_handle = tokio::spawn(async move {
        if let Err(e) = node_for_start.start(bootstrap_addrs_clone).await {
            error!("Node failed: {}", e);
        }
    });

    // If we have bootstrap nodes, show connection progress
    if !bootstrap_addresses.is_empty() {
        sleep(Duration::from_millis(100)).await;
        println!("{} Connecting to bootstrap network...", symbols::NETWORK);
        for addr in &bootstrap_addresses {
            print_item(
                &format!(
                    "{} ... {}",
                    format_address_with_words(addr),
                    symbols::CIRCULAR_ARROWS
                ),
                2,
            );
        }
        println!();
    }

    // Brief delay to let node start up
    sleep(Duration::from_secs(1)).await;

    // If connect peer specified, initiate connection
    if let Some(target_peer_id) = connect_peer {
        print_status(
            symbols::CIRCULAR_ARROWS,
            &format!(
                "Initiating connection to peer {}",
                format_peer_id(&target_peer_id.0)
            ),
            colors::BLUE,
        );
    }

    // Show waiting status and chat instructions
    if bootstrap_addresses.is_empty() {
        print_status(
            symbols::HOURGLASS,
            "Waiting for peers to connect...",
            colors::DIM,
        );
    } else {
        print_status(symbols::CHECK, "Ready for P2P connections", colors::GREEN);
    }
    println!();

    // Show chat instructions
    print_section("💬", "Chat Interface:");
    print_item(
        &format!(
            "Your nickname: {}{}{}",
            colors::CYAN,
            our_nickname,
            colors::RESET
        ),
        2,
    );
    print_item("Type a message to broadcast to all peers", 2);
    print_item("Type '@nickname message' to send to specific peer", 2);
    print_item("Type '/list' to see connected peers", 2);
    print_item("Type '/quit' or Ctrl+C to exit", 2);
    println!();

    // Create a task for live status updates
    let stats_clone = Arc::clone(&node_stats);
    let status_task = tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(30)); // Less frequent to not interfere with chat
        loop {
            interval.tick().await;
            update_status_line(&stats_clone);
        }
    });

    // Chat input handling
    println!("💬 Chat: ");
    let input_handle = tokio::spawn(async move {
        let stdin = io::stdin();
        loop {
            let mut input = String::new();
            match stdin.read_line(&mut input) {
                Ok(_) => {
                    let input = input.trim();

                    if input.is_empty() {
                        print!("💬 Chat: ");
                        continue;
                    }

                    if input == "/quit" {
                        break;
                    }

                    if input == "/list" {
                        let chat_state = chat_state_for_input.lock().unwrap();
                        println!();
                        if chat_state.connected_peers.is_empty() {
                            println!("No peers connected yet.");
                        } else {
                            println!("Connected peers:");
                            for (peer_id, nickname) in &chat_state.connected_peers {
                                println!(
                                    "  {} {}{}{} ({})",
                                    symbols::DOT,
                                    colors::CYAN,
                                    nickname,
                                    colors::RESET,
                                    format_peer_id(&peer_id.0)
                                );
                            }
                        }
                        print!("💬 Chat: ");
                        continue;
                    }

                    // Parse message
                    if input.starts_with('@') {
                        // Direct message
                        if let Some(space_pos) = input.find(' ') {
                            let target_nickname = input[1..space_pos].to_string();
                            let message = input[space_pos + 1..].to_string();

                            if !message.is_empty() {
                                send_chat_message_standalone(
                                    message,
                                    Some(target_nickname),
                                    peer_id_for_chat,
                                    &chat_state_for_input,
                                    &served_peers_for_chat,
                                    local_addr_for_chat,
                                )
                                .await;
                            }
                        } else {
                            println!("Usage: @nickname message");
                        }
                    } else {
                        // Broadcast message
                        send_chat_message_standalone(
                            input.to_string(),
                            None,
                            peer_id_for_chat,
                            &chat_state_for_input,
                            &served_peers_for_chat,
                            local_addr_for_chat,
                        )
                        .await;
                    }

                    print!("💬 Chat: ");
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();
                }
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either input handler to finish or Ctrl+C
    tokio::select! {
        _ = input_handle => {},
        _ = tokio::signal::ctrl_c() => {
            println!();
            print_status(symbols::INFO, "Received Ctrl+C, shutting down...", colors::YELLOW);
        }
    }

    // Cleanup
    println!();
    print_status(symbols::INFO, "Shutting down...", colors::YELLOW);

    status_task.abort();
    node_handle.abort();

    // Print final statistics
    let final_stats = node_stats.lock().unwrap().clone();
    println!();
    print_section("📊", "Final Statistics:");
    print_item(
        &format!(
            "Uptime: {}",
            terminal_ui::format_duration(final_stats.uptime)
        ),
        2,
    );
    print_item(&format!("Role: {:?}", final_stats.current_role), 2);
    print_item(
        &format!(
            "Connections: {} successful, {} failed",
            final_stats.successful_connections, final_stats.failed_connections
        ),
        2,
    );

    if matches!(
        final_stats.current_role,
        NodeRole::Coordinator | NodeRole::Hybrid
    ) {
        print_item(
            &format!("Clients served: {}", final_stats.served_clients),
            2,
        );
        print_item(
            &format!(
                "Discovery requests: {}",
                final_stats.discovery_requests_handled
            ),
            2,
        );
    }

    Ok(())
}

/// Check if server reflexive discovery is expected based on node configuration
async fn should_show_external_discovery_info(bootstrap_addresses: &[SocketAddr]) -> bool {
    // External IP discovery happens via server reflexive discovery when connecting to bootstrap nodes
    !bootstrap_addresses.is_empty()
}

/// Display port allocation information
fn display_port_allocation_info(requested_addr: &SocketAddr, actual_addr: &SocketAddr) {
    println!();
    print_section("🔌", "Port Allocation:");

    if requested_addr.port() == 0 {
        // Random port was requested
        let allocated_port = actual_addr.port();
        print_item(&format!("Requested: {} (random port)", requested_addr), 2);
        print_item(
            &format!("Allocated: {} (port {})", actual_addr, allocated_port),
            2,
        );

        // Provide security assessment
        if allocated_port > 32768 {
            print_status(
                symbols::CHECK,
                &format!("Port {} is in ephemeral range (secure)", allocated_port),
                colors::GREEN,
            );
        } else if allocated_port > 1024 {
            print_status(
                symbols::INFO,
                &format!("Port {} is in registered range", allocated_port),
                colors::BLUE,
            );
        } else {
            print_status(
                symbols::WARNING,
                &format!("Port {} is in privileged range", allocated_port),
                colors::YELLOW,
            );
        }

        // Check for predictable patterns
        if is_predictable_port(allocated_port) {
            print_status(
                symbols::WARNING,
                "Port follows a predictable pattern",
                colors::YELLOW,
            );
        } else {
            print_status(
                symbols::CHECK,
                "Port allocation appears random",
                colors::GREEN,
            );
        }
    } else {
        // Specific port was requested
        print_item(&format!("Requested: {} (explicit)", requested_addr), 2);
        print_item(&format!("Bound to: {}", actual_addr), 2);

        if is_common_port(requested_addr.port()) {
            print_status(
                symbols::WARNING,
                "Using a commonly known port",
                colors::YELLOW,
            );
            print_status(
                symbols::INFO,
                "Consider using a random port (--listen 0.0.0.0:0) for better security",
                colors::BLUE,
            );
        } else {
            print_status(symbols::CHECK, "Using a non-standard port", colors::GREEN);
        }
    }
}

/// Display network interfaces with categorization
async fn display_network_interfaces(bound_addr: SocketAddr, bootstrap_addresses: &[SocketAddr]) {
    // Add a message about four-word addresses
    println!();
    print_section("🗣️", "Human-Readable Four-Word Network Addresses");
    print_item(
        "We use memorable four-word addresses that are easy to share",
        2,
    );
    print_item(
        "Tell your friends these words instead of hard-to-remember numbers!",
        2,
    );
    println!();

    // Show information about server reflexive discovery
    if should_show_external_discovery_info(bootstrap_addresses).await {
        print_item("External Address Discovery:", 2);
        print_item(
            "External address will be discovered via server reflexive discovery",
            4,
        );
        print_item(
            "when connecting to bootstrap nodes (per QUIC NAT traversal spec)",
            4,
        );
        println!();
    } else {
        print_item("External Address Discovery:", 2);
        print_item(
            "Running as coordinator - no bootstrap nodes for external discovery",
            4,
        );
        print_item(
            "External addresses will be discovered when peers connect to us",
            4,
        );
        println!();
    }

    print_item("Local Addresses:", 2);

    // Show the actual bound address
    let bound_desc = if bound_addr.ip().is_unspecified() {
        format!(
            "{} {} bound to all interfaces",
            format_address(&bound_addr),
            symbols::ARROW_RIGHT
        )
    } else {
        format_address_with_words(&bound_addr)
    };
    print_item(&bound_desc, 4);

    // Discover local network interfaces using the proper network discovery
    let local_addresses = discover_local_addresses_proper(bound_addr.port());
    if !local_addresses.is_empty() {
        let mut displayed_v4 = std::collections::HashSet::new();
        let mut displayed_v6 = std::collections::HashSet::new();
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        // Separate IPv4 and IPv6 addresses
        for addr in local_addresses {
            if !addr.ip().is_unspecified() {
                match addr.ip() {
                    IpAddr::V4(_) => {
                        if displayed_v4.insert(addr.to_string()) {
                            ipv4_addrs.push(addr);
                        }
                    }
                    IpAddr::V6(_) => {
                        if displayed_v6.insert(addr.to_string()) {
                            ipv6_addrs.push(addr);
                        }
                    }
                }
            }
        }

        // Display IPv4 addresses
        if !ipv4_addrs.is_empty() {
            for addr in ipv4_addrs {
                let desc = describe_address(&addr);
                print_item(
                    &format!("{} ({})", format_address_with_words(&addr), desc),
                    4,
                );
            }
        }

        // Display IPv6 addresses
        if !ipv6_addrs.is_empty() {
            for addr in ipv6_addrs {
                let desc = describe_address(&addr);
                print_item(
                    &format!("{} ({})", format_address_with_words(&addr), desc),
                    4,
                );
            }
        }
    } else {
        // Fallback if we can't discover interfaces
        if bound_addr.ip().is_unspecified() {
            let localhost_v4 = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                bound_addr.port(),
            );
            let localhost_v6 =
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), bound_addr.port());

            print_item(
                &format!(
                    "{} ({})",
                    format_address_with_words(&localhost_v4),
                    describe_address(&localhost_v4)
                ),
                4,
            );
            print_item(
                &format!(
                    "{} ({})",
                    format_address_with_words(&localhost_v6),
                    describe_address(&localhost_v6)
                ),
                4,
            );
        }
    }
}

/// Update the status line with current statistics
fn update_status_line(stats: &Arc<Mutex<NodeStats>>) {
    let stats = stats.lock().unwrap();
    let uptime = terminal_ui::format_duration(stats.uptime);

    // Clear current line and print status
    print!("\r\x1b[K"); // Clear line
    print!(
        "📊 Status: {} | Mode: {:?} | Peers: {} | Up: {}",
        format!("{}Active{}", colors::GREEN, colors::RESET),
        stats.current_role,
        stats.active_connections,
        uptime
    );

    use std::io::{self, Write};
    io::stdout().flush().unwrap();
}

/// Discover local addresses using the proper network interface discovery
fn discover_local_addresses_proper(port: u16) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    
    // Create a discovery manager with default config
    let discovery_config = DiscoveryConfig {
        total_timeout: Duration::from_secs(30),
        local_scan_timeout: Duration::from_secs(2),
        bootstrap_query_timeout: Duration::from_secs(5),
        max_query_retries: 3,
        max_candidates: 50,
        enable_symmetric_prediction: false,
        min_bootstrap_consensus: 2,
        interface_cache_ttl: Duration::from_secs(60),
        server_reflexive_cache_ttl: Duration::from_secs(300),
    };
    
    let mut discovery = CandidateDiscoveryManager::new(discovery_config);
    
    // Discover local interfaces
    info!("Starting local network interface discovery...");
    match discovery.discover_local_candidates() {
        Ok(candidates) => {
            info!("Raw candidates discovered: {}", candidates.len());
            for candidate in candidates {
                // Convert validated candidates to socket addresses with the correct port
                let mut addr = candidate.address;
                addr.set_port(port);
                addresses.push(addr);
                debug!("Found local address: {} (source: {:?})", addr, candidate.source);
            }
            
            info!("Discovered {} local addresses via proper interface enumeration", addresses.len());
        }
        Err(e) => {
            error!("Failed to discover local interfaces: {}", e);
        }
    }
    
    // If discovery failed, fall back to the lightweight method
    if addresses.is_empty() {
        warn!("Falling back to lightweight address discovery");
        addresses.extend(discover_local_addresses_lightweight(port));
    }
    
    addresses
}

/// Lightweight local address discovery fallback (when proper discovery fails)
fn discover_local_addresses_lightweight(port: u16) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();

    // Try IPv4 discovery
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Connect to a public IP (doesn't actually send data)
        let targets = [
            "8.8.8.8:80",        // Google DNS
            "1.1.1.1:80",        // Cloudflare DNS
            "208.67.222.222:80", // OpenDNS
        ];

        for target in &targets {
            if socket.connect(target).is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    addresses.push(SocketAddr::new(local_addr.ip(), port));
                    break; // One successful discovery is enough
                }
            }
        }
    }

    // Try IPv6 discovery
    if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
        let targets = [
            "[2001:4860:4860::8888]:80", // Google DNS IPv6
            "[2606:4700:4700::1111]:80", // Cloudflare DNS IPv6
        ];

        for target in &targets {
            if socket.connect(target).is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    addresses.push(SocketAddr::new(local_addr.ip(), port));
                    break;
                }
            }
        }
    }

    // Always include localhost as fallback
    if addresses.is_empty() {
        addresses.push(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
        addresses.push(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            port,
        ));
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unified_node_creation() {
        let config = NodeConfig::default();
        let node = UnifiedP2PNode::new("127.0.0.1:0".parse().unwrap(), config).await;
        assert!(node.is_ok());
    }

    #[test]
    fn test_parse_peer_id() {
        let hex_str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let peer_id = parse_peer_id(hex_str);
        assert!(peer_id.is_ok());

        let invalid_hex = "invalid";
        let invalid_peer_id = parse_peer_id(invalid_hex);
        assert!(invalid_peer_id.is_err());
    }

    #[test]
    fn test_parse_bootstrap_addresses() {
        let bootstrap_str = "127.0.0.1:9000,192.168.1.1:9001";
        let addresses = parse_bootstrap_addresses(bootstrap_str);
        assert!(addresses.is_ok());
        assert_eq!(addresses.unwrap().len(), 2);
    }

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert!(config.enable_coordinator);
        assert!(!config.force_coordinator);
        assert_eq!(config.reachability_timeout, Duration::from_secs(5));
    }
    
    #[test]
    fn test_discover_local_addresses() {
        let addresses = discover_local_addresses_proper(9000);
        println!("Discovered addresses: {:?}", addresses);
        assert!(!addresses.is_empty(), "Should discover at least one local address");
    }
}
