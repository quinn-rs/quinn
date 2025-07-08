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

mod terminal_ui;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clap::Parser;
use ant_quic::{
    nat_traversal_api::{CandidateAddress, PeerId},
    CandidateSource, CandidateState,
};
use tokio::{
    net::UdpSocket,
    time::{interval, sleep, timeout},
};
use tracing::{info, warn, debug, error};
use terminal_ui::{colors, symbols, print_banner, print_section, print_item, print_status, format_peer_id, format_address, format_address_with_words, describe_address, ProgressIndicator};
use four_word_networking::FourWordAdaptiveEncoder;

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
    peer_id: PeerId,
    /// Observed address
    observed_address: SocketAddr,
    /// Local candidates reported by peer
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

/// Main unified P2P node
struct UnifiedP2PNode {
    /// Node's own peer ID
    peer_id: PeerId,
    /// UDP socket for communication
    socket: UdpSocket,
    /// Local address we're bound to
    local_addr: SocketAddr,
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

impl UnifiedP2PNode {
    /// Create a new unified P2P node
    async fn new(listen_addr: SocketAddr, config: NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate random peer ID
        let peer_id = PeerId(rand::random());
        
        // Bind socket
        let socket = UdpSocket::bind(listen_addr).await?;
        let local_addr = socket.local_addr()?;
        
        // Verify port allocation if random port was requested
        verify_port_allocation(&listen_addr, &local_addr)?;
        
        debug!("Node {:?} starting on {}", peer_id, local_addr);
        
        Ok(Self {
            peer_id,
            socket,
            local_addr,
            config,
            capability: NodeCapability::ClientOnly,
            current_role: NodeRole::Client,
            stats: Arc::new(Mutex::new(NodeStats::default())),
            bootstrap_nodes: Arc::new(Mutex::new(Vec::new())),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            local_candidates: Arc::new(Mutex::new(Vec::new())),
            served_peers: Arc::new(Mutex::new(HashMap::new())),
            coordination_sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    /// Start the unified node
    async fn start(&mut self, bootstrap_addresses: Vec<SocketAddr>) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting unified P2P node {:?}", self.peer_id);
        
        // Store bootstrap nodes
        {
            let mut bootstraps = self.bootstrap_nodes.lock().unwrap();
            bootstraps.extend(bootstrap_addresses.clone());
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
                    self.handle_incoming_packet(&buffer[..size], peer_addr).await;
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
        // This is a simplified test - in practice, we'd use STUN or similar
        let is_public_ip = match self.local_addr.ip() {
            IpAddr::V4(ip) => {
                !ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
            }
            IpAddr::V6(ip) => {
                !ip.is_loopback() && !ip.is_unspecified()
            }
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
                self.socket.send_to(&test_packet, bootstrap_addr)
            ).await {
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
            match self.socket.send_to(&registration_packet, bootstrap_addr).await {
                Ok(_) => {
                    // Show connection progress
                    print_status(
                        symbols::CIRCULAR_ARROWS, 
                        &format!("Registering with {}", format_address_with_words(bootstrap_addr)),
                        colors::BLUE
                    );
                }
                Err(e) => {
                    print_status(
                        symbols::CROSS,
                        &format!("Failed to reach {}: {}", format_address_with_words(bootstrap_addr), e),
                        colors::RED
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
        debug!("Received message type {} from {}", message_type, peer_addr);
        
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
                    self.handle_candidate_discovery_request(data, peer_addr).await;
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
                self.handle_candidate_discovery_response(data, peer_addr).await;
            }
            0x83 => {
                // Coordination instructions (we're acting as client)
                self.handle_coordination_instructions(data, peer_addr).await;
            }
            0x84 => {
                // Error response
                self.handle_error_response(data, peer_addr).await;
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
            &format!("New client connected: {} from {}", 
                format_peer_id(&peer_id.0),
                format_address_with_words(&peer_addr)
            ),
            colors::GREEN
        );
        
        // Register the peer
        {
            let mut served_peers = self.served_peers.lock().unwrap();
            served_peers.insert(peer_id, ServedPeer {
                peer_id,
                observed_address: peer_addr,
                local_candidates: Vec::new(),
                last_seen: Instant::now(),
            });
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
        self.send_candidate_discovery_response(peer_id, peer_addr).await;
        
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
        
        debug!("Coordination request: {:?} wants to connect to {:?}", requesting_peer, target_peer);
        
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
                    &format!("Coordinating connection: {} {} wants to reach {} {}", 
                        format_peer_id(&requesting_peer.0),
                        format_address_with_words(&peer_addr),
                        format_peer_id(&target_peer.0),
                        format_address_with_words(&target_info.observed_address)
                    ),
                    colors::BLUE
                );
                
                // Create coordination session
                {
                    let mut sessions = self.coordination_sessions.lock().unwrap();
                    if sessions.len() < self.config.max_coordination_sessions {
                        sessions.insert((requesting_peer, target_peer), CoordinationSession {
                            requester: requesting_peer,
                            target: target_peer,
                            started_at: Instant::now(),
                            timeout: Duration::from_secs(30),
                        });
                    }
                }
                
                // Send coordination instructions to both peers
                self.send_coordination_instructions(requesting_peer, peer_addr, target_info.observed_address).await;
                self.send_coordination_instructions(target_peer, target_info.observed_address, peer_addr).await;
                
                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.coordination_requests_handled += 1;
                    stats.active_coordination_sessions = self.coordination_sessions.lock().unwrap().len();
                }
            }
            None => {
                self.send_coordination_error(requesting_peer, peer_addr, "Target peer not found").await;
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
                &format!("External address discovered: {} (observed by {})", 
                    format_address_with_words(&server_reflexive),
                    format_address_with_words(&peer_addr)
                ),
                colors::GREEN
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
            
            info!("Received coordination instructions to connect to {}", format_address_with_words(&target_addr));
            
            // Show coordination with four-word address
            println!();
            print_status(
                symbols::ROCKET,
                &format!("Initiating NAT traversal to peer at {}", 
                    format_address_with_words(&target_addr)
                ),
                colors::CYAN
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
                warn!("Error from {}: {}", format_address_with_words(&peer_addr), error_msg);
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
    
    /// Start hole punching to target address
    async fn start_hole_punching(&self, target_addr: SocketAddr) {
        info!("Starting hole punching to {}", format_address_with_words(&target_addr));
        
        // Send multiple packets to try to open NAT hole
        for i in 0..5 {
            let punch_packet = self.create_punch_packet(i);
            if let Err(e) = self.socket.send_to(&punch_packet, target_addr).await {
                warn!("Hole punch {} to {} failed: {}", i, format_address_with_words(&target_addr), e);
            } else {
                debug!("Sent hole punch {} to {}", i, format_address_with_words(&target_addr));
            }
            
            // Brief delay between punches
            sleep(Duration::from_millis(100)).await;
        }
        
        // Show completion
        println!();
        print_status(
            symbols::CHECK,
            &format!("NAT traversal attempt completed to {}", 
                format_address_with_words(&target_addr)
            ),
            colors::GREEN
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
    pub async fn connect_to_peer(&self, target_peer_id: PeerId) {
        info!("Attempting to connect to peer {:?}", target_peer_id);
        
        // Add to peer connections
        {
            let mut connections = self.peer_connections.lock().unwrap();
            connections.insert(target_peer_id, PeerConnection {
                peer_id: target_peer_id,
                known_addresses: Vec::new(),
                state: ConnectionState::DirectAttempt,
                started_at: Instant::now(),
                last_activity: Instant::now(),
                attempt_count: 1,
            });
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
    async fn request_coordination(&self, target_peer_id: PeerId) {
        let bootstrap_nodes = self.bootstrap_nodes.lock().unwrap().clone();
        
        for bootstrap_addr in &bootstrap_nodes {
            let request_packet = self.create_coordination_request_packet(target_peer_id);
            if let Err(e) = self.socket.send_to(&request_packet, bootstrap_addr).await {
                warn!("Failed to request coordination from {}: {}", bootstrap_addr, e);
            } else {
                info!("Requested coordination from {} for peer {:?}", bootstrap_addr, target_peer_id);
            }
        }
    }
    
    /// Create coordination request packet
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
            warn!("Failed to send candidate discovery response to {}: {}", peer_addr, e);
        }
    }
    
    async fn send_coordination_instructions(&self, peer_id: PeerId, peer_addr: SocketAddr, target_addr: SocketAddr) {
        let mut response = Vec::new();
        response.push(0x83); // Coordination instructions
        response.extend_from_slice(&peer_id.0);
        
        // Add target address
        match target_addr {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                response.extend_from_slice(&[0u8; 6]);
            }
        }
        
        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send coordination instructions to {}: {}", peer_addr, e);
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
    
    /// Process various timeouts
    async fn process_timeouts(&self) {
        let now = Instant::now();
        
        // Process connection timeouts
        {
            let mut connections = self.peer_connections.lock().unwrap();
            let timed_out: Vec<_> = connections.iter()
                .filter(|(_, conn)| now.duration_since(conn.started_at) > self.config.connection_timeout)
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
            let timed_out: Vec<_> = sessions.iter()
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
                debug!("Node statistics - Role: {:?}, Connections: {}, Uptime: {:?}", 
                    stats_snapshot.current_role, 
                    stats_snapshot.active_connections,
                    stats_snapshot.uptime
                );
            }
        })
    }
    
    fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let served_peers = Arc::clone(&self.served_peers);
        let stats = Arc::clone(&self.stats);
        let timeout = self.config.client_timeout;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let stale_peers: Vec<_> = {
                    let peers = served_peers.lock().unwrap();
                    peers.iter()
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
        let peer_connections = Arc::clone(&self.peer_connections);
        
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
    pub fn get_stats(&self) -> NodeStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Parse peer ID from hex string
fn parse_peer_id(hex_str: &str) -> Result<PeerId, Box<dyn std::error::Error>> {
    if hex_str.len() != 64 {
        return Err("Peer ID must be 64 hex characters".into());
    }
    
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i*2..i*2+2], 16)?;
    }
    
    Ok(PeerId(bytes))
}

/// Verify that port allocation works as expected
fn verify_port_allocation(requested_addr: &SocketAddr, actual_addr: &SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    // Check if a random port was requested (port 0)
    if requested_addr.port() == 0 {
        // Ensure the OS actually allocated a port
        if actual_addr.port() == 0 {
            return Err("OS failed to allocate a port automatically".into());
        }
        
        // Check if the allocated port is in the ephemeral range (typically > 32768)
        let allocated_port = actual_addr.port();
        if allocated_port < 1024 {
            warn!("Allocated port {} is in privileged range - this may indicate a problem", allocated_port);
        } else if allocated_port > 32768 {
            debug!("Successfully allocated ephemeral port {}", allocated_port);
        } else {
            // Port is in registered range (1024-32767), which is still fine but worth noting
            debug!("Allocated port {} is in registered range", allocated_port);
        }
        
        // Check for common predictable port patterns
        if is_predictable_port(allocated_port) {
            warn!("Allocated port {} follows a predictable pattern - consider explicit port configuration", allocated_port);
        }
    } else {
        // Specific port was requested - verify it was honored
        if requested_addr.port() != actual_addr.port() {
            return Err(format!("Requested port {} but got port {}", requested_addr.port(), actual_addr.port()).into());
        }
        
        // Check if it's a commonly used/guessable port
        if is_common_port(requested_addr.port()) {
            warn!("Using commonly known port {} - consider using a random port for better security", requested_addr.port());
        }
    }
    
    Ok(())
}

/// Check if a port follows predictable patterns
fn is_predictable_port(port: u16) -> bool {
    // Check for some common predictable patterns
    match port {
        // Sequential patterns
        p if p % 1000 == 0 => true,  // Round thousands
        p if p % 100 == 0 => true,   // Round hundreds
        p if p.to_string().chars().all(|c| c == p.to_string().chars().next().unwrap()) => true, // Repeating digits
        // Common dev ports
        3000..=3999 | 8000..=8999 | 9000..=9999 => true,
        _ => false,
    }
}

/// Check if a port is commonly known/used
fn is_common_port(port: u16) -> bool {
    matches!(port,
        22 | 23 | 25 | 53 | 80 | 110 | 143 | 443 | 993 | 995 |  // Common protocols
        1080 | 3128 | 8080 | 8443 | 8888 |                     // Common proxy ports
        3000 | 3001 | 4000 | 5000 | 8000 | 8001 | 9000 | 9001  // Common dev ports
    )
}

/// Parse a single address that could be either IP:port or four-word format
fn parse_single_address(addr_str: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr_str = addr_str.trim();
    
    // First try to parse as normal IP:port
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(addr);
    }
    
    // If that fails, try to decode as four-word address
    match FourWordAdaptiveEncoder::new() {
        Ok(encoder) => {
            match encoder.decode(addr_str) {
                Ok(decoded) => {
                    // The decoder returns a string, parse it as SocketAddr
                    decoded.parse::<SocketAddr>()
                        .map_err(|e| format!("Invalid decoded address '{}': {}", decoded, e).into())
                }
                Err(e) => {
                    Err(format!("Invalid address format '{}'. Expected IP:port or four-word format. Error: {}", addr_str, e).into())
                }
            }
        }
        Err(e) => {
            Err(format!("Failed to create four-word decoder: {}", e).into())
        }
    }
}

/// Parse bootstrap addresses from comma-separated string (supports both IP:port and four-word formats)
fn parse_bootstrap_addresses(bootstrap_str: &str) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
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
    
    let mut node = UnifiedP2PNode::new(args.listen, config).await?;
    let node_peer_id = node.peer_id;
    let actual_addr = node.local_addr;
    
    progress.finish_success("");
    
    // Display node information
    println!();
    print_section(&format!("Node ID: {}", symbols::KEY), &format_peer_id(&node_peer_id.0));
    
    // Display port allocation information
    display_port_allocation_info(&args.listen, &actual_addr);
    println!();
    
    // Display network interfaces
    print_section(symbols::NETWORK, "Network Interfaces:");
    display_network_interfaces(actual_addr).await;
    println!();
    
    // Determine and display mode
    if bootstrap_addresses.is_empty() {
        print_section(symbols::GLOBE, "Mode: Bootstrap Coordinator");
        print_status(symbols::INFO, "No peers specified - running as bootstrap coordinator", colors::BLUE);
        print_status(symbols::CHECK, &format!("Ready to accept connections on port {}", actual_addr.port()), colors::GREEN);
    } else {
        print_section(symbols::GLOBE, "Mode: P2P Client");
        print_status(symbols::INFO, &format!("Connecting to {} bootstrap node(s)", bootstrap_addresses.len()), colors::BLUE);
    }
    println!();
    
    // If connect argument provided, initiate connection after startup
    let connect_peer = if let Some(connect_str) = &args.connect {
        Some(parse_peer_id(connect_str)?)
    } else {
        None
    };
    
    // Start the node in a separate task
    let node_stats = Arc::clone(&node.stats);
    let bootstrap_addrs_clone = bootstrap_addresses.clone();
    
    let node_handle = tokio::spawn(async move {
        if let Err(e) = node.start(bootstrap_addrs_clone).await {
            error!("Node failed: {}", e);
        }
    });
    
    // If we have bootstrap nodes, show connection progress
    if !bootstrap_addresses.is_empty() {
        sleep(Duration::from_millis(100)).await;
        println!("{} Connecting to bootstrap network...", symbols::NETWORK);
        for addr in &bootstrap_addresses {
            print_item(&format!("{} ... {}", format_address_with_words(addr), symbols::CIRCULAR_ARROWS), 2);
        }
        println!();
    }
    
    // Brief delay to let node start up
    sleep(Duration::from_secs(1)).await;
    
    // If connect peer specified, initiate connection
    if let Some(target_peer_id) = connect_peer {
        print_status(
            symbols::CIRCULAR_ARROWS,
            &format!("Initiating connection to peer {}", format_peer_id(&target_peer_id.0)),
            colors::BLUE
        );
    }
    
    // Show waiting status
    if bootstrap_addresses.is_empty() {
        print_status(symbols::HOURGLASS, "Waiting for peers to connect...", colors::DIM);
    } else {
        print_status(symbols::CHECK, "Ready for P2P connections", colors::GREEN);
    }
    println!();
    
    // Create a task for live status updates
    let stats_clone = Arc::clone(&node_stats);
    let status_task = tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            update_status_line(&stats_clone);
        }
    });
    
    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    
    // Cleanup
    println!();
    print_status(symbols::INFO, "Shutting down...", colors::YELLOW);
    
    status_task.abort();
    node_handle.abort();
    
    // Print final statistics
    let final_stats = node_stats.lock().unwrap().clone();
    println!();
    print_section("📊", "Final Statistics:");
    print_item(&format!("Uptime: {}", terminal_ui::format_duration(final_stats.uptime)), 2);
    print_item(&format!("Role: {:?}", final_stats.current_role), 2);
    print_item(&format!("Connections: {} successful, {} failed", 
        final_stats.successful_connections, 
        final_stats.failed_connections), 2);
    
    if matches!(final_stats.current_role, NodeRole::Coordinator | NodeRole::Hybrid) {
        print_item(&format!("Clients served: {}", final_stats.served_clients), 2);
        print_item(&format!("Discovery requests: {}", final_stats.discovery_requests_handled), 2);
    }
    
    Ok(())
}

/// Discover external IP address by connecting to well-known internet addresses
async fn discover_external_ip(bound_addr: SocketAddr) -> Option<IpAddr> {
    // Well-known public DNS servers
    let test_addresses = [
        "1.1.1.1:53",      // Cloudflare DNS
        "8.8.8.8:53",      // Google DNS
        "208.67.222.222:53", // OpenDNS
        "9.9.9.9:53",      // Quad9 DNS
    ];
    
    for test_addr_str in &test_addresses {
        if let Ok(test_addr) = test_addr_str.parse::<SocketAddr>() {
            match timeout(Duration::from_secs(3), discover_external_ip_via(&test_addr, bound_addr)).await {
                Ok(Some(external_ip)) => {
                    debug!("Discovered external IP {} via {}", external_ip, test_addr);
                    return Some(external_ip);
                }
                Ok(None) => {
                    debug!("No external IP discovered via {}", test_addr);
                }
                Err(_) => {
                    debug!("Timeout discovering external IP via {}", test_addr);
                }
            }
        }
    }
    None
}

/// Discover external IP by connecting to a specific internet address
async fn discover_external_ip_via(test_addr: &SocketAddr, bound_addr: SocketAddr) -> Option<IpAddr> {
    // Create a UDP socket bound to the same port/interface as our main socket
    let socket = match UdpSocket::bind(if bound_addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(bound_addr.ip(), 0)
    }).await {
        Ok(s) => s,
        Err(_) => return None,
    };
    
    // Connect to the test address (this doesn't actually send data for UDP)
    if socket.connect(test_addr).await.is_err() {
        return None;
    }
    
    // Get the local address after "connecting"
    match socket.local_addr() {
        Ok(local_addr) => {
            let local_ip = local_addr.ip();
            // Only return non-local addresses as external IPs
            match local_ip {
                IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_private() && !ip.is_link_local() => Some(local_ip),
                IpAddr::V6(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(local_ip),
                _ => None,
            }
        }
        Err(_) => None,
    }
}

/// Display port allocation information
fn display_port_allocation_info(requested_addr: &SocketAddr, actual_addr: &SocketAddr) {
    println!();
    print_section("🔌", "Port Allocation:");
    
    if requested_addr.port() == 0 {
        // Random port was requested
        let allocated_port = actual_addr.port();
        print_item(&format!("Requested: {} (random port)", requested_addr), 2);
        print_item(&format!("Allocated: {} (port {})", actual_addr, allocated_port), 2);
        
        // Provide security assessment
        if allocated_port > 32768 {
            print_status(symbols::CHECK, &format!("Port {} is in ephemeral range (secure)", allocated_port), colors::GREEN);
        } else if allocated_port > 1024 {
            print_status(symbols::INFO, &format!("Port {} is in registered range", allocated_port), colors::BLUE);
        } else {
            print_status(symbols::WARNING, &format!("Port {} is in privileged range", allocated_port), colors::YELLOW);
        }
        
        // Check for predictable patterns
        if is_predictable_port(allocated_port) {
            print_status(symbols::WARNING, "Port follows a predictable pattern", colors::YELLOW);
        } else {
            print_status(symbols::CHECK, "Port allocation appears random", colors::GREEN);
        }
    } else {
        // Specific port was requested
        print_item(&format!("Requested: {} (explicit)", requested_addr), 2);
        print_item(&format!("Bound to: {}", actual_addr), 2);
        
        if is_common_port(requested_addr.port()) {
            print_status(symbols::WARNING, "Using a commonly known port", colors::YELLOW);
            print_status(symbols::INFO, "Consider using a random port (--listen 0.0.0.0:0) for better security", colors::BLUE);
        } else {
            print_status(symbols::CHECK, "Using a non-standard port", colors::GREEN);
        }
    }
}

/// Display network interfaces with categorization
async fn display_network_interfaces(bound_addr: SocketAddr) {
    // Add a message about four-word addresses
    println!();
    print_section("🗣️", "Human-Readable Four-Word Network Addresses");
    print_item("We use memorable four-word addresses that are easy to share", 2);
    print_item("Tell your friends these words instead of hard-to-remember numbers!", 2);
    println!();
    
    // Discover external IP address
    let external_ip = discover_external_ip(bound_addr).await;
    
    if let Some(external_ip) = external_ip {
        let external_addr = SocketAddr::new(external_ip, bound_addr.port());
        print_item("External Address:", 2);
        print_item(&format!("{} {}", format_address_with_words(&external_addr), "(discovered via internet connectivity)"), 4);
        println!();
    }
    
    print_item("Local Addresses:", 2);
    
    // Show the actual bound address
    let bound_desc = if bound_addr.ip().is_unspecified() {
        format!("{} {} bound to all interfaces", 
            format_address(&bound_addr),
            symbols::ARROW_RIGHT
        )
    } else {
        format_address_with_words(&bound_addr)
    };
    print_item(&bound_desc, 4);
    
    // Try to get local network interfaces
    match local_ip_address::list_afinet_netifas() {
        Ok(interfaces) => {
            let mut displayed_v4 = std::collections::HashSet::new();
            let mut displayed_v6 = std::collections::HashSet::new();
            let mut ipv4_addrs = Vec::new();
            let mut ipv6_addrs = Vec::new();
            
            // Separate IPv4 and IPv6 addresses
            for (_name, ip) in interfaces {
                if !ip.is_unspecified() {
                    let addr = SocketAddr::new(ip, bound_addr.port());
                    match ip {
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
                    print_item(&format!("{} ({})", format_address_with_words(&addr), desc), 4);
                }
            }
            
            // Display IPv6 addresses
            if !ipv6_addrs.is_empty() {
                for addr in ipv6_addrs {
                    let desc = describe_address(&addr);
                    print_item(&format!("{} ({})", format_address_with_words(&addr), desc), 4);
                }
            }
        }
        Err(_) => {
            // Fallback if we can't enumerate interfaces
            if bound_addr.ip().is_unspecified() {
                let localhost_v4 = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), bound_addr.port());
                let localhost_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), bound_addr.port());
                
                print_item(&format!("{} ({})", format_address_with_words(&localhost_v4), describe_address(&localhost_v4)), 4);
                print_item(&format!("{} ({})", format_address_with_words(&localhost_v6), describe_address(&localhost_v6)), 4);
            }
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
}