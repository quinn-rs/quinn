//! Simple NAT Traversal Coordinator Test Binary
//!
//! A basic bootstrap node coordinator for testing QUIC NAT traversal functionality.
//! This serves as a foundation that can be extended as the NAT traversal implementation matures.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clap::Parser;
use quinn_proto::{
    nat_traversal_api::{CandidateAddress, PeerId},
    CandidateSource, CandidateState,
};
use tokio::{
    net::UdpSocket,
    time::{interval, sleep},
};
use tracing::{info, warn, debug};

/// Command line arguments for the coordinator
#[derive(Parser, Debug)]
#[command(name = "simple-nat-coordinator")]
#[command(about = "Simple NAT Traversal Coordinator for QUIC P2P testing")]
struct Args {
    /// Listening address for the coordinator
    #[arg(short, long, default_value = "0.0.0.0:9000")]
    listen: SocketAddr,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Statistics reporting interval in seconds
    #[arg(long, default_value = "30")]
    stats_interval: u64,
    
    /// Maximum concurrent coordination sessions
    #[arg(long, default_value = "100")]
    max_sessions: usize,
}

/// Statistics for the coordinator
#[derive(Debug, Clone)]
struct CoordinatorStats {
    /// Total number of discovery requests served
    total_discovery_requests: u64,
    /// Total number of coordination requests served
    total_coordination_requests: u64,
    /// Number of currently registered clients
    active_clients: usize,
    /// Server reflexive discoveries performed
    reflexive_discoveries: u64,
    /// Uptime since start
    uptime: Duration,
    /// Start time
    start_time: Instant,
}

impl Default for CoordinatorStats {
    fn default() -> Self {
        Self {
            total_discovery_requests: 0,
            total_coordination_requests: 0,
            active_clients: 0,
            reflexive_discoveries: 0,
            uptime: Duration::ZERO,
            start_time: Instant::now(),
        }
    }
}

/// Information about a registered client
#[derive(Debug, Clone)]
struct ClientInfo {
    /// Client's peer ID
    peer_id: PeerId,
    /// Client's observed (server reflexive) address
    observed_address: SocketAddr,
    /// Last activity timestamp
    last_seen: Instant,
    /// Client's reported local candidates
    local_candidates: Vec<CandidateAddress>,
}

/// Simple coordination session between two peers
#[derive(Debug, Clone)]
struct CoordinationSession {
    /// First peer in the coordination
    peer_a: PeerId,
    /// Second peer in the coordination  
    peer_b: PeerId,
    /// Session start time
    started_at: Instant,
    /// Session timeout
    timeout: Duration,
    /// Last activity timestamp
    last_activity: Instant,
}

/// Simple coordinator implementation
struct SimpleCoordinator {
    /// UDP socket for communication
    socket: UdpSocket,
    /// Registry of known clients
    client_registry: Arc<Mutex<HashMap<PeerId, ClientInfo>>>,
    /// Active coordination sessions
    active_sessions: Arc<Mutex<HashMap<(PeerId, PeerId), CoordinationSession>>>,
    /// Coordinator statistics
    stats: Arc<Mutex<CoordinatorStats>>,
    /// Configuration
    config: CoordinatorConfig,
}

/// Configuration for the coordinator
#[derive(Debug, Clone)]
struct CoordinatorConfig {
    /// Listening address
    listen_addr: SocketAddr,
    /// Maximum concurrent sessions
    max_sessions: usize,
    /// Default coordination timeout
    coordination_timeout: Duration,
    /// Client registration timeout (5 minutes)
    client_timeout: Duration,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 9000)),
            max_sessions: 100,
            coordination_timeout: Duration::from_secs(30),
            client_timeout: Duration::from_secs(300),
        }
    }
}

impl SimpleCoordinator {
    /// Create a new simple coordinator
    async fn new(config: CoordinatorConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing Simple NAT Traversal Coordinator on {}", config.listen_addr);
        
        // Bind UDP socket
        let socket = UdpSocket::bind(config.listen_addr).await?;
        info!("Bound UDP socket to {}", config.listen_addr);
        
        let stats = CoordinatorStats::default();
        
        Ok(Self {
            socket,
            client_registry: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(stats)),
            config,
        })
    }
    
    /// Start the coordinator main loop
    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Simple NAT Traversal Coordinator on {}", self.config.listen_addr);
        
        // Start periodic tasks
        let _cleanup_task = self.start_cleanup_task();
        let _stats_task = self.start_stats_task();
        
        // Buffer for incoming packets
        let mut buffer = vec![0u8; 1472];
        
        // Main event loop
        loop {
            // Receive incoming packets
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, peer_addr)) => {
                    self.handle_incoming_packet(&buffer[..size], peer_addr).await;
                }
                Err(e) => {
                    warn!("Error receiving packet: {}", e);
                }
            }
            
            // Process coordination timeouts
            self.process_coordination_timeouts().await;
            
            // Brief sleep to prevent busy waiting
            sleep(Duration::from_millis(1)).await;
        }
    }
    
    /// Handle incoming packet from a peer
    async fn handle_incoming_packet(&self, data: &[u8], peer_addr: SocketAddr) {
        debug!("Received {} bytes from {}", data.len(), peer_addr);
        
        // Simple packet format: [message_type: u8][peer_id: 32 bytes][payload...]
        if data.len() < 33 {
            warn!("Received packet too small from {}", peer_addr);
            return;
        }
        
        let message_type = data[0];
        let peer_id_bytes: [u8; 32] = data[1..33].try_into().unwrap();
        let peer_id = PeerId(peer_id_bytes);
        let payload = &data[33..];
        
        match message_type {
            0x01 => {
                // Client registration / heartbeat
                self.handle_client_registration(peer_id, peer_addr).await;
            }
            0x02 => {
                // Candidate discovery request
                self.handle_candidate_discovery_request(peer_id, peer_addr, payload).await;
            }
            0x03 => {
                // Coordination request
                self.handle_coordination_request_packet(peer_id, peer_addr, payload).await;
            }
            _ => {
                debug!("Unknown message type {} from {}", message_type, peer_addr);
            }
        }
    }
    
    /// Handle client registration
    async fn handle_client_registration(&self, peer_id: PeerId, peer_addr: SocketAddr) {
        debug!("Client registration from {:?} at {}", peer_id, peer_addr);
        
        let client_info = ClientInfo {
            peer_id,
            observed_address: peer_addr,
            last_seen: Instant::now(),
            local_candidates: Vec::new(),
        };
        
        // Register or update client
        {
            let mut registry = self.client_registry.lock().unwrap();
            registry.insert(peer_id, client_info);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.active_clients = self.client_registry.lock().unwrap().len();
        }
        
        // Send registration acknowledgment with server reflexive address
        self.send_registration_ack(peer_id, peer_addr).await;
    }
    
    /// Handle candidate discovery request
    async fn handle_candidate_discovery_request(&self, peer_id: PeerId, peer_addr: SocketAddr, _payload: &[u8]) {
        debug!("Candidate discovery request from {:?}", peer_id);
        
        // Update client info
        {
            let mut registry = self.client_registry.lock().unwrap();
            if let Some(client_info) = registry.get_mut(&peer_id) {
                client_info.last_seen = Instant::now();
                client_info.observed_address = peer_addr;
            }
        }
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_discovery_requests += 1;
            stats.reflexive_discoveries += 1;
        }
        
        // Send candidate discovery response
        self.send_candidate_discovery_response(peer_id, peer_addr).await;
    }
    
    /// Handle coordination request
    async fn handle_coordination_request_packet(&self, requesting_peer: PeerId, peer_addr: SocketAddr, payload: &[u8]) {
        if payload.len() < 32 {
            warn!("Invalid coordination request from {:?}", requesting_peer);
            return;
        }
        
        let target_peer_bytes: [u8; 32] = payload[0..32].try_into().unwrap();
        let target_peer = PeerId(target_peer_bytes);
        
        info!("Coordination request: {:?} wants to connect to {:?}", requesting_peer, target_peer);
        
        // Check if target peer is registered
        let target_info = {
            let registry = self.client_registry.lock().unwrap();
            registry.get(&target_peer).cloned()
        };
        
        match target_info {
            Some(target_info) => {
                // Create coordination session
                self.create_coordination_session(requesting_peer, target_peer).await;
                
                // Send coordination instructions to both peers
                self.send_coordination_instructions(requesting_peer, peer_addr, target_info.observed_address).await;
                self.send_coordination_instructions(target_peer, target_info.observed_address, peer_addr).await;
                
                // Update statistics
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.total_coordination_requests += 1;
                }
            }
            None => {
                warn!("Target peer {:?} not found for coordination request from {:?}", target_peer, requesting_peer);
                self.send_coordination_error(requesting_peer, peer_addr, "Target peer not found").await;
            }
        }
    }
    
    /// Send registration acknowledgment with server reflexive address
    async fn send_registration_ack(&self, peer_id: PeerId, peer_addr: SocketAddr) {
        // Message format: [0x81][peer_id: 32 bytes][server_reflexive_addr: 18 bytes]
        let mut response = Vec::new();
        response.push(0x81); // Registration ACK
        response.extend_from_slice(&peer_id.0);
        
        // Encode server reflexive address (simplified IPv4 + port)
        match peer_addr {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                // For simplicity, we'll just use IPv4 for now
                response.extend_from_slice(&[0u8; 6]);
            }
        }
        
        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send registration ACK to {}: {}", peer_addr, e);
        }
    }
    
    /// Send candidate discovery response
    async fn send_candidate_discovery_response(&self, peer_id: PeerId, peer_addr: SocketAddr) {
        // Message format: [0x82][peer_id: 32 bytes][num_candidates: u8][candidates...]
        let mut response = Vec::new();
        response.push(0x82); // Candidate discovery response
        response.extend_from_slice(&peer_id.0);
        
        // Create server reflexive candidate
        // For simplicity, we'll use None for by_node since we don't have VarInt node IDs
        let server_reflexive = CandidateAddress {
            address: peer_addr,
            priority: 100,
            source: CandidateSource::Observed { by_node: None },
            state: CandidateState::Valid,
        };
        
        // For now, just send the server reflexive candidate
        response.push(1); // Number of candidates
        
        // Encode candidate (simplified)
        match server_reflexive.address {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
                response.extend_from_slice(&server_reflexive.priority.to_be_bytes());
            }
            SocketAddr::V6(_) => {
                // Skip IPv6 for simplicity
                response[33] = 0; // No candidates
            }
        }
        
        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send candidate discovery response to {}: {}", peer_addr, e);
        }
    }
    
    /// Create coordination session between two peers
    async fn create_coordination_session(&self, peer_a: PeerId, peer_b: PeerId) {
        let session = CoordinationSession {
            peer_a,
            peer_b,
            started_at: Instant::now(),
            timeout: self.config.coordination_timeout,
            last_activity: Instant::now(),
        };
        
        // Insert session
        {
            let mut sessions = self.active_sessions.lock().unwrap();
            if sessions.len() < self.config.max_sessions {
                sessions.insert((peer_a, peer_b), session);
                info!("Created coordination session: {:?} <-> {:?}", peer_a, peer_b);
            } else {
                warn!("Maximum coordination sessions reached, rejecting request");
            }
        }
    }
    
    /// Send coordination instructions to a peer
    async fn send_coordination_instructions(&self, peer_id: PeerId, peer_addr: SocketAddr, target_addr: SocketAddr) {
        // Message format: [0x83][peer_id: 32 bytes][target_addr: 6 bytes]
        let mut response = Vec::new();
        response.push(0x83); // Coordination instructions
        response.extend_from_slice(&peer_id.0);
        
        // Encode target address
        match target_addr {
            SocketAddr::V4(addr) => {
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                // Skip IPv6 for simplicity
                response.extend_from_slice(&[0u8; 6]);
            }
        }
        
        if let Err(e) = self.socket.send_to(&response, peer_addr).await {
            warn!("Failed to send coordination instructions to {}: {}", peer_addr, e);
        }
    }
    
    /// Send coordination error response
    async fn send_coordination_error(&self, peer_id: PeerId, peer_addr: SocketAddr, error: &str) {
        // Message format: [0x84][peer_id: 32 bytes][error_len: u8][error_message]
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
    
    /// Process coordination timeouts
    async fn process_coordination_timeouts(&self) {
        let now = Instant::now();
        let timeout_sessions: Vec<_> = {
            let sessions = self.active_sessions.lock().unwrap();
            sessions.iter()
                .filter(|(_, session)| now.duration_since(session.started_at) > session.timeout)
                .map(|(key, _)| *key)
                .collect()
        };
        
        if !timeout_sessions.is_empty() {
            let mut sessions = self.active_sessions.lock().unwrap();
            for session_key in timeout_sessions {
                sessions.remove(&session_key);
                warn!("Coordination session timed out: {:?}", session_key);
            }
        }
    }
    
    /// Start cleanup task for removing stale clients
    fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let client_registry = Arc::clone(&self.client_registry);
        let stats = Arc::clone(&self.stats);
        let timeout = self.config.client_timeout;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let stale_clients: Vec<_> = {
                    let registry = client_registry.lock().unwrap();
                    registry.iter()
                        .filter(|(_, client)| now.duration_since(client.last_seen) > timeout)
                        .map(|(peer_id, _)| *peer_id)
                        .collect()
                };
                
                if !stale_clients.is_empty() {
                    info!("Cleaning up {} stale clients", stale_clients.len());
                    
                    let mut registry = client_registry.lock().unwrap();
                    for peer_id in stale_clients {
                        registry.remove(&peer_id);
                    }
                    
                    // Update statistics
                    {
                        let mut stats = stats.lock().unwrap();
                        stats.active_clients = registry.len();
                    }
                }
            }
        })
    }
    
    /// Start statistics reporting task
    fn start_stats_task(&self) -> tokio::task::JoinHandle<()> {
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let stats_snapshot = {
                    let mut stats = stats.lock().unwrap();
                    stats.uptime = stats.start_time.elapsed();
                    stats.clone()
                };
                
                info!("=== Simple Coordinator Statistics ===");
                info!("Uptime: {:?}", stats_snapshot.uptime);
                info!("Active clients: {}", stats_snapshot.active_clients);
                info!("Total discovery requests: {}", stats_snapshot.total_discovery_requests);
                info!("Total coordination requests: {}", stats_snapshot.total_coordination_requests);
                info!("Server reflexive discoveries: {}", stats_snapshot.reflexive_discoveries);
                info!("====================================");
            }
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("nat_coordinator_simple={}", log_level))
        .init();
    
    info!("Starting Simple NAT Traversal Coordinator");
    info!("Listening on: {}", args.listen);
    info!("Max sessions: {}", args.max_sessions);
    
    // Create coordinator configuration
    let config = CoordinatorConfig {
        listen_addr: args.listen,
        max_sessions: args.max_sessions,
        ..Default::default()
    };
    
    // Create and run coordinator
    let coordinator = SimpleCoordinator::new(config).await?;
    coordinator.run().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coordinator_creation() {
        let config = CoordinatorConfig::default();
        let coordinator = SimpleCoordinator::new(config).await;
        assert!(coordinator.is_ok());
    }
    
    #[test]
    fn test_coordinator_config_default() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.listen_addr.port(), 9000);
        assert_eq!(config.max_sessions, 100);
        assert_eq!(config.coordination_timeout, Duration::from_secs(30));
    }
    
    #[test]
    fn test_coordination_session_creation() {
        let peer_a = PeerId([1; 32]);
        let peer_b = PeerId([2; 32]);
        
        let session = CoordinationSession {
            peer_a,
            peer_b,
            started_at: Instant::now(),
            timeout: Duration::from_secs(30),
            last_activity: Instant::now(),
        };
        
        assert_eq!(session.peer_a, peer_a);
        assert_eq!(session.peer_b, peer_b);
    }
}