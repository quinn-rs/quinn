//! NAT Traversal Coordinator Test Binary
//!
//! This binary implements a bootstrap node coordinator for testing QUIC NAT traversal.
//! It provides:
//! - Server reflexive address discovery for clients
//! - Coordination services for simultaneous hole punching
//! - Health monitoring and statistics
//! - Multi-client coordination with round synchronization

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use clap::Parser;
use quinn_proto::{
    nat_traversal_api::{BootstrapNode, CandidateAddress, EndpointRole, NatTraversalEndpoint, PeerId},
    connection::nat_traversal::{CandidateSource, CandidateState, CoordinationPhase},
    TransportConfig, ServerConfig, EndpointConfig,
};
use tokio::{
    net::UdpSocket as TokioUdpSocket,
    time::{interval, sleep},
};
use tracing::{info, warn, error, debug};

/// Command line arguments for the coordinator
#[derive(Parser, Debug)]
#[command(name = "nat-coordinator")]
#[command(about = "NAT Traversal Coordinator for QUIC P2P connections")]
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
    #[arg(long, default_value = "1000")]
    max_sessions: usize,
    
    /// Coordination timeout in seconds
    #[arg(long, default_value = "30")]
    coordination_timeout: u64,
    
    /// Enable detailed coordination logging
    #[arg(long)]
    debug_coordination: bool,
}

/// Statistics for the coordinator
#[derive(Debug, Clone)]
struct CoordinatorStats {
    /// Total number of clients served
    total_clients_served: u64,
    /// Active coordination sessions
    active_sessions: usize,
    /// Successful coordinations
    successful_coordinations: u64,
    /// Failed coordinations
    failed_coordinations: u64,
    /// Server reflexive discoveries performed
    reflexive_discoveries: u64,
    /// Current client registry size
    client_registry_size: usize,
    /// Uptime
    uptime: Duration,
    /// Start time
    start_time: Instant,
}

impl Default for CoordinatorStats {
    fn default() -> Self {
        Self {
            total_clients_served: 0,
            active_sessions: 0,
            successful_coordinations: 0,
            failed_coordinations: 0,
            reflexive_discoveries: 0,
            client_registry_size: 0,
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
    /// Client's reported local candidates
    local_candidates: Vec<CandidateAddress>,
    /// Last activity timestamp
    last_seen: Instant,
    /// Connection capabilities
    capabilities: ClientCapabilities,
}

/// Client capabilities and configuration
#[derive(Debug, Clone)]
struct ClientCapabilities {
    /// Supports symmetric NAT prediction
    supports_prediction: bool,
    /// Maximum candidates the client can handle
    max_candidates: u32,
    /// Preferred coordination timeout
    preferred_timeout: Duration,
}

/// Active coordination session between two peers
#[derive(Debug)]
struct CoordinationSession {
    /// First peer in the coordination
    peer_a: PeerId,
    /// Second peer in the coordination  
    peer_b: PeerId,
    /// Current coordination phase
    phase: CoordinationPhase,
    /// Session start time
    started_at: Instant,
    /// Coordination round number
    round: u32,
    /// Expected coordination timeout
    timeout: Duration,
    /// Peer A's candidates for this session
    peer_a_candidates: Vec<CandidateAddress>,
    /// Peer B's candidates for this session
    peer_b_candidates: Vec<CandidateAddress>,
    /// Last activity timestamp
    last_activity: Instant,
}

/// Main coordinator state
struct Coordinator {
    /// Coordinator configuration
    config: CoordinatorConfig,
    /// Registry of known clients
    client_registry: Arc<Mutex<HashMap<PeerId, ClientInfo>>>,
    /// Active coordination sessions
    active_sessions: Arc<Mutex<HashMap<(PeerId, PeerId), CoordinationSession>>>,
    /// Coordinator statistics
    stats: Arc<Mutex<CoordinatorStats>>,
    /// NAT traversal endpoint
    nat_endpoint: NatTraversalEndpoint,
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
    /// Client registration timeout
    client_timeout: Duration,
    /// Enable debug logging for coordination
    debug_coordination: bool,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 9000)),
            max_sessions: 1000,
            coordination_timeout: Duration::from_secs(30),
            client_timeout: Duration::from_secs(300), // 5 minutes
            debug_coordination: false,
        }
    }
}

impl Coordinator {
    /// Create a new coordinator
    async fn new(config: CoordinatorConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing NAT Traversal Coordinator on {}", config.listen_addr);
        
        // Setup NAT traversal endpoint configuration
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        
        let mut server_config = ServerConfig::with_single_cert(
            vec![rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap().serialize_der().unwrap()],
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap().serialize_private_key_der(),
        ).unwrap();
        server_config.transport = Arc::new(transport);
        
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.max_udp_payload_size(1472);
        
        // Create NAT traversal endpoint
        let nat_endpoint = NatTraversalEndpoint::new(
            config.listen_addr,
            endpoint_config,
            Some(server_config),
            EndpointRole::Bootstrap,
        ).await?;
        
        let stats = CoordinatorStats {
            start_time: Instant::now(),
            ..Default::default()
        };
        
        Ok(Self {
            config,
            client_registry: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(stats)),
            nat_endpoint,
        })
    }
    
    /// Start the coordinator main loop
    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting NAT Traversal Coordinator on {}", self.config.listen_addr);
        
        // Start periodic tasks
        let cleanup_task = self.start_cleanup_task();
        let stats_task = self.start_stats_task();
        let coordination_task = self.start_coordination_task();
        
        // Main event loop
        loop {
            // Process NAT traversal events
            let events = self.nat_endpoint.poll_events().await;
            for event in events {
                self.handle_nat_event(event).await;
            }
            
            // Process coordination timeouts
            self.process_coordination_timeouts().await;
            
            // Brief sleep to prevent busy waiting
            sleep(Duration::from_millis(10)).await;
        }
    }
    
    /// Handle NAT traversal events
    async fn handle_nat_event(&self, event: quinn_proto::nat_traversal_api::NatTraversalEvent) {
        use quinn_proto::nat_traversal_api::NatTraversalEvent;
        
        match event {
            NatTraversalEvent::ClientConnected { peer_id, observed_address } => {
                self.handle_client_connected(peer_id, observed_address).await;
            }
            NatTraversalEvent::ClientDisconnected { peer_id } => {
                self.handle_client_disconnected(peer_id).await;
            }
            NatTraversalEvent::CandidateDiscoveryRequest { peer_id, local_candidates } => {
                self.handle_candidate_discovery_request(peer_id, local_candidates).await;
            }
            NatTraversalEvent::CoordinationRequested { requesting_peer, target_peer } => {
                self.handle_coordination_request(requesting_peer, target_peer).await;
            }
            _ => {
                debug!("Unhandled NAT traversal event: {:?}", event);
            }
        }
    }
    
    /// Handle client connection
    async fn handle_client_connected(&self, peer_id: PeerId, observed_address: SocketAddr) {
        info!("Client connected: {:?} from {}", peer_id, observed_address);
        
        let client_info = ClientInfo {
            peer_id,
            observed_address,
            local_candidates: Vec::new(),
            last_seen: Instant::now(),
            capabilities: ClientCapabilities {
                supports_prediction: true,
                max_candidates: 10,
                preferred_timeout: Duration::from_secs(30),
            },
        };
        
        // Register client
        {
            let mut registry = self.client_registry.lock().unwrap();
            registry.insert(peer_id, client_info);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_clients_served += 1;
            stats.client_registry_size = self.client_registry.lock().unwrap().len();
        }
        
        // Send server reflexive address back to client
        self.send_server_reflexive_response(peer_id, observed_address).await;
    }
    
    /// Handle client disconnection
    async fn handle_client_disconnected(&self, peer_id: PeerId) {
        info!("Client disconnected: {:?}", peer_id);
        
        // Remove from registry
        {
            let mut registry = self.client_registry.lock().unwrap();
            registry.remove(&peer_id);
        }
        
        // Cancel any active sessions involving this peer
        self.cancel_sessions_for_peer(peer_id).await;
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.client_registry_size = self.client_registry.lock().unwrap().len();
        }
    }
    
    /// Handle candidate discovery request
    async fn handle_candidate_discovery_request(&self, peer_id: PeerId, local_candidates: Vec<CandidateAddress>) {
        debug!("Candidate discovery request from {:?} with {} candidates", peer_id, local_candidates.len());
        
        // Update client info with local candidates
        {
            let mut registry = self.client_registry.lock().unwrap();
            if let Some(client_info) = registry.get_mut(&peer_id) {
                client_info.local_candidates = local_candidates.clone();
                client_info.last_seen = Instant::now();
            }
        }
        
        // Generate additional candidates if possible (symmetric NAT prediction)
        let predicted_candidates = self.generate_predicted_candidates(peer_id, &local_candidates).await;
        
        // Send response with all candidates
        let mut all_candidates = local_candidates;
        all_candidates.extend(predicted_candidates);
        
        self.send_candidate_discovery_response(peer_id, all_candidates).await;
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.reflexive_discoveries += 1;
        }
    }
    
    /// Handle coordination request between two peers
    async fn handle_coordination_request(&self, peer_a: PeerId, peer_b: PeerId) {
        info!("Coordination request: {:?} <-> {:?}", peer_a, peer_b);
        
        // Check if both peers are registered
        let (client_a, client_b) = {
            let registry = self.client_registry.lock().unwrap();
            match (registry.get(&peer_a), registry.get(&peer_b)) {
                (Some(a), Some(b)) => (a.clone(), b.clone()),
                _ => {
                    warn!("Coordination request for unknown peers: {:?} <-> {:?}", peer_a, peer_b);
                    return;
                }
            }
        };
        
        // Check session limits
        {
            let sessions = self.active_sessions.lock().unwrap();
            if sessions.len() >= self.config.max_sessions {
                warn!("Maximum coordination sessions reached, rejecting request");
                return;
            }
        }
        
        // Create coordination session
        let session = CoordinationSession {
            peer_a,
            peer_b,
            phase: CoordinationPhase::Requesting,
            started_at: Instant::now(),
            round: 1,
            timeout: self.config.coordination_timeout,
            peer_a_candidates: client_a.local_candidates.clone(),
            peer_b_candidates: client_b.local_candidates.clone(),
            last_activity: Instant::now(),
        };
        
        // Insert session
        {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.insert((peer_a, peer_b), session);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.active_sessions = self.active_sessions.lock().unwrap().len();
        }
        
        // Start coordination process
        self.start_coordination_process(peer_a, peer_b).await;
    }
    
    /// Handle coordination completion
    async fn handle_coordination_completed(&self, peer_a: PeerId, peer_b: PeerId, successful: bool) {
        info!("Coordination completed: {:?} <-> {:?}, success: {}", peer_a, peer_b, successful);
        
        // Remove session
        {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.remove(&(peer_a, peer_b));
        }
        
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.active_sessions = self.active_sessions.lock().unwrap().len();
            if successful {
                stats.successful_coordinations += 1;
            } else {
                stats.failed_coordinations += 1;
            }
        }
    }
    
    /// Send server reflexive address response to client
    async fn send_server_reflexive_response(&self, peer_id: PeerId, observed_address: SocketAddr) {
        let candidate = CandidateAddress {
            address: observed_address,
            priority: 100, // Standard priority for server reflexive
            source: CandidateSource::Observed { by_node: Some(self.config.listen_addr) },
            state: CandidateState::Valid,
        };
        
        if let Err(e) = self.nat_endpoint.send_candidate_response(peer_id, vec![candidate]).await {
            warn!("Failed to send server reflexive response to {:?}: {}", peer_id, e);
        }
    }
    
    /// Generate predicted candidates for symmetric NAT
    async fn generate_predicted_candidates(&self, peer_id: PeerId, local_candidates: &[CandidateAddress]) -> Vec<CandidateAddress> {
        let mut predicted = Vec::new();
        
        // Simple port prediction for symmetric NAT
        for candidate in local_candidates {
            if candidate.address.is_ipv4() {
                // Predict next few ports for symmetric NAT
                for port_offset in 1..=3 {
                    let mut predicted_addr = candidate.address;
                    predicted_addr.set_port(predicted_addr.port() + port_offset);
                    
                    predicted.push(CandidateAddress {
                        address: predicted_addr,
                        priority: 50, // Lower priority for predicted
                        source: CandidateSource::Predicted,
                        state: CandidateState::Unvalidated,
                    });
                }
            }
        }
        
        debug!("Generated {} predicted candidates for {:?}", predicted.len(), peer_id);
        predicted
    }
    
    /// Send candidate discovery response
    async fn send_candidate_discovery_response(&self, peer_id: PeerId, candidates: Vec<CandidateAddress>) {
        if let Err(e) = self.nat_endpoint.send_candidate_response(peer_id, candidates).await {
            warn!("Failed to send candidate discovery response to {:?}: {}", peer_id, e);
        }
    }
    
    /// Start coordination process between two peers
    async fn start_coordination_process(&self, peer_a: PeerId, peer_b: PeerId) {
        if self.config.debug_coordination {
            debug!("Starting coordination process: {:?} <-> {:?}", peer_a, peer_b);
        }
        
        // Send coordination instructions to both peers
        if let Err(e) = self.nat_endpoint.send_coordination_instructions(peer_a, peer_b).await {
            warn!("Failed to send coordination instructions: {}", e);
        }
    }
    
    /// Cancel all sessions involving a specific peer
    async fn cancel_sessions_for_peer(&self, peer_id: PeerId) {
        let sessions_to_remove: Vec<_> = {
            let sessions = self.active_sessions.lock().unwrap();
            sessions.keys()
                .filter(|(a, b)| *a == peer_id || *b == peer_id)
                .cloned()
                .collect()
        };
        
        for session_key in sessions_to_remove {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.remove(&session_key);
            info!("Cancelled coordination session: {:?}", session_key);
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
        
        for session_key in timeout_sessions {
            {
                let mut sessions = self.active_sessions.lock().unwrap();
                sessions.remove(&session_key);
            }
            
            warn!("Coordination session timed out: {:?}", session_key);
            
            // Update statistics
            {
                let mut stats = self.stats.lock().unwrap();
                stats.failed_coordinations += 1;
                stats.active_sessions = self.active_sessions.lock().unwrap().len();
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
                        stats.client_registry_size = registry.len();
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
                
                info!("=== Coordinator Statistics ===");
                info!("Uptime: {:?}", stats_snapshot.uptime);
                info!("Total clients served: {}", stats_snapshot.total_clients_served);
                info!("Active clients: {}", stats_snapshot.client_registry_size);
                info!("Active coordination sessions: {}", stats_snapshot.active_sessions);
                info!("Successful coordinations: {}", stats_snapshot.successful_coordinations);
                info!("Failed coordinations: {}", stats_snapshot.failed_coordinations);
                info!("Server reflexive discoveries: {}", stats_snapshot.reflexive_discoveries);
                
                let success_rate = if stats_snapshot.successful_coordinations + stats_snapshot.failed_coordinations > 0 {
                    (stats_snapshot.successful_coordinations as f64 / 
                     (stats_snapshot.successful_coordinations + stats_snapshot.failed_coordinations) as f64) * 100.0
                } else {
                    0.0
                };
                info!("Coordination success rate: {:.1}%", success_rate);
                info!("===============================");
            }
        })
    }
    
    /// Start coordination monitoring task
    fn start_coordination_task(&self) -> tokio::task::JoinHandle<()> {
        let active_sessions = Arc::clone(&self.active_sessions);
        let debug_coordination = self.config.debug_coordination;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                if debug_coordination {
                    let sessions = active_sessions.lock().unwrap();
                    if !sessions.is_empty() {
                        debug!("Active coordination sessions: {}", sessions.len());
                        for ((peer_a, peer_b), session) in sessions.iter() {
                            debug!("  {:?} <-> {:?}: Phase {:?}, Round {}, Age: {:?}",
                                   peer_a, peer_b, session.phase, session.round,
                                   session.started_at.elapsed());
                        }
                    }
                }
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
        .with_env_filter(format!("nat_coordinator={},quinn_proto=info", log_level))
        .init();
    
    info!("Starting NAT Traversal Coordinator");
    info!("Listening on: {}", args.listen);
    info!("Max sessions: {}", args.max_sessions);
    info!("Coordination timeout: {}s", args.coordination_timeout);
    
    // Create coordinator configuration
    let config = CoordinatorConfig {
        listen_addr: args.listen,
        max_sessions: args.max_sessions,
        coordination_timeout: Duration::from_secs(args.coordination_timeout),
        debug_coordination: args.debug_coordination,
        ..Default::default()
    };
    
    // Create and run coordinator
    let coordinator = Coordinator::new(config).await?;
    coordinator.run().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coordinator_creation() {
        let config = CoordinatorConfig::default();
        let coordinator = Coordinator::new(config).await;
        assert!(coordinator.is_ok());
    }
    
    #[test]
    fn test_coordinator_config_default() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.listen_addr.port(), 9000);
        assert_eq!(config.max_sessions, 1000);
        assert_eq!(config.coordination_timeout, Duration::from_secs(30));
    }
    
    #[test]
    fn test_client_capabilities_default() {
        let caps = ClientCapabilities {
            supports_prediction: true,
            max_candidates: 10,
            preferred_timeout: Duration::from_secs(30),
        };
        assert!(caps.supports_prediction);
        assert_eq!(caps.max_candidates, 10);
    }
}