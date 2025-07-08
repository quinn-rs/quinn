//! Network Simulation Binary for NAT Traversal Testing
//!
//! This binary provides a comprehensive network simulation environment for testing
//! QUIC NAT traversal functionality with configurable NAT types, network conditions,
//! and realistic scenarios.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
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
use tracing::{info, warn, debug, error};

/// Command line arguments for the network simulator
#[derive(Parser, Debug)]
#[command(name = "nat-simulation")]
#[command(about = "Network simulation for QUIC NAT traversal testing")]
struct Args {
    /// Configuration file for the simulation
    #[arg(short, long, default_value = "simulation.toml")]
    config: String,
    
    /// Number of simulated nodes
    #[arg(short, long, default_value = "10")]
    nodes: usize,
    
    /// Simulation duration in seconds
    #[arg(short, long, default_value = "300")]
    duration: u64,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Output directory for results
    #[arg(short, long, default_value = "./simulation_results")]
    output: String,
    
    /// NAT types to simulate (comma separated)
    #[arg(long, default_value = "full-cone,symmetric,port-restricted")]
    nat_types: String,
    
    /// Enable packet loss simulation
    #[arg(long)]
    packet_loss: bool,
    
    /// Enable latency simulation 
    #[arg(long)]
    latency_sim: bool,
    
    /// Network topology type
    #[arg(long, default_value = "mesh")]
    topology: String,
}

/// Types of simulated network topologies
#[derive(Debug, Clone)]
enum TopologyType {
    /// Full mesh - all nodes can potentially connect to each other
    Mesh,
    /// Star - central coordinator with spoke connections
    Star,
    /// Hierarchical - multi-level tree structure
    Hierarchical,
    /// Real-world - based on actual internet topology patterns
    RealWorld,
}

/// Network simulation coordinator
struct NetworkSimulation {
    /// Configuration parameters
    config: SimulationConfig,
    /// Simulated nodes
    nodes: HashMap<NodeId, SimulatedNode>,
    /// NAT devices in the simulation
    nat_devices: HashMap<NatId, SimulatedNatDevice>,
    /// Network topology
    topology: SimulatedTopology,
    /// Statistics collector
    stats: SimulationStats,
    /// Event timeline
    events: Vec<SimulationEvent>,
}

/// Configuration for the network simulation
#[derive(Debug, Clone)]
struct SimulationConfig {
    /// Number of nodes to simulate
    node_count: usize,
    /// Simulation duration
    duration: Duration,
    /// Types of NAT devices to create
    nat_types: Vec<NatType>,
    /// Network conditions
    conditions: NetworkConditions,
    /// Topology configuration
    topology_type: TopologyType,
    /// Output configuration
    output_dir: String,
    /// Logging configuration
    verbose: bool,
}

/// Individual simulated node
#[derive(Debug)]
struct SimulatedNode {
    /// Unique node identifier
    id: NodeId,
    /// Node's peer ID for QUIC
    peer_id: PeerId,
    /// Current network address
    address: SocketAddr,
    /// NAT device this node is behind (if any)
    nat_device: Option<NatId>,
    /// Node's current state
    state: NodeState,
    /// Connection attempts and results
    connections: HashMap<NodeId, ConnectionAttempt>,
    /// Performance metrics
    metrics: NodeMetrics,
    /// Event history
    events: Vec<NodeEvent>,
}

/// Types of simulated NAT devices
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NatType {
    /// Full Cone NAT - most permissive
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestricted,
    /// Symmetric NAT - most restrictive
    Symmetric,
    /// Carrier Grade NAT (CGNAT)
    CarrierGrade,
}

/// Simulated NAT device
#[derive(Debug)]
struct SimulatedNatDevice {
    /// NAT device identifier
    id: NatId,
    /// Type of NAT behavior
    nat_type: NatType,
    /// Internal to external address mappings
    mappings: HashMap<SocketAddr, SocketAddr>,
    /// NAT configuration
    config: NatDeviceConfig,
    /// Statistics for this NAT device
    stats: NatStats,
}

/// Configuration for a NAT device
#[derive(Debug, Clone)]
struct NatDeviceConfig {
    /// External IP range
    external_ip_range: (IpAddr, IpAddr),
    /// Port range for allocations
    port_range: (u16, u16),
    /// Session timeout
    session_timeout: Duration,
    /// Maximum concurrent sessions
    max_sessions: usize,
    /// Port preservation probability
    port_preservation_rate: f64,
}

/// Network topology representation
#[derive(Debug)]
struct SimulatedTopology {
    /// Topology type
    topology_type: TopologyType,
    /// Node connections (adjacency list)
    connections: HashMap<NodeId, Vec<NodeId>>,
    /// Routing table
    routing: HashMap<(NodeId, NodeId), Route>,
    /// Network segments
    segments: HashMap<SegmentId, NetworkSegment>,
}

/// Route between two nodes
#[derive(Debug, Clone)]
struct Route {
    /// Path through intermediate nodes
    path: Vec<NodeId>,
    /// Base latency
    latency: Duration,
    /// Packet loss probability
    packet_loss: f64,
    /// Bandwidth limit
    bandwidth: u64,
}

/// Network segment (subnet)
#[derive(Debug, Clone)]
struct NetworkSegment {
    /// Segment identifier
    id: SegmentId,
    /// IP address range
    ip_range: (IpAddr, u8),
    /// NAT device for this segment
    nat_device: Option<NatId>,
    /// Nodes in this segment
    nodes: Vec<NodeId>,
}

/// Network conditions affecting the simulation
#[derive(Debug, Clone)]
struct NetworkConditions {
    /// Base packet loss rate
    packet_loss_rate: f64,
    /// Base latency
    base_latency: Duration,
    /// Latency variation
    latency_jitter: Duration,
    /// Bandwidth limitations
    bandwidth_limit: Option<u64>,
    /// Congestion simulation
    congestion_factor: f64,
}

/// Connection attempt between nodes
#[derive(Debug, Clone)]
struct ConnectionAttempt {
    /// Target node
    target: NodeId,
    /// Attempt start time
    started_at: Instant,
    /// Current state
    state: ConnectionState,
    /// Candidates tried
    candidates_tried: Vec<CandidateAddress>,
    /// Results
    result: Option<ConnectionResult>,
}

/// State of a connection attempt
#[derive(Debug, Clone)]
enum ConnectionState {
    /// Discovering candidates
    Discovering,
    /// Coordinating with bootstrap
    Coordinating,
    /// Attempting hole punch
    HolePunching,
    /// Validating path
    Validating,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
}

/// Result of a connection attempt
#[derive(Debug, Clone)]
struct ConnectionResult {
    /// Whether connection succeeded
    success: bool,
    /// Time taken to establish connection
    establishment_time: Duration,
    /// NAT traversal method used
    traversal_method: Option<TraversalMethod>,
    /// Error details if failed
    error: Option<String>,
}

/// NAT traversal methods
#[derive(Debug, Clone)]
enum TraversalMethod {
    /// Direct connection (no NAT)
    Direct,
    /// Full cone hole punching
    FullConeHolePunch,
    /// Restricted cone hole punching
    RestrictedConeHolePunch,
    /// Port restricted hole punching
    PortRestrictedHolePunch,
    /// Symmetric NAT with prediction
    SymmetricPrediction,
    /// Relay through bootstrap node
    Relay,
}

/// Performance metrics for a node
#[derive(Debug, Default)]
struct NodeMetrics {
    /// Total connection attempts
    connection_attempts: u64,
    /// Successful connections
    successful_connections: u64,
    /// Failed connections
    failed_connections: u64,
    /// Average connection time
    avg_connection_time: Duration,
    /// Bytes sent/received
    bytes_sent: u64,
    bytes_received: u64,
    /// NAT traversal success by method
    traversal_success_rates: HashMap<TraversalMethod, f64>,
}

/// Statistics for NAT devices
#[derive(Debug, Default)]
struct NatStats {
    /// Packets processed
    packets_processed: u64,
    /// Sessions created
    sessions_created: u64,
    /// Sessions timed out
    sessions_timeout: u64,
    /// Port allocations
    port_allocations: u64,
    /// Port allocation failures
    allocation_failures: u64,
}

/// Overall simulation statistics
#[derive(Debug, Clone)]
struct SimulationStats {
    /// Simulation start time
    start_time: Instant,
    /// Total nodes simulated
    total_nodes: usize,
    /// Total connection attempts
    total_attempts: u64,
    /// Overall success rate
    success_rate: f64,
    /// Success rates by NAT type combination
    success_by_nat_type: HashMap<(NatType, NatType), f64>,
    /// Average connection establishment time
    avg_connection_time: Duration,
    /// Performance metrics
    performance_metrics: HashMap<String, f64>,
}

impl Default for SimulationStats {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            total_nodes: 0,
            total_attempts: 0,
            success_rate: 0.0,
            success_by_nat_type: HashMap::new(),
            avg_connection_time: Duration::ZERO,
            performance_metrics: HashMap::new(),
        }
    }
}

/// Simulation events
#[derive(Debug, Clone)]
enum SimulationEvent {
    /// Node started
    NodeStarted { node_id: NodeId, timestamp: Instant },
    /// Connection attempt started
    ConnectionStarted { from: NodeId, to: NodeId, timestamp: Instant },
    /// Connection completed
    ConnectionCompleted { from: NodeId, to: NodeId, result: ConnectionResult, timestamp: Instant },
    /// NAT mapping created
    NatMappingCreated { nat_id: NatId, internal: SocketAddr, external: SocketAddr, timestamp: Instant },
    /// Network condition changed
    ConditionChanged { condition: String, value: f64, timestamp: Instant },
}

/// Node-specific events
#[derive(Debug, Clone)]
enum NodeEvent {
    /// Started candidate discovery
    CandidateDiscoveryStarted { timestamp: Instant },
    /// Received coordination instructions
    CoordinationReceived { coordinator: NodeId, timestamp: Instant },
    /// Hole punch attempt
    HolePunchAttempt { target: SocketAddr, timestamp: Instant },
    /// Path validation
    PathValidation { candidate: CandidateAddress, success: bool, timestamp: Instant },
}

/// Unique identifiers
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NodeId(String);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NatId(String);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SegmentId(String);

/// Current state of a simulated node
#[derive(Debug, Clone)]
enum NodeState {
    /// Node is initializing
    Initializing,
    /// Node is active and ready
    Active,
    /// Node is attempting connections
    Connecting,
    /// Node is idle
    Idle,
    /// Node has failed
    Failed,
}

impl NetworkSimulation {
    /// Create a new network simulation
    pub fn new(config: SimulationConfig) -> Self {
        info!("Creating network simulation with {} nodes", config.node_count);
        
        Self {
            config,
            nodes: HashMap::new(),
            nat_devices: HashMap::new(),
            topology: SimulatedTopology::new(),
            stats: SimulationStats::default(),
            events: Vec::new(),
        }
    }
    
    /// Initialize the simulation environment
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing network simulation environment");
        
        // Create network topology
        self.create_topology().await?;
        
        // Create NAT devices
        self.create_nat_devices().await?;
        
        // Create and place nodes
        self.create_nodes().await?;
        
        // Configure network segments
        self.configure_segments().await?;
        
        info!("Network simulation initialized successfully");
        Ok(())
    }
    
    /// Run the network simulation
    pub async fn run(&mut self) -> Result<SimulationStats, Box<dyn std::error::Error>> {
        info!("Starting network simulation for {:?}", self.config.duration);
        self.stats.start_time = Instant::now();
        
        // Start all nodes
        self.start_all_nodes().await?;
        
        // Run simulation phases
        self.run_discovery_phase().await?;
        self.run_connection_phase().await?;
        self.run_traffic_phase().await?;
        
        // Collect final statistics
        self.collect_final_stats().await;
        
        info!("Network simulation completed");
        Ok(self.stats.clone())
    }
    
    /// Create network topology based on configuration
    async fn create_topology(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.config.topology_type {
            TopologyType::Mesh => self.create_mesh_topology().await,
            TopologyType::Star => self.create_star_topology().await,
            TopologyType::Hierarchical => self.create_hierarchical_topology().await,
            TopologyType::RealWorld => self.create_real_world_topology().await,
        }
    }
    
    /// Create full mesh topology
    async fn create_mesh_topology(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating mesh topology");
        
        // In mesh topology, every node can potentially connect to every other node
        for i in 0..self.config.node_count {
            let mut connections = Vec::new();
            for j in 0..self.config.node_count {
                if i != j {
                    connections.push(NodeId(format!("node_{}", j)));
                }
            }
            self.topology.connections.insert(NodeId(format!("node_{}", i)), connections);
        }
        
        Ok(())
    }
    
    /// Create star topology
    async fn create_star_topology(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating star topology");
        
        // Central coordinator node connects to all others
        let coordinator = NodeId("coordinator".to_string());
        let mut coordinator_connections = Vec::new();
        
        for i in 0..self.config.node_count {
            let node_id = NodeId(format!("node_{}", i));
            coordinator_connections.push(node_id.clone());
            
            // Each node only connects to coordinator initially
            self.topology.connections.insert(node_id, vec![coordinator.clone()]);
        }
        
        self.topology.connections.insert(coordinator, coordinator_connections);
        Ok(())
    }
    
    /// Create hierarchical topology
    async fn create_hierarchical_topology(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating hierarchical topology");
        
        // Create a tree structure with multiple levels
        let levels = 3;
        let nodes_per_level = self.config.node_count / levels;
        
        for level in 0..levels {
            for node in 0..nodes_per_level {
                let node_id = NodeId(format!("level_{}_{}", level, node));
                let mut connections = Vec::new();
                
                // Connect to parent level
                if level > 0 {
                    let parent_id = NodeId(format!("level_{}_{}", level - 1, node / 2));
                    connections.push(parent_id);
                }
                
                // Connect to children
                if level < levels - 1 {
                    for child in 0..2 {
                        let child_id = NodeId(format!("level_{}_{}", level + 1, node * 2 + child));
                        connections.push(child_id);
                    }
                }
                
                self.topology.connections.insert(node_id, connections);
            }
        }
        
        Ok(())
    }
    
    /// Create realistic internet-like topology
    async fn create_real_world_topology(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating real-world topology");
        
        // Simulate realistic internet topology with:
        // - Core nodes (ISPs, backbone providers)
        // - Edge nodes (home/office networks)
        // - Variable connectivity patterns
        
        let core_nodes = self.config.node_count / 4;
        let edge_nodes = self.config.node_count - core_nodes;
        
        // Create core network (highly connected)
        for i in 0..core_nodes {
            let node_id = NodeId(format!("core_{}", i));
            let mut connections = Vec::new();
            
            // Core nodes connect to other core nodes
            for j in 0..core_nodes {
                if i != j {
                    connections.push(NodeId(format!("core_{}", j)));
                }
            }
            
            self.topology.connections.insert(node_id, connections);
        }
        
        // Create edge networks
        for i in 0..edge_nodes {
            let node_id = NodeId(format!("edge_{}", i));
            let core_connection = NodeId(format!("core_{}", i % core_nodes));
            
            self.topology.connections.insert(node_id, vec![core_connection]);
        }
        
        Ok(())
    }
    
    /// Create NAT devices based on configuration
    async fn create_nat_devices(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating NAT devices");
        
        for (i, nat_type) in self.config.nat_types.iter().enumerate() {
            let nat_id = NatId(format!("nat_{}", i));
            let nat_device = SimulatedNatDevice {
                id: nat_id.clone(),
                nat_type: nat_type.clone(),
                mappings: HashMap::new(),
                config: NatDeviceConfig {
                    external_ip_range: ("203.0.113.1".parse().unwrap(), "203.0.113.254".parse().unwrap()),
                    port_range: (1024, 65535),
                    session_timeout: Duration::from_secs(300),
                    max_sessions: 1000,
                    port_preservation_rate: 0.8,
                },
                stats: NatStats::default(),
            };
            
            self.nat_devices.insert(nat_id, nat_device);
        }
        
        Ok(())
    }
    
    /// Create simulated nodes
    async fn create_nodes(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating {} simulated nodes", self.config.node_count);
        
        for i in 0..self.config.node_count {
            let node_id = NodeId(format!("node_{}", i));
            let peer_id = PeerId([i as u8; 32]); // Simplified peer ID
            
            // Assign nodes to NAT devices round-robin
            let nat_device = if !self.nat_devices.is_empty() {
                Some(NatId(format!("nat_{}", i % self.nat_devices.len())))
            } else {
                None
            };
            
            let node = SimulatedNode {
                id: node_id.clone(),
                peer_id,
                address: format!("192.168.{}.100:0", i + 1).parse().unwrap(),
                nat_device,
                state: NodeState::Initializing,
                connections: HashMap::new(),
                metrics: NodeMetrics::default(),
                events: Vec::new(),
            };
            
            self.nodes.insert(node_id, node);
        }
        
        Ok(())
    }
    
    /// Configure network segments
    async fn configure_segments(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Configuring network segments");
        
        // Create segments based on NAT devices
        for (nat_id, _) in &self.nat_devices {
            let segment_id = SegmentId(format!("segment_{}", nat_id.0));
            let mut segment_nodes = Vec::new();
            
            // Find nodes behind this NAT
            for (node_id, node) in &self.nodes {
                if node.nat_device.as_ref() == Some(nat_id) {
                    segment_nodes.push(node_id.clone());
                }
            }
            
            let segment = NetworkSegment {
                id: segment_id.clone(),
                ip_range: ("192.168.1.0".parse().unwrap(), 24),
                nat_device: Some(nat_id.clone()),
                nodes: segment_nodes,
            };
            
            self.topology.segments.insert(segment_id, segment);
        }
        
        Ok(())
    }
    
    /// Start all simulated nodes
    async fn start_all_nodes(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting all simulated nodes");
        
        for (node_id, node) in &mut self.nodes {
            node.state = NodeState::Active;
            
            let event = SimulationEvent::NodeStarted {
                node_id: node_id.clone(),
                timestamp: Instant::now(),
            };
            self.events.push(event);
        }
        
        Ok(())
    }
    
    /// Run candidate discovery phase
    async fn run_discovery_phase(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Running candidate discovery phase");
        
        for (node_id, node) in &mut self.nodes {
            let event = NodeEvent::CandidateDiscoveryStarted {
                timestamp: Instant::now(),
            };
            node.events.push(event);
        }
        
        // Simulate discovery delay
        sleep(Duration::from_secs(5)).await;
        Ok(())
    }
    
    /// Run connection establishment phase
    async fn run_connection_phase(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Running connection establishment phase");
        
        let node_ids: Vec<_> = self.nodes.keys().cloned().collect();
        
        // Simulate connection attempts between nodes
        for i in 0..node_ids.len() {
            for j in (i + 1)..node_ids.len() {
                let source = &node_ids[i];
                let target = &node_ids[j];
                
                if let Some(should_connect) = self.should_attempt_connection(source, target).await {
                    if should_connect {
                        self.attempt_connection(source.clone(), target.clone()).await?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Determine if two nodes should attempt connection
    async fn should_attempt_connection(&self, source: &NodeId, target: &NodeId) -> Option<bool> {
        // Check topology constraints
        if let Some(connections) = self.topology.connections.get(source) {
            return Some(connections.contains(target));
        }
        
        // Default: allow connections in mesh topology
        Some(matches!(self.config.topology_type, TopologyType::Mesh))
    }
    
    /// Simulate connection attempt between two nodes
    async fn attempt_connection(&mut self, source: NodeId, target: NodeId) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Attempting connection: {:?} -> {:?}", source, target);
        
        let start_time = Instant::now();
        
        // Determine NAT types
        let source_nat = self.nodes[&source].nat_device.clone();
        let target_nat = self.nodes[&target].nat_device.clone();
        
        // Simulate connection based on NAT types
        let result = self.simulate_nat_traversal(source_nat, target_nat).await;
        
        let connection_result = ConnectionResult {
            success: result.success,
            establishment_time: start_time.elapsed(),
            traversal_method: result.method,
            error: result.error,
        };
        
        // Record statistics
        self.record_connection_result(&source, &target, &connection_result).await;
        
        // Log event
        let event = SimulationEvent::ConnectionCompleted {
            from: source,
            to: target,
            result: connection_result,
            timestamp: Instant::now(),
        };
        self.events.push(event);
        
        Ok(())
    }
    
    /// Simulate NAT traversal between two NAT types
    async fn simulate_nat_traversal(&self, source_nat: Option<NatId>, target_nat: Option<NatId>) -> TraversalResult {
        match (&source_nat, &target_nat) {
            (None, None) => {
                // Direct connection - no NAT
                TraversalResult {
                    success: true,
                    method: Some(TraversalMethod::Direct),
                    error: None,
                }
            }
            (Some(nat_id), None) | (None, Some(nat_id)) => {
                // One node behind NAT
                let nat_device = &self.nat_devices[nat_id];
                match nat_device.nat_type {
                    NatType::FullCone => TraversalResult {
                        success: true,
                        method: Some(TraversalMethod::FullConeHolePunch),
                        error: None,
                    },
                    NatType::Symmetric => TraversalResult {
                        success: false,
                        method: None,
                        error: Some("Symmetric NAT to public endpoint".to_string()),
                    },
                    _ => TraversalResult {
                        success: true,
                        method: Some(TraversalMethod::RestrictedConeHolePunch),
                        error: None,
                    },
                }
            }
            (Some(source_nat_id), Some(target_nat_id)) => {
                // Both nodes behind NAT - most complex case
                let source_nat = &self.nat_devices[source_nat_id];
                let target_nat = &self.nat_devices[target_nat_id];
                
                match (&source_nat.nat_type, &target_nat.nat_type) {
                    (NatType::FullCone, NatType::FullCone) => TraversalResult {
                        success: true,
                        method: Some(TraversalMethod::FullConeHolePunch),
                        error: None,
                    },
                    (NatType::Symmetric, NatType::Symmetric) => TraversalResult {
                        success: rand::random::<f64>() < 0.3, // 30% success rate for symmetric-to-symmetric
                        method: Some(TraversalMethod::SymmetricPrediction),
                        error: if rand::random::<f64>() < 0.7 {
                            Some("Symmetric NAT prediction failed".to_string())
                        } else {
                            None
                        },
                    },
                    _ => TraversalResult {
                        success: rand::random::<f64>() < 0.85, // 85% success rate for mixed types
                        method: Some(TraversalMethod::RestrictedConeHolePunch),
                        error: None,
                    },
                }
            }
        }
    }
    
    /// Record connection attempt result
    async fn record_connection_result(&mut self, source: &NodeId, target: &NodeId, result: &ConnectionResult) {
        // Update source node metrics
        if let Some(source_node) = self.nodes.get_mut(source) {
            source_node.metrics.connection_attempts += 1;
            if result.success {
                source_node.metrics.successful_connections += 1;
            } else {
                source_node.metrics.failed_connections += 1;
            }
            
            // Update average connection time
            let total_time = source_node.metrics.avg_connection_time * source_node.metrics.connection_attempts as u32
                + result.establishment_time;
            source_node.metrics.avg_connection_time = total_time / source_node.metrics.connection_attempts as u32;
        }
        
        // Update global statistics
        self.stats.total_attempts += 1;
        
        // Update success rate by NAT type combination
        let source_nat_type = self.get_node_nat_type(source);
        let target_nat_type = self.get_node_nat_type(target);
        
        if let (Some(source_type), Some(target_type)) = (source_nat_type, target_nat_type) {
            let key = (source_type, target_type);
            let current_rate = self.stats.success_by_nat_type.get(&key).unwrap_or(&0.0);
            let new_rate = if result.success {
                (*current_rate + 1.0) / 2.0
            } else {
                *current_rate / 2.0
            };
            self.stats.success_by_nat_type.insert(key, new_rate);
        }
    }
    
    /// Get NAT type for a node
    fn get_node_nat_type(&self, node_id: &NodeId) -> Option<NatType> {
        if let Some(node) = self.nodes.get(node_id) {
            if let Some(nat_id) = &node.nat_device {
                if let Some(nat_device) = self.nat_devices.get(nat_id) {
                    return Some(nat_device.nat_type.clone());
                }
            }
        }
        None
    }
    
    /// Run traffic simulation phase
    async fn run_traffic_phase(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Running traffic simulation phase");
        
        // Simulate data transfer over established connections
        let duration = Duration::from_secs(30);
        let start = Instant::now();
        
        while start.elapsed() < duration {
            // Simulate periodic traffic
            for (node_id, node) in &mut self.nodes {
                if node.state == NodeState::Active {
                    // Simulate sending data
                    let bytes = rand::random::<u16>() as u64 * 1000; // Random KB amounts
                    node.metrics.bytes_sent += bytes;
                }
            }
            
            sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
    
    /// Collect final simulation statistics
    async fn collect_final_stats(&mut self) {
        info!("Collecting final simulation statistics");
        
        self.stats.total_nodes = self.nodes.len();
        
        // Calculate overall success rate
        let total_successful: u64 = self.nodes.values()
            .map(|node| node.metrics.successful_connections)
            .sum();
        
        if self.stats.total_attempts > 0 {
            self.stats.success_rate = total_successful as f64 / self.stats.total_attempts as f64;
        }
        
        // Calculate average connection time
        let total_time: Duration = self.nodes.values()
            .map(|node| node.metrics.avg_connection_time)
            .sum();
        
        if self.stats.total_nodes > 0 {
            self.stats.avg_connection_time = total_time / self.stats.total_nodes as u32;
        }
    }
    
    /// Generate simulation report
    pub async fn generate_report(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut report = String::new();
        
        report.push_str("=== Network Simulation Report ===\n\n");
        report.push_str(&format!("Simulation Duration: {:?}\n", self.stats.start_time.elapsed()));
        report.push_str(&format!("Total Nodes: {}\n", self.stats.total_nodes));
        report.push_str(&format!("Total Connection Attempts: {}\n", self.stats.total_attempts));
        report.push_str(&format!("Overall Success Rate: {:.2}%\n", self.stats.success_rate * 100.0));
        report.push_str(&format!("Average Connection Time: {:?}\n\n", self.stats.avg_connection_time));
        
        report.push_str("=== Success Rates by NAT Type Combination ===\n");
        for ((source_nat, target_nat), rate) in &self.stats.success_by_nat_type {
            report.push_str(&format!("{:?} -> {:?}: {:.2}%\n", source_nat, target_nat, rate * 100.0));
        }
        
        report.push_str("\n=== Node Performance Summary ===\n");
        for (node_id, node) in &self.nodes {
            report.push_str(&format!("Node {}: {} attempts, {} successful, {:.2}% success rate\n",
                node_id.0,
                node.metrics.connection_attempts,
                node.metrics.successful_connections,
                if node.metrics.connection_attempts > 0 {
                    node.metrics.successful_connections as f64 / node.metrics.connection_attempts as f64 * 100.0
                } else {
                    0.0
                }
            ));
        }
        
        Ok(report)
    }
}

/// Result of a NAT traversal simulation
struct TraversalResult {
    success: bool,
    method: Option<TraversalMethod>,
    error: Option<String>,
}

impl SimulatedTopology {
    fn new() -> Self {
        Self {
            topology_type: TopologyType::Mesh,
            connections: HashMap::new(),
            routing: HashMap::new(),
            segments: HashMap::new(),
        }
    }
}

impl PartialEq for NodeState {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("nat_simulation={}", log_level))
        .init();
    
    info!("Starting NAT traversal network simulation");
    info!("Configuration: {} nodes, {:?} duration", args.nodes, Duration::from_secs(args.duration));
    
    // Parse NAT types
    let nat_types: Vec<NatType> = args.nat_types
        .split(',')
        .filter_map(|s| match s.trim() {
            "full-cone" => Some(NatType::FullCone),
            "restricted-cone" => Some(NatType::RestrictedCone),
            "port-restricted" => Some(NatType::PortRestricted),
            "symmetric" => Some(NatType::Symmetric),
            "carrier-grade" => Some(NatType::CarrierGrade),
            _ => None,
        })
        .collect();
    
    // Parse topology type
    let topology_type = match args.topology.as_str() {
        "mesh" => TopologyType::Mesh,
        "star" => TopologyType::Star,
        "hierarchical" => TopologyType::Hierarchical,
        "real-world" => TopologyType::RealWorld,
        _ => TopologyType::Mesh,
    };
    
    // Create simulation configuration
    let config = SimulationConfig {
        node_count: args.nodes,
        duration: Duration::from_secs(args.duration),
        nat_types,
        conditions: NetworkConditions {
            packet_loss_rate: if args.packet_loss { 0.01 } else { 0.0 },
            base_latency: if args.latency_sim { Duration::from_millis(50) } else { Duration::from_millis(10) },
            latency_jitter: Duration::from_millis(10),
            bandwidth_limit: None,
            congestion_factor: 1.0,
        },
        topology_type,
        output_dir: args.output,
        verbose: args.verbose,
    };
    
    // Create and run simulation
    let mut simulation = NetworkSimulation::new(config);
    simulation.initialize().await?;
    let stats = simulation.run().await?;
    
    // Generate and save report
    let report = simulation.generate_report().await?;
    println!("{}", report);
    
    // Save report to file
    tokio::fs::create_dir_all(&simulation.config.output_dir).await?;
    let report_path = format!("{}/simulation_report.txt", simulation.config.output_dir);
    tokio::fs::write(&report_path, &report).await?;
    
    info!("Simulation completed. Report saved to: {}", report_path);
    info!("Final statistics: {:.2}% success rate, {:?} avg connection time", 
          stats.success_rate * 100.0, stats.avg_connection_time);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_simulation_initialization() {
        let config = SimulationConfig {
            node_count: 5,
            duration: Duration::from_secs(10),
            nat_types: vec![NatType::FullCone, NatType::Symmetric],
            conditions: NetworkConditions {
                packet_loss_rate: 0.0,
                base_latency: Duration::from_millis(10),
                latency_jitter: Duration::from_millis(5),
                bandwidth_limit: None,
                congestion_factor: 1.0,
            },
            topology_type: TopologyType::Mesh,
            output_dir: "/tmp/sim_test".to_string(),
            verbose: false,
        };
        
        let mut simulation = NetworkSimulation::new(config);
        let result = simulation.initialize().await;
        
        assert!(result.is_ok());
        assert_eq!(simulation.nodes.len(), 5);
        assert_eq!(simulation.nat_devices.len(), 2);
    }
    
    #[tokio::test]
    async fn test_nat_traversal_simulation() {
        let config = SimulationConfig {
            node_count: 2,
            duration: Duration::from_secs(5),
            nat_types: vec![NatType::FullCone],
            conditions: NetworkConditions {
                packet_loss_rate: 0.0,
                base_latency: Duration::from_millis(10),
                latency_jitter: Duration::from_millis(5),
                bandwidth_limit: None,
                congestion_factor: 1.0,
            },
            topology_type: TopologyType::Mesh,
            output_dir: "/tmp/sim_test".to_string(),
            verbose: false,
        };
        
        let mut simulation = NetworkSimulation::new(config);
        simulation.initialize().await.unwrap();
        
        let nat_id = Some(NatId("nat_0".to_string()));
        let result = simulation.simulate_nat_traversal(nat_id.clone(), nat_id).await;
        
        assert!(result.success);
        assert!(matches!(result.method, Some(TraversalMethod::FullConeHolePunch)));
    }
    
    #[test]
    fn test_topology_types() {
        let mesh = TopologyType::Mesh;
        let star = TopologyType::Star;
        
        assert!(!matches!(mesh, TopologyType::Star));
        assert!(matches!(star, TopologyType::Star));
    }
}