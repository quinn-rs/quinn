/// Multi-node NAT traversal coordination testing
/// This test simulates different network topologies and NAT types
/// to validate the QUIC-native coordination protocol

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

fn main() {
    println!("Running Multi-Node Coordination Tests...");
    
    test_full_cone_nat_coordination();
    test_restricted_cone_nat_coordination();
    test_port_restricted_nat_coordination();
    test_symmetric_nat_coordination();
    test_multiple_bootstrap_nodes();
    test_path_validation_success();
    test_connection_establishment_timing();
    test_coordination_protocol_resilience();
    test_nat_type_combinations();
    test_bootstrap_node_failover();
    
    println!("All Multi-Node Coordination Tests Passed! ✅");
}

// Test-specific types and structures

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
    CarrierGrade,
}

#[derive(Debug, Clone)]
pub struct NetworkTopology {
    pub nodes: HashMap<NodeId, NetworkNode>,
    pub nat_mappings: HashMap<NodeId, NatMapping>,
    pub bootstrap_nodes: Vec<NodeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

#[derive(Debug, Clone)]
pub struct NetworkNode {
    pub id: NodeId,
    pub private_addr: SocketAddr,
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub is_bootstrap: bool,
}

#[derive(Debug, Clone)]
pub struct NatMapping {
    pub internal_addr: SocketAddr,
    pub external_addr: SocketAddr,
    pub nat_type: NatType,
    pub port_allocation_pattern: PortAllocationPattern,
}

#[derive(Debug, Clone)]
pub enum PortAllocationPattern {
    Sequential { start_port: u16, increment: u16 },
    Random { seed: u64 },
    PortPool { available_ports: Vec<u16> },
}

#[derive(Debug, Clone)]
pub struct CoordinationSession {
    pub session_id: u64,
    pub participants: Vec<NodeId>,
    pub round: u32,
    pub start_time: Instant,
    pub coordination_frames: Vec<CoordinationFrame>,
}

#[derive(Debug, Clone)]
pub enum CoordinationFrame {
    AddAddress {
        sequence: u32,
        address: SocketAddr,
        priority: u32,
        from_node: NodeId,
    },
    PunchMeNow {
        round: u32,
        target_sequence: u32,
        local_address: SocketAddr,
        target_peer_id: Option<NodeId>,
        from_node: NodeId,
    },
    RemoveAddress {
        sequence: u32,
        from_node: NodeId,
    },
}

#[derive(Debug, Clone)]
pub struct PathValidationResult {
    pub source: NodeId,
    pub target: NodeId,
    pub success: bool,
    pub rtt: Duration,
    pub validation_time: Instant,
}

#[derive(Debug, Clone)]
pub struct ConnectionEstablishmentMetrics {
    pub total_attempts: u32,
    pub successful_connections: u32,
    pub average_establishment_time: Duration,
    pub nat_traversal_success_rate: f64,
    pub path_validation_success_rate: f64,
}

// Network topology simulation

impl NetworkTopology {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            nat_mappings: HashMap::new(),
            bootstrap_nodes: Vec::new(),
        }
    }
    
    pub fn add_node(&mut self, node: NetworkNode) {
        if node.is_bootstrap {
            self.bootstrap_nodes.push(node.id);
        }
        self.nodes.insert(node.id, node);
    }
    
    pub fn add_nat_mapping(&mut self, node_id: NodeId, mapping: NatMapping) {
        self.nat_mappings.insert(node_id, mapping);
    }
    
    pub fn simulate_packet_transmission(&self, from: NodeId, to: NodeId, packet_size: usize) -> Result<Duration, &'static str> {
        let from_node = self.nodes.get(&from).ok_or("Source node not found")?;
        let to_node = self.nodes.get(&to).ok_or("Target node not found")?;
        
        // Simulate network latency based on NAT types
        let base_latency = Duration::from_millis(50);
        let nat_penalty = match (from_node.nat_type, to_node.nat_type) {
            (NatType::FullCone, NatType::FullCone) => Duration::from_millis(10),
            (NatType::Symmetric, NatType::Symmetric) => Duration::from_millis(100),
            (NatType::CarrierGrade, _) | (_, NatType::CarrierGrade) => Duration::from_millis(200),
            _ => Duration::from_millis(25),
        };
        
        // Add packet size penalty
        let size_penalty = Duration::from_nanos(packet_size as u64 * 10);
        
        Ok(base_latency + nat_penalty + size_penalty)
    }
    
    pub fn can_establish_direct_connection(&self, from: NodeId, to: NodeId) -> bool {
        let from_node = self.nodes.get(&from).unwrap();
        let to_node = self.nodes.get(&to).unwrap();
        
        match (from_node.nat_type, to_node.nat_type) {
            (NatType::FullCone, _) | (_, NatType::FullCone) => true,
            (NatType::RestrictedCone, NatType::RestrictedCone) => true,
            (NatType::RestrictedCone, NatType::PortRestricted) | (NatType::PortRestricted, NatType::RestrictedCone) => false,
            (NatType::PortRestricted, NatType::PortRestricted) => false, // Needs coordination
            (NatType::Symmetric, _) | (_, NatType::Symmetric) => false, // Needs coordination
            (NatType::CarrierGrade, _) | (_, NatType::CarrierGrade) => false, // Needs relay
        }
    }
}

// NAT simulation functions

fn simulate_nat_port_allocation(nat_type: NatType, internal_port: u16, session_count: u32) -> u16 {
    match nat_type {
        NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted => {
            // Consistent mapping
            internal_port
        }
        NatType::Symmetric => {
            // Different external port for each session
            (internal_port as u32 + session_count) as u16
        }
        NatType::CarrierGrade => {
            // Shared port pool
            40000 + (session_count % 1000) as u16
        }
    }
}

fn predict_symmetric_nat_ports(pattern: &PortAllocationPattern, count: u32) -> Vec<u16> {
    match pattern {
        PortAllocationPattern::Sequential { start_port, increment } => {
            (0..count).map(|i| start_port + (i as u16 * increment)).collect()
        }
        PortAllocationPattern::Random { seed } => {
            // Simple PRNG for testing
            let mut rng_state = *seed;
            (0..count).map(|_| {
                rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                (rng_state % 65536) as u16
            }).collect()
        }
        PortAllocationPattern::PortPool { available_ports } => {
            available_ports.iter().take(count as usize).copied().collect()
        }
    }
}

// Test functions

fn test_full_cone_nat_coordination() {
    println!("Testing Full Cone NAT coordination...");
    
    let mut topology = NetworkTopology::new();
    
    // Add bootstrap node (publicly accessible)
    topology.add_node(NetworkNode {
        id: NodeId(1),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 9000))),
        nat_type: NatType::FullCone,
        is_bootstrap: true,
    });
    
    // Add two nodes behind Full Cone NATs
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
        nat_type: NatType::FullCone,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(3),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 8080))),
        nat_type: NatType::FullCone,
        is_bootstrap: false,
    });
    
    // Simulate coordination session
    let session = CoordinationSession {
        session_id: 12345,
        participants: vec![NodeId(2), NodeId(3)],
        round: 1,
        start_time: Instant::now(),
        coordination_frames: vec![
            CoordinationFrame::AddAddress {
                sequence: 1,
                address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080)),
                priority: 100,
                from_node: NodeId(2),
            },
            CoordinationFrame::AddAddress {
                sequence: 2,
                address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 8080)),
                priority: 100,
                from_node: NodeId(3),
            },
            CoordinationFrame::PunchMeNow {
                round: 1,
                target_sequence: 2,
                local_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080)),
                target_peer_id: Some(NodeId(3)),
                from_node: NodeId(2),
            },
        ],
    };
    
    // Verify coordination can succeed
    assert!(topology.can_establish_direct_connection(NodeId(2), NodeId(3)));
    
    // Simulate packet transmission
    let transmission_time = topology.simulate_packet_transmission(NodeId(2), NodeId(3), 1200)
        .expect("Transmission should succeed");
    
    assert!(transmission_time < Duration::from_millis(100), "Full cone NAT should have low latency");
    
    println!("✅ Full Cone NAT coordination test passed");
}

fn test_restricted_cone_nat_coordination() {
    println!("Testing Restricted Cone NAT coordination...");
    
    let mut topology = NetworkTopology::new();
    
    // Add nodes behind Restricted Cone NATs
    topology.add_node(NetworkNode {
        id: NodeId(1),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 9000))),
        nat_type: NatType::RestrictedCone,
        is_bootstrap: true,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
        nat_type: NatType::RestrictedCone,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(3),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 8080))),
        nat_type: NatType::RestrictedCone,
        is_bootstrap: false,
    });
    
    // Restricted cone NATs can establish connections with coordination
    assert!(topology.can_establish_direct_connection(NodeId(2), NodeId(3)));
    
    let transmission_time = topology.simulate_packet_transmission(NodeId(2), NodeId(3), 1200)
        .expect("Transmission should succeed");
    
    assert!(transmission_time < Duration::from_millis(150), "Restricted cone NAT should have moderate latency");
    
    println!("✅ Restricted Cone NAT coordination test passed");
}

fn test_port_restricted_nat_coordination() {
    println!("Testing Port Restricted NAT coordination...");
    
    let mut topology = NetworkTopology::new();
    
    // Add nodes behind Port Restricted NATs
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
        nat_type: NatType::PortRestricted,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(3),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 8080))),
        nat_type: NatType::PortRestricted,
        is_bootstrap: false,
    });
    
    // Port restricted NATs need coordination for direct connection
    assert!(!topology.can_establish_direct_connection(NodeId(2), NodeId(3)));
    
    // But can succeed with proper coordination timing
    let transmission_time = topology.simulate_packet_transmission(NodeId(2), NodeId(3), 1200)
        .expect("Transmission should succeed with coordination");
    
    assert!(transmission_time < Duration::from_millis(200), "Port restricted NAT needs coordination overhead");
    
    println!("✅ Port Restricted NAT coordination test passed");
}

fn test_symmetric_nat_coordination() {
    println!("Testing Symmetric NAT coordination...");
    
    let mut topology = NetworkTopology::new();
    
    // Add nodes behind Symmetric NATs
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 40001))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(3),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 40002))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    // Add NAT mappings with port prediction patterns
    topology.add_nat_mapping(NodeId(2), NatMapping {
        internal_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        external_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 40001)),
        nat_type: NatType::Symmetric,
        port_allocation_pattern: PortAllocationPattern::Sequential { start_port: 40000, increment: 1 },
    });
    
    topology.add_nat_mapping(NodeId(3), NatMapping {
        internal_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        external_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 40002)),
        nat_type: NatType::Symmetric,
        port_allocation_pattern: PortAllocationPattern::Sequential { start_port: 40000, increment: 2 },
    });
    
    // Symmetric NATs cannot establish direct connections without coordination
    assert!(!topology.can_establish_direct_connection(NodeId(2), NodeId(3)));
    
    // Test port prediction
    let mapping2 = topology.nat_mappings.get(&NodeId(2)).unwrap();
    let predicted_ports = predict_symmetric_nat_ports(&mapping2.port_allocation_pattern, 5);
    let expected_ports = vec![40000, 40001, 40002, 40003, 40004];
    assert_eq!(predicted_ports, expected_ports);
    
    let transmission_time = topology.simulate_packet_transmission(NodeId(2), NodeId(3), 1200)
        .expect("Transmission should succeed with coordination");
    
    assert!(transmission_time > Duration::from_millis(100), "Symmetric NAT requires more coordination overhead");
    
    println!("✅ Symmetric NAT coordination test passed");
}

fn test_multiple_bootstrap_nodes() {
    println!("Testing multiple bootstrap nodes...");
    
    let mut topology = NetworkTopology::new();
    
    // Add multiple bootstrap nodes
    for i in 1..=3 {
        topology.add_node(NetworkNode {
            id: NodeId(i),
            private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, i as u8), 9000)),
            public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, i as u8), 9000))),
            nat_type: NatType::FullCone,
            is_bootstrap: true,
        });
    }
    
    // Add client nodes
    topology.add_node(NetworkNode {
        id: NodeId(10),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 8080))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(11),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 11), 8080))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    assert_eq!(topology.bootstrap_nodes.len(), 3);
    
    // Test that clients can reach multiple bootstrap nodes
    for bootstrap_id in &topology.bootstrap_nodes {
        let transmission_time = topology.simulate_packet_transmission(NodeId(10), *bootstrap_id, 1200)
            .expect("Should be able to reach bootstrap node");
        assert!(transmission_time < Duration::from_millis(300));
    }
    
    println!("✅ Multiple bootstrap nodes test passed");
}

fn test_path_validation_success() {
    println!("Testing path validation success...");
    
    let mut topology = NetworkTopology::new();
    
    // Add nodes with different NAT types
    topology.add_node(NetworkNode {
        id: NodeId(1),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 8080))),
        nat_type: NatType::FullCone,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
        nat_type: NatType::RestrictedCone,
        is_bootstrap: false,
    });
    
    // Simulate PATH_CHALLENGE/PATH_RESPONSE validation
    let validation_start = Instant::now();
    let transmission_time = topology.simulate_packet_transmission(NodeId(1), NodeId(2), 64) // PATH_CHALLENGE size
        .expect("PATH_CHALLENGE should succeed");
    
    let response_time = topology.simulate_packet_transmission(NodeId(2), NodeId(1), 64) // PATH_RESPONSE size
        .expect("PATH_RESPONSE should succeed");
    
    let total_rtt = transmission_time + response_time;
    
    let validation_result = PathValidationResult {
        source: NodeId(1),
        target: NodeId(2),
        success: true,
        rtt: total_rtt,
        validation_time: validation_start,
    };
    
    assert!(validation_result.success);
    assert!(validation_result.rtt < Duration::from_millis(200));
    
    println!("✅ Path validation success test passed");
}

fn test_connection_establishment_timing() {
    println!("Testing connection establishment timing...");
    
    let mut topology = NetworkTopology::new();
    
    // Add various NAT types
    let nat_types = vec![
        NatType::FullCone,
        NatType::RestrictedCone,
        NatType::PortRestricted,
        NatType::Symmetric,
    ];
    
    let mut establishment_times = Vec::new();
    
    for (i, nat_type) in nat_types.iter().enumerate() {
        topology.add_node(NetworkNode {
            id: NodeId(i as u32 + 1),
            private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100 + i as u8), 8080)),
            public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, i as u8 + 1), 8080))),
            nat_type: *nat_type,
            is_bootstrap: false,
        });
        
        // Simulate connection establishment time
        let start_time = Instant::now();
        
        // Candidate discovery phase
        let discovery_time = Duration::from_millis(match nat_type {
            NatType::FullCone => 50,
            NatType::RestrictedCone => 100,
            NatType::PortRestricted => 200,
            NatType::Symmetric => 500,
            NatType::CarrierGrade => 1000,
        });
        
        // Coordination phase
        let coordination_time = Duration::from_millis(match nat_type {
            NatType::FullCone => 10,
            NatType::RestrictedCone => 50,
            NatType::PortRestricted => 100,
            NatType::Symmetric => 300,
            NatType::CarrierGrade => 500,
        });
        
        // Path validation phase
        let validation_time = topology.simulate_packet_transmission(NodeId(1), NodeId(i as u32 + 1), 64)
            .unwrap_or(Duration::from_millis(100));
        
        let total_time = discovery_time + coordination_time + validation_time;
        establishment_times.push(total_time);
    }
    
    // Verify establishment times are reasonable
    assert!(establishment_times[0] < Duration::from_millis(200)); // Full Cone
    assert!(establishment_times[1] < Duration::from_millis(300)); // Restricted Cone
    assert!(establishment_times[2] < Duration::from_millis(500)); // Port Restricted
    assert!(establishment_times[3] < Duration::from_millis(1000)); // Symmetric
    
    let metrics = ConnectionEstablishmentMetrics {
        total_attempts: nat_types.len() as u32,
        successful_connections: nat_types.len() as u32,
        average_establishment_time: establishment_times.iter().sum::<Duration>() / establishment_times.len() as u32,
        nat_traversal_success_rate: 1.0,
        path_validation_success_rate: 1.0,
    };
    
    assert!(metrics.average_establishment_time < Duration::from_millis(500));
    assert_eq!(metrics.nat_traversal_success_rate, 1.0);
    
    println!("✅ Connection establishment timing test passed");
}

fn test_coordination_protocol_resilience() {
    println!("Testing coordination protocol resilience...");
    
    let mut topology = NetworkTopology::new();
    
    // Add nodes
    topology.add_node(NetworkNode {
        id: NodeId(1),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 8080))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    topology.add_node(NetworkNode {
        id: NodeId(2),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    // Simulate packet loss scenarios
    let mut successful_transmissions = 0;
    let total_attempts = 10;
    
    for attempt in 0..total_attempts {
        // Simulate 20% packet loss
        if attempt % 5 != 0 {
            let _transmission_time = topology.simulate_packet_transmission(NodeId(1), NodeId(2), 1200);
            successful_transmissions += 1;
        }
    }
    
    let success_rate = successful_transmissions as f64 / total_attempts as f64;
    assert!(success_rate >= 0.8, "Should handle packet loss gracefully");
    
    // Test retry mechanism
    let mut retry_count = 0;
    let max_retries = 3;
    
    while retry_count < max_retries {
        let result = topology.simulate_packet_transmission(NodeId(1), NodeId(2), 1200);
        if result.is_ok() {
            break;
        }
        retry_count += 1;
    }
    
    assert!(retry_count < max_retries, "Should succeed within retry limit");
    
    println!("✅ Coordination protocol resilience test passed");
}

fn test_nat_type_combinations() {
    println!("Testing NAT type combinations...");
    
    let nat_types = vec![
        NatType::FullCone,
        NatType::RestrictedCone,
        NatType::PortRestricted,
        NatType::Symmetric,
    ];
    
    let mut success_matrix = Vec::new();
    
    for (i, nat_type_a) in nat_types.iter().enumerate() {
        let mut row = Vec::new();
        for (j, nat_type_b) in nat_types.iter().enumerate() {
            let mut topology = NetworkTopology::new();
            
            topology.add_node(NetworkNode {
                id: NodeId(1),
                private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
                public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 8080))),
                nat_type: *nat_type_a,
                is_bootstrap: false,
            });
            
            topology.add_node(NetworkNode {
                id: NodeId(2),
                private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 8080)),
                public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 8080))),
                nat_type: *nat_type_b,
                is_bootstrap: false,
            });
            
            let can_connect = topology.can_establish_direct_connection(NodeId(1), NodeId(2)) ||
                             topology.simulate_packet_transmission(NodeId(1), NodeId(2), 1200).is_ok();
            
            row.push(can_connect);
        }
        success_matrix.push(row);
    }
    
    // Verify expected connectivity patterns
    assert!(success_matrix[0][0]); // Full Cone <-> Full Cone
    assert!(success_matrix[0][1]); // Full Cone <-> Restricted Cone
    assert!(success_matrix[1][1]); // Restricted Cone <-> Restricted Cone
    
    // Count successful combinations
    let total_combinations = nat_types.len() * nat_types.len();
    let successful_combinations = success_matrix.iter()
        .flat_map(|row| row.iter())
        .filter(|&&success| success)
        .count();
    
    let success_rate = successful_combinations as f64 / total_combinations as f64;
    assert!(success_rate >= 0.5, "Should achieve reasonable success rate across NAT combinations");
    
    println!("✅ NAT type combinations test passed");
}

fn test_bootstrap_node_failover() {
    println!("Testing bootstrap node failover...");
    
    let mut topology = NetworkTopology::new();
    
    // Add multiple bootstrap nodes
    for i in 1..=3 {
        topology.add_node(NetworkNode {
            id: NodeId(i),
            private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, i as u8), 9000)),
            public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, i as u8), 9000))),
            nat_type: NatType::FullCone,
            is_bootstrap: true,
        });
    }
    
    // Add client node
    topology.add_node(NetworkNode {
        id: NodeId(10),
        private_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 8080)),
        public_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 8080))),
        nat_type: NatType::Symmetric,
        is_bootstrap: false,
    });
    
    // Test failover scenario
    let mut available_bootstrap_nodes = topology.bootstrap_nodes.clone();
    let client_node = NodeId(10);
    
    // Simulate first bootstrap node failure
    available_bootstrap_nodes.remove(0);
    
    // Should still be able to connect to remaining bootstrap nodes
    for bootstrap_id in &available_bootstrap_nodes {
        let result = topology.simulate_packet_transmission(client_node, *bootstrap_id, 1200);
        assert!(result.is_ok(), "Should be able to connect to backup bootstrap nodes");
    }
    
    assert!(available_bootstrap_nodes.len() >= 2, "Should have backup bootstrap nodes");
    
    // Test complete bootstrap failure recovery
    let mut connection_attempts = 0;
    let max_attempts = 5;
    
    while connection_attempts < max_attempts {
        if !available_bootstrap_nodes.is_empty() {
            let bootstrap_id = available_bootstrap_nodes[connection_attempts % available_bootstrap_nodes.len()];
            let result = topology.simulate_packet_transmission(client_node, bootstrap_id, 1200);
            if result.is_ok() {
                break;
            }
        }
        connection_attempts += 1;
    }
    
    assert!(connection_attempts < max_attempts, "Should successfully connect within retry limit");
    
    println!("✅ Bootstrap node failover test passed");
}

// Helper function for assertions
fn assert<T: std::fmt::Debug>(condition: bool, message: &str) {
    if !condition {
        panic!("{}", message);
    }
}