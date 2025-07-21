//! NAT traversal scenario tests
//!
//! Tests various NAT type combinations and hole-punching scenarios

use ant_quic::{
    auth::AuthConfig,
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{
        EndpointRole, NatTraversalConfig, NatTraversalEndpoint, NatTraversalError,
        NatTraversalEvent, PeerId,
    },
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, mpsc},
    time::{sleep, timeout},
};
use tracing::{debug, info};

/// Simulated NAT types for testing
#[derive(Debug, Clone, Copy, PartialEq)]
enum NatType {
    /// No NAT - direct public IP
    None,
    /// Full Cone NAT - least restrictive
    FullCone,
    /// Restricted Cone NAT
    RestrictedCone,
    /// Port Restricted Cone NAT
    PortRestrictedCone,
    /// Symmetric NAT - most restrictive
    Symmetric,
    /// Carrier Grade NAT
    CarrierGrade,
}

impl NatType {
    /// Get expected success rate for NAT combination
    fn success_rate_with(&self, other: &NatType) -> f64 {
        use NatType::*;

        match (self, other) {
            (None, _) | (_, None) => 1.0,
            (FullCone, FullCone) => 1.0,
            (FullCone, RestrictedCone) | (RestrictedCone, FullCone) => 0.95,
            (FullCone, PortRestrictedCone) | (PortRestrictedCone, FullCone) => 0.90,
            (FullCone, Symmetric) | (Symmetric, FullCone) => 0.85,
            (RestrictedCone, RestrictedCone) => 0.90,
            (RestrictedCone, PortRestrictedCone) | (PortRestrictedCone, RestrictedCone) => 0.85,
            (RestrictedCone, Symmetric) | (Symmetric, RestrictedCone) => 0.70,
            (PortRestrictedCone, PortRestrictedCone) => 0.80,
            (PortRestrictedCone, Symmetric) | (Symmetric, PortRestrictedCone) => 0.60,
            (Symmetric, Symmetric) => 0.40,
            (CarrierGrade, _) | (_, CarrierGrade) => 0.30,
        }
    }

    /// Whether this NAT type requires relay fallback
    #[allow(dead_code)]
    fn requires_relay(&self, other: &NatType) -> bool {
        self.success_rate_with(other) < 0.50
    }
}

/// Test peer with simulated NAT
struct NatTestPeer {
    id: PeerId,
    node: Arc<QuicP2PNode>,
    nat_type: NatType,
    public_addr: SocketAddr,
    private_addr: SocketAddr,
    _event_rx: mpsc::UnboundedReceiver<NatTraversalEvent>,
    nat_state: Arc<Mutex<NatState>>,
}

/// NAT state tracking for realistic simulation
#[derive(Debug)]
struct NatState {
    /// Outbound connections (destination -> mapped port)
    outbound_mappings: HashMap<SocketAddr, u16>,
    /// Allowed inbound connections for restricted NATs
    allowed_sources: HashSet<IpAddr>,
    /// Port allocation counter for symmetric NAT
    next_port: u16,
    /// Connection timestamps for timeout simulation
    connection_times: HashMap<SocketAddr, Instant>,
    /// NAT mapping timeout (typically 30-300 seconds)
    mapping_timeout: Duration,
}

impl NatTestPeer {
    /// Create a new peer with simulated NAT
    async fn new(
        nat_type: NatType,
        private_port: u16,
        public_port: u16,
        bootstrap_nodes: Vec<SocketAddr>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        let private_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), private_port);

        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), public_port);

        // Determine role based on NAT type
        let role = match nat_type {
            NatType::None => EndpointRole::Server {
                can_coordinate: true,
            },
            _ => EndpointRole::Client,
        };

        let config = QuicNodeConfig {
            role,
            bootstrap_nodes,
            enable_coordinator: matches!(role, EndpointRole::Server { .. }),
            max_connections: 100,
            connection_timeout: Duration::from_secs(10),
            stats_interval: Duration::from_secs(5),
            auth_config: AuthConfig::default(),
            bind_addr: None,
        };

        let (_event_tx, _event_rx) = mpsc::unbounded_channel();

        // TODO: Configure NAT traversal event callback
        let node = Arc::new(QuicP2PNode::new(config).await?);

        let nat_state = Arc::new(Mutex::new(NatState {
            outbound_mappings: HashMap::new(),
            allowed_sources: HashSet::new(),
            next_port: 40000,
            connection_times: HashMap::new(),
            mapping_timeout: Duration::from_secs(120), // 2 minute timeout
        }));

        Ok(Self {
            id: peer_id,
            node,
            nat_type,
            public_addr,
            private_addr,
            _event_rx,
            nat_state,
        })
    }

    /// Simulate NAT behavior for connection attempts
    async fn simulate_nat_behavior(&self, remote_addr: SocketAddr, inbound: bool) -> Option<u16> {
        let mut state = self.nat_state.lock().await;

        // Clean up expired mappings
        let now = Instant::now();
        let timeout = state.mapping_timeout;
        state
            .connection_times
            .retain(|_addr, time| now.duration_since(*time) < timeout);

        match self.nat_type {
            NatType::None => {
                // No NAT - use original port
                Some(self.private_addr.port())
            }
            NatType::FullCone => {
                // Full Cone - same mapping for all destinations
                if inbound {
                    Some(self.public_addr.port())
                } else {
                    state
                        .outbound_mappings
                        .insert(remote_addr, self.public_addr.port());
                    state.connection_times.insert(remote_addr, now);
                    Some(self.public_addr.port())
                }
            }
            NatType::RestrictedCone => {
                // Restricted Cone - allows from IPs we've sent to
                if inbound {
                    if state.allowed_sources.contains(&remote_addr.ip()) {
                        Some(self.public_addr.port())
                    } else {
                        None
                    }
                } else {
                    state.allowed_sources.insert(remote_addr.ip());
                    state
                        .outbound_mappings
                        .insert(remote_addr, self.public_addr.port());
                    state.connection_times.insert(remote_addr, now);
                    Some(self.public_addr.port())
                }
            }
            NatType::PortRestrictedCone => {
                // Port Restricted - allows only from exact IP:port we've sent to
                if inbound {
                    if state.outbound_mappings.contains_key(&remote_addr) {
                        Some(self.public_addr.port())
                    } else {
                        None
                    }
                } else {
                    state
                        .outbound_mappings
                        .insert(remote_addr, self.public_addr.port());
                    state.connection_times.insert(remote_addr, now);
                    Some(self.public_addr.port())
                }
            }
            NatType::Symmetric => {
                // Symmetric - different port for each destination
                if inbound {
                    // Only allow from addresses we've connected to
                    state.outbound_mappings.get(&remote_addr).copied()
                } else {
                    // Allocate new port for this destination
                    let port = state.next_port;
                    state.next_port = state.next_port.wrapping_add(1);
                    state.outbound_mappings.insert(remote_addr, port);
                    state.connection_times.insert(remote_addr, now);
                    Some(port)
                }
            }
            NatType::CarrierGrade => {
                // CGNAT - very restrictive, often blocks P2P
                if inbound {
                    None // Usually blocks all inbound
                } else {
                    // Limited outbound with port restrictions
                    let port = 50000 + (state.next_port % 1000);
                    state.next_port = state.next_port.wrapping_add(1);
                    state.outbound_mappings.insert(remote_addr, port);
                    state.connection_times.insert(remote_addr, now);
                    Some(port)
                }
            }
        }
    }
}

/// NAT traversal test environment
struct NatTestEnvironment {
    peers: HashMap<String, NatTestPeer>,
    bootstrap_node: NatTestPeer,
}

impl NatTestEnvironment {
    /// Create a new NAT test environment
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create bootstrap node with public IP
        // Bootstrap nodes with Server role need at least one bootstrap address
        let bootstrap_addr = "127.0.0.1:9000".parse().unwrap();
        let bootstrap = NatTestPeer::new(NatType::None, 9000, 9000, vec![bootstrap_addr]).await?;

        Ok(Self {
            peers: HashMap::new(),
            bootstrap_node: bootstrap,
        })
    }

    /// Add a peer with specific NAT type
    async fn add_peer(
        &mut self,
        name: &str,
        nat_type: NatType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let private_port = 10000 + self.peers.len() as u16;
        let public_port = 20000 + self.peers.len() as u16;

        let peer = NatTestPeer::new(
            nat_type,
            private_port,
            public_port,
            vec![self.bootstrap_node.public_addr],
        )
        .await?;

        self.peers.insert(name.to_string(), peer);
        Ok(())
    }

    /// Test connection between two peers
    async fn test_connection(
        &self,
        peer1_name: &str,
        peer2_name: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let peer1 = self.peers.get(peer1_name).ok_or("Peer1 not found")?;
        let peer2 = self.peers.get(peer2_name).ok_or("Peer2 not found")?;

        // Check if NAT combination should work
        let _expected_success = peer1.nat_type.success_rate_with(&peer2.nat_type) > 0.5;

        // Attempt connection
        let result = timeout(
            Duration::from_secs(10),
            peer1
                .node
                .connect_to_peer(peer2.id, self.bootstrap_node.public_addr),
        )
        .await;

        match result {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }
}

// ===== NAT Traversal Scenario Tests =====

#[tokio::test]
async fn test_full_cone_to_full_cone() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    env.add_peer("peer1", NatType::FullCone).await.unwrap();
    env.add_peer("peer2", NatType::FullCone).await.unwrap();

    let success = env
        .test_connection("peer1", "peer2")
        .await
        .expect("Connection test failed");

    assert!(success, "Full Cone to Full Cone should always succeed");
}

#[tokio::test]
async fn test_symmetric_to_symmetric() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    env.add_peer("peer1", NatType::Symmetric).await.unwrap();
    env.add_peer("peer2", NatType::Symmetric).await.unwrap();

    let success = env
        .test_connection("peer1", "peer2")
        .await
        .expect("Connection test failed");

    // Symmetric to Symmetric has low success rate without relay
    if !success {
        println!("Symmetric NAT traversal failed as expected, would need relay");
    }
}

#[tokio::test]
async fn test_restricted_cone_combinations() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    // Test various restricted cone combinations
    let nat_types = [
        ("full", NatType::FullCone),
        ("restricted", NatType::RestrictedCone),
        ("port_restricted", NatType::PortRestrictedCone),
    ];

    for (name1, type1) in &nat_types {
        for (name2, type2) in &nat_types {
            env.add_peer(&format!("{}1", name1), *type1).await.unwrap();
            env.add_peer(&format!("{}2", name2), *type2).await.unwrap();

            let success = env
                .test_connection(&format!("{}1", name1), &format!("{}2", name2))
                .await
                .expect("Connection test failed");

            let expected = type1.success_rate_with(type2) > 0.8;

            println!(
                "{} to {} - Success: {}, Expected: {}",
                name1, name2, success, expected
            );
        }
    }
}

#[tokio::test]
async fn test_carrier_grade_nat() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    env.add_peer("cgnat_peer", NatType::CarrierGrade)
        .await
        .unwrap();
    env.add_peer("public_peer", NatType::None).await.unwrap();

    // CGNAT to public should work with relay
    let success = env
        .test_connection("cgnat_peer", "public_peer")
        .await
        .expect("Connection test failed");

    if !success {
        println!("CGNAT connection failed, relay would be required");
    }
}

#[tokio::test]
async fn test_simultaneous_connections() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    // Create multiple peers
    for i in 0..4 {
        let nat_type = match i % 3 {
            0 => NatType::FullCone,
            1 => NatType::RestrictedCone,
            _ => NatType::PortRestrictedCone,
        };
        env.add_peer(&format!("peer{}", i), nat_type).await.unwrap();
    }

    // All peers try to connect simultaneously
    let mut tasks = vec![];

    for i in 0..4 {
        for j in i + 1..4 {
            let peer1_name = format!("peer{}", i);
            let peer2_name = format!("peer{}", j);

            // Clone what we need for the async block
            let bootstrap_addr = env.bootstrap_node.public_addr;
            let peer1 = env.peers.get(&peer1_name).unwrap();
            let peer2 = env.peers.get(&peer2_name).unwrap();
            let peer1_node = Arc::clone(&peer1.node);
            let peer2_id = peer2.id;

            let task = tokio::spawn(async move {
                timeout(
                    Duration::from_secs(10),
                    peer1_node.connect_to_peer(peer2_id, bootstrap_addr),
                )
                .await
            });

            tasks.push(task);
        }
    }

    // Wait for all connection attempts
    let mut successes = 0;
    for task in tasks {
        if let Ok(Ok(Ok(_))) = task.await {
            successes += 1;
        }
    }

    println!("Simultaneous connections succeeded: {}/6", successes);
    assert!(
        successes >= 3,
        "At least half of connections should succeed"
    );
}

#[tokio::test]
async fn test_hole_punching_timing() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    env.add_peer("peer1", NatType::RestrictedCone)
        .await
        .unwrap();
    env.add_peer("peer2", NatType::RestrictedCone)
        .await
        .unwrap();

    let peer1 = env.peers.get("peer1").unwrap();
    let peer2 = env.peers.get("peer2").unwrap();

    // Start monitoring NAT traversal events
    let _events1 = Arc::new(Mutex::new(Vec::<NatTraversalEvent>::new()));
    let _events2 = Arc::new(Mutex::new(Vec::<NatTraversalEvent>::new()));

    // Track hole punching timing
    let _punch_times = Arc::new(Mutex::new(Vec::<Instant>::new()));

    // Both peers connect simultaneously for hole punching
    let bootstrap_addr = env.bootstrap_node.public_addr;
    let p1_node = Arc::clone(&peer1.node);
    let p2_node = Arc::clone(&peer2.node);
    let p1_id = peer1.id;
    let p2_id = peer2.id;

    let start = Instant::now();

    let connect1 = tokio::spawn(async move {
        let result = p1_node.connect_to_peer(p2_id, bootstrap_addr).await;
        let elapsed = start.elapsed();
        debug!("Peer1 connection attempt took {:?}", elapsed);
        result
    });

    let connect2 = tokio::spawn(async move {
        let result = p2_node.connect_to_peer(p1_id, bootstrap_addr).await;
        let elapsed = start.elapsed();
        debug!("Peer2 connection attempt took {:?}", elapsed);
        result
    });

    // At least one should succeed with proper hole punching
    let (r1, r2) = tokio::join!(connect1, connect2);

    let success = r1.unwrap().is_ok() || r2.unwrap().is_ok();
    assert!(
        success,
        "Hole punching should succeed with simultaneous connect"
    );

    // Verify timing was reasonable (should complete within 5 seconds)
    let total_time = start.elapsed();
    assert!(
        total_time < Duration::from_secs(5),
        "Hole punching took too long: {:?}",
        total_time
    );
}

// ===== Port Prediction Tests =====

#[tokio::test]
async fn test_symmetric_nat_port_prediction() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test port prediction accuracy for symmetric NATs
    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    env.add_peer("symmetric_peer", NatType::Symmetric)
        .await
        .unwrap();

    let peer = env.peers.get("symmetric_peer").unwrap();
    let nat_state = peer.nat_state.lock().await;

    // Simulate multiple connections to observe port allocation pattern
    let mut allocated_ports = Vec::new();

    for i in 0..5 {
        let dest_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)), 80);

        if let Some(port) = peer.simulate_nat_behavior(dest_addr, false).await {
            allocated_ports.push(port);
            debug!("Connection {} allocated port {}", i, port);
        }
    }

    drop(nat_state);

    // Analyze port allocation pattern
    if allocated_ports.len() >= 2 {
        let mut increments = Vec::new();
        for i in 1..allocated_ports.len() {
            let increment = allocated_ports[i] as i32 - allocated_ports[i - 1] as i32;
            increments.push(increment);
        }

        // Check if increments are consistent (linear prediction)
        let avg_increment = increments.iter().sum::<i32>() as f64 / increments.len() as f64;
        let variance = increments
            .iter()
            .map(|&x| (x as f64 - avg_increment).powi(2))
            .sum::<f64>()
            / increments.len() as f64;

        debug!(
            "Port allocation pattern - Average increment: {:.2}, Variance: {:.2}",
            avg_increment, variance
        );

        // For symmetric NAT, ports should increase consistently
        assert!(variance < 10.0, "Port allocation should be predictable");
    }
}

// ===== Relay Fallback Tests =====

#[tokio::test]
async fn test_relay_fallback() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut env = NatTestEnvironment::new()
        .await
        .expect("Failed to create test environment");

    // Create peers that will need relay
    env.add_peer("symmetric1", NatType::Symmetric)
        .await
        .unwrap();
    env.add_peer("symmetric2", NatType::Symmetric)
        .await
        .unwrap();

    // Add a relay-capable peer (usually a server with public IP)
    env.add_peer("relay", NatType::None).await.unwrap();

    // Connection should fail initially
    let direct_result = env
        .test_connection("symmetric1", "symmetric2")
        .await
        .expect("Connection test failed");

    if !direct_result {
        println!("Direct connection failed as expected, testing relay fallback");

        // Both peers should be able to connect to the relay
        let relay_conn1 = env
            .test_connection("symmetric1", "relay")
            .await
            .expect("Connection test failed");
        let relay_conn2 = env
            .test_connection("symmetric2", "relay")
            .await
            .expect("Connection test failed");

        assert!(relay_conn1, "Symmetric NAT should connect to public relay");
        assert!(relay_conn2, "Symmetric NAT should connect to public relay");

        // TODO: Implement actual relay message forwarding
        // In a real implementation, the relay would forward messages between the two peers
    }
}

// ===== Helper Functions =====

/// Simulate different NAT behaviors
#[allow(dead_code)]
fn simulate_nat_mapping(nat_type: NatType, internal_port: u16, dest_addr: SocketAddr) -> u16 {
    match nat_type {
        NatType::None | NatType::FullCone => internal_port,
        NatType::RestrictedCone | NatType::PortRestrictedCone => internal_port,
        NatType::Symmetric => {
            // Different port for each destination
            let hash = dest_addr.port() ^ (dest_addr.ip().to_string().len() as u16);
            30000 + (hash % 10000)
        }
        NatType::CarrierGrade => {
            // Multiple NAT layers
            40000 + (internal_port % 5000)
        }
    }
}
