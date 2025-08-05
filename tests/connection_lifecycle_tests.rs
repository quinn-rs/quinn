//! Connection lifecycle integration tests
//!
//! This test suite validates connection establishment, maintenance, and teardown
//! including error conditions, state transitions, and resource management.

use ant_quic::{
    auth::AuthConfig,
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{EndpointRole, PeerId},
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, RwLock},
    time::{Instant, sleep, timeout},
};

/// Connection lifecycle states
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    /// Initial state
    Idle,
    /// Connection attempt in progress
    Connecting,
    /// Connection established
    Connected,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
    /// Connection failed
    Failed(String),
}

/// Test harness for connection lifecycle
struct ConnectionLifecycleTest {
    node: Arc<QuicP2PNode>,
    peer_id: PeerId,
    state: Arc<RwLock<ConnectionState>>,
    events: Arc<Mutex<Vec<ConnectionEvent>>>,
    stats: ConnectionStats,
}

/// Connection statistics tracking
#[derive(Default)]
struct ConnectionStats {
    connection_attempts: Arc<AtomicU32>,
    successful_connections: Arc<AtomicU32>,
    failed_connections: Arc<AtomicU32>,
    bytes_sent: Arc<AtomicU32>,
    _bytes_received: Arc<AtomicU32>,
    reconnect_count: Arc<AtomicU32>,
}

/// Connection lifecycle events
#[derive(Debug, Clone)]
enum ConnectionEvent {
    StateChanged(ConnectionState),
    DataSent(()),
    _DataReceived(usize),
    Error(()),
    Reconnect,
}

impl ConnectionLifecycleTest {
    /// Create a new test harness
    async fn new(
        _bind_addr: SocketAddr,
        role: EndpointRole,
        bootstrap_nodes: Vec<SocketAddr>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

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

        let node =
            Arc::new(QuicP2PNode::new(config).await.map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?);

        Ok(Self {
            node,
            peer_id,
            state: Arc::new(RwLock::new(ConnectionState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
            stats: ConnectionStats::default(),
        })
    }

    /// Connect to a peer
    async fn connect(
        &self,
        target: PeerId,
        coordinator: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.set_state(ConnectionState::Connecting).await;
        self.stats
            .connection_attempts
            .fetch_add(1, Ordering::Relaxed);

        match self.node.connect_to_peer(target, coordinator).await {
            Ok(_addr) => {
                self.set_state(ConnectionState::Connected).await;
                self.stats
                    .successful_connections
                    .fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.set_state(ConnectionState::Failed(err_str.clone()))
                    .await;
                self.stats
                    .failed_connections
                    .fetch_add(1, Ordering::Relaxed);
                self.add_event(ConnectionEvent::Error(())).await;
                Err(err_str.into())
            }
        }
    }

    /// Send data to a peer
    async fn send_data(
        &self,
        target: &PeerId,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = self.state.read().await;
        if *state != ConnectionState::Connected {
            return Err("Not connected".into());
        }
        drop(state);

        self.node
            .send_to_peer(target, data)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
        self.stats
            .bytes_sent
            .fetch_add(data.len() as u32, Ordering::Relaxed);
        self.add_event(ConnectionEvent::DataSent(())).await;
        Ok(())
    }

    /// Close connection
    async fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.set_state(ConnectionState::Closing).await;

        // TODO: Implement actual connection close
        sleep(Duration::from_millis(100)).await;

        self.set_state(ConnectionState::Closed).await;
        Ok(())
    }

    /// Set connection state
    async fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.write().await;
        *state = new_state.clone();
        self.add_event(ConnectionEvent::StateChanged(new_state))
            .await;
    }

    /// Add event to history
    async fn add_event(&self, event: ConnectionEvent) {
        let mut events = self.events.lock().await;
        events.push(event);
    }

    /// Get current state
    async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// Simulate connection failure
    async fn simulate_failure(&self) {
        self.set_state(ConnectionState::Failed("Simulated failure".to_string()))
            .await;
    }

    /// Attempt reconnection
    async fn reconnect(
        &self,
        target: PeerId,
        coordinator: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stats.reconnect_count.fetch_add(1, Ordering::Relaxed);
        self.add_event(ConnectionEvent::Reconnect).await;
        self.connect(target, coordinator).await
    }
}

// ===== Connection Lifecycle Tests =====

#[tokio::test]
async fn test_basic_connection_lifecycle() {
    let _ = tracing_subscriber::fmt::try_init();

    // Create bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19000);
    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await
    .expect("Failed to create bootstrap");

    // Create two test nodes
    let node1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19001);
    let node1 =
        ConnectionLifecycleTest::new(node1_addr, EndpointRole::Client, vec![bootstrap_addr])
            .await
            .expect("Failed to create node1");

    let node2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19002);
    let node2 =
        ConnectionLifecycleTest::new(node2_addr, EndpointRole::Client, vec![bootstrap_addr])
            .await
            .expect("Failed to create node2");

    // Test state transitions
    assert_eq!(node1.get_state().await, ConnectionState::Idle);

    // Connect
    node1
        .connect(node2.peer_id, bootstrap_addr)
        .await
        .expect("Failed to connect");

    assert_eq!(node1.get_state().await, ConnectionState::Connected);

    // Send data
    node1
        .send_data(&node2.peer_id, b"Hello, World!")
        .await
        .expect("Failed to send data");

    assert_eq!(node1.stats.bytes_sent.load(Ordering::Relaxed), 13);

    // Close connection
    node1.close().await.expect("Failed to close");
    assert_eq!(node1.get_state().await, ConnectionState::Closed);

    // Verify events
    let events = node1.events.lock().await;
    assert!(events.len() >= 4); // Connecting, Connected, DataSent, Closing, Closed
}

#[tokio::test]
async fn test_connection_failure_recovery() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19100);
    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await
    .expect("Failed to create bootstrap");

    let node = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19101),
        EndpointRole::Client,
        vec![bootstrap_addr],
    )
    .await
    .expect("Failed to create node");

    // Try to connect to non-existent peer
    let fake_peer = PeerId([255; 32]);
    let result = node.connect(fake_peer, bootstrap_addr).await;

    assert!(result.is_err());
    assert!(matches!(node.get_state().await, ConnectionState::Failed(_)));
    assert_eq!(node.stats.failed_connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_reconnection_behavior() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19200);
    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await
    .expect("Failed to create bootstrap");

    let node1 = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19201),
        EndpointRole::Client,
        vec![bootstrap_addr],
    )
    .await
    .expect("Failed to create node1");

    let node2 = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19202),
        EndpointRole::Client,
        vec![bootstrap_addr],
    )
    .await
    .expect("Failed to create node2");

    // Initial connection
    node1
        .connect(node2.peer_id, bootstrap_addr)
        .await
        .expect("Failed to connect");

    // Simulate failure
    node1.simulate_failure().await;
    assert!(matches!(
        node1.get_state().await,
        ConnectionState::Failed(_)
    ));

    // Attempt reconnection
    node1
        .reconnect(node2.peer_id, bootstrap_addr)
        .await
        .expect("Failed to reconnect");

    assert_eq!(node1.get_state().await, ConnectionState::Connected);
    assert_eq!(node1.stats.reconnect_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_concurrent_connections() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19300);
    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await
    .expect("Failed to create bootstrap");

    // Create multiple nodes
    let mut nodes = Vec::new();
    for i in 0..5 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19301 + i);
        let node = ConnectionLifecycleTest::new(addr, EndpointRole::Client, vec![bootstrap_addr])
            .await
            .expect("Failed to create node");
        nodes.push(Arc::new(node));
    }

    // All nodes connect to first node concurrently
    let target = nodes[0].peer_id;
    let mut tasks = vec![];

    for node in nodes.iter().skip(1) {
        let node = Arc::clone(node);
        let bootstrap_addr_copy = bootstrap_addr;
        let task = tokio::spawn(async move { node.connect(target, bootstrap_addr_copy).await });
        tasks.push(task);
    }

    // Wait for all connections
    let mut successes = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    assert!(successes >= 3, "Most concurrent connections should succeed");
}

#[tokio::test]
async fn test_connection_timeout() {
    let _ = tracing_subscriber::fmt::try_init();

    let node = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19400),
        EndpointRole::Client,
        vec![], // No bootstrap nodes
    )
    .await
    .expect("Failed to create node");

    // Try to connect with invalid coordinator
    let fake_peer = PeerId([100; 32]);
    let fake_coordinator = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 99, 99)), 9999);

    let start = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        node.connect(fake_peer, fake_coordinator),
    )
    .await;

    assert!(result.is_err() || result.unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn test_data_transfer_states() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19500);
    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await
    .expect("Failed to create bootstrap");

    let node1 = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19501),
        EndpointRole::Client,
        vec![bootstrap_addr],
    )
    .await
    .expect("Failed to create node1");

    let node2 = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19502),
        EndpointRole::Client,
        vec![bootstrap_addr],
    )
    .await
    .expect("Failed to create node2");

    // Can't send data when not connected
    let result = node1.send_data(&node2.peer_id, b"test").await;
    assert!(result.is_err());

    // Connect first
    node1
        .connect(node2.peer_id, bootstrap_addr)
        .await
        .expect("Failed to connect");

    // Now sending should work
    node1
        .send_data(&node2.peer_id, b"test")
        .await
        .expect("Failed to send data");

    // Send multiple messages
    for i in 0..10 {
        let data = format!("Message {i}");
        node1
            .send_data(&node2.peer_id, data.as_bytes())
            .await
            .expect("Failed to send data");
    }

    let bytes_sent = node1.stats.bytes_sent.load(Ordering::Relaxed);
    assert!(bytes_sent > 100, "Should have sent multiple messages");
}

#[tokio::test]
async fn test_resource_cleanup() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19600);

    // Create nodes in a scope to test cleanup
    {
        let _bootstrap = ConnectionLifecycleTest::new(
            bootstrap_addr,
            EndpointRole::Server {
                can_coordinate: true,
            },
            vec![],
        )
        .await
        .expect("Failed to create bootstrap");

        let node = ConnectionLifecycleTest::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19601),
            EndpointRole::Client,
            vec![bootstrap_addr],
        )
        .await
        .expect("Failed to create node");

        // Create some connections
        for i in 0..3 {
            let peer_id = PeerId([i; 32]);
            let _ = node.connect(peer_id, bootstrap_addr).await;
        }

        // Close explicitly
        node.close().await.expect("Failed to close");
        assert_eq!(node.get_state().await, ConnectionState::Closed);
    }

    // Resources should be cleaned up after scope exit
    // Give some time for cleanup
    sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn test_state_machine_invariants() {
    let _ = tracing_subscriber::fmt::try_init();

    let node = ConnectionLifecycleTest::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19700),
        EndpointRole::Client,
        vec![],
    )
    .await
    .expect("Failed to create node");

    // Test invalid state transitions
    assert_eq!(node.get_state().await, ConnectionState::Idle);

    // Can't close when not connected
    node.close().await.expect("Close should be idempotent");

    // State should transition through Closing to Closed
    let events = node.events.lock().await;
    let state_changes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ConnectionEvent::StateChanged(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    // Verify state transition sequence
    assert!(state_changes.contains(&ConnectionState::Closing));
    assert!(state_changes.contains(&ConnectionState::Closed));
}

// ===== Helper Functions =====

/// Create a test environment with multiple nodes
async fn _create_test_cluster(
    num_nodes: usize,
) -> Result<(SocketAddr, Vec<Arc<ConnectionLifecycleTest>>), Box<dyn std::error::Error + Send + Sync>>
{
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20000);

    let _bootstrap = ConnectionLifecycleTest::new(
        bootstrap_addr,
        EndpointRole::Server {
            can_coordinate: true,
        },
        vec![],
    )
    .await?;

    let mut nodes = Vec::new();
    for i in 0..num_nodes {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20001 + i as u16);
        let node =
            ConnectionLifecycleTest::new(addr, EndpointRole::Client, vec![bootstrap_addr]).await?;
        nodes.push(Arc::new(node));
    }

    Ok((bootstrap_addr, nodes))
}
