//! Comprehensive ant-quic Connection Testing Suite
//!
//! This test suite investigates connection lifecycle and identifies why connections
//! close immediately after establishment in communitas-core P2P messaging tests.
//!
//! Based on: ANT_QUIC_COMPREHENSIVE_SPEC.md

use ant_quic::{
    auth::AuthConfig, EndpointRole, NatTraversalEvent, PeerId, QuicNodeConfig, QuicP2PNode,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Helper macro for error conversion from Box<dyn Error> to anyhow::Error
macro_rules! box_err {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::anyhow!("{}", e))
    };
}

/// Helper function to create a test node with default configuration
async fn create_test_node() -> anyhow::Result<QuicP2PNode> {
    let config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: false,
        max_connections: 100,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
        bind_addr: Some("127.0.0.1:0".parse()?),
    };

    QuicP2PNode::new(config).await.map_err(|e| anyhow::anyhow!("{}", e))
}

/// Extension trait for convenient QuicP2PNode operations
trait QuicNodeExt {
    fn local_addr(&self) -> anyhow::Result<SocketAddr>;
}

impl QuicNodeExt for QuicP2PNode {
    fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        let nat_endpoint = box_err!(self.get_nat_endpoint())?;
        let quinn_endpoint = nat_endpoint
            .get_quinn_endpoint()
            .ok_or_else(|| anyhow::anyhow!("No quinn endpoint"))?;
        Ok(quinn_endpoint.local_addr()?)
    }
}

// ============================================================================
// PHASE 1: CRITICAL TESTS - These are expected to reveal the bug
// ============================================================================

/// Test 2.4.2 - Endpoint Closure Timing (HIGHEST PRIORITY)
///
/// This test checks if send operations work immediately after connect or if there's
/// a timing issue. Tests by attempting send with progressively longer delays.
#[tokio::test]
async fn test_endpoint_closure_timing() -> anyhow::Result<()> {
    println!("\n=== Test 2.4.2: Endpoint Closure Timing ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    println!("Before connect - creating connection...");

    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    println!("After connect - Peer ID: {:?}", peer_id);

    // Try immediate send (no delay)
    println!("\nTest 1: Immediate send (0ms delay)");
    let result1 = node1.send_to_peer(&peer_id, b"test_immediate").await;
    println!("Send result: {:?}", result1.is_ok());
    if let Err(e) = &result1 {
        println!("Error: {}", e);
    }

    // Try with 10ms delay
    sleep(Duration::from_millis(10)).await;
    println!("\nTest 2: Send after 10ms");
    let result2 = node1.send_to_peer(&peer_id, b"test_10ms").await;
    println!("Send result: {:?}", result2.is_ok());
    if let Err(e) = &result2 {
        println!("Error: {}", e);
    }

    // Try with 100ms delay
    sleep(Duration::from_millis(90)).await;
    println!("\nTest 3: Send after 100ms total");
    let result3 = node1.send_to_peer(&peer_id, b"test_100ms").await;
    println!("Send result: {:?}", result3.is_ok());
    if let Err(e) = &result3 {
        println!("Error: {}", e);
    }

    // Summary
    if result1.is_ok() {
        println!("\n✅ Immediate send worked - no timing bug");
    } else if result2.is_ok() {
        println!("\n⚠️  Send requires ~10ms delay after connect");
    } else if result3.is_ok() {
        println!("\n⚠️  Send requires ~100ms delay after connect");
    } else {
        println!("\n❌ CRITICAL BUG: Send fails even after 100ms");
    }

    Ok(())
}

/// Test 2.1.3 - Immediate Send After Connect (HIGHEST PRIORITY)
///
/// Tests if send works without delay after connect. Expected to FAIL based on
/// current behavior showing connections close within 13 microseconds.
#[tokio::test]
async fn test_immediate_send_after_connect() -> anyhow::Result<()> {
    println!("\n=== Test 2.1.3: Immediate Send After Connect ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect and send immediately (no delay)
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    // CRITICAL: Send with NO delay after connect
    let data = b"Immediate message";
    let send_result = box_err!(node1.send_to_peer(&peer_id, data).await);

    match send_result {
        Ok(_) => {
            // Verify message is received
            let (_, received) = box_err!(node2.receive().await)?;
            assert_eq!(received, data);
            println!("✅ Immediate send succeeded");
        }
        Err(e) => {
            println!("❌ Immediate send failed: {}", e);
            println!("BUG CONFIRMED: Cannot send immediately after connect");
            return Err(e);
        }
    }

    Ok(())
}

/// Test 2.4.1 - Endpoint Stays Open (HIGHEST PRIORITY)
///
/// Verifies that connections can send messages after some time has elapsed.
/// Tests connection persistence over time.
#[tokio::test]
async fn test_endpoint_stays_open() -> anyhow::Result<()> {
    println!("\n=== Test 2.4.1: Endpoint Stays Open ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    println!("✅ Connection established");

    // Try send immediately
    let result1 = node1.send_to_peer(&peer_id, b"test1").await;
    println!("Immediate send: {}", if result1.is_ok() { "OK" } else { "FAILED" });

    // Wait 500ms and try again
    sleep(Duration::from_millis(500)).await;

    let result2 = box_err!(node1.send_to_peer(&peer_id, b"test2").await)?;
    println!("✅ Send succeeded after 500ms delay");

    // Verify message was received
    let (_, data) = box_err!(node2.receive().await)?;
    println!("✅ Message received: {} bytes", data.len());

    Ok(())
}

/// Test 4.2.1 - Inspect Connection State (HIGH PRIORITY - DIAGNOSTIC)
///
/// Tests connection state at various timing points to identify when issues occur.
#[tokio::test]
async fn test_connection_state_inspection() -> anyhow::Result<()> {
    println!("\n=== Test 4.2.1: Connection State Inspection ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    let nat_endpoint = box_err!(node1.get_nat_endpoint())?;
    let quinn_endpoint = nat_endpoint
        .get_quinn_endpoint()
        .ok_or_else(|| anyhow::anyhow!("No quinn endpoint"))?;

    println!("=== Before Connect ===");
    println!("Local addr: {:?}", quinn_endpoint.local_addr());

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    println!("\n=== After Connect (immediate) ===");
    println!("Peer ID: {:?}", peer_id);

    // Try immediate send
    let result1 = node1.send_to_peer(&peer_id, b"test_immediate").await;
    println!("Immediate send result: {}", if result1.is_ok() { "OK" } else { "FAILED" });

    // Wait 50ms
    sleep(Duration::from_millis(50)).await;

    println!("\n=== After 50ms ===");
    let result2 = node1.send_to_peer(&peer_id, b"test_50ms").await;
    println!("Send after 50ms: {}", if result2.is_ok() { "OK" } else { "FAILED" });

    // Summary
    println!("\n=== Summary ===");
    if result1.is_ok() {
        println!("✅ Connection works immediately");
    } else if result2.is_ok() {
        println!("⚠️  Connection requires delay to become usable");
    } else {
        println!("❌ Connection not working");
    }

    Ok(())
}

// ============================================================================
// PHASE 2: DIAGNOSTIC TIMING TESTS
// ============================================================================

/// Test 4.1.1 - Measure Connect-to-Send Timing
///
/// Measures timing characteristics to understand when connection becomes usable.
#[tokio::test]
async fn test_connect_send_timing() -> anyhow::Result<()> {
    println!("\n=== Test 4.1.1: Connect-to-Send Timing ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Measure time from connect to successful send
    let start = Instant::now();
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;
    let connect_time = start.elapsed();

    let send_start = Instant::now();
    let send_result = node1.send_to_peer(&peer_id, b"test").await;
    let send_time = send_start.elapsed();

    println!("Connect time: {:?}", connect_time);
    println!("Send time: {:?}", send_time);
    println!("Total time: {:?}", start.elapsed());

    match send_result {
        Ok(_) => println!("✅ Send succeeded"),
        Err(e) => println!("❌ Send failed: {}", e),
    }

    Ok(())
}

/// Test 4.1.2 - Event Polling Latency
///
/// Shows when events become available after connect.
#[tokio::test]
async fn test_event_polling_latency() -> anyhow::Result<()> {
    println!("\n=== Test 4.1.2: Event Polling Latency ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    let connect_time = Instant::now();
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;
    let connect_elapsed = connect_time.elapsed();

    // Poll immediately after connect
    let poll_start = Instant::now();
    let nat_endpoint = box_err!(node1.get_nat_endpoint())?;
    let events = box_err!(nat_endpoint.poll(Instant::now()))?;
    let poll_elapsed = poll_start.elapsed();

    println!("Connect took: {:?}", connect_elapsed);
    println!("Poll took: {:?}", poll_elapsed);
    println!("Events found: {}", events.len());
    println!("Events: {:?}", events);

    // Poll again after delay
    sleep(Duration::from_millis(100)).await;
    let events2 = box_err!(nat_endpoint.poll(Instant::now()))?;
    println!("Events after 100ms: {:?}", events2);

    Ok(())
}

// ============================================================================
// PHASE 3: BASIC VALIDATION TESTS
// ============================================================================

/// Test 2.1.1 - Single Connection Lifecycle
///
/// Basic test that all operations succeed and connection stays open throughout.
#[tokio::test]
async fn test_single_connection_lifecycle() -> anyhow::Result<()> {
    println!("\n=== Test 2.1.1: Single Connection Lifecycle ===");

    // SETUP
    let config1 = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: false,
        max_connections: 100,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
        bind_addr: Some("127.0.0.1:0".parse()?),
    };

    let config2 = config1.clone();

    let node1 = box_err!(QuicP2PNode::new(config1).await)?;
    let node2 = box_err!(QuicP2PNode::new(config2).await)?;

    let addr2 = node2.local_addr()?;

    // TEST: Connect node1 -> node2
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;
    assert!(peer_id != PeerId([0; 32]), "Valid peer ID returned");

    // VERIFY: Connection is active
    sleep(Duration::from_millis(100)).await;

    // TEST: Send message
    let data = b"Hello from node1";
    box_err!(node1.send_to_peer(&peer_id, data).await)?;

    // TEST: Receive message
    let (received_peer, received_data) = box_err!(node2.receive().await)?;
    assert_eq!(received_data, data, "Message received correctly");

    // TEST: Bidirectional - send back
    let response = b"Hello from node2";
    box_err!(node2.send_to_peer(&received_peer, response).await)?;

    let (resp_peer, resp_data) = box_err!(node1.receive().await)?;
    assert_eq!(resp_data, response, "Response received correctly");
    assert_eq!(resp_peer, peer_id, "Peer ID matches");

    println!("✅ All operations succeeded");

    Ok(())
}

/// Test 2.1.2 - Connection Persistence
///
/// Tests that connection stays open for multiple messages without reconnect.
#[tokio::test]
async fn test_connection_persistence() -> anyhow::Result<()> {
    println!("\n=== Test 2.1.2: Connection Persistence ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    // Multiple messages without reconnect
    for i in 0..10 {
        let msg = format!("Message {}", i);
        box_err!(node1.send_to_peer(&peer_id, msg.as_bytes()).await)?;

        let (_, data) = box_err!(node2.receive().await)?;
        assert_eq!(data, msg.as_bytes());

        // Small delay between messages
        sleep(Duration::from_millis(10)).await;
    }

    println!("✅ All 10 messages sent successfully");

    Ok(())
}

// ============================================================================
// PHASE 4: EVENT HANDLING TESTS
// ============================================================================

/// Test 2.3.1 - ConnectionEstablished Event
///
/// Verifies that ConnectionEstablished event appears with correct information.
#[tokio::test]
async fn test_connection_established_event() -> anyhow::Result<()> {
    println!("\n=== Test 2.3.1: ConnectionEstablished Event ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    // Poll for ConnectionEstablished event
    sleep(Duration::from_millis(100)).await;

    let nat_endpoint = box_err!(node1.get_nat_endpoint())?;
    let events = box_err!(nat_endpoint.poll(Instant::now()))?;

    let established = events.iter().find(|e| {
        matches!(e, NatTraversalEvent::ConnectionEstablished { peer_id: p, .. } if p == &peer_id)
    });

    assert!(established.is_some(), "ConnectionEstablished event found");

    if let Some(NatTraversalEvent::ConnectionEstablished { remote_address, .. }) = established {
        println!("Connection established to: {}", remote_address);
        assert_eq!(*remote_address, addr2, "Remote address matches");
    }

    println!("✅ Event verified successfully");

    Ok(())
}

/// Test 2.3.2 - ConnectionLost Event
///
/// Verifies that ConnectionLost event appears when peer disconnects.
#[tokio::test]
async fn test_connection_lost_event() -> anyhow::Result<()> {
    println!("\n=== Test 2.3.2: ConnectionLost Event ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;
    sleep(Duration::from_millis(100)).await;

    // Close node2 to trigger connection loss
    drop(node2);

    // Wait for connection loss detection
    sleep(Duration::from_millis(500)).await;

    // Poll for ConnectionLost event
    let nat_endpoint = box_err!(node1.get_nat_endpoint())?;
    let events = box_err!(nat_endpoint.poll(Instant::now()))?;

    let lost = events.iter().find(|e| {
        matches!(e, NatTraversalEvent::ConnectionLost { peer_id: p, .. } if p == &peer_id)
    });

    assert!(lost.is_some(), "ConnectionLost event found");

    if let Some(NatTraversalEvent::ConnectionLost { reason, .. }) = lost {
        println!("Connection lost: {}", reason);
    }

    println!("✅ Event verified successfully");

    Ok(())
}

// ============================================================================
// PHASE 5: ERROR HANDLING TESTS
// ============================================================================

/// Test 2.6.1 - Send to Disconnected Peer
///
/// Verifies that send_to_peer returns error for disconnected peer.
#[tokio::test]
async fn test_send_to_disconnected_peer() -> anyhow::Result<()> {
    println!("\n=== Test 2.6.1: Send to Disconnected Peer ===");

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = box_err!(node1.connect_to_bootstrap(addr2).await)?;

    // Close node2
    drop(node2);
    sleep(Duration::from_millis(200)).await;

    // Send to disconnected peer
    let result = node1.send_to_peer(&peer_id, b"test").await;

    // Should return error
    assert!(result.is_err(), "Send to disconnected peer should fail");

    if let Err(e) = result {
        println!("Error (expected): {}", e);
    }

    println!("✅ Error handling verified");

    Ok(())
}

/// Test 2.6.2 - Connect to Invalid Address
///
/// Verifies that connection fails or times out for invalid address.
#[tokio::test]
async fn test_connect_to_invalid_address() -> anyhow::Result<()> {
    println!("\n=== Test 2.6.2: Connect to Invalid Address ===");

    let node = create_test_node().await?;

    // Connect to non-existent address
    let invalid_addr: SocketAddr = "127.0.0.1:1".parse()?;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        node.connect_to_bootstrap(invalid_addr),
    )
    .await;

    // Should timeout or return error
    match result {
        Ok(Ok(_)) => panic!("Should not connect to invalid address"),
        Ok(Err(e)) => println!("Connection failed as expected: {}", e),
        Err(_) => println!("Connection timed out as expected"),
    }

    println!("✅ Error handling verified");

    Ok(())
}
