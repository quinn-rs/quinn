# ant-quic Comprehensive Testing Specification

**Purpose**: Investigate ant-quic v0.8.17 connection lifecycle and verify all methods required for P2P messaging work correctly.

**Context**: communitas-core P2P messaging tests reveal connections close immediately after establishment. This spec defines comprehensive testing to isolate the issue.

---

## 1. Core Requirements

### 1.1 Connection Lifecycle
- **Establish**: Connect from peer A to peer B
- **Stability**: Connection stays open for message exchange
- **Send/Receive**: Bidirectional message passing works
- **Close**: Clean connection shutdown
- **Reconnect**: Can reconnect after close

### 1.2 NAT Traversal
- **Negotiation**: NAT traversal capability negotiation completes
- **Candidates**: Local candidate discovery works
- **Direct**: Direct connection over localhost works
- **Simultaneous**: Both peers can connect simultaneously

### 1.3 Event Handling
- **ConnectionEstablished**: Fires when connection succeeds
- **ConnectionLost**: Fires when connection closes
- **TraversalFailed**: Fires when connection fails
- **Event Polling**: poll() returns events correctly

---

## 2. Test Matrix

### 2.1 Basic Connection Tests

#### Test 2.1.1: Single Connection Lifecycle
```rust
#[tokio::test]
async fn test_single_connection_lifecycle() -> anyhow::Result<()> {
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

    let node1 = QuicP2PNode::new(config1).await?;
    let node2 = QuicP2PNode::new(config2).await?;

    let addr1 = node1.get_nat_endpoint()?.get_quinn_endpoint().unwrap().local_addr()?;
    let addr2 = node2.get_nat_endpoint()?.get_quinn_endpoint().unwrap().local_addr()?;

    // TEST: Connect node1 -> node2
    let peer_id = node1.connect_to_bootstrap(addr2).await?;
    assert!(peer_id != PeerId([0; 32]), "Valid peer ID returned");

    // VERIFY: Connection is active
    sleep(Duration::from_millis(100)).await;

    // TEST: Send message
    let data = b"Hello from node1";
    node1.send_to_peer(&peer_id, data).await?;

    // TEST: Receive message
    let (received_peer, received_data) = node2.receive().await?;
    assert_eq!(received_data, data, "Message received correctly");

    // TEST: Bidirectional - send back
    let response = b"Hello from node2";
    node2.send_to_peer(&received_peer, response).await?;

    let (resp_peer, resp_data) = node1.receive().await?;
    assert_eq!(resp_data, response, "Response received correctly");
    assert_eq!(resp_peer, peer_id, "Peer ID matches");

    Ok(())
}
```

**Expected**: All operations succeed, connection stays open throughout test.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 2.1.2: Connection Persistence
```rust
#[tokio::test]
async fn test_connection_persistence() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // TEST: Multiple messages without reconnect
    for i in 0..10 {
        let msg = format!("Message {}", i);
        node1.send_to_peer(&peer_id, msg.as_bytes()).await?;

        let (_, data) = node2.receive().await?;
        assert_eq!(data, msg.as_bytes());

        // Small delay between messages
        sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}
```

**Expected**: All 10 messages send successfully without reconnection.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 2.1.3: Immediate Send After Connect
```rust
#[tokio::test]
async fn test_immediate_send_after_connect() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect and send immediately (no delay)
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // CRITICAL: Send with NO delay after connect
    let data = b"Immediate message";
    let send_result = node1.send_to_peer(&peer_id, data).await;

    match send_result {
        Ok(_) => {
            // Verify message is received
            let (_, received) = node2.receive().await?;
            assert_eq!(received, data);
            println!("✅ Immediate send succeeded");
        }
        Err(e) => {
            println!("❌ Immediate send failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
```

**Expected**: Message sends successfully immediately after connect.

**Actual Result**: ⏳ TO BE TESTED (likely to FAIL based on current behavior)

---

### 2.2 NAT Traversal Tests

#### Test 2.2.1: NAT Capability Negotiation
```rust
#[tokio::test]
async fn test_nat_capability_negotiation() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect and verify NAT negotiation
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // VERIFY: Check NAT traversal events
    let nat_endpoint = node1.get_nat_endpoint()?;
    let events = nat_endpoint.poll(Instant::now())?;

    let has_negotiation = events.iter().any(|e| matches!(e,
        NatTraversalEvent::ConnectionEstablished { .. }
    ));

    assert!(has_negotiation, "NAT negotiation event found");

    Ok(())
}
```

**Expected**: NAT negotiation event appears in poll results.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 2.2.2: Candidate Discovery
```rust
#[tokio::test]
async fn test_candidate_discovery() -> anyhow::Result<()> {
    // SETUP
    let node = create_test_node().await?;

    // TEST: Trigger candidate discovery
    let nat_endpoint = node.get_nat_endpoint()?;

    // Wait for discovery to complete
    sleep(Duration::from_secs(3)).await;

    // VERIFY: Poll for discovery events
    let events = nat_endpoint.poll(Instant::now())?;
    println!("Discovery events: {:?}", events);

    // Should have local candidates
    assert!(!events.is_empty(), "Candidate discovery produced events");

    Ok(())
}
```

**Expected**: Candidate discovery completes and produces events.

**Actual Result**: ⏳ TO BE TESTED

---

### 2.3 Event Handling Tests

#### Test 2.3.1: ConnectionEstablished Event
```rust
#[tokio::test]
async fn test_connection_established_event() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // VERIFY: Poll for ConnectionEstablished event
    sleep(Duration::from_millis(100)).await;

    let nat_endpoint = node1.get_nat_endpoint()?;
    let events = nat_endpoint.poll(Instant::now())?;

    let established = events.iter().find(|e| {
        matches!(e, NatTraversalEvent::ConnectionEstablished { peer_id: p, .. } if p == &peer_id)
    });

    assert!(established.is_some(), "ConnectionEstablished event found");

    if let Some(NatTraversalEvent::ConnectionEstablished { remote_address, .. }) = established {
        println!("Connection established to: {}", remote_address);
        assert_eq!(*remote_address, addr2, "Remote address matches");
    }

    Ok(())
}
```

**Expected**: ConnectionEstablished event appears with correct peer_id and remote_address.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 2.3.2: ConnectionLost Event
```rust
#[tokio::test]
async fn test_connection_lost_event() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;
    sleep(Duration::from_millis(100)).await;

    // Close node2 to trigger connection loss
    drop(node2);

    // Wait for connection loss detection
    sleep(Duration::from_millis(500)).await;

    // VERIFY: Poll for ConnectionLost event
    let nat_endpoint = node1.get_nat_endpoint()?;
    let events = nat_endpoint.poll(Instant::now())?;

    let lost = events.iter().find(|e| {
        matches!(e, NatTraversalEvent::ConnectionLost { peer_id: p, .. } if p == &peer_id)
    });

    assert!(lost.is_some(), "ConnectionLost event found");

    if let Some(NatTraversalEvent::ConnectionLost { reason, .. }) = lost {
        println!("Connection lost: {}", reason);
    }

    Ok(())
}
```

**Expected**: ConnectionLost event appears when peer disconnects.

**Actual Result**: ⏳ TO BE TESTED

---

### 2.4 Endpoint Lifecycle Tests

#### Test 2.4.1: Endpoint Stays Open
```rust
#[tokio::test]
async fn test_endpoint_stays_open() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // VERIFY: Endpoint is open
    let nat_endpoint = node1.get_nat_endpoint()?;
    let quinn_endpoint = nat_endpoint.get_quinn_endpoint().unwrap();

    // Check if endpoint is closed
    let is_closed = quinn_endpoint.close_reason().is_some();
    assert!(!is_closed, "Endpoint should be open after connect");

    // Wait and check again
    sleep(Duration::from_millis(500)).await;

    let is_closed_after = quinn_endpoint.close_reason().is_some();
    assert!(!is_closed_after, "Endpoint should still be open after delay");

    Ok(())
}
```

**Expected**: Endpoint stays open after connection.

**Actual Result**: ⏳ TO BE TESTED (likely to FAIL - endpoint closing prematurely)

---

#### Test 2.4.2: Endpoint Closure Timing
```rust
#[tokio::test]
async fn test_endpoint_closure_timing() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // TEST: Monitor endpoint state during connection
    let nat_endpoint = node1.get_nat_endpoint()?;
    let quinn_endpoint = nat_endpoint.get_quinn_endpoint().unwrap();

    println!("Before connect - endpoint closed: {:?}", quinn_endpoint.close_reason());

    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    println!("After connect - endpoint closed: {:?}", quinn_endpoint.close_reason());

    // Try immediate send
    let result = node1.send_to_peer(&peer_id, b"test").await;

    println!("After send attempt - endpoint closed: {:?}", quinn_endpoint.close_reason());
    println!("Send result: {:?}", result);

    Ok(())
}
```

**Expected**: Endpoint stays open through connect and send.

**Actual Result**: ⏳ TO BE TESTED

---

### 2.5 Concurrent Connection Tests

#### Test 2.5.1: Simultaneous Bidirectional Connect
```rust
#[tokio::test]
async fn test_simultaneous_bidirectional_connect() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr1 = node1.local_addr()?;
    let addr2 = node2.local_addr()?;

    // TEST: Both nodes connect to each other simultaneously
    let (result1, result2) = tokio::join!(
        node1.connect_to_bootstrap(addr2),
        node2.connect_to_bootstrap(addr1)
    );

    let peer_id1 = result1?;
    let peer_id2 = result2?;

    println!("Node1 connected to: {:?}", peer_id1);
    println!("Node2 connected to: {:?}", peer_id2);

    // VERIFY: Both connections work
    node1.send_to_peer(&peer_id1, b"From node1").await?;
    node2.send_to_peer(&peer_id2, b"From node2").await?;

    let (_, data1) = node2.receive().await?;
    let (_, data2) = node1.receive().await?;

    assert_eq!(data1, b"From node1");
    assert_eq!(data2, b"From node2");

    Ok(())
}
```

**Expected**: Both connections succeed, messages flow both ways.

**Actual Result**: ⏳ TO BE TESTED

---

### 2.6 Error Handling Tests

#### Test 2.6.1: Send to Disconnected Peer
```rust
#[tokio::test]
async fn test_send_to_disconnected_peer() -> anyhow::Result<()> {
    // SETUP
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    // Close node2
    drop(node2);
    sleep(Duration::from_millis(200)).await;

    // TEST: Send to disconnected peer
    let result = node1.send_to_peer(&peer_id, b"test").await;

    // VERIFY: Should return error
    assert!(result.is_err(), "Send to disconnected peer should fail");

    if let Err(e) = result {
        println!("Error (expected): {}", e);
    }

    Ok(())
}
```

**Expected**: send_to_peer returns error for disconnected peer.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 2.6.2: Connect to Invalid Address
```rust
#[tokio::test]
async fn test_connect_to_invalid_address() -> anyhow::Result<()> {
    // SETUP
    let node = create_test_node().await?;

    // TEST: Connect to non-existent address
    let invalid_addr = "127.0.0.1:1".parse()?;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        node.connect_to_bootstrap(invalid_addr)
    ).await;

    // VERIFY: Should timeout or return error
    match result {
        Ok(Ok(_)) => panic!("Should not connect to invalid address"),
        Ok(Err(e)) => println!("Connection failed as expected: {}", e),
        Err(_) => println!("Connection timed out as expected"),
    }

    Ok(())
}
```

**Expected**: Connection fails or times out.

**Actual Result**: ⏳ TO BE TESTED

---

## 3. saorsa-core Integration Tests

### 3.1 P2PNetworkNode Wrapper Tests

#### Test 3.1.1: P2PNetworkNode Basic Operations
```rust
#[tokio::test]
async fn test_p2p_network_node_basic() -> anyhow::Result<()> {
    use saorsa_core::transport::ant_quic_adapter::P2PNetworkNode;

    // SETUP
    let addr1: SocketAddr = "127.0.0.1:0".parse()?;
    let addr2: SocketAddr = "127.0.0.1:0".parse()?;

    let node1 = P2PNetworkNode::new(addr1).await?;
    let node2 = P2PNetworkNode::new(addr2).await?;

    let actual_addr2 = node2.actual_listening_address().await?;

    // TEST: Connect
    let peer_id = node1.connect_to_peer(actual_addr2).await?;

    // VERIFY: Peer is registered
    let peers = node1.get_connected_peers().await;
    assert_eq!(peers.len(), 1, "One peer registered");
    assert_eq!(peers[0].0, peer_id, "Correct peer ID");

    // TEST: Send
    node1.send_to_peer(&peer_id, b"test").await?;

    // TEST: Receive
    let (recv_peer, data) = node2.receive_from_any_peer().await?;
    assert_eq!(data, b"test");

    Ok(())
}
```

**Expected**: All wrapper methods work correctly.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 3.1.2: Connection Event Subscription
```rust
#[tokio::test]
async fn test_connection_event_subscription() -> anyhow::Result<()> {
    use saorsa_core::transport::ant_quic_adapter::{P2PNetworkNode, ConnectionEvent};

    // SETUP
    let node1 = P2PNetworkNode::new("127.0.0.1:0".parse()?).await?;
    let node2 = P2PNetworkNode::new("127.0.0.1:0".parse()?).await?;

    // Subscribe to events
    let mut event_rx = node1.subscribe_connection_events();

    let addr2 = node2.actual_listening_address().await?;

    // TEST: Connect (should trigger event)
    let peer_id = node1.connect_to_peer(addr2).await?;

    // VERIFY: Receive ConnectionEstablished event
    let event = tokio::time::timeout(
        Duration::from_secs(2),
        event_rx.recv()
    ).await??;

    match event {
        ConnectionEvent::Established { peer_id: p, remote_address } => {
            assert_eq!(p, peer_id, "Event peer ID matches");
            assert_eq!(remote_address, addr2, "Event address matches");
            println!("✅ ConnectionEstablished event received correctly");
        }
        _ => panic!("Expected ConnectionEstablished event"),
    }

    Ok(())
}
```

**Expected**: ConnectionEstablished event is received after connect.

**Actual Result**: ⏳ TO BE TESTED

---

### 3.2 DualStackNetworkNode Tests

#### Test 3.2.1: DualStack Basic Operations
```rust
#[tokio::test]
async fn test_dualstack_basic() -> anyhow::Result<()> {
    use saorsa_core::transport::ant_quic_adapter::DualStackNetworkNode;

    // SETUP
    let v4_addr1 = Some("127.0.0.1:0".parse()?);
    let v4_addr2 = Some("127.0.0.1:0".parse()?);

    let node1 = DualStackNetworkNode::new(None, v4_addr1).await?;
    let node2 = DualStackNetworkNode::new(None, v4_addr2).await?;

    let addrs2 = node2.local_addrs().await?;
    assert!(!addrs2.is_empty(), "Node2 has listening addresses");

    // TEST: Happy Eyeballs connect
    let peer_id = node1.connect_happy_eyeballs(&addrs2).await?;

    // TEST: Send
    node1.send_to_peer(&peer_id, b"test").await?;

    // TEST: Receive
    let (recv_peer, data) = node2.receive_any().await?;
    assert_eq!(data, b"test");

    Ok(())
}
```

**Expected**: DualStack operations work correctly.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 3.2.2: DualStack Event Merging
```rust
#[tokio::test]
async fn test_dualstack_event_merging() -> anyhow::Result<()> {
    use saorsa_core::transport::ant_quic_adapter::{DualStackNetworkNode, ConnectionEvent};

    // SETUP
    let node1 = DualStackNetworkNode::new(
        None,
        Some("127.0.0.1:0".parse()?)
    ).await?;

    let node2 = DualStackNetworkNode::new(
        None,
        Some("127.0.0.1:0".parse()?)
    ).await?;

    // Subscribe to merged events
    let mut event_rx = node1.subscribe_connection_events();

    let addrs2 = node2.local_addrs().await?;

    // TEST: Connect
    let peer_id = node1.connect_happy_eyeballs(&addrs2).await?;

    // VERIFY: Event received through merged channel
    let event = tokio::time::timeout(
        Duration::from_secs(2),
        event_rx.recv()
    ).await??;

    assert!(matches!(event, ConnectionEvent::Established { .. }),
            "Event received through merged channel");

    Ok(())
}
```

**Expected**: Events from IPv4 node appear in merged channel.

**Actual Result**: ⏳ TO BE TESTED

---

## 4. Diagnostic Tests

### 4.1 Timing Analysis

#### Test 4.1.1: Measure Connect-to-Send Timing
```rust
#[tokio::test]
async fn test_connect_send_timing() -> anyhow::Result<()> {
    use std::time::Instant;

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // MEASURE: Time from connect to successful send
    let start = Instant::now();
    let peer_id = node1.connect_to_bootstrap(addr2).await?;
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
```

**Expected**: Timing data shows how long connection establishment takes.

**Actual Result**: ⏳ TO BE TESTED

---

#### Test 4.1.2: Event Polling Latency
```rust
#[tokio::test]
async fn test_event_polling_latency() -> anyhow::Result<()> {
    use std::time::Instant;

    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    let connect_time = Instant::now();
    let peer_id = node1.connect_to_bootstrap(addr2).await?;
    let connect_elapsed = connect_time.elapsed();

    // Poll immediately after connect
    let poll_start = Instant::now();
    let nat_endpoint = node1.get_nat_endpoint()?;
    let events = nat_endpoint.poll(Instant::now())?;
    let poll_elapsed = poll_start.elapsed();

    println!("Connect took: {:?}", connect_elapsed);
    println!("Poll took: {:?}", poll_elapsed);
    println!("Events found: {}", events.len());
    println!("Events: {:?}", events);

    // Poll again after delay
    sleep(Duration::from_millis(100)).await;
    let events2 = nat_endpoint.poll(Instant::now())?;
    println!("Events after 100ms: {:?}", events2);

    Ok(())
}
```

**Expected**: Shows when events become available after connect.

**Actual Result**: ⏳ TO BE TESTED

---

### 4.2 Connection State Inspection

#### Test 4.2.1: Inspect Connection State
```rust
#[tokio::test]
async fn test_connection_state_inspection() -> anyhow::Result<()> {
    let node1 = create_test_node().await?;
    let node2 = create_test_node().await?;
    let addr2 = node2.local_addr()?;

    // Get NAT endpoint before connect
    let nat_endpoint = node1.get_nat_endpoint()?;
    let quinn_endpoint = nat_endpoint.get_quinn_endpoint().unwrap();

    println!("=== Before Connect ===");
    println!("Endpoint closed: {:?}", quinn_endpoint.close_reason());
    println!("Local addr: {:?}", quinn_endpoint.local_addr());

    // Connect
    let peer_id = node1.connect_to_bootstrap(addr2).await?;

    println!("\n=== After Connect (immediate) ===");
    println!("Endpoint closed: {:?}", quinn_endpoint.close_reason());
    println!("Peer ID: {:?}", peer_id);

    // Wait and check
    sleep(Duration::from_millis(50)).await;

    println!("\n=== After 50ms ===");
    println!("Endpoint closed: {:?}", quinn_endpoint.close_reason());

    // Try send
    let send_result = node1.send_to_peer(&peer_id, b"test").await;

    println!("\n=== After Send Attempt ===");
    println!("Endpoint closed: {:?}", quinn_endpoint.close_reason());
    println!("Send result: {:?}", send_result);

    Ok(())
}
```

**Expected**: Shows exact point where endpoint closes.

**Actual Result**: ⏳ TO BE TESTED

---

## 5. Test Execution Plan

### Phase 1: Basic Validation (Priority: HIGH)
1. Test 2.1.1 - Single Connection Lifecycle
2. Test 2.1.3 - Immediate Send After Connect ⚠️ (critical)
3. Test 2.4.1 - Endpoint Stays Open ⚠️ (critical)
4. Test 2.4.2 - Endpoint Closure Timing ⚠️ (critical)

### Phase 2: Diagnostic Analysis (Priority: HIGH)
1. Test 4.1.1 - Measure Connect-to-Send Timing
2. Test 4.1.2 - Event Polling Latency
3. Test 4.2.1 - Inspect Connection State

### Phase 3: saorsa-core Integration (Priority: MEDIUM)
1. Test 3.1.1 - P2PNetworkNode Basic Operations
2. Test 3.1.2 - Connection Event Subscription
3. Test 3.2.1 - DualStack Basic Operations

### Phase 4: Advanced Scenarios (Priority: LOW)
1. Test 2.1.2 - Connection Persistence
2. Test 2.2.1 - NAT Capability Negotiation
3. Test 2.5.1 - Simultaneous Bidirectional Connect

---

## 6. Test Harness

### Helper Functions
```rust
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

    QuicP2PNode::new(config).await.map_err(Into::into)
}

trait QuicNodeExt {
    fn local_addr(&self) -> anyhow::Result<SocketAddr>;
}

impl QuicNodeExt for QuicP2PNode {
    fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        self.get_nat_endpoint()?
            .get_quinn_endpoint()
            .ok_or_else(|| anyhow::anyhow!("No quinn endpoint"))?
            .local_addr()
            .map_err(Into::into)
    }
}
```

### Test File Structure
```
communitas-core/tests/
├── ant_quic_comprehensive/
│   ├── mod.rs                    # Test harness and helpers
│   ├── basic_connection.rs       # Tests 2.1.x
│   ├── nat_traversal.rs          # Tests 2.2.x
│   ├── event_handling.rs         # Tests 2.3.x
│   ├── endpoint_lifecycle.rs     # Tests 2.4.x ⚠️ CRITICAL
│   ├── concurrent.rs             # Tests 2.5.x
│   ├── error_handling.rs         # Tests 2.6.x
│   ├── saorsa_integration.rs     # Tests 3.x
│   └── diagnostics.rs            # Tests 4.x ⚠️ CRITICAL
```

---

## 7. Expected Failures

Based on current communitas-core P2P messaging test results, we expect:

### ❌ Test 2.1.3 - Immediate Send After Connect
**Reason**: Current logs show connection closes within 13 microseconds of establishment.

### ❌ Test 2.4.1 - Endpoint Stays Open
**Reason**: "Endpoint closed" error appears in logs.

### ❌ Test 2.4.2 - Endpoint Closure Timing
**Reason**: Will reveal exact timing of endpoint closure.

### ⚠️ Test 3.1.2 - Connection Event Subscription
**Reason**: May work but reveal timing issues with event polling.

---

## 8. Success Criteria

### Minimum Viable (MVP):
1. ✅ Test 2.1.1 passes - basic connection and message exchange works
2. ✅ Test 2.1.3 passes - immediate send after connect works
3. ✅ Test 2.4.1 passes - endpoint stays open throughout test

### Full Success:
1. All Phase 1-3 tests pass
2. Connection lifecycle events work correctly
3. No "Endpoint closed" errors
4. No "Temporary peer ID" warnings

### Diagnostic Success:
1. Test 4.2.1 reveals exact point of endpoint closure
2. Test 4.1.1 shows timing characteristics
3. Can reproduce communitas-core issue in isolation

---

## 9. Next Steps

1. **Create test file**: `communitas-core/tests/ant_quic_comprehensive.rs`
2. **Run Phase 1 tests**: Identify which tests fail
3. **Run diagnostic tests**: Understand timing and state transitions
4. **Document findings**: Update this spec with actual results
5. **File ant-quic issue**: If bug confirmed, report to ant-quic repository
6. **Implement workaround**: If ant-quic limitation, adapt saorsa-core

---

## 10. Investigation Questions

### Connection Lifecycle:
- ❓ Does `connect_to_bootstrap()` wait for handshake completion?
- ❓ Is connection immediately usable after `Ok()` return?
- ❓ What causes "Endpoint closed" error?

### Event Timing:
- ❓ When does `ConnectionEstablished` event become available?
- ❓ Is there a delay between connection and event?
- ❓ Can events be missed if not polling frequently?

### Peer ID:
- ❓ Why are "temporary peer IDs" being generated?
- ❓ What's the difference between persistent and temporary IDs?
- ❓ Does temporary ID indicate incomplete handshake?

### Endpoint Management:
- ❓ What causes endpoint to close automatically?
- ❓ Is there an idle timeout even for active connections?
- ❓ Can endpoint be kept alive explicitly?

---

**Status**: Specification Complete - Ready for Implementation
**Priority**: HIGH - Blocking P2P messaging functionality
**Estimated Effort**: 4-6 hours for complete test implementation
**Expected Outcome**: Identify root cause of immediate connection closure

---

**Created**: 2025-10-02
**By**: Claude (Comprehensive Investigation Spec)
**Purpose**: Isolate ant-quic connection closure issue blocking communitas-core P2P messaging
