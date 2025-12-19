# ant-quic API Reference

This document provides a comprehensive API reference for ant-quic v0.13.0+.

## Table of Contents

1. [Primary API: P2pEndpoint](#primary-api-p2pendpoint)
2. [Configuration](#configuration)
3. [NAT Traversal](#nat-traversal)
4. [Transport Parameters](#transport-parameters)
5. [Extension Frames](#extension-frames)
6. [Events](#events)
7. [Error Handling](#error-handling)
8. [Code Examples](#code-examples)

## Primary API: P2pEndpoint

The primary entry point for all P2P operations. All nodes are symmetric - every node can both initiate and accept connections.

### Creating an Endpoint

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

// Simple endpoint
let config = P2pConfig::builder()
    .known_peer("quic.saorsalabs.com:9000".parse()?)
    .build()?;
let endpoint = P2pEndpoint::new(config).await?;

// With custom configuration
let config = P2pConfig::builder()
    .bind_addr("0.0.0.0:9000".parse()?)
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .max_connections(100)
    .connection_timeout(Duration::from_secs(30))
    .build()?;
let endpoint = P2pEndpoint::new(config).await?;
```

### Connecting to Peers

```rust
// Direct connection
let connection = endpoint.connect(peer_addr).await?;

// Via known peer (for NAT traversal coordination)
let connection = endpoint.connect_via_peer(peer_id, known_peer_addr).await?;
```

### Accepting Connections

```rust
// Accept incoming connections (all endpoints can accept)
while let Some(conn) = endpoint.accept().await {
    tokio::spawn(async move {
        handle_connection(conn).await;
    });
}
```

### Working with Streams

```rust
// Bidirectional stream
let (mut send, mut recv) = connection.open_bi().await?;
send.write_all(b"Hello").await?;
send.finish()?;
let response = recv.read_to_end(4096).await?;

// Unidirectional stream
let mut send = connection.open_uni().await?;
send.write_all(b"Data").await?;
send.finish()?;
```

## Configuration

### P2pConfig Builder

```rust
let config = P2pConfig::builder()
    .bind_addr(SocketAddr)          // Local address to bind
    .known_peer(SocketAddr)         // Known peer for discovery (repeatable)
    .nat(NatConfig)                 // NAT traversal configuration
    .pqc(PqcConfig)                 // Post-quantum crypto configuration
    .mtu(MtuConfig)                 // MTU configuration
    .max_connections(usize)         // Maximum concurrent connections
    .connection_timeout(Duration)   // Connection establishment timeout
    .idle_timeout(Duration)         // Idle connection timeout
    .build()?;
```

### NatConfig

```rust
pub struct NatConfig {
    pub max_candidates: usize,           // Max address candidates (default: 10)
    pub coordination_timeout: Duration,  // Hole punch timeout (default: 15s)
    pub discovery_timeout: Duration,     // Discovery timeout (default: 5s)
    pub enable_symmetric_nat: bool,      // Enable port prediction (default: true)
    pub hole_punch_retries: u32,         // Punch attempts (default: 5)
}
```

### PqcConfig

PQC is always enabled. These options tune PQC behavior:

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)                       // Enable ML-KEM-768 (default: true)
    .ml_dsa(true)                       // Enable ML-DSA-65 (default: true)
    .memory_pool_size(10)               // Buffer pool size (default: 10)
    .handshake_timeout_multiplier(1.5)  // Timeout multiplier (default: 1.5)
    .build()?;
```

### MtuConfig

```rust
pub struct MtuConfig {
    pub initial: u16,  // Initial MTU (default: 1200)
    pub min: u16,      // Minimum MTU (default: 1200)
    pub max: u16,      // Maximum MTU (default: 1500)
}
```

## NAT Traversal

### Address Discovery

```rust
// Connect to known peers and discover external address
endpoint.connect_bootstrap().await?;

// Get discovered external address
let external: Option<SocketAddr> = endpoint.external_address();

// Get all discovered addresses
let addresses: Vec<SocketAddr> = endpoint.discovered_addresses();

// Get local candidates
let candidates: Vec<CandidateAddress> = endpoint.get_local_candidates();
```

### CandidateAddress

```rust
pub struct CandidateAddress {
    pub addr: SocketAddr,
    pub source: CandidateSource,
    pub priority: u32,
}

pub enum CandidateSource {
    Local,      // Interface address
    Observed,   // Via OBSERVED_ADDRESS frame
    Predicted,  // Symmetric NAT port prediction
}
```

## Transport Parameters

### NAT Traversal Capability

| Parameter ID | Description |
|-------------|-------------|
| `0x3d7e9f0bca12fea6` | NAT traversal capability indicator |
| `0x3d7e9f0bca12fea8` | RFC-compliant frame format support |
| `0x9f81a176` | Address discovery configuration |

## Extension Frames

### ADD_ADDRESS Frame

Advertises address candidates to peer.

```
Type: 0x3d7e90 (IPv4), 0x3d7e91 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       IP Address (4/16)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Port (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### PUNCH_ME_NOW Frame

Coordinates hole punching timing.

```
Type: 0x3d7e92 (IPv4), 0x3d7e93 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Target IP Address (4/16)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Target Port (16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### REMOVE_ADDRESS Frame

```
Type: 0x3d7e94

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### OBSERVED_ADDRESS Frame

Reports observed external address to peer.

```
Type: 0x9f81a6 (IPv4), 0x9f81a7 (IPv6)

Format:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (i)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Observed IP Address (4/16)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Observed Port (16)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Events

### P2pEvent

```rust
pub enum P2pEvent {
    // Connection lifecycle
    Connected { peer_id: PeerId, addr: SocketAddr },
    Disconnected { peer_id: PeerId, reason: String },
    ConnectionFailed { peer_id: PeerId, reason: String },

    // Address discovery
    AddressDiscovered { addr: SocketAddr },
    AddressChanged { old: SocketAddr, new: SocketAddr },

    // NAT traversal
    HolePunchStarted { peer_id: PeerId },
    HolePunchSucceeded { peer_id: PeerId, addr: SocketAddr },
    HolePunchFailed { peer_id: PeerId, reason: String },

    // Candidates
    CandidatesDiscovered { peer_id: PeerId, count: usize },
}
```

### Event Handling

```rust
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, addr } => {
            println!("Connected to {} at {}", peer_id.to_hex(), addr);
        }
        P2pEvent::AddressDiscovered { addr } => {
            println!("External address: {}", addr);
        }
        P2pEvent::HolePunchSucceeded { peer_id, addr } => {
            println!("Direct connection to {}", peer_id.to_hex());
        }
        _ => {}
    }
}
```

## Error Handling

### EndpointError

```rust
pub enum EndpointError {
    BindFailed(std::io::Error),
    ConnectionFailed(String),
    Timeout,
    InvalidConfiguration(String),
    // ...
}
```

### NatTraversalError

```rust
pub enum NatTraversalError {
    NoViableCandidates,
    CoordinationTimeout,
    HolePunchFailed(String),
    // ...
}
```

## Code Examples

### Complete P2P Node

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent, NatConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure endpoint
    let config = P2pConfig::builder()
        .bind_addr("0.0.0.0:9000".parse()?)
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .nat(NatConfig {
            max_candidates: 15,
            coordination_timeout: Duration::from_secs(20),
            enable_symmetric_nat: true,
            ..Default::default()
        })
        .max_connections(100)
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    // Discover external address
    endpoint.connect_bootstrap().await?;
    if let Some(addr) = endpoint.external_address() {
        println!("External: {}", addr);
    }

    // Subscribe to events
    let mut events = endpoint.subscribe();
    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            println!("Event: {:?}", event);
        }
    });

    // Accept connections (all nodes can accept)
    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            // Handle streams
            while let Ok((send, recv)) = conn.accept_bi().await {
                // Echo server
                let data = recv.read_to_end(4096).await?;
                send.write_all(&data).await?;
                send.finish()?;
            }
            Ok::<_, anyhow::Error>(())
        });
    }

    Ok(())
}
```

### Statistics Monitoring

```rust
let stats = endpoint.stats();
println!("Active connections: {}", stats.active_connections);
println!("Discovered addresses: {}", stats.discovered_addresses);
println!("Successful punches: {}", stats.successful_hole_punches);
println!("Failed punches: {}", stats.failed_hole_punches);
println!("Bytes sent: {}", stats.bytes_sent);
println!("Bytes received: {}", stats.bytes_received);
```

## Removed API (v0.13.0)

The following types were **removed** in v0.13.0:

| Removed | Reason |
|---------|--------|
| `QuicNodeConfig` | Use `P2pConfig` |
| `QuicP2PNode` | Use `P2pEndpoint` |
| `EndpointRole` | All nodes are symmetric |
| `NatTraversalRole` | All nodes are symmetric |
| `PqcMode` | PQC always enabled |
| `HybridPreference` | No mode selection |
| `bootstrap_nodes` | Use `known_peer()` |

## Support

- GitHub Issues: https://github.com/dirvine/ant-quic/issues
- Documentation: https://docs.rs/ant-quic
- Examples: https://github.com/dirvine/ant-quic/tree/main/examples

