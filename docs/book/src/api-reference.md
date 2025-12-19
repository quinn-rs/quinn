# API Reference

This page provides a comprehensive reference for ant-quic's public API in v0.13.0+.

## Primary API: P2pEndpoint

The main entry point for all P2P operations.

### Creating an Endpoint

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
```

### P2pEndpoint Methods

#### Identity

```rust
// Get the local peer ID (derived from Ed25519 public key)
let peer_id: PeerId = endpoint.peer_id();

// Get the peer ID as hex string
let hex: String = peer_id.to_hex();
```

#### Address Discovery

```rust
// Connect to known peers and discover external address
endpoint.connect_bootstrap().await?;

// Get the discovered external address
let external: Option<SocketAddr> = endpoint.external_address();

// Get all discovered addresses
let addresses: Vec<SocketAddr> = endpoint.discovered_addresses();
```

#### Connections

```rust
// Connect to a peer by address
let connection = endpoint.connect("192.168.1.100:9000".parse()?).await?;

// Connect to a peer by ID through a known peer
let connection = endpoint.connect_via_peer(peer_id, known_peer_addr).await?;

// Accept incoming connections
while let Some(conn) = endpoint.accept().await {
    // Handle connection
}

// Close all connections
endpoint.close_all_connections().await;
```

#### Events

```rust
// Subscribe to P2P events
let mut events = endpoint.subscribe();

while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, addr } => { ... }
        P2pEvent::Disconnected { peer_id, reason } => { ... }
        P2pEvent::AddressDiscovered { addr } => { ... }
        // ... more events
    }
}
```

#### Statistics

```rust
// Get endpoint statistics
let stats: EndpointStats = endpoint.stats();
println!("Active connections: {}", stats.active_connections);
println!("Discovered addresses: {}", stats.discovered_addresses);
```

## Configuration Types

### P2pConfig

Builder pattern for endpoint configuration.

```rust
let config = P2pConfig::builder()
    .bind_addr("0.0.0.0:9000".parse()?)
    .known_peer("peer.example.com:9000".parse()?)
    .nat(NatConfig { ... })
    .pqc(PqcConfig::builder().build()?)
    .mtu(MtuConfig { ... })
    .max_connections(100)
    .connection_timeout(Duration::from_secs(30))
    .idle_timeout(Duration::from_secs(60))
    .build()?;
```

### NatConfig

NAT traversal configuration.

```rust
pub struct NatConfig {
    pub max_candidates: usize,
    pub coordination_timeout: Duration,
    pub discovery_timeout: Duration,
    pub enable_symmetric_nat: bool,
    pub hole_punch_retries: u32,
}
```

### PqcConfig

Post-quantum cryptography configuration (cannot disable PQC).

```rust
let pqc = PqcConfig::builder()
    .ml_kem(true)      // ML-KEM-768
    .ml_dsa(true)      // ML-DSA-65
    .memory_pool_size(10)
    .handshake_timeout_multiplier(1.5)
    .build()?;
```

### MtuConfig

MTU configuration for PQC overhead.

```rust
pub struct MtuConfig {
    pub initial: u16,
    pub min: u16,
    pub max: u16,
}
```

## Event Types

### P2pEvent

Events emitted by the endpoint.

```rust
pub enum P2pEvent {
    // Connection events
    Connected { peer_id: PeerId, addr: SocketAddr },
    Disconnected { peer_id: PeerId, reason: String },
    ConnectionFailed { peer_id: PeerId, reason: String },

    // Address discovery events
    AddressDiscovered { addr: SocketAddr },
    AddressChanged { old: SocketAddr, new: SocketAddr },

    // NAT traversal events
    HolePunchStarted { peer_id: PeerId },
    HolePunchSucceeded { peer_id: PeerId, addr: SocketAddr },
    HolePunchFailed { peer_id: PeerId, reason: String },

    // Candidate events
    CandidatesDiscovered { peer_id: PeerId, count: usize },
}
```

## Identity Types

### PeerId

Peer identity derived from Ed25519 public key.

```rust
use ant_quic::PeerId;

// Create from hex string
let peer_id = PeerId::from_hex("abcd1234...")?;

// Convert to hex string
let hex = peer_id.to_hex();

// Get the underlying bytes
let bytes: &[u8] = peer_id.as_bytes();
```

### Key Utilities

```rust
use ant_quic::key_utils::{
    generate_ed25519_keypair,
    derive_peer_id,
};

// Generate a new keypair
let (private_key, public_key) = generate_ed25519_keypair();

// Derive peer ID from public key
let peer_id = derive_peer_id(&public_key);
```

## Connection Type

QUIC connection with streams.

```rust
// Open a bidirectional stream
let (mut send, mut recv) = connection.open_bi().await?;

// Send data
send.write_all(b"Hello").await?;
send.finish()?;

// Receive data
let data = recv.read_to_end(4096).await?;

// Open a unidirectional stream
let mut send = connection.open_uni().await?;

// Accept streams
let (send, recv) = connection.accept_bi().await?;
let recv = connection.accept_uni().await?;

// Close the connection
connection.close(0u32.into(), b"goodbye").await;

// Check if connection is closed
let closed: bool = connection.is_closed();
```

## Statistics Types

### EndpointStats

```rust
pub struct EndpointStats {
    pub active_connections: usize,
    pub discovered_addresses: usize,
    pub successful_hole_punches: usize,
    pub failed_hole_punches: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
```

## Error Types

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

## Candidate Types

### CandidateAddress

Address candidate for NAT traversal.

```rust
pub struct CandidateAddress {
    pub addr: SocketAddr,
    pub source: CandidateSource,
    pub priority: u32,
}

pub enum CandidateSource {
    Local,       // Local interface address
    Observed,    // Discovered via OBSERVED_ADDRESS
    Predicted,   // Symmetric NAT port prediction
}
```

```rust
// Get local candidates
let candidates = endpoint.get_local_candidates();

for candidate in candidates {
    println!("{} from {:?} (priority: {})",
        candidate.addr,
        candidate.source,
        candidate.priority
    );
}
```

## Removed API (v0.13.0)

The following types were removed in v0.13.0:

| Removed | Replacement |
|---------|-------------|
| `QuicNodeConfig` | `P2pConfig` |
| `QuicP2PNode` | `P2pEndpoint` |
| `EndpointRole` | (removed - all nodes symmetric) |
| `NatTraversalRole` | (removed - all nodes symmetric) |
| `PqcMode` | (removed - PQC always on) |
| `HybridPreference` | (removed - no mode selection) |

## Full Example

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent, NatConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .nat(NatConfig {
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(15),
            ..Default::default()
        })
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    // Discover address
    endpoint.connect_bootstrap().await?;
    println!("External: {:?}", endpoint.external_address());

    // Subscribe to events
    let mut events = endpoint.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            println!("Event: {:?}", event);
        }
    });

    // Connect to peer
    let connection = endpoint.connect("192.168.1.100:9000".parse()?).await?;

    // Use connection
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"Hello!").await?;
    send.finish()?;

    let response = recv.read_to_end(1024).await?;
    println!("Response: {:?}", response);

    Ok(())
}
```

## See Also

- [docs.rs/ant-quic](https://docs.rs/ant-quic) - Autogenerated API documentation
- [Configuration](./configuration.md) - Configuration options
- [Examples](./examples.md) - More examples
