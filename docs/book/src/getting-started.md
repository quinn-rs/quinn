# Getting Started

This guide will help you get started with ant-quic v0.13.0+.

## Prerequisites

- Rust 1.85.0 or later
- Basic understanding of networking concepts
- Familiarity with async Rust programming

## Installation

Add ant-quic to your `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.13"
tokio = { version = "1", features = ["full"] }
```

## Understanding the Symmetric P2P Model

In ant-quic v0.13.0+, **all nodes are symmetric**. There are no special roles - every node can:

- **Initiate connections** to other nodes
- **Accept connections** from other nodes
- **Observe external addresses** of connecting peers
- **Coordinate NAT traversal** for other peers

This means there's no distinction between "client" and "server" - your application is both.

## Your First ant-quic Application

Here's a simple example that creates a P2P endpoint:

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure the endpoint
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .build()?;

    // Create the endpoint
    let endpoint = P2pEndpoint::new(config).await?;

    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    // Discover external address through known peers
    endpoint.connect_bootstrap().await?;

    if let Some(addr) = endpoint.external_address() {
        println!("External address: {}", addr);
    }

    // Handle incoming connections
    while let Some(conn) = endpoint.accept().await {
        println!("New connection from peer");
        tokio::spawn(async move {
            // Handle the connection
            if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                if let Ok(data) = recv.read_to_end(4096).await {
                    println!("Received: {}", String::from_utf8_lossy(&data));
                }
            }
        });
    }

    Ok(())
}
```

## Key Concepts

### Known Peers

Known peers are simply addresses to connect to first for address discovery. Unlike "bootstrap nodes" in other systems, known peers are not special infrastructure - they're just regular peers with known addresses.

```rust
let config = P2pConfig::builder()
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .build()?;
```

### Address Discovery

When you connect to a known peer, they observe your external address and report it back to you via OBSERVED_ADDRESS frames. This works without STUN servers - it's built into the QUIC protocol.

```rust
// Connect to known peers and discover external address
endpoint.connect_bootstrap().await?;

// Now you know how others see you
let external = endpoint.external_address();
```

### Events

Subscribe to events to monitor your endpoint:

```rust
let mut events = endpoint.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, addr } => {
            println!("Connected to {} at {}", peer_id.to_hex(), addr);
        }
        P2pEvent::AddressDiscovered { addr } => {
            println!("Discovered external address: {}", addr);
        }
        P2pEvent::HolePunchSucceeded { peer_id, addr } => {
            println!("Direct connection to {} via {}", peer_id.to_hex(), addr);
        }
        _ => {}
    }
}
```

## Security

Every connection in ant-quic uses hybrid post-quantum cryptography:

- **Key Exchange**: X25519 + ML-KEM-768
- **Signatures**: Ed25519 + ML-DSA-65

This is always enabled - there's no way to disable PQC. Your communications are protected against both current and future quantum attacks.

## What's NOT in ant-quic v0.13.0

The following concepts were **removed** in v0.13.0:

| Removed | Reason |
|---------|--------|
| `EndpointRole::Client/Server/Bootstrap` | All nodes are symmetric |
| `PqcMode` | PQC is always on |
| `HybridPreference` | No mode selection |
| Bootstrap nodes as special infrastructure | All peers are equal |

If you're migrating from an earlier version, see the [migration guide](../guides/pqc-migration.md).

## Next Steps

- [Installation](./installation.md) - Detailed installation instructions
- [Quick Start](./quick-start.md) - Build a complete P2P application
- [Configuration](./configuration.md) - All configuration options
- [Examples](./examples.md) - Explore more complex examples

