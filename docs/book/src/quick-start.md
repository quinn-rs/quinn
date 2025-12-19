# Quick Start

Let's build a simple P2P application using ant-quic v0.13.0+.

## Create a New Project

```bash
cargo new ant-quic-demo
cd ant-quic-demo
```

## Add Dependencies

Edit `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.13"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1.0"
```

## Basic P2P Application

Create `src/main.rs`:

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent, NatConfig};
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Configure the P2P endpoint
    // All nodes are symmetric - no roles to configure!
    let config = P2pConfig::builder()
        // Known peers to connect to first for address discovery
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        // NAT traversal tuning (optional - sensible defaults provided)
        .nat(NatConfig {
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(15),
            discovery_timeout: Duration::from_secs(5),
            enable_symmetric_nat: true,
            ..Default::default()
        })
        .build()?;

    // Create the endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    info!("Node started with peer ID: {:?}", endpoint.peer_id());

    // Connect to known peers and discover our external address
    endpoint.connect_bootstrap().await?;

    // Check what address others see us as
    if let Some(addr) = endpoint.external_address() {
        info!("Our external address: {}", addr);
    }

    // Subscribe to P2P events
    let mut events = endpoint.subscribe();

    // Spawn event handler
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            match event {
                P2pEvent::Connected { peer_id, addr } => {
                    info!("Connected to {} at {}", peer_id.to_hex(), addr);
                }
                P2pEvent::Disconnected { peer_id, reason } => {
                    info!("Disconnected from {}: {}", peer_id.to_hex(), reason);
                }
                P2pEvent::AddressDiscovered { addr } => {
                    info!("Discovered external address: {}", addr);
                }
                P2pEvent::HolePunchSucceeded { peer_id, addr } => {
                    info!("Direct connection to {} via {}", peer_id.to_hex(), addr);
                }
                _ => {}
            }
        }
    });

    // Keep the application running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
```

## Running the Application

```bash
# Run the node
cargo run
```

Since all nodes are symmetric, there's no separate "server" or "client" mode. Every node can both connect to others and accept connections.

## Connecting to a Specific Peer

```rust
// Connect to a peer by address
let target = "192.168.1.100:9000".parse()?;
let connection = endpoint.connect(target).await?;

// Open a bidirectional stream
let (mut send, mut recv) = connection.open_bi().await?;

// Send data
send.write_all(b"Hello, peer!").await?;
send.finish()?;

// Receive response
let response = recv.read_to_end(1024).await?;
println!("Response: {:?}", response);
```

## Accepting Connections

```rust
// Accept incoming connections (all nodes can do this!)
while let Some(conn) = endpoint.accept().await {
    tokio::spawn(async move {
        // Handle the connection
        if let Ok(stream) = conn.accept_bi().await {
            let (send, mut recv) = stream;
            // Process incoming data
            let data = recv.read_to_end(4096).await.unwrap_or_default();
            println!("Received: {:?}", data);
        }
    });
}
```

## Key Concepts

1. **Symmetric P2P**: Every node is identical - no roles, no special infrastructure
2. **Known Peers**: Addresses to connect to first for address discovery (not "bootstrap nodes")
3. **100% PQC**: ML-KEM-768 + ML-DSA-65 on every connection (cannot be disabled)
4. **NAT Traversal**: Automatic via QUIC protocol extensions
5. **Address Discovery**: Learn your external address from peers via OBSERVED_ADDRESS frames

## Next Steps

- [Configuration](./configuration.md) - Learn about all configuration options
- [NAT Traversal](./nat-traversal.md) - Understanding NAT traversal in depth
- [Examples](./examples.md) - More complete examples
- [API Reference](./api-reference.md) - Full API documentation
