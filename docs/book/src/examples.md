# Examples

ant-quic comes with several example applications demonstrating various features.

## Running Examples

All examples are in the `examples/` directory:

```bash
# Simple chat application
cargo run --example simple_chat

# Chat demo with full features
cargo run --example chat_demo

# Dashboard demo
cargo run --example dashboard_demo

# PQC demo
cargo run --example pqc_demo
```

## Simple P2P Node

The simplest example showing basic P2P communication with v0.13.0+ API:

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure endpoint - all nodes are symmetric
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {}", endpoint.peer_id().to_hex());

    // Discover external address
    endpoint.connect_bootstrap().await?;
    if let Some(addr) = endpoint.external_address() {
        println!("External address: {}", addr);
    }

    // Handle events
    let mut events = endpoint.subscribe();
    while let Ok(event) = events.recv().await {
        match event {
            P2pEvent::Connected { peer_id, addr } => {
                println!("Connected: {} at {}", peer_id.to_hex(), addr);
            }
            P2pEvent::AddressDiscovered { addr } => {
                println!("Discovered: {}", addr);
            }
            _ => {}
        }
    }

    Ok(())
}
```

## Chat Application

A complete chat application with message handling:

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;
    endpoint.connect_bootstrap().await?;

    println!("Chat started. Peer ID: {}", endpoint.peer_id().to_hex());
    println!("Enter peer address to connect, or type messages:");

    // Handle incoming connections
    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        while let Some(conn) = endpoint_clone.accept().await {
            tokio::spawn(async move {
                if let Ok((_, mut recv)) = conn.accept_bi().await {
                    if let Ok(data) = recv.read_to_end(4096).await {
                        let msg = String::from_utf8_lossy(&data);
                        println!("Received: {}", msg);
                    }
                }
            });
        }
    });

    // Handle user input
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    let mut current_conn = None;

    while let Ok(Some(line)) = lines.next_line().await {
        if line.starts_with("/connect ") {
            let addr = line[9..].parse()?;
            current_conn = Some(endpoint.connect(addr).await?);
            println!("Connected!");
        } else if let Some(conn) = &current_conn {
            let (mut send, _) = conn.open_bi().await?;
            send.write_all(line.as_bytes()).await?;
            send.finish()?;
            println!("Sent: {}", line);
        }
    }

    Ok(())
}
```

## NAT Traversal Demo

Demonstrates NAT traversal between nodes behind different NATs:

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent, NatConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure with NAT traversal tuning
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .nat(NatConfig {
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(15),
            enable_symmetric_nat: true,
            ..Default::default()
        })
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;

    // Discover external address
    endpoint.connect_bootstrap().await?;
    println!("External: {:?}", endpoint.external_address());

    // Show candidates
    let candidates = endpoint.get_local_candidates();
    println!("Candidates:");
    for c in candidates {
        println!("  {} from {:?}", c.addr, c.source);
    }

    // Monitor NAT traversal events
    let mut events = endpoint.subscribe();
    while let Ok(event) = events.recv().await {
        match event {
            P2pEvent::HolePunchStarted { peer_id } => {
                println!("Hole punching: {}", peer_id.to_hex());
            }
            P2pEvent::HolePunchSucceeded { peer_id, addr } => {
                println!("Direct connection: {} at {}", peer_id.to_hex(), addr);
            }
            P2pEvent::HolePunchFailed { peer_id, reason } => {
                println!("Failed: {} - {}", peer_id.to_hex(), reason);
            }
            _ => {}
        }
    }

    Ok(())
}
```

## Statistics Monitor

Monitor endpoint statistics:

```rust
use ant_quic::{P2pEndpoint, P2pConfig};
use tokio::time::{interval, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder()
        .known_peer("quic.saorsalabs.com:9000".parse()?)
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;
    endpoint.connect_bootstrap().await?;

    // Print statistics every 10 seconds
    let mut ticker = interval(Duration::from_secs(10));
    loop {
        ticker.tick().await;

        let stats = endpoint.stats();
        println!("=== Statistics ===");
        println!("Active connections: {}", stats.active_connections);
        println!("Discovered addresses: {}", stats.discovered_addresses);
        println!("Successful punches: {}", stats.successful_hole_punches);
        println!("Failed punches: {}", stats.failed_hole_punches);
        println!("Bytes sent: {}", stats.bytes_sent);
        println!("Bytes received: {}", stats.bytes_received);
    }
}
```

## Key Generation

Generate and manage Ed25519 keys:

```rust
use ant_quic::key_utils::{generate_ed25519_keypair, derive_peer_id};

fn main() {
    // Generate a new keypair
    let (private_key, public_key) = generate_ed25519_keypair();

    // Derive peer ID
    let peer_id = derive_peer_id(&public_key);

    println!("Generated new identity:");
    println!("  Peer ID: {}", peer_id.to_hex());
    println!("  Public key: {} bytes", public_key.len());

    // In a real application:
    // - Store private_key securely
    // - Share peer_id with trusted peers
}
```

## Running the Examples

### Terminal Setup

```bash
# Terminal 1: Start first node
cargo run --example simple_chat

# Terminal 2: Start second node and connect
cargo run --example simple_chat
# Then type: /connect <address-from-terminal-1>
```

### With Logging

```bash
# Enable debug logging
RUST_LOG=ant_quic=debug cargo run --example simple_chat

# NAT traversal specific logging
RUST_LOG=ant_quic::nat_traversal=trace cargo run --example nat_demo

# PQC logging
RUST_LOG=ant_quic::crypto::pqc=debug cargo run --example pqc_demo
```

## Key Changes from v0.12

If you're updating examples from earlier versions:

```rust
// OLD (v0.12 and earlier) - DO NOT USE
// let config = QuicNodeConfig {
//     role: EndpointRole::Client,
//     bootstrap_nodes: vec![...],
//     ...
// };
// let node = QuicP2PNode::new(config).await?;

// NEW (v0.13.0+)
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;
let endpoint = P2pEndpoint::new(config).await?;
```

## See Also

- [Quick Start](./quick-start.md)
- [API Reference](./api-reference.md)
- [Configuration](./configuration.md)
