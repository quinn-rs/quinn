# Getting Started

This guide will help you get started with ant-quic.

## Prerequisites

- Rust 1.74.1 or later
- Basic understanding of networking concepts
- Familiarity with async Rust programming

## Installation

Add ant-quic to your `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.4"
tokio = { version = "1", features = ["full"] }
```

## Your First ant-quic Application

Here's a simple example that creates a QUIC endpoint:

```rust
use ant_quic::{
    quic_node::{QuicNodeConfig, QuicP2PNode},
    nat_traversal_api::EndpointRole,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the node
    let config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec!["bootstrap.example.com:9000".parse()?],
        enable_coordinator: false,
        max_connections: 100,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: Default::default(),
        bind_addr: None,
    };

    // Create the node
    let node = QuicP2PNode::new(config).await?;
    
    println!("Node created with peer ID: {:?}", node.peer_id());
    
    Ok(())
}
```

## Next Steps

- [Installation](./installation.md) - Detailed installation instructions
- [Quick Start](./quick-start.md) - Build your first P2P application
- [Examples](./examples.md) - Explore more complex examples