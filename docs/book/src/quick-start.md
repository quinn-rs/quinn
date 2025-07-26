# Quick Start

Let's build a simple P2P chat application using ant-quic.

## Create a New Project

```bash
cargo new ant-quic-chat
cd ant-quic-chat
```

## Add Dependencies

Edit `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.4"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1.0"
```

## Basic Chat Application

Create `src/main.rs`:

```rust
use ant_quic::{
    chat::ChatMessage,
    quic_node::{QuicNodeConfig, QuicP2PNode},
    nat_traversal_api::EndpointRole,
    auth::AuthConfig,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let listen_addr: SocketAddr = args
        .get(1)
        .unwrap_or(&"0.0.0.0:0".to_string())
        .parse()?;

    // Configure the node
    let config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![], // Add bootstrap nodes here
        enable_coordinator: false,
        max_connections: 100,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(),
        bind_addr: Some(listen_addr),
    };

    // Create the node
    let node = Arc::new(QuicP2PNode::new(config).await?);
    info!("Node started with peer ID: {:?}", node.peer_id());

    // Handle incoming messages
    let node_clone = Arc::clone(&node);
    tokio::spawn(async move {
        loop {
            match node_clone.receive().await {
                Ok((peer_id, data)) => {
                    if let Ok(msg) = ChatMessage::deserialize(&data) {
                        info!("Received from {:?}: {:?}", peer_id, msg);
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
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

1. Start a bootstrap node:
```bash
cargo run -- 127.0.0.1:9000
```

2. Start client nodes:
```bash
cargo run -- 127.0.0.1:0
```

## Next Steps

- Add user input handling
- Implement proper message formatting
- Add peer discovery
- Explore NAT traversal features