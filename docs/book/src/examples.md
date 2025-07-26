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

# NAT simulation
cargo run --example nat_simulation
```

## Simple Chat

The simplest example showing basic P2P communication:

```rust
// examples/simple_chat.rs
use ant_quic::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple P2P chat node
    let config = create_default_config();
    let node = QuicP2PNode::new(config).await?;
    
    // Start chat interface
    run_chat_loop(node).await?;
    
    Ok(())
}
```

## NAT Traversal Demo

Demonstrates NAT traversal capabilities:

```bash
# Start bootstrap/coordinator
cargo run --example chat_demo -- --force-coordinator --listen 0.0.0.0:9000

# Start clients behind NAT
cargo run --example chat_demo -- --bootstrap localhost:9000
```

## Dashboard Demo

Real-time monitoring dashboard:

```bash
cargo run --example dashboard_demo -- --dashboard
```

Features:
- Connection statistics
- NAT traversal metrics
- Performance graphs
- Real-time updates

## Integration Examples

For more complex integration examples, see:
- `examples/nat_simulation.rs` - NAT behavior simulation
- `examples/verify_quic_endpoints.rs` - QUIC endpoint verification
- `examples/trace_demo.rs` - Tracing demonstration