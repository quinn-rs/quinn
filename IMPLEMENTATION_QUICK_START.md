# Implementation Quick Start Guide

## Immediate Actions (Can Start Now)

### 1. Fix Compilation Error (5 minutes)
```bash
# In src/nat_traversal_api.rs, add at line 8:
use crate::Endpoint;
```

### 2. Implement Connection Status Check (1 hour)
```rust
// In src/connection_establishment.rs:844, replace simulation with:
async fn check_connection_status(&self, connection: &Connection) -> ConnectionStatus {
    if connection.close_reason().is_some() {
        ConnectionStatus::Closed
    } else if !connection.is_handshaking() {
        ConnectionStatus::Connected
    } else {
        ConnectionStatus::Handshaking
    }
}
```

### 3. Session State Machine Polling (2 hours)
```rust
// In src/nat_traversal_api.rs:2020, implement:
pub fn poll_sessions(&mut self, now: Instant) {
    let mut expired = Vec::new();
    
    for (id, session) in &mut self.coordination_sessions {
        if now.duration_since(session.last_activity) > session.timeout_duration() {
            if session.retry_count < 3 {
                session.retry_count += 1;
                session.last_activity = now;
                // Trigger retry
            } else {
                expired.push(id.clone());
            }
        }
    }
    
    for id in expired {
        self.coordination_sessions.remove(&id);
    }
}
```

## Main Binary QUIC Conversion

### Step 1: Add Dependencies
```rust
// In src/bin/ant-quic.rs
use ant_quic::{
    quinn_high_level::{Endpoint, ServerConfig},
    QuicP2PNode, QuicNodeConfig,
    NatTraversalConfig, EndpointRole,
};
```

### Step 2: Replace UDP Socket Creation
```rust
// Replace this:
let socket = DualStackSocket::new(args.listen).await?;

// With this:
let config = QuicNodeConfig {
    listen_addr: args.listen,
    bootstrap_nodes: args.bootstrap,
    enable_nat_traversal: true,
    ..Default::default()
};
let node = QuicP2PNode::new(config).await?;
```

### Step 3: Replace Message Handling
```rust
// Replace UDP packet handling:
match socket.recv_from(&mut buf).await {
    Ok((len, addr)) => handle_packet(&buf[..len], addr),
    // ...
}

// With QUIC stream handling:
while let Some(conn) = node.accept().await {
    tokio::spawn(async move {
        while let Ok((send, recv)) = conn.accept_bi().await {
            handle_stream(send, recv).await;
        }
    });
}
```

## Testing Your Changes

### Quick Smoke Test
```bash
# Compile check
cargo check --all-targets

# Run basic tests
cargo test connection_establishment
cargo test nat_traversal_api

# Run the binary
cargo run --bin ant-quic -- --listen 0.0.0.0:9000
```

### Integration Test
```rust
#[tokio::test]
async fn test_quic_connection() {
    let node1 = create_test_node(9001).await;
    let node2 = create_test_node(9002).await;
    
    let conn = node1.connect_to(node2.addr()).await.unwrap();
    assert!(conn.is_connected());
}
```

## Common Issues & Solutions

### Issue: "cannot find type `Endpoint`"
**Solution**: Add `use crate::Endpoint;` to imports

### Issue: "method `accept_bi` not found"
**Solution**: The high-level API isn't available in the fork. Use the low-level API or implement the missing methods.

### Issue: Connection times out
**Solution**: Check that NAT traversal is enabled and bootstrap nodes are reachable

## Development Workflow

1. **Make changes incrementally** - Don't try to convert everything at once
2. **Test after each change** - Run `cargo test` frequently
3. **Use feature flags** - Add `#[cfg(feature = "quic-migration")]` for new code
4. **Keep UDP fallback** - Maintain backward compatibility during transition
5. **Monitor logs** - Use `RUST_LOG=debug` to see what's happening

## Getting Help

- Check `ULTRATHINK_IMPLEMENTATION_PLAN.md` for detailed analysis
- Review existing examples in `examples/` directory
- Look at test implementations in `tests/` for patterns
- Use `cargo doc --open` to browse API documentation