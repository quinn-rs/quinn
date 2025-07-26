# Configuration

ant-quic provides extensive configuration options through the `QuicNodeConfig` struct.

## Basic Configuration

```rust
use ant_quic::{
    quic_node::QuicNodeConfig,
    nat_traversal_api::EndpointRole,
    auth::AuthConfig,
};
use std::time::Duration;

let config = QuicNodeConfig {
    // Node role determines behavior
    role: EndpointRole::Client,
    
    // List of bootstrap nodes for network discovery
    bootstrap_nodes: vec!["bootstrap1.example.com:9000".parse()?],
    
    // Enable NAT traversal coordination
    enable_coordinator: false,
    
    // Connection limits
    max_connections: 100,
    connection_timeout: Duration::from_secs(30),
    
    // Statistics reporting interval
    stats_interval: Duration::from_secs(60),
    
    // Authentication configuration
    auth_config: AuthConfig::default(),
    
    // Bind address (None for auto-select)
    bind_addr: None,
};
```

## Endpoint Roles

- `EndpointRole::Client`: Standard client node
- `EndpointRole::Server`: Server with coordination capabilities
- `EndpointRole::Bootstrap`: Bootstrap node for network discovery

## Authentication

Configure authentication requirements:

```rust
use ant_quic::auth::AuthConfig;

let auth_config = AuthConfig {
    require_authentication: true,
    allowed_peers: Some(vec![trusted_peer_id]),
    auth_timeout: Duration::from_secs(10),
};
```

## Transport Parameters

Fine-tune QUIC transport parameters:

```rust
use ant_quic::config::TransportConfig;

let transport_config = TransportConfig::default()
    .max_concurrent_bidi_streams(100u32.into())
    .max_concurrent_uni_streams(100u32.into())
    .max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
```