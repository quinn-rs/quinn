# ant-quic API Reference

This document provides a comprehensive API reference for external testers and developers integrating with ant-quic.

## Table of Contents

1. [Client API](#client-api)
2. [Server API](#server-api)
3. [NAT Traversal API](#nat-traversal-api)
4. [Transport Parameters](#transport-parameters)
5. [Extension Frames](#extension-frames)
6. [Error Codes](#error-codes)
7. [Metrics API](#metrics-api)

## Client API

### Creating a Client

```rust
use ant_quic::{ClientConfig, Endpoint};

// Basic client
let endpoint = Endpoint::client("0.0.0.0:0")?;

// With custom configuration
let mut config = ClientConfig::with_native_roots();
config.transport_config_mut().max_idle_timeout(Some(Duration::from_secs(30)));

let endpoint = Endpoint::client_with_config("0.0.0.0:0", config)?;
```

### Connecting to a Server

```rust
// Simple connection
let connection = endpoint.connect(server_addr, "example.com")?.await?;

// With NAT traversal
let connection = endpoint
    .connect_with_nat_traversal(server_addr, "example.com", bootstrap_nodes)?
    .await?;
```

### Opening Streams

```rust
// Bidirectional stream
let (mut send, mut recv) = connection.open_bi().await?;

// Unidirectional stream
let mut send = connection.open_uni().await?;
```

## Server API

### Creating a Server

```rust
use ant_quic::{ServerConfig, Endpoint};

// Generate certificate
let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

// Create server config
let mut server_config = ServerConfig::with_single_cert(
    vec![cert.serialize_der()?],
    cert.serialize_private_key_der()
)?;

// Create endpoint
let endpoint = Endpoint::server(server_config, "0.0.0.0:9000")?;
```

### Accepting Connections

```rust
// Accept incoming connections
while let Some(connecting) = endpoint.accept().await {
    let connection = connecting.await?;

    // Handle connection
    tokio::spawn(async move {
        handle_connection(connection).await;
    });
}
```

### Bootstrap Node Configuration

```rust
// Enable coordinator mode for NAT traversal
let mut server_config = ServerConfig::with_single_cert(certs, key)?;
server_config.enable_nat_coordinator(true);
server_config.set_nat_traversal_role(NatTraversalRole::Bootstrap);
```

## NAT Traversal API

### High-Level API

```rust
use ant_quic::nat_traversal_api::{NatTraversalEndpoint, NatTraversalConfig, EndpointRole};

// Create NAT traversal endpoint
let config = NatTraversalConfig {
    role: EndpointRole::Client,
    bootstrap_nodes: vec!["quic.saorsalabs.com:9000".parse()?],
    max_candidates: 50,
    coordination_timeout: Duration::from_secs(30),
    enable_symmetric_nat: true,
    enable_relay_fallback: true,
    max_concurrent_attempts: 3,
    bind_addr: None,
};

let nat_endpoint = NatTraversalEndpoint::new(config, event_callback);

// Connect through NAT
let connection = nat_endpoint.connect_to_peer(peer_id).await?;
```

### Event Handling

```rust
// NAT traversal events
fn event_callback(event: NatTraversalEvent) {
    match event {
        NatTraversalEvent::CandidateDiscovered { address, source } => {
            println!("Discovered candidate: {} from {:?}", address, source);
        }
        NatTraversalEvent::HolePunchingStarted { peer_id } => {
            println!("Starting hole punching with {}", peer_id);
        }
        NatTraversalEvent::ConnectionEstablished { peer_id, path } => {
            println!("Connected to {} via {}", peer_id, path);
        }
        NatTraversalEvent::RelayRequired { peer_id } => {
            println!("Relay needed for {}", peer_id);
        }
    }
}
```

## Transport Parameters

### Standard QUIC Parameters

```rust
// Configure transport parameters
let mut transport_config = TransportConfig::default();
transport_config
    .max_concurrent_bidi_streams(100u32.into())
    .max_concurrent_uni_streams(100u32.into())
    .max_idle_timeout(Some(Duration::from_secs(60)))
    .initial_max_data(10_000_000)
    .initial_max_stream_data_bidi_local(1_000_000)
    .initial_max_stream_data_bidi_remote(1_000_000);
```

### NAT Traversal Extension Parameters

| Parameter | ID | Type | Description |
|-----------|-----|------|-------------|
| nat_traversal_enabled | 0x58 | varint | Enable NAT traversal (1) or disable (0) |
| observed_address_enabled | 0x1f00 | varint | Enable address discovery (1) or disable (0) |
| max_observed_addresses | 0x1f01 | varint | Maximum observed addresses to track |
| address_validation_token | 0x1f02 | bytes | Token for address validation |

## Extension Frames

### OBSERVED_ADDRESS Frame (0x43)

Informs peer of their observed address:

```
OBSERVED_ADDRESS Frame {
    Type (i) = 0x43,
    Sequence Number (i),
    IP Version (8),
    IP Address (32/128),
    Port (16),
}
```

### ADD_ADDRESS Frame (0x40)

Advertises additional addresses for connection:

```
ADD_ADDRESS Frame {
    Type (i) = 0x40,
    Address ID (i),
    IP Version (8),
    IP Address (32/128),
    Port (16),
    Priority (8),
}
```

### PUNCH_ME_NOW Frame (0x41)

Coordinates simultaneous hole punching:

```
PUNCH_ME_NOW Frame {
    Type (i) = 0x41,
    Round ID (i),
    Target Address ID (i),
    Timestamp (i),
}
```

### REMOVE_ADDRESS Frame (0x42)

Removes a previously advertised address:

```
REMOVE_ADDRESS Frame {
    Type (i) = 0x42,
    Address ID (i),
}
```

## Error Codes

### Connection Errors

| Code | Name | Description |
|------|------|-------------|
| 0x0 | NO_ERROR | Graceful shutdown |
| 0x1 | INTERNAL_ERROR | Implementation error |
| 0x2 | CONNECTION_REFUSED | Server refusing connections |
| 0x3 | FLOW_CONTROL_ERROR | Flow control violation |
| 0x4 | STREAM_LIMIT_ERROR | Too many streams |
| 0x5 | STREAM_STATE_ERROR | Stream in wrong state |
| 0x6 | FINAL_SIZE_ERROR | Final size mismatch |
| 0x7 | FRAME_ENCODING_ERROR | Frame parsing failed |
| 0x8 | TRANSPORT_PARAMETER_ERROR | Invalid transport parameters |
| 0x9 | CONNECTION_ID_LIMIT_ERROR | Too many connection IDs |
| 0xa | PROTOCOL_VIOLATION | Protocol rules violated |
| 0xb | INVALID_TOKEN | Invalid address validation token |

### NAT Traversal Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x100 | NAT_TRAVERSAL_FAILED | Could not establish direct connection |
| 0x101 | NO_VALID_CANDIDATES | No viable address candidates |
| 0x102 | COORDINATION_TIMEOUT | Hole punching coordination timeout |
| 0x103 | RELAY_UNAVAILABLE | No relay nodes available |

## Metrics API

### HTTP Endpoints

```bash
# Connection statistics
GET /api/stats
{
  "connections": {
    "active": 42,
    "total": 1337,
    "failed": 13
  },
  "streams": {
    "active_bidi": 84,
    "active_uni": 21,
    "total": 5678
  },
  "bytes": {
    "sent": 1234567890,
    "received": 9876543210
  }
}

# NAT traversal statistics
GET /api/stats/nat
{
  "success_rate": 0.87,
  "total_attempts": 543,
  "successful_attempts": 472,
  "relay_connections": 45,
  "hole_punching_successes": 427,
  "average_connection_time_ms": 342
}

# Health check
GET /api/health
{
  "status": "healthy",
  "uptime": 86400,
  "version": "0.4.4"
}
```

### Prometheus Metrics

```prometheus
# Connection metrics
ant_quic_connections_total{type="active"} 42
ant_quic_connections_total{type="established"} 1337
ant_quic_connections_total{type="failed"} 13

# NAT traversal metrics
ant_quic_nat_attempts_total 543
ant_quic_nat_successes_total 472
ant_quic_nat_relay_used_total 45
ant_quic_nat_success_rate 0.87

# Performance metrics
ant_quic_handshake_duration_seconds{quantile="0.5"} 0.123
ant_quic_handshake_duration_seconds{quantile="0.95"} 0.456
ant_quic_handshake_duration_seconds{quantile="0.99"} 0.789
```

## Code Examples

### Complete Client Example

```rust
use ant_quic::{ClientConfig, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse server address
    let server_addr: SocketAddr = "quic.saorsalabs.com:9000".parse()?;

    // Create client endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0")?;

    // Configure client
    let client_config = ClientConfig::with_native_roots();
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connection = endpoint.connect(server_addr, "example.com")?.await?;
    println!("Connected to {}", connection.remote_address());

    // Open a bidirectional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send data
    send.write_all(b"Hello, QUIC!").await?;
    send.finish().await?;

    // Receive response
    let response = recv.read_to_end(1024).await?;
    println!("Received: {:?}", String::from_utf8(response)?);

    // Close connection
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}
```

### Complete Server Example

```rust
use ant_quic::{ServerConfig, Endpoint};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate self-signed certificate
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    // Create server configuration
    let server_config = ServerConfig::with_single_cert(
        vec![cert_der],
        key_der
    )?;

    // Create endpoint
    let endpoint = Endpoint::server(server_config, "0.0.0.0:9000")?;
    println!("Listening on {}", endpoint.local_addr()?);

    // Accept connections
    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    println!("Connection from {}", connection.remote_address());
                    handle_connection(connection).await;
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn handle_connection(connection: quinn::Connection) {
    // Handle streams
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // Echo server
                let data = recv.read_to_end(1024).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().await.unwrap();
            }
            Err(e) => {
                println!("Connection closed: {}", e);
                break;
            }
        }
    }
}
```

## Testing Your Implementation

### Interoperability Test

```bash
# Test against ant-quic
cargo run --example your_client -- quic.saorsalabs.com:9000

# Enable debug logging
RUST_LOG=debug cargo run --example your_client -- quic.saorsalabs.com:9000

# Test specific features
cargo run --example your_client -- \
    --test-0rtt \
    --test-migration \
    --test-nat-traversal \
    quic.saorsalabs.com:9000
```

### Performance Test

```rust
// Measure handshake time
let start = Instant::now();
let connection = endpoint.connect(addr, "example.com")?.await?;
let handshake_time = start.elapsed();
println!("Handshake completed in {:?}", handshake_time);

// Measure throughput
let start = Instant::now();
let bytes_sent = send_large_data(&mut stream).await?;
let duration = start.elapsed();
let throughput = bytes_sent as f64 / duration.as_secs_f64();
println!("Throughput: {:.2} MB/s", throughput / 1_000_000.0);
```

## Support

- GitHub Issues: https://github.com/dirvine/ant-quic/issues
- Documentation: https://docs.rs/ant-quic
- Examples: https://github.com/dirvine/ant-quic/tree/main/examples
