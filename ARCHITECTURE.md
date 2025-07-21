# ant-quic Architecture

## Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks. It's a fork of Quinn that extends the QUIC protocol with NAT traversal capabilities based on draft-seemann-quic-nat-traversal-01.

## Three-Layer Architecture

### Layer 1: Protocol Implementation (Low-Level)

This layer contains the core QUIC protocol implementation, forked from Quinn.

#### Core Components
- **`src/endpoint.rs`** - QUIC endpoint managing connections and packets
- **`src/connection/mod.rs`** - Connection state machine with NAT traversal extensions
- **`src/frame.rs`** - QUIC frames including NAT traversal extension frames:
  - `ADD_ADDRESS` (0x40) - Advertise candidate addresses
  - `PUNCH_ME_NOW` (0x41) - Coordinate simultaneous hole punching
  - `REMOVE_ADDRESS` (0x42) - Remove invalid candidates
- **`src/crypto/`** - Cryptographic implementations:
  - TLS 1.3 support via rustls
  - Raw Public Keys (RFC 7250) with Ed25519
  - Certificate negotiation and management
- **`src/transport_parameters.rs`** - QUIC transport parameters including:
  - NAT traversal capability negotiation (ID 0x58)

#### Key Features
- Full QUIC v1 (RFC 9000) implementation
- Zero-copy packet processing
- Congestion control (New Reno, Cubic, BBR)
- Connection migration support
- 0-RTT data support

### Layer 2: Integration APIs (High-Level)

This layer provides developer-friendly APIs wrapping the low-level protocol.

#### Primary Components
- **`src/nat_traversal_api.rs`** - `NatTraversalEndpoint` class
  - High-level NAT traversal coordination
  - Bootstrap node management
  - Session state management
  - Event-driven architecture

- **`src/quic_node.rs`** - `QuicP2PNode` class
  - Application-ready P2P node
  - Peer discovery and connection management
  - Authentication with Ed25519
  - Chat protocol support

- **`src/quinn_high_level/`** - Async QUIC wrapper (when `production-ready` feature enabled)
  - `Endpoint` - Async endpoint management
  - `Connection` - High-level connection API
  - `SendStream`/`RecvStream` - Stream I/O with tokio integration

- **`src/connection_establishment.rs`** - `SimpleConnectionEstablishmentManager`
  - Connection attempt orchestration
  - Multiple strategy support (direct, NAT traversal, relay)
  - Currently needs wiring to actual QUIC implementation

#### Helper Components
- **`src/candidate_discovery.rs`** - Network interface and address discovery
- **`src/auth.rs`** - Authentication manager with challenge-response protocol
- **`src/chat.rs`** - Chat protocol implementation

### Layer 3: Applications (Binaries)

User-facing applications demonstrating the library capabilities.

#### Main Binary
- **`src/bin/ant-quic.rs`** - Full QUIC P2P implementation
  - Uses `QuicP2PNode` for all networking
  - Implements chat with peer discovery
  - Dashboard support for monitoring
  - Coordinator and client roles
  - NAT traversal event handling

#### Examples
- **`examples/chat_demo.rs`** - Chat application demo
- **`examples/simple_chat.rs`** - Minimal chat implementation
- **`examples/dashboard_demo.rs`** - Real-time statistics monitoring

## Data Flow

### Connection Establishment Flow

```
Application (ant-quic)
    ↓
QuicP2PNode
    ↓
NatTraversalEndpoint
    ↓
quinn_high_level::Endpoint
    ↓
Low-level Endpoint → Connection → Streams
```

### NAT Traversal Flow

1. **Discovery Phase**
   - Local interface enumeration
   - Bootstrap connection establishment
   - Reflexive address learning via ADD_ADDRESS frames

2. **Coordination Phase**
   - Exchange candidates with peer via bootstrap
   - Receive PUNCH_ME_NOW frame for timing

3. **Hole Punching Phase**
   - Simultaneous transmission to create NAT bindings
   - Multiple candidate pairs tested in parallel

4. **Validation Phase**
   - QUIC path validation
   - Connection migration to direct path

## Key Design Decisions

### Why Fork Quinn?
- Need to add NAT traversal at the protocol level
- Extension frames require deep integration
- Maintain compatibility with standard QUIC

### Why Not Use STUN/TURN?
- draft-seemann-quic-nat-traversal-01 provides QUIC-native approach
- No external protocols needed
- Address observation happens through normal QUIC connections
- More efficient and simpler architecture

### Single Binary Design
- **ant-quic**: Full QUIC implementation with NAT traversal
- Clean, focused architecture without test tools

### Raw Public Keys
- Implements RFC 7250 for certificate-free operation
- Ed25519 keys for peer identity
- Reduces overhead for P2P connections
- No Certificate Authority needed

## Integration Points

### For Library Users

```rust
use ant_quic::{QuicP2PNode, QuicNodeConfig};

// Create configuration
let config = QuicNodeConfig {
    listen_addr: "0.0.0.0:0".parse()?,
    bootstrap_nodes: vec!["bootstrap.example.com:9000".parse()?],
    private_key: generate_ed25519_keypair(),
    ..Default::default()
};

// Create node
let node = QuicP2PNode::new(config).await?;

// Connect to peer
let peer_id = PeerId([1; 32]);
node.connect_to_peer(peer_id).await?;

// Send data
node.send_message(peer_id, b"Hello P2P").await?;
```

### For Protocol Extensions

The architecture supports extensions through:
- Custom transport parameters
- Additional frame types
- Event callbacks
- Custom authentication schemes

## Current Status

### Completed
- Core QUIC protocol (RFC 9000)
- NAT traversal extension frames
- Raw Public Keys support
- High-level APIs (`QuicP2PNode`, `NatTraversalEndpoint`)
- Production binary with full functionality
- Comprehensive test suite

### In Progress
- Session state machine polling (nat_traversal_api.rs:2022)
- Connection status checking (connection_establishment.rs:844)
- Platform-specific network discovery (stubs exist)

### Future Work
- Performance optimizations
- Additional NAT traversal strategies
- Enhanced monitoring and metrics
- WebTransport support

## Testing

The codebase includes:
- Unit tests throughout modules
- Integration tests for NAT traversal
- Network simulation capabilities
- Stress tests for performance
- Platform-specific tests

Run tests with:
```bash
cargo test                    # All tests
cargo test nat_traversal     # NAT traversal tests
cargo test --ignored stress  # Stress tests
```

## Contributing

When contributing, maintain the three-layer architecture:
1. Protocol changes go in Layer 1
2. API improvements go in Layer 2
3. New examples/apps go in Layer 3

Ensure all changes are compatible with the three core specifications:
- RFC 9000 (QUIC)
- draft-seemann-quic-nat-traversal-01
- RFC 7250 (Raw Public Keys)