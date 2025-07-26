# Architecture

ant-quic has a three-layer architecture designed for modularity and extensibility.

## Overview

```
┌─────────────────────────────────────────┐
│         Applications (Layer 3)          │
│  ant-quic binary, examples, your apps   │
├─────────────────────────────────────────┤
│      Integration APIs (Layer 2)         │
│  NatTraversalEndpoint, QuicP2PNode      │
├─────────────────────────────────────────┤
│   Protocol Implementation (Layer 1)     │
│  QUIC endpoints, connections, frames    │
└─────────────────────────────────────────┘
```

## Layer 1: Protocol Implementation

The foundation layer implements the QUIC protocol with NAT traversal extensions:

- **Endpoint** (`src/endpoint.rs`): Core QUIC endpoint management
- **Connection** (`src/connection/`): Connection state machine with NAT traversal
- **Frames** (`src/frame.rs`): QUIC frames including extension frames
- **Crypto** (`src/crypto/`): TLS and Raw Public Key support

## Layer 2: Integration APIs

High-level APIs that make ant-quic easy to use:

- **NatTraversalEndpoint** (`src/nat_traversal_api.rs`): High-level NAT traversal
- **QuicP2PNode** (`src/quic_node.rs`): Application-friendly P2P node
- **Connection Establishment** (`src/connection_establishment.rs`): Connection orchestration

## Layer 3: Applications

User-facing applications and tools:

- **ant-quic binary** (`src/bin/ant-quic.rs`): Main executable
- **Examples** (`examples/`): Demo applications
- **Your applications**: Built on top of the APIs

## Key Design Principles

1. **Modular**: Each layer can be used independently
2. **Extensible**: Easy to add new features
3. **Performant**: Zero-cost abstractions where possible
4. **Secure**: Authentication and encryption by default
5. **Testable**: Comprehensive test coverage at each layer