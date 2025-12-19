# Symmetric P2P Architecture

This document explains ant-quic's symmetric P2P node model introduced in v0.13.0.

## Overview

In ant-quic v0.13.0, **every node is identical**. There are no special roles, no bootstrap servers, and no client/server distinction beyond who initiates the QUIC handshake.

```
┌─────────────────────────────────────────────────────────────┐
│                    ant-quic Network                         │
│                                                             │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐           │
│   │  Node A  │◄───►│  Node B  │◄───►│  Node C  │           │
│   │  (peer)  │     │  (peer)  │     │  (peer)  │           │
│   └──────────┘     └──────────┘     └──────────┘           │
│        │                │                │                  │
│        └────────────────┴────────────────┘                  │
│                         │                                   │
│                   All nodes can:                            │
│                   - Initiate connections                    │
│                   - Accept connections                      │
│                   - Observe external addresses              │
│                   - Coordinate NAT traversal                │
└─────────────────────────────────────────────────────────────┘
```

## Every Node is Equal

All nodes have identical capabilities:

| Capability | Description |
|------------|-------------|
| **Connect** | Initiate connections to other peers |
| **Accept** | Accept incoming connections from peers |
| **Observe** | See the external address of connecting peers |
| **Report** | Send OBSERVED_ADDRESS frames to peers |
| **Coordinate** | Help two other peers establish a connection |
| **Relay** | Forward traffic when direct connection fails |

## No Special Roles

In v0.13.0, we removed all role distinctions:

### Removed Types

```rust
// These no longer exist in v0.13.0:
enum EndpointRole {
    Client,
    Server,
    Bootstrap,
}

enum NatTraversalRole {
    Client,
    Server,
    Coordinator,
}
```

### Why We Removed Roles

1. **The RFC doesn't require them** - [draft-seemann-quic-nat-traversal-02](../rfcs/draft-seemann-quic-nat-traversal-02.txt) describes peer-to-peer coordination, not client/server roles.

2. **"Client/Server" is confusing** - In QUIC, "client" and "server" refer only to who initiates the handshake, not node capabilities.

3. **Bootstrap nodes aren't special** - Any peer can observe your address and help with discovery.

4. **Simpler API** - No need to choose roles; just create an endpoint and connect.

## Known Peers (Not "Bootstrap Nodes")

The term "bootstrap" implied special infrastructure. In v0.13.0, we use **"known_peers"** instead.

### What Are Known Peers?

Known peers are simply addresses you connect to first:

```rust
let config = P2pConfig::builder()
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peer("peer2.example.com:9000".parse()?)
    .build()?;
```

Any connected peer can help you:
- Discover your external address
- Find other peers
- Coordinate NAT traversal

### Why the Name Change?

| Old Term | New Term | Reason |
|----------|----------|--------|
| bootstrap_nodes | known_peers | All nodes are symmetric |
| bootstrap server | (none) | No special servers |
| client mode | (none) | No modes |
| server mode | (none) | No modes |

## External Address Discovery

Every peer you connect to can observe your external address and tell you:

```
You: Connect to Peer A
     │
     └──► Peer A sees packet from 203.0.113.42:54321
               │
               └──► Peer A sends: OBSERVED_ADDRESS(203.0.113.42:54321)
                         │
                         └──► You learn your external address
```

This works because:
1. Your packets arrive at Peer A from your NAT's external address
2. Peer A can see this source address
3. Peer A sends an OBSERVED_ADDRESS frame back to you
4. You now know how other peers see you

### Multiple Observers

For reliability, connect to multiple peers:

```rust
let config = P2pConfig::builder()
    .known_peers(vec![
        "peer1.example.com:9000".parse()?,
        "peer2.example.com:9000".parse()?,
        "peer3.example.com:9000".parse()?,
    ])
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;
endpoint.connect_bootstrap().await?;

// May have multiple observed addresses (one from each peer)
for addr in endpoint.discovered_addresses() {
    println!("Observed: {}", addr);
}
```

## NAT Traversal Coordination

Any peer can coordinate NAT traversal between two other peers:

```
Peer A ◄───────────────────────────────► Peer B
(behind NAT)                              (behind NAT)
    │                                         │
    │  "I want to connect to Peer B"          │
    └────────────────►Peer C◄─────────────────┘
                      (any peer)
                          │
    ┌─────────────────────┴─────────────────────┐
    │  Peer C coordinates:                      │
    │  1. Tells A: "Send to B's external addr"  │
    │  2. Tells B: "Send to A's external addr"  │
    │  3. Both punch simultaneously             │
    └───────────────────────────────────────────┘
```

### Coordination Frames

| Frame | Purpose |
|-------|---------|
| `ADD_ADDRESS` | "Here are my candidate addresses" |
| `PUNCH_ME_NOW` | "Start punching NOW" |
| `REMOVE_ADDRESS` | "This address is no longer valid" |

## Configuration

### Basic Usage

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

// Minimal configuration - just known peers
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .build()?;

let endpoint = P2pEndpoint::new(config).await?;

// Connect to known peers for discovery
endpoint.connect_bootstrap().await?;

// Your external address is now discoverable
println!("External: {:?}", endpoint.external_address());
```

### NAT Configuration

```rust
use ant_quic::{P2pConfig, NatConfig};

let nat = NatConfig {
    max_candidates: 10,              // Max address candidates
    enable_symmetric_nat: true,      // Enable symmetric NAT prediction
    enable_relay_fallback: true,     // Fall back to relay if direct fails
    max_concurrent_attempts: 3,      // Parallel punch attempts
    prefer_rfc_nat_traversal: true,  // Use RFC frame format
};

let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .nat(nat)
    .build()?;
```

### MTU Configuration

```rust
use ant_quic::{P2pConfig, MtuConfig};

// Optimize for PQC (larger keys need larger packets)
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .mtu(MtuConfig::pqc_optimized())
    .build()?;
```

## Events

Subscribe to P2P events:

```rust
let mut events = endpoint.subscribe();

while let Ok(event) = events.recv().await {
    match event {
        P2pEvent::Connected { peer_id, addr } => {
            println!("Connected to {} at {}", peer_id, addr);
        }
        P2pEvent::Disconnected { peer_id } => {
            println!("Disconnected from {}", peer_id);
        }
        P2pEvent::AddressDiscovered { addr } => {
            println!("External address: {}", addr);
        }
        P2pEvent::NatTraversalComplete { peer_id, success } => {
            println!("NAT traversal to {}: {}", peer_id, success);
        }
        _ => {}
    }
}
```

## Migration from Role-Based API

### Before (v0.12.x and earlier)

```rust
use ant_quic::{NatTraversalConfig, EndpointRole};

let config = NatTraversalConfig {
    role: EndpointRole::Client,           // Role selection
    bootstrap_nodes: vec![addr],          // "Bootstrap" terminology
    pqc_mode: PqcMode::Hybrid,           // PQC mode selection
    ..Default::default()
};

let endpoint = NatTraversalEndpoint::new(config).await?;
```

### After (v0.13.0+)

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

let config = P2pConfig::builder()
    .known_peer(addr)                     // Just "known peers"
    .build()?;                            // No role, no PQC mode

let endpoint = P2pEndpoint::new(config).await?;
// PQC is always on - no configuration needed
```

## Why Symmetric?

The IETF drafts we implement don't define roles:

- [draft-seemann-quic-nat-traversal-02](../rfcs/draft-seemann-quic-nat-traversal-02.txt): Describes peer coordination, not client/server
- [draft-ietf-quic-address-discovery-00](../rfcs/draft-ietf-quic-address-discovery-00.txt): Any endpoint can observe addresses

The term "client/server" in QUIC refers only to who initiates the TLS handshake (client sends ClientHello first). Both endpoints have identical protocol capabilities afterward.

## Summary

| Concept | v0.12.x | v0.13.0 |
|---------|---------|---------|
| Node roles | Client, Server, Bootstrap | (none - all equal) |
| Known addresses | bootstrap_nodes | known_peers |
| Address discovery | Bootstrap servers only | Any peer |
| NAT coordination | Designated coordinators | Any peer |
| PQC mode | ClassicalOnly, Hybrid, PqcOnly | Always on |
| API | NatTraversalEndpoint | P2pEndpoint |

## See Also

- [API Guide](API_GUIDE.md) - Complete API reference
- [NAT Traversal Guide](NAT_TRAVERSAL_GUIDE.md) - NAT traversal details
- [RFC Compliance](review.md) - Standards compliance analysis
