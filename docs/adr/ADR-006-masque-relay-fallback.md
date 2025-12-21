# ADR-006: MASQUE CONNECT-UDP Bind Relay

## Status

Accepted (2025-12-21)

## Context

### The Problem

Native QUIC NAT traversal (ADR-005) achieves ~80-95% success rate depending on NAT types. However, some scenarios cannot be resolved through hole punching:

- **Double symmetric NAT**: Both peers behind symmetric NATs
- **Carrier-grade NAT (CGNAT)**: Multiple NAT layers with limited port mappings
- **Firewall restrictions**: UDP blocked or severely rate-limited
- **Hostile network environments**: Corporate proxies, captive portals

For ant-quic to deliver reliable P2P connectivity without central infrastructure, we need a **guaranteed fallback** that works in 100% of cases while still operating within our symmetric peer model.

### Requirements

Per ant-quic's scope (ADR-005):
- Mandatory capability to relay (subject to rate limits/budgets)
- No central coordinator dependency
- Any peer can serve as relay
- Transparent migration to direct path when possible

### Why Not Traditional TURN?

TURN (RFC 5766) has issues:
- Requires dedicated TURN servers (infrastructure dependency)
- Complex credential management
- Designed for WebRTC, not QUIC-native
- Doesn't leverage QUIC's strengths (connection migration, 0-RTT)

## Decision

Implement **MASQUE CONNECT-UDP Bind** per `draft-ietf-masque-connect-udp-listen-10` as the relay fallback mechanism.

### Protocol Overview

MASQUE (Multiplexed Application Substrate over QUIC Encryption) enables UDP proxying over QUIC:

```
┌──────────────┐    QUIC+MASQUE    ┌────────────┐    QUIC+MASQUE    ┌──────────────┐
│   Peer A     │◄────────────────►│   Relay    │◄────────────────►│   Peer B     │
│              │                   │   (Any     │                   │              │
└──────────────┘                   │   Peer)    │                   └──────────────┘
       │                           └────────────┘                          │
       │                                                                   │
       └───────────────── Direct QUIC (after hole punch) ──────────────────┘
```

### Key Protocol Components

**1. HTTP Capsules (Header Compression)**

| Capsule Type | ID | Purpose |
|--------------|-----|---------|
| COMPRESSION_ASSIGN | 0x11 | Register Context ID for target address |
| COMPRESSION_ACK | 0x12 | Acknowledge context registration |
| COMPRESSION_CLOSE | 0x13 | Reject or close context |

**2. Context ID Allocation**

```
Client: Even IDs (2, 4, 6, ...)
Server: Odd IDs (1, 3, 5, ...)
Reserved: Context ID 0
```

**3. Datagram Formats**

Uncompressed (arbitrary targets):
```
[Context ID (VarInt)] [IP Version (1)] [IP Address (4|16)] [Port (2)] [Payload]
```

Compressed (known targets):
```
[Context ID (VarInt)] [Payload]
```

### Three-Layer Connectivity Strategy

| Layer | Method | Success Rate | Latency |
|-------|--------|--------------|---------|
| 1 | Direct QUIC (no NAT) | ~20% | Lowest |
| 2 | Native NAT traversal | ~80% | Low |
| 3 | MASQUE relay | ~100% | Higher |

### Relay-to-Direct Migration

MASQUE enables transparent upgrade to direct connectivity:

1. Peers connect via MASQUE relay
2. Exchange addresses via NAT traversal frames
3. Attempt hole punching in background
4. Use QUIC connection migration to switch paths
5. Relay becomes inactive fallback

This happens transparently to the application layer.

### Every Peer is a Relay

Per ADR-004 (Symmetric P2P), all peers participate in relaying:
- No opt-out (NAT traversal reliability depends on participation)
- Resource budgets prevent abuse (see ADR-002)
- Peer quality scoring includes relay capability bonus

## Consequences

### Benefits

- **100% connectivity guarantee**: MASQUE always works (it's just QUIC)
- **IETF standard**: Based on active IETF draft, not custom protocol
- **QUIC-native**: Leverages connection migration, multiplexing, 0-RTT
- **Symmetric**: Any peer can relay, no special infrastructure
- **Transparent upgrade**: Applications don't know if relayed or direct
- **Header compression**: Efficient for established peer pairs

### Trade-offs

- **Additional latency**: Relay adds one hop (~50-100ms typical)
- **Relay bandwidth**: Peers must contribute relay capacity
- **Complexity**: HTTP Capsule protocol adds implementation complexity
- **Draft status**: Specification not yet RFC (may evolve)

### Performance Characteristics

| Scenario | Latency Impact | Bandwidth Overhead |
|----------|----------------|-------------------|
| Compressed datagram | +1 hop RTT | ~4 bytes/packet |
| Uncompressed datagram | +1 hop RTT | ~8-20 bytes/packet |
| Connection migration | One-time ~100ms | None after migration |

## Alternatives Considered

1. **TURN (RFC 5766)**: Traditional relay protocol
   - Rejected: Requires dedicated servers, not QUIC-native

2. **Custom relay protocol**: Proprietary design
   - Rejected: Reinventing the wheel, interoperability concerns
   - Note: Legacy implementation exists (frames 0x44-0x46) but being deprecated

3. **Always relay**: Skip direct connectivity attempts
   - Rejected: Wastes bandwidth, increases latency unnecessarily

4. **No relay**: Direct-only, accept connectivity gaps
   - Rejected: Violates 100% connectivity goal

5. **WebRTC TURN**: Use existing WebRTC infrastructure
   - Rejected: Wrong abstraction layer, browser-focused

## Implementation Status

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | HTTP Capsule protocol | ✅ Complete |
| 2 | Context ID management | ✅ Complete |
| 3 | HTTP CONNECT handler | 🚧 Planned |
| 4 | Relay server integration | 🚧 Planned |
| 5 | Connection migration | 🚧 Planned |

## References

- **Specification**: `draft-ietf-masque-connect-udp-listen-10`
- **Base protocol**: RFC 9298 (CONNECT-UDP), RFC 9297 (HTTP Datagrams)
- **Implementation**: `src/masque/` (capsule.rs, context.rs, datagram.rs)
- **Integration**: `src/nat_traversal_api.rs` (relay fallback config)
- **Related ADRs**: ADR-004 (Symmetric P2P), ADR-005 (Native QUIC NAT)
