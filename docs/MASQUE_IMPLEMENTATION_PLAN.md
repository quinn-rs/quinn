# ant-quic MASQUE Relay Implementation Plan

## Executive Summary

This document outlines a comprehensive plan for implementing MASQUE CONNECT-UDP Bind relay functionality in ant-quic. This implementation will enable **fully connectable nodes** by providing a standards-compliant relay fallback mechanism that integrates seamlessly with the existing QUIC-native NAT traversal.

### The Vision (Marten Seemann's P2P QUIC Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                     Connection Lifecycle                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Connect to Relay    2. Exchange Data      3. Hole Punch     │
│  ─────────────────      ──────────────────    ─────────────     │
│  [Peer A] ──QUIC──► [Relay] ◄──QUIC── [Peer B]                  │
│           (MASQUE)         (MASQUE)                              │
│                    ↓                                             │
│           [Encrypted P2P Data]                                   │
│                    ↓                                             │
│  4. Migrate to Direct (QUIC Connection Migration)               │
│  ────────────────────────────────────────────────               │
│  [Peer A] ◄────────── Direct QUIC ──────────► [Peer B]          │
│                                                                  │
│  ✓ Relay remains available as fallback                          │
│  ✓ Application sees seamless connection                          │
│  ✓ 100% PQC on all paths                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Current State Analysis

### Existing ant-quic Components

| Component | Status | Location |
|-----------|--------|----------|
| NAT Traversal Frames | ✓ Aligned with drafts | `src/nat_traversal/frames.rs` |
| OBSERVED_ADDRESS | ✓ Implemented | `src/frame.rs` |
| TURN-style Relay | ⚠️ Custom (non-standard) | `src/relay/` |
| Session Management | ✓ Good foundation | `src/relay/session_manager.rs` |
| Rate Limiting | ✓ Implemented | `src/relay/rate_limiter.rs` |
| Authentication | ✓ PQC-ready | `src/relay/authenticator.rs` |

### Gap Analysis

| Requirement | Current | Target |
|-------------|---------|--------|
| Relay Protocol | TURN-style frames (0x44-0x46) | MASQUE CONNECT-UDP Bind |
| Capsule Support | None | HTTP Capsule Protocol |
| Context Compression | None | COMPRESSION_ASSIGN/ACK/CLOSE |
| Relay-to-Direct Migration | Manual | Transparent QUIC migration |
| Standards Compliance | Custom | IETF draft-ietf-masque-connect-udp-listen-10 |

## Implementation Architecture

### Module Structure

```
src/
├── masque/                          # NEW: MASQUE protocol implementation
│   ├── mod.rs                       # Module root and public API
│   ├── capsule.rs                   # HTTP Capsule types and codec
│   ├── context.rs                   # Context ID management
│   ├── bind.rs                      # CONNECT-UDP Bind protocol
│   ├── datagram.rs                  # HTTP Datagram encoding/decoding
│   └── migration.rs                 # Relay-to-direct migration logic
│
├── relay/                           # REFACTOR: Update existing
│   ├── mod.rs                       # Add MASQUE backend option
│   ├── masque_backend.rs            # NEW: MASQUE relay backend
│   ├── legacy_backend.rs            # RENAME: Existing TURN-style
│   └── ... (keep existing files)
│
└── connection/
    └── nat_traversal.rs             # UPDATE: Integrate migration
```

### Core Components

#### 1. HTTP Capsule Protocol

Per draft-ietf-masque-connect-udp-listen-10:
- COMPRESSION_ASSIGN (0x11) - Register Context ID
- COMPRESSION_ACK (0x12) - Confirm registration
- COMPRESSION_CLOSE (0x13) - Reject/close context

#### 2. Context Manager

- Clients allocate even Context IDs
- Servers allocate odd Context IDs
- Context ID 0 is reserved
- Only one uncompressed context allowed

#### 3. Migration Coordinator

Handles transparent relay-to-direct migration:
1. Start with relay connection
2. Exchange addresses via ADD_ADDRESS frames
3. Coordinate hole punching with PUNCH_ME_NOW
4. Validate direct path with PATH_CHALLENGE/PATH_RESPONSE
5. Migrate QUIC connection
6. Keep relay as fallback

## Protocol Flow

### Connection via Relay

```
┌──────────┐          ┌──────────┐          ┌──────────┐
│  Peer A  │          │  Relay   │          │  Peer B  │
└────┬─────┘          └────┬─────┘          └────┬─────┘
     │                     │                     │
     │ QUIC Handshake      │                     │
     │ (ML-KEM-768 + ML-DSA-65)                  │
     │────────────────────►│                     │
     │                     │                     │
     │ HTTP CONNECT        │                     │
     │ connect-udp-bind=?1 │                     │
     │────────────────────►│                     │
     │                     │                     │
     │ 200 OK              │                     │
     │ proxy-public-address│                     │
     │◄────────────────────│                     │
     │                     │                     │
     │ COMPRESSION_ASSIGN  │                     │
     │ (uncompressed ctx)  │                     │
     │────────────────────►│                     │
     │                     │                     │
     │ COMPRESSION_ACK     │                     │
     │◄────────────────────│                     │
```

### Migration to Direct

```
     │====== BACKGROUND HOLE PUNCHING ======    │
     │                     │                     │
     │ ADD_ADDRESS (local candidates)           │
     │─────────────────────────────────────────►│
     │                     │                     │
     │◄───────────────────────────────────────────│
     │ ADD_ADDRESS (remote candidates)          │
     │                     │                     │
     │ PUNCH_ME_NOW (round=1)                   │
     │◄────────────────────────────────────────►│
     │                     │                     │
     │ Simultaneous PATH_CHALLENGE               │
     │◄────────────────────────────────────────►│
     │                     │                     │
     │ QUIC Connection Migration to direct path │
     │◄────────────────────────────────────────►│
```

## Implementation Phases

### Phase 1: Core MASQUE Protocol (Week 1-2)
- Capsule encoding/decoding
- Context manager
- Datagram handling

### Phase 2: Relay Client (Week 2-3)
- HTTP CONNECT request
- Header parsing
- Context registration

### Phase 3: Relay Server (Week 3-4)
- HTTP CONNECT handling
- UDP forwarding
- PQC integration

### Phase 4: Migration (Week 4-5)
- Relay-to-direct migration
- QUIC connection migration
- Fallback handling

### Phase 5: Testing (Week 5-6)
- Integration tests
- NAT simulator tests
- Performance benchmarks

## Security Requirements

- All connections use ML-KEM-768 for key exchange
- All connections use ML-DSA-65 for authentication
- No classical algorithm fallback
- Rate limiting on context registrations
- Address validation to prevent spoofing

## Success Metrics

| Metric | Target |
|--------|--------|
| Connection success rate (any NAT) | >99% |
| Relay-to-direct migration success | >70% |
| Migration latency | <5s |
| Relay overhead | <10% bandwidth |

---

*Document Version: 1.0*
*Last Updated: December 2025*
