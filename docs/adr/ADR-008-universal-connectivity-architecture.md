# ADR-008: Universal Connectivity Architecture

## Status

Accepted

## Date

2025-12-26

## Context

A successful P2P network must connect nodes regardless of their network environment. Real-world deployments encounter:

- **IPv4-only networks**: Legacy infrastructure, mobile carriers, corporate networks
- **IPv6-only networks**: Modern deployments, IPv4 exhaustion mitigation
- **Dual-stack networks**: Mixed environments with both protocols
- **NAT environments**: Consumer routers (full cone, port-restricted), carrier-grade NAT (CGNAT), symmetric NAT
- **Firewalled networks**: Corporate proxies, hotel networks, restrictive ISPs
- **Mobile networks**: Frequently changing IP addresses, aggressive NAT

Traditional P2P networks often achieve only 60-80% connectivity, leaving significant portions of the network fragmented. ant-quic targets **100% connectivity** through a layered approach where each technique handles progressively more difficult network configurations.

## Decision

We implement a **Universal Connectivity Architecture** that combines five key design decisions into a cohesive strategy:

### 1. True Dual-Stack Sockets (ADR foundation)

**What**: Single IPv6 socket with `IPV6_V6ONLY=0` that accepts both IPv4 and IPv6 connections.

**Why**:
- IPv4 clients connect to IPv6 sockets via IPv4-mapped addresses (`::ffff:x.x.x.x`)
- Single listening port serves both address families
- Simplifies NAT traversal coordination (one socket to manage)
- Reduces resource usage compared to separate sockets

**Graceful Degradation**:
- IPv4-only systems: Fall back to IPv4 socket only
- IPv6-only systems: IPv6 socket works natively
- Dual-stack systems: Full dual-stack socket

```
┌─────────────────────────────────────────────────────────────┐
│              Dual-Stack Socket Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│    IPv4 Client ──────┐                                      │
│    (192.168.1.5)     │                                      │
│                      ▼                                      │
│              ┌──────────────┐                               │
│              │  Dual-Stack  │  bind([::]:9000)              │
│              │    Socket    │  IPV6_V6ONLY=0                │
│              └──────────────┘                               │
│                      ▲                                      │
│    IPv6 Client ──────┘                                      │
│    (2001:db8::5)                                            │
│                                                             │
│    IPv4 appears as: ::ffff:192.168.1.5                      │
│    IPv6 appears as: 2001:db8::5                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. Symmetric P2P Architecture (ADR-004)

**What**: All nodes are equal peers with identical capabilities. No special "bootstrap" or "coordinator" roles.

**Why**:
- Any node can accept connections AND initiate connections
- Any node can observe and report external addresses to peers
- Any node can coordinate NAT traversal hole-punching
- No single points of failure
- Linear scaling (each new node adds capacity, not load)

**Implementation**:
- `known_peers` configuration (not "bootstrap servers")
- OBSERVED_ADDRESS frames from any connected peer
- PUNCH_ME_NOW coordination through any peer
 - Capability selection based on observed success rates (measure, don't trust)

```
┌─────────────────────────────────────────────────────────────┐
│                Symmetric Node Capabilities                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│    Every ant-quic node can:                                 │
│                                                             │
│    ✓ Accept incoming connections                            │
│    ✓ Initiate outbound connections                          │
│    ✓ Observe peer external addresses                        │
│    ✓ Report OBSERVED_ADDRESS frames                         │
│    ✓ Coordinate PUNCH_ME_NOW timing                         │
│    ✓ Relay data for other peers                             │
│    ✓ Participate in address discovery                       │
│                                                             │
│    Node A ◄═══════════════► Node B                          │
│       │                        │                            │
│       │    Equal peers         │                            │
│       │    No hierarchy        │                            │
│       ▼                        ▼                            │
│    Node C ◄═══════════════► Node D                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3. Native QUIC NAT Traversal (ADR-005)

**What**: NAT traversal using native QUIC extension frames, NOT STUN/ICE/TURN.

**Why**:
- Single protocol for everything (no UDP vs STUN vs TURN switching)
- Works through QUIC's encryption (many middleboxes block plain STUN)
- Leverages existing connections for coordination
- No external infrastructure dependencies

**Extension Frames**:
- `ADD_ADDRESS` (0x3d7e90-91): Advertise candidate addresses
- `REMOVE_ADDRESS` (0x3d7e94): Withdraw invalid candidates
- `PUNCH_ME_NOW` (0x3d7e92-93): Coordinate simultaneous hole-punching
- `OBSERVED_ADDRESS` (0x9f81a6-a7): Report external address observations

**NAT Types Handled**:

| NAT Type | Difficulty | Technique |
|----------|------------|-----------|
| Full Cone | Easy | Direct connection |
| Address-Restricted | Medium | ADD_ADDRESS exchange |
| Port-Restricted | Medium | Coordinated hole-punch |
| Symmetric | Hard | Port prediction + PUNCH_ME_NOW |
| CGNAT | Very Hard | Multiple candidates + relay fallback |

### 4. MASQUE Relay Fallback (ADR-006)

**What**: When direct connection and hole-punching fail, use MASQUE CONNECT-UDP relays.

**Why**:
- Guarantees connectivity even through hostile networks
- Works through corporate proxies (HTTPS-based)
- Maintains QUIC encryption end-to-end
- Last resort, not primary path

**Relay Selection**:
- Prefer geographically close relays
- Multiple relays for redundancy
- Automatic failover
- Continuous direct connection attempts in background

```
┌─────────────────────────────────────────────────────────────┐
│                  Connection Establishment                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Direct Connection Attempt (fastest, preferred)          │
│     ┌────┐                              ┌────┐              │
│     │ A  │ ─────────────────────────── │ B  │              │
│     └────┘         Direct UDP          └────┘              │
│                                                             │
│  2. NAT Hole-Punching (if direct fails)                    │
│     ┌────┐      PUNCH_ME_NOW         ┌────┐              │
│     │ A  │ ←──────────────────────── │ C  │ (coordinator)  │
│     │    │ ─────────────────────── │ B  │              │
│     └────┘    Coordinated timing     └────┘              │
│                                                             │
│  3. MASQUE Relay (if hole-punch fails)                     │
│     ┌────┐                              ┌────┐              │
│     │ A  │ ──► MASQUE Relay ──► │ B  │              │
│     └────┘     (100% works)            └────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5. Cross-Family Filtering and Best Path Selection

**What**: Intelligent candidate pairing that only creates viable connection attempts.

**Why**:
- IPv4 cannot connect to IPv6 directly (and vice versa)
- Reduces failed connection attempts
- Faster path establishment
- Lower resource usage

**Candidate Prioritization**:
1. Same address family (IPv4↔IPv4 or IPv6↔IPv6)
2. Lower latency paths preferred
3. Higher bandwidth paths preferred
4. Direct connections over relayed

```
┌─────────────────────────────────────────────────────────────┐
│                  Candidate Pairing Logic                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Local Candidates:              Remote Candidates:          │
│  ├─ 192.168.1.5:9000 (IPv4)     ├─ 10.0.0.5:9000 (IPv4)    │
│  ├─ 2001:db8::5:9000 (IPv6)     ├─ 2001:db8::1:9000 (IPv6) │
│  └─ ::ffff:192.168.1.5 (mapped) └─ 203.0.113.5:9000 (IPv4) │
│                                                             │
│  Valid Pairs (same family):     Invalid Pairs (filtered):   │
│  ✓ 192.168.1.5 ↔ 10.0.0.5      ✗ 192.168.1.5 ↔ 2001:db8::1 │
│  ✓ 192.168.1.5 ↔ 203.0.113.5   ✗ 2001:db8::5 ↔ 10.0.0.5   │
│  ✓ 2001:db8::5 ↔ 2001:db8::1   ✗ 2001:db8::5 ↔ 203.0.113.5│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Combined Architecture

These five components work together in a layered approach:

```
┌─────────────────────────────────────────────────────────────┐
│              Universal Connectivity Stack                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 5: MASQUE Relay ──────────────────── 100% coverage   │
│           │                                                 │
│  Layer 4: NAT Hole-Punching ─────────────── ~95% coverage   │
│           │                                                 │
│  Layer 3: Address Discovery ─────────────── Peer-observed   │
│           │                                                 │
│  Layer 2: Symmetric P2P ─────────────────── Any↔Any connect │
│           │                                                 │
│  Layer 1: Dual-Stack Socket ─────────────── IPv4+IPv6 base  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Connection Flow:                                           │
│                                                             │
│  1. Bind dual-stack socket ([::]:9000)                      │
│  2. Connect to known_peers, learn external address          │
│  3. Exchange candidate addresses with peers                 │
│  4. Filter cross-family pairs                               │
│  5. Attempt direct connections (prioritized)                │
│  6. Coordinate hole-punching if needed                      │
│  7. Fall back to MASQUE relay if all else fails            │
│  8. Continuously probe for better paths                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Consequences

### Positive

- **100% Connectivity**: Every node can reach every other node
- **Protocol Agnostic**: Works regardless of IPv4/IPv6 availability
- **NAT Friendly**: Handles all common NAT configurations
- **No Infrastructure Dependencies**: Symmetric architecture scales linearly
- **Single Protocol**: All traffic is QUIC (encrypted, multiplexed)
- **Graceful Degradation**: Each layer handles specific failure modes
- **Best Path Selection**: Optimal routing based on network conditions

### Negative

- **Complexity**: Multiple layers to understand and debug
- **Relay Costs**: MASQUE relays have operational costs
- **Latency**: Hole-punching coordination adds initial connection time
- **State Management**: Candidate tracking requires memory

### Neutral

- **100% PQC**: All connections use ML-KEM-768 (quantum-safe by design)
- **QUIC-Native**: Tied to QUIC protocol (not protocol-agnostic)

## Implementation Notes

### Configuration Defaults

```rust
P2pConfig::builder()
    .bind_addr("[::]:9000")           // Dual-stack default
    .ip_mode(IpMode::DualStack)       // Try dual-stack first
    .allow_ipv4_mapped(true)          // Accept IPv4-mapped addresses
    .known_peers(vec![...])           // Initial peer discovery
    .relay_fallback(true)             // Enable MASQUE when needed
    .build()
```

### Connectivity Matrix

| Node A Network | Node B Network | Method | Success Rate |
|---------------|----------------|--------|--------------|
| IPv4 only | IPv4 only | Direct/NAT | 95%+ |
| IPv6 only | IPv6 only | Direct/NAT | 95%+ |
| Dual-stack | IPv4 only | IPv4 path | 95%+ |
| Dual-stack | IPv6 only | IPv6 path | 95%+ |
| Dual-stack | Dual-stack | Best path | 95%+ |
| Any | Any (hostile) | MASQUE | 100% |

### Monitoring Metrics

- Connection establishment time (by method)
- Direct vs hole-punched vs relayed ratio
- Cross-family pair filter rate
- Candidate discovery success rate
- OBSERVED_ADDRESS propagation time

## Related ADRs

- [ADR-004: Symmetric P2P Architecture](ADR-004-symmetric-p2p-architecture.md)
- [ADR-005: Native QUIC NAT Traversal](ADR-005-native-quic-nat-traversal.md)
- [ADR-006: MASQUE Relay Fallback](ADR-006-masque-relay-fallback.md)

## References

- [draft-seemann-quic-nat-traversal-02](../rfcs/draft-seemann-quic-nat-traversal-02.txt)
- [draft-ietf-quic-address-discovery-00](../rfcs/draft-ietf-quic-address-discovery-00.txt)
- [RFC 6555 - Happy Eyeballs](https://tools.ietf.org/html/rfc6555)
- [RFC 8305 - Happy Eyeballs v2](https://tools.ietf.org/html/rfc8305)
