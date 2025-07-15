# Claude Code Task List for Ant-QUIC NAT Traversal Implementation

## CRITICAL DISCOVERY: This is a Fork of quinn-proto

**IMPORTANT**: Investigation reveals that ant-quic is a fork of quinn-proto (part of the quinn QUIC implementation). Evidence:
1. The lib.rs file still contains the original quinn-proto documentation comment: "quinn-proto contains a fully deterministic implementation of QUIC protocol logic"
2. The code structure and files (packet.rs, connection/, endpoint.rs, etc.) match quinn-proto's architecture
3. Core QUIC protocol implementation is already complete from quinn-proto

**Implications**:
- We should NOT be creating a "bridge" to quinn - we already HAVE quinn's core protocol implementation
- The task should be to modify the existing quinn-proto code directly to add NAT traversal
- No need to reimplement QUIC protocol logic - it's already there
- Focus should be on adding the NAT traversal extensions to the existing codebase

**Recommended Approach**:
1. Work within the existing quinn-proto fork structure
2. Add NAT traversal frames to the existing frame handling system
3. Extend the existing connection and endpoint logic
4. No need for a separate "bridge" - just enhance what's already there

## Phase 1: Core Draft Compliance (Priority: CRITICAL)

### Task 1.1: Implement QUIC Extension Frames
**File**: `src/frame/nat_traversal.rs`

```bash
claude-code create src/frame/nat_traversal.rs
```

**Requirements**:
- Implement `AddAddress`, `PunchMeNow`, `RemoveAddress` frame types
- Follow exact encoding from draft-seemann-quic-nat-traversal-01
- Include proper error handling and validation
- Add comprehensive unit tests with test vectors

**Acceptance Criteria**:
- All frames encode/decode according to draft specification
- Support both IPv4 (type bit 0) and IPv6 (type bit 1) variants
- Proper VarInt encoding for sequence numbers and rounds
- Frame type constants match draft: 0x3d7e90-0x3d7e94

### Task 1.2: Enhance Frame Module Integration
**File**: `src/frame/mod.rs`

```bash
claude-code modify src/frame/mod.rs
```

**Requirements**:
- Integrate NAT traversal frames into main frame enum
- Add frame dispatching logic
- Update frame encoding/decoding handlers
- Add frame statistics tracking

### Task 1.3: Transport Parameter Implementation
**File**: `src/transport_parameters.rs`

```bash
claude-code modify src/transport_parameters.rs
```

**Requirements**:
- Add `nat_traversal` parameter (0x3d7e9f0bca12fea6)
- Client: empty value validation
- Server: concurrency limit as VarInt
- 0-RTT compatibility handling
- Parameter validation and error handling

### Task 1.4: Server-side Path Validation
**File**: `src/connection/mod.rs`

```bash
claude-code modify src/connection/mod.rs
```

**Requirements**:
- Enable servers to initiate path validation
- Handle PUNCH_ME_NOW frame reception
- Implement amplification attack mitigation
- Add proper rate limiting for server-initiated validation

## Phase 2: Raw Public Key Support (Priority: CRITICAL)

### Task 2.1: Create Raw Public Key Module
**File**: `src/crypto/raw_keys.rs`

```bash
claude-code create src/crypto/raw_keys.rs
```

**Requirements**:
- Implement RFC 7250 Raw Public Key support
- Custom `ServerCertVerifier` and `ClientCertVerifier`
- SubjectPublicKeyInfo parsing for Ed25519 keys
- TLS extension negotiation (`client_certificate_type`, `server_certificate_type`)
- Follow Iroh's proven implementation pattern

**Key Features**:
- Certificate type value 2 for RawPublicKey
- Ed25519 OID: 1.3.101.112
- Public key extraction without certificate chain validation
- Peer identity mapping from public key

### Task 2.2: Integrate Raw Keys into Config
**File**: `src/config.rs`

```bash
claude-code modify src/config.rs
```

**Requirements**:
- Add `use_raw_public_keys()` method to builders
- `identity_from_ed25519()` for direct keypair input
- Backward compatibility with X.509 certificates
- Configuration validation

### Task 2.3: Update Crypto Module
**File**: `src/crypto/mod.rs`

```bash
claude-code modify src/crypto/mod.rs
```

**Requirements**:
- Export raw key functionality
- Integration with rustls dangerous configuration
- TLS extension support
- Proper feature flagging

## Phase 3: Bootstrap Coordination Enhancement (Priority: HIGH)

### Task 3.1: Enhanced Bootstrap Coordinator
**File**: `src/connection/nat_traversal.rs`

```bash
claude-code modify src/connection/nat_traversal.rs
```

**Requirements**:
- Complete `BootstrapCoordinator` implementation
- PUNCH_ME_NOW relay between peers
- Address observation and ADD_ADDRESS generation
- Coordination session management
- Security validation and rate limiting

### Task 3.2: Multi-destination Transmission
**File**: `src/connection/packet_builder.rs`

```bash
claude-code modify src/connection/packet_builder.rs
```

**Requirements**:
- Enhance `MultiDestinationTransmitter`
- Simultaneous hole punching to multiple destinations
- Adaptive timing based on network conditions
- Coordinate with the draft's round-based approach

### Task 3.3: Connection Migration Support
**File**: `src/connection/paths.rs`

```bash
claude-code modify src/connection/paths.rs
```

**Requirements**:
- Connection migration after successful hole punching
- Path promotion and selection logic
- Graceful fallback mechanisms
- Multi-path connection handling

## Phase 4: High-Level API Enhancement (Priority: MEDIUM)

### Task 4.1: NAT Traversal API Completion
**File**: `src/nat_traversal_api.rs`

```bash
claude-code modify src/nat_traversal_api.rs
```

**Requirements**:
- Complete missing frame transmission methods
- Bridge Quinn Connection to ant-quic Connection
- Implement real Quinn-based bootstrap queries
- Add missing event handling

### Task 4.2: Endpoint Integration
**File**: `src/endpoint.rs`

```bash
claude-code modify src/endpoint.rs
```

**Requirements**:
- Integrate NAT traversal with main endpoint
- Handle extension frame reception/transmission
- Connection establishment flow with NAT traversal
- Error handling and event propagation

## Phase 5: Testing Infrastructure (Priority: HIGH)

### Task 5.1: Comprehensive Test Suite
**Files**: `tests/nat_traversal_*`

```bash
claude-code create tests/nat_traversal_frames.rs
claude-code create tests/raw_keys_integration.rs
claude-code create tests/bootstrap_coordination.rs
claude-code create tests/ipv4_ipv6_traversal.rs
```

**Requirements**:
- Frame encoding/decoding test vectors
- Raw key authentication tests
- Multi-node coordination tests
- IPv4/IPv6 compatibility tests
- Security validation tests
- Performance benchmarks

### Task 5.2: Integration Test Scripts
**Files**: `tests/scripts/*`

```bash
claude-code create tests/scripts/test-symmetric-nat.sh
claude-code create tests/scripts/test-multi-node.sh
claude-code create tests/scripts/benchmark-hole-punching.sh
```

**Requirements**:
- NAT simulation test environments
- Multi-node coordination testing
- Performance benchmarking
- Automated compliance checking

### Task 5.3: Example Applications
**Files**: `examples/p2p_*`

```bash
claude-code create examples/p2p_bootstrap_node.rs
claude-code create examples/p2p_client_raw_keys.rs
claude-code create examples/p2p_server_raw_keys.rs
```

**Requirements**:
- Bootstrap node implementation
- P2P client using raw keys
- P2P server using raw keys
- Complete hole punching demo

## Phase 6: Documentation and Polish (Priority: LOW)

### Task 6.1: API Documentation
**Files**: Various

```bash
claude-code document src/crypto/raw_keys.rs
claude-code document src/frame/nat_traversal.rs
claude-code document src/nat_traversal_api.rs
```

**Requirements**:
- Comprehensive rustdoc comments
- Usage examples in docs
- Integration guides
- Security considerations

### Task 6.2: README and Guides
**Files**: `README.md`, `docs/*`

```bash
claude-code modify README.md
claude-code create docs/NAT_TRAVERSAL.md
claude-code create docs/RAW_KEYS.md
claude-code create docs/P2P_SETUP.md
```

**Requirements**:
- Updated project description
- NAT traversal setup guide
- Raw keys configuration guide
- P2P networking tutorial

## Critical Implementation Notes

### Draft Compliance Requirements
1. **Exact frame format compliance** - Use test vectors from reference implementations
2. **Transport parameter values** - Must match draft specification exactly
3. **Bootstrap coordination** - Follow state machine in draft precisely
4. **Security measures** - Implement all amplification attack mitigations

### Raw Keys Requirements  
1. **Follow RFC 7250** - Certificate type 2, proper TLS extensions
2. **Use Iroh's approach** - Proven implementation pattern from v0.34
3. **Ed25519 support** - Proper OID and SubjectPublicKeyInfo handling
4. **Peer identity** - Map public key to peer ID consistently

### Testing Strategy
1. **Multi-node testing** - Essential for coordination validation
2. **NAT simulation** - Test all NAT types (symmetric, cone, etc.)
3. **IPv4/IPv6 dual-stack** - Ensure proper address family handling
4. **Security testing** - Validate against attack vectors
5. **Performance testing** - Measure hole punching success rates

### Deployment Considerations
1. **Bootstrap node reliability** - Redundant bootstrap infrastructure
2. **Rate limiting** - Prevent DoS attacks on bootstrap nodes
3. **Monitoring** - Comprehensive metrics for production use
4. **Graceful degradation** - Fallback strategies when NAT traversal fails

## Success Metrics

### Functional Requirements
- [ ] All draft-seemann-quic-nat-traversal-01 frames implemented
- [ ] Raw public key authentication working
- [ ] Bootstrap coordination functional
- [ ] IPv4 and IPv6 hole punching successful
- [ ] Connection migration working

### Performance Requirements
- [ ] >90% hole punching success rate
- [ ] <500ms average connection establishment
- [ ] Support 100+ concurrent traversal attempts
- [ ] Minimal memory overhead

### Security Requirements
- [ ] Rate limiting prevents flooding attacks
- [ ] Address validation prevents scanning
- [ ] Security validation comprehensive
- [ ] No amplification vulnerabilities

This task list provides Claude Code with clear, actionable items to implement a complete, standards-compliant P2P QUIC solution with NAT traversal and raw public key authentication.
