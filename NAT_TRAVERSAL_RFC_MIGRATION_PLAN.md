# NAT Traversal RFC Compliance Migration Plan

## Overview

This document outlines the plan to migrate the current NAT traversal frame implementations to be fully compliant with draft-seemann-quic-nat-traversal-02.

## Current Issues

### 1. ADD_ADDRESS Frame
- **Extra field**: `priority` (not in RFC)
- **Wrong encoding**: Uses separate byte for IP version instead of frame type LSB
- **Extra encoding**: IPv6 includes flowinfo and scope_id (not in RFC)

### 2. PUNCH_ME_NOW Frame  
- **Wrong field name**: `target_sequence` should be `paired_with_sequence_number`
- **Extra field**: `local_address` (RFC only specifies the target address)
- **Extra field**: `target_peer_id` (not in RFC)
- **Wrong encoding**: Uses separate byte for IP version instead of frame type LSB

### 3. Transport Parameter
- ✅ Correct ID: `0x3d7e9f0bca12fea6`

## Migration Strategy

### Phase 1: Create Compatibility Layer
1. Keep existing frame structures for backward compatibility
2. Add RFC-compliant versions alongside existing ones
3. Add feature flag `rfc_compliant_nat_traversal` to switch between them

### Phase 2: Update Encode/Decode Logic
1. Fix frame type encoding to use LSB for IPv4/IPv6 distinction
2. Remove extra fields from encoding
3. Add compatibility mode that can read both old and new formats

### Phase 3: Update NAT Traversal Logic
1. Update connection/nat_traversal.rs to work without priority field
2. Update hole punching logic to work without local_address in PUNCH_ME_NOW
3. Update bootstrap relay logic to work without target_peer_id

### Phase 4: Testing & Validation
1. Add comprehensive tests for RFC compliance
2. Test interoperability between old and new implementations
3. Validate against reference implementations

### Phase 5: Deprecation
1. Mark old frame formats as deprecated
2. Add migration guide for users
3. Plan removal in next major version

## Implementation Details

### ADD_ADDRESS Frame (RFC-compliant)
```rust
pub struct AddAddress {
    pub sequence_number: VarInt,
    pub address: SocketAddr,  // No priority field
}
```

Encoding:
- Frame type: 0x3d7e90 (IPv4) or 0x3d7e91 (IPv6)
- Sequence Number (VarInt)
- IPv4 (32 bits) or IPv6 (128 bits) based on frame type
- Port (16 bits)

### PUNCH_ME_NOW Frame (RFC-compliant)
```rust
pub struct PunchMeNow {
    pub round: VarInt,
    pub paired_with_sequence_number: VarInt,  // Renamed
    pub address: SocketAddr,  // Target address only
}
```

Encoding:
- Frame type: 0x3d7e92 (IPv4) or 0x3d7e93 (IPv6)
- Round (VarInt)
- Paired With Sequence Number (VarInt)
- IPv4 (32 bits) or IPv6 (128 bits) based on frame type
- Port (16 bits)

## Risks & Mitigations

### Risk 1: Breaking Existing Deployments
**Mitigation**: Use compatibility layer and feature flags to allow gradual migration

### Risk 2: Loss of Functionality
**Mitigation**: Ensure NAT traversal works without extra fields before removing them

### Risk 3: Interoperability Issues
**Mitigation**: Extensive testing with other QUIC implementations

## Timeline

- Week 1: Implement RFC-compliant frames alongside existing ones
- Week 2: Add compatibility layer and feature flags
- Week 3: Update NAT traversal logic to work with RFC frames
- Week 4: Testing and validation
- Week 5: Documentation and migration guide
- Week 6: Release with deprecation notices

## Success Criteria

1. All NAT traversal frames match RFC byte-for-byte
2. Existing deployments continue to work with compatibility mode
3. New deployments can use RFC-compliant mode
4. Comprehensive test coverage for both modes
5. Clear migration path documented