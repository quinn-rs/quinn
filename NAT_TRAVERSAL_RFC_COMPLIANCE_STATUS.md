# NAT Traversal RFC Compliance Status

## Overview

This document summarizes the work completed to ensure ant-quic's NAT traversal implementation complies with draft-seemann-quic-nat-traversal-02.

## Completed Work ✅

### 1. RFC Compliance Analysis
- Identified non-compliant frame structures
- Documented all deviations from RFC specification
- Created detailed migration plan

### 2. Test-Driven Development
- Created comprehensive RFC compliance tests (`tests/nat_traversal_rfc_compliance_tests.rs`)
- All tests passing with correct VarInt encoding
- Tests verify byte-for-byte compliance with RFC

### 3. RFC-Compliant Frame Implementation
- Created `src/frame/rfc_nat_traversal.rs` with:
  - `RfcAddAddress` - compliant ADD_ADDRESS frame
  - `RfcPunchMeNow` - compliant PUNCH_ME_NOW frame  
  - `RfcRemoveAddress` - compliant REMOVE_ADDRESS frame
- Proper frame type encoding (using LSB for IPv4/IPv6)
- No extra fields (priority, target_peer_id, etc.)

### 4. Compatibility Layer
- Created `src/frame/nat_compat.rs` for migration support:
  - Conversion functions between old and RFC formats
  - Priority calculation strategies
  - Compatibility mode configuration
- Tested interoperability between formats

### 5. Migration Strategy
- Created `src/nat_traversal/rfc_migration.rs` with:
  - Dynamic priority calculation (ICE-like, simple, fixed)
  - Frame format detection and conversion
  - Peer capability tracking
  - Gradual migration support

## Current Frame Comparison

### ADD_ADDRESS Frame

**Old Format (Non-compliant):**
```
Type (i) = 0x3d7e90/0x3d7e91
Sequence Number (i)
Priority (i)            // NOT IN RFC!
IP Version (u8)         // NOT IN RFC!
IP Address (32/128 bits)
Port (16 bits)
[Flowinfo (32 bits)]    // IPv6 only, NOT IN RFC!
[Scope ID (32 bits)]    // IPv6 only, NOT IN RFC!
```

**RFC Format (Compliant):**
```
Type (i) = 0x3d7e90 (IPv4) / 0x3d7e91 (IPv6)
Sequence Number (i)
IPv4/IPv6 Address (32/128 bits)
Port (16 bits)
```

### PUNCH_ME_NOW Frame

**Old Format (Non-compliant):**
```
Type (i) = 0x3d7e92/0x3d7e93
Round (i)
Target Sequence (i)     // Wrong name!
IP Version (u8)         // NOT IN RFC!
Local Address + Port
[Target Peer ID (256 bits)] // NOT IN RFC!
```

**RFC Format (Compliant):**
```
Type (i) = 0x3d7e92 (IPv4) / 0x3d7e93 (IPv6)
Round (i)
Paired With Sequence Number (i)
IPv4/IPv6 Address (32/128 bits)
Port (16 bits)
```

## Migration Path

### Phase 1: Compatibility Mode (Current)
- Accept both old and RFC formats
- Calculate priority dynamically when not present
- Use compatibility layer for conversion

### Phase 2: RFC-First Mode
- Send RFC-compliant frames to new peers
- Maintain compatibility with old peers
- Track peer capabilities

### Phase 3: RFC-Only Mode
- Send only RFC-compliant frames
- Reject non-compliant frames
- Full RFC compliance

## Remaining Work 🚧

### High Priority
1. **Wire Protocol Integration**
   - Replace old frame encoding/decoding with RFC versions
   - Update frame parser to handle both formats
   - Implement transport parameter negotiation

2. **NAT Traversal Logic Updates**
   - Update connection establishment to work without priority field
   - Modify candidate pairing to use calculated priorities
   - Remove dependency on target_peer_id field

3. **Integration Testing**
   - End-to-end NAT traversal tests with RFC frames
   - Interoperability testing with other QUIC implementations
   - Performance comparison between old and new formats

### Medium Priority
1. **Configuration Options**
   - Add config flags for RFC compliance mode
   - Implement peer capability detection
   - Create migration timeline settings

2. **Documentation**
   - Update API documentation
   - Create migration guide for users
   - Document breaking changes

### Low Priority
1. **Monitoring and Metrics**
   - Track RFC vs legacy frame usage
   - Monitor migration progress
   - Performance metrics comparison

## Breaking Changes

1. **Priority Field Removal**: Applications relying on explicit priority values will need to use calculated priorities
2. **Frame Structure Changes**: Direct frame manipulation code will need updates
3. **Target Peer ID Removal**: Relay functionality may need alternative implementation

## Testing Strategy

1. **Unit Tests**: ✅ Complete
2. **Integration Tests**: 🚧 In Progress
3. **Interop Tests**: ⏳ Planned
4. **Performance Tests**: ⏳ Planned

## Conclusion

The foundation for RFC compliance is complete with:
- RFC-compliant frame structures implemented
- Comprehensive test coverage
- Compatibility layer for migration
- Clear migration strategy

The next steps focus on integration and gradual migration to ensure smooth transition without breaking existing deployments.