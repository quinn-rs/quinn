# RFC Compliance Report for ant-quic

## Executive Summary

This report identifies critical RFC compliance issues in the ant-quic implementation compared to the official IETF draft specifications.

## 1. draft-seemann-quic-nat-traversal-02 Compliance Issues

### Transport Parameter
✅ **COMPLIANT**: Using correct transport parameter ID `0x3d7e9f0bca12fea6`

### ADD_ADDRESS Frame Issues
❌ **NON-COMPLIANT**: Frame structure differs from RFC

**RFC Specification:**
```
ADD_ADDRESS Frame {
    Type (i) = 0x3d7e90..0x3d7e91,
    Sequence Number (i),
    [ IPv4 (32) ],
    [ IPv6 (128) ],
    Port (16),
}
```

**Current Implementation Issues:**
1. Includes extra `priority` field not in RFC
2. Uses separate byte for address type instead of frame type bit
3. Frame types 0x3d7e90 (IPv4) and 0x3d7e91 (IPv6) should be distinguished by least significant bit

### PUNCH_ME_NOW Frame Issues
❌ **NON-COMPLIANT**: Frame structure significantly differs from RFC

**RFC Specification:**
```
PUNCH_ME_NOW Frame {
    Type (i) = 0x3d7e92..0x3d7e93,
    Round (i),
    Paired With Sequence Number (i),
    [ IPv4 (32) ],
    [ IPv6 (128) ],
    Port (16),
}
```

**Current Implementation Issues:**
1. Field named `target_sequence` instead of `Paired With Sequence Number`
2. Includes extra `local_address` field not in RFC
3. Includes extra `target_peer_id` field not in RFC
4. Uses separate byte for address type instead of frame type bit
5. Frame types 0x3d7e92 (IPv4) and 0x3d7e93 (IPv6) should be distinguished by least significant bit

### REMOVE_ADDRESS Frame
✅ **COMPLIANT**: Structure matches RFC specification

## 2. draft-ietf-quic-address-discovery-00 Compliance

### Transport Parameter
✅ **COMPLIANT**: Using correct transport parameter ID `0x9f81a176`

### OBSERVED_ADDRESS Frame
✅ **COMPLIANT**: Frame types 0x9f81a6 (IPv4) and 0x9f81a7 (IPv6) are correct

## 3. Critical Issues Summary

1. **Frame Encoding**: Not using least significant bit of frame type to distinguish IPv4/IPv6
2. **Extra Fields**: Implementation includes fields not specified in RFC
3. **Field Names**: Some field names don't match RFC terminology
4. **Address Encoding**: Using separate address type byte instead of frame type differentiation

## 4. Required Fixes

### High Priority
1. Fix ADD_ADDRESS frame to remove `priority` field
2. Fix PUNCH_ME_NOW frame to match RFC structure exactly
3. Update frame encoding to use frame type LSB for IPv4/IPv6 distinction
4. Remove all extra fields not specified in RFC

### Medium Priority
1. Fix compilation warnings in examples and tests
2. Update field names to match RFC terminology

## 5. Implementation Notes

The current implementation appears to have evolved beyond the RFC draft specification, possibly to support additional features. However, for RFC compliance, we must strictly adhere to the draft specifications unless we're implementing experimental extensions (which should be clearly documented).

## 6. Recommendations

1. Create RFC-compliant versions of the frames
2. If extra fields are needed, consider using extension frames or negotiating capabilities
3. Ensure all frame encodings match the RFC byte-for-byte
4. Add comprehensive tests to verify RFC compliance
5. Document any intentional deviations from the RFC