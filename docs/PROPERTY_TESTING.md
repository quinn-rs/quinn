# Property-Based Testing Guide

This guide explains the property-based testing approach used in ant-quic to ensure protocol correctness and robustness.

## Overview

Property-based testing verifies that certain properties or invariants hold for all possible inputs, rather than testing specific examples. We use both `proptest` and `quickcheck` to generate random test inputs and automatically minimize failing cases.

## Test Organization

Property tests are located in `tests/property_tests/` with the following structure:

```
tests/property_tests/
├── mod.rs                    # Main module and configuration
├── generators.rs             # Custom input generators
├── frame_properties.rs       # Frame encoding/decoding properties
├── nat_properties.rs         # NAT traversal properties
├── transport_properties.rs   # Transport parameter properties
├── connection_properties.rs  # Connection state machine properties
└── crypto_properties.rs      # Cryptographic operation properties
```

## Key Properties Tested

### 1. Frame Properties

- **Encoding/Decoding Roundtrips**: All frames can be encoded and decoded without loss
- **Size Constraints**: Encoded frames respect size limits
- **Type Safety**: Frame types are preserved through serialization
- **Invariants**: Frame-specific invariants (e.g., ACK ranges)

```rust
proptest! {
    #[test]
    fn frame_roundtrip(frame in arb_frame()) {
        let encoded = encode_frame(&frame);
        let decoded = decode_frame(&encoded)?;
        prop_assert_eq!(frame, decoded);
    }
}
```

### 2. NAT Traversal Properties

- **Role Consistency**: NAT roles behave according to specification
- **Address Priority**: Address types have correct priority ordering
- **Hole Punching**: Coordination maintains timing constraints
- **State Machine**: NAT traversal states follow valid transitions

### 3. Transport Properties

- **Parameter Validation**: All parameters within valid ranges
- **Relationship Invariants**: Related parameters maintain consistency
- **Encoding Stability**: Parameters survive encoding/decoding
- **Size Limits**: Encoded size within protocol limits

### 4. Connection Properties

- **Stream ID Allocation**: IDs follow QUIC rules (client/server, uni/bidi)
- **State Transitions**: Connection states only move forward
- **Flow Control**: Windows never exceed limits
- **Packet Numbering**: Numbers unique within spaces

### 5. Cryptographic Properties

- **Key Derivation**: Deterministic for same inputs
- **Nonce Uniqueness**: Each packet gets unique nonce
- **Header Protection**: Reversible operations
- **Fragment Reassembly**: No data loss in fragmentation

## Writing Property Tests

### 1. Define Generators

Create custom generators for your types in `generators.rs`:

```rust
pub fn arb_varint() -> impl Strategy<Value = VarInt> {
    prop_oneof![
        (0u64..=63).prop_map(|n| VarInt::from_u32(n as u32)),
        (64u64..=16383).prop_map(|n| VarInt::from_u32(n as u32)),
        // ... more ranges
    ]
}
```

### 2. Write Properties

Express invariants as property tests:

```rust
proptest! {
    #[test]
    fn connection_id_uniqueness(
        ids in prop::collection::vec(arb_connection_id(), 1..20)
    ) {
        let unique_ids: HashSet<_> = ids.iter().collect();
        prop_assert!(unique_ids.len() > ids.len() / 2,
            "Too many duplicate connection IDs");
    }
}
```

### 3. Configure Test Runs

Use different configurations for different scenarios:

```rust
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,              // Number of test cases
        max_shrink_iters: 50000,  // Shrinking iterations
        ..Default::default()
    })]
    
    #[test]
    fn expensive_property_test(...) {
        // Test implementation
    }
}
```

## Running Property Tests

### Local Development

```bash
# Run all property tests
cargo test --test property_tests

# Run specific suite
cargo test --test property_tests frame_properties

# Run with more cases
PROPTEST_CASES=1000 cargo test --test property_tests

# Run with verbose output
cargo test --test property_tests -- --nocapture
```

### CI/CD Integration

Property tests run automatically in CI with different configurations:

1. **Quick Tests**: 100 cases on every PR
2. **Standard Tests**: 256 cases on merge to master
3. **Extended Tests**: 1024 cases weekly
4. **Matrix Tests**: Feature combinations

### Debugging Failures

When a property test fails, proptest automatically minimizes the failing input:

```
Test failed with input: [complex data structure]
Minimized to: VarInt(64)
Saved to: proptest-regressions/module/test_name.txt
```

To reproduce:
```bash
# Run the specific failing case
cargo test --test property_tests failing_test_name
```

## Best Practices

### 1. Make Properties Specific

```rust
// Bad: Too general
prop_assert!(result.is_ok());

// Good: Specific property
prop_assert_eq!(decoded.packet_number, original.packet_number);
prop_assert!(decoded.timestamp >= original.timestamp);
```

### 2. Use Appropriate Generators

```rust
// Bad: Too random
any::<Vec<u8>>()

// Good: Constrained to valid range
arb_bytes(1200..1500)  // Valid QUIC packet sizes
```

### 3. Consider Shrinking

Make generators shrink toward simpler cases:

```rust
// Shrinks toward smaller numbers
(0u64..1000).prop_map(VarInt::from)

// Shrinks toward empty vec
prop::collection::vec(any::<u8>(), 0..100)
```

### 4. Test Invariants, Not Implementation

```rust
// Bad: Testing implementation details
prop_assert_eq!(hash(&data), 0x12345678);

// Good: Testing properties
prop_assert_ne!(hash(&data), 0);
prop_assert_eq!(hash(&data), hash(&data));  // Deterministic
```

## Performance Considerations

### 1. Generator Efficiency

Avoid expensive operations in generators:

```rust
// Bad: Expensive computation in generator
arb_data().prop_map(|d| expensive_process(d))

// Good: Generate processed data directly
arb_processed_data()
```

### 2. Test Complexity

Keep individual properties focused:

```rust
// Bad: Testing too many things
fn kitchen_sink_property() {
    // 20 different assertions
}

// Good: Focused properties
fn encoding_preserves_type() { ... }
fn encoding_preserves_size() { ... }
```

### 3. Parallel Execution

Property tests can run in parallel:

```bash
cargo test --test property_tests -- --test-threads=8
```

## Integration with Fuzzing

Property tests complement fuzzing:

1. **Property tests**: Verify invariants hold
2. **Fuzzing**: Find edge cases and crashes
3. **Hybrid approach**: Use fuzzer-generated inputs in property tests

## Continuous Improvement

### 1. Add Regressions

When bugs are found, add them as regression tests:

```rust
#[test]
fn regression_issue_123() {
    // Specific case that failed
    let input = VarInt::from(4611686018427387904);
    assert!(encode_decode_roundtrip(input).is_ok());
}
```

### 2. Expand Properties

As understanding grows, add more properties:

```rust
// Initial property
fn packets_have_unique_numbers() { ... }

// Expanded property
fn packet_numbers_increase_monotonically() { ... }
fn packet_number_gaps_are_bounded() { ... }
```

### 3. Monitor Coverage

Use coverage reports to find untested properties:

```bash
cargo tarpaulin --test property_tests
```

## Troubleshooting

### Common Issues

1. **Test Timeout**: Reduce number of cases or optimize generators
2. **Flaky Tests**: Ensure properties are deterministic
3. **Poor Shrinking**: Improve generator shrinking strategies
4. **Memory Usage**: Limit collection sizes in generators

### Debug Mode

Enable detailed output:

```rust
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        verbose: 1,
        ..Default::default()
    })]
}
```

## References

- [Proptest Documentation](https://docs.rs/proptest)
- [QuickCheck Documentation](https://docs.rs/quickcheck)
- [Property-Based Testing Book](https://hypothesis.works/articles/what-is-property-based-testing/)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)