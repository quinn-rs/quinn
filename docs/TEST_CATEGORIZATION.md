# Test Categorization Guide

This document describes the test categorization system for ant-quic, designed to optimize CI/CD performance and developer experience.

## Overview

Tests are organized into three categories based on execution time:

| Category | Max Duration | Purpose | When to Run |
|----------|-------------|---------|-------------|
| Quick | < 30 seconds | Unit tests, basic integration | Every push/PR |
| Standard | < 5 minutes | Integration, protocol compliance | After quick checks pass |
| Long | > 5 minutes | Stress, comprehensive NAT, performance | Nightly/manual |

## Test Structure

```
tests/
├── quick/           # Fast unit and basic tests
│   ├── main.rs     # Test runner and utilities
│   ├── auth_tests.rs
│   ├── connection_tests.rs
│   ├── crypto_tests.rs
│   └── frame_tests.rs
├── standard/        # Integration and protocol tests
│   ├── main.rs
│   ├── integration_tests.rs
│   ├── protocol_tests.rs
│   └── nat_basic_tests.rs
├── long/           # Comprehensive and stress tests
│   ├── main.rs     # Custom test runner
│   ├── stress_tests.rs
│   ├── nat_comprehensive_tests.rs
│   └── performance_tests.rs
└── legacy/         # Tests pending migration
```

## Running Tests

### Local Development

```bash
# Run only quick tests (recommended during development)
make test-quick
# or
cargo test --test quick

# Run standard integration tests
make test-standard
# or
cargo test --test standard

# Run long tests (requires significant time)
make test-long
# or
cargo test --test long -- --ignored
```

### CI/CD Workflows

1. **Quick Checks** (`quick-checks.yml`)
   - Triggered on every push/PR
   - Runs format, lint, and quick tests
   - Must pass before other workflows

2. **Standard Tests** (`standard-tests.yml`)
   - Triggered after quick checks pass
   - Runs integration and protocol tests
   - Required for merge

3. **Long Tests** (`long-tests.yml`)
   - Scheduled nightly or manual trigger
   - Comprehensive NAT, stress, performance tests
   - Not blocking for PRs

## Writing New Tests

### Quick Tests
- Focus on unit testing individual components
- Mock external dependencies
- Avoid network I/O or file system operations
- Use timeouts < 5 seconds per test

Example:
```rust
#[test]
fn test_frame_encoding() {
    let frame = ObservedAddress::new(/* ... */);
    let encoded = frame.encode();
    let decoded = ObservedAddress::decode(&encoded).unwrap();
    assert_eq!(frame, decoded);
}
```

### Standard Tests
- Test integration between components
- Can use real network sockets (localhost)
- Limited external dependencies
- Use timeouts < 30 seconds per test

Example:
```rust
#[tokio::test]
async fn test_connection_establishment() {
    let (client, server) = create_test_pair().await;
    let conn = client.connect(server.addr()).await.unwrap();
    assert!(conn.is_established());
}
```

### Long Tests
- Comprehensive scenario testing
- Stress and performance testing
- Cross-platform compatibility
- Can use Docker containers
- No timeout restrictions

Example:
```rust
#[test]
#[ignore] // Only run with --ignored flag
fn stress_test_concurrent_connections() {
    const NUM_CONNECTIONS: usize = 1000;
    // Run stress test...
}
```

## Test Categories by Feature

### Quick Tests
- **Authentication**: Basic Ed25519 operations, token validation
- **Frames**: Encoding/decoding, serialization
- **Crypto**: Key generation, certificate validation
- **Connection**: State machine transitions

### Standard Tests
- **NAT Traversal**: Basic hole punching scenarios
- **Protocol**: QUIC compliance, transport parameters
- **Integration**: Client-server communication
- **Chat**: Message exchange protocols

### Long Tests
- **NAT Comprehensive**: All NAT type combinations
- **Stress**: High connection counts, data throughput
- **Performance**: Benchmarks, profiling
- **Cross-Platform**: OS compatibility matrix

## Migration Guide

If you have existing tests to migrate:

1. **Determine Category**: Based on execution time
2. **Move to Module**: Copy test functions to appropriate module
3. **Update Imports**: Ensure all dependencies are imported
4. **Add Attributes**: Use `#[ignore]` for long tests
5. **Update CI**: Ensure test is included in workflow

## Best Practices

1. **Isolation**: Tests should not depend on external services
2. **Determinism**: Avoid time-based or random failures
3. **Cleanup**: Always clean up resources (ports, files)
4. **Documentation**: Document why a test is in its category
5. **Monitoring**: Track test execution times

## Monitoring Test Performance

```bash
# Generate test timing report
cargo test --test quick -- --nocapture --test-threads=1 -Z unstable-options --report-time

# Profile specific test
cargo test --test standard specific_test_name -- --nocapture
```

## Future Improvements

1. **Automatic Categorization**: Based on historical execution times
2. **Parallel Execution**: Within categories for faster CI
3. **Flaky Test Detection**: Automatic retry and reporting
4. **Performance Regression**: Track test execution trends