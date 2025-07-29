# Long Tests Guide

This guide explains the long-running test infrastructure for ant-quic, including how to run, manage, and optimize tests that take more than 5 minutes.

## Overview

Long tests are critical for validating:
- System behavior under sustained load
- Memory leaks and resource exhaustion
- NAT traversal reliability over time
- Performance characteristics at scale
- Edge cases that only appear after extended operation

## Test Categories

### 1. Stress Tests (~15-60 minutes)
Tests system behavior under high load:
- **connection-storm**: 1000+ simultaneous connections
- **high-throughput**: Sustained data transfer
- **memory-stress**: Memory allocation patterns

### 2. Performance Benchmarks (~30-120 minutes)
Extended performance measurements:
- Connection establishment rates
- Throughput under various NAT types
- Latency distribution analysis
- Resource usage profiling

### 3. NAT Comprehensive Tests (~30-45 minutes)
Thorough NAT traversal validation:
- All NAT type combinations
- Multi-hop scenarios
- Address change handling
- Timeout edge cases

### 4. Integration Tests (~15-60 minutes)
Large-scale integration scenarios:
- P2P network formation
- Authentication at scale
- Message routing stress tests
- Multi-platform interoperability

### 5. Docker NAT Simulation (~45-90 minutes)
Containerized NAT testing:
- Full Cone NAT
- Restricted NAT
- Port Restricted NAT
- Symmetric NAT
- Carrier-Grade NAT (CGNAT)

## Running Long Tests

### Local Development

#### Quick Run (5-15 minutes)
```bash
# Run all categories with reduced parameters
make long-tests-quick

# Run specific category
make long-tests-stress
```

#### Standard Run (15-60 minutes)
```bash
# Run all long tests
make long-tests

# Run specific categories
make long-tests-performance
make long-tests-nat
```

#### Thorough Run (60+ minutes)
```bash
# Use the test manager directly
.github/scripts/long-test-manager.sh run all thorough

# With resource monitoring
.github/scripts/long-test-manager.sh monitor $$ &
make long-tests
```

### CI/CD Workflows

#### Manual Trigger
```bash
# Via GitHub UI or CLI
gh workflow run long-tests.yml \
  -f test-suite=stress \
  -f test-intensity=normal
```

#### Scheduled Runs
- Weekly: Sunday 3 AM UTC (all tests)
- Release branches: Automatic on push
- PR with label: Add `run-long-tests` label

## Test Configuration

### Environment Variables

```bash
# Test duration controls
export TEST_ITERATIONS=1000     # Number of test iterations
export STRESS_DURATION=3600     # Stress test duration (seconds)
export STRESS_CONNECTIONS=500   # Number of connections

# Performance tuning
export RUST_TEST_THREADS=1      # Prevent test interference
export RUST_TEST_TIME_UNIT=60000 # Test timeout (ms)

# Logging
export RUST_LOG=ant_quic=info   # Log level
export RUST_BACKTRACE=full      # Full backtrace on panic
```

### Configuration Files

#### proptest.toml
```toml
# Extended property test configuration
cases = 10000               # 10x normal
max_shrink_time = 600      # 10 minutes
timeout = 300000           # 5 minutes per test
```

#### stress-config.toml
```toml
[stress]
scenario = "connection-storm"
connections = 1000
duration = 900  # 15 minutes
report_interval = 60
```

## Test Organization

### Directory Structure
```
tests/
├── long/                   # Long-running tests
│   ├── stress_tests.rs
│   ├── performance_tests.rs
│   └── nat_comprehensive_tests.rs
├── integration/           # Integration tests
│   ├── p2p_integration_tests.rs
│   └── auth_comprehensive_tests.rs
└── docker/               # Docker-based tests
    └── nat_docker_integration.rs
```

### Test Attributes
```rust
#[test]
#[ignore]  // Ignored by default
fn long_running_stress_test() {
    // Test implementation
}

// Run with: cargo test -- --ignored
```

## Performance Monitoring

### Resource Monitoring
The test infrastructure automatically monitors:
- CPU usage
- Memory consumption
- Network connections
- File descriptors

### Metrics Collection
```bash
# During test execution
ps aux | grep ant-quic      # Process info
free -m                     # Memory usage
ss -tan | grep ESTAB | wc -l # Connection count
```

### Analysis Tools
```bash
# Generate test report
make long-tests-categorize

# View resource usage
cat resource-monitor.log

# Analyze test results
grep -E "test result:|Peak" test-output.log
```

## Optimizing Long Tests

### 1. Test Parallelization
```rust
// Use test threads wisely
#[test]
fn parallel_safe_test() {
    // Can run in parallel
}

#[test]
#[serial]  // From serial_test crate
fn exclusive_test() {
    // Runs exclusively
}
```

### 2. Resource Limits
```bash
# Set system limits before tests
ulimit -n 65536  # File descriptors
ulimit -u 32768  # Processes
```

### 3. Test Data Management
```rust
// Use lazy_static for shared test data
lazy_static! {
    static ref TEST_DATA: Arc<TestData> = Arc::new(generate_test_data());
}
```

### 4. Timeout Configuration
```rust
// Per-test timeout
#[test]
#[timeout(Duration::from_secs(300))]
fn test_with_timeout() {
    // Test implementation
}
```

## Troubleshooting

### Common Issues

#### 1. Tests Timing Out
```bash
# Increase timeout
export RUST_TEST_TIME_UNIT=120000  # 2 minutes

# Check for deadlocks
RUST_LOG=trace cargo test specific_test -- --nocapture
```

#### 2. Resource Exhaustion
```bash
# Monitor during test
watch -n 1 'ps aux | grep ant-quic'

# Check limits
ulimit -a
```

#### 3. Flaky Tests
```bash
# Run multiple times to identify flakes
for i in {1..10}; do
    cargo test flaky_test -- --nocapture || break
done
```

### Debug Strategies

1. **Enable verbose logging**:
   ```bash
   RUST_LOG=ant_quic=trace cargo test
   ```

2. **Use test isolation**:
   ```bash
   cargo test -- --test-threads=1
   ```

3. **Profile performance**:
   ```bash
   cargo test --release -- --profile
   ```

## CI/CD Integration

### Workflow Configuration
```yaml
# .github/workflows/long-tests.yml
timeout-minutes: 180  # 3 hour max
concurrency:
  group: long-tests-${{ github.ref }}
  cancel-in-progress: true
```

### Test Artifacts
- Test results: `test-results-*.log`
- Resource monitoring: `resource-monitor.log`
- Performance reports: `benchmark-results/`
- Coverage data: `coverage-report.html`

### Failure Handling
- Automatic issue creation on scheduled test failure
- PR comment with test summary
- Artifact retention for 30-90 days

## Best Practices

1. **Categorize tests appropriately**
   - Quick: < 30 seconds
   - Standard: 30 seconds - 5 minutes
   - Long: > 5 minutes

2. **Use appropriate timeouts**
   - Set realistic timeouts
   - Add buffer for CI variability

3. **Monitor resource usage**
   - Track peak memory usage
   - Monitor connection counts
   - Check for leaks

4. **Document test purpose**
   ```rust
   /// Tests system behavior under sustained load of 1000 connections
   /// over 15 minutes to identify memory leaks and performance degradation.
   #[test]
   #[ignore]
   fn stress_test_connections() {
       // Implementation
   }
   ```

5. **Make tests deterministic**
   - Use fixed seeds for randomness
   - Control time-based behavior
   - Avoid external dependencies

## Advanced Usage

### Custom Test Scenarios
```bash
# Create custom stress scenario
cat > custom-stress.toml << EOF
[stress]
scenario = "custom"
connections = 2000
duration = 7200  # 2 hours
pattern = "burst"
EOF

.github/scripts/long-test-manager.sh run stress normal
```

### Performance Regression Detection
```bash
# Save baseline
cargo bench -- --save-baseline main

# Compare after changes
cargo bench -- --baseline main
```

### Multi-Platform Testing
```bash
# Test across platforms in parallel
parallel -j 3 ::: \
  "ssh linux-box 'cd ant-quic && make long-tests'" \
  "ssh mac-box 'cd ant-quic && make long-tests'" \
  "ssh windows-box 'cd ant-quic && make long-tests'"
```

## Maintenance

### Regular Tasks
1. Review and update test timeouts monthly
2. Analyze flaky tests quarterly
3. Optimize slow tests when identified
4. Update resource limits as needed

### Test Cleanup
```bash
# Remove old test artifacts
find . -name "*.log" -mtime +30 -delete
find target/criterion -mtime +90 -delete
```

### Performance Tracking
- Track test execution times over releases
- Identify performance regressions
- Document optimization opportunities

## Related Documentation

- [CI/CD Guide](CI_CD_GUIDE.md) - Overall CI/CD architecture
- [Workflow Reference](WORKFLOW_REFERENCE.md) - Detailed workflow documentation
- [Troubleshooting Guide](CI_TROUBLESHOOTING.md) - Common CI issues
- [Testing Guide](TESTING_GUIDE.md) - General testing practices