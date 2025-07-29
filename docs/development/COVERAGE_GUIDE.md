# Test Coverage Guide for ant-quic

This guide explains how to use and improve test coverage for the ant-quic project.

## Quick Start

### 1. Install Coverage Tools

```bash
# Install cargo-tarpaulin (recommended for Linux/macOS)
cargo install cargo-tarpaulin

# Alternative: cargo-llvm-cov (better Windows support)
cargo install cargo-llvm-cov
```

### 2. Generate Coverage Reports

```bash
# Quick coverage check
make coverage-quick

# Full HTML report
make coverage-html

# All formats with analysis
make coverage-report

# CI mode (fails if below 80%)
make coverage-ci
```

### 3. View Results

- **HTML Report**: Open `coverage/tarpaulin-report.html` in a browser
- **Summary**: Check console output for overall percentage
- **Analysis**: Run `python3 scripts/analyze_coverage.py` for recommendations

## Understanding Coverage Metrics

### Coverage Types

1. **Line Coverage**: Percentage of code lines executed by tests
2. **Branch Coverage**: Percentage of conditional branches tested
3. **Function Coverage**: Percentage of functions called by tests

### Coverage Targets

- **Overall Target**: 80% minimum
- **Critical Modules**: 90% minimum
  - Connection handling (`src/connection/`)
  - NAT traversal (`src/nat_traversal/`)
  - Frame processing (`src/frame.rs`)
  - Cryptography (`src/crypto/`)

### Interpreting Results

In the HTML report:
- **Green**: Fully covered lines
- **Red**: Uncovered lines
- **Orange**: Partially covered (some branches untested)

## Improving Coverage

### 1. Identify Gaps

```bash
# List files with low coverage
python3 scripts/analyze_coverage.py --threshold 50

# Show top 10 files needing tests
python3 scripts/analyze_coverage.py --top 10
```

### 2. Focus Areas

Priority order for adding tests:

1. **Error Handling Paths**
   ```rust
   #[test]
   fn test_error_conditions() {
       let result = risky_operation();
       assert!(matches!(result, Err(Error::Expected)));
   }
   ```

2. **Edge Cases**
   ```rust
   #[test]
   fn test_boundary_conditions() {
       assert_eq!(handle_size(0), Ok(()));
       assert_eq!(handle_size(MAX_SIZE), Ok(()));
       assert!(handle_size(MAX_SIZE + 1).is_err());
   }
   ```

3. **State Transitions**
   ```rust
   #[test]
   fn test_state_machine() {
       let mut state = State::Initial;
       state = state.transition(Event::Start);
       assert_eq!(state, State::Running);
   }
   ```

### 3. Writing Effective Tests

#### Test Template
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_test_name() {
        // Arrange: Set up test data
        let input = TestData::new();
        
        // Act: Execute the code under test
        let result = function_under_test(input);
        
        // Assert: Verify the outcome
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }
}
```

#### NAT Traversal Tests
```rust
#[test]
fn test_nat_traversal_coordination() {
    let coordinator = create_test_coordinator();
    let client_a = create_test_client("A");
    let client_b = create_test_client("B");
    
    // Test coordination flow
    let result = coordinator.coordinate(&client_a, &client_b).await;
    assert!(result.is_ok());
    
    // Verify hole punching occurred
    assert!(client_a.has_punched_hole());
    assert!(client_b.has_punched_hole());
}
```

#### Frame Processing Tests
```rust
#[test]
fn test_frame_roundtrip() {
    let original = ObservedAddress {
        sequence_number: VarInt(42),
        addr: "192.168.1.1:8080".parse().unwrap(),
    };
    
    // Encode
    let mut buf = Vec::new();
    original.encode(&mut buf);
    
    // Decode
    let decoded = ObservedAddress::decode(&mut &buf[..], false).unwrap();
    
    // Verify roundtrip
    assert_eq!(original, decoded);
}
```

## CI/CD Integration

### GitHub Actions

The project includes automated coverage reporting:

```yaml
# .github/workflows/coverage.yml
- Runs on every push and PR
- Generates coverage reports
- Uploads to Codecov
- Comments on PRs with coverage changes
- Fails if coverage drops below 80%
```

### Local Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
make coverage-quick
if [ $? -ne 0 ]; then
    echo "Coverage check failed. Please add tests."
    exit 1
fi
```

## Common Issues

### 1. Tests Not Counted

**Problem**: Some tests don't contribute to coverage
**Solution**: Ensure tests actually execute the code path

```rust
// Bad: Test might be optimized away
#[test]
fn test_trivial() {
    assert!(true);
}

// Good: Actually tests code
#[test]
fn test_real_functionality() {
    let result = my_function(42);
    assert_eq!(result, 84);
}
```

### 2. Async Tests

**Problem**: Async tests may not be fully covered
**Solution**: Use proper async test attributes

```rust
#[tokio::test]
async fn test_async_operation() {
    let result = async_function().await;
    assert!(result.is_ok());
}
```

### 3. Platform-Specific Code

**Problem**: Code for other platforms shows as uncovered
**Solution**: Use conditional compilation in tests

```rust
#[cfg(target_os = "linux")]
#[test]
fn test_linux_specific() {
    // Linux-specific test
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_specific() {
    // Windows-specific test
}
```

## Best Practices

1. **Test Behavior, Not Implementation**
   - Focus on public APIs
   - Test outcomes, not internal details

2. **Maintain Test Quality**
   - Each test should have a clear purpose
   - Avoid duplicate tests
   - Keep tests simple and focused

3. **Balance Coverage vs. Value**
   - 100% coverage ≠ bug-free code
   - Focus on critical paths first
   - Some code (like panic handlers) may not need tests

4. **Regular Coverage Checks**
   - Run `make coverage-quick` before commits
   - Review coverage trends over time
   - Address coverage drops immediately

## Resources

- [Cargo Tarpaulin Documentation](https://github.com/xd009642/tarpaulin)
- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Property Testing with Proptest](https://proptest-rs.github.io/proptest/)
- [Mocking with Mockall](https://docs.rs/mockall/)