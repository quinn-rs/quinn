# Test Coverage for ant-quic

This directory contains test coverage reports for the ant-quic project. We aim to maintain at least 80% code coverage across the codebase.

## Quick Start

### Generate Coverage Report
```bash
# Generate all coverage formats
make coverage

# Generate and view HTML report
make coverage-html

# Quick coverage summary
make coverage-quick

# Detailed analysis with recommendations
make coverage-report
```

### Install Coverage Tools
```bash
# Install required tools
make install-tools

# Or manually:
cargo install cargo-tarpaulin
cargo install cargo-llvm-cov
```

## Coverage Formats

The coverage script generates multiple output formats:

- **HTML Report** (`tarpaulin-report.html`) - Interactive web report
- **JSON Report** (`tarpaulin-report.json`) - Machine-readable data
- **LCOV Report** (`lcov.info`) - For CI integration
- **XML Report** (`cobertura.xml`) - For various tools

## CI Integration

Coverage is automatically generated on:
- Every push to main/master/develop
- Every pull request
- Manual workflow dispatch

Results are:
- Uploaded to Codecov
- Posted as PR comments
- Stored as artifacts

## Coverage Goals

### Current Status
- **Target**: 80% overall coverage
- **Critical modules**: 90% coverage
  - `src/connection/`
  - `src/endpoint/`
  - `src/nat_traversal/`
  - `src/crypto/`

### Excluded from Coverage
- Test files (`*/tests/*`)
- Examples (`*/examples/*`)
- Benchmarks (`*/benches/*`)
- Build scripts (`build.rs`)

## Analyzing Coverage

### View Uncovered Code
```bash
# Run analysis script
python3 scripts/analyze_coverage.py

# View specific module
python3 scripts/analyze_coverage.py --threshold 70
```

### Understanding the Report

The HTML report shows:
- **Green lines**: Covered by tests
- **Red lines**: Not covered
- **Orange lines**: Partially covered (branches)

Focus on:
1. Critical paths (connection, NAT traversal)
2. Error handling code
3. Edge cases
4. Public API surfaces

## Writing Tests to Improve Coverage

### Priority Areas

1. **NAT Traversal** (`src/nat_traversal/`)
   - Test all NAT type combinations
   - Test coordination failures
   - Test timeout scenarios

2. **Connection Management** (`src/connection/`)
   - Test state transitions
   - Test concurrent operations
   - Test error recovery

3. **Frame Processing** (`src/frame.rs`)
   - Test malformed frames
   - Test boundary conditions
   - Test all frame types

### Test Templates

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_path() {
        // Arrange
        let input = setup_test_data();
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_condition() {
        // Test error handling
        let invalid_input = create_invalid_input();
        let result = function_under_test(invalid_input);
        assert!(matches!(result, Err(Error::InvalidInput)));
    }

    #[test]
    fn test_edge_case() {
        // Test boundary conditions
        let edge_case = create_edge_case();
        let result = function_under_test(edge_case);
        verify_edge_case_handling(result);
    }
}
```

## Troubleshooting

### Common Issues

1. **"No coverage data generated"**
   - Ensure tests are actually running
   - Check for test timeouts
   - Verify no tests are hanging

2. **"Coverage below threshold"**
   - Run `make coverage-report` for recommendations
   - Focus on high-priority files first
   - Add tests incrementally

3. **"Tarpaulin crashes"**
   - Try `cargo clean` first
   - Use `--force-clean` flag
   - Consider using cargo-llvm-cov instead

### Platform-Specific Notes

- **Linux**: Works best with tarpaulin
- **macOS**: May need `--exclude-files` adjustments
- **Windows**: Use cargo-llvm-cov for better support

## Badges

Coverage badges are generated automatically:

```markdown
![Coverage](coverage/coverage-badge.svg)
```

Update your README with:
```markdown
[![codecov](https://codecov.io/gh/your-org/ant-quic/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/ant-quic)
```

## Contributing

When submitting PRs:
1. Run `make coverage` locally first
2. Ensure coverage doesn't decrease
3. Add tests for new functionality
4. Focus on meaningful tests, not just coverage numbers

Remember: High coverage doesn't guarantee bug-free code, but it helps catch issues early!