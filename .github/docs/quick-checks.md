# Quick Checks Workflow

## Overview

The `quick-checks.yml` workflow provides fast feedback on code quality for every push and pull request. It runs multiple lightweight checks in parallel to catch common issues early.

## Trigger Conditions

- **Push**: Triggered on pushes to the `master` branch
- **Pull Request**: Triggered on PRs targeting `master`
- **Workflow Call**: Can be called by other workflows

## Jobs

### 1. Format Check
- **Purpose**: Ensures code follows Rust formatting standards
- **Tool**: `cargo fmt`
- **Duration**: ~10 seconds
- **Failure Action**: Block merge

### 2. Clippy Lint
- **Purpose**: Catches common Rust mistakes and enforces best practices
- **Tool**: `cargo clippy`
- **Configuration**: All warnings treated as errors (`-D warnings`)
- **Duration**: ~1 minute
- **Failure Action**: Block merge

### 3. Quick Tests
- **Purpose**: Runs fast unit tests
- **Scope**: Library tests only (`--lib`)
- **Timeout**: 30 seconds hard limit
- **Duration**: <30 seconds
- **Failure Action**: Block merge

### 4. Cargo Check
- **Purpose**: Verifies code compiles on all platforms
- **Platforms**: Ubuntu, Windows, macOS
- **Duration**: ~2 minutes (parallel)
- **Failure Action**: Block merge

### 5. Dependencies Check
- **Purpose**: Identifies dependency issues
- **Tools**: 
  - `cargo-machete`: Finds unused dependencies
  - `cargo-outdated`: Identifies outdated packages
- **Duration**: ~1 minute
- **Failure Action**: Warning only (non-blocking)

### 6. License Header Check
- **Purpose**: Ensures all source files have proper license headers
- **Scope**: All `.rs` files in `src/`, `tests/`, `examples/`
- **License**: MIT/Apache-2.0 dual license
- **Duration**: ~5 seconds
- **Failure Action**: Warning only (non-blocking)

### 7. YAML/TOML Validation
- **Purpose**: Validates configuration files
- **Tools**:
  - `actionlint`: GitHub Actions syntax
  - `cargo verify-project`: Cargo.toml validity
- **Duration**: ~10 seconds
- **Failure Action**: Block merge

## Performance Optimizations

1. **Shallow Clone**: Uses `fetch-depth: 1` for faster checkout
2. **Concurrency Control**: Cancels previous runs on same branch
3. **Caching**: Uses `rust-cache` for dependencies
4. **Parallel Execution**: All jobs run in parallel

## Local Testing

Run all quick checks locally before pushing:

```bash
.github/scripts/test-quick-checks.sh
```

Or run individual checks:

```bash
# Format
cargo fmt --all -- --check

# Clippy
cargo clippy --all-targets --all-features -- -D warnings

# Quick tests
cargo test --lib

# Compilation
cargo check --all-targets
```

## Troubleshooting

### Format Check Fails
```bash
# Auto-fix formatting
cargo fmt --all
```

### Clippy Warnings
```bash
# See detailed clippy suggestions
cargo clippy --all-targets --all-features

# Auto-fix some clippy warnings
cargo clippy --fix
```

### Test Timeout
If tests exceed 30 seconds, they need to be moved to standard or long test suites (implemented in Task 3).

### Cache Issues
If you see stale cache errors:
1. Check the [Actions Cache](https://github.com/YOUR_REPO/actions/caches)
2. Clear problematic caches
3. Re-run the workflow

## Integration with Other Workflows

- **Standard Tests**: Only run after quick checks pass
- **Release**: Calls quick checks as a pre-flight check
- **Long Tests**: Independent, not gated by quick checks

## Configuration

Key settings in the workflow:

```yaml
env:
  RUST_BACKTRACE: 1          # Enable backtraces for debugging
  RUSTFLAGS: "-D warnings"   # Treat warnings as errors

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true   # Cancel old runs when new commits pushed
```

## Success Criteria

All quick checks must complete within **5 minutes** total and provide clear feedback on any issues found.