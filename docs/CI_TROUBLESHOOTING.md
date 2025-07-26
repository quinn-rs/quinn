# CI/CD Troubleshooting Guide

## Common Issues and Solutions

### Build Failures

#### Rust Toolchain Issues

**Problem**: `error: no default toolchain configured`
```
Error: The process '/home/runner/.cargo/bin/cargo' failed with exit code 101
```

**Solution**:
```yaml
- uses: dtolnay/rust-toolchain@stable
  with:
    toolchain: stable
    components: rustfmt, clippy
```

#### Cache Corruption

**Problem**: Strange compilation errors after dependency updates

**Solution**:
1. Bump cache version:
   ```yaml
   key: ${{ runner.os }}-cargo-v2-${{ hashFiles('**/Cargo.lock') }}
   ```
2. Or clear cache manually in Actions → Caches

#### Out of Disk Space

**Problem**: `No space left on device`

**Solution**:
```yaml
- name: Free disk space
  run: |
    sudo rm -rf /usr/share/dotnet
    sudo rm -rf /opt/ghc
    sudo rm -rf "/usr/local/share/boost"
    sudo rm -rf "$AGENT_TOOLSDIRECTORY"
```

### Test Failures

#### Flaky Network Tests

**Problem**: External endpoint tests failing intermittently

**Solution**:
```rust
#[test]
#[retry(3)]  // Add retry attribute
async fn test_external_endpoint() {
    // Test code
}
```

Or in workflow:
```yaml
- name: Run tests with retry
  uses: nick-invision/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    command: cargo test external
```

#### Platform-Specific Failures

**Problem**: Tests pass locally but fail on CI

**Debug Steps**:
1. Check OS version:
   ```yaml
   - run: |
       echo "OS: ${{ runner.os }}"
       echo "Version: $(uname -a)"
   ```

2. Enable verbose logging:
   ```yaml
   env:
     RUST_LOG: debug
     RUST_BACKTRACE: full
   ```

3. Use platform-specific conditions:
   ```rust
   #[cfg_attr(target_os = "windows", ignore = "Windows specific issue")]
   #[test]
   fn problematic_test() {}
   ```

#### Timeout Issues

**Problem**: Tests timing out on slower CI runners

**Solution**:
```yaml
# Increase step timeout
- name: Run slow tests
  timeout-minutes: 60  # Increase from default
  run: cargo test --test slow_tests

# Or adjust test timeouts
env:
  TEST_TIMEOUT_MULTIPLIER: 3  # 3x slower than local
```

### Docker Issues

#### Build Failures

**Problem**: `docker: command not found` or build errors

**Solution**:
```yaml
- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@v3
  
- name: Build with proper platform
  run: |
    docker buildx build \
      --platform linux/amd64 \
      --load \
      -t test-image .
```

#### Network Configuration

**Problem**: NAT tests failing due to network setup

**Debug**:
```yaml
- name: Debug Docker network
  run: |
    docker network ls
    docker network inspect bridge
    ip addr show
```

#### Permission Errors

**Problem**: `permission denied` in Docker containers

**Solution**:
```dockerfile
# In Dockerfile
USER root
RUN chmod +x /app/entrypoint.sh

# Or in workflow
- name: Fix permissions
  run: |
    sudo chown -R $USER:$USER .
    chmod +x scripts/*.sh
```

### Security Scanning Issues

#### False Positives

**Problem**: Security scanner flagging safe dependencies

**Solution**:
```toml
# In deny.toml
[advisories]
ignore = [
    "RUSTSEC-2023-0001",  # Known false positive
    # Add explanation for each ignore
]
```

#### Outdated Advisory Database

**Problem**: Missing recent vulnerabilities

**Solution**:
```yaml
- name: Update advisory database
  run: |
    cargo install cargo-audit --locked
    cargo audit --db-update
```

### Performance Regression

#### Benchmark Variability

**Problem**: Benchmarks showing false regressions due to CI variability

**Solution**:
```yaml
# Use dedicated runners if possible
runs-on: [self-hosted, benchmark]

# Or increase sample size
env:
  CRITERION_SAMPLE_SIZE: 200  # Default is 100
```

#### Missing Baseline

**Problem**: No baseline for comparison

**Solution**:
```yaml
- name: Download baseline
  uses: actions/download-artifact@v4
  with:
    name: benchmark-baseline
    path: target/criterion
  continue-on-error: true  # OK if missing
```

### Release Issues

#### Version Mismatch

**Problem**: Tag version doesn't match Cargo.toml

**Solution**:
```bash
# Before tagging
./scripts/verify-version.sh v1.2.3

# Or automated
- name: Verify versions match
  run: |
    CARGO_VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)
    TAG_VERSION="${GITHUB_REF#refs/tags/v}"
    if [ "$CARGO_VERSION" != "$TAG_VERSION" ]; then
      echo "Version mismatch!"
      exit 1
    fi
```

#### Publishing Failures

**Problem**: `cargo publish` fails

**Common causes**:
1. Invalid token
2. Version already exists
3. Missing dependencies

**Debug**:
```yaml
- name: Dry run publish
  run: cargo publish --dry-run --verbose
```

### Debugging Workflows

#### Enable Debug Logging

1. Go to Settings → Secrets → Actions
2. Add these secrets:
   - `ACTIONS_STEP_DEBUG` = `true`
   - `ACTIONS_RUNNER_DEBUG` = `true`

#### SSH into Runner

For complex debugging:
```yaml
- name: Setup tmate session
  if: ${{ failure() }}
  uses: mxschmitt/action-tmate@v3
  timeout-minutes: 15
```

#### Local Testing with act

```bash
# Install act
brew install act

# List workflows
act -l

# Run specific job
act -j quick-checks

# With secrets
act -j release --secret-file .env.secrets
```

### GitHub Actions Limits

#### Rate Limits

**Problem**: `API rate limit exceeded`

**Solution**:
```yaml
- name: Wait for rate limit
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    gh api rate_limit
    sleep 60  # If needed
```

#### Concurrency Limits

**Problem**: Jobs queued for long time

**Solution**:
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

#### Storage Limits

**Problem**: Artifact storage full

**Solution**:
1. Reduce retention:
   ```yaml
   retention-days: 3  # Instead of default 90
   ```

2. Clean up old artifacts:
   ```yaml
   - uses: c-hive/gha-remove-artifacts@v1
     with:
       age: '1 week'
   ```

## Getting Help

### Diagnostics Commands

Add this job for debugging:
```yaml
debug-info:
  runs-on: ${{ matrix.os }}
  strategy:
    matrix:
      os: [ubuntu-latest, macos-latest, windows-latest]
  steps:
    - name: System info
      run: |
        echo "::group::System Information"
        uname -a || echo "Not Unix"
        echo "::endgroup::"
        
        echo "::group::Environment Variables"
        env | sort
        echo "::endgroup::"
        
        echo "::group::Tool Versions"
        rustc --version
        cargo --version
        docker --version || echo "Docker not available"
        echo "::endgroup::"
        
        echo "::group::Network Configuration"
        ip addr || ipconfig || echo "No network info"
        echo "::endgroup::"
```

### Useful Resources

1. [GitHub Actions Documentation](https://docs.github.com/en/actions)
2. [GitHub Status](https://www.githubstatus.com/)
3. [Actions Virtual Environments](https://github.com/actions/virtual-environments)
4. [Community Forum](https://github.community/c/code-to-cloud/github-actions/41)

### Opening Issues

When reporting CI issues:
1. Link to failing workflow run
2. Include relevant logs (sanitized)
3. Mention if it's consistent or intermittent
4. Include any recent changes
5. Tag with `ci/cd` label