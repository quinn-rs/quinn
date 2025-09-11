# GitHub Actions Workflow Reference

This document provides detailed information about each workflow in the ant-quic CI/CD pipeline.

## Workflow Index

1. [quick-checks.yml](#quick-checks) - Fast validation checks
2. [cross-platform.yml](#cross-platform) - Multi-platform testing
3. [security.yml](#security) - Security scanning
4. [property-tests.yml](#property-tests) - Property-based testing
5. [benchmarks.yml](#benchmarks) - Performance monitoring
6. [docker-nat-tests.yml](#docker-nat-tests) - NAT traversal testing
7. [external-validation.yml](#external-validation) - Real-world endpoint testing
8. [release-enhanced.yml](#release-enhanced) - Release automation
9. [coverage.yml](#coverage) - Code coverage reporting

---

## quick-checks

**File**: `.github/workflows/quick-checks.yml`

### Purpose
Provides fast feedback on code quality issues before running expensive tests.

### Triggers
- Push to any branch
- Pull request (opened, synchronize, reopened)
- Manual dispatch

### Jobs

#### format-check
- **Runner**: ubuntu-latest
- **Steps**:
  1. Check code formatting with `cargo fmt`
  2. Fail if any formatting changes needed
- **Duration**: ~30s

#### lint
- **Runner**: ubuntu-latest
- **Steps**:
  1. Run clippy on library, binaries, and examples
  2. Enforce panic-free policy: forbid `panic`, `unwrap_used`, `expect_used` (tests are checked separately, advisory)
- **Duration**: ~2m

#### quick-test
- **Runner**: ubuntu-latest
- **Steps**:
  1. Run unit tests with 30s timeout
  2. Only library tests (fastest)
- **Duration**: ~30s

#### doc-check
- **Runner**: ubuntu-latest  
- **Steps**:
  1. Build documentation
  2. Check for broken links
- **Duration**: ~1m

### Usage
```bash
# Run locally
make quick-checks
```

---

## cross-platform

**File**: `.github/workflows/cross-platform.yml`

### Purpose
Ensure code compiles and tests pass on all supported platforms.

### Triggers
- Pull request
- Push to main branch
- Weekly schedule (Sundays)
- Manual dispatch

### Matrix

| OS | Target | Toolchain | Features |
|----|--------|-----------|----------|
| ubuntu-latest | x86_64-unknown-linux-gnu | stable | default |
| ubuntu-latest | aarch64-unknown-linux-gnu | stable | via cross |
| macos-latest | x86_64-apple-darwin | stable | default |
| macos-latest | aarch64-apple-darwin | stable | cross-compile |
| windows-latest | x86_64-pc-windows-msvc | stable | default |
| windows-latest | x86_64-pc-windows-gnu | stable-gnu | default |

### Special Builds

#### Android
```yaml
- name: Android ARM64
  target: aarch64-linux-android
  uses: cargo-ndk
```

#### iOS
```yaml
- name: iOS
  target: aarch64-apple-ios
  build-only: true
```

#### WASM
```yaml
- name: WASM
  target: wasm32-unknown-unknown
  features: no-default
```

### Artifacts
- Test results (JUnit XML)
- Build artifacts for failing platforms

---

## security

**File**: `.github/workflows/security.yml`

### Purpose
Scan for security vulnerabilities and license compliance issues.

### Triggers
- Pull request
- Daily at 3 AM UTC
- Manual dispatch

### Checks

#### Vulnerability Scanning
```bash
cargo audit --json > audit-results.json
```
- Checks against RustSec Advisory Database
- Fails on CRITICAL/HIGH vulnerabilities
- Generates SARIF report for GitHub Security

#### License Compliance
```bash
cargo deny check licenses
```
- Ensures approved licenses only
- Blocks copyleft in dependencies
- Validates license compatibility

#### Dependency Verification
```bash
cargo vet
```
- Cryptographic verification of dependencies
- Supply chain security

### Configuration
- `deny.toml` - License and security policies
- `.cargo/audit.toml` - Vulnerability exceptions

### Outputs
- SARIF reports uploaded to GitHub Security
- JSON reports as artifacts
- Summary in PR comments

---

## property-tests

**File**: `.github/workflows/property-tests.yml`

### Purpose
Run extensive randomized testing to find edge cases.

### Triggers
- Pull request (with path filters)
- Nightly at 1 AM UTC
- Manual dispatch with intensity control

### Test Suites

#### Frame Properties
- Encoding/decoding roundtrips
- Size boundary testing
- Invalid input handling
- **Cases**: 10,000 per property

#### NAT Traversal Properties
- State machine invariants
- Timing constraint validation
- Message ordering
- **Cases**: 5,000 per property

#### Connection Properties  
- Establishment sequences
- Migration scenarios
- Error propagation
- **Cases**: 1,000 per property

### Configuration Options
```yaml
inputs:
  test_intensity:
    description: 'Test intensity'
    options: [quick, standard, exhaustive]
    default: standard
```

### Failure Handling
- Minimized failing examples saved
- Seed for reproduction
- Detailed shrinking output

---

## benchmarks

**File**: `.github/workflows/benchmarks.yml`

### Purpose
Monitor performance and prevent regressions.

### Triggers
- Pull request (with benchmark label)
- Weekly on main branch
- Manual dispatch

### Benchmark Suites

#### Connection Benchmarks
- Handshake performance
- Data transfer throughput
- Connection migration overhead

#### Frame Benchmarks
- Encoding/decoding speed
- Memory allocation patterns
- Batch processing performance

#### NAT Traversal Benchmarks
- Hole punching latency
- Candidate discovery time
- Success rate metrics

### Regression Detection
```python
# Threshold configuration
REGRESSION_THRESHOLD = 0.15  # 15% slower = regression
IMPROVEMENT_THRESHOLD = 0.10  # 10% faster = improvement
```

### Outputs
- HTML reports with graphs
- Comparison tables in PR comments
- Historical trend data

---

## docker-nat-tests

**File**: `.github/workflows/docker-nat-tests.yml`

### Purpose
Test NAT traversal in controlled network environments.

### Triggers
- Pull request (NAT-related changes)
- Manual dispatch

### Test Scenarios

| Scenario | Client NAT | Server NAT | Success Rate |
|----------|------------|------------|--------------|
| Easy | Full Cone | Full Cone | 100% |
| Moderate | Restricted | Full Cone | 95% |
| Hard | Symmetric | Symmetric | 70% |
| CGNAT | CGNAT | Full Cone | 85% |

### Infrastructure
```yaml
services:
  client:
    build: ./docker/client
    networks: [nat_network]
    
  nat_router:
    build: ./docker/nat-router
    cap_add: [NET_ADMIN]
    
  server:
    build: ./docker/server
    networks: [public_network]
```

### Test Execution
1. Build Docker images
2. Create network topology
3. Configure NAT rules
4. Run connection tests
5. Collect metrics

### Debugging
- Packet captures available
- NAT table dumps
- Connection state logs

---

## external-validation

**File**: `.github/workflows/external-validation.yml`

### Purpose
Validate against real-world QUIC endpoints.

### Triggers
- Daily at 2 AM UTC
- Manual dispatch
- On release

### Endpoints Tested

| Endpoint | Protocol | Purpose |
|----------|----------|---------|
| www.google.com | h3, gQUIC | Major implementation |
| cloudflare-quic.com | h3 | CDN provider |
| facebook.com | h3, mvfst | Social media |
| quic.nginx.org | h3 | Web server |
| test.privateoctopus.com | h3 | Reference implementation |

### Metrics Collected
- Connection success rate
- Handshake time
- Protocol negotiation
- Feature support

### Failure Handling
- Creates GitHub issue if success rate < 80%
- Notifications via Discord webhook
- Detailed failure analysis

---

## release-enhanced

**File**: `.github/workflows/release-enhanced.yml`

### Purpose
Automate the entire release process.

### Triggers
- Push of version tags (v*)
- Manual dispatch with version

### Release Process

#### 1. Validation
- Version format check
- Cargo.toml version match
- Changelog entry exists

#### 2. Build Matrix

| Platform | Target | Binary |
|----------|--------|--------|
| Linux x64 | x86_64-unknown-linux-gnu | ant-quic |
| Linux ARM64 | aarch64-unknown-linux-gnu | ant-quic |
| macOS Intel | x86_64-apple-darwin | ant-quic |
| macOS M1 | aarch64-apple-darwin | ant-quic |
| Windows | x86_64-pc-windows-msvc | ant-quic.exe |

#### 3. Publishing
```bash
# crates.io
cargo publish

# Docker Hub
docker push maidsafe/ant-quic:latest

# GitHub Release
gh release create $VERSION
```

#### 4. Notifications
- Discord webhook
- GitHub release notes
- Crates.io update

### Rollback
```bash
# If issues found
cargo yank --version $VERSION
gh release edit $VERSION --prerelease
```

---

## coverage

**File**: `.github/workflows/coverage.yml`

### Purpose
Generate and track code coverage metrics.

### Triggers
- Pull request
- Push to main
- Weekly

### Coverage Tools

#### cargo-tarpaulin
- Line coverage
- Branch coverage
- Function coverage

#### cargo-llvm-cov
- More accurate for async code
- Better inline function handling

### Thresholds
```yaml
fail_ci_if_error: true
fail_on_decrease: true
threshold_total: 70
threshold_new_files: 80
```

### Reports
- Codecov.io integration
- HTML reports as artifacts
- Coverage badges updated

### Exclusions
```toml
# tarpaulin.toml
exclude = [
  "src/bin/*",
  "tests/*",
  "examples/*"
]
```

---

## Workflow Best Practices

### 1. Idempotency
Workflows should produce same results when re-run:
```yaml
- name: Create directory
  run: mkdir -p output
```

### 2. Timeout Management
Always set reasonable timeouts:
```yaml
jobs:
  test:
    timeout-minutes: 30
    steps:
      - timeout-minutes: 10
```

### 3. Conditional Execution
Skip expensive steps when not needed:
```yaml
- name: Expensive step
  if: github.event_name == 'push' || 
      contains(github.event.pull_request.labels.*.name, 'benchmark')
```

### 4. Secret Management
Never log secrets:
```yaml
- name: Use secret
  env:
    TOKEN: ${{ secrets.TOKEN }}
  run: |
    echo "Using token: ***"
```

### 5. Artifact Management
Clean up artifacts:
```yaml
retention-days: 7  # Don't keep forever
```

## Monitoring

### GitHub Insights
- Actions tab → Workflow runs
- Filter by status, branch, actor
- View timing and logs

### Cost Management
- Monitor billable minutes
- Use concurrency limits
- Cache effectively

### Alerts
Set up notifications for:
- Failed workflows on main
- Security vulnerabilities
- Performance regressions
