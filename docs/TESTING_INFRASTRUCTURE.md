# ant-quic Testing Infrastructure Documentation

This document provides a comprehensive guide to the testing infrastructure for ant-quic, including NAT traversal testing, performance benchmarking, CI/CD pipelines, and deployment procedures.

## Table of Contents

1. [Overview](#overview)
2. [Local Testing](#local-testing)
3. [Docker-based NAT Simulation](#docker-based-nat-simulation)
4. [Performance Benchmarking](#performance-benchmarking)
5. [CI/CD Pipeline](#cicd-pipeline)
6. [DigitalOcean Deployment](#digitalocean-deployment)
7. [Monitoring and Debugging](#monitoring-and-debugging)

## Overview

The ant-quic testing infrastructure provides:

- **Comprehensive Test Suite**: 580+ tests covering all aspects of the protocol
- **NAT Traversal Testing**: Simulates Full Cone, Symmetric, Port Restricted, and CGNAT scenarios
- **Performance Benchmarking**: Throughput, latency, and connection establishment metrics
- **Docker Integration**: Realistic network condition simulation
- **Automated CI/CD**: GitHub Actions workflows for testing and deployment
- **Production Deployment**: Automated deployment to DigitalOcean with health checks

## Local Testing

### Running All Tests

```bash
# Run complete test suite
./scripts/run-integration-tests.sh

# Run with Docker tests enabled (default)
DOCKER_TESTS_ENABLED=true ./scripts/run-integration-tests.sh

# Run with stress tests
STRESS_TESTS_ENABLED=true ./scripts/run-integration-tests.sh

# Run tests in parallel
PARALLEL_EXECUTION=true ./scripts/run-integration-tests.sh
```

### Test Categories

#### Unit Tests
```bash
# Basic unit tests
cargo test --release

# Feature-specific tests
cargo test --features "pqc aws-lc-rs" pqc
cargo test nat_traversal
cargo test frame
```

#### Integration Tests
```bash
# Run specific integration test
cargo test --test integration_test_suite test_basic_p2p_network -- --nocapture

# Run NAT traversal comprehensive tests
cargo test --test nat_traversal_comprehensive -- --nocapture

# Run connection lifecycle tests
cargo test --test connection_lifecycle_tests
```

#### Benchmarks
```bash
# Run throughput benchmarks
cargo bench --bench throughput_benchmarks

# Run latency benchmarks
cargo bench --bench latency_benchmarks

# Run NAT traversal performance benchmarks
cargo bench --bench nat_traversal_performance

# Run connection management benchmarks
cargo bench --bench connection_management
```

### Test Output

Test results are saved in timestamped directories:
```
integration-test-results-YYYYMMDD-HHMMSS/
├── metadata.json       # Test run metadata
├── results.jsonl       # Individual test results
├── summary.md         # Human-readable summary
├── summary.json       # Machine-readable summary
├── logs/              # Test logs
├── reports/           # Detailed reports
└── metrics/           # Performance metrics
```

## Docker-based NAT Simulation

### Prerequisites

- Docker and Docker Compose installed
- Sufficient system resources (8GB RAM recommended)

### NAT Type Simulations

The Docker infrastructure simulates four NAT types:

1. **Full Cone NAT**: Most permissive, allows any external host to send packets
2. **Symmetric NAT**: Most restrictive, different mapping for each destination
3. **Port Restricted NAT**: Allows packets only from specific IP:port pairs
4. **CGNAT**: Carrier-grade NAT with multiple layers

### Running Docker Tests

```bash
# Start Docker test environment
cd docker
docker-compose up -d

# Run specific NAT test
docker exec test-runner /app/run-test.sh full_cone_nat

# Run all NAT scenarios
docker exec test-runner /app/run-test.sh all_nat_tests

# View logs
docker-compose logs -f client-1

# Stop environment
docker-compose down -v
```

### Docker Network Topology

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Bootstrap     │     │  NAT Gateway 1  │     │  NAT Gateway 2  │
│  172.20.0.10    │     │  10.1.0.1       │     │  10.2.0.1       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
    ─────┴───────────────────────┴───────────────────────┴─────
                         Docker Network
    ─────┬───────────────────────┬───────────────────────┬─────
         │                       │                       │
┌────────┴────────┐     ┌────────┴────────┐     ┌────────┴────────┐
│    Client 1     │     │    Client 2     │     │    Client 3     │
│   10.1.0.10     │     │   10.1.0.11     │     │   10.2.0.10     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Configuring NAT Rules

NAT rules are configured in `docker/nat-setup.sh`:

```bash
# Full Cone NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Symmetric NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random

# Port Restricted NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -j DROP
```

## Performance Benchmarking

### Local Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark suite
cargo bench --bench throughput_benchmarks

# Generate baseline
cargo bench --bench throughput_benchmarks -- --save-baseline baseline

# Compare with baseline
cargo bench --bench throughput_benchmarks -- --baseline baseline
```

### Performance Metrics

The benchmarking suite measures:

- **Connection Establishment**: Time to establish QUIC connections
- **Throughput**: Maximum data transfer rate (MB/s)
- **Latency**: Round-trip time for messages (ms)
- **NAT Traversal Success Rate**: Percentage of successful hole punching
- **Concurrent Connections**: Maximum simultaneous connections

### Performance Testing on DigitalOcean

```bash
# Run performance tests against production
./scripts/do-performance-test.sh

# Custom test duration (seconds)
TEST_DURATION=600 ./scripts/do-performance-test.sh

# Test specific scenarios
./scripts/do-performance-test.sh connection_establishment
./scripts/do-performance-test.sh throughput
./scripts/do-performance-test.sh latency
```

### Performance Baselines

Expected performance baselines:

| Metric | Baseline | Acceptable Range |
|--------|----------|------------------|
| Connection Establishment | < 100ms | 50-200ms |
| Throughput (LAN) | > 100 MB/s | 80-150 MB/s |
| Throughput (WAN) | > 10 MB/s | 5-50 MB/s |
| Latency (p50) | < 10ms | 5-20ms |
| Latency (p99) | < 50ms | 20-100ms |
| NAT Traversal Success | > 95% | 90-100% |

## CI/CD Pipeline

### GitHub Actions Workflows

#### 1. Comprehensive CI (`comprehensive-ci.yml`)
Runs on every commit to ensure code quality:

```yaml
on:
  push:
  pull_request:
```

Includes:
- Quick checks (formatting, linting)
- Test matrix (multiple OS/Rust versions)
- Feature tests (different crypto backends)
- Security validation
- Coverage reporting

#### 2. NAT Traversal Tests (`nat_traversal_tests.yml`)
Specialized testing for NAT traversal:

```yaml
on:
  push:
    paths:
      - 'src/nat_traversal/**'
      - 'src/connection/**'
```

Runs:
- Unit tests for NAT components
- Docker-based NAT simulations
- Stress tests for hole punching
- Platform-specific tests

#### 3. Benchmarks (`benchmarks.yml`)
Performance regression testing:

```yaml
on:
  push:
    branches: [master]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
```

Measures:
- Throughput benchmarks
- Latency benchmarks
- NAT traversal performance
- Connection management overhead

#### 4. Deploy to DigitalOcean (`deploy-do.yml`)
Automated deployment pipeline:

```yaml
on:
  push:
    branches: [master]
    tags: ['v*']
  workflow_dispatch:
```

Process:
1. Build and test
2. Create deployment package
3. Deploy to staging (manual trigger)
4. Deploy to production
5. Run performance tests
6. Automatic rollback on failure

### Running CI Locally

```bash
# Install act (GitHub Actions locally)
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run specific workflow
act -W .github/workflows/comprehensive-ci.yml

# Run with specific event
act push -W .github/workflows/nat_traversal_tests.yml

# Run with secrets
act -s GITHUB_TOKEN=$GITHUB_TOKEN
```

## DigitalOcean Deployment

### Prerequisites

1. DigitalOcean droplet with Ubuntu 22.04
2. SSH key configured
3. GitHub secrets configured:
   - `DO_SSH_KEY`: SSH private key
   - `DO_HOST`: Droplet IP address
   - `DO_USER`: SSH username

### Manual Deployment

```bash
# Deploy to production
export DO_HOST="your-droplet-ip"
export DO_USER="your-ssh-user"
./scripts/deploy-do.sh deploy

# Check health
./scripts/deploy-do.sh health

# View logs
./scripts/deploy-do.sh logs

# Rollback
./scripts/deploy-do.sh rollback
```

### Deployment Process

1. **Build**: Compiles release binary with all features
2. **Package**: Creates deployment archive with binary and config
3. **Transfer**: Securely copies to DigitalOcean via SSH
4. **Deploy**: Atomic deployment with systemd service
5. **Verify**: Health checks and connectivity tests
6. **Monitor**: Continuous monitoring and alerting

### Service Configuration

The ant-quic service runs as a systemd service:

```ini
[Unit]
Description=ant-quic P2P Node
After=network.target

[Service]
Type=simple
User=ant-quic
Group=ant-quic
ExecStart=/opt/ant-quic/bin/ant-quic --config /opt/ant-quic/config/ant-quic.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Configuration File

Default configuration (`/opt/ant-quic/config/ant-quic.toml`):

```toml
[server]
listen_addr = "0.0.0.0:9000"
force_coordinator = true
dashboard_enabled = true

[logging]
level = "info"
format = "json"

[performance]
max_connections = 10000
max_streams_per_connection = 100

[nat_traversal]
enable_hole_punching = true
max_candidates = 10
punch_timeout_ms = 5000
```

## Monitoring and Debugging

### Viewing Logs

```bash
# Local logs with filtering
RUST_LOG=ant_quic=debug cargo run --bin ant-quic

# Production logs
ssh user@host "journalctl -u ant-quic -f"

# Docker logs
docker-compose logs -f client-1

# Parse JSON logs
ssh user@host "journalctl -u ant-quic -o json" | jq '.MESSAGE'
```

### Debug Commands

```bash
# Test connectivity
cargo run --bin ant-quic -- --bootstrap quic.saorsalabs.com:9000 --minimal

# Run with dashboard
cargo run --bin ant-quic -- --dashboard --listen 0.0.0.0:9000

# Force coordinator mode
cargo run --bin ant-quic -- --force-coordinator

# Verbose NAT traversal debugging
RUST_LOG=ant_quic::nat_traversal=trace cargo run --bin ant-quic
```

### Performance Monitoring

```bash
# Monitor connection count
watch -n 1 'ss -tan | grep :9000 | wc -l'

# Monitor CPU/memory
htop -p $(pgrep ant-quic)

# Network statistics
iftop -i eth0 -f "port 9000"

# Check NAT traversal stats
curl http://localhost:8080/metrics | grep nat_traversal
```

### Common Issues and Solutions

#### NAT Traversal Failures

1. **Symmetric NAT**: Expected ~85% success rate
   - Solution: Ensure bootstrap node has public IP
   - Enable address prediction in config

2. **Firewall blocking**: Check iptables rules
   ```bash
   sudo iptables -L -n | grep 9000
   ```

3. **Port exhaustion**: Monitor available ports
   ```bash
   ss -s | grep ports
   ```

#### Performance Issues

1. **High CPU usage**: Check for connection loops
   ```bash
   strace -p $(pgrep ant-quic) -c
   ```

2. **Memory leaks**: Monitor RSS growth
   ```bash
   ps aux | grep ant-quic | awk '{print $6}'
   ```

3. **Network congestion**: Check packet loss
   ```bash
   ping -c 100 bootstrap-node | grep loss
   ```

### Reporting Issues

When reporting issues, include:

1. Test results directory (tar.gz)
2. System information: `uname -a`
3. Rust version: `rustc --version`
4. Docker version: `docker --version`
5. Relevant logs with `RUST_LOG=debug`

## Best Practices

1. **Always run tests before deployment**
   ```bash
   ./scripts/run-integration-tests.sh && ./scripts/deploy-do.sh deploy
   ```

2. **Monitor after deployment**
   - Check health endpoint
   - Verify NAT traversal success rate
   - Monitor resource usage

3. **Use feature flags for testing**
   ```bash
   cargo test --features "pqc aws-lc-rs docker-tests stress-tests"
   ```

4. **Regular performance baseline updates**
   ```bash
   cargo bench -- --save-baseline $(date +%Y%m%d)
   ```

5. **Backup before major changes**
   ```bash
   ./scripts/deploy-do.sh backup
   ```

## Conclusion

The ant-quic testing infrastructure provides comprehensive validation of the protocol implementation, with particular focus on NAT traversal reliability. By following this guide, you can:

- Run thorough local and Docker-based tests
- Monitor performance and identify regressions
- Deploy safely to production with automatic rollback
- Debug issues effectively with detailed logging

For additional support, refer to the main project documentation or open an issue on GitHub.