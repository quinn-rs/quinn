# Multi-Node Local Network Testing Guide

This guide explains how to set up and run real NAT traversal tests across multiple physical machines, moving beyond Docker-based simulation to validate ant-quic's behavior in actual network environments.

## Overview

The multi-node testing framework allows you to:
- Test NAT traversal across real network boundaries
- Validate performance with actual NAT devices and ISP configurations
- Test IPv4/IPv6 dual-stack connectivity
- Simulate various network conditions and stress scenarios
- Generate comprehensive test reports with detailed metrics

## Architecture

The framework consists of three main components:

1. **Setup Script** (`scripts/setup-multi-node-test.sh`) - Deploys ant-quic to multiple machines
2. **Test Runner** (`scripts/run-real-nat-traversal-tests.sh`) - Executes NAT traversal tests
3. **Configuration** (`configs/multi-node-test.yaml`) - Defines test scenarios and node configurations

## Prerequisites

### Hardware Requirements
- **Minimum**: 2 physical machines (1 bootstrap node + 1 client node)
- **Recommended**: 3+ machines for comprehensive testing
- **Network**: Machines should be on different network segments or behind different NAT devices

### Software Requirements
- **SSH Access**: Passwordless SSH between test coordinator and all nodes
- **Rust**: All nodes must have Rust installed (`cargo` command available)
- **System Dependencies**: `iptables`, `tc` (traffic control) for network simulation

### Network Requirements
- **Port Access**: UDP ports 9000-9100 should be open/forwarded
- **IPv4/IPv6**: Both protocols supported (IPv6 recommended for better connectivity)
- **NAT Types**: Various NAT types for comprehensive testing (full-cone, restricted, symmetric)

## Quick Start

### 1. Configure Test Environment

Edit `configs/multi-node-test.yaml` to define your test nodes:

```yaml
# Example configuration for local testing
nodes:
  bootstrap:
    - coordinator.local:22
  clients:
    - client1.local:22
    - client2.local:22
    - client3.local:22
  nat_gateways:
    - nat1.local:22
```

### 2. Setup Multi-Node Environment

```bash
# Setup all nodes (deploys ant-quic and configures networks)
make multi-node-setup

# Or run the script directly
./scripts/setup-multi-node-test.sh
```

### 3. Run NAT Traversal Tests

```bash
# Run comprehensive NAT traversal tests
make multi-node-test

# Or run the script directly
./scripts/run-real-nat-traversal-tests.sh
```

### 4. Check Results

Test results are saved to `results/multi-node/` and include:
- Detailed logs from each node
- Performance metrics and timing data
- NAT type detection results
- Comprehensive test reports in multiple formats

## Configuration Details

### Node Configuration

The configuration file supports several node types:

#### Bootstrap Nodes
Coordinate the network and help with NAT traversal:
```yaml
bootstrap:
  - coordinator.example.com:22
  - backup-coordinator.example.com:22
```

#### Client Nodes
Participate in P2P connections and test scenarios:
```yaml
clients:
  - client1.example.com:22
  - client2.example.com:22
  - client3.example.com:22
```

#### NAT Gateways
Simulate different NAT behaviors (optional):
```yaml
nat_gateways:
  - nat-gateway.example.com:22
```

### Test Scenarios

The framework supports multiple test scenarios:

#### Direct Connectivity
Tests basic connectivity between nodes without NAT traversal.

#### NAT Traversal
Tests hole punching and NAT traversal mechanisms across different NAT types.

#### IPv6 Connectivity
Tests dual-stack connectivity using IPv6 addresses.

#### Network Stress Testing
Tests performance under adverse network conditions (packet loss, latency, congestion).

### Network Configuration

Configure network parameters in the config file:

```yaml
network:
  ports:
    ant_quic: 9000
    bootstrap: 9001
    client_base: 9002
    nat_base: 9100

  interfaces:
    internal: eth1
    external: eth0

  ipv6:
    enabled: true
    prefix: "2001:db8::/32"
```

## Advanced Usage

### Custom Test Scenarios

Create custom test scenarios by modifying the test runner script or adding new test functions:

```bash
# Test specific NAT type combinations
./scripts/run-real-nat-traversal-tests.sh --nat-types full_cone,symmetric

# Test with custom network conditions
./scripts/run-real-nat-traversal-tests.sh --network-profile congested

# Test specific node pairs
./scripts/run-real-nat-traversal-tests.sh --nodes client1,client2
```

### Monitoring and Metrics

The framework collects comprehensive metrics:

#### Performance Metrics
- Connection establishment time
- Data transfer rates
- Packet loss statistics
- Latency measurements

#### NAT Detection
- Automatic NAT type detection
- NAT behavior analysis
- Port allocation patterns

#### Network Analysis
- IPv4/IPv6 connectivity status
- Network topology mapping
- Traffic pattern analysis

### Troubleshooting

#### Common Issues

**SSH Connection Failures**
```bash
# Test SSH connectivity manually
ssh -p 22 ant-quic@hostname "echo 'SSH working'"

# Check SSH keys and permissions
chmod 600 ~/.ssh/id_rsa
ssh-add ~/.ssh/id_rsa
```

**NAT Configuration Problems**
```bash
# Check NAT forwarding rules
sudo iptables -t nat -L

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

**Port Access Issues**
```bash
# Test port connectivity
nc -zv hostname 9000

# Check firewall rules
sudo ufw status
sudo iptables -L
```

#### Debug Mode

Run tests in debug mode for detailed logging:

```bash
# Enable debug logging
export LOG_LEVEL=debug
./scripts/run-real-nat-traversal-tests.sh

# Generate verbose reports
./scripts/run-real-nat-traversal-tests.sh --verbose
```

## Integration with CI/CD

### Automated Testing

The multi-node testing framework can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Setup Multi-Node Test
  run: make multi-node-setup

- name: Run NAT Traversal Tests
  run: make multi-node-test

- name: Upload Test Results
  uses: actions/upload-artifact@v3
  with:
    name: multi-node-test-results
    path: results/multi-node/
```

### Pre-commit Hooks

Add multi-node tests to pre-commit validation:

```bash
# Add to .pre-commit-config.yaml
- repo: local
  hooks:
  - id: multi-node-test
    name: Multi-Node NAT Tests
    entry: make multi-node-test
    language: system
    pass_filenames: false
    require_serial: true
```

## Best Practices

### Test Environment Setup

1. **Network Isolation**: Use dedicated test networks to avoid interference
2. **Consistent Configuration**: Ensure all nodes have identical software versions
3. **Resource Allocation**: Allocate sufficient CPU/memory for test nodes
4. **Monitoring**: Implement monitoring to track test progress and resource usage

### Test Execution

1. **Gradual Rollout**: Start with simple scenarios, then increase complexity
2. **Baseline Testing**: Establish performance baselines before major changes
3. **Regression Testing**: Run tests regularly to catch regressions early
4. **Documentation**: Document test results and any issues encountered

### Security Considerations

1. **Network Security**: Ensure test networks are properly isolated
2. **Access Control**: Use SSH keys and restrict access to test nodes
3. **Data Privacy**: Avoid exposing sensitive data during testing
4. **Resource Limits**: Implement resource limits to prevent runaway tests

## Performance Optimization

### Hardware Optimization

- **CPU**: Multi-core systems recommended for concurrent testing
- **Memory**: 4GB+ RAM per node for optimal performance
- **Network**: Gigabit Ethernet or better for accurate measurements
- **Storage**: SSD storage for faster test execution

### Software Optimization

- **Compilation**: Use release builds for better performance
- **Parallelization**: Run multiple test scenarios concurrently
- **Caching**: Implement result caching to avoid redundant tests
- **Cleanup**: Regular cleanup of test artifacts and logs

## Troubleshooting Guide

### Common Error Messages

**"SSH connection failed"**
- Check SSH keys and network connectivity
- Verify hostname resolution and port access
- Ensure SSH service is running on target nodes

**"NAT traversal failed"**
- Check NAT device configuration and port forwarding
- Verify firewall rules allow UDP traffic
- Test with simpler network topologies first

**"Test timeout exceeded"**
- Increase timeout values in configuration
- Check network performance and latency
- Verify system resources are adequate

### Debug Commands

```bash
# Check system status on all nodes
./scripts/setup-multi-node-test.sh --status

# Collect logs from all nodes
./scripts/setup-multi-node-test.sh --collect-logs

# Test individual components
./scripts/run-real-nat-traversal-tests.sh --test direct_connectivity

# Validate configuration
./scripts/setup-multi-node-test.sh --validate-config
```

## Contributing

### Adding New Test Scenarios

1. Add test function to `scripts/run-real-nat-traversal-tests.sh`
2. Update configuration file with new scenario parameters
3. Add documentation for the new test scenario
4. Update Makefile targets if needed

### Improving Test Infrastructure

1. Enhance error handling and recovery mechanisms
2. Add support for additional NAT types and network conditions
3. Implement better monitoring and metrics collection
4. Optimize test execution for faster results

## Support

For issues and questions:

1. **Documentation**: Check this guide and related documentation
2. **Issues**: Report bugs and feature requests in the project repository
3. **Community**: Join discussions in the project forums or chat
4. **Examples**: Review example configurations and test scenarios

## References

- [NAT Traversal RFC Implementation Status](../../RFC_NAT_TRAVERSAL_IMPLEMENTATION_STATUS.md)
- [Docker NAT Testing Guide](../docker/NAT_TESTING_GUIDE.md)
- [Network Testing Best Practices](../../docs/guides/NETWORK_TESTING_BEST_PRACTICES.md)
- [Performance Testing Guide](../../docs/guides/PERFORMANCE_TESTING_GUIDE.md)