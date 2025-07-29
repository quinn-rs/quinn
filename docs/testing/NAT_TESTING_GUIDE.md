# NAT Testing Infrastructure Guide

This guide describes the Docker-based NAT testing infrastructure for ant-quic.

## Overview

The NAT testing infrastructure simulates various NAT scenarios to validate ant-quic's NAT traversal capabilities. It uses Docker containers to create isolated network environments with different NAT configurations.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Bootstrap     │     │   NAT Gateway   │     │     Client      │
│  (Public IP)    │<--->│  (NAT Router)   │<--->│  (Private IP)   │
│ 203.0.113.10    │     │                 │     │ 192.168.x.x     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## NAT Types Simulated

1. **Full Cone NAT** - Least restrictive
   - Any external host can send to the mapped port
   - Common in consumer routers

2. **Restricted Cone NAT** - IP-based filtering
   - Only hosts that received packets can reply
   - Filters by source IP only

3. **Port Restricted NAT** - IP:Port filtering
   - Only specific IP:Port combinations can reply
   - Common in enterprise environments

4. **Symmetric NAT** - Most restrictive
   - Different external ports for different destinations
   - Common in corporate and mobile networks

5. **CGNAT (Carrier-Grade NAT)** - ISP-level NAT
   - Multiple layers of NAT
   - Limited port allocation
   - Shared IP addresses

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- Linux host (for iptables NAT simulation)
- At least 4GB RAM available

### Running Tests

1. **Basic NAT Tests**
   ```bash
   cd docker
   ./scripts/run-nat-tests.sh
   ```

2. **Specific Scenario**
   ```bash
   # Test only symmetric NAT scenarios
   docker compose up nat2_gateway client2 bootstrap
   docker exec ant-quic-client2 ant-quic --bootstrap 203.0.113.10:9000
   ```

3. **CI/CD Integration**
   ```bash
   # Run in GitHub Actions
   gh workflow run nat-tests.yml
   ```

## Test Scenarios

### 1. Basic Connectivity
Tests that clients can reach the bootstrap node through their NATs.

### 2. Peer-to-Peer Traversal
Tests direct connections between clients behind different NAT types:
- Full Cone ↔ Full Cone (should always work)
- Full Cone ↔ Symmetric (usually works)
- Symmetric ↔ Symmetric (challenging, requires coordination)
- Port Restricted ↔ CGNAT (very challenging)

### 3. Network Stress
Tests NAT traversal under adverse conditions:
- 5% packet loss
- 100ms added latency
- Bandwidth limitations
- Connection churn

### 4. Double NAT
Tests traversal through multiple NAT layers, common in:
- Home router + ISP CGNAT
- Corporate network + VPN
- Container + Host NAT

## Configuration

### Docker Compose Services

```yaml
services:
  bootstrap:       # Public coordinator node
  nat1_gateway:    # Full Cone NAT
  nat2_gateway:    # Symmetric NAT
  nat3_gateway:    # Port Restricted NAT
  nat4_gateway:    # CGNAT
  client1-4:       # Test clients
```

### Environment Variables

- `NAT_TYPE`: Type of NAT to simulate
- `LOG_LEVEL`: Logging verbosity (debug/info/warn/error)
- `TEST_DURATION`: How long to run tests
- `INTERNAL_NET`: Private network CIDR
- `EXTERNAL_IFACE`: WAN interface name

### Network Configuration

```yaml
networks:
  internet:        # Public network (203.0.113.0/24)
  nat1_lan:        # Private network 1 (192.168.1.0/24)
  nat2_lan:        # Private network 2 (192.168.2.0/24)
  nat3_lan:        # Private network 3 (10.0.0.0/24)
  nat4_lan:        # Private network 4 (10.1.0.0/24)
```

## Test Results

Results are saved in `docker/results/`:
- `summary.txt` - Overall test summary
- `*.log` - Individual test logs
- `nat-test-report-*.html` - HTML report

### Success Criteria

- Bootstrap connectivity: 100% success rate
- Same NAT type traversal: >95% success rate
- Different NAT types: >80% success rate
- Symmetric-to-Symmetric: >60% success rate
- Under network stress: >70% success rate

## Debugging

### View NAT Rules
```bash
docker exec nat1_gateway iptables -t nat -L -n -v
```

### Monitor Connections
```bash
docker exec nat1_gateway conntrack -L
```

### Packet Capture
```bash
docker exec nat1_gateway tcpdump -i any -w /tmp/capture.pcap udp port 9000
docker cp nat1_gateway:/tmp/capture.pcap ./
```

### Container Logs
```bash
docker compose logs -f client1
docker compose logs -f nat1_gateway
```

## Troubleshooting

### Common Issues

1. **"Connection refused" errors**
   - Check if services are running: `docker compose ps`
   - Verify iptables rules: `docker exec nat1_gateway iptables -L`

2. **"No route to host"**
   - Check network configuration: `docker network ls`
   - Verify IP forwarding: `docker exec nat1_gateway sysctl net.ipv4.ip_forward`

3. **Tests timing out**
   - Increase TEST_DURATION
   - Check CPU/memory resources: `docker stats`

4. **Inconsistent results**
   - Ensure clean environment: `docker compose down -v`
   - Check for port exhaustion on symmetric NAT

### Debug Mode

Enable verbose logging:
```bash
LOG_LEVEL=debug ./scripts/run-nat-tests.sh
```

View detailed packet flow:
```bash
docker exec nat1_gateway iptables -t nat -A POSTROUTING -j LOG --log-prefix "NAT: "
docker exec nat1_gateway dmesg -w
```

## Advanced Usage

### Custom NAT Scenarios

Create custom NAT rules in `docker/nat-simulator/scripts/custom.sh`:
```bash
#!/bin/bash
# Custom NAT configuration
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE \
  -m statistic --mode random --probability 0.5 \
  -j MASQUERADE
```

### Performance Testing

Run concurrent connection tests:
```bash
docker compose up -d --scale client1=50
```

### Integration with ant-quic Tests

```rust
#[cfg(feature = "docker-nat-tests")]
#[test]
fn test_symmetric_nat_traversal() {
    let docker = Docker::connect();
    docker.start_nat_scenario("symmetric");
    
    let result = test_traversal();
    assert!(result.success_rate() > 0.6);
}
```

## Contributing

To add new NAT scenarios:

1. Create NAT script in `docker/nat-simulator/scripts/`
2. Add service definition in `docker-compose.yml`
3. Update test scenarios in `run-nat-tests.sh`
4. Document expected behavior

## References

- [RFC 3489](https://tools.ietf.org/html/rfc3489) - STUN
- [RFC 4787](https://tools.ietf.org/html/rfc4787) - NAT Behavioral Requirements
- [RFC 6146](https://tools.ietf.org/html/rfc6146) - Stateful NAT64
- [RFC 6598](https://tools.ietf.org/html/rfc6598) - CGNAT Address Space