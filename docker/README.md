# Docker-based NAT Testing Environment

This directory contains a comprehensive Docker-based testing environment for simulating various NAT configurations and network conditions to test ant-quic's NAT traversal capabilities.

## Overview

The testing environment simulates:
- Multiple NAT types (Full Cone, Symmetric, Port Restricted, CGNAT)
- Various network conditions (latency, packet loss, bandwidth limits)
- Multi-client scenarios behind different NAT configurations
- Automated test execution and result collection

## Architecture

```
┌─────────────────┐
│   Bootstrap     │ 203.0.113.10:9000
│  (Coordinator)  │ (Public Internet)
└────────┬────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    │         │          │          │
┌───▼──┐  ┌──▼───┐  ┌──▼───┐  ┌──▼───┐
│ NAT1 │  │ NAT2 │  │ NAT3 │  │ NAT4 │
│Full  │  │ Sym  │  │Port  │  │CGNAT │
│Cone  │  │metric│  │Rest. │  │      │
└───┬──┘  └──┬───┘  └──┬───┘  └──┬───┘
    │        │          │          │
┌───▼──┐  ┌──▼───┐  ┌──▼───┐  ┌──▼───┐
│Client│  │Client│  │Client│  │Client│
│  1   │  │  2   │  │  3   │  │  4   │
└──────┘  └──────┘  └──────┘  └──────┘
```

## Quick Start

1. **Build the containers:**
   ```bash
   docker-compose -f docker/docker-compose.yml build
   ```

2. **Run the test suite:**
   ```bash
   ./docker/scripts/run-nat-tests.sh
   ```

3. **View results:**
   ```bash
   cat docker/results/summary.txt
   ```

## Components

### Dockerfiles

- **`Dockerfile.ant-quic`**: Base container with ant-quic binary and testing tools
- **`Dockerfile.nat-gateway`**: NAT gateway container with iptables configuration

### Docker Compose Services

1. **bootstrap**: Public coordinator node
2. **nat1_gateway**: Full Cone NAT
3. **nat2_gateway**: Symmetric NAT  
4. **nat3_gateway**: Port Restricted NAT
5. **nat4_gateway**: Carrier Grade NAT (CGNAT)
6. **client1-4**: Clients behind each NAT type
7. **network_sim**: Network condition simulator

### Scripts

- **`run-nat-tests.sh`**: Main test orchestration script
- **`nat-gateway-entrypoint.sh`**: NAT gateway configuration entry point
- **`network-conditions.sh`**: Apply network impairments (delay, loss, etc.)

### NAT Type Scripts

- **`full-cone.sh`**: Most permissive, allows any external host
- **`symmetric.sh`**: Most restrictive, different ports for different destinations
- **`port-restricted.sh`**: Middle ground, requires matching source ports
- **`cgnat.sh`**: ISP-level NAT with limited port ranges

## NAT Types Explained

### Full Cone NAT
- External hosts can send packets to the internal host once a mapping exists
- Most permissive type
- Common in home routers with "DMZ" mode

### Symmetric NAT
- Different external endpoints see different external ports
- Most restrictive type
- Common in corporate firewalls

### Port Restricted NAT
- External host must send from the same port that received packets
- Middle ground restrictiveness
- Common in home routers

### CGNAT (Carrier Grade NAT)
- ISP-level NAT using 100.64.0.0/10 address space
- Limited port ranges per subscriber
- Increasingly common with IPv4 exhaustion

## Running Specific Tests

### Basic Connectivity Test
```bash
docker exec ant-quic-client1 ant-quic --ping 203.0.113.10:9000
```

### NAT Traversal Test
```bash
# Terminal 1: Start receiver
docker exec -it ant-quic-client2 ant-quic --listen 0.0.0.0:9001

# Terminal 2: Connect from different NAT
docker exec -it ant-quic-client1 ant-quic --connect <discovered-address>
```

### Apply Network Conditions
```bash
# Add 100ms latency to NAT gateway
docker exec nat1_gateway tc qdisc add dev eth0 root netem delay 100ms

# Add 5% packet loss
docker exec nat2_gateway tc qdisc add dev eth0 root netem loss 5%

# Limit bandwidth
docker exec nat3_gateway tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
```

## Test Scenarios

### 1. Basic NAT Traversal
Tests connectivity between clients behind different NAT types under normal conditions.

### 2. Stressed NAT Traversal
Tests with added network impairments:
- 5% packet loss
- 100ms additional latency
- Bandwidth limitations

### 3. Mobile Network Simulation
Simulates 3G/4G/5G network conditions with appropriate latency and loss characteristics.

### 4. Satellite Network Simulation
Tests with high latency (600ms) typical of satellite connections.

## Monitoring and Debugging

### View NAT Gateway Logs
```bash
docker logs nat1_gateway
```

### Monitor Connection Tracking
```bash
docker exec nat1_gateway conntrack -L
```

### Capture Packets
```bash
docker exec nat1_gateway tcpdump -i any -w /tmp/capture.pcap
docker cp nat1_gateway:/tmp/capture.pcap ./
```

### Check iptables Rules
```bash
docker exec nat1_gateway iptables -t nat -L -n -v
```

## Results

Test results are collected in:
- `docker/results/summary.txt`: Overall test summary
- `docker/results/*.log`: Individual test logs
- `docker/logs/*.log`: Container logs

## Customization

### Add New NAT Type
1. Create script in `docker/scripts/nat-types/`
2. Add service to `docker-compose.yml`
3. Update `run-nat-tests.sh` to include new tests

### Add Network Profile
Edit `docker/configs/network-conditions.yaml` to add new profiles.

### Modify Test Duration
```bash
TEST_DURATION=600 ./docker/scripts/run-nat-tests.sh
```

## Troubleshooting

### Container won't start
- Check Docker daemon is running
- Ensure sufficient permissions for NET_ADMIN capability
- Verify port 9000 is available

### NAT traversal fails
- Check bootstrap node is accessible
- Verify iptables rules with `docker exec <nat-gateway> iptables -L -n`
- Check connection tracking: `docker exec <nat-gateway> conntrack -L`

### Network conditions not applying
- Ensure tc (traffic control) is available in container
- Check interface names match (eth0, eth1)
- Verify NET_ADMIN capability is set

## Integration with CI/CD

```yaml
# Example GitHub Actions workflow
- name: Run NAT Tests
  run: |
    cd docker
    docker-compose build
    ./scripts/run-nat-tests.sh
    
- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: nat-test-results
    path: docker/results/
```

## License

Same as ant-quic project (MIT/Apache-2.0)