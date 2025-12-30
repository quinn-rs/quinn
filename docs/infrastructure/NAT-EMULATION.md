# NAT Emulation Infrastructure

This document describes the Docker-based NAT emulation infrastructure for comprehensive ant-quic NAT traversal testing.

## Overview

The NAT emulation system allows testing ant-quic connectivity across all common NAT configurations found in home and ISP networks. This enables validation of NAT traversal before deployment to real-world users.

## NAT Types Supported

| Type | Difficulty | Common In | Docker Service |
|------|------------|-----------|----------------|
| Full Cone | Easy | Gaming routers, UPnP-enabled | `nat-fullcone` |
| Address-Restricted | Medium | Older home routers | `nat-restricted` |
| Port-Restricted | Medium | Most home routers (default) | `nat-portrestricted` |
| Symmetric | Very Hard | Enterprise NAT, some ISPs | `nat-symmetric` |
| CGNAT | Hard | ISPs, mobile carriers | `nat-cgnat` |
| Double NAT | Very Hard | Apartments, dorms | `nat-doublenat-*` |
| Hairpin NAT | Special | Better home routers | `nat-hairpin` |

## RFC 4787 Behavior Classification

### Mapping Behavior

| Behavior | Description | NAT Types |
|----------|-------------|-----------|
| Endpoint Independent (EIM) | Same external port for all destinations | Full Cone, Restricted |
| Address Dependent (ADM) | Different port per destination IP | Some enterprise NAT |
| Address+Port Dependent (APDM) | Different port per destination IP:port | Symmetric |

### Filtering Behavior

| Behavior | Description | NAT Types |
|----------|-------------|-----------|
| Endpoint Independent (EIF) | Accept from any external host | Full Cone |
| Address Dependent (ADF) | Only accept from IPs we've sent to | Address-Restricted |
| Address+Port Dependent (APDF) | Only from exact IP:port we sent to | Port-Restricted, Symmetric |

## Quick Start

```bash
# Deploy NAT emulation to VPS nodes
./scripts/deploy-nat-emulation.sh

# Or deploy to a specific node
./scripts/deploy-nat-emulation.sh --node fullcone

# Start NAT containers
./scripts/vps-test-orchestrator.sh run nat_docker_start

# Run comprehensive NAT tests
./scripts/vps-test-orchestrator.sh run nat_comprehensive

# Stop NAT containers
./scripts/vps-test-orchestrator.sh run nat_docker_stop
```

## Architecture

### Network Topology

```
                         nat-external (172.20.0.0/16)
                                    |
    +------------------+------------+------------+------------------+
    |                  |            |            |                  |
nat-fullcone      nat-symmetric  nat-cgnat  nat-doublenat-outer  node-public
(172.20.1.1)      (172.20.4.1)   (172.20.5.1)  (172.20.6.1)     (172.20.100.1)
    |                  |            |            |
internal-1.0      internal-4.0  internal-5.0  middle-1.0
(10.100.1.0/24)   (10.100.4.0/24)(10.100.5.0/24)(10.200.1.0/24)
    |                  |            |            |
node-fullcone     node-symmetric node-cgnat  nat-doublenat-inner
(10.100.1.10)     (10.100.4.10)  (10.100.5.10)  (10.200.1.10)
                                                     |
                                              internal-6.0
                                              (10.100.6.0/24)
                                                     |
                                              node-doublenat
                                              (10.100.6.10)
```

### VPS Node Configuration

| Node | IP | NAT Types |
|------|-----|-----------|
| fullcone | 67.205.158.158 | Full Cone, UPnP |
| restricted | 161.35.231.80 | Address-Restricted, Hairpin |
| portrestricted | 178.62.192.11 | Port-Restricted, NAT-PMP |
| symmetric | 159.65.90.128 | Symmetric, CGNAT |

## Test Scenarios

### Basic NAT Matrix (`nat_matrix`)

Tests connectivity between all configured nodes using their native NAT types.

```bash
./scripts/vps-test-orchestrator.sh run nat_matrix
```

### Comprehensive NAT Test (`nat_comprehensive`)

Tests all NAT type combinations with expected difficulty ratings:

- **Easy**: Full Cone involved - >95% expected success
- **Moderate**: Cone-to-Cone NAT - >85% expected success
- **Hard**: Symmetric involved - >70% expected success
- **Very Hard**: Double NAT or CGNAT pairs - >50% expected success (relay)

```bash
./scripts/vps-test-orchestrator.sh run nat_comprehensive
```

### Double NAT Test (`double_nat`)

Tests connectivity from double-NAT configurations (two layers of NAT). This is common in:
- Apartment buildings with shared routers
- University dorms
- Mobile hotspot chains

```bash
./scripts/vps-test-orchestrator.sh run double_nat
```

### CGNAT Stress Test (`cgnat_stress`)

Tests port exhaustion scenarios with limited port ranges (256 ports).

```bash
./scripts/vps-test-orchestrator.sh run cgnat_stress
```

### Hairpin NAT Test (`hairpin`)

Tests if nodes can reach their own external IP from inside the NAT (loopback).

```bash
./scripts/vps-test-orchestrator.sh run hairpin
```

## Expected Success Rates

Based on the NAT test matrix implementation:

| Source NAT | Dest NAT | Expected Method | Success Rate |
|------------|----------|-----------------|--------------|
| None | Any | Direct | 99% |
| Full Cone | Any | Hole Punch | 95% |
| Port-Restricted | Port-Restricted | Hole Punch | 85% |
| Symmetric | Port-Restricted | Hole Punch/Relay | 65% |
| Symmetric | Symmetric | Relay | 50% |
| CGNAT | CGNAT | Relay | 40% |
| Double NAT | Double NAT | Relay | 30% |

## Implementation Details

### Full Cone NAT

```bash
# Full Cone: 1:1 port mapping, any external host can reach internal
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT  # Allow ANY incoming
```

### Symmetric NAT

```bash
# Symmetric: Random port per connection
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random-fully
```

### CGNAT

```bash
# CGNAT: Shared IP, limited port range (256 ports)
sysctl -w net.ipv4.ip_local_port_range="32768 33023"
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source $SHARED_IP:32768-33023
```

## Adding New NAT Types

1. Create directory: `docker/nat-emulation/nat-newtype/`
2. Copy Dockerfile from similar NAT type
3. Create `entrypoint.sh` with iptables rules
4. Add to `docker/nat-emulation/docker-compose.yml`
5. Add to `NAT_DOCKER_CONFIG` in `scripts/vps-test-orchestrator.sh`
6. Add to `NatType` enum in `crates/ant-quic-test-network/src/registry/types.rs`
7. Update match statements in orchestrator and API
8. Run tests to verify

## Monitoring

### Check Container Status

```bash
# On a specific node
ssh root@67.205.158.158 "cd /opt/ant-quic/nat-emulation && docker compose ps"

# All nodes
./scripts/vps-test-orchestrator.sh status
```

### View NAT State

```bash
# Watch conntrack table on a NAT container
docker exec nat-symmetric watch -n 1 conntrack -L -p udp
```

### View Logs

```bash
# Container logs
docker exec nat-symmetric cat /var/log/messages

# ant-quic logs inside container
docker exec node-symmetric tail -f /var/log/ant-quic.log
```

## Troubleshooting

### Container Can't Reach External Network

```bash
# Check IP forwarding
docker exec nat-symmetric cat /proc/sys/net/ipv4/ip_forward

# Check iptables rules
docker exec nat-symmetric iptables -L -n -v
docker exec nat-symmetric iptables -t nat -L -n -v
```

### Port Exhaustion with CGNAT

```bash
# Check available ports
docker exec nat-cgnat cat /proc/sys/net/ipv4/ip_local_port_range

# Check current connections
docker exec nat-cgnat conntrack -L | wc -l
```

### NAT Container Won't Start

```bash
# Check Docker logs
docker logs nat-symmetric

# Verify network configuration
docker network inspect nat-external
docker network inspect internal-4.0
```

## References

- [RFC 4787: NAT Behavioral Requirements for UDP](https://datatracker.ietf.org/doc/html/rfc4787)
- [RFC 3489: STUN NAT Classification](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 6598: CGNAT Address Space](https://datatracker.ietf.org/doc/html/rfc6598)
- [draft-seemann-quic-nat-traversal](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/)

## Files

| File | Description |
|------|-------------|
| `docker/nat-emulation/` | Docker NAT emulation infrastructure |
| `docker/nat-emulation/docker-compose.yml` | Main compose file with all NAT types |
| `docker/nat-emulation/README.md` | Quick reference for Docker setup |
| `scripts/deploy-nat-emulation.sh` | Deploy Docker configs to VPS nodes |
| `scripts/vps-test-orchestrator.sh` | VPS test orchestrator with NAT scenarios |
| `crates/ant-quic-test-network/src/registry/types.rs` | NAT type definitions |
| `crates/ant-quic-test-network/src/orchestrator.rs` | NAT test matrix implementation |
