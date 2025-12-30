# Saorsa Network Infrastructure

This document describes the VPS infrastructure used for running bootstrap nodes, relay nodes, and test nodes across the Saorsa ecosystem (ant-quic, saorsa-node, communitas).

## Node Overview

| Node | Provider | IP Address | Region | Purpose | Status |
|------|----------|------------|--------|---------|--------|
| saorsa-1 | Hetzner | 77.42.75.115 | Helsinki | Dashboard & Website | Active |
| saorsa-2 | DigitalOcean | 142.93.199.50 | NYC1 | Bootstrap Node | Active |
| saorsa-3 | DigitalOcean | 147.182.234.192 | SFO3 | Bootstrap Node | Active |
| saorsa-4 | DigitalOcean | 206.189.7.117 | AMS3 | Test Node | Active |
| saorsa-5 | DigitalOcean | 144.126.230.161 | LON1 | Test Node | Active |
| saorsa-6 | Hetzner | 65.21.157.229 | Helsinki | Test Node | Active |
| saorsa-7 | Hetzner | 116.203.101.172 | Nuremberg | Test Node | Active |
| saorsa-8 | Vultr | 149.28.156.231 | Singapore | Test Node | Active |
| saorsa-9 | Vultr | 45.77.176.184 | Tokyo | Test Node | Active |

## Port Allocation

All P2P services use **dynamic port allocation** (port 0) - the OS assigns an available port automatically.

This approach:
- Prevents port collisions between services
- Allows multiple instances on the same node
- Eliminates port management complexity
- Works reliably across all platforms

Services register their actual bound address with the registry after startup.

Additional ports:
- SSH: 22 (TCP)
- HTTP: 80 (TCP) - Dashboard only
- HTTPS: 443 (TCP) - Dashboard only

## DNS Configuration

All nodes use the `saorsalabs.com` domain. Configure the following A records:

```
saorsa-1.saorsalabs.com  →  77.42.75.115
saorsa-2.saorsalabs.com  →  142.93.199.50
saorsa-3.saorsalabs.com  →  147.182.234.192
saorsa-4.saorsalabs.com  →  206.189.7.117
saorsa-5.saorsalabs.com  →  144.126.230.161
saorsa-6.saorsalabs.com  →  65.21.157.229
saorsa-7.saorsalabs.com  →  116.203.101.172
saorsa-8.saorsalabs.com  →  149.28.156.231
saorsa-9.saorsalabs.com  →  45.77.176.184
```

## Bootstrap Discovery

Bootstrap nodes use dynamic ports. New nodes discover bootstrap addresses via:

1. **Registry API**: `https://saorsa-1.saorsalabs.com/api/peers` returns active bootstrap nodes with their current addresses
2. **DNS hostnames**: Use hostnames (saorsa-2.saorsalabs.com, saorsa-3.saorsalabs.com) - ports are discovered via registry
3. **Gossip**: Once connected to any peer, discover others via gossip protocol

## Node Roles

### Dashboard Node (saorsa-1)
- **IP:** 77.42.75.115
- **Provider:** Hetzner (Helsinki)
- Hosts the Saorsa Labs website
- Runs monitoring dashboards
- Central admin interface

### Bootstrap Nodes (saorsa-2, saorsa-3)
- **IPs:** 142.93.199.50, 147.182.234.192
- **Provider:** DigitalOcean (NYC, SFO)
- Primary entry points for new peers joining the network
- Run stable, long-lived node instances
- Geographically distributed (US East, US West)
- Must maintain high uptime

### Test Nodes (saorsa-4 through saorsa-9)
- **IPs:** See table above
- **Providers:** DigitalOcean (AMS, LON), Hetzner (HEL, NBG), Vultr (TBD)
- Used for development testing
- Can be spun up/down for specific tests
- Geographically distributed (EU, UK, etc.)
- May run experimental code

## Provider CLI Setup

### DigitalOcean
```bash
# Already configured via DIGITALOCEAN_API_TOKEN
doctl compute droplet list --tag-name saorsa
```

### Hetzner
```bash
# Uses HETZNER_API_KEY environment variable
HCLOUD_TOKEN="$HETZNER_API_KEY" hcloud server list
```

### Vultr
```bash
# Requires VULTR_API_TOKEN environment variable
# CLI installation: brew install vultr/vultr-cli/vultr-cli
VULTR_API_KEY="$VULTR_API_TOKEN" vultr-cli instance list
```

## Firewall Configuration

### DigitalOcean Firewall (saorsa-p2p-firewall)
Applied to all nodes tagged with `saorsa`:

**Inbound Rules:**
- TCP 22 (SSH)
- TCP 80 (HTTP)
- TCP 443 (HTTPS)
- UDP 9000 (ant-quic)
- UDP 10000 (saorsa-node)
- UDP 11000 (communitas)

**Outbound Rules:**
- All TCP
- All UDP
- ICMP

### Hetzner Firewall (saorsa-p2p-firewall)
Applied to all saorsa servers:

**Inbound Rules:**
- TCP 22 (SSH)
- TCP 80 (HTTP)
- TCP 443 (HTTPS)
- UDP 9000 (ant-quic)
- UDP 10000 (saorsa-node)
- UDP 11000 (communitas)
- ICMP

## SSH Access

### DigitalOcean Keys
- `mac` (ID: 48810465)
- `dirvine` (ID: 2064413)

### Hetzner Keys
- `davidirvine@MacBook-Pro.localdomain` (ID: 104686182)

```bash
# Connect to a node
ssh root@saorsa-1.saorsalabs.com
ssh root@77.42.75.115
```

## Node Provisioning

### Create New DO Node
```bash
doctl compute droplet create saorsa-N \
  --size s-1vcpu-2gb \
  --image ubuntu-24-04-x64 \
  --region nyc1 \
  --ssh-keys 48810465,2064413 \
  --tag-names saorsa,testnode \
  --wait
```

### Create New Hetzner Node
```bash
HCLOUD_TOKEN="$HETZNER_API_KEY" hcloud server create \
  --name saorsa-N \
  --type cx22 \
  --image ubuntu-24.04 \
  --location hel1 \
  --ssh-key 104686182 \
  --label role=testnode \
  --label project=saorsa
```

### Create New Vultr Node
```bash
VULTR_API_KEY="$VULTR_API_TOKEN" vultr-cli instance create \
  --region ewr \
  --plan vc2-1c-2gb \
  --os 2284 \
  --label saorsa-N \
  --ssh-keys your-key-id
```

## Running Bootstrap Nodes

### ant-quic Bootstrap
```bash
# On saorsa-2 or saorsa-3
cd /opt/ant-quic
./ant-quic-node --listen 0.0.0.0:9000 --bootstrap
```

### saorsa-node Bootstrap
```bash
# On saorsa-2 or saorsa-3
cd /opt/saorsa-node
./saorsa-node --listen 0.0.0.0:10000 --bootstrap
```

### communitas Bootstrap
```bash
# On saorsa-2 or saorsa-3
cd /opt/communitas
./communitas-headless --listen 0.0.0.0:11000 --bootstrap
```

## Systemd Service Templates

### ant-quic Bootstrap Service
```ini
# /etc/systemd/system/ant-quic-bootstrap.service
[Unit]
Description=ant-quic Bootstrap Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/ant-quic/ant-quic-node --listen 0.0.0.0:9000 --bootstrap
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### saorsa-node Bootstrap Service
```ini
# /etc/systemd/system/saorsa-node-bootstrap.service
[Unit]
Description=saorsa-node Bootstrap Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/saorsa-node/saorsa-node --listen 0.0.0.0:10000 --bootstrap
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### communitas Bootstrap Service
```ini
# /etc/systemd/system/communitas-bootstrap.service
[Unit]
Description=Communitas Bootstrap Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/communitas/communitas-headless --listen 0.0.0.0:11000 --bootstrap
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Monitoring

### Check Node Status
```bash
# DigitalOcean
doctl compute droplet list --tag-name saorsa --format Name,Status,PublicIPv4

# Hetzner
HCLOUD_TOKEN="$HETZNER_API_KEY" hcloud server list

# Vultr
VULTR_API_KEY="$VULTR_API_TOKEN" vultr-cli instance list
```

### Check Port Connectivity
```bash
# Test UDP port reachability
nc -vzu saorsa-2.saorsalabs.com 9000
nc -vzu saorsa-2.saorsalabs.com 10000
nc -vzu saorsa-2.saorsalabs.com 11000
```

### Check Service Status (on node)
```bash
systemctl status ant-quic-bootstrap
systemctl status saorsa-node-bootstrap
systemctl status communitas-bootstrap
```

## Grafana Configuration

### Dashboard Access
The Grafana dashboards are hosted on saorsa-1.saorsalabs.com.

**Dashboard URLs:**
- NAT Traversal Dashboard: `https://saorsa-1.saorsalabs.com/grafana/d/ant-quic-nat`
- Testnet Dashboard: `https://saorsa-1.saorsalabs.com/grafana/d/ant-quic-testnet`

### Enable Public Access (No Login)
To allow anonymous access to dashboards without requiring login, add these settings to `/etc/grafana/grafana.ini` on saorsa-1:

```ini
[auth.anonymous]
# Enable anonymous access
enabled = true

# Organization name for unauthenticated users
org_name = Main Org.

# Role for unauthenticated users (Viewer = read-only)
org_role = Viewer

[security]
# Allow embedding in iframes
allow_embedding = true
```

After modifying the configuration:
```bash
ssh root@77.42.75.115
sudo systemctl restart grafana-server
```

### Prometheus Configuration
Prometheus runs on saorsa-1 and scrapes metrics from:
- Registry: `http://localhost:8080/metrics`
- Bootstrap nodes: `http://saorsa-2:9000/metrics`, `http://saorsa-3:9000/metrics`

Prometheus rules are in `/etc/prometheus/rules/ant-quic.yml`.

## Cost Estimates

| Provider | Node Type | Monthly Cost | Nodes | Total |
|----------|-----------|--------------|-------|-------|
| DigitalOcean | s-1vcpu-2gb | $12/month | 4 | $48 |
| Hetzner | CX22 | ~$4/month | 3 | $12 |
| Vultr | vc2-1c-2gb | ~$10/month | 2 | $20 |

**Total estimated monthly cost:** ~$80/month for 9 nodes

## Quick Reference - All IPs

```bash
# Dashboard
export SAORSA_DASHBOARD="77.42.75.115"

# Bootstrap nodes
export SAORSA_BOOTSTRAP_1="142.93.199.50"
export SAORSA_BOOTSTRAP_2="147.182.234.192"

# Test nodes - DigitalOcean
export SAORSA_TEST_DO_1="206.189.7.117"
export SAORSA_TEST_DO_2="144.126.230.161"

# Test nodes - Hetzner
export SAORSA_TEST_HZ_1="65.21.157.229"
export SAORSA_TEST_HZ_2="116.203.101.172"

# Test nodes - Vultr
export SAORSA_TEST_VL_1="149.28.156.231"
export SAORSA_TEST_VL_2="45.77.176.184"
```

## Maintenance

### Update All Nodes
```bash
# SSH to each node and run:
apt update && apt upgrade -y
```

### Restart Services
```bash
systemctl restart ant-quic-bootstrap
systemctl restart saorsa-node-bootstrap
systemctl restart communitas-bootstrap
```

### Deploy New Binary
```bash
# Example: deploy ant-quic update
scp target/release/ant-quic-node root@saorsa-2.saorsalabs.com:/opt/ant-quic/
ssh root@saorsa-2.saorsalabs.com "systemctl restart ant-quic-bootstrap"
```

## Troubleshooting

### Node Unreachable
1. Check firewall rules on the provider
2. Verify the node is running
3. Check system logs: `ssh root@node journalctl -xe`

### Port Not Responding
1. Verify service is running: `systemctl status <service>`
2. Check if port is listening: `ss -tulpn | grep <port>`
3. Test from another node in the network

### High Latency
1. Check node resource usage: `htop`
2. Verify network isn't saturated: `iftop`
3. Consider geographic routing issues

## Security Notes

- All nodes run Ubuntu 24.04 LTS
- SSH key-only authentication (password auth disabled)
- Firewalls configured via provider APIs
- Regular security updates applied
- No sensitive data stored on nodes (stateless design)
- All P2P traffic uses PQC encryption (ML-DSA/ML-KEM)

## Related Documentation

- [ant-quic README](https://github.com/maidsafe/ant-quic)
- [saorsa-gossip](../../../saorsa-gossip/README.md)
- [communitas Architecture](../architecture/README.md)
- [Port Allocation](./PORTS.md)
