# Digital Ocean Deployment Guide for ant-quic

This guide provides instructions for deploying ant-quic as a public node on Digital Ocean.

## Note on Symmetric P2P

In ant-quic v0.13.0+, **all nodes are symmetric** - there are no special "bootstrap" or "coordinator" roles. Every node can:
- Initiate and accept connections
- Observe external addresses of connecting peers
- Coordinate NAT traversal for other peers
- Relay traffic when needed

The node deployed via this guide simply has a **public IP address** and is configured as a "known peer" for other nodes to connect to first. It runs the same code with the same capabilities as any other node.

## Prerequisites

1. Digital Ocean account with API token
2. Domain name (optional, for HTTPS)
3. SSH key pair for server access
4. Local tools:
   - Terraform (>= 1.0)
   - Ansible (>= 2.9)
   - SSH client

## Directory Structure

```
deploy/digitalocean/
├── terraform/          # Infrastructure as Code
│   ├── main.tf        # DO resources definition
│   └── user-data.sh   # Cloud-init script
├── ansible/           # Configuration management
│   ├── playbook.yml   # Main deployment playbook
│   ├── inventory.ini  # Server inventory
│   └── templates/     # Configuration templates
└── README.md          # This file
```

## Deployment Steps

### 1. Infrastructure Provisioning with Terraform

```bash
cd terraform/

# Initialize Terraform
terraform init

# Set your DO API token
export TF_VAR_do_token="your-digital-ocean-api-token"

# Review the deployment plan
terraform plan

# Create infrastructure
terraform apply

# Note the output values
terraform output
```

This creates:
- Ubuntu 22.04 droplet (2 vCPU, 4GB RAM)
- Firewall rules for QUIC (UDP 9000-9010)
- Floating IP for stable addressing
- Initial system configuration via cloud-init

### 2. Configuration with Ansible

```bash
cd ../ansible/

# Update inventory with your server IP
vim inventory.ini
# Replace YOUR_DO_IP with the floating IP from Terraform

# Set environment variables
export DOMAIN_NAME="your-domain.com"  # Optional
export CERTBOT_EMAIL="your-email@example.com"
export ANT_QUIC_VERSION="v0.13.0"  # Or "latest" to build from source

# Run the playbook
ansible-playbook -i inventory.ini playbook.yml
```

### 3. Manual Binary Deployment (if not using Ansible)

```bash
# SSH to the server
ssh root@YOUR_DO_IP

# Upload the binary
scp ant-quic root@YOUR_DO_IP:/opt/ant-quic/bin/

# Or build from source
git clone https://github.com/dirvine/ant-quic.git
cd ant-quic
cargo build --release --bin ant-quic
cp target/release/ant-quic /opt/ant-quic/bin/

# Set permissions
chown ant-quic:ant-quic /opt/ant-quic/bin/ant-quic
chmod +x /opt/ant-quic/bin/ant-quic

# Start the service
systemctl start ant-quic
systemctl status ant-quic
```

## Service Management

### Starting/Stopping

```bash
# Start the service
systemctl start ant-quic

# Stop the service
systemctl stop ant-quic

# Restart the service
systemctl restart ant-quic

# Check status
systemctl status ant-quic
```

### Logs

```bash
# View recent logs
journalctl -u ant-quic -f

# View log files
tail -f /var/log/ant-quic/ant-quic.log

# View error logs
tail -f /var/log/ant-quic/ant-quic-error.log
```

### Monitoring

The deployment includes:
- Prometheus node exporter metrics at `http://YOUR_IP:9100/metrics`
- Custom ant-quic metrics via monitoring script
- Nginx reverse proxy for HTTPS dashboard access
- Health check endpoint at `https://YOUR_DOMAIN/health`

## Testing the Deployment

### 1. Basic Connectivity Test

```bash
# From your local machine
nc -u -z YOUR_DO_IP 9000
echo $?  # Should return 0

# Using ant-quic from another node
ant-quic --known-peer YOUR_DO_IP:9000
```

### 2. Health Check

```bash
curl https://YOUR_DOMAIN/health
# Should return "OK"
```

### 3. Dashboard Access

Open `https://YOUR_DOMAIN` in your browser to access the monitoring dashboard.

## Security Considerations

1. **Firewall**: Only required ports are open (SSH, HTTP/S, QUIC)
2. **TLS**: Let's Encrypt certificates auto-renewed via certbot
3. **Service Hardening**: Systemd security features enabled
4. **User Isolation**: ant-quic runs as unprivileged user
5. **Automatic Updates**: Daily cron job checks for new releases

## Backup and Recovery

### Backup

```bash
# Backup configuration and certificates
tar -czf ant-quic-backup.tar.gz \
  /opt/ant-quic/config \
  /opt/ant-quic/certs \
  /etc/systemd/system/ant-quic.service
```

### Restore

```bash
# Restore from backup
tar -xzf ant-quic-backup.tar.gz -C /
systemctl daemon-reload
systemctl restart ant-quic
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u ant-quic -n 100

# Verify binary
/opt/ant-quic/bin/ant-quic --version

# Check permissions
ls -la /opt/ant-quic/
```

### Connection Issues

```bash
# Check firewall
ufw status

# Check if port is listening
ss -lnu | grep 9000

# Test locally
nc -u -z localhost 9000
```

### Certificate Issues

```bash
# Renew certificate manually
certbot renew --nginx

# Check certificate
openssl x509 -in /etc/letsencrypt/live/YOUR_DOMAIN/cert.pem -text -noout
```

## Maintenance

### Updates

The deployment includes automatic daily checks for new ant-quic releases. To update manually:

```bash
# Check current version
/opt/ant-quic/bin/ant-quic --version

# Download new version
wget https://github.com/dirvine/ant-quic/releases/download/vX.Y.Z/ant-quic-linux-x86_64
mv ant-quic-linux-x86_64 /opt/ant-quic/bin/ant-quic
chmod +x /opt/ant-quic/bin/ant-quic

# Restart service
systemctl restart ant-quic
```

### Scaling

To handle more connections:

1. Upgrade droplet size
2. Adjust systemd resource limits
3. Tune kernel UDP buffers:

```bash
# Add to /etc/sysctl.conf
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Apply
sysctl -p
```

## Cost Estimation

- Droplet (s-2vcpu-4gb): ~$24/month
- Bandwidth: 4TB included, $0.01/GB after
- Floating IP: Free with droplet
- Snapshots: $0.06/GB/month

## Support

For issues specific to ant-quic:
- GitHub: https://github.com/dirvine/ant-quic/issues

For infrastructure issues:
- Check Digital Ocean status: https://status.digitalocean.com/
- DO Community: https://www.digitalocean.com/community