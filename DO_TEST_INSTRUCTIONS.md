# Testing ant-quic v0.5.0 on DigitalOcean

## Quick Start

Since the automated release had some CI issues, here's how to test the PQC release on your DO server:

### Option 1: Build from Source on DO Server

```bash
# SSH to your server
ssh root@quic.saorsalabs.com

# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
cd /opt
git clone https://github.com/dirvine/ant-quic
cd ant-quic
git checkout v0.5.0
cargo build --release --bin ant-quic

# Test the binary
./target/release/ant-quic --version
./target/release/ant-quic --help

# Run as bootstrap node
./target/release/ant-quic --force-coordinator --listen 0.0.0.0:9000
```

### Option 2: Use Pre-built Binary (when available)

Once the release workflow is fixed:

```bash
# Download the test script
wget https://raw.githubusercontent.com/dirvine/ant-quic/v0.5.0/scripts/test-release-on-do.sh
chmod +x test-release-on-do.sh

# Run comprehensive tests
./test-release-on-do.sh v0.5.0
```

### Option 3: Manual Testing

```bash
# Start bootstrap node
/opt/ant-quic/target/release/ant-quic --force-coordinator --listen 0.0.0.0:9000 &

# From your local machine, test connection
cargo run --bin ant-quic -- --bootstrap quic.saorsalabs.com:9000
```

## What's New in v0.5.0

1. **Post-Quantum Cryptography Framework**
   - ML-KEM-768 (FIPS 203)
   - ML-DSA-65 (FIPS 204)
   - Hybrid modes combining classical + PQC
   - Memory pool optimization

2. **Code Quality**
   - Zero clippy errors
   - 625+ passing tests
   - Enhanced documentation

3. **NAT Traversal**
   - IPv4/IPv6 dual-stack verified
   - 27% improvement with address discovery
   - Enhanced Docker testing

## Testing Checklist

- [ ] Binary starts without errors
- [ ] Can bind to public IP
- [ ] Accepts client connections
- [ ] NAT traversal frames working
- [ ] Multiple concurrent connections stable
- [ ] Memory usage reasonable
- [ ] No crashes after 30 minutes

## Monitoring

```bash
# Check process
ps aux | grep ant-quic

# Monitor connections
netstat -anup | grep 9000

# Check logs
journalctl -f -u ant-quic

# Resource usage
htop
```

## Systemd Service (Optional)

```bash
# Create service file
cat > /etc/systemd/system/ant-quic.service <<EOF
[Unit]
Description=ant-quic Bootstrap Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/ant-quic/target/release/ant-quic --force-coordinator --listen 0.0.0.0:9000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable ant-quic
systemctl start ant-quic
systemctl status ant-quic
```

## Report Issues

If you encounter any issues:
1. Check logs: `journalctl -u ant-quic -n 100`
2. Create issue: https://github.com/dirvine/ant-quic/issues
3. Include version, OS, and error messages