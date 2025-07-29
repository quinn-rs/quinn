# ant-quic v0.5.0 Release Testing Guide

## Overview
This guide helps you test the v0.5.0 release with Post-Quantum Cryptography support on your DigitalOcean server.

## Release Status
- **Version**: v0.5.0
- **Status**: Building (check https://github.com/dirvine/ant-quic/actions)
- **Features**: Post-Quantum Cryptography, Enhanced NAT Traversal, IPv6 Support

## Testing Steps

### 1. Wait for Release to Complete
The GitHub Actions workflow typically takes 5-10 minutes to build all platforms:
- Linux x86_64 ✓
- Linux ARM64 ✓
- macOS x86_64 ✓
- macOS ARM64 ✓
- Windows x86_64 ✓

Check status: https://github.com/dirvine/ant-quic/actions/workflows/release.yml

### 2. Test on DigitalOcean Server

Once the release is ready, SSH to your server and run:

```bash
# Option 1: Use the automated test script (from your local machine)
./scripts/deploy-and-test-do.sh

# Option 2: Manual testing on the server
ssh root@quic.saorsalabs.com

# Download and test the release
cd /tmp
wget https://github.com/dirvine/ant-quic/releases/download/v0.5.0/ant-quic-x86_64-linux.tar.gz
tar -xzf ant-quic-x86_64-linux.tar.gz
chmod +x ant-quic

# Test basic functionality
./ant-quic --version
./ant-quic --help

# Run as bootstrap node
./ant-quic --force-coordinator --listen 0.0.0.0:9000
```

### 3. Test Suite Coverage

The automated test script (`test-release-on-do.sh`) runs:

1. **Basic Tests**
   - Version check
   - Help output
   - Binary integrity

2. **Bootstrap Node Test**
   - Public IP binding
   - Coordinator mode
   - Stability check

3. **Client Connectivity**
   - Bootstrap connection
   - Address discovery
   - NAT traversal frames

4. **NAT Traversal**
   - Multiple peer connections
   - Hole punching
   - Frame exchange

5. **IPv6 Support**
   - Dual-stack binding
   - IPv6 connectivity
   - Graceful fallback

6. **Performance Test**
   - 5 concurrent connections
   - 30-second stability test
   - Resource usage

### 4. Testing from Local Machine

After deploying to DO server:

```bash
# Test connection to public bootstrap
cargo run --bin ant-quic -- --bootstrap quic.saorsalabs.com:9000

# Expected output:
# ✓ Connected to bootstrap node
# 🌐 Discovered external address: YOUR.IP:PORT
# ✓ NAT traversal initialized
```

### 5. PQC-Specific Testing

While the binary includes PQC support, the current implementation uses test vectors. To verify:

```bash
# Check for PQC in version info
./ant-quic --version | grep -i pqc

# The implementation includes:
# - ML-KEM-768 framework
# - ML-DSA-65 framework
# - Hybrid TLS modes
# - Memory pool optimization
```

### 6. Expected Test Results

✅ **Should Pass**:
- All basic functionality tests
- Bootstrap node operation
- Client connections
- NAT traversal coordination
- IPv4 connectivity
- Performance under load

⚠️ **May Vary**:
- IPv6 (depends on DO droplet config)
- External address discovery (depends on NAT)
- Specific NAT traversal scenarios

❌ **Known Limitations**:
- PQC uses test vectors (not real crypto yet)
- Some Docker tests require bash 4+

### 7. Monitoring Production Deployment

Once running on DO:

```bash
# Check process
ps aux | grep ant-quic

# Monitor logs
journalctl -u ant-quic -f

# Check network connections
netstat -tlnp | grep 9000

# Test from external client
nc -u -v quic.saorsalabs.com 9000
```

### 8. Troubleshooting

**Binary won't start**:
- Check firewall: `ufw allow 9000/udp`
- Verify no port conflicts: `lsof -i :9000`

**Connection failures**:
- Ensure UDP traffic allowed
- Check DigitalOcean firewall rules
- Verify public IP is accessible

**Performance issues**:
- Monitor CPU/memory: `htop`
- Check bandwidth: `iftop`
- Review logs for errors

## Test Report

The automated test generates `/tmp/ant-quic-test-*/test-report.txt` with:
- Version information
- Test results summary
- System configuration
- Performance metrics

## Next Steps

After successful testing:
1. Deploy as systemd service
2. Configure auto-start on boot
3. Set up monitoring/alerting
4. Add to load balancer (if applicable)

## Support

- GitHub Issues: https://github.com/dirvine/ant-quic/issues
- Release Notes: RELEASE_NOTES_v0.5.0.md
- Documentation: docs/