#!/bin/bash
# Deploy ant-quic-test v0.14.101 to VPS infrastructure
# Run this script from a machine with SSH access to the VPS nodes

set -e

VERSION="v0.14.101"
RELEASE_URL="https://github.com/saorsa-labs/ant-quic/releases/download/${VERSION}/ant-quic-test-x86_64-linux.tar.gz"

# VPS nodes to update (exclude saorsa-1 which is dashboard only)
BOOTSTRAP_NODES="142.93.199.50 147.182.234.192"  # saorsa-2, saorsa-3
TEST_NODES="206.189.7.117 144.126.230.161 65.21.157.229 116.203.101.172 149.28.156.231 45.77.176.184"  # saorsa-4 through saorsa-9

ALL_NODES="$BOOTSTRAP_NODES $TEST_NODES"

echo "=== Deploying ant-quic-test $VERSION ==="
echo ""
echo "This will update the following nodes:"
for ip in $ALL_NODES; do
    echo "  - $ip"
done
echo ""

# Download and verify locally first
echo "=== Step 1: Download and verify release ==="
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

curl -L -o ant-quic-test.tar.gz "$RELEASE_URL"
curl -L -o ant-quic-test.tar.gz.sha256 "${RELEASE_URL}.sha256"

echo "Verifying checksum..."
if shasum -a 256 -c ant-quic-test.tar.gz.sha256; then
    echo "✓ Checksum verified"
else
    echo "✗ Checksum verification FAILED"
    exit 1
fi

echo ""
echo "=== Step 2: Deploy to nodes ==="

deploy_node() {
    local ip=$1
    echo ""
    echo "--- Deploying to $ip ---"

    # Copy tarball
    scp -o ConnectTimeout=10 ant-quic-test.tar.gz root@${ip}:/tmp/

    # Install and restart
    ssh -o ConnectTimeout=10 root@${ip} <<'REMOTE_SCRIPT'
set -e
cd /tmp
tar xzf ant-quic-test.tar.gz

# Stop service if running
systemctl stop ant-quic-test || true

# Install binary
mkdir -p /opt/ant-quic
mv ant-quic-test /opt/ant-quic/
chmod +x /opt/ant-quic/ant-quic-test

# Restart service
systemctl start ant-quic-test

# Verify
sleep 2
if systemctl is-active ant-quic-test; then
    echo "✓ Service running"
    /opt/ant-quic/ant-quic-test --version || true
else
    echo "✗ Service failed to start"
    journalctl -u ant-quic-test --no-pager -n 20
fi

# Cleanup
rm -f /tmp/ant-quic-test.tar.gz
REMOTE_SCRIPT

    echo "✓ Deployed to $ip"
}

# Deploy to all nodes
for ip in $ALL_NODES; do
    deploy_node "$ip" || echo "✗ Failed to deploy to $ip"
done

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo ""
echo "=== Step 3: Verify deployment ==="
echo ""

for ip in $ALL_NODES; do
    echo -n "$ip: "
    ssh -o ConnectTimeout=5 root@$ip "/opt/ant-quic/ant-quic-test --version 2>/dev/null" || echo "unreachable"
done

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Monitor the network at: https://saorsa-1.saorsalabs.com/"
echo "Check peers via API: curl https://saorsa-1.saorsalabs.com/api/peers"
