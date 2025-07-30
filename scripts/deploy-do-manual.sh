#!/bin/bash
# Manual deployment script for DigitalOcean
# Use this when GitHub release binaries aren't available

set -euo pipefail

# Configuration
SERVER="quic.saorsalabs.com"
DEPLOY_DIR="/opt/ant-quic-v0.5.0"

echo "🚀 Manual deployment to $SERVER"

# Commands to run on the server
ssh root@$SERVER << 'EOF'
set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Setting up ant-quic v0.5.0 ===${NC}"

# Install Rust if needed
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Create deployment directory
echo -e "${YELLOW}Creating deployment directory...${NC}"
mkdir -p /opt/ant-quic-v0.5.0
cd /opt/ant-quic-v0.5.0

# Clone specific version
echo -e "${YELLOW}Cloning ant-quic v0.5.0...${NC}"
if [ -d "ant-quic" ]; then
    cd ant-quic
    git fetch --tags
    git checkout v0.5.0
else
    git clone --branch v0.5.0 --single-branch https://github.com/dirvine/ant-quic
    cd ant-quic
fi

# Build release binary
echo -e "${YELLOW}Building release binary...${NC}"
cargo build --release --bin ant-quic

# Create symlink for easy access
ln -sf /opt/ant-quic-v0.5.0/ant-quic/target/release/ant-quic /usr/local/bin/ant-quic-v0.5.0

# Test the binary
echo -e "${YELLOW}Testing binary...${NC}"
/usr/local/bin/ant-quic-v0.5.0 --version

echo -e "${GREEN}✓ Build complete!${NC}"

# Stop any existing ant-quic service
echo -e "${YELLOW}Stopping existing services...${NC}"
systemctl stop ant-quic 2>/dev/null || true
pkill -f ant-quic 2>/dev/null || true

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/ant-quic.service << 'SERVICE'
[Unit]
Description=ant-quic Bootstrap Node v0.5.0
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ant-quic-v0.5.0
ExecStart=/usr/local/bin/ant-quic-v0.5.0 --force-coordinator --listen 0.0.0.0:9000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

# Reload and start service
systemctl daemon-reload
systemctl enable ant-quic
systemctl start ant-quic

# Check status
sleep 3
systemctl status ant-quic --no-pager

# Check if listening
echo -e "${YELLOW}Checking network binding...${NC}"
netstat -tlnup | grep 9000 || echo "Port 9000 not yet bound"

echo -e "${GREEN}✅ Deployment complete!${NC}"
echo -e "${BLUE}Bootstrap node should be available at quic.saorsalabs.com:9000${NC}"
EOF

echo "
📋 Next Steps:
1. Test from local machine:
   cargo run --bin ant-quic -- --bootstrap $SERVER:9000

2. Check logs on server:
   ssh root@$SERVER 'journalctl -u ant-quic -f'

3. Monitor status:
   ssh root@$SERVER 'systemctl status ant-quic'
"