#!/bin/bash
# Script to check your external address using ant-quic

# Default bootstrap node (Digital Ocean instance)
BOOTSTRAP="${BOOTSTRAP:-159.89.81.21:9000}"

echo "Checking external address using bootstrap node: $BOOTSTRAP"
echo "Building ant-quic..."

# Build the binary
cargo build --bin ant-quic --release 2>/dev/null || {
    echo "Failed to build ant-quic"
    exit 1
}

echo "Discovering external address..."
echo "========================================"

# Run ant-quic with bootstrap to discover external address
timeout 5 cargo run --bin ant-quic -- --bootstrap "$BOOTSTRAP" 2>&1 | grep -E "Discovered external address|CANNOT_FIND_EXTERNAL_ADDRESS" | head -1

echo "========================================"
echo ""
echo "To use a different bootstrap node:"
echo "  BOOTSTRAP=your.bootstrap.node:9000 $0"