#!/bin/bash
# Simple NAT Traversal Test
# Tests the traversal logic on a single network without complex NAT simulation

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[SIMPLE-TEST]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2; }
info() { echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }

# Configuration
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.simple.yml}
RESULTS_DIR=${RESULTS_DIR:-./results/simple}
LOGS_DIR=${LOGS_DIR:-./logs/simple}

# Create directories
mkdir -p "$RESULTS_DIR" "$LOGS_DIR"

# Start containers
log "Starting simple test environment..."
docker compose -f "$COMPOSE_FILE" up -d

# Wait for bootstrap to be ready
log "Waiting for bootstrap node..."
for i in {1..30}; do
    if docker exec ant-quic-bootstrap-simple ss -u -l | grep -q ':9000'; then
        log "Bootstrap is ready"
        break
    fi
    sleep 2
done

# Test basic connectivity
log "Testing basic connectivity..."
for client in {1..3}; do
    container="ant-quic-client${client}-simple"
    log "Testing connectivity from $container..."

    # Test ping to bootstrap
    if docker exec "$container" ping -c 1 -W 2 172.20.0.10 > /dev/null 2>&1; then
        log "✓ $container can ping bootstrap"
    else
        error "✗ $container cannot ping bootstrap"
        continue
    fi

    # Test ant-quic ping
    if docker exec "$container" timeout 10 ant-quic --ping 172.20.0.10:9000 > "$RESULTS_DIR/client${client}_ping.log" 2>&1; then
        log "✓ $container ant-quic ping successful"
    else
        error "✗ $container ant-quic ping failed"
    fi
done

# Start chat clients
log "Starting chat clients..."
for client in {1..3}; do
    container="ant-quic-client${client}-simple"
    log "Starting chat client on $container..."

    docker exec -d "$container" sh -c \
        "ant-quic --bootstrap 172.20.0.10:9000 chat --nickname 'client${client}' > /app/logs/client${client}_chat.log 2>&1" || true
done

# Wait for clients to connect
log "Waiting for clients to connect to bootstrap..."
sleep 10

# Test peer discovery
log "Testing peer discovery..."
for client in {1..3}; do
    container="ant-quic-client${client}-simple"
    log "Testing peer discovery from $container..."

    # Try to query for other peers
    for target in {1..3}; do
        if [ "$client" != "$target" ]; then
            log "  Querying for client$target from client$client..."
            docker exec "$container" timeout 5 ant-quic --query-peer "client${target}" --protocol ipv4 > "$RESULTS_DIR/client${client}_query_client${target}.log" 2>&1 || true
        fi
    done
done

# Test direct P2P connection (simplified)
log "Testing direct P2P connection..."
client1_container="ant-quic-client1-simple"
client2_container="ant-quic-client2-simple"

# Start receiver on client2
log "Starting receiver on client2..."
docker exec -d "$client2_container" sh -c \
    "ant-quic --listen 172.20.2.100:9001 --test-receiver --id 'client2' > /app/logs/client2_receiver.log 2>&1"

# Wait for receiver to start
sleep 3

# Try direct connection from client1 to client2
log "Attempting direct connection from client1 to client2..."
if docker exec "$client1_container" timeout 10 ant-quic --connect 172.20.2.100:9001 --test-sender > "$RESULTS_DIR/direct_p2p_test.log" 2>&1; then
    log "✓ Direct P2P connection successful"
else
    error "✗ Direct P2P connection failed"
fi

# Generate report
log "Generating test report..."
cat > "$RESULTS_DIR/simple_test_report.md" << EOF
# Simple NAT Traversal Test Report

## Test Environment
- **Network**: Single Docker bridge network (172.20.0.0/16)
- **Bootstrap**: 172.20.0.10:9000
- **Clients**: 3 clients on different subnets
- **Purpose**: Test NAT traversal logic without complex network setup

## Test Results

### Basic Connectivity
$(for client in {1..3}; do
    if [ -f "$RESULTS_DIR/client${client}_ping.log" ] && grep -q "PING_OK" "$RESULTS_DIR/client${client}_ping.log"; then
        echo "- Client $client: ✓ Connected to bootstrap"
    else
        echo "- Client $client: ✗ Failed to connect to bootstrap"
    fi
done)

### Peer Discovery
$(for client in {1..3}; do
    echo "- Client $client queries:"
    for target in {1..3}; do
        if [ "$client" != "$target" ] && [ -f "$RESULTS_DIR/client${client}_query_client${target}.log" ]; then
            if grep -q "172.20." "$RESULTS_DIR/client${client}_query_client${target}.log"; then
                echo "  - Client $target: ✓ Found"
            else
                echo "  - Client $target: ✗ Not found"
            fi
        fi
    done
done)

### Direct P2P Test
$(if [ -f "$RESULTS_DIR/direct_p2p_test.log" ] && grep -q "SENDER_OK" "$RESULTS_DIR/direct_p2p_test.log"; then
    echo "- Status: ✓ Successful"
else
    echo "- Status: ✗ Failed"
fi)

## Logs Location
- Results: $RESULTS_DIR/
- Container logs: $LOGS_DIR/

## Conclusion
This test validates the NAT traversal logic on a simplified network setup.
EOF

log "Test report generated: $RESULTS_DIR/simple_test_report.md"

# Cleanup
log "Cleaning up..."
docker compose -f "$COMPOSE_FILE" down

log "Simple test completed. Check $RESULTS_DIR/simple_test_report.md for results."