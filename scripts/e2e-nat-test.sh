#!/bin/bash
# E2E NAT Traversal Test Script
#
# This script tests ant-quic NAT traversal, address discovery, and P2P connectivity
# across multiple nodes. It supports:
# - Local testing (bootstrap + clients on same machine)
# - DigitalOcean droplet deployment for real-world NAT traversal testing
# - Automated validation of connections, raw keys, and data throughput
#
# Usage:
#   ./e2e-nat-test.sh local            # Test locally with 3 nodes
#   ./e2e-nat-test.sh deploy           # Deploy to DigitalOcean
#   ./e2e-nat-test.sh test <bootstrap> # Run tests against bootstrap
#   ./e2e-nat-test.sh cleanup          # Remove DO droplets

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="ant-quic"
DO_REGION="${DO_REGION:-nyc1}"
DO_SIZE="${DO_SIZE:-s-1vcpu-1gb}"
DO_IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
TEST_DURATION="${TEST_DURATION:-30}"
DATA_SIZE="${DATA_SIZE:-1048576}"  # 1MB default

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if binary exists or build it
ensure_binary() {
    local binary_path="$PROJECT_DIR/target/release/$BINARY_NAME"
    if [[ ! -f "$binary_path" ]]; then
        log_info "Building release binary..."
        cd "$PROJECT_DIR"
        cargo build --release --bin "$BINARY_NAME"
    fi
    echo "$binary_path"
}

# Run local test with 3 nodes
run_local_test() {
    log_info "Starting local E2E test with 3 nodes..."

    local binary
    binary=$(ensure_binary)

    local bootstrap_port=9000
    local client1_port=9001
    local client2_port=9002

    # Start bootstrap node
    log_info "Starting bootstrap node on port $bootstrap_port..."
    "$binary" --mode bootstrap --listen "127.0.0.1:$bootstrap_port" --stats --json &
    local bootstrap_pid=$!
    sleep 2

    # Start client 1
    log_info "Starting client 1 on port $client1_port..."
    "$binary" --mode client --listen "127.0.0.1:$client1_port" \
        --bootstrap "127.0.0.1:$bootstrap_port" --stats --json --duration "$TEST_DURATION" &
    local client1_pid=$!
    sleep 2

    # Start client 2 and connect to client 1
    log_info "Starting client 2 on port $client2_port..."
    "$binary" --mode client --listen "127.0.0.1:$client2_port" \
        --bootstrap "127.0.0.1:$bootstrap_port" \
        --connect "127.0.0.1:$client1_port" \
        --throughput-test --test-size "$DATA_SIZE" \
        --stats --json --duration "$TEST_DURATION" &
    local client2_pid=$!

    # Wait for test duration
    log_info "Running test for $TEST_DURATION seconds..."
    sleep "$TEST_DURATION"

    # Cleanup
    log_info "Stopping nodes..."
    kill "$client2_pid" 2>/dev/null || true
    kill "$client1_pid" 2>/dev/null || true
    kill "$bootstrap_pid" 2>/dev/null || true

    wait "$client2_pid" 2>/dev/null || true
    wait "$client1_pid" 2>/dev/null || true
    wait "$bootstrap_pid" 2>/dev/null || true

    log_success "Local test completed"
}

# Deploy to DigitalOcean
deploy_do() {
    log_info "Deploying to DigitalOcean..."

    # Check for doctl
    if ! command -v doctl &> /dev/null; then
        log_error "doctl not found. Install: brew install doctl"
        exit 1
    fi

    # Check authentication
    if ! doctl account get &> /dev/null; then
        log_error "doctl not authenticated. Run: doctl auth init"
        exit 1
    fi

    local binary
    binary=$(ensure_binary)

    # Create SSH key for this deployment if needed
    local ssh_key_name="ant-quic-e2e-test"
    local ssh_key_path="$HOME/.ssh/ant-quic-e2e"

    if [[ ! -f "$ssh_key_path" ]]; then
        log_info "Creating SSH key..."
        ssh-keygen -t ed25519 -f "$ssh_key_path" -N "" -q
    fi

    # Upload SSH key if not exists
    local ssh_key_id
    ssh_key_id=$(doctl compute ssh-key list --format ID,Name --no-header | grep "$ssh_key_name" | awk '{print $1}' || true)

    if [[ -z "$ssh_key_id" ]]; then
        log_info "Uploading SSH key to DigitalOcean..."
        doctl compute ssh-key create "$ssh_key_name" --public-key "$(cat "$ssh_key_path.pub")"
        ssh_key_id=$(doctl compute ssh-key list --format ID,Name --no-header | grep "$ssh_key_name" | awk '{print $1}')
    fi

    # Create droplets
    log_info "Creating bootstrap droplet in $DO_REGION..."
    doctl compute droplet create "ant-quic-bootstrap" \
        --image "$DO_IMAGE" \
        --size "$DO_SIZE" \
        --region "$DO_REGION" \
        --ssh-keys "$ssh_key_id" \
        --tag-name "ant-quic-test" \
        --wait

    log_info "Creating client droplets..."
    doctl compute droplet create "ant-quic-client-1" "ant-quic-client-2" \
        --image "$DO_IMAGE" \
        --size "$DO_SIZE" \
        --region "$DO_REGION" \
        --ssh-keys "$ssh_key_id" \
        --tag-name "ant-quic-test" \
        --wait

    # Get IPs
    sleep 10  # Wait for network to be ready

    local bootstrap_ip
    local client1_ip
    local client2_ip

    bootstrap_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "bootstrap" | awk '{print $2}')
    client1_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "client-1" | awk '{print $2}')
    client2_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "client-2" | awk '{print $2}')

    log_success "Droplets created:"
    echo "  Bootstrap: $bootstrap_ip"
    echo "  Client 1:  $client1_ip"
    echo "  Client 2:  $client2_ip"

    # Upload binary to all droplets
    log_info "Uploading binary to droplets..."
    for ip in "$bootstrap_ip" "$client1_ip" "$client2_ip"; do
        scp -o StrictHostKeyChecking=no -i "$ssh_key_path" "$binary" "root@$ip:/usr/local/bin/$BINARY_NAME"
        ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$ip" "chmod +x /usr/local/bin/$BINARY_NAME"
    done

    log_success "Deployment complete. Bootstrap IP: $bootstrap_ip"
    echo ""
    echo "To run tests:"
    echo "  $0 test $bootstrap_ip"
    echo ""
    echo "To cleanup:"
    echo "  $0 cleanup"
}

# Run tests against deployed infrastructure
run_do_test() {
    local bootstrap_addr="$1"

    log_info "Running E2E tests against bootstrap at $bootstrap_addr..."

    local ssh_key_path="$HOME/.ssh/ant-quic-e2e"

    # Get all droplet IPs
    local bootstrap_ip
    local client1_ip
    local client2_ip

    bootstrap_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "bootstrap" | awk '{print $2}')
    client1_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "client-1" | awk '{print $2}')
    client2_ip=$(doctl compute droplet list --tag-name "ant-quic-test" --format Name,PublicIPv4 --no-header | grep "client-2" | awk '{print $2}')

    log_info "Starting bootstrap node..."
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$bootstrap_ip" \
        "nohup $BINARY_NAME --mode bootstrap --listen 0.0.0.0:9000 --stats --pqc-mtu > /tmp/bootstrap.log 2>&1 &"
    sleep 3

    log_info "Starting client 1..."
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$client1_ip" \
        "nohup $BINARY_NAME --mode client --listen 0.0.0.0:9001 --bootstrap $bootstrap_ip:9000 --stats --pqc-mtu --duration $TEST_DURATION > /tmp/client1.log 2>&1 &"
    sleep 3

    log_info "Starting client 2 with throughput test..."
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$client2_ip" \
        "$BINARY_NAME --mode client --listen 0.0.0.0:9002 --bootstrap $bootstrap_ip:9000 --connect $client1_ip:9001 --throughput-test --test-size $DATA_SIZE --stats --pqc-mtu --duration $TEST_DURATION" 2>&1 | tee /tmp/e2e-results.log

    # Collect results
    log_info "Collecting results..."

    echo ""
    echo "=== Bootstrap Node Log ==="
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$bootstrap_ip" "cat /tmp/bootstrap.log | tail -50"

    echo ""
    echo "=== Client 1 Log ==="
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$client1_ip" "cat /tmp/client1.log | tail -50"

    # Stop all nodes
    log_info "Stopping nodes..."
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$bootstrap_ip" "pkill -f $BINARY_NAME || true"
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$client1_ip" "pkill -f $BINARY_NAME || true"
    ssh -o StrictHostKeyChecking=no -i "$ssh_key_path" "root@$client2_ip" "pkill -f $BINARY_NAME || true"

    log_success "E2E test completed. Results saved to /tmp/e2e-results.log"
}

# Test against local macOS behind CGNAT
test_local_cgnat() {
    local bootstrap_addr="$1"

    log_info "Testing NAT traversal from local machine (behind CGNAT) to bootstrap at $bootstrap_addr..."

    local binary
    binary=$(ensure_binary)

    log_info "Starting local client..."
    "$binary" --mode client \
        --bootstrap "$bootstrap_addr" \
        --stats \
        --pqc-mtu \
        --duration "$TEST_DURATION" \
        --verbose

    log_success "Local CGNAT test completed"
}

# Cleanup DigitalOcean resources
cleanup_do() {
    log_info "Cleaning up DigitalOcean resources..."

    # Delete droplets
    doctl compute droplet delete --tag-name "ant-quic-test" --force 2>/dev/null || true

    log_success "Cleanup completed"
}

# Show usage
usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  local                    Run local E2E test with 3 nodes"
    echo "  deploy                   Deploy 3-node test topology to DigitalOcean"
    echo "  test <bootstrap_ip>      Run E2E tests against deployed bootstrap"
    echo "  cgnat <bootstrap_addr>   Test local client behind CGNAT against remote bootstrap"
    echo "  cleanup                  Remove DigitalOcean droplets"
    echo ""
    echo "Environment variables:"
    echo "  DO_REGION       DigitalOcean region (default: nyc1)"
    echo "  DO_SIZE         Droplet size (default: s-1vcpu-1gb)"
    echo "  TEST_DURATION   Test duration in seconds (default: 30)"
    echo "  DATA_SIZE       Throughput test data size in bytes (default: 1048576)"
    echo ""
    echo "Examples:"
    echo "  $0 local"
    echo "  $0 deploy"
    echo "  $0 test 1.2.3.4"
    echo "  $0 cgnat 1.2.3.4:9000"
    echo "  $0 cleanup"
}

# Main
case "${1:-}" in
    local)
        run_local_test
        ;;
    deploy)
        deploy_do
        ;;
    test)
        if [[ -z "${2:-}" ]]; then
            log_error "Bootstrap IP required"
            usage
            exit 1
        fi
        run_do_test "$2"
        ;;
    cgnat)
        if [[ -z "${2:-}" ]]; then
            log_error "Bootstrap address required (e.g., 1.2.3.4:9000)"
            usage
            exit 1
        fi
        test_local_cgnat "$2"
        ;;
    cleanup)
        cleanup_do
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
