#!/usr/bin/env bash
# Multi-Node Local Network Testing Setup Script
# Sets up ant-quic nodes across multiple machines for real network testing

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_CONFIG="${TEST_CONFIG:-$PROJECT_ROOT/configs/multi-node-test.yaml}"
LOG_DIR="${LOG_DIR:-$PROJECT_ROOT/logs/multi-node}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/results/multi-node}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[MULTI-NODE]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Node roles
BOOTSTRAP_NODES=()
CLIENT_NODES=()
NAT_GATEWAYS=()

# Declare arrays to avoid unbound variable errors
declare -a BOOTSTRAP_NODES
declare -a CLIENT_NODES
declare -a NAT_GATEWAYS

# Parse configuration
parse_config() {
    if [[ ! -f "$TEST_CONFIG" ]]; then
        error "Test configuration not found: $TEST_CONFIG"
        exit 1
    fi

    log "Parsing test configuration: $TEST_CONFIG"

    # Use Python script to parse YAML configuration
    if ! command -v python3 &> /dev/null; then
        error "python3 is required for configuration parsing"
        exit 1
    fi

    # Extract node information using Python YAML parser
    eval "$(python3 "$SCRIPT_DIR/parse-multi-node-config.py")"

    # Convert comma-separated strings to arrays
    IFS=',' read -ra BOOTSTRAP_NODES <<< "${BOOTSTRAP_NODES:-}"
    IFS=',' read -ra CLIENT_NODES <<< "${CLIENT_NODES:-}"
    IFS=',' read -ra NAT_GATEWAYS <<< "${NAT_GATEWAYS:-}"

    # Debug output
    info "Parsed nodes: BOOTSTRAP=${#BOOTSTRAP_NODES[@]}, CLIENT=${#CLIENT_NODES[@]}, NAT=${#NAT_GATEWAYS[@]}"
}

# Setup SSH access to all nodes
setup_ssh_access() {
    log "Setting up SSH access to all nodes..."

    local all_nodes=()

    # Build array of all nodes, skipping empty arrays
    if [[ ${#BOOTSTRAP_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${BOOTSTRAP_NODES[@]}")
    fi
    if [[ ${#CLIENT_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${CLIENT_NODES[@]}")
    fi
    if [[ ${#NAT_GATEWAYS[@]} -gt 0 ]]; then
        all_nodes+=("${NAT_GATEWAYS[@]}")
    fi

    for node in "${all_nodes[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Setting up SSH access to $host:$port"

        # Skip SSH setup for localhost (local testing)
        if [[ "$host" == "localhost" ]]; then
            info "Skipping SSH setup for localhost (local testing)"
            continue
        fi

        # Test SSH connection
        if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p "$port" "$host" "echo 'SSH connection successful'" > /dev/null 2>&1; then
            error "Cannot connect to $host:$port"
            exit 1
        fi

        # Setup ant-quic user and directories
        ssh -p "$port" "$host" "
            sudo useradd -m -s /bin/bash ant-quic 2>/dev/null || true
            sudo mkdir -p /home/ant-quic/ant-quic
            sudo chown -R ant-quic:ant-quic /home/ant-quic/ant-quic
        "
    done
}

# Deploy ant-quic to all nodes
deploy_ant_quic() {
    log "Deploying ant-quic to all nodes..."

    local all_nodes=()

    # Build array of all nodes, skipping empty arrays
    if [[ ${#BOOTSTRAP_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${BOOTSTRAP_NODES[@]}")
    fi
    if [[ ${#CLIENT_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${CLIENT_NODES[@]}")
    fi
    if [[ ${#NAT_GATEWAYS[@]} -gt 0 ]]; then
        all_nodes+=("${NAT_GATEWAYS[@]}")
    fi

    for node in "${all_nodes[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        # Skip deployment to localhost (already local)
        if [[ "$host" == "localhost" ]]; then
            info "Skipping deployment to localhost (already local)"
            continue
        fi

        info "Deploying to $host:$port"

        # Copy project files
        rsync -avz -e "ssh -p $port" \
            --exclude target/ \
            --exclude .git/ \
            --exclude logs/ \
            --exclude results/ \
            "$PROJECT_ROOT/" "ant-quic@$host:/home/ant-quic/ant-quic/"

        # Build ant-quic on the node
        ssh -p "$port" "ant-quic@$host" "
            cd /home/ant-quic/ant-quic
            cargo build --release --features docker-nat-tests
        "
    done
}

# Setup network configuration
setup_network() {
    log "Setting up network configuration..."

    # Configure NAT gateways (skip if none configured)
    if [[ ${#NAT_GATEWAYS[@]} -eq 0 ]]; then
        info "No NAT gateways configured, skipping network setup"
        return 0
    fi

    # Configure NAT gateways
    for gateway in "${NAT_GATEWAYS[@]}"; do
        local host="${gateway%%:*}"
        local port="${gateway##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Configuring NAT gateway on $host:$port"

        ssh -p "$port" "ant-quic@$host" "
            # Enable IP forwarding
            sudo sysctl -w net.ipv4.ip_forward=1
            sudo sysctl -w net.ipv6.conf.all.forwarding=1

            # Configure iptables for NAT
            sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
            sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
            sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
        "
    done
}

# Start bootstrap nodes
start_bootstrap_nodes() {
    log "Starting bootstrap nodes..."

    for node in "${BOOTSTRAP_NODES[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Starting bootstrap on $host:$port"

        if [[ "$host" == "localhost" ]]; then
            # Run locally instead of via SSH
            info "Starting bootstrap locally"
            cd "$PROJECT_ROOT"
            nohup ./target/release/ant-quic \
                --force-coordinator \
                --listen [::]:9000 > bootstrap.log 2>&1 &
        else
            # Run via SSH on remote host
            ssh -p "$port" "ant-quic@$host" "
                cd /home/ant-quic/ant-quic
                nohup ./target/release/ant-quic \
                    --force-coordinator \
                    --listen [::]:9000 \
                    --log-level debug > bootstrap.log 2>&1 &
            "
        fi
    done
}

# Start client nodes
start_client_nodes() {
    log "Starting client nodes..."

    for node in "${CLIENT_NODES[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Starting client on $host:$port"

        # Get bootstrap node address
        local bootstrap_addr="${BOOTSTRAP_NODES[0]%%:*}:9000"

        if [[ "$host" == "localhost" ]]; then
            # Run locally instead of via SSH
            info "Starting client locally"
            cd "$PROJECT_ROOT"
            nohup ./target/release/ant-quic \
                --bootstrap $bootstrap_addr > client.log 2>&1 &
        else
            # Run via SSH on remote host
            ssh -p "$port" "ant-quic@$host" "
                cd /home/ant-quic/ant-quic
                nohup ./target/release/ant-quic \
                    --bootstrap $bootstrap_addr \
                    --log-level debug > client.log 2>&1 &
            "
        fi
    done
}

# Run NAT traversal tests
run_nat_tests() {
    log "Running NAT traversal tests..."

    # Test basic connectivity
    for node in "${CLIENT_NODES[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Testing connectivity from $host"

        if [[ "$host" == "localhost" ]]; then
            # Run locally instead of via SSH
            info "Testing connectivity locally"
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --ping 127.0.0.1:9000
        else
            # Run via SSH on remote host
            ssh -p "$port" "ant-quic@$host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --ping ${BOOTSTRAP_NODES[0]%%:*}:9000
            "
        fi
    done

    # Test P2P connections between clients
    local client_count=${#CLIENT_NODES[@]}
    for ((i=0; i<client_count-1; i++)); do
        for ((j=i+1; j<client_count; j++)); do
            local client1="${CLIENT_NODES[i]%%:*}"
            local client2="${CLIENT_NODES[j]%%:*}"

            info "Testing P2P connection: $client1 <-> $client2"

            # This would need more sophisticated coordination
            # For now, just test basic connectivity
            if [[ "$client1" == "localhost" ]]; then
                # Run locally instead of via SSH
                info "Testing P2P connection locally"
                cd "$PROJECT_ROOT"
                timeout 30 ./target/release/ant-quic --connect $client2:9001 || true
            else
                # Run via SSH on remote host
                ssh -p 22 "ant-quic@$client1" "
                    cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --connect $client2:9001 || true
                "
            fi
        done
    done
}

# Collect results
collect_results() {
    log "Collecting test results..."

    mkdir -p "$RESULTS_DIR"

    local all_nodes=()

    # Build array of all nodes, skipping empty arrays
    if [[ ${#BOOTSTRAP_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${BOOTSTRAP_NODES[@]}")
    fi
    if [[ ${#CLIENT_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${CLIENT_NODES[@]}")
    fi
    if [[ ${#NAT_GATEWAYS[@]} -gt 0 ]]; then
        all_nodes+=("${NAT_GATEWAYS[@]}")
    fi

    for node in "${all_nodes[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        info "Collecting logs from $host"

        # Copy logs
        scp -P "$port" "ant-quic@$host:/home/ant-quic/ant-quic/*.log" "$RESULTS_DIR/" 2>/dev/null || true

        # Copy any test results
        scp -P "$port" -r "ant-quic@$host:/home/ant-quic/ant-quic/results" "$RESULTS_DIR/$host/" 2>/dev/null || true
    done
}

# Cleanup
cleanup() {
    log "Cleaning up..."

    local all_nodes=()

    # Build array of all nodes, skipping empty arrays
    if [[ ${#BOOTSTRAP_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${BOOTSTRAP_NODES[@]}")
    fi
    if [[ ${#CLIENT_NODES[@]} -gt 0 ]]; then
        all_nodes+=("${CLIENT_NODES[@]}")
    fi
    if [[ ${#NAT_GATEWAYS[@]} -gt 0 ]]; then
        all_nodes+=("${NAT_GATEWAYS[@]}")
    fi

    for node in "${all_nodes[@]}"; do
        local host="${node%%:*}"
        local port="${node##*:}"

        if [[ "$host" == "$port" ]]; then
            port=22
        fi

        # Skip cleanup for localhost (local testing)
        if [[ "$host" == "localhost" ]]; then
            info "Skipping cleanup for localhost (local testing)"
            continue
        fi

        info "Cleaning up $host"

        ssh -p "$port" "ant-quic@$host" "
            pkill -f ant-quic || true
            rm -f /home/ant-quic/ant-quic/*.log
        " 2>/dev/null || true
    done
}

# Main execution
main() {
    log "=== Multi-Node Local Network Testing Setup ==="

    # Parse configuration
    parse_config

    # Validate we have nodes
    if [[ ${#BOOTSTRAP_NODES[@]} -eq 0 ]]; then
        error "No bootstrap nodes configured"
        exit 1
    fi

    if [[ ${#CLIENT_NODES[@]} -eq 0 ]]; then
        error "No client nodes configured"
        exit 1
    fi

    # Setup SSH access
    setup_ssh_access

    # Deploy ant-quic
    deploy_ant_quic

    # Setup network
    setup_network

    # Start services
    start_bootstrap_nodes
    sleep 5
    start_client_nodes

    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 10

    # Run tests
    run_nat_tests

    # Collect results
    collect_results

    log "Multi-node test setup complete!"
    log "Results collected in: $RESULTS_DIR"
}

# Trap cleanup on exit
trap cleanup EXIT

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi