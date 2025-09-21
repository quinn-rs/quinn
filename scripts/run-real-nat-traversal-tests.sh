#!/usr/bin/env bash
# Real NAT Traversal Testing Script
# Tests ant-quic across actual network boundaries and real NAT devices

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_CONFIG="${TEST_CONFIG:-$PROJECT_ROOT/configs/multi-node-test.yaml}"
LOG_DIR="${LOG_DIR:-$PROJECT_ROOT/logs/real-nat}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/results/real-nat}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[REAL-NAT]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
debug() { echo -e "${CYAN}[DEBUG]${NC} $1"; }

# Test results
TEST_RESULTS=()
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# NAT detection
detect_nat_type() {
    local host=$1
    local port=${2:-22}

    info "Detecting NAT type for $host"

    # Handle localhost differently
    if [[ "$host" == "localhost" ]]; then
        # Use ant-quic's built-in NAT detection locally
        cd "$PROJECT_ROOT"
        ./target/release/ant-quic --detect-nat --timeout 30 2>/dev/null || echo "unknown"
    else
        # Use ant-quic's built-in NAT detection via SSH
        ssh -p "$port" "ant-quic@$host" "
            cd /home/ant-quic/ant-quic
            ./target/release/ant-quic --detect-nat --timeout 30
        " 2>/dev/null || echo "unknown"
    fi
}

# Test direct connectivity
test_direct_connectivity() {
    local test_name="direct_connectivity"
    local client1=$1
    local client2=$2

    ((TOTAL_TESTS++))

    info "Testing direct connectivity: $client1 -> $client2"

    local client1_host="${client1%%:*}"
    local client2_host="${client2%%:*}"

    # Handle localhost connections
    if [[ "$client1_host" == "localhost" ]]; then
        # Try direct connection locally
        if cd "$PROJECT_ROOT" && ./target/release/ant-quic --test-sender --connect 127.0.0.1:9001 --timeout 30 > "$RESULTS_DIR/${test_name}.log" 2>&1; then
            record_test_result "$test_name" "PASSED" "Direct connection successful"
        else
            record_test_result "$test_name" "FAILED" "Direct connection failed"
        fi
    else
        # Try direct connection via SSH
        if ssh -p 22 "ant-quic@$client1_host" "
            cd /home/ant-quic/ant-quic
            ./target/release/ant-quic --test-sender --connect $client2_host:9001 --timeout 30
        " > "$RESULTS_DIR/${test_name}.log" 2>&1; then
            record_test_result "$test_name" "PASSED" "Direct connection successful"
        else
            record_test_result "$test_name" "FAILED" "Direct connection failed"
        fi
    fi
}

# Test NAT traversal
test_nat_traversal() {
    local test_name="nat_traversal"
    local client1=$1
    local client2=$2
    local nat_type1=$3
    local nat_type2=$4

    ((TOTAL_TESTS++))

    info "Testing NAT traversal: $client1 ($nat_type1) -> $client2 ($nat_type2)"

    local client1_host="${client1%%:*}"
    local client2_host="${client2%%:*}"

    # Handle localhost connections
    if [[ "$client2_host" == "localhost" ]]; then
        # Start listener locally
        cd "$PROJECT_ROOT"
        ./target/release/ant-quic --test-receiver --id 'client2' > "$RESULTS_DIR/receiver.log" 2>&1 &
        local listener_pid=$!

        sleep 2

        # Try NAT traversal from client1
        if [[ "$client1_host" == "localhost" ]]; then
            # Both clients are localhost
            ./target/release/ant-quic --test-sender --connect 127.0.0.1:9001 --timeout 60 > "$RESULTS_DIR/${test_name}_${nat_type1}_to_${nat_type2}.log" 2>&1
            local result=$?
        else
            # client1 is remote, client2 is localhost
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --test-sender --connect 127.0.0.1:9001 --timeout 60
            " > "$RESULTS_DIR/${test_name}_${nat_type1}_to_${nat_type2}.log" 2>&1
            local result=$?
        fi

        # Cleanup
        kill $listener_pid 2>/dev/null || true
    else
        # Start listener on remote client2
        ssh -p 22 "ant-quic@$client2_host" "
            cd /home/ant-quic/ant-quic
            ./target/release/ant-quic --listen 0.0.0.0:9001 --test-receiver --id 'client2' > receiver.log 2>&1
        " &
        local ssh_pid=$!

        sleep 2

        # Try NAT traversal from client1
        if [[ "$client1_host" == "localhost" ]]; then
            # client1 is localhost, client2 is remote
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --test-sender --connect $client2_host:9001 --timeout 60 > "$RESULTS_DIR/${test_name}_${nat_type1}_to_${nat_type2}.log" 2>&1
            local result=$?
        else
            # Both clients are remote
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --test-sender --connect $client2_host:9001 --timeout 60
            " > "$RESULTS_DIR/${test_name}_${nat_type1}_to_${nat_type2}.log" 2>&1
            local result=$?
        fi

        # Cleanup
        ssh -p 22 "ant-quic@$client2_host" "pkill -f 'ant-quic --listen'" 2>/dev/null || true
        kill $ssh_pid 2>/dev/null || true
    fi

    if [[ $result -eq 0 ]]; then
        record_test_result "${test_name}_${nat_type1}_to_${nat_type2}" "PASSED" "NAT traversal successful"
    else
        record_test_result "${test_name}_${nat_type1}_to_${nat_type2}" "FAILED" "NAT traversal failed"
    fi
}

# Test under network stress
test_network_stress() {
    local test_name="network_stress"
    local client1=$1
    local client2=$2

    ((TOTAL_TESTS++))

    info "Testing under network stress: $client1 -> $client2"

    local client1_host="${client1%%:*}"
    local client2_host="${client2%%:*}"

    # Handle localhost connections for network stress testing
    if [[ "$client1_host" == "localhost" ]]; then
        # Apply network conditions locally (this is a simulation)
        warn "Network stress testing with localhost - using simulated conditions"
        sudo tc qdisc add dev lo root netem loss 5% 2>/dev/null || true
        sudo tc qdisc add dev lo root netem delay 50ms 20ms distribution normal 2>/dev/null || true

        # Start listener
        if [[ "$client2_host" == "localhost" ]]; then
            # Both clients are localhost
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --listen 0.0.0.0:9002 --test-receiver --id 'client2' > "$RESULTS_DIR/stress_receiver.log" 2>&1 &
            local listener_pid=$!

            sleep 2

            # Try connection under stress
            ./target/release/ant-quic --test-sender --connect $client2_host:9002 --timeout 90 > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?

            # Cleanup
            kill $listener_pid 2>/dev/null || true
        else
            # client1 is localhost, client2 is remote
            ssh -p 22 "ant-quic@$client2_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --listen 0.0.0.0:9002 --test-receiver --id 'client2' > stress_receiver.log 2>&1
            " &
            local ssh_pid=$!

            sleep 2

            # Try connection under stress
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --test-sender --connect $client2_host:9002 --timeout 90 > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?

            # Cleanup
            ssh -p 22 "ant-quic@$client2_host" "pkill -f 'ant-quic --listen'" 2>/dev/null || true
            kill $ssh_pid 2>/dev/null || true
        fi

        # Cleanup local network conditions
        sudo tc qdisc del dev lo root 2>/dev/null || true
    else
        # Apply network conditions on remote client1
        ssh -p 22 "ant-quic@$client1_host" "
            # Add packet loss
            sudo tc qdisc add dev eth0 root netem loss 5% 2>/dev/null || true
            # Add latency
            sudo tc qdisc add dev eth0 root netem delay 50ms 20ms distribution normal 2>/dev/null || true
        "

        # Start listener on client2
        if [[ "$client2_host" == "localhost" ]]; then
            # client1 is remote, client2 is localhost
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --listen 0.0.0.0:9002 --test-receiver --id 'client2' > "$RESULTS_DIR/stress_receiver.log" 2>&1 &
            local listener_pid=$!

            sleep 2

            # Try connection under stress
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                timeout 90 ./target/release/ant-quic --connect $client2_host:9002 --test-sender --nat-traversal
            " > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?

            # Cleanup
            kill $listener_pid 2>/dev/null || true
        else
            # Both clients are remote
            ssh -p 22 "ant-quic@$client2_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --listen 0.0.0.0:9002 --test-receiver --id 'client2' > stress_receiver.log 2>&1
            " &
            local ssh_pid=$!

            sleep 2

            # Try connection under stress
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                timeout 90 ./target/release/ant-quic --connect $client2_host:9002 --test-sender --nat-traversal
            " > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?

            # Cleanup
            ssh -p 22 "ant-quic@$client2_host" "pkill -f 'ant-quic --listen'" 2>/dev/null || true
            kill $ssh_pid 2>/dev/null || true
        fi

        # Cleanup remote network conditions
        ssh -p 22 "ant-quic@$client1_host" "sudo tc qdisc del dev eth0 root 2>/dev/null || true"
    fi

    if [[ $result -eq 0 ]]; then
        record_test_result "$test_name" "PASSED" "Connection successful under stress"
    else
        record_test_result "$test_name" "FAILED" "Connection failed under stress"
    fi
}

# Test IPv6 connectivity
test_ipv6_connectivity() {
    local test_name="ipv6_connectivity"
    local client1=$1
    local client2=$2

    ((TOTAL_TESTS++))

    info "Testing IPv6 connectivity: $client1 -> $client2"

    local client1_host="${client1%%:*}"
    local client2_host="${client2%%:*}"

    # Get IPv6 addresses
    local client1_ipv6
    local client2_ipv6

    if [[ "$client1_host" == "localhost" ]]; then
        # Use ifconfig on macOS or ip on Linux
        if command -v ip >/dev/null 2>&1; then
            client1_ipv6=$(ip -6 addr show lo | grep -o 'inet6 [^/]*' | head -1 | awk '{print $2}' 2>/dev/null)
        else
            client1_ipv6=$(ifconfig lo0 | grep -o 'inet6 [^ ]*' | head -1 | awk '{print $2}' 2>/dev/null)
        fi
    else
        client1_ipv6=$(ssh -p 22 "ant-quic@$client1_host" "ip -6 addr show eth0 | grep -o 'inet6 [^/]*' | head -1 | awk '{print \$2}'" 2>/dev/null)
    fi

    if [[ "$client2_host" == "localhost" ]]; then
        # Use ifconfig on macOS or ip on Linux
        if command -v ip >/dev/null 2>&1; then
            client2_ipv6=$(ip -6 addr show lo | grep -o 'inet6 [^/]*' | head -1 | awk '{print $2}' 2>/dev/null)
        else
            client2_ipv6=$(ifconfig lo0 | grep -o 'inet6 [^ ]*' | head -1 | awk '{print $2}' 2>/dev/null)
        fi
    else
        client2_ipv6=$(ssh -p 22 "ant-quic@$client2_host" "ip -6 addr show eth0 | grep -o 'inet6 [^/]*' | head -1 | awk '{print \$2}'" 2>/dev/null)
    fi

    if [[ -z "$client1_ipv6" || -z "$client2_ipv6" ]]; then
        record_test_result "$test_name" "SKIPPED" "IPv6 addresses not available"
        return
    fi

    # Handle localhost connections for IPv6 testing
    if [[ "$client2_host" == "localhost" ]]; then
        # Start IPv6 listener locally
        cd "$PROJECT_ROOT"
        ./target/release/ant-quic --listen [$client2_ipv6]:9003 --test-receiver --id 'client2' > "$RESULTS_DIR/ipv6_receiver.log" 2>&1 &
        local listener_pid=$!

        sleep 2

        # Try IPv6 connection from client1
        if [[ "$client1_host" == "localhost" ]]; then
            # Both clients are localhost
            ./target/release/ant-quic --test-sender --connect [$client2_ipv6]:9003 --timeout 60 > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?
        else
            # client1 is remote, client2 is localhost
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --test-sender --connect [$client2_ipv6]:9003 --timeout 60
            " > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?
        fi

        # Cleanup
        kill $listener_pid 2>/dev/null || true
    else
        # Start IPv6 listener on remote client2
        ssh -p 22 "ant-quic@$client2_host" "
            cd /home/ant-quic/ant-quic
            ./target/release/ant-quic --listen [$client2_ipv6]:9003 --test-receiver --id 'client2' > ipv6_receiver.log 2>&1
        " &
        local ssh_pid=$!

        sleep 2

        # Try IPv6 connection from client1
        if [[ "$client1_host" == "localhost" ]]; then
            # client1 is localhost, client2 is remote
            cd "$PROJECT_ROOT"
            ./target/release/ant-quic --test-sender --connect [$client2_ipv6]:9003 --timeout 60 > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?
        else
            # Both clients are remote
            ssh -p 22 "ant-quic@$client1_host" "
                cd /home/ant-quic/ant-quic
                ./target/release/ant-quic --test-sender --connect [$client2_ipv6]:9003 --timeout 60
            " > "$RESULTS_DIR/${test_name}.log" 2>&1
            local result=$?
        fi

        # Cleanup
        ssh -p 22 "ant-quic@$client2_host" "pkill -f 'ant-quic --listen'" 2>/dev/null || true
        kill $ssh_pid 2>/dev/null || true
    fi

    if [[ $result -eq 0 ]]; then
        record_test_result "$test_name" "PASSED" "IPv6 connection successful"
    else
        record_test_result "$test_name" "FAILED" "IPv6 connection failed"
    fi
}

# Record test result
record_test_result() {
    local test_name=$1
    local status=$2
    local message=$3

    TEST_RESULTS+=("$test_name:$status:$message")

    if [[ "$status" == "PASSED" ]]; then
        ((PASSED_TESTS++))
        log "✓ $test_name: PASSED"
    elif [[ "$status" == "FAILED" ]]; then
        ((FAILED_TESTS++))
        error "✗ $test_name: FAILED - $message"
    else
        log "- $test_name: SKIPPED - $message"
    fi
}

# Generate report
generate_report() {
    log "Generating test report..."

    local report_file="$RESULTS_DIR/real_nat_test_report.md"
    local success_rate
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$(awk "BEGIN {printf \"%.1f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")
    else
        success_rate="0.0"
    fi

    cat > "$report_file" << EOF
# Real NAT Traversal Test Report

## Executive Summary
- **Date**: $(date)
- **Total Tests**: $TOTAL_TESTS
- **Passed**: $PASSED_TESTS
- **Failed**: $FAILED_TESTS
- **Success Rate**: ${success_rate}%

## Test Environment
- **Network**: Real multi-node setup
- **NAT Types**: Detected automatically
- **Protocol**: IPv4/IPv6 dual-stack
- **Test Duration**: $(date)

## Test Results

EOF

    for result in "${TEST_RESULTS[@]}"; do
        IFS=':' read -r test_name status message <<< "$result"
        echo "- **$test_name**: $status - $message" >> "$report_file"
    done

    cat >> "$report_file" << EOF

## NAT Type Analysis

EOF

    # Add NAT type analysis
    for client in "${CLIENT_NODES[@]}"; do
        local host="${client%%:*}"
        local nat_type=$(detect_nat_type "$host")
        echo "- **$host**: $nat_type" >> "$report_file"
    done

    cat >> "$report_file" << EOF

## Recommendations

1. **Network Configuration**: Ensure proper NAT settings for optimal traversal
2. **Firewall Rules**: Verify UDP port forwarding on NAT devices
3. **IPv6 Support**: Enable IPv6 for better connectivity options
4. **Monitoring**: Implement continuous monitoring of NAT behavior

## Detailed Logs

All test logs are available in: $RESULTS_DIR/

## Troubleshooting

- Check network connectivity between nodes
- Verify NAT device configuration
- Ensure no firewall blocking UDP traffic
- Check system resource usage during tests
EOF

    log "Report generated: $report_file"
}

# Main execution
main() {
    log "=== Real NAT Traversal Testing ==="

    # Create directories
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"

    # Parse configuration
    if [[ ! -f "$TEST_CONFIG" ]]; then
        error "Test configuration not found: $TEST_CONFIG"
        exit 1
    fi

    # Use Python script to parse YAML configuration
    log "Parsing configuration from $TEST_CONFIG..."

    # Check if we should use local_test config or main config
    local active_config
    active_config=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    print(config.get('active_config', 'nodes'))
")

    # Extract nodes based on active configuration
    local bootstrap_nodes
    local client_nodes
    local nat_gateways

    if [[ "$active_config" == "local_test" ]]; then
        # Use local_test configuration
        bootstrap_nodes=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('local_test', {}).get('nodes', {})
    bootstrap = nodes.get('bootstrap', [])
    print(','.join(bootstrap) if bootstrap else '')
")

        client_nodes=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('local_test', {}).get('nodes', {})
    clients = nodes.get('clients', [])
    print(','.join(clients) if clients else '')
")

        nat_gateways=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('local_test', {}).get('nodes', {})
    gateways = nodes.get('nat_gateways', [])
    print(','.join(gateways) if gateways else '')
")
    else
        # Use main nodes configuration
        bootstrap_nodes=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('nodes', {})
    bootstrap = nodes.get('bootstrap', [])
    print(','.join(bootstrap) if bootstrap else '')
")

        client_nodes=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('nodes', {})
    clients = nodes.get('clients', [])
    print(','.join(clients) if clients else '')
")

        nat_gateways=$(python3 -c "
import yaml
with open('$TEST_CONFIG', 'r') as f:
    config = yaml.safe_load(f)
    nodes = config.get('nodes', {})
    gateways = nodes.get('nat_gateways', [])
    print(','.join(gateways) if gateways else '')
")
    fi

    # Convert to arrays, handling empty strings
    IFS=',' read -ra BOOTSTRAP_NODES <<< "${bootstrap_nodes:-}"
    IFS=',' read -ra CLIENT_NODES <<< "${client_nodes:-}"
    IFS=',' read -ra NAT_GATEWAYS <<< "${nat_gateways:-}"

    # Filter out empty entries
    BOOTSTRAP_NODES=(${BOOTSTRAP_NODES[@]:-})
    CLIENT_NODES=(${CLIENT_NODES[@]:-})
    NAT_GATEWAYS=(${NAT_GATEWAYS[@]:-})

    # Validate we have nodes
    if [[ ${#BOOTSTRAP_NODES[@]} -eq 0 ]]; then
        error "No bootstrap nodes configured in $active_config"
        exit 1
    fi

    if [[ ${#CLIENT_NODES[@]} -lt 2 ]]; then
        error "Need at least 2 client nodes for testing (found ${#CLIENT_NODES[@]} in $active_config)"
        exit 1
    fi

    info "Configuration loaded:"
    info "  Bootstrap nodes: ${#BOOTSTRAP_NODES[@]} (${BOOTSTRAP_NODES[*]})"
    info "  Client nodes: ${#CLIENT_NODES[@]} (${CLIENT_NODES[*]})"
    info "  NAT gateways: ${#NAT_GATEWAYS[@]} (${NAT_GATEWAYS[*]:-})"

    # Detect NAT types
    log "Detecting NAT types..."
    for client in "${CLIENT_NODES[@]}"; do
        local host="${client%%:*}"
        local nat_type=$(detect_nat_type "$host")
        info "NAT type for $host: $nat_type"
    done

    # Run test scenarios
    log "Running test scenarios..."

    # Test all client pairs
    local client_count=${#CLIENT_NODES[@]}
    for ((i=0; i<client_count; i++)); do
        for ((j=i+1; j<client_count; j++)); do
            local client1="${CLIENT_NODES[i]}"
            local client2="${CLIENT_NODES[j]}"

            # Direct connectivity test
            test_direct_connectivity "$client1" "$client2"

            # NAT traversal test
            local nat_type1=$(detect_nat_type "${client1%%:*}")
            local nat_type2=$(detect_nat_type "${client2%%:*}")
            test_nat_traversal "$client1" "$client2" "$nat_type1" "$nat_type2"

            # IPv6 connectivity test
            test_ipv6_connectivity "$client1" "$client2"

            # Network stress test
            test_network_stress "$client1" "$client2"
        done
    done

    # Generate report
    generate_report

    # Summary
    echo
    log "=== Test Summary ==="
    log "Total: $TOTAL_TESTS"
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        local pass_pct=$(awk -v p="$PASSED_TESTS" -v t="$TOTAL_TESTS" 'BEGIN { printf "%.1f", (t>0? (p/t)*100 : 0) }')
        local fail_pct=$(awk -v f="$FAILED_TESTS" -v t="$TOTAL_TESTS" 'BEGIN { printf "%.1f", (t>0? (f/t)*100 : 0) }')
        log "Passed: $PASSED_TESTS (${pass_pct}%)"
        log "Failed: $FAILED_TESTS (${fail_pct}%)"
    else
        log "Passed: $PASSED_TESTS (0.0%)"
        log "Failed: $FAILED_TESTS (0.0%)"
    fi

    if [[ $FAILED_TESTS -eq 0 ]]; then
        log "All real NAT traversal tests passed! 🎉"
        exit 0
    else
        error "Some tests failed. Check $RESULTS_DIR for details."
        exit 1
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi