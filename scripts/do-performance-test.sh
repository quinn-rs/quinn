#!/bin/bash

# DigitalOcean Performance Testing Script
# Runs performance tests against deployed ant-quic instances

set -euo pipefail

# Configuration
DO_USER="${DO_USER:-root}"
DO_HOST="${DO_HOST:-}"
DO_PORT="${DO_PORT:-22}"
DO_KEY="${DO_SSH_KEY:-~/.ssh/id_rsa}"
RESULTS_DIR="performance-results-$(date +%Y%m%d-%H%M%S)"

# Test parameters
TEST_DURATION="${TEST_DURATION:-300}"  # 5 minutes default
CONNECTION_COUNTS=(1 10 50 100)
PAYLOAD_SIZES=(1024 10240 102400 1048576)  # 1KB, 10KB, 100KB, 1MB

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Setup test environment
setup_test_env() {
    log "Setting up test environment..."
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    # Record test metadata
    cat > "$RESULTS_DIR/metadata.json" << EOF
{
    "test_start": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "do_host": "$DO_HOST",
    "test_duration": $TEST_DURATION,
    "git_sha": "$(git rev-parse HEAD)",
    "rust_version": "$(rustc --version)"
}
EOF
    
    # Build test binaries
    log "Building test binaries..."
    cargo build --release --features "pqc aws-lc-rs" --bin ant-quic
    cargo build --release --examples
}

# Test connection establishment performance
test_connection_establishment() {
    log "Testing connection establishment performance..."
    
    local output_file="$RESULTS_DIR/connection_establishment.json"
    
    # Run connection establishment test
    timeout $TEST_DURATION cargo run --release --example perf_client -- \
        --server "$DO_HOST:9000" \
        --test connection-establishment \
        --iterations 1000 \
        --output "$output_file" 2>&1 | tee "$RESULTS_DIR/connection_establishment.log"
    
    # Analyze results
    if [ -f "$output_file" ]; then
        log "Connection establishment results:"
        jq -r '.summary' "$output_file"
    fi
}

# Test throughput
test_throughput() {
    log "Testing throughput performance..."
    
    for payload_size in "${PAYLOAD_SIZES[@]}"; do
        for conn_count in "${CONNECTION_COUNTS[@]}"; do
            log "Testing throughput: ${payload_size} bytes, ${conn_count} connections"
            
            local test_name="throughput_${payload_size}b_${conn_count}conn"
            local output_file="$RESULTS_DIR/${test_name}.json"
            
            timeout $TEST_DURATION cargo run --release --example perf_client -- \
                --server "$DO_HOST:9000" \
                --test throughput \
                --payload-size $payload_size \
                --connections $conn_count \
                --duration $TEST_DURATION \
                --output "$output_file" 2>&1 | tee "$RESULTS_DIR/${test_name}.log"
            
            # Brief pause between tests
            sleep 5
        done
    done
}

# Test latency
test_latency() {
    log "Testing latency performance..."
    
    for payload_size in 64 256 1024 4096; do
        log "Testing latency: ${payload_size} bytes"
        
        local test_name="latency_${payload_size}b"
        local output_file="$RESULTS_DIR/${test_name}.json"
        
        timeout $TEST_DURATION cargo run --release --example perf_client -- \
            --server "$DO_HOST:9000" \
            --test latency \
            --payload-size $payload_size \
            --iterations 10000 \
            --output "$output_file" 2>&1 | tee "$RESULTS_DIR/${test_name}.log"
        
        sleep 5
    done
}

# Test NAT traversal performance
test_nat_traversal() {
    log "Testing NAT traversal performance..."
    
    # Deploy test nodes on DO
    ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" << 'EOF'
        # Create test network namespaces
        sudo ip netns add nat_test_1 || true
        sudo ip netns add nat_test_2 || true
        
        # Setup virtual interfaces
        sudo ip link add veth0 type veth peer name veth1
        sudo ip link set veth0 netns nat_test_1
        sudo ip link set veth1 netns nat_test_2
        
        # Configure NAT
        sudo ip netns exec nat_test_1 iptables -t nat -A POSTROUTING -o veth0 -j MASQUERADE
        sudo ip netns exec nat_test_2 iptables -t nat -A POSTROUTING -o veth1 -j MASQUERADE
EOF
    
    # Run NAT traversal test
    local output_file="$RESULTS_DIR/nat_traversal.json"
    
    timeout $TEST_DURATION cargo run --release --example nat_perf_test -- \
        --bootstrap "$DO_HOST:9000" \
        --iterations 100 \
        --output "$output_file" 2>&1 | tee "$RESULTS_DIR/nat_traversal.log"
}

# Monitor resource usage on DO
monitor_resources() {
    log "Starting resource monitoring..."
    
    # Start monitoring script on DO
    ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" << 'EOF' &
        while true; do
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$(vmstat 1 2 | tail -1 | awk '{print $13","$14","$15}'),$(free -m | grep Mem | awk '{print $3}'),$(netstat -i | grep eth0 | awk '{print $3","$7}')"
            sleep 5
        done
EOF
    
    echo $! > "$RESULTS_DIR/monitor.pid"
}

# Stop resource monitoring
stop_monitoring() {
    if [ -f "$RESULTS_DIR/monitor.pid" ]; then
        local pid=$(cat "$RESULTS_DIR/monitor.pid")
        kill $pid 2>/dev/null || true
        rm "$RESULTS_DIR/monitor.pid"
    fi
}

# Generate performance report
generate_report() {
    log "Generating performance report..."
    
    cat > "$RESULTS_DIR/report.md" << EOF
# ant-quic Performance Test Report

## Test Information
- Date: $(date)
- Target: $DO_HOST
- Duration: $TEST_DURATION seconds
- Git SHA: $(git rev-parse HEAD)

## Results Summary

EOF
    
    # Add connection establishment results
    if [ -f "$RESULTS_DIR/connection_establishment.json" ]; then
        echo "### Connection Establishment" >> "$RESULTS_DIR/report.md"
        jq -r '.summary | to_entries[] | "- \(.key): \(.value)"' "$RESULTS_DIR/connection_establishment.json" >> "$RESULTS_DIR/report.md"
        echo "" >> "$RESULTS_DIR/report.md"
    fi
    
    # Add throughput results
    echo "### Throughput Performance" >> "$RESULTS_DIR/report.md"
    echo "| Payload Size | Connections | Throughput (MB/s) | CPU Usage (%) |" >> "$RESULTS_DIR/report.md"
    echo "|--------------|-------------|-------------------|---------------|" >> "$RESULTS_DIR/report.md"
    
    for result in $RESULTS_DIR/throughput_*.json; do
        if [ -f "$result" ]; then
            jq -r '"| \(.payload_size) | \(.connections) | \(.throughput_mbps) | \(.cpu_usage) |"' "$result" >> "$RESULTS_DIR/report.md" || true
        fi
    done
    echo "" >> "$RESULTS_DIR/report.md"
    
    # Add latency results
    echo "### Latency Performance" >> "$RESULTS_DIR/report.md"
    echo "| Payload Size | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) |" >> "$RESULTS_DIR/report.md"
    echo "|--------------|----------|----------|----------|----------|" >> "$RESULTS_DIR/report.md"
    
    for result in $RESULTS_DIR/latency_*.json; do
        if [ -f "$result" ]; then
            jq -r '"| \(.payload_size) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.max_ms) |"' "$result" >> "$RESULTS_DIR/report.md" || true
        fi
    done
    
    log "Report generated: $RESULTS_DIR/report.md"
}

# Upload results to GitHub
upload_results() {
    log "Uploading results..."
    
    # Create tarball
    tar -czf "${RESULTS_DIR}.tar.gz" "$RESULTS_DIR"
    
    # If running in CI, upload as artifact
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::set-output name=results::${RESULTS_DIR}.tar.gz"
    fi
    
    log "Results saved to ${RESULTS_DIR}.tar.gz"
}

# Main test execution
main() {
    # Check prerequisites
    if [ -z "$DO_HOST" ]; then
        error "DO_HOST environment variable is not set"
        exit 1
    fi
    
    # Setup trap to cleanup on exit
    trap 'stop_monitoring; log "Test completed"' EXIT
    
    # Run tests
    setup_test_env
    monitor_resources
    
    test_connection_establishment
    test_throughput
    test_latency
    test_nat_traversal
    
    stop_monitoring
    generate_report
    upload_results
    
    log "All tests completed successfully"
    log "Results saved in: $RESULTS_DIR"
}

# Run main function
main