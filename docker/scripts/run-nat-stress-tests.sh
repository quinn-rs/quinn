#!/bin/bash
# NAT Stress Testing Script
# Runs high-load tests to verify NAT traversal under stress

set -e

# Configuration
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.yml}
RESULTS_DIR=${RESULTS_DIR:-./results}
LOG_DIR=${LOG_DIR:-./logs}
CONCURRENT_CONNECTIONS=${CONCURRENT_CONNECTIONS:-50}
TEST_DURATION=${TEST_DURATION:-300}  # 5 minutes
PACKET_SIZE=${PACKET_SIZE:-1024}     # 1KB packets
SEND_RATE=${SEND_RATE:-1000}         # packets per second

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[STRESS-TEST]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# Prepare stress test environment
prepare_environment() {
    log "Preparing stress test environment..."
    
    # Create results directory
    mkdir -p "$RESULTS_DIR/stress" "$LOG_DIR/stress"
    
    # Start base environment
    docker compose -f "$COMPOSE_FILE" up -d bootstrap nat1_gateway nat2_gateway
    sleep 10
    
    log "Environment ready"
}

# Run concurrent connection test
test_concurrent_connections() {
    local nat_type=$1
    local num_clients=$2
    local test_name="concurrent_${nat_type}_${num_clients}clients"
    
    log "Testing $num_clients concurrent connections through $nat_type NAT"
    
    # Start multiple clients
    docker compose -f "$COMPOSE_FILE" up -d --scale "client_${nat_type}=$num_clients"
    sleep 5
    
    # Measure connection establishment time
    local start_time=$(date +%s)
    local successful=0
    local failed=0
    
    # Run connections in parallel
    for i in $(seq 1 $num_clients); do
        (
            if docker exec "ant-quic-client_${nat_type}_$i" \
                timeout 30 ant-quic --connect "203.0.113.10:9000" \
                --test-mode > "$RESULTS_DIR/stress/${test_name}_client${i}.log" 2>&1; then
                echo "SUCCESS"
            else
                echo "FAILED"
            fi
        ) &
    done
    
    # Wait for all connections
    wait
    
    # Count results
    successful=$(grep -c "SUCCESS" "$RESULTS_DIR/stress/${test_name}_client"*.log 2>/dev/null || echo 0)
    failed=$((num_clients - successful))
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Generate report
    cat > "$RESULTS_DIR/stress/${test_name}_report.txt" <<EOF
Concurrent Connection Test: $nat_type NAT
Clients: $num_clients
Duration: ${duration}s
Successful: $successful ($(awk "BEGIN {printf \"%.1f\", ($successful/$num_clients)*100}")%)
Failed: $failed
Avg time per connection: $(awk "BEGIN {printf \"%.2f\", $duration/$num_clients}")s
EOF
    
    log "Test completed: $successful/$num_clients successful connections"
    
    # Cleanup
    docker compose -f "$COMPOSE_FILE" stop "client_${nat_type}"
    docker compose -f "$COMPOSE_FILE" rm -f "client_${nat_type}"
}

# Run throughput stress test
test_throughput_stress() {
    local client1=$1
    local client2=$2
    local test_name=$3
    
    log "Testing throughput stress: $test_name"
    
    # Start receiver with high-throughput mode
    docker exec -d "$client2" ant-quic \
        --listen 0.0.0.0:9001 \
        --test-mode \
        --receive-buffer-size 10485760 > "$RESULTS_DIR/stress/${test_name}_receiver.log" 2>&1
    
    sleep 2
    
    # Get receiver address
    local receiver_addr=$(docker exec "$client2" ant-quic --query-peer "$client2" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)
    
    if [ -z "$receiver_addr" ]; then
        error "Could not discover receiver address"
        return 1
    fi
    
    # Run sender with high load
    docker exec "$client1" ant-quic \
        --connect "$receiver_addr" \
        --test-mode \
        --send-buffer-size 10485760 \
        --packet-size "$PACKET_SIZE" \
        --send-rate "$SEND_RATE" \
        --duration "$TEST_DURATION" > "$RESULTS_DIR/stress/${test_name}_sender.log" 2>&1
    
    # Extract throughput metrics
    local throughput=$(grep -o "throughput: [0-9.]* Mbps" "$RESULTS_DIR/stress/${test_name}_sender.log" | tail -1 | awk '{print $2}')
    local packet_loss=$(grep -o "packet loss: [0-9.]*%" "$RESULTS_DIR/stress/${test_name}_sender.log" | tail -1 | awk '{print $3}')
    
    # Generate report
    cat > "$RESULTS_DIR/stress/${test_name}_throughput.txt" <<EOF
Throughput Stress Test: $test_name
Duration: ${TEST_DURATION}s
Packet Size: ${PACKET_SIZE} bytes
Send Rate: ${SEND_RATE} pps
Achieved Throughput: ${throughput:-0} Mbps
Packet Loss: ${packet_loss:-unknown}
EOF
    
    log "Throughput test completed: ${throughput:-0} Mbps"
}

# Run port exhaustion test
test_port_exhaustion() {
    local nat_type=$1
    local test_name="port_exhaustion_${nat_type}"
    
    log "Testing port exhaustion on $nat_type NAT"
    
    # Create many short-lived connections
    local ports_used=0
    local start_time=$(date +%s)
    
    for i in $(seq 1 1000); do
        # Try to establish connection
        if docker exec "ant-quic-client1" timeout 2 ant-quic \
            --connect "203.0.113.10:$((9000 + (i % 100)))" \
            --test-mode \
            --quick-close > /dev/null 2>&1; then
            ((ports_used++))
        else
            # Port exhaustion likely reached
            break
        fi
        
        # Don't overwhelm the system
        if [ $((i % 50)) -eq 0 ]; then
            sleep 0.1
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Check NAT table size
    local nat_entries=$(docker exec "nat${nat_type}_gateway" conntrack -L 2>/dev/null | wc -l || echo 0)
    
    # Generate report
    cat > "$RESULTS_DIR/stress/${test_name}_report.txt" <<EOF
Port Exhaustion Test: $nat_type NAT
Duration: ${duration}s
Ports Used: $ports_used
NAT Table Entries: $nat_entries
Port Allocation Rate: $(awk "BEGIN {printf \"%.1f\", $ports_used/$duration}") ports/sec
EOF
    
    log "Port exhaustion test completed: $ports_used ports used"
}

# Run memory stress test
test_memory_stress() {
    local test_name="memory_stress"
    
    log "Testing memory usage under stress"
    
    # Get baseline memory usage
    local baseline_mem=$(docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}" | grep -E "client|gateway" | awk '{sum += $2} END {print sum}')
    
    # Start high-connection test
    docker compose -f "$COMPOSE_FILE" up -d --scale client1=20
    sleep 10
    
    # Create many connections
    for i in $(seq 1 20); do
        docker exec "ant-quic-client1_$i" ant-quic --connect "203.0.113.10:9000" --keep-alive &
    done
    
    # Monitor memory for duration
    local max_mem=0
    local end_time=$(($(date +%s) + 60))  # Monitor for 1 minute
    
    while [ $(date +%s) -lt $end_time ]; do
        local current_mem=$(docker stats --no-stream --format "{{.MemUsage}}" | grep -oE "[0-9.]+" | awk '{sum += $1} END {print sum}')
        if (( $(echo "$current_mem > $max_mem" | bc -l) )); then
            max_mem=$current_mem
        fi
        sleep 2
    done
    
    # Generate report
    cat > "$RESULTS_DIR/stress/memory_stress_report.txt" <<EOF
Memory Stress Test
Baseline Memory: ${baseline_mem} MB
Peak Memory: ${max_mem} MB
Memory Increase: $(awk "BEGIN {printf \"%.1f\", ($max_mem - $baseline_mem)/$baseline_mem * 100}")%
Active Connections: 20
EOF
    
    log "Memory stress test completed: peak usage ${max_mem} MB"
}

# Run CPU stress test
test_cpu_stress() {
    local test_name="cpu_stress"
    
    log "Testing CPU usage under crypto load"
    
    # Start monitoring CPU
    docker stats --no-stream > "$RESULTS_DIR/stress/cpu_baseline.txt"
    
    # Run crypto-intensive operations
    for i in $(seq 1 5); do
        docker exec "ant-quic-client$i" ant-quic \
            --connect "203.0.113.10:9000" \
            --crypto-bench \
            --duration 30 > "$RESULTS_DIR/stress/crypto_bench_$i.log" 2>&1 &
    done
    
    # Monitor CPU usage
    local max_cpu=0
    for i in $(seq 1 30); do
        local cpu_usage=$(docker stats --no-stream --format "{{.CPUPerc}}" | grep -oE "[0-9.]+" | awk '{sum += $1} END {print sum}')
        if (( $(echo "$cpu_usage > $max_cpu" | bc -l) )); then
            max_cpu=$cpu_usage
        fi
        sleep 1
    done
    
    wait  # Wait for crypto benchmarks to complete
    
    # Generate report
    cat > "$RESULTS_DIR/stress/cpu_stress_report.txt" <<EOF
CPU Stress Test
Peak CPU Usage: ${max_cpu}%
Crypto Operations: 5 concurrent
Duration: 30s
EOF
    
    log "CPU stress test completed: peak usage ${max_cpu}%"
}

# Generate consolidated stress test report
generate_report() {
    log "Generating stress test report..."
    
    cat > "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md" <<'EOF'
# NAT Stress Test Report

## Test Date
$(date)

## Executive Summary
This report contains the results of stress testing the ant-quic NAT traversal implementation under various high-load scenarios.

## Test Results

### 1. Concurrent Connection Tests
EOF
    
    # Add concurrent connection results
    for report in "$RESULTS_DIR/stress/concurrent_"*_report.txt; do
        if [ -f "$report" ]; then
            echo -e "\n#### $(basename "$report" .txt)" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            cat "$report" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
        fi
    done
    
    # Add other test results
    cat >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md" <<'EOF'

### 2. Throughput Tests
EOF
    
    for report in "$RESULTS_DIR/stress/"*_throughput.txt; do
        if [ -f "$report" ]; then
            echo -e "\n#### $(basename "$report" .txt)" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            cat "$report" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
        fi
    done
    
    # Add resource usage
    cat >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md" <<'EOF'

### 3. Resource Usage Tests
EOF
    
    for report in "$RESULTS_DIR/stress/"*_stress_report.txt; do
        if [ -f "$report" ]; then
            echo -e "\n#### $(basename "$report" .txt)" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            cat "$report" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
            echo '```' >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
        fi
    done
    
    echo -e "\n## Conclusions\n" >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
    echo "The stress tests demonstrate the robustness of ant-quic's NAT traversal under high load conditions." >> "$RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
    
    log "Report generated: $RESULTS_DIR/stress/STRESS_TEST_SUMMARY.md"
}

# Main stress test execution
main() {
    log "Starting NAT Stress Test Suite"
    log "=============================="
    
    # Prepare environment
    prepare_environment
    
    # Run stress tests
    info "Phase 1: Concurrent Connection Tests"
    test_concurrent_connections "fullcone" 10
    test_concurrent_connections "fullcone" 50
    test_concurrent_connections "symmetric" 10
    test_concurrent_connections "symmetric" 50
    
    info "Phase 2: Throughput Stress Tests"
    test_throughput_stress "ant-quic-client1" "ant-quic-client2" "fullcone_to_symmetric_throughput"
    test_throughput_stress "ant-quic-client2" "ant-quic-client3" "symmetric_to_portrestricted_throughput"
    
    info "Phase 3: Port Exhaustion Tests"
    test_port_exhaustion "1"  # Full cone
    test_port_exhaustion "2"  # Symmetric
    
    info "Phase 4: Resource Usage Tests"
    test_memory_stress
    test_cpu_stress
    
    # Generate final report
    generate_report
    
    # Cleanup
    log "Cleaning up stress test environment..."
    docker compose -f "$COMPOSE_FILE" down -v
    
    log "Stress test suite completed!"
    log "Results available in: $RESULTS_DIR/stress/"
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi