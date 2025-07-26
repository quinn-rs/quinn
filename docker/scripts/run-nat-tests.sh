#!/bin/bash
# NAT Testing Orchestration Script
# Runs comprehensive NAT traversal tests

set -e

# Configuration
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.yml}
LOG_DIR=${LOG_DIR:-./logs}
RESULTS_DIR=${RESULTS_DIR:-./results}
TEST_DURATION=${TEST_DURATION:-300}  # 5 minutes default

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
PASSED=0
FAILED=0
TOTAL=0

log() {
    echo -e "${GREEN}[NAT-TEST]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker not found. Please install Docker."
        exit 1
    fi
    
    # Check for docker compose (v2) or docker-compose (v1)
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        error "Docker Compose not found. Please install Docker Compose."
        exit 1
    fi
    
    if [ ! -f "$COMPOSE_FILE" ]; then
        error "Docker compose file not found: $COMPOSE_FILE"
        exit 1
    fi
    
    # Create directories
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    
    log "Prerequisites check passed (using: $COMPOSE_CMD)"
}

# Build containers
build_containers() {
    log "Building Docker containers..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" build --parallel
    log "Containers built successfully"
}

# Start test environment
start_environment() {
    log "Starting test environment..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" up -d
    
    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 10
    
    # Check service health
    for service in bootstrap nat1_gateway nat2_gateway nat3_gateway nat4_gateway; do
        if $COMPOSE_CMD -f "$COMPOSE_FILE" ps | grep -q "${service}.*Up"; then
            log "✓ Service $service is running"
        else
            error "✗ Service $service failed to start"
            return 1
        fi
    done
    
    log "Test environment is ready"
}

# Run connectivity test
test_connectivity() {
    local client=$1
    local target=$2
    local test_name=$3
    
    info "Testing: $test_name"
    
    # Execute ping test in client container
    if docker exec "$client" timeout 5 ant-quic --ping "$target" > "$RESULTS_DIR/${test_name}.log" 2>&1; then
        log "✓ $test_name: PASSED"
        ((PASSED++))
        return 0
    else
        error "✗ $test_name: FAILED"
        ((FAILED++))
        return 1
    fi
}

# Run NAT traversal test between two clients
test_nat_traversal() {
    local client1=$1
    local client2=$2
    local test_name=$3
    
    info "Testing NAT traversal: $test_name"
    
    # Start receiver on client2
    docker exec -d "$client2" ant-quic --listen 0.0.0.0:9001 --test-mode > "$RESULTS_DIR/${test_name}_receiver.log" 2>&1
    sleep 2
    
    # Get client2's discovered address via bootstrap
    local client2_addr=$(docker exec "$client2" ant-quic --query-peer client2 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)
    
    if [ -z "$client2_addr" ]; then
        error "✗ $test_name: Could not discover peer address"
        ((FAILED++))
        return 1
    fi
    
    # Attempt connection from client1
    if docker exec "$client1" timeout 30 ant-quic --connect "$client2_addr" --test-mode > "$RESULTS_DIR/${test_name}_sender.log" 2>&1; then
        log "✓ $test_name: PASSED"
        ((PASSED++))
        return 0
    else
        error "✗ $test_name: FAILED"
        ((FAILED++))
        return 1
    fi
}

# Apply network conditions
apply_network_conditions() {
    local container=$1
    local scenario=$2
    
    log "Applying network conditions '$scenario' to $container"
    
    case "$scenario" in
        "lossy")
            docker exec "$container" tc qdisc add dev eth0 root netem loss 5%
            ;;
        "slow")
            docker exec "$container" tc qdisc add dev eth0 root netem delay 100ms 20ms
            ;;
        "congested")
            docker exec "$container" tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
            ;;
        "normal")
            docker exec "$container" tc qdisc del dev eth0 root 2>/dev/null || true
            ;;
    esac
}

# Run test suite
run_test_suite() {
    log "Starting NAT traversal test suite"
    
    TOTAL=0
    
    # Test 1: Bootstrap connectivity from all clients
    for i in 1 2 3 4; do
        ((TOTAL++))
        test_connectivity "ant-quic-client$i" "203.0.113.10:9000" "client${i}_to_bootstrap"
    done
    
    # Test 2: NAT traversal between different NAT types
    ((TOTAL++))
    test_nat_traversal "ant-quic-client1" "ant-quic-client2" "fullcone_to_symmetric"
    
    ((TOTAL++))
    test_nat_traversal "ant-quic-client1" "ant-quic-client3" "fullcone_to_portrestricted"
    
    ((TOTAL++))
    test_nat_traversal "ant-quic-client2" "ant-quic-client3" "symmetric_to_portrestricted"
    
    ((TOTAL++))
    test_nat_traversal "ant-quic-client1" "ant-quic-client4" "fullcone_to_cgnat"
    
    ((TOTAL++))
    test_nat_traversal "ant-quic-client2" "ant-quic-client4" "symmetric_to_cgnat"
    
    # Test 3: NAT traversal under network stress
    log "Testing under network stress conditions"
    
    # Apply lossy network
    apply_network_conditions "nat1_gateway" "lossy"
    ((TOTAL++))
    test_nat_traversal "ant-quic-client1" "ant-quic-client2" "fullcone_to_symmetric_lossy"
    apply_network_conditions "nat1_gateway" "normal"
    
    # Apply high latency
    apply_network_conditions "nat2_gateway" "slow"
    ((TOTAL++))
    test_nat_traversal "ant-quic-client2" "ant-quic-client3" "symmetric_to_portrestricted_slow"
    apply_network_conditions "nat2_gateway" "normal"
    
    log "Test suite completed"
}

# Collect results
collect_results() {
    log "Collecting test results..."
    
    # Generate summary report
    cat > "$RESULTS_DIR/summary.txt" <<EOF
NAT Traversal Test Summary
==========================
Date: $(date)
Total Tests: $TOTAL
Passed: $PASSED
Failed: $FAILED
Success Rate: $(awk "BEGIN {printf \"%.1f\", ($PASSED/$TOTAL)*100}")%

Test Environment:
- Bootstrap: 203.0.113.10:9000
- NAT Types: Full Cone, Symmetric, Port Restricted, CGNAT
- Network Conditions: Normal, Lossy (5%), High Latency (100ms)

Detailed Results:
EOF
    
    # Append individual test results
    for log_file in "$RESULTS_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            echo -e "\n--- $(basename "$log_file") ---" >> "$RESULTS_DIR/summary.txt"
            tail -20 "$log_file" >> "$RESULTS_DIR/summary.txt"
        fi
    done
    
    # Collect container logs
    for service in bootstrap client1 client2 client3 client4; do
        $COMPOSE_CMD -f "$COMPOSE_FILE" logs "$service" > "$LOG_DIR/${service}.log" 2>&1
    done
    
    log "Results collected in $RESULTS_DIR/summary.txt"
}

# Cleanup
cleanup() {
    log "Cleaning up test environment..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" down -v
    log "Cleanup completed"
}

# Main execution
main() {
    log "ANT-QUIC NAT Testing Suite"
    log "=========================="
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Run test pipeline
    check_prerequisites
    build_containers
    start_environment
    run_test_suite
    collect_results
    
    # Print summary
    echo
    log "Test Summary:"
    log "============="
    log "Total Tests: $TOTAL"
    log "Passed: $PASSED ($(awk "BEGIN {printf \"%.1f\", ($PASSED/$TOTAL)*100}")%)"
    log "Failed: $FAILED ($(awk "BEGIN {printf \"%.1f\", ($FAILED/$TOTAL)*100}")%)"
    
    if [ $FAILED -eq 0 ]; then
        log "All tests passed! 🎉"
        exit 0
    else
        error "Some tests failed. Check $RESULTS_DIR for details."
        exit 1
    fi
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi