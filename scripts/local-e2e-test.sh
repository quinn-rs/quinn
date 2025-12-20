#!/bin/bash
# Local E2E Test Script for ant-quic
#
# This script orchestrates local E2E testing with multiple nodes:
# - Builds the e2e-test-node binary with zero warnings
# - Starts 3-5 local nodes on different ports
# - Runs data exchange with verification
# - Reports pass/fail status
#
# Usage:
#   ./scripts/local-e2e-test.sh [OPTIONS]
#
# Options:
#   --nodes N       Number of nodes to spawn (default: 3)
#   --data-size N   Data size per node in bytes (default: 104857600 = 100 MB)
#   --duration N    Test duration in seconds (default: 60)
#   --verbose       Enable verbose logging
#   --quick         Quick test with smaller data (10 MB)
#   --heavy         Heavy test with 1 GB per node

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
NUM_NODES=3
DATA_SIZE=104857600  # 100 MB
DURATION=60
VERBOSE=false
BASE_PORT=9100
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="${PROJECT_DIR}/target/release/e2e-test-node"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)
            NUM_NODES="$2"
            shift 2
            ;;
        --data-size)
            DATA_SIZE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --quick)
            DATA_SIZE=10485760  # 10 MB
            DURATION=30
            shift
            ;;
        --heavy)
            DATA_SIZE=1073741824  # 1 GB
            DURATION=180
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

format_bytes() {
    local bytes=$1
    if [ $bytes -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [ $bytes -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [ $bytes -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
    else
        echo "$bytes B"
    fi
}

cleanup() {
    log_info "Cleaning up..."
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Main test execution
main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                ant-quic LOCAL E2E TEST"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    log_info "Configuration:"
    log_info "  Nodes: $NUM_NODES"
    log_info "  Data per node: $(format_bytes $DATA_SIZE)"
    log_info "  Duration: ${DURATION}s"
    log_info "  Base port: $BASE_PORT"
    echo ""

    # Step 1: Build with zero warnings
    log_info "Step 1: Building with zero warnings..."
    cd "$PROJECT_DIR"

    if ! RUSTFLAGS="-D warnings" cargo build --release --bin e2e-test-node 2>&1; then
        log_error "Build failed with warnings or errors!"
        exit 1
    fi
    log_success "Build completed with zero warnings"

    # Verify binary exists
    if [ ! -f "$BINARY" ]; then
        log_error "Binary not found at $BINARY"
        exit 1
    fi

    # Step 2: Start seed node (first node)
    log_info "Step 2: Starting seed node on port $BASE_PORT..."

    NODE_PIDS=()
    LOG_DIR="${PROJECT_DIR}/target/e2e-logs"
    mkdir -p "$LOG_DIR"

    SEED_PORT=$BASE_PORT
    SEED_ADDR="127.0.0.1:$SEED_PORT"

    VERBOSE_FLAG=""
    if [ "$VERBOSE" = true ]; then
        VERBOSE_FLAG="--verbose"
    fi

    # Start seed node (accepts connections, echoes data)
    "$BINARY" \
        --listen "0.0.0.0:$SEED_PORT" \
        --node-id "seed-node" \
        --node-location "local" \
        --echo \
        --no-auth \
        --duration "$DURATION" \
        $VERBOSE_FLAG \
        > "$LOG_DIR/node-seed.log" 2>&1 &

    NODE_PIDS+=($!)
    log_info "Seed node started (PID: ${NODE_PIDS[0]})"

    # Wait for seed node to be ready
    sleep 2

    # Step 3: Start additional nodes (echo nodes first, then senders)
    log_info "Step 3: Starting $((NUM_NODES - 1)) additional nodes..."

    # First, start all echo nodes (even-numbered) so senders can connect to them
    ECHO_PEERS="$SEED_ADDR"
    for i in $(seq 2 $NUM_NODES); do
        if [ $((i % 2)) -eq 0 ]; then
            NODE_PORT=$((BASE_PORT + i - 1))
            NODE_ID="node-$i"

            # Even node: receiver/echo - connects to seed
            "$BINARY" \
                --listen "0.0.0.0:$NODE_PORT" \
                --known-peers "$SEED_ADDR" \
                --node-id "$NODE_ID" \
                --node-location "local" \
                --echo \
                --no-auth \
                --duration "$DURATION" \
                $VERBOSE_FLAG \
                > "$LOG_DIR/node-$i.log" 2>&1 &

            NODE_PIDS+=($!)
            log_info "Echo node $NODE_ID started on port $NODE_PORT (PID: $!)"

            # Add this echo node to the list of peers for senders
            ECHO_PEERS="$ECHO_PEERS,127.0.0.1:$NODE_PORT"

            sleep 1
        fi
    done

    # Wait for echo nodes to be ready
    sleep 2

    # Now start sender nodes (odd-numbered) - they connect to ALL other nodes
    for i in $(seq 2 $NUM_NODES); do
        if [ $((i % 2)) -ne 0 ]; then
            NODE_PORT=$((BASE_PORT + i - 1))
            NODE_ID="node-$i"

            # Odd node: sender - connects to seed AND all echo nodes
            "$BINARY" \
                --listen "0.0.0.0:$NODE_PORT" \
                --known-peers "$ECHO_PEERS" \
                --node-id "$NODE_ID" \
                --node-location "local" \
                --generate-data "$DATA_SIZE" \
                --verify-data \
                --show-progress \
                --no-auth \
                --duration "$DURATION" \
                $VERBOSE_FLAG \
                > "$LOG_DIR/node-$i.log" 2>&1 &

            NODE_PIDS+=($!)
            log_info "Sender node $NODE_ID started on port $NODE_PORT, peers: $ECHO_PEERS (PID: $!)"

            sleep 1
        fi
    done

    # Step 4: Monitor progress
    log_info "Step 4: Monitoring test progress..."
    echo ""

    START_TIME=$(date +%s)
    PROGRESS_INTERVAL=5

    while true; do
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))

        if [ $ELAPSED -ge $DURATION ]; then
            echo ""
            log_info "Test duration complete"
            break
        fi

        # Check if all nodes are still running
        RUNNING=0
        for pid in "${NODE_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ((RUNNING++))
            fi
        done

        if [ $RUNNING -eq 0 ]; then
            echo ""
            log_info "All nodes have completed"
            break
        fi

        # Progress bar
        PROGRESS=$((ELAPSED * 100 / DURATION))
        FILLED=$((PROGRESS / 2))
        EMPTY=$((50 - FILLED))
        BAR=""
        for i in $(seq 1 $FILLED); do BAR="${BAR}#"; done
        for i in $(seq 1 $EMPTY); do BAR="${BAR}-"; done

        printf "\r[${BAR}] %3d%% (%ds/%ds) - %d/%d nodes running" \
            "$PROGRESS" "$ELAPSED" "$DURATION" "$RUNNING" "${#NODE_PIDS[@]}"

        sleep $PROGRESS_INTERVAL
    done

    echo ""
    echo ""

    # Step 5: Wait for nodes to finish gracefully
    log_info "Step 5: Waiting for nodes to complete..."
    sleep 3

    # Send interrupt signal to all nodes
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -INT "$pid" 2>/dev/null || true
        fi
    done

    # Wait for all nodes
    for pid in "${NODE_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Step 6: Analyze results
    log_info "Step 6: Analyzing results..."
    echo ""

    TOTAL_BYTES_SENT=0
    TOTAL_BYTES_RECEIVED=0
    TOTAL_CHUNKS_VERIFIED=0
    VERIFICATION_FAILURES=0
    NAT_SUCCESSES=0

    for i in $(seq 1 $NUM_NODES); do
        LOG_FILE="$LOG_DIR/node-$i.log"
        if [ $i -eq 1 ]; then
            LOG_FILE="$LOG_DIR/node-seed.log"
        fi

        if [ -f "$LOG_FILE" ]; then
            # Extract metrics from final stats
            BYTES_SENT=$(grep -o 'bytes_sent":[0-9]*' "$LOG_FILE" | tail -1 | cut -d: -f2 || echo 0)
            BYTES_RECV=$(grep -o 'bytes_received":[0-9]*' "$LOG_FILE" | tail -1 | cut -d: -f2 || echo 0)
            CHUNKS_OK=$(grep -o 'chunks_verified":[0-9]*' "$LOG_FILE" | tail -1 | cut -d: -f2 || echo 0)
            VERIFY_FAIL=$(grep -o 'verification_failures":[0-9]*' "$LOG_FILE" | tail -1 | cut -d: -f2 || echo 0)
            NAT_OK=$(grep -o 'nat_traversals_completed":[0-9]*' "$LOG_FILE" | tail -1 | cut -d: -f2 || echo 0)

            TOTAL_BYTES_SENT=$((TOTAL_BYTES_SENT + ${BYTES_SENT:-0}))
            TOTAL_BYTES_RECEIVED=$((TOTAL_BYTES_RECEIVED + ${BYTES_RECV:-0}))
            TOTAL_CHUNKS_VERIFIED=$((TOTAL_CHUNKS_VERIFIED + ${CHUNKS_OK:-0}))
            VERIFICATION_FAILURES=$((VERIFICATION_FAILURES + ${VERIFY_FAIL:-0}))
            NAT_SUCCESSES=$((NAT_SUCCESSES + ${NAT_OK:-0}))
        fi
    done

    # Calculate throughput
    TOTAL_BYTES=$((TOTAL_BYTES_SENT + TOTAL_BYTES_RECEIVED))
    THROUGHPUT_MBPS=$(echo "scale=2; $TOTAL_BYTES * 8 / $DURATION / 1000000" | bc)

    echo "═══════════════════════════════════════════════════════════════"
    echo "                    TEST RESULTS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Nodes: $NUM_NODES"
    echo "  Duration: ${DURATION}s"
    echo "  Total bytes sent: $(format_bytes $TOTAL_BYTES_SENT)"
    echo "  Total bytes received: $(format_bytes $TOTAL_BYTES_RECEIVED)"
    echo "  Average throughput: ${THROUGHPUT_MBPS} Mbps"
    echo "  Data chunks verified: $TOTAL_CHUNKS_VERIFIED"
    echo "  Verification failures: $VERIFICATION_FAILURES"
    echo "  NAT traversals: $NAT_SUCCESSES"
    echo ""
    echo "  Logs: $LOG_DIR/"
    echo ""

    # Determine pass/fail
    if [ $VERIFICATION_FAILURES -gt 0 ]; then
        log_error "TEST FAILED: $VERIFICATION_FAILURES verification failures"
        echo "═══════════════════════════════════════════════════════════════"
        exit 1
    elif [ $TOTAL_BYTES_SENT -eq 0 ]; then
        log_warn "TEST WARNING: No data was sent"
        echo "═══════════════════════════════════════════════════════════════"
        exit 1
    else
        log_success "TEST PASSED: All data verified successfully"
        echo "═══════════════════════════════════════════════════════════════"
        exit 0
    fi
}

main "$@"
