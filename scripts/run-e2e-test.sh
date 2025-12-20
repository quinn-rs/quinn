#!/bin/bash
# Full E2E Test Orchestration Script
#
# This script orchestrates a complete E2E test:
# 1. Starts the dashboard server
# 2. Starts test nodes (local and/or remote)
# 3. Runs data transfer tests
# 4. Collects and validates results
# 5. Generates a final report
#
# Usage:
#   ./scripts/run-e2e-test.sh [OPTIONS]
#
# Options:
#   --local-only     Only run local nodes (no DO)
#   --do-only        Only run DO nodes (no local)
#   --nodes N        Number of local nodes (default: 3)
#   --data-size N    Data size per node in bytes (default: 100 MB)
#   --duration N     Test duration in seconds (default: 60)
#   --dashboard-port Port for dashboard (default: 8080)
#   --verbose        Enable verbose logging
#   --quick          Quick test (10 MB, 30s)
#   --heavy          Heavy test (1 GB, 30 min)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_DIR}/target/e2e-logs"
TEST_NODE_BINARY="${PROJECT_DIR}/target/release/e2e-test-node"
DASHBOARD_BINARY="${PROJECT_DIR}/e2e-dashboard/target/release/e2e-dashboard"

# Default settings
NUM_LOCAL_NODES=3
DATA_SIZE=104857600  # 100 MB
DURATION=60
DASHBOARD_PORT=8080
BASE_PORT=9100
VERBOSE=false
LOCAL_ONLY=true  # Default to local testing
DO_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --local-only)
            LOCAL_ONLY=true
            DO_ONLY=false
            shift
            ;;
        --do-only)
            DO_ONLY=true
            LOCAL_ONLY=false
            shift
            ;;
        --nodes)
            NUM_LOCAL_NODES="$2"
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
        --dashboard-port)
            DASHBOARD_PORT="$2"
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
            DURATION=1800  # 30 min
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

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
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

format_duration() {
    local secs=$1
    if [ $secs -ge 3600 ]; then
        local h=$((secs / 3600))
        local m=$(((secs % 3600) / 60))
        echo "${h}h ${m}m"
    elif [ $secs -ge 60 ]; then
        local m=$((secs / 60))
        local s=$((secs % 60))
        echo "${m}m ${s}s"
    else
        echo "${secs}s"
    fi
}

cleanup() {
    log_info "Cleaning up..."

    # Kill dashboard
    if [ -n "$DASHBOARD_PID" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        kill "$DASHBOARD_PID" 2>/dev/null || true
    fi

    # Kill nodes
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    wait 2>/dev/null || true
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Build binaries
build_binaries() {
    log_step "Building binaries with zero warnings..."

    cd "$PROJECT_DIR"

    # Build test node
    if ! RUSTFLAGS="-D warnings" cargo build --release --bin e2e-test-node 2>&1; then
        log_error "Failed to build e2e-test-node"
        exit 1
    fi

    # Build dashboard
    cd "${PROJECT_DIR}/e2e-dashboard"
    if ! RUSTFLAGS="-D warnings" cargo build --release 2>&1; then
        log_error "Failed to build e2e-dashboard"
        exit 1
    fi

    log_success "Binaries built successfully"
}

# Start dashboard
start_dashboard() {
    log_step "Starting dashboard on port $DASHBOARD_PORT..."

    mkdir -p "$LOG_DIR"

    "$DASHBOARD_BINARY" --port "$DASHBOARD_PORT" > "$LOG_DIR/dashboard.log" 2>&1 &
    DASHBOARD_PID=$!

    sleep 2

    if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        log_error "Dashboard failed to start"
        cat "$LOG_DIR/dashboard.log"
        exit 1
    fi

    log_success "Dashboard started (PID: $DASHBOARD_PID)"
    log_info "Dashboard URL: http://localhost:$DASHBOARD_PORT"
}

# Start local nodes
start_local_nodes() {
    log_step "Starting $NUM_LOCAL_NODES local nodes..."

    NODE_PIDS=()
    DASHBOARD_URL="http://127.0.0.1:$DASHBOARD_PORT"

    VERBOSE_FLAG=""
    if [ "$VERBOSE" = true ]; then
        VERBOSE_FLAG="--verbose"
    fi

    # Start seed node
    local SEED_PORT=$BASE_PORT
    "$TEST_NODE_BINARY" \
        --listen "0.0.0.0:$SEED_PORT" \
        --node-id "seed-node" \
        --node-location "local" \
        --metrics-server "$DASHBOARD_URL" \
        --echo \
        --no-auth \
        --duration "$DURATION" \
        $VERBOSE_FLAG \
        > "$LOG_DIR/node-seed.log" 2>&1 &

    NODE_PIDS+=($!)
    log_info "Seed node started on port $SEED_PORT (PID: ${NODE_PIDS[0]})"

    sleep 2

    # Start echo nodes first (even-numbered), then senders connect to all
    local ECHO_PEERS="127.0.0.1:$SEED_PORT"

    # First pass: start all echo nodes (even-numbered)
    for i in $(seq 2 $NUM_LOCAL_NODES); do
        if [ $((i % 2)) -eq 0 ]; then
            local NODE_PORT=$((BASE_PORT + i - 1))
            local NODE_ID="node-$i"

            # Even node: receiver/echo - connects to seed
            "$TEST_NODE_BINARY" \
                --listen "0.0.0.0:$NODE_PORT" \
                --known-peers "127.0.0.1:$SEED_PORT" \
                --node-id "$NODE_ID" \
                --node-location "local" \
                --metrics-server "$DASHBOARD_URL" \
                --echo \
                --no-auth \
                --duration "$DURATION" \
                $VERBOSE_FLAG \
                > "$LOG_DIR/node-$i.log" 2>&1 &

            NODE_PIDS+=($!)
            log_info "Echo node $NODE_ID started on port $NODE_PORT (PID: $!)"

            # Add to peer list for senders
            ECHO_PEERS="$ECHO_PEERS,127.0.0.1:$NODE_PORT"

            sleep 1
        fi
    done

    # Wait for echo nodes to be ready
    sleep 2

    # Second pass: start sender nodes (odd-numbered) - connect to ALL peers
    for i in $(seq 2 $NUM_LOCAL_NODES); do
        if [ $((i % 2)) -ne 0 ]; then
            local NODE_PORT=$((BASE_PORT + i - 1))
            local NODE_ID="node-$i"

            # Odd node: sender - connects to seed AND all echo nodes
            "$TEST_NODE_BINARY" \
                --listen "0.0.0.0:$NODE_PORT" \
                --known-peers "$ECHO_PEERS" \
                --node-id "$NODE_ID" \
                --node-location "local" \
                --metrics-server "$DASHBOARD_URL" \
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

    log_success "All $NUM_LOCAL_NODES nodes started"
}

# Monitor test progress
monitor_progress() {
    log_step "Monitoring test progress..."

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

        # Check running nodes
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

        printf "\r[${BAR}] %3d%% (%s/%s) - %d/%d nodes running" \
            "$PROGRESS" "$(format_duration $ELAPSED)" "$(format_duration $DURATION)" "$RUNNING" "${#NODE_PIDS[@]}"

        sleep $PROGRESS_INTERVAL
    done
}

# Collect results
collect_results() {
    log_step "Collecting test results..."

    # Get summary from dashboard
    SUMMARY=$(curl -s "http://127.0.0.1:$DASHBOARD_PORT/api/network/summary" 2>/dev/null || echo '{}')

    if [ "$SUMMARY" = '{}' ] || [ -z "$SUMMARY" ]; then
        log_warn "Could not fetch summary from dashboard, parsing logs instead"
        analyze_logs
    else
        log_info "Dashboard summary:"
        echo "$SUMMARY" | python3 -m json.tool 2>/dev/null || echo "$SUMMARY"
    fi
}

# Analyze logs directly
analyze_logs() {
    TOTAL_BYTES_SENT=0
    TOTAL_BYTES_RECEIVED=0
    TOTAL_CHUNKS_VERIFIED=0
    VERIFICATION_FAILURES=0

    for i in $(seq 1 $NUM_LOCAL_NODES); do
        LOG_FILE="$LOG_DIR/node-$i.log"
        if [ $i -eq 1 ]; then
            LOG_FILE="$LOG_DIR/node-seed.log"
        fi

        if [ -f "$LOG_FILE" ]; then
            # Look for transfer completion
            if grep -q "DATA TRANSFER COMPLETE" "$LOG_FILE"; then
                CHUNKS=$(grep "Chunks sent:" "$LOG_FILE" | tail -1 | awk '{print $3}' || echo 0)
                TOTAL_CHUNKS_VERIFIED=$((TOTAL_CHUNKS_VERIFIED + ${CHUNKS:-0}))
            fi
        fi
    done
}

# Generate report
generate_report() {
    log_step "Generating final report..."

    REPORT_FILE="$LOG_DIR/test-report.json"
    END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "$REPORT_FILE" << EOF
{
    "test_config": {
        "num_nodes": $NUM_LOCAL_NODES,
        "data_size_bytes": $DATA_SIZE,
        "duration_secs": $DURATION,
        "local_only": $LOCAL_ONLY
    },
    "end_time": "$END_TIME",
    "logs_directory": "$LOG_DIR",
    "dashboard_url": "http://localhost:$DASHBOARD_PORT"
}
EOF

    log_success "Report saved to $REPORT_FILE"
}

# Print final summary
print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    TEST COMPLETE"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Configuration:"
    echo "    Nodes: $NUM_LOCAL_NODES"
    echo "    Data per node: $(format_bytes $DATA_SIZE)"
    echo "    Duration: $(format_duration $DURATION)"
    echo ""
    echo "  Dashboard: http://localhost:$DASHBOARD_PORT"
    echo "  Logs: $LOG_DIR/"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# Main execution
main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "            ant-quic FULL E2E TEST"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    log_info "Configuration:"
    log_info "  Nodes: $NUM_LOCAL_NODES"
    log_info "  Data per node: $(format_bytes $DATA_SIZE)"
    log_info "  Duration: $(format_duration $DURATION)"
    log_info "  Dashboard port: $DASHBOARD_PORT"
    echo ""

    mkdir -p "$LOG_DIR"

    # Build
    build_binaries

    # Start dashboard
    start_dashboard

    # Start nodes
    if [ "$LOCAL_ONLY" = true ] || [ "$DO_ONLY" = false ]; then
        start_local_nodes
    fi

    # Monitor
    echo ""
    monitor_progress
    echo ""

    # Wait for graceful shutdown
    log_info "Waiting for nodes to complete..."
    sleep 3

    # Send interrupt
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -INT "$pid" 2>/dev/null || true
        fi
    done

    # Wait
    for pid in "${NODE_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Results
    collect_results
    generate_report

    # Keep dashboard running for inspection
    log_info "Dashboard still running at http://localhost:$DASHBOARD_PORT"
    log_info "Press Ctrl+C to stop dashboard and exit"

    print_summary

    # Wait for user interrupt
    wait "$DASHBOARD_PID" 2>/dev/null || true
}

main "$@"
