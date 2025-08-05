#!/bin/bash

# Run specific integration tests within Docker container

set -euo pipefail

TEST_NAME="${1:-basic}"
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"
RESULT_FILE="/app/results/test-${TEST_NAME}-$(date +%s).json"

# Ensure results directory exists
mkdir -p /app/results

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
}

# Initialize test metrics
CONNECTIONS_ESTABLISHED=0
CONNECTIONS_FAILED=0
MESSAGES_SENT=0
MESSAGES_RECEIVED=0
NAT_TRAVERSALS_SUCCESSFUL=0
NAT_TRAVERSALS_FAILED=0

# Run specific test based on name
case "$TEST_NAME" in
    "basic")
        log "Running basic connectivity test"
        /app/ant-quic --test basic --duration 30
        ;;
    
    "full_cone_nat")
        log "Running Full Cone NAT test"
        # Connect through Full Cone NAT
        /app/ant-quic --bootstrap bootstrap:9000 --test nat-traversal --nat-type full-cone &
        CLIENT_PID=$!
        
        # Monitor for success
        timeout $TEST_TIMEOUT tail -f /app/logs/client.log | while read line; do
            if echo "$line" | grep -q "NAT traversal successful"; then
                ((NAT_TRAVERSALS_SUCCESSFUL++))
                echo "NAT traversal successful"
                break
            elif echo "$line" | grep -q "NAT traversal failed"; then
                ((NAT_TRAVERSALS_FAILED++))
                error "NAT traversal failed"
                break
            fi
        done
        
        kill $CLIENT_PID 2>/dev/null || true
        ;;
    
    "symmetric_nat")
        log "Running Symmetric NAT test"
        # More complex test for symmetric NAT
        /app/ant-quic --bootstrap bootstrap:9000 --test nat-traversal --nat-type symmetric &
        CLIENT_PID=$!
        
        # Symmetric NAT requires multiple attempts
        ATTEMPTS=0
        MAX_ATTEMPTS=5
        
        while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
            if timeout 30 grep -q "NAT traversal successful" /app/logs/client.log; then
                ((NAT_TRAVERSALS_SUCCESSFUL++))
                log "Symmetric NAT traversal successful after $((ATTEMPTS + 1)) attempts"
                break
            fi
            ((ATTEMPTS++))
            ((NAT_TRAVERSALS_FAILED++))
            log "Attempt $ATTEMPTS failed, retrying..."
            sleep 5
        done
        
        kill $CLIENT_PID 2>/dev/null || true
        ;;
    
    "port_restricted_nat")
        log "Running Port Restricted NAT test"
        /app/ant-quic --bootstrap bootstrap:9000 --test nat-traversal --nat-type port-restricted &
        CLIENT_PID=$!
        
        # Port restricted NAT test
        if timeout $TEST_TIMEOUT grep -q "NAT traversal successful" /app/logs/client.log; then
            ((NAT_TRAVERSALS_SUCCESSFUL++))
            log "Port Restricted NAT traversal successful"
        else
            ((NAT_TRAVERSALS_FAILED++))
            error "Port Restricted NAT traversal failed"
        fi
        
        kill $CLIENT_PID 2>/dev/null || true
        ;;
    
    "latency_"*)
        log "Running latency test: $TEST_NAME"
        LATENCY_TYPE="${TEST_NAME#latency_}"
        
        # Run latency-sensitive test
        /app/ant-quic --bootstrap bootstrap:9000 --test latency --duration 60 &
        CLIENT_PID=$!
        
        # Collect latency metrics
        sleep 60
        
        # Parse results
        if [ -f "/app/metrics/latency.json" ]; then
            AVG_LATENCY=$(jq -r '.avg_latency_ms' /app/metrics/latency.json)
            P99_LATENCY=$(jq -r '.p99_latency_ms' /app/metrics/latency.json)
            
            log "Latency test results: avg=${AVG_LATENCY}ms, p99=${P99_LATENCY}ms"
            
            # Check thresholds based on latency type
            case "$LATENCY_TYPE" in
                "low")
                    if (( $(echo "$P99_LATENCY < 50" | bc -l) )); then
                        ((CONNECTIONS_ESTABLISHED++))
                    else
                        ((CONNECTIONS_FAILED++))
                    fi
                    ;;
                "medium")
                    if (( $(echo "$P99_LATENCY < 150" | bc -l) )); then
                        ((CONNECTIONS_ESTABLISHED++))
                    else
                        ((CONNECTIONS_FAILED++))
                    fi
                    ;;
                "high")
                    if (( $(echo "$P99_LATENCY < 500" | bc -l) )); then
                        ((CONNECTIONS_ESTABLISHED++))
                    else
                        ((CONNECTIONS_FAILED++))
                    fi
                    ;;
            esac
        fi
        
        kill $CLIENT_PID 2>/dev/null || true
        ;;
    
    "stress")
        log "Running stress test"
        # Launch multiple clients
        for i in {1..10}; do
            /app/ant-quic --bootstrap bootstrap:9000 --client-id "stress-$i" &
            PIDS[$i]=$!
        done
        
        # Let them run
        sleep 60
        
        # Collect metrics
        for i in {1..10}; do
            if kill -0 ${PIDS[$i]} 2>/dev/null; then
                ((CONNECTIONS_ESTABLISHED++))
            else
                ((CONNECTIONS_FAILED++))
            fi
            kill ${PIDS[$i]} 2>/dev/null || true
        done
        ;;
    
    *)
        error "Unknown test: $TEST_NAME"
        exit 1
        ;;
esac

# Calculate success rate
TOTAL_CONNECTIONS=$((CONNECTIONS_ESTABLISHED + CONNECTIONS_FAILED))
if [ $TOTAL_CONNECTIONS -gt 0 ]; then
    SUCCESS_RATE=$(echo "scale=4; $CONNECTIONS_ESTABLISHED / $TOTAL_CONNECTIONS" | bc)
else
    SUCCESS_RATE=0
fi

# Write results
cat > "$RESULT_FILE" << EOF
{
    "test_name": "$TEST_NAME",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "connections_established": $CONNECTIONS_ESTABLISHED,
    "connections_failed": $CONNECTIONS_FAILED,
    "messages_sent": $MESSAGES_SENT,
    "messages_received": $MESSAGES_RECEIVED,
    "nat_traversals_successful": $NAT_TRAVERSALS_SUCCESSFUL,
    "nat_traversals_failed": $NAT_TRAVERSALS_FAILED,
    "success_rate": $SUCCESS_RATE,
    "duration_seconds": $TEST_TIMEOUT
}
EOF

# Output metrics for parsing
echo "Test completed: $TEST_NAME"
echo "connections_established: $CONNECTIONS_ESTABLISHED"
echo "connections_failed: $CONNECTIONS_FAILED"
echo "success_rate: $SUCCESS_RATE"

# Check for network recovery (for partition tests)
if [ "$TEST_NAME" = "partition_recovery" ]; then
    if [ $CONNECTIONS_ESTABLISHED -gt 0 ]; then
        echo "Network recovered from partition"
    fi
fi

# Exit with appropriate code
if [ $CONNECTIONS_FAILED -eq 0 ] && [ $CONNECTIONS_ESTABLISHED -gt 0 ]; then
    exit 0
else
    exit 1
fi