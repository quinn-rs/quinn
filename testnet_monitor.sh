#!/bin/bash

# Testnet monitoring script for ant-quic
NODES=(
  "162.243.167.201"  # bootstrap
  "159.65.221.230"
  "67.205.158.158"
  "161.35.231.80"
  "178.62.192.11"
  "159.65.90.128"
)

BOOTSTRAP="162.243.167.201"
DURATION=600  # 10 minutes in seconds
INTERVAL=60   # Check every 60 seconds
ITERATIONS=$((DURATION / INTERVAL))
ITERATION=0
ISSUES=()

echo "====== ANT-QUIC TESTNET MONITOR ======"
echo "Duration: $DURATION seconds ($((DURATION/60)) minutes)"
echo "Check interval: $INTERVAL seconds"
echo "Nodes: ${#NODES[@]}"
echo "Starting monitoring at $(date)"
echo "======================================="
echo ""

while [ $ITERATION -lt $ITERATIONS ]; do
  ITERATION=$((ITERATION + 1))
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

  echo "[$TIMESTAMP] Iteration $ITERATION/$ITERATIONS"
  echo "---"

  # Check each node
  for NODE in "${NODES[@]}"; do
    NODE_LABEL=$NODE
    if [ "$NODE" == "$BOOTSTRAP" ]; then
      NODE_LABEL="$NODE (BOOTSTRAP)"
    fi

    # Check 1: Process running
    PROCESS_STATUS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@$NODE "pgrep -f ant-quic" 2>&1)

    if [ $? -eq 0 ] && [ ! -z "$PROCESS_STATUS" ]; then
      PIDS=$(echo "$PROCESS_STATUS" | wc -l)
      echo "  ✓ $NODE_LABEL: ant-quic running ($PIDS process(es))"
    else
      ERROR_MSG="✗ $NODE_LABEL: ant-quic NOT RUNNING"
      echo "  $ERROR_MSG"
      ISSUES+=("$TIMESTAMP - $ERROR_MSG")
    fi

    # Check 2: Errors in logs
    ERROR_LOG=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@$NODE "tail -5 /var/log/ant-quic.log 2>/dev/null | grep -i error" 2>&1)

    if [ ! -z "$ERROR_LOG" ]; then
      ERROR_MSG="✗ $NODE_LABEL: Found errors in logs"
      echo "    $ERROR_MSG"
      echo "    Log: $(echo "$ERROR_LOG" | head -1)"
      ISSUES+=("$TIMESTAMP - $ERROR_MSG")
    fi
  done

  # Check 3: Bootstrap connections
  if [ $ITERATION -eq 1 ] || [ $((ITERATION % 5)) -eq 0 ]; then
    echo "  Checking bootstrap connections..."
    CONNECTIONS=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@$BOOTSTRAP "tail -20 /var/log/ant-quic.log 2>/dev/null | grep 'Active connections' | tail -1" 2>&1)

    if [ ! -z "$CONNECTIONS" ]; then
      echo "    $CONNECTIONS"
    else
      echo "    (No recent connection status)"
    fi
  fi

  echo ""

  # Wait for next iteration (but not after last iteration)
  if [ $ITERATION -lt $ITERATIONS ]; then
    echo "Sleeping $INTERVAL seconds until next check..."
    echo ""
    sleep $INTERVAL
  fi
done

echo "====== MONITORING COMPLETE ======"
echo "Completed at $(date)"
echo ""

if [ ${#ISSUES[@]} -gt 0 ]; then
  echo "ISSUES FOUND:"
  for ISSUE in "${ISSUES[@]}"; do
    echo "  - $ISSUE"
  done
  exit 1
else
  echo "✓ No issues detected during monitoring period"
  exit 0
fi
