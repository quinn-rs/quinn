#!/bin/bash
# VPS Test Orchestrator for ant-quic
# Part of the Designer Flow workflow
#
# Usage:
#   ./vps-test-orchestrator.sh deploy              Deploy binary to all nodes
#   ./vps-test-orchestrator.sh run <scenario>      Run a test scenario
#   ./vps-test-orchestrator.sh collect             Collect results from all nodes
#   ./vps-test-orchestrator.sh report              Generate summary report
#   ./vps-test-orchestrator.sh status              Check node status

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/test-results"
BINARY_PATH="$PROJECT_DIR/target/release/ant-quic"

# =============================================================================
# VPS Fleet Configuration - Multi-Provider
# =============================================================================
# Providers: DigitalOcean (DO), Hetzner (HZ), Vultr (VT)
# Infrastructure defined in: ../saorsa-infra/terraform/
#
# To refresh from terraform:
#   cd ../saorsa-infra/terraform && terraform output -json all_existing_nodes
# =============================================================================

SAORSA_INFRA_DIR="$PROJECT_DIR/../saorsa-infra"

# Node definitions using indexed arrays (bash 3.x compatible)
# Format: name:ip:provider:region:nat_type:role
NODE_DATA=(
  "saorsa1:77.42.75.115:hetzner:hel1:none:monitoring"
  "node1:162.243.167.201:digitalocean:nyc1:none:testnet"
  "node2:159.65.221.230:digitalocean:nyc1:none:testnet"
  "bootstrap:138.197.29.195:digitalocean:nyc3:none:bootstrap"
  "fullcone:67.205.158.158:digitalocean:nyc1:full_cone:nat_test"
  "restricted:161.35.231.80:digitalocean:sfo3:address_restricted:nat_test"
  "portrestricted:178.62.192.11:digitalocean:ams3:port_restricted:nat_test"
  "symmetric:159.65.90.128:digitalocean:lon1:symmetric:nat_test"
)

# Helper functions to extract node data
get_node_names() {
  for entry in "${NODE_DATA[@]}"; do
    echo "${entry%%:*}"
  done
}

get_node_ip() {
  local name="$1"
  for entry in "${NODE_DATA[@]}"; do
    if [[ "${entry%%:*}" == "$name" ]]; then
      echo "$entry" | cut -d: -f2
      return
    fi
  done
}

get_node_provider() {
  local name="$1"
  for entry in "${NODE_DATA[@]}"; do
    if [[ "${entry%%:*}" == "$name" ]]; then
      echo "$entry" | cut -d: -f3
      return
    fi
  done
}

get_node_region() {
  local name="$1"
  for entry in "${NODE_DATA[@]}"; do
    if [[ "${entry%%:*}" == "$name" ]]; then
      echo "$entry" | cut -d: -f4
      return
    fi
  done
}

get_node_nat() {
  local name="$1"
  for entry in "${NODE_DATA[@]}"; do
    if [[ "${entry%%:*}" == "$name" ]]; then
      echo "$entry" | cut -d: -f5
      return
    fi
  done
}

get_node_role() {
  local name="$1"
  for entry in "${NODE_DATA[@]}"; do
    if [[ "${entry%%:*}" == "$name" ]]; then
      echo "$entry" | cut -d: -f6
      return
    fi
  done
}

# =============================================================================
# Dynamic Node Discovery from Terraform
# =============================================================================

load_nodes_from_terraform() {
  local tf_dir="$SAORSA_INFRA_DIR/terraform"

  if [ ! -d "$tf_dir" ]; then
    log_warn "Terraform directory not found: $tf_dir"
    log_info "Using static node definitions"
    return 1
  fi

  # Try to get nodes from terraform output
  local tf_nodes
  tf_nodes=$(cd "$tf_dir" && terraform output -json all_existing_nodes 2>/dev/null) || {
    log_warn "Could not get terraform output, using static definitions"
    return 1
  }

  if [ "$tf_nodes" = "null" ] || [ -z "$tf_nodes" ]; then
    log_warn "No nodes in terraform state, using static definitions"
    return 1
  fi

  log_info "Loaded nodes from terraform state"
  # Note: For now we use static definitions which match terraform
  # Future: dynamically populate NODES array from terraform output
  return 0
}

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
NC="\033[0m"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

#
# COMMANDS
#

cmd_deploy() {
  log_info "Deploying ant-quic binary to all nodes..."

  if [ ! -f "$BINARY_PATH" ]; then
    log_error "Binary not found at $BINARY_PATH"
    log_info "Building release binary..."
    cargo build --release -p ant-quic
  fi

  for name in $(get_node_names); do
    ip=$(get_node_ip "$name")
    log_info "Deploying to $name ($ip)..."

    # Copy binary
    scp -o ConnectTimeout=10 "$BINARY_PATH" "root@$ip:/opt/saorsa/bin/ant-quic" || {
      log_error "Failed to copy binary to $name"
      continue
    }

    # Make executable and restart
    ssh -o ConnectTimeout=10 "root@$ip" "chmod +x /opt/saorsa/bin/ant-quic && systemctl restart saorsa-node 2>/dev/null || true" || {
      log_warn "Failed to restart on $name"
    }

    log_success "Deployed to $name"
  done

  log_success "Deployment complete"
}

cmd_status() {
  log_info "Checking node status across all providers..."
  echo ""
  printf "%-15s %-10s %-8s %-18s %-15s %-12s %-10s\n" \
    "NAME" "PROVIDER" "REGION" "IP" "NAT TYPE" "ROLE" "STATUS"
  printf "%s\n" "=========================================================================================="

  # Sort nodes by provider for cleaner output
  for provider in "hetzner" "digitalocean" "vultr"; do
    has_nodes=false

    for name in $(get_node_names); do
      node_provider=$(get_node_provider "$name")
      if [ "$node_provider" = "$provider" ]; then
        has_nodes=true
        ip=$(get_node_ip "$name")
        nat=$(get_node_nat "$name")
        region=$(get_node_region "$name")
        role=$(get_node_role "$name")

        # Provider short code for display
        case "$provider" in
          hetzner) prov_short="HZ" ;;
          digitalocean) prov_short="DO" ;;
          vultr) prov_short="VT" ;;
          *) prov_short="??" ;;
        esac

        if ssh -o ConnectTimeout=5 -o BatchMode=yes "root@$ip" "pgrep ant-quic" > /dev/null 2>&1; then
          status="${GREEN}RUNNING${NC}"
        elif ssh -o ConnectTimeout=5 -o BatchMode=yes "root@$ip" "echo ok" > /dev/null 2>&1; then
          status="${YELLOW}STOPPED${NC}"
        else
          status="${RED}UNREACHABLE${NC}"
        fi

        printf "%-15s %-10s %-8s %-18s %-15s %-12s " \
          "$name" "$prov_short" "$region" "$ip" "$nat" "$role"
        echo -e "$status"
      fi
    done

    if [ "$has_nodes" = true ]; then
      echo ""
    fi
  done

  # Summary
  echo "=========================================================================================="
  total_nodes=${#NODE_DATA[@]}
  hz_count=0
  do_count=0
  vt_count=0
  for name in $(get_node_names); do
    case "$(get_node_provider "$name")" in
      hetzner) hz_count=$((hz_count + 1)) ;;
      digitalocean) do_count=$((do_count + 1)) ;;
      vultr) vt_count=$((vt_count + 1)) ;;
    esac
  done
  echo "Total: $total_nodes nodes (HZ: $hz_count, DO: $do_count, VT: $vt_count)"
}

cmd_run() {
  local scenario="${1:-}"
  
  if [ -z "$scenario" ]; then
    echo "Usage: $0 run <scenario>"
    echo "Available scenarios:"
    echo "  nat_matrix         - Test all NAT type combinations"
    echo "  chaos_kill_random  - Kill random nodes and measure recovery"
    echo "  message_relay      - End-to-end message delivery test"
    echo "  sustained_load     - Stability under sustained traffic"
    echo "  all                - Run all scenarios"
    exit 1
  fi
  
  mkdir -p "$RESULTS_DIR"
  local timestamp=$(date +%Y%m%d_%H%M%S)
  local result_file="$RESULTS_DIR/${scenario}_${timestamp}.log"
  
  case "$scenario" in
    nat_matrix)
      run_nat_matrix "$result_file"
      ;;
    chaos_kill_random)
      run_chaos_kill_random "$result_file"
      ;;
    message_relay)
      run_message_relay "$result_file"
      ;;
    sustained_load)
      run_sustained_load "$result_file"
      ;;
    all)
      run_nat_matrix "$RESULTS_DIR/nat_matrix_${timestamp}.log"
      run_chaos_kill_random "$RESULTS_DIR/chaos_${timestamp}.log"
      run_message_relay "$RESULTS_DIR/relay_${timestamp}.log"
      ;;
    *)
      log_error "Unknown scenario: $scenario"
      exit 1
      ;;
  esac
}

#
# SCENARIO IMPLEMENTATIONS
#

run_nat_matrix() {
  local result_file="$1"
  log_info "Running NAT matrix test..."

  total=0
  success=0
  failed=0

  echo "=== NAT Matrix Test ===" | tee "$result_file"
  echo "Started: $(date)" | tee -a "$result_file"
  echo "" | tee -a "$result_file"

  for src_name in $(get_node_names); do
    src_ip=$(get_node_ip "$src_name")
    src_nat=$(get_node_nat "$src_name")

    for dst_name in $(get_node_names); do
      if [ "$src_name" = "$dst_name" ]; then
        continue
      fi

      dst_ip=$(get_node_ip "$dst_name")
      dst_nat=$(get_node_nat "$dst_name")
      total=$((total + 1))

      log_info "Testing $src_name ($src_nat) -> $dst_name ($dst_nat)"

      # Run connection test
      if ssh -o ConnectTimeout=10 "root@$src_ip" \
        "/opt/saorsa/bin/ant-quic --connect $dst_ip:9000 --test-mode --timeout 15" \
        > /tmp/test_result.log 2>&1; then
        success=$((success + 1))
        echo "PASS: $src_name -> $dst_name" | tee -a "$result_file"
      else
        failed=$((failed + 1))
        echo "FAIL: $src_name -> $dst_name" | tee -a "$result_file"
      fi
    done
  done

  rate=$((success * 100 / total))
  echo "" | tee -a "$result_file"
  echo "=== Summary ===" | tee -a "$result_file"
  echo "Total tests: $total" | tee -a "$result_file"
  echo "Passed: $success" | tee -a "$result_file"
  echo "Failed: $failed" | tee -a "$result_file"
  echo "Success rate: ${rate}%" | tee -a "$result_file"

  if [ $rate -ge 95 ]; then
    log_success "NAT matrix test PASSED (${rate}%)"
  else
    log_error "NAT matrix test FAILED (${rate}%)"
  fi
}

run_chaos_kill_random() {
  local result_file="$1"
  log_info "Running chaos test: kill random nodes..."

  echo "=== Chaos Test: Kill Random ===" | tee "$result_file"
  echo "Started: $(date)" | tee -a "$result_file"

  # Get node names into array
  nodes_array=($(get_node_names))
  node_count=${#nodes_array[@]}

  # Select 2 random nodes to kill
  victim1="${nodes_array[$((RANDOM % node_count))]}"
  victim2="${nodes_array[$((RANDOM % node_count))]}"
  while [ "$victim1" = "$victim2" ]; do
    victim2="${nodes_array[$((RANDOM % node_count))]}"
  done

  echo "Killing nodes: $victim1, $victim2" | tee -a "$result_file"

  # Kill the processes
  ssh "root@$(get_node_ip "$victim1")" "pkill -9 ant-quic" 2>/dev/null || true
  ssh "root@$(get_node_ip "$victim2")" "pkill -9 ant-quic" 2>/dev/null || true

  # Measure recovery time
  start=$(date +%s)
  recovered=0
  max_wait=60

  while [ $recovered -lt 2 ] && [ $(($(date +%s) - start)) -lt $max_wait ]; do
    sleep 2
    recovered=0

    for victim in "$victim1" "$victim2"; do
      if ssh "root@$(get_node_ip "$victim")" "pgrep ant-quic" > /dev/null 2>&1; then
        recovered=$((recovered + 1))
      fi
    done

    echo "Recovered: $recovered/2 (elapsed: $(($(date +%s) - start))s)" | tee -a "$result_file"
  done

  elapsed=$(($(date +%s) - start))
  echo "" | tee -a "$result_file"
  echo "Recovery time: ${elapsed}s" | tee -a "$result_file"

  if [ $elapsed -lt 10 ]; then
    log_success "Chaos test PASSED (recovery in ${elapsed}s)"
  else
    log_warn "Chaos test SLOW (recovery in ${elapsed}s)"
  fi
}

run_message_relay() {
  local result_file="$1"
  local message_count=50

  log_info "Running message relay test..."
  echo "=== Message Relay Test ===" | tee "$result_file"

  sender_ip=$(get_node_ip "node1")
  receiver_ip=$(get_node_ip "symmetric")  # Hardest target

  echo "Sender: node1 ($sender_ip)" | tee -a "$result_file"
  echo "Receiver: symmetric ($receiver_ip)" | tee -a "$result_file"
  echo "Messages: $message_count" | tee -a "$result_file"

  success=0
  for i in $(seq 1 $message_count); do
    if ssh -o ConnectTimeout=10 "root@$sender_ip" \
      "/opt/saorsa/bin/ant-quic --connect $receiver_ip:9000 --message \"Test $i\" --one-shot --timeout 10" \
      > /dev/null 2>&1; then
      success=$((success + 1))
    fi
    echo -ne "\rProgress: $i/$message_count"
  done
  echo ""

  rate=$((success * 100 / message_count))
  echo "" | tee -a "$result_file"
  echo "Delivered: $success/$message_count (${rate}%)" | tee -a "$result_file"

  if [ $rate -ge 95 ]; then
    log_success "Message relay test PASSED (${rate}%)"
  else
    log_error "Message relay test FAILED (${rate}%)"
  fi
}

run_sustained_load() {
  local result_file="$1"
  local duration=60

  log_info "Running sustained load test (${duration}s)..."
  echo "=== Sustained Load Test ===" | tee "$result_file"

  start=$(date +%s)
  messages=0
  failures=0
  nodes_array=($(get_node_names))
  node_count=${#nodes_array[@]}

  while [ $(($(date +%s) - start)) -lt $duration ]; do
    # Pick random source and destination
    src="${nodes_array[$((RANDOM % node_count))]}"
    dst="${nodes_array[$((RANDOM % node_count))]}"

    if [ "$src" = "$dst" ]; then
      continue
    fi

    src_ip=$(get_node_ip "$src")
    dst_ip=$(get_node_ip "$dst")

    if ssh -o ConnectTimeout=5 "root@$src_ip" \
      "/opt/saorsa/bin/ant-quic --connect $dst_ip:9000 --message \"Load\" --one-shot --timeout 5" \
      > /dev/null 2>&1; then
      messages=$((messages + 1))
    else
      failures=$((failures + 1))
    fi

    echo -ne "\rMessages: $messages, Failures: $failures"
  done
  echo ""

  total=$((messages + failures))
  rate=$((messages * 100 / total))

  echo "" | tee -a "$result_file"
  echo "Total attempts: $total" | tee -a "$result_file"
  echo "Successful: $messages" | tee -a "$result_file"
  echo "Failed: $failures" | tee -a "$result_file"
  echo "Success rate: ${rate}%" | tee -a "$result_file"

  if [ $rate -ge 90 ]; then
    log_success "Sustained load test PASSED (${rate}%)"
  else
    log_error "Sustained load test FAILED (${rate}%)"
  fi
}

cmd_collect() {
  log_info "Collecting logs from all nodes..."
  mkdir -p "$RESULTS_DIR/logs"

  for name in $(get_node_names); do
    ip=$(get_node_ip "$name")
    log_info "Collecting from $name..."

    scp -o ConnectTimeout=10 "root@$ip:/opt/saorsa/logs/*.log" \
      "$RESULTS_DIR/logs/${name}_" 2>/dev/null || {
      log_warn "No logs on $name"
    }
  done

  log_success "Logs collected to $RESULTS_DIR/logs/"
}

cmd_report() {
  log_info "Generating test report..."

  if [ ! -d "$RESULTS_DIR" ]; then
    log_error "No results directory found"
    exit 1
  fi
  
  echo ""
  echo "====================================="
  echo "       VPS Test Report"
  echo "====================================="
  echo ""
  
  for result in "$RESULTS_DIR"/*.log; do
    if [ -f "$result" ]; then
      local name=$(basename "$result")
      echo "--- $name ---"
      tail -10 "$result"
      echo ""
    fi
  done
}

#
# MAIN
#

main() {
  local cmd="${1:-help}"
  shift || true
  
  case "$cmd" in
    deploy)
      cmd_deploy "$@"
      ;;
    status)
      cmd_status "$@"
      ;;
    run)
      cmd_run "$@"
      ;;
    collect)
      cmd_collect "$@"
      ;;
    report)
      cmd_report "$@"
      ;;
    help|--help|-h)
      echo "VPS Test Orchestrator for ant-quic"
      echo ""
      echo "Multi-Provider Infrastructure:"
      echo "  HZ (Hetzner)       - Monitoring and core services"
      echo "  DO (DigitalOcean)  - Testnet and NAT test nodes"
      echo "  VT (Vultr)         - Additional geographic coverage"
      echo ""
      echo "Usage: $0 <command> [options]"
      echo ""
      echo "Commands:"
      echo "  deploy     Deploy binary to all VPS nodes (all providers)"
      echo "  status     Check status of all nodes with provider info"
      echo "  run        Run a test scenario across the fleet"
      echo "  collect    Collect logs from all nodes"
      echo "  report     Generate test report"
      echo ""
      echo "Test Scenarios:"
      echo "  nat_matrix         Test all NAT type combinations"
      echo "  chaos_kill_random  Kill random nodes, measure recovery"
      echo "  message_relay      End-to-end message delivery test"
      echo "  sustained_load     Stability under sustained traffic"
      echo "  all                Run all scenarios"
      echo ""
      echo "Examples:"
      echo "  $0 status              # Show all nodes across providers"
      echo "  $0 deploy              # Deploy to HZ, DO, VT nodes"
      echo "  $0 run nat_matrix      # Test NAT traversal matrix"
      echo "  $0 run all             # Full test suite"
      echo ""
      echo "Infrastructure: ../saorsa-infra/terraform/"
      ;;
    *)
      log_error "Unknown command: $cmd"
      echo "Run \"$0 help\" for usage"
      exit 1
      ;;
  esac
}

main "$@"
