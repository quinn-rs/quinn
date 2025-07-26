#!/bin/bash
# Test Orchestrator - Coordinates complex test scenarios

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
    local level=$1
    shift
    case $level in
        ERROR) echo -e "${RED}[ERROR]${NC} $*" >&2 ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $*" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $*" ;;
        *) echo "[INFO] $*" ;;
    esac
}

# Function to run a test suite
run_test_suite() {
    local suite_name=$1
    local test_command=$2
    local timeout_minutes=${3:-30}
    
    log INFO "Running test suite: $suite_name"
    log INFO "Command: $test_command"
    log INFO "Timeout: ${timeout_minutes} minutes"
    
    local start_time=$(date +%s)
    local test_output="${TEST_RESULTS_DIR}/${suite_name}-output.txt"
    local test_status=0
    
    # Run the test with timeout
    if timeout "${timeout_minutes}m" bash -c "$test_command" > "$test_output" 2>&1; then
        test_status=0
        log SUCCESS "$suite_name completed successfully"
    else
        test_status=$?
        if [ $test_status -eq 124 ]; then
            log ERROR "$suite_name timed out after ${timeout_minutes} minutes"
        else
            log ERROR "$suite_name failed with exit code $test_status"
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Generate test report
    generate_test_report "$suite_name" "$test_status" "$duration" "$test_output"
    
    return $test_status
}

# Function to generate test report
generate_test_report() {
    local suite_name=$1
    local status=$2
    local duration=$3
    local output_file=$4
    
    local report_file="${TEST_RESULTS_DIR}/${suite_name}-report.json"
    local status_text="failed"
    [ $status -eq 0 ] && status_text="passed"
    
    cat > "$report_file" << EOF
{
    "suite": "$suite_name",
    "status": "$status_text",
    "exit_code": $status,
    "duration_seconds": $duration,
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "output_file": "$output_file"
}
EOF
    
    log INFO "Report generated: $report_file"
}

# Function to run parallel tests
run_parallel_tests() {
    local -a test_pids=()
    local -a test_names=()
    local overall_status=0
    
    # Start NAT traversal tests
    log INFO "Starting parallel test execution..."
    
    # Test 1: Basic NAT scenarios
    (run_test_suite "basic-nat" "cargo test --test nat_traversal -- --ignored") &
    test_pids+=($!)
    test_names+=("basic-nat")
    
    # Test 2: Stress tests
    (run_test_suite "stress" "cargo test --test stress_tests -- --ignored --test-threads=1") &
    test_pids+=($!)
    test_names+=("stress")
    
    # Test 3: Cross-platform
    (run_test_suite "cross-platform" "cargo test --test cross_platform -- --ignored") &
    test_pids+=($!)
    test_names+=("cross-platform")
    
    # Wait for all tests to complete
    log INFO "Waiting for ${#test_pids[@]} parallel tests to complete..."
    
    for i in "${!test_pids[@]}"; do
        local pid=${test_pids[$i]}
        local name=${test_names[$i]}
        
        if wait $pid; then
            log SUCCESS "$name completed successfully"
        else
            log ERROR "$name failed"
            overall_status=1
        fi
    done
    
    return $overall_status
}

# Function to collect and merge results
merge_test_results() {
    local merged_file="${TEST_RESULTS_DIR}/merged-results.json"
    
    log INFO "Merging test results..."
    
    echo '{"test_runs": [' > "$merged_file"
    
    local first=true
    for report in "${TEST_RESULTS_DIR}"/*-report.json; do
        if [ -f "$report" ]; then
            if [ "$first" = true ]; then
                first=false
            else
                echo "," >> "$merged_file"
            fi
            cat "$report" >> "$merged_file"
        fi
    done
    
    echo ']}' >> "$merged_file"
    
    log SUCCESS "Results merged to: $merged_file"
}

# Function to generate summary
generate_summary() {
    local summary_file="${TEST_RESULTS_DIR}/test-summary.md"
    
    log INFO "Generating test summary..."
    
    cat > "$summary_file" << 'EOF'
# Test Execution Summary

## Overview
EOF
    
    echo "**Date**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "## Test Results" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "| Test Suite | Status | Duration | Details |" >> "$summary_file"
    echo "|------------|--------|----------|---------|" >> "$summary_file"
    
    for report in "${TEST_RESULTS_DIR}"/*-report.json; do
        if [ -f "$report" ]; then
            local suite=$(jq -r .suite "$report")
            local status=$(jq -r .status "$report")
            local duration=$(jq -r .duration_seconds "$report")
            local emoji="❌"
            [ "$status" = "passed" ] && emoji="✅"
            
            echo "| $suite | $emoji $status | ${duration}s | [View]($report) |" >> "$summary_file"
        fi
    done
    
    log SUCCESS "Summary generated: $summary_file"
    
    # Also output to GitHub Actions summary if available
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        cat "$summary_file" >> "$GITHUB_STEP_SUMMARY"
    fi
}

# Main execution
main() {
    local command=${1:-help}
    
    # Create results directory
    mkdir -p "$TEST_RESULTS_DIR"
    
    case $command in
        quick)
            log INFO "Running quick tests..."
            run_test_suite "quick" "cargo test --lib --bins" 5
            ;;
        
        standard)
            log INFO "Running standard tests..."
            run_test_suite "standard" "cargo test --all" 10
            ;;
        
        long)
            log INFO "Running long tests..."
            run_parallel_tests
            merge_test_results
            generate_summary
            ;;
        
        nat-scenario)
            local scenario=${2:-all}
            log INFO "Running NAT scenario: $scenario"
            run_test_suite "nat-$scenario" "cargo test --test nat_traversal -- --ignored $scenario" 30
            ;;
        
        clean)
            log INFO "Cleaning test results..."
            rm -rf "$TEST_RESULTS_DIR"
            log SUCCESS "Test results cleaned"
            ;;
        
        help|*)
            cat << 'HELP'
Test Orchestrator - Coordinate complex test scenarios

Usage: test-orchestrator.sh <command> [options]

Commands:
    quick       Run quick tests (<5 min)
    standard    Run standard test suite
    long        Run long-running tests in parallel
    nat-scenario <name>  Run specific NAT scenario
    clean       Clean test results
    help        Show this help message

Examples:
    ./test-orchestrator.sh quick
    ./test-orchestrator.sh nat-scenario symmetric
    ./test-orchestrator.sh long

HELP
            ;;
    esac
}

# Run main function
main "$@"