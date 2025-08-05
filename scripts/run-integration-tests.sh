#!/bin/bash

# Comprehensive integration test runner for ant-quic

set -euo pipefail

# Configuration
TEST_RESULTS_DIR="integration-test-results-$(date +%Y%m%d-%H%M%S)"
DOCKER_TESTS_ENABLED="${DOCKER_TESTS_ENABLED:-true}"
STRESS_TESTS_ENABLED="${STRESS_TESTS_ENABLED:-false}"
PARALLEL_EXECUTION="${PARALLEL_EXECUTION:-false}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

# Initialize test environment
init_test_env() {
    log "Initializing test environment"
    
    # Create results directory
    mkdir -p "$TEST_RESULTS_DIR"/{logs,reports,metrics}
    
    # Check prerequisites
    if ! command -v cargo &> /dev/null; then
        error "Cargo not found. Please install Rust."
        exit 1
    fi
    
    if [ "$DOCKER_TESTS_ENABLED" = "true" ]; then
        if ! command -v docker &> /dev/null; then
            warning "Docker not found. Disabling Docker tests."
            DOCKER_TESTS_ENABLED="false"
        elif ! docker info &> /dev/null; then
            warning "Docker daemon not running. Disabling Docker tests."
            DOCKER_TESTS_ENABLED="false"
        fi
    fi
    
    # Build test binaries
    log "Building test binaries"
    cargo build --release --all-features --tests
    cargo build --release --examples
    
    # Generate test metadata
    cat > "$TEST_RESULTS_DIR/metadata.json" << EOF
{
    "test_run_id": "$(uuidgen || echo "test-$(date +%s)")",
    "start_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "git_sha": "$(git rev-parse HEAD)",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD)",
    "rust_version": "$(rustc --version)",
    "platform": "$(uname -s)",
    "docker_enabled": $DOCKER_TESTS_ENABLED,
    "stress_tests_enabled": $STRESS_TESTS_ENABLED
}
EOF
}

# Run a single test with timeout and logging
run_test() {
    local test_name="$1"
    local test_command="$2"
    local timeout_seconds="${3:-300}"
    local test_type="${4:-unit}"
    
    ((TOTAL_TESTS++))
    
    info "Running $test_type test: $test_name"
    
    local test_log="$TEST_RESULTS_DIR/logs/${test_name}.log"
    local test_start=$(date +%s)
    
    # Run test with timeout
    if timeout "$timeout_seconds" bash -c "$test_command" > "$test_log" 2>&1; then
        local test_end=$(date +%s)
        local duration=$((test_end - test_start))
        
        log "✅ Test '$test_name' PASSED (${duration}s)"
        ((PASSED_TESTS++))
        
        # Record success
        echo "{\"test\": \"$test_name\", \"result\": \"passed\", \"duration\": $duration, \"type\": \"$test_type\"}" \
            >> "$TEST_RESULTS_DIR/results.jsonl"
    else
        local exit_code=$?
        local test_end=$(date +%s)
        local duration=$((test_end - test_start))
        
        if [ $exit_code -eq 124 ]; then
            error "❌ Test '$test_name' TIMED OUT after ${timeout_seconds}s"
        else
            error "❌ Test '$test_name' FAILED with exit code $exit_code (${duration}s)"
        fi
        
        ((FAILED_TESTS++))
        
        # Record failure
        echo "{\"test\": \"$test_name\", \"result\": \"failed\", \"duration\": $duration, \"exit_code\": $exit_code, \"type\": \"$test_type\"}" \
            >> "$TEST_RESULTS_DIR/results.jsonl"
        
        # Extract error summary
        tail -n 50 "$test_log" > "$TEST_RESULTS_DIR/logs/${test_name}_error.log"
    fi
}

# Run unit tests
run_unit_tests() {
    log "Running unit tests"
    
    # Basic unit tests
    run_test "unit_tests" "cargo test --release" 600 "unit"
    
    # Feature-specific tests
    run_test "pqc_tests" "cargo test --features 'pqc aws-lc-rs' pqc" 300 "unit"
    run_test "nat_traversal_tests" "cargo test nat_traversal" 300 "unit"
    run_test "frame_tests" "cargo test frame" 300 "unit"
}

# Run integration tests
run_integration_tests() {
    log "Running integration tests"
    
    # Core integration tests
    run_test "basic_p2p_network" \
        "cargo test --test integration_test_suite test_basic_p2p_network -- --nocapture" \
        300 "integration"
    
    run_test "nat_traversal_scenarios" \
        "cargo test --test integration_test_suite test_nat_traversal_scenarios -- --nocapture" \
        600 "integration"
    
    run_test "network_resilience" \
        "cargo test --test integration_test_suite test_network_resilience -- --nocapture" \
        300 "integration"
    
    run_test "message_broadcast" \
        "cargo test --test integration_test_suite test_message_broadcast -- --nocapture" \
        300 "integration"
    
    # Comprehensive NAT tests
    run_test "nat_comprehensive" \
        "cargo test --test nat_traversal_comprehensive -- --nocapture" \
        900 "integration"
}

# Run Docker-based tests
run_docker_tests() {
    if [ "$DOCKER_TESTS_ENABLED" != "true" ]; then
        warning "Docker tests disabled"
        return
    fi
    
    log "Running Docker-based integration tests"
    
    # Ensure Docker images are built
    log "Building Docker images"
    (cd docker && docker-compose build) || {
        error "Failed to build Docker images"
        return
    }
    
    # Run Docker NAT tests
    run_test "docker_nat_scenarios" \
        "cargo test --test integration_test_suite --features docker-tests test_docker_nat_scenarios -- --nocapture" \
        900 "docker"
    
    run_test "docker_network_partitions" \
        "cargo test --test integration_test_suite --features docker-tests test_docker_network_partitions -- --nocapture" \
        600 "docker"
    
    run_test "docker_latency_scenarios" \
        "cargo test --test integration_test_suite --features docker-tests test_docker_latency_scenarios -- --nocapture" \
        600 "docker"
    
    run_test "docker_scale_scenario" \
        "cargo test --test integration_test_suite --features docker-tests test_docker_scale_scenario -- --nocapture" \
        900 "docker"
    
    # Clean up Docker containers
    log "Cleaning up Docker containers"
    (cd docker && docker-compose down -v) || true
}

# Run stress tests
run_stress_tests() {
    if [ "$STRESS_TESTS_ENABLED" != "true" ]; then
        info "Stress tests disabled (enable with STRESS_TESTS_ENABLED=true)"
        return
    fi
    
    log "Running stress tests"
    
    run_test "high_load_scenario" \
        "cargo test --test integration_test_suite --features stress-tests test_high_load_scenario -- --nocapture" \
        1800 "stress"
    
    run_test "connection_churn" \
        "cargo test --test connection_lifecycle_tests stress -- --ignored --nocapture" \
        600 "stress"
}

# Run benchmarks as tests
run_benchmark_tests() {
    log "Running benchmark tests"
    
    # Quick benchmark runs to ensure they work
    run_test "throughput_bench" \
        "cargo bench --bench throughput_benchmarks -- --test" \
        300 "benchmark"
    
    run_test "latency_bench" \
        "cargo bench --bench latency_benchmarks -- --test" \
        300 "benchmark"
    
    run_test "nat_perf_bench" \
        "cargo bench --bench nat_traversal_performance -- --test" \
        300 "benchmark"
}

# Generate test report
generate_report() {
    log "Generating test report"
    
    local end_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local total_duration=$SECONDS
    
    # Create summary report
    cat > "$TEST_RESULTS_DIR/summary.md" << EOF
# Integration Test Report

## Summary
- **Total Tests**: $TOTAL_TESTS
- **Passed**: $PASSED_TESTS ✅
- **Failed**: $FAILED_TESTS ❌
- **Skipped**: $SKIPPED_TESTS ⏭️
- **Success Rate**: $(awk "BEGIN {printf \"%.2f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")%
- **Total Duration**: ${total_duration}s
- **End Time**: $end_time

## Test Results

EOF
    
    # Add detailed results
    echo "### Detailed Results" >> "$TEST_RESULTS_DIR/summary.md"
    echo "" >> "$TEST_RESULTS_DIR/summary.md"
    echo "| Test Name | Type | Result | Duration |" >> "$TEST_RESULTS_DIR/summary.md"
    echo "|-----------|------|--------|----------|" >> "$TEST_RESULTS_DIR/summary.md"
    
    # Parse results.jsonl and add to markdown
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            test_name=$(echo "$line" | jq -r '.test')
            test_type=$(echo "$line" | jq -r '.type')
            result=$(echo "$line" | jq -r '.result')
            duration=$(echo "$line" | jq -r '.duration')
            
            if [ "$result" = "passed" ]; then
                result_icon="✅"
            else
                result_icon="❌"
            fi
            
            echo "| $test_name | $test_type | $result_icon | ${duration}s |" >> "$TEST_RESULTS_DIR/summary.md"
        fi
    done < "$TEST_RESULTS_DIR/results.jsonl"
    
    # Add failed test details
    if [ $FAILED_TESTS -gt 0 ]; then
        echo "" >> "$TEST_RESULTS_DIR/summary.md"
        echo "### Failed Test Details" >> "$TEST_RESULTS_DIR/summary.md"
        echo "" >> "$TEST_RESULTS_DIR/summary.md"
        
        for error_log in "$TEST_RESULTS_DIR/logs"/*_error.log; do
            if [ -f "$error_log" ]; then
                test_name=$(basename "$error_log" _error.log)
                echo "#### $test_name" >> "$TEST_RESULTS_DIR/summary.md"
                echo '```' >> "$TEST_RESULTS_DIR/summary.md"
                cat "$error_log" >> "$TEST_RESULTS_DIR/summary.md"
                echo '```' >> "$TEST_RESULTS_DIR/summary.md"
                echo "" >> "$TEST_RESULTS_DIR/summary.md"
            fi
        done
    fi
    
    # Create JSON summary
    cat > "$TEST_RESULTS_DIR/summary.json" << EOF
{
    "total_tests": $TOTAL_TESTS,
    "passed": $PASSED_TESTS,
    "failed": $FAILED_TESTS,
    "skipped": $SKIPPED_TESTS,
    "success_rate": $(awk "BEGIN {print ($PASSED_TESTS/$TOTAL_TESTS)}"),
    "duration_seconds": $total_duration,
    "end_time": "$end_time"
}
EOF
    
    # Display summary
    log "Test Summary:"
    cat "$TEST_RESULTS_DIR/summary.md"
}

# Main test execution
main() {
    log "Starting ant-quic integration test suite"
    
    # Initialize environment
    init_test_env
    
    # Run test suites
    if [ "$PARALLEL_EXECUTION" = "true" ]; then
        log "Running tests in parallel"
        
        run_unit_tests &
        PID_UNIT=$!
        
        run_integration_tests &
        PID_INTEGRATION=$!
        
        run_docker_tests &
        PID_DOCKER=$!
        
        # Wait for all to complete
        wait $PID_UNIT
        wait $PID_INTEGRATION
        wait $PID_DOCKER
        
        run_stress_tests
        run_benchmark_tests
    else
        log "Running tests sequentially"
        
        run_unit_tests
        run_integration_tests
        run_docker_tests
        run_stress_tests
        run_benchmark_tests
    fi
    
    # Generate report
    generate_report
    
    # Archive results if in CI
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        log "Archiving test results for CI"
        tar -czf "integration-test-results.tar.gz" "$TEST_RESULTS_DIR"
        echo "::set-output name=results::integration-test-results.tar.gz"
        echo "::set-output name=summary::$TEST_RESULTS_DIR/summary.json"
    fi
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -eq 0 ]; then
        log "All tests passed! 🎉"
        exit 0
    else
        error "$FAILED_TESTS tests failed"
        exit 1
    fi
}

# Handle interrupts
trap 'error "Test run interrupted"; generate_report; exit 130' INT TERM

# Run main function
main "$@"