#!/bin/bash
# Long test management script for ant-quic CI/CD

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LONG_TEST_THRESHOLD=300  # 5 minutes in seconds
TEST_CATEGORIES=(
    "stress"
    "performance"
    "nat-comprehensive"
    "integration"
    "docker-nat"
)

# Function to categorize tests by duration
categorize_tests() {
    local test_dir="$1"
    local output_file="$2"
    
    echo "Analyzing test durations in $test_dir..."
    
    # Create categorization file
    cat > "$output_file" << EOF
# Test Categorization Report
# Generated: $(date)
# Threshold: ${LONG_TEST_THRESHOLD}s ($(($LONG_TEST_THRESHOLD / 60))m)

## Quick Tests (<30s)
EOF
    
    # Find and time tests
    cargo test --list 2>/dev/null | grep -E "^test " | while read -r test_name; do
        # Estimate test duration (would need actual timing in practice)
        if [[ "$test_name" =~ stress|comprehensive|integration ]]; then
            echo "$test_name" >> "${output_file}.long"
        else
            echo "$test_name" >> "${output_file}.quick"
        fi
    done
    
    # Append categorized tests
    echo "" >> "$output_file"
    echo "## Standard Tests (30s-5m)" >> "$output_file"
    # Add standard tests here
    
    echo "" >> "$output_file"
    echo "## Long Tests (>5m)" >> "$output_file"
    if [ -f "${output_file}.long" ]; then
        cat "${output_file}.long" >> "$output_file"
        rm "${output_file}.long"
    fi
    
    if [ -f "${output_file}.quick" ]; then
        rm "${output_file}.quick"
    fi
}

# Function to run specific test category
run_test_category() {
    local category="$1"
    local intensity="${2:-normal}"
    
    echo -e "${GREEN}Running $category tests with $intensity intensity...${NC}"
    
    case "$category" in
        stress)
            run_stress_tests "$intensity"
            ;;
        performance)
            run_performance_tests "$intensity"
            ;;
        nat-comprehensive)
            run_nat_comprehensive_tests "$intensity"
            ;;
        integration)
            run_integration_tests "$intensity"
            ;;
        docker-nat)
            run_docker_nat_tests "$intensity"
            ;;
        *)
            echo -e "${RED}Unknown test category: $category${NC}"
            exit 1
            ;;
    esac
}

# Stress test runner
run_stress_tests() {
    local intensity="$1"
    local connections=100
    local duration=300
    
    case "$intensity" in
        quick)
            connections=50
            duration=60
            ;;
        thorough)
            connections=1000
            duration=1800
            ;;
    esac
    
    echo "Stress test configuration:"
    echo "  Connections: $connections"
    echo "  Duration: ${duration}s"
    
    # Create stress test binary if needed
    cargo build --release --features stress-test
    
    # Run stress tests
    STRESS_CONNECTIONS=$connections \
    STRESS_DURATION=$duration \
    cargo test --release stress_ -- --test-threads=1 --nocapture
}

# Performance test runner
run_performance_tests() {
    local intensity="$1"
    local iterations=10
    local warmup=5
    local measurement=30
    
    case "$intensity" in
        quick)
            iterations=3
            warmup=2
            measurement=10
            ;;
        thorough)
            iterations=100
            warmup=10
            measurement=120
            ;;
    esac
    
    echo "Performance test configuration:"
    echo "  Iterations: $iterations"
    echo "  Warmup: ${warmup}s"
    echo "  Measurement: ${measurement}s"
    
    # Run benchmarks
    cargo bench -- \
        --warm-up-time $warmup \
        --measurement-time $measurement \
        --sample-size $iterations
}

# NAT comprehensive test runner
run_nat_comprehensive_tests() {
    local intensity="$1"
    
    echo "Running comprehensive NAT traversal tests..."
    
    # Build with test features
    cargo build --release --features test-utils
    
    # Run NAT scenario tests
    cargo test --release --test nat_traversal_scenarios -- --test-threads=1
    cargo test --release --test nat_traversal_simulation -- --test-threads=1
}

# Integration test runner
run_integration_tests() {
    local intensity="$1"
    
    echo "Running integration tests..."
    
    # Large integration tests
    local tests=(
        "p2p_integration_tests"
        "auth_comprehensive_tests"
        "relay_queue_tests"
    )
    
    for test in "${tests[@]}"; do
        echo -e "${YELLOW}Running $test...${NC}"
        cargo test --release --test "$test" -- --test-threads=1 --nocapture || {
            echo -e "${RED}$test failed!${NC}"
            return 1
        }
    done
}

# Docker NAT test runner
run_docker_nat_tests() {
    local intensity="$1"
    
    echo "Running Docker-based NAT tests..."
    
    # Check Docker availability
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not available!${NC}"
        return 1
    fi
    
    # Build and run Docker tests
    cd docker
    docker-compose build
    docker-compose up -d
    
    # Wait for containers
    sleep 10
    
    # Run tests through Docker
    local nat_types=("fullcone" "restricted" "port-restricted" "symmetric")
    for nat_type in "${nat_types[@]}"; do
        echo "Testing $nat_type NAT..."
        docker exec "nat-$nat_type" cargo test nat_docker -- "$nat_type"
    done
    
    # Cleanup
    docker-compose down
    cd ..
}

# Monitor resource usage during tests
monitor_resources() {
    local output_file="$1"
    local pid="$2"
    
    echo "Monitoring resources for PID $pid..."
    
    while kill -0 "$pid" 2>/dev/null; do
        {
            echo "=== $(date) ==="
            ps aux | grep -E "PID|$pid" | grep -v grep
            echo ""
            free -m
            echo ""
            ss -tan | grep ESTAB | wc -l
            echo "---"
        } >> "$output_file"
        sleep 30
    done
}

# Generate test report
generate_report() {
    local test_category="$1"
    local start_time="$2"
    local end_time="$3"
    local log_file="$4"
    
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    cat > "test-report-${test_category}.md" << EOF
# Long Test Report: $test_category

**Date**: $(date)  
**Duration**: ${minutes}m ${seconds}s  
**Status**: $(grep -q "FAILED" "$log_file" && echo "FAILED" || echo "PASSED")

## Test Summary

$(grep -E "test result:|running .* test" "$log_file" || echo "No test summary found")

## Test Details

\`\`\`
$(tail -50 "$log_file")
\`\`\`

## Resource Usage

$(grep -A5 "Peak" resource-monitor.log 2>/dev/null || echo "No resource data")

EOF
}

# Main function
main() {
    local action="${1:-help}"
    
    case "$action" in
        categorize)
            categorize_tests "." "test-categories.md"
            ;;
        run)
            local category="${2:-all}"
            local intensity="${3:-normal}"
            
            if [ "$category" = "all" ]; then
                for cat in "${TEST_CATEGORIES[@]}"; do
                    run_test_category "$cat" "$intensity"
                done
            else
                run_test_category "$category" "$intensity"
            fi
            ;;
        monitor)
            local pid="${2:-$$}"
            monitor_resources "resource-monitor.log" "$pid" &
            ;;
        report)
            local category="${2:-unknown}"
            local start="${3:-0}"
            local end="${4:-$(date +%s)}"
            local log="${5:-test.log}"
            generate_report "$category" "$start" "$end" "$log"
            ;;
        help|*)
            cat << EOF
Long Test Manager for ant-quic

Usage: $0 <action> [options]

Actions:
  categorize              - Analyze and categorize tests by duration
  run <category> [level]  - Run specific test category
  monitor <pid>          - Monitor resource usage for a process
  report <cat> <s> <e> <log> - Generate test report

Test Categories:
  - stress              - Connection stress tests
  - performance         - Performance benchmarks
  - nat-comprehensive   - Comprehensive NAT testing
  - integration         - Large integration tests
  - docker-nat          - Docker-based NAT simulation
  - all                 - Run all categories

Intensity Levels:
  - quick      - Reduced test parameters (5-15 min)
  - normal     - Standard parameters (15-60 min)
  - thorough   - Extended parameters (60+ min)

Examples:
  $0 categorize
  $0 run stress quick
  $0 run all normal
  $0 monitor \$\$
  $0 report stress 0 3600 stress.log
EOF
            ;;
    esac
}

# Run main function
main "$@"