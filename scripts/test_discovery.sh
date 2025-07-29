#!/bin/bash
# Test Discovery Script for ant-quic
# This script discovers and categorizes all tests in the project

set -euo pipefail

echo "=== ANT-QUIC Test Discovery Report ==="
echo "Generated at: $(date)"
echo ""

# Create output directory
mkdir -p target/test-discovery

# Function to count tests in a file
count_tests_in_file() {
    local file=$1
    grep -c "#\[test\]" "$file" 2>/dev/null || echo 0
}

# Function to check if test is ignored
count_ignored_tests() {
    local file=$1
    grep -c "#\[ignore\]" "$file" 2>/dev/null || echo 0
}

echo "## Unit Tests (in src/)"
echo "---"
unit_test_count=0
unit_test_files=0
for file in $(find src -name "*.rs" -type f | sort); do
    test_count=$(count_tests_in_file "$file")
    if [ "$test_count" -gt 0 ]; then
        ignored_count=$(count_ignored_tests "$file")
        echo "$file: $test_count tests ($ignored_count ignored)"
        ((unit_test_count += test_count))
        ((unit_test_files += 1))
    fi
done
echo "Total unit tests: $unit_test_count in $unit_test_files files"
echo ""

echo "## Integration Tests (in tests/)"
echo "---"
integration_test_files=$(find tests -name "*.rs" -type f | grep -v "mod.rs" | sort)
integration_test_count=0
for file in $integration_test_files; do
    if [[ -f "$file" ]]; then
        test_count=$(count_tests_in_file "$file")
        ignored_count=$(count_ignored_tests "$file")
        echo "$file: $test_count tests ($ignored_count ignored)"
        ((integration_test_count += test_count))
    fi
done
echo "Total integration test files: $(echo "$integration_test_files" | wc -l)"
echo ""

echo "## Benchmark Files (in benches/)"
echo "---"
if [ -d "benches" ]; then
    bench_files=$(find benches -name "*.rs" -type f | sort)
    for file in $bench_files; do
        echo "$file"
    done
    echo "Total benchmark files: $(echo "$bench_files" | wc -l)"
else
    echo "No benches directory found"
fi
echo ""

echo "## Ignored Tests"
echo "---"
ignored_files=$(find . -name "*.rs" -exec grep -l "#\[ignore\]" {} \; | sort)
total_ignored=0
for file in $ignored_files; do
    ignored_count=$(count_ignored_tests "$file")
    if [ "$ignored_count" -gt 0 ]; then
        echo "$file: $ignored_count ignored tests"
        ((total_ignored += ignored_count))
    fi
done
echo "Total ignored tests: $total_ignored"
echo ""

echo "## Test Categories"
echo "---"
echo "### Stress Tests"
find . -name "*.rs" -exec grep -l "stress" {} \; | grep -E "(test|tests)" | sort || echo "No stress tests found"

echo ""
echo "### NAT Traversal Tests"
find . -name "*.rs" -exec grep -l "nat_traversal\|nat" {} \; | grep -E "(test|tests)" | sort | head -20

echo ""
echo "### PQC Tests"
find . -name "*.rs" -exec grep -l "pqc\|ml_kem\|ml_dsa" {} \; | grep -E "(test|tests)" | sort || echo "No PQC tests found"

echo ""
echo "### Docker Tests"
find . -name "*.rs" -exec grep -l "docker" {} \; | grep -E "(test|tests)" | sort || echo "No Docker tests found"

echo ""
echo "## Feature-specific Tests"
echo "---"
echo "Checking for feature-gated tests..."
grep -r "#\[cfg(feature" src tests --include="*.rs" | grep -i test | head -10 || echo "No feature-gated tests found"

echo ""
echo "## Platform-specific Tests"
echo "---"
echo "### Unix-specific"
grep -r "#\[cfg(unix)\]\|#\[cfg(target_os = \"linux\")\]" src tests --include="*.rs" | grep -B1 -A1 test | head -10 || echo "None found"

echo "### Windows-specific"
grep -r "#\[cfg(windows)\]\|#\[cfg(target_os = \"windows\")\]" src tests --include="*.rs" | grep -B1 -A1 test | head -10 || echo "None found"

echo ""
echo "## Test Organization Summary"
echo "---"
echo "- Standard tests: tests/standard/"
echo "- Quick tests: tests/quick/"
echo "- Long/stress tests: tests/long/"
echo "- Property tests: tests/property_tests.disabled/"
echo "- Interop tests: tests/interop/"
echo "- Discovery tests: tests/discovery/"

# Save summary to file
{
    echo "# Test Discovery Summary"
    echo "Generated: $(date)"
    echo ""
    echo "## Counts"
    echo "- Unit tests: $unit_test_count"
    echo "- Integration test files: $(echo "$integration_test_files" | wc -l)"
    echo "- Ignored tests: $total_ignored"
    echo "- Benchmark files: $(find benches -name "*.rs" 2>/dev/null | wc -l || echo 0)"
} > target/test-discovery/summary.md

echo ""
echo "Summary saved to: target/test-discovery/summary.md"