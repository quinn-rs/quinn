#!/bin/bash
#
# Test Coverage Report Generator for ant-quic
#
# This script generates comprehensive test coverage reports using cargo-tarpaulin
# or cargo-llvm-cov depending on platform and availability.
#
# Usage:
#   ./scripts/coverage.sh [options]
#
# Options:
#   --html      Generate HTML report (default)
#   --json      Generate JSON report
#   --lcov      Generate LCOV report
#   --xml       Generate Cobertura XML report
#   --all       Generate all report formats
#   --open      Open HTML report after generation
#   --ci        CI mode (fail if below threshold)
#   --verbose   Show detailed output

set -euo pipefail

# Configuration
COVERAGE_DIR="coverage"
THRESHOLD=80
EXCLUDE_PATTERNS="--exclude-files */tests/* --exclude-files */examples/* --exclude-files */benches/*"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
HTML=true
JSON=false
LCOV=false
XML=false
OPEN=false
CI_MODE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --html) HTML=true; shift ;;
        --json) JSON=true; HTML=false; shift ;;
        --lcov) LCOV=true; HTML=false; shift ;;
        --xml) XML=true; HTML=false; shift ;;
        --all) HTML=true; JSON=true; LCOV=true; XML=true; shift ;;
        --open) OPEN=true; shift ;;
        --ci) CI_MODE=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check for coverage tool
if command -v cargo-tarpaulin &> /dev/null; then
    TOOL="tarpaulin"
    echo "Using cargo-tarpaulin for coverage analysis"
elif command -v cargo-llvm-cov &> /dev/null; then
    TOOL="llvm-cov"
    echo "Using cargo-llvm-cov for coverage analysis"
else
    echo -e "${RED}Error: No coverage tool found!${NC}"
    echo "Install one of the following:"
    echo "  cargo install cargo-tarpaulin"
    echo "  cargo install cargo-llvm-cov"
    exit 1
fi

# Create coverage directory
mkdir -p "$COVERAGE_DIR"

# Clean previous coverage data
echo "Cleaning previous coverage data..."
rm -rf "$COVERAGE_DIR"/*

# Run coverage based on tool
if [ "$TOOL" = "tarpaulin" ]; then
    echo "Running tests with coverage..."
    
    # Build output formats
    OUTPUT_FORMATS=""
    if [ "$HTML" = true ]; then OUTPUT_FORMATS="$OUTPUT_FORMATS --out Html"; fi
    if [ "$JSON" = true ]; then OUTPUT_FORMATS="$OUTPUT_FORMATS --out Json"; fi
    if [ "$LCOV" = true ]; then OUTPUT_FORMATS="$OUTPUT_FORMATS --out Lcov"; fi
    if [ "$XML" = true ]; then OUTPUT_FORMATS="$OUTPUT_FORMATS --out Xml"; fi
    
    # Run tarpaulin
    TARPAULIN_CMD="cargo tarpaulin $OUTPUT_FORMATS --output-dir $COVERAGE_DIR $EXCLUDE_PATTERNS"
    
    if [ "$VERBOSE" = true ]; then
        TARPAULIN_CMD="$TARPAULIN_CMD --verbose"
    fi
    
    if [ "$CI_MODE" = true ]; then
        TARPAULIN_CMD="$TARPAULIN_CMD --fail-under $THRESHOLD"
    fi
    
    # Execute coverage
    eval $TARPAULIN_CMD
    
elif [ "$TOOL" = "llvm-cov" ]; then
    echo "Running tests with LLVM coverage..."
    
    # Clean and run tests
    cargo llvm-cov clean
    
    # Run based on output format
    if [ "$HTML" = true ]; then
        cargo llvm-cov --html --output-dir "$COVERAGE_DIR"
    fi
    
    if [ "$JSON" = true ]; then
        cargo llvm-cov --json --output-path "$COVERAGE_DIR/coverage.json"
    fi
    
    if [ "$LCOV" = true ]; then
        cargo llvm-cov --lcov --output-path "$COVERAGE_DIR/lcov.info"
    fi
    
    if [ "$XML" = true ]; then
        echo "Warning: cargo-llvm-cov doesn't support Cobertura XML directly"
    fi
fi

# Parse coverage percentage
if [ -f "$COVERAGE_DIR/tarpaulin-report.json" ]; then
    COVERAGE=$(jq '.coverage' "$COVERAGE_DIR/tarpaulin-report.json" 2>/dev/null || echo "0")
elif [ -f "$COVERAGE_DIR/coverage.json" ]; then
    COVERAGE=$(jq '.data[0].totals.lines.percent' "$COVERAGE_DIR/coverage.json" 2>/dev/null || echo "0")
else
    COVERAGE="unknown"
fi

# Display results
echo ""
echo "=================================="
echo "Test Coverage Report"
echo "=================================="
echo ""

if [ "$COVERAGE" != "unknown" ]; then
    COVERAGE_INT=$(echo "$COVERAGE" | cut -d. -f1)
    
    if [ "$COVERAGE_INT" -ge "$THRESHOLD" ]; then
        echo -e "Total Coverage: ${GREEN}${COVERAGE}%${NC} ✓"
    else
        echo -e "Total Coverage: ${RED}${COVERAGE}%${NC} ✗"
    fi
    
    echo "Threshold: $THRESHOLD%"
    echo ""
    
    # Show uncovered files if verbose
    if [ "$VERBOSE" = true ] && [ -f "$COVERAGE_DIR/tarpaulin-report.json" ]; then
        echo "Files with low coverage:"
        jq -r '.files[] | select(.coverage < 50) | "\(.path): \(.coverage)%"' "$COVERAGE_DIR/tarpaulin-report.json" 2>/dev/null || true
    fi
    
    # CI mode - fail if below threshold
    if [ "$CI_MODE" = true ] && [ "$COVERAGE_INT" -lt "$THRESHOLD" ]; then
        echo -e "${RED}Coverage is below threshold!${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Coverage percentage could not be determined${NC}"
fi

echo ""
echo "Reports generated in: $COVERAGE_DIR/"
ls -la "$COVERAGE_DIR"

# Open HTML report if requested
if [ "$OPEN" = true ] && [ "$HTML" = true ]; then
    if [ -f "$COVERAGE_DIR/tarpaulin-report.html" ]; then
        open "$COVERAGE_DIR/tarpaulin-report.html" 2>/dev/null || xdg-open "$COVERAGE_DIR/tarpaulin-report.html" 2>/dev/null || echo "Please open $COVERAGE_DIR/tarpaulin-report.html manually"
    elif [ -f "$COVERAGE_DIR/html/index.html" ]; then
        open "$COVERAGE_DIR/html/index.html" 2>/dev/null || xdg-open "$COVERAGE_DIR/html/index.html" 2>/dev/null || echo "Please open $COVERAGE_DIR/html/index.html manually"
    fi
fi

# Generate coverage badge
if command -v coverage-badge &> /dev/null && [ "$COVERAGE" != "unknown" ]; then
    echo ""
    echo "Generating coverage badge..."
    coverage-badge -f -o "$COVERAGE_DIR/coverage-badge.svg" "$COVERAGE"
    echo "Badge saved to: $COVERAGE_DIR/coverage-badge.svg"
fi

echo ""
echo "Coverage analysis complete!"