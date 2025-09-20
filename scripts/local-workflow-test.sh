#!/bin/bash

# ANT-QUIC Local Workflow Testing Script
# Comprehensive validation of GitHub workflows using act

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_DIR/workflow-test-$(date +%Y%m%d-%H%M%S).log"

# Function to log messages
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to log success
success() {
    echo -e "${GREEN}✅ $1${NC}" | tee -a "$LOG_FILE"
}

# Function to log warning
warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" | tee -a "$LOG_FILE"
}

# Function to log error
error() {
    echo -e "${RED}❌ $1${NC}" | tee -a "$LOG_FILE"
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if act is installed
    if ! command -v act &> /dev/null; then
        error "act is not installed. Please install it: brew install act"
        exit 1
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker Desktop"
        exit 1
    fi

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_DIR/Cargo.toml" ]]; then
        error "Not in ANT-QUIC project directory"
        exit 1
    fi

    success "Prerequisites check passed"
}

# Function to test quick-checks workflow
test_quick_checks() {
    log "Testing Quick Checks workflow..."

    # Run the key jobs from quick-checks workflow
    if act -W .github/workflows/quick-checks.yml -j lint --platform macos-latest && \
       act -W .github/workflows/quick-checks.yml -j check --platform macos-latest && \
       act -W .github/workflows/quick-checks.yml -j dependencies --platform macos-latest; then
        success "Quick Checks workflow completed successfully"
        return 0
    else
        error "Quick Checks workflow failed"
        return 1
    fi
}

# Function to test CI consolidated workflow
test_ci_consolidated() {
    log "Testing CI Consolidated workflow..."

    # Run the key jobs from CI consolidated workflow
    if act -W .github/workflows/ci-consolidated.yml -j quick-checks --platform macos-latest && \
       act -W .github/workflows/ci-consolidated.yml -j test --platform macos-latest; then
        success "CI Consolidated workflow completed successfully"
        return 0
    else
        error "CI Consolidated workflow failed"
        return 1
    fi
}

# Function to test Docker NAT tests (not compatible with act)
test_docker_nat() {
    log "Testing Docker NAT Tests workflow..."

    warning "Docker NAT Tests workflow is NOT compatible with act"
    warning "This workflow requires Docker-in-Docker support"
    warning "Skipping Docker NAT tests - run manually with: ./scripts/test_nat_traversal.sh"

    # Don't attempt to run with act - it will fail
    warning "Docker NAT Tests workflow cannot be tested locally with act"
    return 0  # Don't fail overall test for this
}

# Function to run all tests
run_all_tests() {
    log "Starting comprehensive workflow testing..."

    local test_results=()
    local overall_success=true

    # Test Quick Checks
    if test_quick_checks; then
        test_results+=("✅ Quick Checks: PASSED")
    else
        test_results+=("❌ Quick Checks: FAILED")
        overall_success=false
    fi

    echo "" | tee -a "$LOG_FILE"

    # Test CI Consolidated
    if test_ci_consolidated; then
        test_results+=("✅ CI Consolidated: PASSED")
    else
        test_results+=("❌ CI Consolidated: FAILED")
        overall_success=false
    fi

    echo "" | tee -a "$LOG_FILE"

    # Test Docker NAT Tests
    if test_docker_nat; then
        test_results+=("❌ Docker NAT Tests: NOT COMPATIBLE (requires DinD)")
    else
        test_results+=("❌ Docker NAT Tests: NOT COMPATIBLE (requires DinD)")
    fi

    # Print summary
    echo "" | tee -a "$LOG_FILE"
    log "=== TEST SUMMARY ==="

    for result in "${test_results[@]}"; do
        echo -e "$result" | tee -a "$LOG_FILE"
    done

    echo "" | tee -a "$LOG_FILE"

    if [ "$overall_success" = true ]; then
        success "All compatible workflows passed! 🎉"
        log "Log file saved to: $LOG_FILE"
        return 0
    else
        error "Some workflows failed. Check the log for details."
        log "Log file saved to: $LOG_FILE"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "ANT-QUIC Local Workflow Testing Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -q, --quick         Run only quick-checks workflow"
    echo "  -c, --ci            Run only CI consolidated workflow"
    echo "  -d, --docker        Run only Docker NAT tests workflow"
    echo "  -a, --all           Run all workflows (default)"
    echo "  -l, --list          List available workflows"
    echo ""
    echo "Examples:"
    echo "  $0                  # Run all workflows"
    echo "  $0 --quick          # Run only quick checks"
    echo "  $0 --ci             # Run only CI consolidated"
    echo "  $0 --docker         # Run only Docker NAT tests"
}

# Function to list workflows
list_workflows() {
    echo "Available workflows for local testing:"
    echo ""
    echo "✅ Quick Checks (.github/workflows/quick-checks.yml)"
    echo "   - Fast validation of code quality and formatting"
    echo "   - Runtime: ~2-3 minutes"
    echo "   - Fully compatible with act"
    echo ""
    echo "✅ CI Consolidated (.github/workflows/ci-consolidated.yml)"
    echo "   - Comprehensive testing suite"
    echo "   - Runtime: ~10-15 minutes"
    echo "   - Fully compatible with act"
    echo ""
echo "❌ Docker NAT Tests (.github/workflows/docker-nat-tests.yml)"
echo "   - NAT traversal testing with Docker"
echo "   - Runtime: ~5-10 minutes"
echo "   - NOT compatible with act (requires Docker-in-Docker)"
}

# Main script logic
main() {
    cd "$PROJECT_DIR"

    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -l|--list)
            list_workflows
            exit 0
            ;;
        -q|--quick)
            check_prerequisites
            test_quick_checks
            ;;
        -c|--ci)
            check_prerequisites
            test_ci_consolidated
            ;;
        -d|--docker)
            check_prerequisites
            test_docker_nat
            ;;
        -a|--all|"")
            check_prerequisites
            run_all_tests
            ;;
        *)
            error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"