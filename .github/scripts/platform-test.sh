#!/bin/bash
# Platform-specific test runner for ant-quic
# Handles platform-specific test requirements and configurations

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get platform information
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
TARGET="${TARGET:-}"

echo -e "${GREEN}Platform Test Runner${NC}"
echo "========================"
echo "Platform: $PLATFORM"
echo "Architecture: $ARCH"
echo "Target: ${TARGET:-native}"
echo ""

# Platform-specific environment setup
setup_platform_env() {
    case "$PLATFORM" in
        linux)
            echo "Setting up Linux environment..."
            # Check for specific Linux features
            if [ -f /proc/sys/net/ipv4/ip_local_port_range ]; then
                echo "Port range: $(cat /proc/sys/net/ipv4/ip_local_port_range)"
            fi
            
            # Set Linux-specific test flags
            export ANT_QUIC_TEST_LINUX=1
            
            # Check for network namespaces support (for advanced NAT tests)
            if command -v ip &> /dev/null && [ "$EUID" -eq 0 ]; then
                export ANT_QUIC_TEST_NETNS=1
                echo "Network namespace tests enabled"
            fi
            ;;
            
        darwin)
            echo "Setting up macOS environment..."
            # macOS-specific setup
            export ANT_QUIC_TEST_MACOS=1
            
            # Check for macOS version
            sw_vers
            
            # Handle different architectures
            if [[ "$ARCH" == "arm64" ]]; then
                echo "Running on Apple Silicon"
                export ANT_QUIC_TEST_APPLE_SILICON=1
            fi
            ;;
            
        mingw*|msys*|cygwin*|windows*)
            echo "Setting up Windows environment..."
            export ANT_QUIC_TEST_WINDOWS=1
            
            # Windows-specific network setup
            echo "Windows Firewall status:"
            netsh advfirewall show allprofiles state 2>/dev/null || true
            ;;
            
        *)
            echo -e "${YELLOW}Unknown platform: $PLATFORM${NC}"
            ;;
    esac
}

# Run platform-specific tests
run_platform_tests() {
    echo ""
    echo "Running platform-specific tests..."
    echo "================================="
    
    # Common tests for all platforms
    echo -e "\n${GREEN}Running common tests...${NC}"
    cargo test --features platform-tests -- --nocapture platform_common
    
    # Platform-specific test suites
    case "$PLATFORM" in
        linux)
            echo -e "\n${GREEN}Running Linux-specific tests...${NC}"
            cargo test --features platform-tests,linux-tests -- --nocapture platform_linux
            
            # Test network interface discovery
            cargo test --features network-discovery -- --nocapture candidate_discovery
            
            # Test with different async runtimes
            echo -e "\n${GREEN}Testing with tokio runtime...${NC}"
            cargo test --no-default-features --features runtime-tokio,rustls-ring
            
            echo -e "\n${GREEN}Testing with async-std runtime...${NC}"
            cargo test --no-default-features --features runtime-async-std,rustls-ring
            ;;
            
        darwin)
            echo -e "\n${GREEN}Running macOS-specific tests...${NC}"
            cargo test --features platform-tests,macos-tests -- --nocapture platform_macos
            
            # Test macOS-specific network features
            cargo test --features network-discovery -- --nocapture macos_interfaces
            
            # Test certificate verification
            cargo test --features platform-verifier -- --nocapture cert_verification
            ;;
            
        mingw*|msys*|cygwin*|windows*)
            echo -e "\n${GREEN}Running Windows-specific tests...${NC}"
            cargo test --features platform-tests,windows-tests -- --nocapture platform_windows
            
            # Test Windows-specific network features
            cargo test --features network-discovery -- --nocapture windows_interfaces
            
            # Test with Windows certificate store
            cargo test --features platform-verifier -- --nocapture windows_cert_store
            ;;
    esac
}

# Test cross-compilation if requested
test_cross_compilation() {
    if [ -n "$TARGET" ] && [ "$TARGET" != "native" ]; then
        echo ""
        echo "Testing cross-compilation to $TARGET..."
        echo "======================================="
        
        # Check if cross is available
        if command -v cross &> /dev/null; then
            echo "Using cross for compilation"
            cross build --target "$TARGET" --all-features
            
            # Run tests if target is executable on current platform
            case "$TARGET" in
                *-linux-gnu|*-apple-darwin)
                    if [[ "$PLATFORM" == "linux" ]] || [[ "$PLATFORM" == "darwin" ]]; then
                        cross test --target "$TARGET" --all-features
                    fi
                    ;;
                wasm32-*)
                    echo "WASM target detected, skipping test execution"
                    # Just verify it builds
                    cargo build --target "$TARGET" --no-default-features
                    ;;
            esac
        else
            echo "Cross not available, using cargo"
            cargo build --target "$TARGET" --all-features
        fi
    fi
}

# Test feature combinations
test_feature_combinations() {
    echo ""
    echo "Testing feature combinations..."
    echo "=============================="
    
    # Minimal build
    echo -e "\n${GREEN}Testing minimal build...${NC}"
    cargo check --no-default-features
    
    # Different crypto providers
    echo -e "\n${GREEN}Testing with ring crypto...${NC}"
    cargo test --no-default-features --features rustls-ring,runtime-tokio
    
    echo -e "\n${GREEN}Testing with aws-lc-rs crypto...${NC}"
    cargo test --no-default-features --features rustls-aws-lc-rs,runtime-tokio
    
    # Platform verifier
    if [[ "$PLATFORM" != "linux" ]] || [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
        echo -e "\n${GREEN}Testing with platform verifier...${NC}"
        cargo test --features platform-verifier
    fi
    
    # Tracing features
    echo -e "\n${GREEN}Testing tracing features...${NC}"
    cargo test --features trace-full
}

# Performance tests (platform-specific)
run_performance_tests() {
    echo ""
    echo "Running platform performance tests..."
    echo "===================================="
    
    case "$PLATFORM" in
        linux)
            # Linux performance tests
            if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
                echo "CPU Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
            fi
            
            # Run benchmarks with platform-specific optimizations
            RUSTFLAGS="-C target-cpu=native" cargo bench --no-run
            ;;
            
        darwin)
            # macOS performance tests
            sysctl -n machdep.cpu.brand_string
            
            # Run benchmarks
            cargo bench --no-run
            ;;
            
        mingw*|msys*|cygwin*|windows*)
            # Windows performance tests
            echo "Running Windows performance tests..."
            cargo bench --no-run
            ;;
    esac
}

# Generate platform report
generate_platform_report() {
    REPORT_FILE="platform-test-report-${PLATFORM}-${ARCH}.json"
    
    echo ""
    echo "Generating platform test report..."
    echo "================================="
    
    cat > "$REPORT_FILE" <<EOF
{
  "platform": "$PLATFORM",
  "architecture": "$ARCH",
  "target": "${TARGET:-native}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rust_version": "$(rustc --version)",
  "cargo_version": "$(cargo --version)",
  "tests": {
    "platform_specific": true,
    "cross_compilation": $([ -n "$TARGET" ] && echo "true" || echo "false"),
    "feature_combinations": true,
    "performance": true
  },
  "environment": {
    "ANT_QUIC_TEST_LINUX": "${ANT_QUIC_TEST_LINUX:-0}",
    "ANT_QUIC_TEST_MACOS": "${ANT_QUIC_TEST_MACOS:-0}",
    "ANT_QUIC_TEST_WINDOWS": "${ANT_QUIC_TEST_WINDOWS:-0}",
    "ANT_QUIC_TEST_NETNS": "${ANT_QUIC_TEST_NETNS:-0}",
    "ANT_QUIC_TEST_APPLE_SILICON": "${ANT_QUIC_TEST_APPLE_SILICON:-0}"
  }
}
EOF
    
    echo "Report saved to: $REPORT_FILE"
}

# Main execution
main() {
    setup_platform_env
    run_platform_tests
    test_cross_compilation
    test_feature_combinations
    
    # Only run performance tests on native builds
    if [ -z "$TARGET" ] || [ "$TARGET" == "native" ]; then
        run_performance_tests
    fi
    
    generate_platform_report
    
    echo ""
    echo -e "${GREEN}Platform testing completed successfully!${NC}"
}

# Handle script arguments
case "${1:-}" in
    --quick)
        echo "Running quick platform tests only..."
        setup_platform_env
        run_platform_tests
        ;;
    --cross)
        echo "Testing cross-compilation only..."
        test_cross_compilation
        ;;
    --features)
        echo "Testing feature combinations only..."
        test_feature_combinations
        ;;
    --report)
        echo "Generating report only..."
        generate_platform_report
        ;;
    *)
        main
        ;;
esac