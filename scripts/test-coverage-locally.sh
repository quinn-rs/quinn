#!/bin/bash

# Script to test the coverage workflow locally using Act
# This helps debug the Linux test segfault issue

set -e

echo "🐳 Testing coverage workflow locally with Act..."
echo ""
echo "This will run the coverage workflow in a Docker container to debug the Linux test segfault issue."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Act is installed
if ! command -v act &> /dev/null; then
    echo -e "${RED}❌ Act is not installed!${NC}"
    echo "Please install Act first: brew install act"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running!${NC}"
    echo "Please start Docker Desktop first."
    exit 1
fi

echo -e "${GREEN}✓ Act and Docker are ready${NC}"
echo ""

# Create a simplified workflow for testing just the problematic test
cat > .github/workflows/test-linux-coverage.yml << 'EOF'
name: Test Linux Coverage Issue

on:
  workflow_dispatch:
  push:

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: full
  RUST_LOG: debug

jobs:
  test-coverage:
    name: Debug Linux Test Coverage
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: llvm-tools-preview
        
    - name: Install cargo-tarpaulin
      run: |
        echo "Installing cargo-tarpaulin..."
        cargo install cargo-tarpaulin --locked --version 0.27.3
        
    - name: Check system info
      run: |
        echo "=== System Information ==="
        uname -a
        echo ""
        echo "=== Memory Info ==="
        free -h
        echo ""
        echo "=== CPU Info ==="
        nproc
        echo ""
        echo "=== Network Interfaces ==="
        ip addr show
        echo ""
        echo "=== Rust Version ==="
        rustc --version
        cargo --version
        
    - name: Run specific Linux test with debugging
      run: |
        echo "Running the problematic Linux test with debugging..."
        export RUST_TEST_THREADS=1
        
        # First, try running just the specific test with timeout
        timeout 30s cargo test linux_tests::test_linux_interface_discovery -- --nocapture --test-threads=1 || true
        
        echo ""
        echo "=== Running with strace to debug segfault ==="
        # Install strace for debugging
        sudo apt-get update && sudo apt-get install -y strace
        
        # Run with strace to capture system calls
        timeout 30s strace -f -o /tmp/strace.log cargo test linux_tests::test_linux_interface_discovery -- --nocapture --test-threads=1 || true
        
        # Show last 100 lines of strace output
        echo "=== Last 100 lines of strace output ==="
        tail -n 100 /tmp/strace.log || true
        
    - name: Run tarpaulin with minimal settings
      run: |
        echo "Running tarpaulin with minimal settings and timeout..."
        
        # Run tarpaulin with specific test and short timeout
        cargo tarpaulin \
          --timeout 30 \
          --test-timeout 10 \
          --exclude-files "*/tests/*" \
          --exclude-files "*/examples/*" \
          --exclude-files "*/benches/*" \
          --exclude-files "*/build.rs" \
          --workspace \
          --verbose \
          -- linux_tests::test_linux_interface_discovery || true
          
    - name: Run all tests without tarpaulin
      run: |
        echo "Running all tests without tarpaulin to check if they pass..."
        cargo test --workspace -- --nocapture || true
EOF

echo "📝 Created test workflow: .github/workflows/test-linux-coverage.yml"
echo ""

# Option 1: Run with the default Ubuntu runner image
echo -e "${YELLOW}Option 1: Running with default Ubuntu runner (catthehacker/ubuntu:act-latest)${NC}"
echo "This uses the Act default Ubuntu image which is similar to GitHub Actions environment"
echo ""
read -p "Run with default Ubuntu image? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting Act with default Ubuntu image..."
    act -W .github/workflows/test-linux-coverage.yml \
        --container-architecture linux/amd64 \
        -P ubuntu-latest=catthehacker/ubuntu:act-latest \
        --verbose
fi

echo ""
echo -e "${YELLOW}Option 2: Running with official Ubuntu 22.04 image${NC}"
echo "This uses the official Ubuntu 22.04 image for a cleaner environment"
echo ""
read -p "Run with Ubuntu 22.04 image? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Create a custom workflow that doesn't use composite actions
    cat > .github/workflows/test-linux-coverage-simple.yml << 'EOF'
name: Test Linux Coverage Simple

on:
  workflow_dispatch:
  push:

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: full

jobs:
  test-coverage:
    name: Debug Linux Test Coverage
    runs-on: ubuntu-latest
    container: ubuntu:22.04
    
    steps:
    - name: Setup container
      run: |
        apt-get update
        apt-get install -y curl git build-essential pkg-config libssl-dev
        
    - name: Checkout repository
      run: |
        git clone https://github.com/${{ github.repository }} /workspace
        cd /workspace
        git checkout ${{ github.sha }}
      
    - name: Install Rust
      run: |
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        . "$HOME/.cargo/env"
        rustup toolchain install stable
        rustup default stable
        rustup component add llvm-tools-preview
        
    - name: Install cargo-tarpaulin
      run: |
        . "$HOME/.cargo/env"
        cargo install cargo-tarpaulin --locked --version 0.27.3
        
    - name: Run Linux test
      run: |
        . "$HOME/.cargo/env"
        cd /workspace
        export RUST_TEST_THREADS=1
        timeout 30s cargo test linux_tests::test_linux_interface_discovery -- --nocapture --test-threads=1 || true
EOF

    echo "Starting Act with Ubuntu 22.04 container..."
    act -W .github/workflows/test-linux-coverage-simple.yml \
        --container-architecture linux/amd64 \
        --verbose
fi

echo ""
echo -e "${YELLOW}Option 3: Run locally without Docker (macOS host)${NC}"
echo "This will run the tests directly on your macOS system"
echo ""
read -p "Run tests locally on macOS? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running tests locally on macOS..."
    echo ""
    
    # Only run non-Linux specific tests on macOS
    echo "Running non-Linux tests..."
    cargo test --workspace -- --nocapture
    
    echo ""
    echo -e "${YELLOW}Note: Linux-specific tests are skipped on macOS${NC}"
fi

echo ""
echo "✅ Test script complete!"
echo ""
echo "📋 Summary of findings:"
echo "- The segfault occurs in the linux_tests::test_linux_interface_discovery test"
echo "- This test uses Linux-specific network interface discovery via Netlink"
echo "- The issue may be related to cargo-tarpaulin's instrumentation on Linux"
echo ""
echo "🔧 Suggested fixes:"
echo "1. Add timeout to the test itself"
echo "2. Exclude this specific test from tarpaulin coverage"
echo "3. Use a different coverage tool (llvm-cov instead of tarpaulin)"
echo "4. Fix potential memory safety issues in the Netlink code"