#!/bin/bash

echo "🐳 Testing coverage workflow with Act (simplified)..."
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running! Please start Docker Desktop."
    exit 1
fi

# Create a minimal test workflow
cat > .github/workflows/test-minimal.yml << 'EOF'
name: Minimal Test

on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Show system info
      run: |
        echo "=== System Info ==="
        uname -a
        echo "=== Network ==="
        ip addr || ifconfig || echo "No network info available"
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
    - name: Run basic test
      run: |
        cargo --version
        cargo test --lib --no-fail-fast -- --test-threads=1 || true
EOF

echo "Running minimal workflow with Act..."
act push -W .github/workflows/test-minimal.yml -P ubuntu-latest=catthehacker/ubuntu:act-latest --rm

echo "✅ Done!"