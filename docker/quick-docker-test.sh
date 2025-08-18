#!/bin/bash
# Quick Docker test after restart

set -e

echo "=== Quick Docker Test ==="
echo ""

# Test 1: Docker is running
echo -n "1. Docker daemon: "
if docker ps >/dev/null 2>&1; then
    echo "✅ Running"
else
    echo "❌ Not running"
    exit 1
fi

# Test 2: Can pull images
echo -n "2. Pull test image: "
if docker pull alpine:latest >/dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
    exit 1
fi

# Test 3: Can run containers
echo -n "3. Run container: "
if docker run --rm alpine echo "test" >/dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
    exit 1
fi

# Test 4: Build simple Dockerfile
echo -n "4. Build test: "
cat > /tmp/Dockerfile.test <<EOF
FROM alpine:latest
RUN echo "Build test"
CMD ["echo", "Hello from test container"]
EOF

if docker build -t test:simple -f /tmp/Dockerfile.test /tmp >/dev/null 2>&1; then
    echo "✅ Success"
    docker rmi test:simple >/dev/null 2>&1
else
    echo "❌ Failed"
    exit 1
fi

rm -f /tmp/Dockerfile.test

# Test 5: Docker Compose
echo -n "5. Docker Compose: "
if docker compose version >/dev/null 2>&1; then
    echo "✅ Available"
else
    echo "❌ Not available"
    exit 1
fi

echo ""
echo "✅ All Docker tests passed!"
echo ""
echo "Now you can run the ant-quic Docker tests:"
echo "  cd docker"
echo "  ./scripts/run-enhanced-nat-tests.sh test_basic_connectivity"