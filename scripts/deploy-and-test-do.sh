#!/bin/bash
# Deploy and test ant-quic on DigitalOcean server
# Run this from your local machine

set -euo pipefail

# Configuration
SERVER="quic.saorsalabs.com"
RELEASE_VERSION="v0.5.0"

echo "🚀 Deploying and testing ant-quic $RELEASE_VERSION on $SERVER"

# First, copy the test script to the server
echo "📤 Copying test script to server..."
scp scripts/test-release-on-do.sh root@$SERVER:/tmp/

# Run the test script on the server
echo "🧪 Running tests on server..."
ssh root@$SERVER "bash /tmp/test-release-on-do.sh $RELEASE_VERSION"

# Download the test report
echo "📥 Downloading test report..."
scp root@$SERVER:/tmp/ant-quic-test-*/test-report.txt ./test-report-do.txt 2>/dev/null || echo "No test report found"

# Also test that the server can act as a public bootstrap node
echo -e "\n🌐 Testing public bootstrap node..."
echo "You can now test from your local machine:"
echo "cargo run --bin ant-quic -- --bootstrap $SERVER:9000"

echo -e "\n✅ Deployment test complete!"
echo "Check test-report-do.txt for detailed results"