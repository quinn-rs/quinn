#!/bin/bash

# Simple script to run coverage workflow locally with Act

set -e

echo "🐳 Running coverage workflow locally with Act..."
echo ""

# Check requirements
if ! command -v act &> /dev/null; then
    echo "❌ Act is not installed!"
    echo "Install with: brew install act"
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running!"
    echo "Please start Docker Desktop."
    exit 1
fi

# Use the improved coverage workflow
WORKFLOW=".github/workflows/coverage-improved.yml"

if [ ! -f "$WORKFLOW" ]; then
    WORKFLOW=".github/workflows/coverage.yml"
    echo "⚠️  Using original coverage workflow. Run from project root."
fi

echo "📋 Using workflow: $WORKFLOW"
echo ""
echo "Starting Act..."
echo "This will take a while as it downloads the Docker image and runs tests..."
echo ""

# Run with Act using the default Ubuntu image
act push \
    -W "$WORKFLOW" \
    -P ubuntu-latest=catthehacker/ubuntu:act-latest \
    --container-architecture linux/amd64 \
    -j coverage-llvm-cov \
    --rm

echo ""
echo "✅ Coverage workflow completed!"