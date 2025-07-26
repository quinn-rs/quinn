#!/bin/bash
# Script to help categorize existing tests into quick/standard/long

set -euo pipefail

echo "Test Categorization Helper"
echo "========================="
echo ""

# Quick tests (unit tests, basic integration)
QUICK_TESTS=(
    "auth_comprehensive_tests.rs"
    "chat_protocol_tests.rs"
    "connection_lifecycle_tests.rs"
    "observed_address_frame_flow.rs"
)

# Standard tests (integration, protocol compliance)
STANDARD_TESTS=(
    "nat_traversal_frames_test.rs"
    "address_discovery_nat_traversal.rs"
    "address_discovery_security_simple.rs"
    "nat_simulation.rs"
    "interop_test.rs"
)

# Long tests (stress, performance, comprehensive scenarios)
LONG_TESTS=(
    "nat_traversal_scenarios.rs"
    "p2p_integration_tests.rs"
    "stress_tests.rs"
    "nat_docker_integration.rs"
    "address_discovery_security.rs"
    "nat_test_harness.rs"
)

echo "Categorization Summary:"
echo "======================"
echo "Quick tests: ${#QUICK_TESTS[@]} files"
echo "Standard tests: ${#STANDARD_TESTS[@]} files"
echo "Long tests: ${#LONG_TESTS[@]} files"
echo ""

# Create symlinks for migration (preserving originals)
echo "Creating test organization..."

# Note: In a real migration, we would move files. For now, we'll document
# the categorization and update the workflows to use appropriate test subsets.

cat > tests/TEST_CATEGORIES.md << EOF
# Test Categorization

This document describes how tests are organized by execution time.

## Quick Tests (<30 seconds total)
Run with: \`cargo test --test quick\`

- auth_comprehensive_tests.rs - Authentication unit tests
- chat_protocol_tests.rs - Chat protocol unit tests  
- connection_lifecycle_tests.rs - Basic connection tests
- observed_address_frame_flow.rs - Frame parsing tests

## Standard Tests (<5 minutes total)
Run with: \`cargo test --test standard\`

- nat_traversal_frames_test.rs - NAT frame integration tests
- address_discovery_nat_traversal.rs - Address discovery tests
- address_discovery_security_simple.rs - Basic security tests
- nat_simulation.rs - NAT simulation tests
- interop_test.rs - Interoperability tests

## Long Tests (>5 minutes)
Run with: \`cargo test --test long -- --ignored\`

- nat_traversal_scenarios.rs - Comprehensive NAT scenarios
- p2p_integration_tests.rs - Full P2P integration tests
- stress_tests.rs - Stress and load tests
- nat_docker_integration.rs - Docker-based NAT tests
- address_discovery_security.rs - Comprehensive security tests
- nat_test_harness.rs - NAT test infrastructure

## Running Test Categories

### In CI/CD:
- Quick checks workflow: \`cargo test --test quick\`
- Standard tests workflow: \`cargo test --test standard\`
- Long tests workflow: \`cargo test --test long -- --ignored\`

### Locally:
\`\`\`bash
# Run all quick tests
make test-quick

# Run standard integration tests  
make test-standard

# Run long/stress tests (requires time!)
make test-long
\`\`\`
EOF

echo "Created tests/TEST_CATEGORIES.md"
echo ""
echo "Next steps:"
echo "1. Move test files to appropriate directories"
echo "2. Update test imports in category main.rs files"
echo "3. Update CI workflows to use categorized tests"