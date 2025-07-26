#!/bin/bash
# Script to migrate tests to categorized structure

set -euo pipefail

echo "Test Migration Script"
echo "===================="
echo ""

# Base directory
TEST_DIR="tests"

# Function to check if a test is quick (<30s)
is_quick_test() {
    local file="$1"
    case "$file" in
        auth_comprehensive_tests.rs | \
        chat_protocol_tests.rs | \
        connection_lifecycle_tests.rs | \
        observed_address_frame_flow.rs | \
        frame_encoding_tests.rs | \
        relay_queue_tests.rs | \
        test_raw_public_keys.rs)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Function to check if a test is standard (<5min)
is_standard_test() {
    local file="$1"
    case "$file" in
        nat_traversal_frames_test.rs | \
        nat_traversal_frame_tests.rs | \
        address_discovery_nat_traversal.rs | \
        address_discovery_security_simple.rs | \
        address_discovery_integration_simple.rs | \
        nat_simulation.rs | \
        interop_test.rs | \
        auth_integration_tests.rs | \
        auth_security_tests.rs | \
        nat_traversal_api_tests.rs)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Function to check if a test is long (>5min)
is_long_test() {
    local file="$1"
    case "$file" in
        nat_traversal_scenarios.rs | \
        p2p_integration_tests.rs | \
        stress_tests.rs | \
        nat_docker_integration.rs | \
        address_discovery_security.rs | \
        nat_test_harness.rs | \
        address_discovery_integration.rs | \
        address_discovery_e2e.rs | \
        connection_success_rates.rs | \
        infrastructure_tests.rs | \
        nat_traversal_simulation.rs)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

echo "Creating test module files..."

# Create quick test modules (these already exist)
echo "Quick tests already have modules."

# Create standard test modules
cat > "$TEST_DIR/standard/integration_tests.rs" << 'EOF'
//! Integration tests for standard test suite

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for integration test structure
    // Individual tests will be added as we migrate them
}
EOF

cat > "$TEST_DIR/standard/protocol_tests.rs" << 'EOF'
//! Protocol compliance tests

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for protocol test structure
    // Individual tests will be added as we migrate them
}
EOF

cat > "$TEST_DIR/standard/nat_basic_tests.rs" << 'EOF'
//! Basic NAT traversal tests

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for NAT test structure
    // Individual tests will be added as we migrate them
}
EOF

# Update standard/main.rs to include the new modules
cat > "$TEST_DIR/standard/main.rs" << 'EOF'
//! Standard test suite for ant-quic
//! These tests run in < 5 minutes and include integration and protocol tests

pub mod utils {
    use std::time::Duration;
    
    pub const STANDARD_TEST_TIMEOUT: Duration = Duration::from_secs(30);
    
    // Add common test utilities here
    pub fn setup_test_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("ant_quic=debug,warn")
            .try_init();
    }
}

// Test modules
pub mod integration_tests;
pub mod protocol_tests;
pub mod nat_basic_tests;

// Re-export test utilities
pub use utils::*;
EOF

# Create long test modules
cat > "$TEST_DIR/long/stress_tests.rs" << 'EOF'
//! Stress and load tests

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for stress test structure
    // Individual tests will be added as we migrate them
}
EOF

cat > "$TEST_DIR/long/nat_comprehensive_tests.rs" << 'EOF'
//! Comprehensive NAT traversal tests

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for comprehensive NAT test structure
    // Individual tests will be added as we migrate them
}
EOF

cat > "$TEST_DIR/long/performance_tests.rs" << 'EOF'
//! Performance and benchmark tests

use ant_quic::*;
use std::time::Duration;

// Re-export common test utilities
pub use crate::utils::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder for performance test structure
    // Individual tests will be added as we migrate them
}
EOF

# Update long/main.rs to include the new modules
cat > "$TEST_DIR/long/main.rs" << 'EOF'
//! Long-running test suite for ant-quic
//! These tests take > 5 minutes and include stress, performance, and comprehensive tests

use std::time::Duration;

pub mod utils {
    use super::*;
    
    pub const LONG_TEST_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
    
    // Add common test utilities here
    pub fn setup_test_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("ant_quic=debug,warn")  
            .try_init();
    }
}

// Test modules
pub mod stress_tests;
pub mod nat_comprehensive_tests;
pub mod performance_tests;

// Custom test runner for long tests
fn main() {
    println!("Running long tests...");
    
    // Set up logging
    utils::setup_test_logger();
    
    // Run test suites
    println!("Note: Long tests are typically run with --ignored flag");
    println!("Use: cargo test --test long -- --ignored");
}
EOF

echo ""
echo "Creating migration summary..."

# Count tests in each category
QUICK_COUNT=0
STANDARD_COUNT=0
LONG_COUNT=0
DISABLED_COUNT=0

for test_file in "$TEST_DIR"/*.rs; do
    if [[ ! -f "$test_file" ]]; then
        continue
    fi
    
    filename=$(basename "$test_file")
    
    # Skip directory main files
    if [[ "$filename" == "main.rs" ]]; then
        continue
    fi
    
    # Count disabled tests
    if [[ "$filename" == *.disabled ]]; then
        DISABLED_COUNT=$((DISABLED_COUNT + 1))
        continue
    fi
    
    if is_quick_test "$filename"; then
        QUICK_COUNT=$((QUICK_COUNT + 1))
        echo "  Quick: $filename"
    elif is_standard_test "$filename"; then
        STANDARD_COUNT=$((STANDARD_COUNT + 1))
        echo "  Standard: $filename"
    elif is_long_test "$filename"; then
        LONG_COUNT=$((LONG_COUNT + 1))
        echo "  Long: $filename"
    else
        echo "  Uncategorized: $filename"
    fi
done

echo ""
echo "Migration Summary:"
echo "=================="
echo "Quick tests: $QUICK_COUNT files"
echo "Standard tests: $STANDARD_COUNT files"
echo "Long tests: $LONG_COUNT files"
echo "Disabled tests: $DISABLED_COUNT files"
echo ""

# Create a migration plan file
cat > "$TEST_DIR/MIGRATION_PLAN.md" << EOF
# Test Migration Plan

This document outlines the migration of existing tests to the categorized structure.

## Quick Tests (< 30 seconds)
To be migrated to \`tests/quick/\`:
- auth_comprehensive_tests.rs → auth_tests.rs (already done)
- chat_protocol_tests.rs → protocol_tests.rs
- connection_lifecycle_tests.rs → connection_tests.rs (already done)
- observed_address_frame_flow.rs → frame_tests.rs (already done)
- frame_encoding_tests.rs → frame_tests.rs
- relay_queue_tests.rs → misc_tests.rs
- test_raw_public_keys.rs → crypto_tests.rs (already done)

## Standard Tests (< 5 minutes)
To be migrated to \`tests/standard/\`:
- nat_traversal_frames_test.rs → nat_basic_tests.rs
- nat_traversal_frame_tests.rs → nat_basic_tests.rs
- address_discovery_nat_traversal.rs → nat_basic_tests.rs
- address_discovery_security_simple.rs → protocol_tests.rs
- address_discovery_integration_simple.rs → integration_tests.rs
- nat_simulation.rs → nat_basic_tests.rs
- interop_test.rs → protocol_tests.rs
- auth_integration_tests.rs → integration_tests.rs
- auth_security_tests.rs → protocol_tests.rs
- nat_traversal_api_tests.rs → integration_tests.rs

## Long Tests (> 5 minutes)
To be migrated to \`tests/long/\`:
- nat_traversal_scenarios.rs → nat_comprehensive_tests.rs
- p2p_integration_tests.rs → nat_comprehensive_tests.rs
- stress_tests.rs → stress_tests.rs
- nat_docker_integration.rs → nat_comprehensive_tests.rs
- address_discovery_security.rs → nat_comprehensive_tests.rs
- nat_test_harness.rs → nat_comprehensive_tests.rs
- address_discovery_integration.rs → nat_comprehensive_tests.rs
- address_discovery_e2e.rs → nat_comprehensive_tests.rs
- connection_success_rates.rs → performance_tests.rs
- infrastructure_tests.rs → performance_tests.rs
- nat_traversal_simulation.rs → nat_comprehensive_tests.rs

## Disabled Tests
These tests are currently disabled and need review:
- integration_end_to_end_tests.rs.disabled
- ipv6_dual_stack_tests.rs.disabled
- multi_node_coordination_tests.rs.disabled
- nat_traversal_negotiation.rs.disabled
- nat_traversal_public_api.rs.disabled
- performance_validation_tests.rs.disabled
- platform_api_integration_tests.rs.disabled
- platform_compatibility_tests.rs.disabled
- quinn_extension_frame_integration.rs.disabled
- security_validation_tests.rs.disabled
- standalone_frame_tests.rs.disabled
- connection_stress_tests.rs.disabled

## Migration Steps

1. **Phase 1**: Module structure (COMPLETED)
   - Created directory structure
   - Created main.rs files for each category
   - Created placeholder module files

2. **Phase 2**: Test migration (TODO)
   - Move test content to appropriate modules
   - Update imports and module declarations
   - Ensure tests compile and run

3. **Phase 3**: CI/CD integration (IN PROGRESS)
   - Update workflows to use categorized tests
   - Verify test execution times
   - Monitor for flaky tests

4. **Phase 4**: Cleanup
   - Remove old test files
   - Update documentation
   - Create test writing guidelines
EOF

echo "Migration plan created: $TEST_DIR/MIGRATION_PLAN.md"
echo ""
echo "Next steps:"
echo "1. Review the migration plan"
echo "2. Start moving test content to appropriate modules"
echo "3. Update imports and ensure compilation"
echo "4. Run tests in each category to verify"