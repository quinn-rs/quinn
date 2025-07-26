# Test Migration Plan

This document outlines the migration of existing tests to the categorized structure.

## Quick Tests (< 30 seconds)
To be migrated to `tests/quick/`:
- auth_comprehensive_tests.rs → auth_tests.rs (already done)
- chat_protocol_tests.rs → protocol_tests.rs
- connection_lifecycle_tests.rs → connection_tests.rs (already done)
- observed_address_frame_flow.rs → frame_tests.rs (already done)
- frame_encoding_tests.rs → frame_tests.rs
- relay_queue_tests.rs → misc_tests.rs
- test_raw_public_keys.rs → crypto_tests.rs (already done)

## Standard Tests (< 5 minutes)
To be migrated to `tests/standard/`:
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
To be migrated to `tests/long/`:
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
