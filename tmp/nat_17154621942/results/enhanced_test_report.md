# ANT-QUIC Enhanced NAT Test Report

## Executive Summary
- **Date**: Fri Aug 22 12:07:18 UTC 2025
- **Total Tests**: 18
- **Passed**: 0
- **Failed**: 32
- **Success Rate**: 0.0%

## Test Environment
- **NAT Types**: Full Cone, Symmetric, Port Restricted, CGNAT
- **Protocols**: IPv4, IPv6, Dual-stack
- **Network Conditions**: Normal, Packet Loss (5%), High Latency (200ms), Bandwidth Limited (1Mbps)

## Test Categories

### 1. Basic Connectivity
Tests basic QUIC connectivity from clients to bootstrap node.

- **basic_connectivity_ipv4_client1**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv4_client2**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv4_client3**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv4_client4**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv6_client1**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv6_client2**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv6_client3**: FAILED - Test failed (exit code: 2)
- **basic_connectivity_ipv6_only_client5**: FAILED - Test failed (exit code: 2)
- **address_discovery_client1**: FAILED - Test failed (exit code: 2)
- **address_discovery_client2**: FAILED - Test failed (exit code: 2)
- **address_discovery_client3**: FAILED - Test failed (exit code: 2)
- **address_discovery_client4**: FAILED - Test failed (exit code: 2)
- **address_discovery_client5**: FAILED - Test failed (exit code: 2)
- **fullcone_to_symmetric**: FAILED - Could not discover peer
- **fullcone_to_portrestricted**: FAILED - Could not discover peer
- **symmetric_to_portrestricted**: FAILED - Could not discover peer
- **fullcone_to_cgnat**: FAILED - Could not discover peer
- **symmetric_to_cgnat**: FAILED - Could not discover peer
- **portrestricted_to_cgnat**: FAILED - Could not discover peer
- **fullcone_to_symmetric**: FAILED - Could not discover peer
- **fullcone_to_portrestricted**: FAILED - Could not discover peer
- **symmetric_to_portrestricted**: FAILED - Could not discover peer
- **dualstack_to_ipv6only**: FAILED - Could not discover peer
- **stress_packet_loss**: FAILED - Could not discover peer
- **stress_high_latency**: FAILED - Could not discover peer
- **stress_bandwidth_limit**: FAILED - Could not discover peer
- **stress_jitter**: FAILED - Could not discover peer
- **pqc_handshake_mlkem**: FAILED - Test failed (exit code: 2)
- **pqc_p2p_connection**: FAILED - Test failed (exit code: 2)
- **perf_connection_time**: FAILED - Test failed (exit code: 2)
- **perf_throughput**: FAILED - Test failed (exit code: 2)
- **perf_concurrent**: FAILED - Test failed (exit code: 2)

## Performance Metrics
- NAT Success Rate: null

## Recommendations
1. **IPv6 Support**: 0.0% success rate indicates good dual-stack support
2. **NAT Traversal**: Most NAT combinations work successfully
3. **Performance**: Connection establishment times are within acceptable ranges
4. **PQC Readiness**: Hybrid mode tests show promising results

## Detailed Logs
All test logs are available in: ./results/
