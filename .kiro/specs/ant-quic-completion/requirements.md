# Requirements Document

## Introduction

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. The project is a fork of quinn-proto that extends the proven QUIC implementation with sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs.

This implementation follows two key specifications:
1. **NAT Traversal**: [draft-seemann-quic-nat-traversal-01](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) - using the QUIC-native approach (NOT the STUN option) for cleaner integration
2. **Raw Public Keys**: RFC 7250 using SubjectPublicKeyInfo format - essential for P2P networks to avoid certificate overhead and PKI dependencies

Based on the comprehensive code review and analysis, the current implementation has a well-architected foundation but contains significant gaps in core networking functionality. The most critical missing pieces are the actual implementation of NAT traversal protocols using QUIC extension frames, platform-specific network discovery, and complete integration with the underlying QUIC transport.

## Requirements

### Requirement 1: Complete NAT Traversal Protocol Implementation

**User Story:** As a P2P application developer, I want to establish QUIC connections through NATs using the draft-seemann-quic-nat-traversal-01 protocol, so that my applications can achieve near 100% connectivity regardless of NAT configuration.

#### Acceptance Criteria

1. WHEN a client initiates NAT traversal THEN the system SHALL implement all required QUIC extension frames (ADD_ADDRESS, PUNCH_ME_NOW, REMOVE_ADDRESS) according to draft-seemann-quic-nat-traversal-01
2. WHEN transport parameters are negotiated THEN the system SHALL support the nat_traversal parameter (0x3d7e9f0bca12fea6) with proper client/server value handling
3. WHEN frames are encoded/decoded THEN the system SHALL use exact frame type constants (0x3d7e90-0x3d7e94) and proper VarInt encoding
4. WHEN bootstrap coordination occurs THEN the system SHALL implement server-initiated path validation and amplification attack mitigation
5. WHEN hole punching is performed THEN the system SHALL support coordinated simultaneous transmission to multiple destinations

### Requirement 2: Platform-Specific Network Interface Discovery

**User Story:** As a node running on different operating systems, I want the system to discover my network interfaces and addresses using native platform APIs, so that NAT traversal can work reliably across Windows, Linux, and macOS.

#### Acceptance Criteria

1. WHEN running on Windows THEN the system SHALL use IP Helper API to enumerate network interfaces and addresses
2. WHEN running on Linux THEN the system SHALL use Netlink sockets to discover network configuration
3. WHEN running on macOS THEN the system SHALL use System Configuration framework for interface discovery
4. WHEN discovering candidates THEN the system SHALL return actual interface information instead of hardcoded placeholder values
5. WHEN multiple interfaces exist THEN the system SHALL prioritize candidates according to ICE-like algorithms

### Requirement 3: Real QUIC Connection Establishment

**User Story:** As a P2P application, I want to establish actual QUIC connections after successful NAT traversal, so that I can send and receive data reliably between peers.

#### Acceptance Criteria

1. WHEN NAT traversal succeeds THEN the system SHALL establish real Quinn QUIC connections instead of simulated ones
2. WHEN connection establishment is attempted THEN the system SHALL use actual network I/O instead of artificial timeouts
3. WHEN connections are managed THEN the system SHALL integrate with Quinn's connection lifecycle management
4. WHEN data is transmitted THEN the system SHALL support bidirectional data flow over established connections
5. WHEN connections fail THEN the system SHALL provide proper error handling and recovery mechanisms

### Requirement 4: Bootstrap Node Communication

**User Story:** As a client behind a NAT, I want to communicate with bootstrap nodes using real network protocols, so that I can discover my external address and coordinate hole punching with peers.

#### Acceptance Criteria

1. WHEN contacting bootstrap nodes THEN the system SHALL establish actual QUIC connections instead of placeholder logging
2. WHEN requesting coordination THEN the system SHALL send and receive real NAT traversal frames
3. WHEN discovering server-reflexive addresses THEN the system SHALL receive actual observed addresses from bootstrap nodes
4. WHEN coordinating hole punching THEN the system SHALL implement the round-based synchronization protocol
5. WHEN bootstrap nodes are unavailable THEN the system SHALL implement proper fallback and retry mechanisms

### Requirement 5: Raw Public Key Authentication

**User Story:** As a P2P network participant, I want to authenticate peers using raw public keys instead of X.509 certificates, so that the system can operate without traditional PKI infrastructure.

#### Acceptance Criteria

1. WHEN establishing connections THEN the system SHALL support RFC 7250 Raw Public Key authentication
2. WHEN negotiating TLS extensions THEN the system SHALL properly handle client_certificate_type and server_certificate_type
3. WHEN processing certificates THEN the system SHALL extract Ed25519 public keys from SubjectPublicKeyInfo structures
4. WHEN validating peers THEN the system SHALL map public keys to peer identities consistently
5. WHEN configuring endpoints THEN the system SHALL provide APIs for raw key configuration while maintaining X.509 compatibility

### Requirement 6: High-Level API Completion

**User Story:** As an application developer, I want to use a simple, high-level API for P2P networking, so that I can focus on application logic rather than low-level QUIC and NAT traversal details.

#### Acceptance Criteria

1. WHEN using NatTraversalEndpoint THEN the system SHALL provide working implementations of discover_candidates(), coordinate_with_bootstrap(), and attempt_hole_punching()
2. WHEN using QuicP2PNode THEN the system SHALL implement functional accept(), send_to_peer(), and receive() methods
3. WHEN managing connections THEN the system SHALL provide real peer ID resolution and connection state management
4. WHEN handling events THEN the system SHALL emit actual NAT traversal events with real data instead of placeholder values
5. WHEN errors occur THEN the system SHALL provide meaningful error messages and recovery suggestions

### Requirement 7: Comprehensive Testing Infrastructure

**User Story:** As a developer maintaining the codebase, I want comprehensive tests that validate NAT traversal functionality, so that I can ensure the system works correctly across different network conditions.

#### Acceptance Criteria

1. WHEN testing frame encoding/decoding THEN the system SHALL include test vectors for all NAT traversal frames
2. WHEN testing multi-node scenarios THEN the system SHALL support simulated network topologies with different NAT types
3. WHEN testing platform compatibility THEN the system SHALL validate interface discovery on Windows, Linux, and macOS
4. WHEN testing security THEN the system SHALL validate protection against amplification attacks and flooding
5. WHEN testing performance THEN the system SHALL measure hole punching success rates and connection establishment times

### Requirement 8: Security and Rate Limiting

**User Story:** As a bootstrap node operator, I want protection against abuse and attacks, so that my node can provide reliable coordination services without being overwhelmed.

#### Acceptance Criteria

1. WHEN receiving coordination requests THEN the system SHALL implement rate limiting to prevent flooding attacks
2. WHEN validating addresses THEN the system SHALL verify addresses before initiating hole punching to prevent scanning
3. WHEN handling server-initiated validation THEN the system SHALL implement amplification attack mitigation
4. WHEN processing frames THEN the system SHALL validate frame contents and reject malformed data
5. WHEN coordinating between peers THEN the system SHALL use cryptographically secure random values for coordination rounds

### Requirement 9: IPv4/IPv6 Dual Stack Support

**User Story:** As a network administrator, I want the system to work correctly in dual-stack IPv4/IPv6 environments, so that it can adapt to modern network configurations.

#### Acceptance Criteria

1. WHEN discovering candidates THEN the system SHALL support both IPv4 and IPv6 addresses
2. WHEN encoding frames THEN the system SHALL properly handle both address families in ADD_ADDRESS frames
3. WHEN prioritizing candidates THEN the system SHALL implement proper IPv4/IPv6 preference algorithms
4. WHEN establishing connections THEN the system SHALL support connection establishment over both protocols
5. WHEN migrating connections THEN the system SHALL handle transitions between IPv4 and IPv6 paths

### Requirement 10: Production Readiness and Monitoring

**User Story:** As a system operator, I want comprehensive monitoring and production-ready defaults, so that I can deploy and maintain the system reliably in production environments.

#### Acceptance Criteria

1. WHEN operating in production THEN the system SHALL provide comprehensive metrics for connection success rates, latency, and error rates
2. WHEN debugging issues THEN the system SHALL offer detailed logging and diagnostic information
3. WHEN handling errors THEN the system SHALL implement graceful degradation and automatic recovery
4. WHEN managing resources THEN the system SHALL optimize memory usage and prevent resource leaks
5. WHEN scaling THEN the system SHALL support high-throughput scenarios with efficient resource utilization