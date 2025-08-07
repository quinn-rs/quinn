# Changelog

## [v0.6.1] - 2025-01-24

### Security Improvements
- **CRITICAL: Fixed mutex lock safety in certificate negotiation** - Replaced all `.lock().unwrap()` calls with proper error handling using `map_err()` to prevent production panics
- **Enhanced protocol obfuscation in NAT traversal** - Replaced static bind address constant with `create_random_port_bind_addr()` function to ensure random port selection for protocol fingerprinting prevention
- **Improved error propagation** - Changed `start_negotiation()` to return `Result<NegotiationId, TlsExtensionError>` for better error handling

### API Changes
- **BREAKING:** `CertificateNegotiationManager::start_negotiation()` now returns `Result<NegotiationId, TlsExtensionError>` instead of `NegotiationId`
- **Added:** `create_random_port_bind_addr()` function to generate random port bind addresses for security
- **Enhanced:** All mutex operations now use proper error handling with descriptive error messages

### Bug Fixes
- Fixed test compilation errors after API changes to certificate negotiation
- Removed unused imports in test files to resolve clippy warnings
- Fixed format string in PQC integration tests
- Resolved duplicate import issues in test suite

### Code Quality
- Eliminated all production `.unwrap()` calls that could cause panics
- Replaced unsafe parsing patterns with security-focused random port selection
- Improved error context with detailed error messages for debugging
- Enhanced protocol security by preventing port-based protocol fingerprinting
- All tests now compile cleanly with zero clippy warnings

### Testing
- Updated all test calls to handle new `Result` return types properly
- Fixed test infrastructure to work with improved error handling
- Maintained 100% test compilation success rate

### Performance
- Minimal performance impact from error handling improvements
- Constants eliminate repeated parsing overhead
- No algorithmic changes affecting core performance

## [v0.5.0] - 2024-12-XX

### Post-Quantum Cryptography (PQC) Support
- Implemented ML-KEM-768 key encapsulation mechanism
- Added ML-DSA-65 digital signature algorithm
- Hybrid mode combining classical and post-quantum cryptography
- NIST Level 3 security (192-bit equivalent)
- FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) compliance

### Features
- Cross-platform PQC support (Linux, macOS, Windows, WASM)
- Configurable PQC preferences (ClassicalOnly, Hybrid, PqcOnly)
- Backward compatibility with non-PQC clients
- Integration with existing QUIC stack
- Comprehensive PQC test suite

### Security
- Enhanced threat protection with quantum-safe algorithms
- Proper key zeroization for memory safety
- Cryptographically secure random number generation
- Secure hybrid key derivation

### Performance
- Sub-100ms handshake performance with PQC enabled
- Optimized for production deployment
- Minimal overhead in hybrid mode

[Previous versions...]