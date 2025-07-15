# Project Structure

## Root Directory
- `Cargo.toml`: Main workspace configuration with dependencies and feature flags
- `README.md`: Comprehensive project documentation and usage examples
- `LICENSE-MIT` / `LICENSE-APACHE`: Dual licensing
- `deny.toml`: Security and license policy configuration
- `rustfmt.toml`: Code formatting configuration

## Source Code Organization (`src/`)

### Core Library (`src/lib.rs`)
Main library entry point exposing all public APIs and re-exports

### Binary Targets (`src/bin/`)
- `ant-quic.rs`: Main P2P node binary with automatic coordinator detection

### Core Protocol Modules
- `connection/`: QUIC connection management and state
- `endpoint.rs`: QUIC endpoint implementation
- `frame.rs`: QUIC frame types and encoding/decoding
- `packet.rs`: Packet parsing and construction
- `transport_parameters.rs`: QUIC transport parameter negotiation

### NAT Traversal Components
- `candidate_discovery/`: Platform-specific network interface discovery
  - `linux.rs`: Linux netlink-based discovery
  - `macos.rs`: macOS System Configuration framework
  - `windows.rs`: Windows IP Helper API
- `nat_traversal_api.rs`: High-level NAT traversal API
- `connection_establishment_simple.rs`: Simplified connection establishment

### Crypto & Security (`src/crypto/`)
- `rustls.rs`: Rustls integration
- `raw_public_keys.rs`: Raw public key support
- `certificate_*.rs`: Certificate management and negotiation
- `tls_extensions.rs`: Custom TLS extensions for NAT traversal

### Networking & Transport
- `congestion/`: Congestion control algorithms (BBR, Cubic, NewReno)
- `config/`: Configuration management and validation
- `range_set/`: Efficient range tracking data structures

### Monitoring & Observability (`src/monitoring/`)
- `metrics.rs`: Performance and connection metrics
- `diagnostics.rs`: Network diagnostics and troubleshooting
- `health.rs`: Health check and status reporting

### Utilities
- `terminal_ui.rs`: CLI user interface components
- `workflow/`: Workflow orchestration for complex operations
- `validation/`: Test validation and network condition simulation

## Testing Structure

### Unit Tests
- Embedded in source files using `#[cfg(test)]`
- Module-specific test utilities in `test_utils` submodules

### Integration Tests (`tests/`)
- `nat_traversal_*.rs`: NAT traversal integration tests
- `stress/`: Stress testing scenarios
- `quinn_extension_frame_integration.rs`: Quinn integration tests

### Benchmarks (`benches/`)
- `candidate_discovery.rs`: Network discovery performance
- `nat_traversal.rs`: NAT traversal protocol performance
- `connection_management.rs`: Connection lifecycle benchmarks

### Disabled Tests (`temp_disabled_tests/`)
- Tests temporarily disabled during development
- Organized by category for re-enabling

## Configuration Files
- `.cargo/config.toml`: Cargo build configuration
- `.codecov.yml`: Code coverage configuration
- `.github/`: CI/CD workflows and issue templates

## Examples (`examples/`)
- `workflow_example.rs`: Workflow system usage
- `certificate_type_negotiation.rs`: Certificate negotiation examples
- `phase3_advanced_features.rs`: Advanced feature demonstrations

## Architecture Patterns

### Module Organization
- Each major feature has its own module with clear boundaries
- Platform-specific code isolated in separate files
- Test utilities co-located with implementation

### Error Handling
- Custom error types using `thiserror` for each module
- Comprehensive error propagation with context
- Result types for all fallible operations

### Async Patterns
- Tokio-based async runtime throughout
- Stream-based APIs for continuous operations
- Timeout and cancellation support

### Configuration Management
- Serde-based configuration with validation
- Feature flags for optional components
- Environment-specific defaults

### Testing Strategy
- Unit tests for individual components
- Integration tests for cross-module functionality
- Stress tests for performance validation
- Mock implementations for network simulation