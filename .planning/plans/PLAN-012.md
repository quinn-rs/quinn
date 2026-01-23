# Phase 1.2: P2pEndpoint → NatTraversalEndpoint Wiring

## Overview
Pass TransportRegistry from P2pEndpoint to NatTraversalEndpoint, enabling the NAT traversal layer to use transport providers for socket binding. This completes the second link in the wiring chain: NodeConfig → P2pEndpoint → NatTraversalEndpoint.

## Technical Decisions
- Breakdown approach: TDD (tests first)
- Task size: Small (~50 lines, 1 file per task)
- Testing strategy: Integration test first, then unit tests for config and socket binding
- Dependencies: Depends on Phase 1.1 (complete), blocks Phase 1.3
- Patterns: Follow existing Arc<TransportRegistry> pattern from P2pEndpoint
- Socket access: Add socket() to TransportProvider trait for generic access

## Task Complexity Summary (Anthropic Best Practice: Effort Scaling)

| Task | Est. Lines | Files | Complexity | Model |
|------|-----------|-------|------------|-------|
| Task 1 | ~40 | 1 | simple | haiku |
| Task 2 | ~30 | 1 | standard | sonnet |
| Task 3 | ~50 | 1 | simple | haiku |
| Task 4 | ~40 | 1 | simple | haiku |
| Task 5 | ~40 | 1 | simple | haiku |
| Task 6 | ~80 | 1 | standard | sonnet |
| Task 7 | ~60 | 2 | standard | sonnet |
| Task 8 | ~50 | 1 | simple | haiku |

**Complexity Guide:**
- `simple` (< 50 lines, 1 file) → haiku
- `standard` (50-200 lines, 1-2 files) → sonnet
- `complex` (> 200 lines, 3+ files, architectural) → opus

## Tasks

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 1: Integration Test (Failing)</n>
  <activeForm>Writing failing integration test for registry flow to NatTraversalEndpoint</activeForm>
  <files>
    tests/transport_registry_flow.rs
  </files>
  <estimated_lines>~40</estimated_lines>
  <depends></depends>
  <action>
    Add a new integration test to tests/transport_registry_flow.rs that attempts to verify
    the TransportRegistry flows from Node through to NatTraversalEndpoint.

    The test should:
    1. Create a MockTransportProvider (or use UdpTransport)
    2. Create NodeConfig with the provider registered
    3. Build Node
    4. Attempt to access the registry through NatTraversalEndpoint (this will fail initially)

    This test defines the acceptance criteria for Phase 1.2.

    Requirements:
    - NO .unwrap() or .expect() in the test implementation (use proper assertions)
    - Test should compile but fail until Tasks 2-7 are complete
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test --test transport_registry_flow -- --nocapture 2>&1 | grep -E "(FAILED|error|test result)"
  </verify>
  <done>
    - Test compiles
    - Test fails with expected error (registry not accessible from NatTraversalEndpoint)
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 2: Add socket() to TransportProvider Trait</n>
  <activeForm>Adding socket() method to TransportProvider trait</activeForm>
  <files>
    src/transport/provider.rs
    src/transport/udp.rs
  </files>
  <estimated_lines>~30</estimated_lines>
  <depends>Task 1</depends>
  <action>
    Add a socket() method to the TransportProvider trait that returns an optional reference
    to the underlying socket. This enables generic socket extraction from any provider.

    In src/transport/provider.rs:
    1. Add method to TransportProvider trait:
       ```rust
       /// Returns the underlying socket if available.
       /// For UDP transports, this provides access to the UdpSocket.
       /// For transports without traditional sockets (BLE), returns None.
       fn socket(&self) -> Option<&std::sync::Arc<tokio::net::UdpSocket>> {
           None  // Default implementation
       }
       ```

    In src/transport/udp.rs:
    2. Override the socket() method in UdpTransport impl:
       ```rust
       fn socket(&self) -> Option<&std::sync::Arc<tokio::net::UdpSocket>> {
           Some(&self.socket)
       }
       ```

    Requirements:
    - Default implementation returns None (for BLE and other non-socket transports)
    - UdpTransport overrides to return Some(&self.socket)
    - NO .unwrap() or .expect() in production code
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic --lib
  </verify>
  <done>
    - TransportProvider trait has socket() method
    - UdpTransport implements socket() returning the underlying socket
    - All existing tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 3: Add transport_registry to NatTraversalConfig</n>
  <activeForm>Adding transport_registry field to NatTraversalConfig</activeForm>
  <files>
    src/nat_traversal_api.rs
  </files>
  <estimated_lines>~50</estimated_lines>
  <depends>Task 2</depends>
  <action>
    Add transport_registry field to NatTraversalConfig struct and its builder.

    Find NatTraversalConfig struct (around line 239-309) and add:
    1. Field (after existing fields):
       ```rust
       /// Transport registry containing available transport providers.
       /// When provided, NatTraversalEndpoint uses registered transports
       /// for socket binding instead of hardcoded UDP.
       pub transport_registry: Option<Arc<TransportRegistry>>,
       ```

    2. Add import at top of file:
       ```rust
       use crate::transport::TransportRegistry;
       ```

    3. Find NatTraversalConfigBuilder and add builder method:
       ```rust
       /// Set the transport registry.
       pub fn transport_registry(mut self, registry: Arc<TransportRegistry>) -> Self {
           self.transport_registry = Some(registry);
           self
       }
       ```

    4. Update Default impl if present to initialize transport_registry: None

    Requirements:
    - Field is Option<Arc<TransportRegistry>> for backward compatibility
    - NO .unwrap() or .expect() in production code
    - Document the field with doc comments
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic --lib
  </verify>
  <done>
    - NatTraversalConfig has transport_registry field
    - Builder has transport_registry() method
    - All existing tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 4: Unit Tests for NatTraversalConfig</n>
  <activeForm>Writing unit tests for NatTraversalConfig transport_registry</activeForm>
  <files>
    src/nat_traversal_api.rs
  </files>
  <estimated_lines>~40</estimated_lines>
  <depends>Task 3</depends>
  <action>
    Add unit tests for the transport_registry field in NatTraversalConfig.

    Find the tests module in nat_traversal_api.rs and add:

    ```rust
    #[test]
    fn test_nat_config_default_has_no_registry() {
        let config = NatTraversalConfig::builder().build();
        assert!(config.transport_registry.is_none());
    }

    #[test]
    fn test_nat_config_builder_accepts_registry() {
        use crate::transport::TransportRegistry;
        let registry = Arc::new(TransportRegistry::new());
        let config = NatTraversalConfig::builder()
            .transport_registry(Arc::clone(&registry))
            .build();
        assert!(config.transport_registry.is_some());
        assert!(Arc::ptr_eq(&config.transport_registry.unwrap(), &registry));
    }
    ```

    Requirements:
    - Tests verify default config has None registry
    - Tests verify builder sets registry correctly
    - Use .unwrap() in tests (allowed per CLAUDE.md)
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic nat_config
  </verify>
  <done>
    - Tests for NatTraversalConfig transport_registry pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 5: Store registry in NatTraversalEndpoint</n>
  <activeForm>Adding transport_registry storage to NatTraversalEndpoint</activeForm>
  <files>
    src/nat_traversal_api.rs
  </files>
  <estimated_lines>~40</estimated_lines>
  <depends>Task 3</depends>
  <action>
    Add transport_registry field to NatTraversalEndpoint struct and expose via accessor.

    1. Find NatTraversalEndpoint struct and add field:
       ```rust
       /// Transport registry for multi-transport support.
       transport_registry: Option<Arc<TransportRegistry>>,
       ```

    2. In NatTraversalEndpoint::new(), store the registry from config:
       ```rust
       // Near start of new() method
       let transport_registry = config.transport_registry.clone();
       ```

       And in the struct initialization:
       ```rust
       transport_registry,
       ```

    3. Add accessor method:
       ```rust
       /// Returns the transport registry if one was configured.
       pub fn transport_registry(&self) -> Option<&TransportRegistry> {
           self.transport_registry.as_ref().map(|arc| arc.as_ref())
       }
       ```

    Requirements:
    - Field is Option<Arc<TransportRegistry>> (matching config)
    - Accessor returns Option<&TransportRegistry> for borrowing
    - NO .unwrap() or .expect() in production code
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic --lib
  </verify>
  <done>
    - NatTraversalEndpoint has transport_registry field
    - Accessor method available
    - All existing tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 6: Modify create_inner_endpoint() for registry socket</n>
  <activeForm>Modifying create_inner_endpoint() to use registry socket</activeForm>
  <files>
    src/nat_traversal_api.rs
  </files>
  <estimated_lines>~80</estimated_lines>
  <depends>Task 2, Task 5</depends>
  <action>
    Modify create_inner_endpoint() to use the transport registry's UDP socket
    instead of hardcoded UdpSocket::bind(), with fallback for backward compatibility.

    Find create_inner_endpoint() (around line 1534-1720) and locate the socket binding
    code (around lines 1676-1682):

    Current code:
    ```rust
    let bind_addr = config.bind_addr.unwrap_or_else(create_random_port_bind_addr);
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        NatTraversalError::NetworkError(format!("Failed to bind UDP socket: {e}"))
    })?;
    ```

    Replace with:
    ```rust
    // Try to get socket from transport registry first
    let socket = if let Some(ref registry) = config.transport_registry {
        // Look for an online UDP transport provider
        let udp_providers = registry.providers_by_type(crate::transport::TransportType::Udp);
        if let Some(provider) = udp_providers.first().filter(|p| p.is_online()) {
            if let Some(socket_ref) = provider.socket() {
                // Clone the Arc and try to extract the socket
                // Note: This requires try_unwrap or similar - evaluate approach
                tracing::debug!("Using socket from transport registry");
                socket_ref.try_clone().await.map_err(|e| {
                    NatTraversalError::NetworkError(format!("Failed to clone registry socket: {e}"))
                })?
            } else {
                tracing::debug!("UDP provider has no socket, falling back to direct binding");
                let bind_addr = config.bind_addr.unwrap_or_else(create_random_port_bind_addr);
                UdpSocket::bind(bind_addr).await.map_err(|e| {
                    NatTraversalError::NetworkError(format!("Failed to bind UDP socket: {e}"))
                })?
            }
        } else {
            tracing::debug!("No online UDP provider in registry, falling back to direct binding");
            let bind_addr = config.bind_addr.unwrap_or_else(create_random_port_bind_addr);
            UdpSocket::bind(bind_addr).await.map_err(|e| {
                NatTraversalError::NetworkError(format!("Failed to bind UDP socket: {e}"))
            })?
        }
    } else {
        // No registry configured - use original behavior
        let bind_addr = config.bind_addr.unwrap_or_else(create_random_port_bind_addr);
        UdpSocket::bind(bind_addr).await.map_err(|e| {
            NatTraversalError::NetworkError(format!("Failed to bind UDP socket: {e}"))
        })?
    };
    ```

    IMPORTANT: The exact approach for socket sharing needs verification.
    The Arc<UdpSocket> from registry may need special handling since Quinn wants
    ownership of the socket. Consider:
    - Using try_clone() on the socket
    - Sharing via Arc (Quinn may accept this)
    - Binding fresh socket but using registry for provider tracking

    Requirements:
    - Backward compatible: None registry uses original behavior
    - Proper error handling with ?
    - Add tracing::debug! for observability
    - NO .unwrap() or .expect() in production code
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic --lib
  </verify>
  <done>
    - create_inner_endpoint() checks registry for UDP provider
    - Falls back to direct binding when registry is None or no UDP provider
    - All existing tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 7: Wire P2pEndpoint → NatTraversalEndpoint</n>
  <activeForm>Wiring P2pEndpoint to pass registry to NatTraversalEndpoint</activeForm>
  <files>
    src/p2p_endpoint.rs
    src/unified_config.rs
  </files>
  <estimated_lines>~60</estimated_lines>
  <depends>Task 6</depends>
  <action>
    Wire the transport_registry from P2pEndpoint to NatTraversalEndpoint through config conversion.

    In src/unified_config.rs:
    1. Find the conversion from P2pConfig to NatTraversalConfig
       (look for to_nat_config or similar method, or where NatTraversalConfig is built from P2pConfig)

    2. Add transport_registry propagation:
       ```rust
       // When building NatTraversalConfig from P2pConfig:
       .transport_registry(Arc::new(p2p_config.transport_registry.clone()))
       // or
       transport_registry: Some(Arc::new(config.transport_registry.clone())),
       ```

    In src/p2p_endpoint.rs:
    3. Find P2pEndpoint::new() around line 435-450 where NatTraversalEndpoint::new() is called

    4. Ensure the nat_config passed to NatTraversalEndpoint::new() includes the transport_registry:
       ```rust
       // The transport_registry should flow through nat_config
       // Verify nat_config.transport_registry is Some(...) when P2pConfig had a registry
       ```

    The key is ensuring the chain:
    P2pConfig.transport_registry → NatTraversalConfig.transport_registry → NatTraversalEndpoint.transport_registry

    Requirements:
    - Registry flows through config conversion
    - NO .unwrap() or .expect() in production code
    - Maintain backward compatibility (empty registry if none configured)
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic --lib
    cargo test --test transport_registry_flow
  </verify>
  <done>
    - P2pConfig.transport_registry flows to NatTraversalConfig
    - NatTraversalEndpoint receives the registry
    - Integration test from Task 1 passes
    - All tests pass, zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 8: Unit Tests for Socket Binding Logic</n>
  <activeForm>Writing unit tests for socket binding with registry</activeForm>
  <files>
    src/nat_traversal_api.rs
  </files>
  <estimated_lines>~50</estimated_lines>
  <depends>Task 6, Task 7</depends>
  <action>
    Add unit tests verifying create_inner_endpoint() socket binding behavior with registry.

    Add tests to the tests module in nat_traversal_api.rs:

    ```rust
    #[tokio::test]
    async fn test_create_inner_endpoint_without_registry() {
        // Test that create_inner_endpoint works without registry (backward compat)
        let config = NatTraversalConfig::builder()
            .bind_addr(some_addr)
            .build();
        // Verify socket is created via direct binding
        // (Implementation depends on how we can test this)
    }

    #[tokio::test]
    async fn test_create_inner_endpoint_with_registry_no_udp_provider() {
        // Test fallback when registry has no UDP provider
        let registry = Arc::new(TransportRegistry::new());
        let config = NatTraversalConfig::builder()
            .transport_registry(registry)
            .bind_addr(some_addr)
            .build();
        // Should fall back to direct binding
    }

    // Additional test for registry with UDP provider if feasible
    ```

    Note: Full socket binding tests may require mocking or integration-level testing.
    Add what's testable at unit level.

    Requirements:
    - Test backward compatibility (no registry case)
    - Test fallback behavior (registry without UDP provider)
    - Use .unwrap() in tests (allowed per CLAUDE.md)
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic create_inner_endpoint
  </verify>
  <done>
    - Unit tests for socket binding logic pass
    - Backward compatibility verified
    - Zero warnings
  </done>
</task>

## Exit Criteria
- [ ] All 8 tasks complete
- [ ] Integration test from Task 1 passes
- [ ] All 1171+ tests passing
- [ ] Zero clippy warnings
- [ ] TransportRegistry flows: P2pEndpoint → NatTraversalConfig → NatTraversalEndpoint
- [ ] Code reviewed via /gsd:review
