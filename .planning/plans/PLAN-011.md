# Phase 1.1: Node → P2pEndpoint Wiring

## Overview
Pass TransportRegistry from NodeConfig through to P2pEndpoint, following existing patterns for how keypair and other fields flow through the configuration chain.

## Technical Decisions
- Breakdown approach: TDD - Integration test first
- Task size: Small (~50 lines, 1 file per task)
- Testing strategy: Integration test for full flow + Unit tests per component + Property tests
- Dependencies: Transport module must exist (it does), Blocks Phase 1.2
- Pattern: Follow existing keypair passing pattern through NodeConfig → P2pConfig → P2pEndpoint

## Task Complexity Summary (Anthropic Best Practice: Effort Scaling)

| Task | Est. Lines | Files | Complexity | Model |
|------|-----------|-------|------------|-------|
| Task 1 | ~60 | 1 | standard | sonnet |
| Task 2 | ~80 | 1 | standard | sonnet |
| Task 3 | ~50 | 1 | simple | haiku |
| Task 4 | ~60 | 1 | standard | sonnet |
| Task 5 | ~40 | 1 | simple | haiku |
| Task 6 | ~30 | 1 | simple | haiku |

**Complexity Guide:**
- `simple` (< 50 lines, 1 file) → haiku
- `standard` (50-200 lines, 1-2 files) → sonnet
- `complex` (> 200 lines, 3+ files, architectural) → opus

## Tasks

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 1: Integration Test for Transport Registry Flow</n>
  <activeForm>Writing integration test for transport registry flow</activeForm>
  <files>
    tests/transport_registry_flow.rs
  </files>
  <estimated_lines>~60</estimated_lines>
  <depends></depends>
  <action>
    Create a new integration test file that tests the full transport registry flow:

    1. Create `tests/transport_registry_flow.rs`
    2. Write test `test_transport_registry_flows_from_node_config_to_p2p_endpoint`:
       - Create a mock/test TransportProvider (or use UdpTransport)
       - Build NodeConfig with transport_provider()
       - Call Node::with_config()
       - Assert that P2pEndpoint has access to the registered transport

    The test should FAIL initially because:
    - P2pConfig doesn't have transport_registry field yet
    - P2pEndpoint doesn't store the registry yet
    - Node::with_config() doesn't pass it through yet

    This failing test defines the acceptance criteria for this phase.

    Requirements:
    - NO .unwrap() or .expect() in src/ (test code can use them)
    - Use tokio::test for async
    - Follow existing integration test patterns in tests/ directory
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --test transport_registry_flow -- --nocapture 2>&1 | grep -E "(FAILED|error\[)" || echo "Test fails as expected (TDD)"
  </verify>
  <done>
    - tests/transport_registry_flow.rs exists
    - Test compiles (may fail to run - that's expected for TDD)
    - Zero warnings in test file
    - Test documents expected behavior
  </done>
</task>

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 2: Add transport_registry to P2pConfig</n>
  <activeForm>Adding transport_registry field to P2pConfig</activeForm>
  <files>
    src/unified_config.rs
  </files>
  <estimated_lines>~80</estimated_lines>
  <depends>Task 1</depends>
  <action>
    Modify P2pConfig in src/unified_config.rs to include transport registry:

    1. Add import for TransportRegistry at top of file:
       `use crate::transport::{TransportProvider, TransportRegistry};`

    2. Add field to P2pConfig struct (~line 47-83):
       `pub transport_registry: TransportRegistry,`

    3. Update P2pConfig::default() to initialize with empty registry:
       `transport_registry: TransportRegistry::new(),`

    4. Add to P2pConfigBuilder struct:
       `transport_registry: Option<TransportRegistry>,`

    5. Add builder methods:
       ```rust
       /// Add a single transport provider to the registry
       pub fn transport_provider(mut self, provider: Arc<dyn TransportProvider>) -> Self {
           let registry = self.transport_registry.get_or_insert_with(TransportRegistry::new);
           registry.register(provider);
           self
       }

       /// Set the entire transport registry
       pub fn transport_registry(mut self, registry: TransportRegistry) -> Self {
           self.transport_registry = Some(registry);
           self
       }
       ```

    6. Update build() method to use the registry:
       `transport_registry: self.transport_registry.unwrap_or_default(),`

    Requirements:
    - NO .unwrap() or .expect() in the implementation (unwrap_or_default is OK)
    - Follow existing builder pattern exactly
    - Add doc comments to new methods
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic unified_config
  </verify>
  <done>
    - P2pConfig has transport_registry field
    - P2pConfigBuilder has transport_provider() method
    - P2pConfigBuilder has transport_registry() method
    - Default creates empty registry
    - All existing tests still pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 3: Unit Tests for P2pConfig Builder</n>
  <activeForm>Writing unit tests for P2pConfig transport builder</activeForm>
  <files>
    src/unified_config.rs
  </files>
  <estimated_lines>~50</estimated_lines>
  <depends>Task 2</depends>
  <action>
    Add unit tests in the existing tests module of src/unified_config.rs:

    1. Find the #[cfg(test)] mod tests section
    2. Add test: `test_p2p_config_builder_transport_provider`
       - Build config with transport_provider()
       - Assert registry has 1 provider
    3. Add test: `test_p2p_config_builder_transport_registry`
       - Create registry, add multiple providers
       - Build config with transport_registry()
       - Assert all providers present
    4. Add test: `test_p2p_config_default_has_empty_registry`
       - Assert P2pConfig::default().transport_registry.is_empty()

    Requirements:
    - Tests can use .unwrap() and .expect()
    - Use UdpTransport::bind() for real provider instances
    - Follow existing test patterns in the file
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic unified_config::tests
  </verify>
  <done>
    - 3+ new tests for transport registry builder
    - All tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="standard" model="sonnet">
  <n>Task 4: Store TransportRegistry in P2pEndpoint</n>
  <activeForm>Storing TransportRegistry in P2pEndpoint</activeForm>
  <files>
    src/p2p_endpoint.rs
  </files>
  <estimated_lines>~60</estimated_lines>
  <depends>Task 2</depends>
  <action>
    Modify P2pEndpoint to store and expose the transport registry:

    1. Add field to P2pEndpoint struct (~line 82-117):
       `transport_registry: Arc<TransportRegistry>,`
       (Use Arc for shared ownership - other components may need access)

    2. In P2pEndpoint::new() (~line 342-458):
       - Create Arc from config: `let transport_registry = Arc::new(config.transport_registry.clone());`
       - Or take ownership: consider if P2pConfig should give ownership
       - Store in struct initialization

    3. Add public accessor method:
       ```rust
       /// Returns the transport registry for this endpoint
       pub fn transport_registry(&self) -> &TransportRegistry {
           &self.transport_registry
       }
       ```

    4. Update Debug impl if needed to include transport_registry count

    Requirements:
    - NO .unwrap() or .expect() in implementation
    - Use Arc for shared ownership pattern
    - Follow existing accessor patterns (e.g., peer_id(), local_addr())
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic p2p_endpoint
  </verify>
  <done>
    - P2pEndpoint has transport_registry field
    - P2pEndpoint::new() stores registry from config
    - transport_registry() accessor method exists
    - All existing tests still pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 5: Unit Tests for P2pEndpoint Registry Storage</n>
  <activeForm>Writing unit tests for P2pEndpoint registry storage</activeForm>
  <files>
    src/p2p_endpoint.rs
  </files>
  <estimated_lines>~40</estimated_lines>
  <depends>Task 4</depends>
  <action>
    Add unit tests for P2pEndpoint transport registry storage:

    1. Find or create #[cfg(test)] mod tests section
    2. Add test: `test_p2p_endpoint_stores_transport_registry`
       - Create P2pConfig with transport provider
       - Create P2pEndpoint
       - Assert transport_registry() returns registry with provider
    3. Add test: `test_p2p_endpoint_default_config_empty_registry`
       - Create P2pEndpoint with default config
       - Assert transport_registry().is_empty()

    Requirements:
    - Tests can use .unwrap() and .expect()
    - Use tokio::test for async
    - May need to handle endpoint creation carefully (network binding)
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic p2p_endpoint::tests
  </verify>
  <done>
    - 2+ new tests for registry storage
    - All tests pass
    - Zero warnings
  </done>
</task>

<task type="auto" priority="p1" complexity="simple" model="haiku">
  <n>Task 6: Wire Node::with_config to Pass Registry</n>
  <activeForm>Wiring Node::with_config to pass transport registry</activeForm>
  <files>
    src/node.rs
  </files>
  <estimated_lines>~30</estimated_lines>
  <depends>Task 2, Task 4</depends>
  <action>
    Complete the wiring in Node::with_config():

    1. In Node::with_config() (~line 263-294), after copying other fields:
       ```rust
       // Pass transport registry from NodeConfig to P2pConfig
       p2p_config.transport_registry = config.build_transport_registry();
       ```

       OR use the builder pattern if P2pConfig uses builder in this context:
       ```rust
       let registry = config.build_transport_registry();
       // ... existing config setup ...
       p2p_config.transport_registry = registry;
       ```

    2. Verify the integration test from Task 1 now passes

    Requirements:
    - NO .unwrap() or .expect()
    - build_transport_registry() already exists on NodeConfig
    - Follow the exact pattern used for other fields (bind_addr, known_peers, keypair)
  </action>
  <verify>
    cargo fmt --all -- --check
    cargo clippy -p ant-quic -- -D warnings
    cargo test -p ant-quic
    cargo test --test transport_registry_flow
  </verify>
  <done>
    - Node::with_config() passes transport_providers to P2pConfig
    - Integration test from Task 1 passes
    - All unit tests pass
    - Zero warnings
    - Full registry flow working: NodeConfig → P2pConfig → P2pEndpoint
  </done>
</task>

## Exit Criteria
- [ ] All 6 tasks complete
- [ ] Integration test passes (transport registry flows end-to-end)
- [ ] All unit tests pass
- [ ] Zero clippy warnings
- [ ] Code reviewed via /review
- [ ] TransportRegistry accessible from P2pEndpoint
