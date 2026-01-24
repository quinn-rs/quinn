# Phase 1.3: Multi-Transport Send/Receive Path

**Status**: In Progress
**Dependencies**: Phase 1.2 (TransportRegistry wired to NatTraversalEndpoint)
**Blocks**: Phase 2.1+ (address migration needs multi-transport working)

## Overview

Enable concurrent receive on all online transports and implement transport selection logic for sending. This phase makes the TransportRegistry actually functional - completing the wiring so that registered transports (UDP, BLE, etc.) are used for I/O operations.

## Success Criteria

- [ ] `TransportRegistry.online_providers()` iterator implemented
- [ ] Multi-transport listen: loop over all online providers in `create_inner_endpoint()`
- [ ] Transport selection: `P2pEndpoint::send()` chooses provider based on capabilities
- [ ] Backward compatible: single-UDP setups work unchanged
- [ ] Comprehensive tests: unit, integration, and property-based
- [ ] Zero warnings, zero clippy violations

## Tasks

### Task 1: Add TransportRegistry.online_providers() iterator
**File**: `src/transport/provider.rs`
**Estimate**: ~30 lines
**Prompt**:
```
Add `online_providers()` method to `TransportRegistry` that returns an iterator
over all registered providers where `is_online() == true`.

Implementation:
1. Add method to TransportRegistry impl block:
   ```rust
   pub fn online_providers(&self) -> impl Iterator<Item = Arc<dyn TransportProvider>> + '_
   ```
2. Use `self.providers.iter().filter(|p| p.is_online()).cloned()`
3. Document the method with usage example
4. Keep it simple - just filter and iterate

This is the foundation for multi-transport iteration throughout the stack.
```

### Task 2: Wire TransportRegistry through create_inner_endpoint
**File**: `src/nat_traversal_api.rs`
**Estimate**: ~40 lines
**Prompt**:
```
Pass `transport_registry` from `NatTraversalConfig` through to `create_inner_endpoint()`.
Extract the first online UDP transport to bind the QUIC endpoint.

Implementation:
1. In `create_inner_endpoint()` signature, accept `transport_registry: &TransportRegistry`
2. Find first UDP transport: `registry.online_providers().find(|p| p.transport_type() == TransportType::Udp)`
3. If found, extract socket via `p.local_addr()` or bind new socket
4. If no UDP provider, fall back to current `UdpSocket::bind()` behavior (backward compat)
5. Update call site in `NatTraversalEndpoint::new()` to pass `config.transport_registry`

Maintain backward compatibility - if no providers registered, use direct UDP binding.
```

### Task 3: Multi-transport listen in NatTraversalEndpoint::new
**File**: `src/nat_traversal_api.rs`
**Estimate**: ~60 lines
**Prompt**:
```
Loop over `registry.online_providers()` to bind/listen on all transports.
Spawn concurrent receive tasks for each transport.

Implementation:
1. After `create_inner_endpoint()`, iterate `config.transport_registry.online_providers()`
2. For each provider:
   - Skip if already handled (e.g., UDP used for QUIC endpoint)
   - Spawn tokio task to receive from `provider.inbound()` channel
   - Route inbound datagrams to appropriate handler (log for now, full routing in Phase 2.3)
3. Store task handles for cleanup on shutdown
4. Add debug logging: "Listening on {count} transports: {names}"

Note: Full multi-transport datagram routing requires address migration (Phase 2+).
For now, additional transports listen but defer to QUIC UDP path for actual packet processing.
```

### Task 4: Update P2pEndpoint::send() for transport selection
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~50 lines
**Prompt**:
```
Modify `send()` to select transport provider based on destination address type and
ProtocolEngine capabilities.

Implementation:
1. Check if peer uses non-UDP transport (future: query from connected_peers metadata)
2. For now: if connected via QUIC, use existing `connection.open_uni()` path (no change)
3. Add comment hook for future: "TODO: Select provider from transport_registry based on peer's advertised address"
4. Document the selection logic in method docs
5. Ensure backward compatibility - existing UDP QUIC connections work unchanged

This prepares the infrastructure. Full transport selection happens in Phase 2.3 when
addresses carry transport type information.
```

### Task 5: Update P2pEndpoint::recv() for multi-transport
**File**: `src/p2p_endpoint.rs`
**Estimate**: ~40 lines
**Prompt**:
```
Verify and document that `recv()` already handles datagrams from all transports via
the inner endpoint event system.

Implementation:
1. Review `recv()` method - it polls `inner.accept_bi()` which receives from all transports
2. Add documentation comment explaining multi-transport receive flow:
   - "Receives data from any connected peer, regardless of transport type"
   - "The inner NatTraversalEndpoint aggregates all transport inbound channels"
3. Verify timeout logic works correctly with multiple concurrent transports
4. Add trace logging: "Received {bytes} from {peer_id} via {transport_type}"

No functional changes needed - this is documentation and verification only.
```

### Task 6: Add TransportRegistry unit tests
**File**: `src/transport/provider.rs` (tests module)
**Estimate**: ~60 lines
**Prompt**:
```
Test `online_providers()` iteration, filtering, and registry behavior.

Tests:
1. `test_online_providers_filters_offline`: Register 3 providers (2 online, 1 offline),
   verify iterator returns only 2
2. `test_online_providers_empty_when_all_offline`: All providers offline, iterator empty
3. `test_get_provider_by_type`: Verify `get_provider(TransportType::Udp)` returns correct provider
4. `test_registry_default_includes_udp`: Verify `default_registry()` has at least UDP

Use the existing test utilities and mock providers from the transport module tests.
```

### Task 7: Add multi-transport integration tests
**File**: `tests/transport_registry_flow.rs`
**Estimate**: ~80 lines
**Prompt**:
```
End-to-end test with multiple transport providers, verifying concurrent send/receive.

Test scenario:
1. Create registry with UDP and mock BLE transport
2. Create two P2pEndpoint instances with the multi-transport registry
3. Connect peers and exchange data
4. Verify both transports show activity in stats
5. Shut down one transport mid-test, verify failover to remaining transport

This extends the existing `transport_registry_flow.rs` test file. Add as a new test
function `test_multi_transport_concurrent_io`.
```

### Task 8: Add property-based tests for transport selection
**File**: `tests/transport_selection_properties.rs` (new)
**Estimate**: ~50 lines
**Prompt**:
```
Proptest to verify transport selection logic under various capability profiles.

Properties to test:
1. `prop_transport_selection_deterministic`: Given same capabilities, always select same provider
2. `prop_online_filter_correct`: online_providers() never returns offline providers
3. `prop_registry_lookup_consistent`: get_provider() matches what online_providers() returns

Use proptest to generate random TransportCapabilities and provider online/offline states.
Verify invariants hold across all generated inputs.

Create new test file with standard proptest setup.
```

## Files Modified

- `src/transport/provider.rs` - Add `online_providers()` iterator
- `src/nat_traversal_api.rs` - Multi-transport listen, registry wiring
- `src/p2p_endpoint.rs` - Transport selection hooks, recv() docs
- `tests/transport_registry_flow.rs` - Integration tests
- `tests/transport_selection_properties.rs` - Property tests (new)

## Testing Strategy

- **Unit tests**: Registry iteration, provider filtering
- **Integration tests**: Multi-transport send/receive scenarios
- **Property tests**: Transport selection invariants
- **Backward compatibility**: Existing single-UDP setups must work unchanged

## Notes

- This phase focuses on infrastructure - full multi-transport routing requires Phase 2 (address migration)
- QUIC endpoint remains UDP-only (Quinn limitation) - other transports use constrained protocol (Phase 4)
- Maintains strict backward compatibility with existing code
