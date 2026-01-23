# ant-quic Multi-Transport Core Roadmap

## Milestone: Multi-Transport Abstraction Layer

Extend the multi-transport core from `docs/research/CONSTRAINED_TRANSPORTS.md:233-964` into production code.

## Overview

Implement a transport abstraction layer that enables ant-quic to operate over multiple physical mediums beyond UDP/IP, including BLE, LoRa, serial links, and overlay networks, while maintaining pure PQC security.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION                                   │
│                    (Node, P2pEndpoint, higher layers)                   │
├─────────────────────────────────────────────────────────────────────────┤
│                          ant-quic API                                    │
│         P2pEndpoint, Streams, Datagrams, Connection Events              │
├─────────────────────────────────────────────────────────────────────────┤
│                        PROTOCOL ENGINES                                  │
│   ┌─────────────────────┐     ┌─────────────────────────────────────┐   │
│   │    QUIC Engine      │     │      Constrained Engine             │   │
│   │  • Full RFC 9000    │     │  • Minimal headers (4-8 bytes)      │   │
│   │  • Quinn-based      │     │  • ARQ reliability                  │   │
│   └─────────────────────┘     └─────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────┤
│                      TRANSPORT ABSTRACTION                               │
│                      (TransportProvider trait)                           │
│   ┌───────┬───────┬────────┬───────┬───────────────────────────────┐    │
│   │  UDP  │ BLE   │ Serial │ LoRa  │  Future Transports...         │    │
│   └───────┴───────┴────────┴───────┴───────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Phase 1: Transport Abstraction Foundation

### Tasks

1. **Create Transport Module Structure**
   - `src/transport/mod.rs` - Module exports and orchestration
   - `src/transport/addr.rs` - TransportAddr enum
   - `src/transport/capabilities.rs` - TransportCapabilities struct
   - `src/transport/provider.rs` - TransportProvider trait

2. **Implement TransportAddr**
   - UDP (SocketAddr)
   - BLE (device_id + service_uuid)
   - Serial (port name)
   - LoRa (device_addr + channel params)
   - Broadcast variant

3. **Implement TransportCapabilities**
   - Bandwidth (bps)
   - MTU
   - RTT (typical/max)
   - Half-duplex flag
   - Broadcast support
   - Metered/power-constrained flags
   - Predefined profiles: broadband(), ble(), lora_long_range(), etc.

4. **Implement TransportProvider Trait**
   ```rust
   #[async_trait]
   pub trait TransportProvider: Send + Sync + 'static {
       fn name(&self) -> &str;
       fn transport_type(&self) -> TransportType;
       fn capabilities(&self) -> &TransportCapabilities;
       fn local_addr(&self) -> Option<TransportAddr>;
       async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError>;
       fn inbound(&self) -> mpsc::Receiver<InboundDatagram>;
       fn is_online(&self) -> bool;
       async fn shutdown(&self) -> Result<(), TransportError>;
   }
   ```

5. **Protocol Engine Selector**
   - QUIC engine for capable transports (bandwidth >= 10kbps, MTU >= 1200, RTT < 2s)
   - Constrained engine for limited transports

## Phase 2: Transport Registry on NodeConfig

### Tasks

1. **Extend NodeConfig**
   - Add `transport_providers: Vec<Arc<dyn TransportProvider>>`
   - Default to UDP transport (current behavior)
   - Builder methods for adding providers

2. **Propagate Capabilities**
   - Include transport capabilities in peer advertisements
   - Update routing tables with transport information

## Phase 3: BLE Transport Provider (Feature-Gated)

### Tasks

1. **Add Feature Flag**
   - `ble` feature in Cargo.toml
   - Conditional compilation for BLE code

2. **Implement BLE Provider**
   - Use BlueZ/bluer for Linux
   - MTU: 244 bytes (BLE 4.2)
   - Bandwidth: 125 kbps typical
   - RTT: 100ms typical
   - Link-layer ACKs: true

3. **PQC Mitigations**
   - Aggressive session caching (24+ hours)
   - Resume tokens (32 bytes vs 8KB handshake)
   - Key pre-distribution via propagation nodes

## Phase 4: Diagnostics and Testing

### Tasks

1. **Transport Diagnostics**
   - Current RTT per transport
   - Bandwidth class (constrained/broadband)
   - Active protocol engine
   - Link quality metrics

2. **Test Coverage**
   - UDP-only build tests
   - BLE-enabled build tests
   - Feature flag isolation
   - Integration tests with mock transports

## Deliverables

1. `src/transport/mod.rs` - Core module
2. `src/transport/addr.rs` - Transport addressing
3. `src/transport/capabilities.rs` - Capability profiles
4. `src/transport/provider.rs` - Provider trait
5. `src/transport/udp.rs` - UDP implementation
6. `src/transport/ble.rs` - BLE implementation (feature-gated)
7. `src/transport/diagnostics.rs` - Runtime diagnostics
8. Updated `NodeConfig` with transport registry

## Success Criteria

- [ ] `cargo build` compiles with default features
- [ ] `cargo build --features ble` compiles on Linux
- [ ] `cargo test` passes all existing tests
- [ ] `cargo test --all-features` passes on supported platforms
- [ ] Zero clippy warnings
- [ ] Zero compilation warnings
- [ ] All public APIs documented
