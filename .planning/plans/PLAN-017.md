# Phase 3.1: BLE GATT Implementation

**Phase**: 3.1
**Name**: BLE GATT Implementation
**Depends On**: Milestone 2 (Address Migration)
**Status**: Planning

---

## Overview

Implement the actual BLE GATT service and characteristic definitions for P2P data transfer, including peripheral mode (advertising, accepting connections) and central mode (scanning, connecting).

Currently, `BleTransport` has the basic structure with btleplug integration started, session caching, and TransportProvider trait implementation - but send/receive are simulated. This phase implements real BLE communication.

---

## Success Criteria

1. GATT service with data transfer characteristic defined
2. Peripheral mode: advertise service, accept connections, receive data
3. Central mode: scan for services, connect to peers, send data
4. Real send/receive through btleplug (not simulated)
5. Platform support: Linux (BlueZ), macOS (Core Bluetooth), Windows (WinRT)
6. Connection management and lifecycle
7. Zero warnings, comprehensive tests

---

## Technical Analysis

### Current State

- `BleTransport` struct exists with btleplug manager initialization
- Session caching for PQC mitigation implemented
- `TransportProvider` trait implemented but `send()` and `inbound()` are stubs
- Platform detection via `#[cfg]` attributes
- UUIDs defined but no GATT characteristics

### Target State

- Complete GATT service with write and notify characteristics
- Background tasks for peripheral advertising and central scanning
- Real data transfer through btleplug characteristic writes
- Inbound datagram channel fed by characteristic notifications
- Connection pool management

### GATT Architecture

```
┌─────────────────────────────────────────────────┐
│           ant-quic BLE Service                  │
│  UUID: a03d7e9f-0bca-12fe-a600-000000000001    │
├─────────────────────────────────────────────────┤
│  TX Characteristic (Write Without Response)    │
│  UUID: a03d7e9f-0bca-12fe-a600-000000000002    │
│  - Central writes to send data to peripheral   │
├─────────────────────────────────────────────────┤
│  RX Characteristic (Notify)                    │
│  UUID: a03d7e9f-0bca-12fe-a600-000000000003    │
│  - Peripheral notifies to send data to central │
└─────────────────────────────────────────────────┘
```

---

## Tasks

### Task 1: Define GATT characteristic UUIDs and constants
**Files**: `src/transport/ble.rs`
**Changes**:
- Add TX_CHARACTERISTIC_UUID constant
- Add RX_CHARACTERISTIC_UUID constant
- Add CCCD_UUID for Client Characteristic Config Descriptor
- Add documentation for GATT architecture

### Task 2: Implement BLE connection handle abstraction
**Files**: `src/transport/ble.rs`
**Changes**:
- Create `BleConnection` struct to wrap btleplug Peripheral
- Store characteristic handles for read/write
- Track connection state (connecting, connected, disconnecting)
- Implement Drop for clean disconnection

### Task 3: Implement central mode scanning
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `start_scanning()` method
- Filter discovered peripherals by service UUID
- Maintain discovered_devices: HashMap<[u8; 6], PeripheralInfo>
- Add `stop_scanning()` method
- Add scan result callback/channel

### Task 4: Implement central mode connection
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `connect_to_device(device_id: [u8; 6])` method
- Discover services and characteristics on connect
- Subscribe to RX characteristic notifications
- Store connection in active_connections map
- Handle connection errors with retry logic

### Task 5: Implement real send via characteristic write
**Files**: `src/transport/ble.rs`
**Changes**:
- Update `send()` to use real btleplug write
- Look up connection by device_id
- Write to TX characteristic (write without response)
- Handle write errors and connection loss
- Update stats on success/failure

### Task 6: Implement inbound datagram channel
**Files**: `src/transport/ble.rs`
**Changes**:
- Create background task that receives notifications
- Parse notification data into InboundDatagram
- Send to inbound_tx channel
- Update `inbound()` to return real receiver
- Handle notification subscription errors

### Task 7: Implement peripheral mode (advertising)
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `BlePeripheral` struct (feature-gated, platform-specific)
- Start GATT server with service and characteristics
- Begin advertising with service UUID
- Handle incoming connections from centrals
- Note: btleplug has limited peripheral support

### Task 8: Implement connection pool management
**Files**: `src/transport/ble.rs`
**Changes**:
- Add ConnectionPool struct with max_connections limit
- Track connection lifecycle: pending, active, closing
- Implement connection eviction (LRU or priority-based)
- Handle disconnection events
- Reconnection logic for dropped connections

### Task 9: Add integration tests for BLE transport
**Files**: `tests/ble_transport.rs` (NEW)
**Changes**:
- Test central mode scanning (mock or real if hardware available)
- Test connection establishment
- Test send/receive roundtrip
- Test connection pool limits
- Test session resumption
- Add CI skip for tests requiring BLE hardware

### Task 10: Update documentation and examples
**Files**: `src/transport/ble.rs`, `examples/ble_chat.rs` (NEW)
**Changes**:
- Document GATT architecture in module docs
- Add usage examples for scanning and connecting
- Document platform-specific quirks
- Create example BLE chat application

---

## Platform Considerations

### Linux (BlueZ)
- Full central mode support
- Peripheral mode via D-Bus GATT server
- May require BlueZ 5.50+ for stable operation

### macOS (Core Bluetooth)
- Full central mode support
- Limited peripheral mode (app-level only)
- Entitlements required for background BLE

### Windows (WinRT)
- Central mode via UWP Bluetooth LE API
- Peripheral mode limited
- May need manifest declarations

---

## Backward Compatibility

- Existing BleConfig API unchanged
- New methods are additive
- Simulated mode available as fallback when btleplug unavailable
- Tests skip when no BLE hardware detected

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| btleplug peripheral support limited | Focus on central mode first, peripheral as extension |
| Platform-specific bugs | CI matrix with platform-specific tests |
| No BLE hardware in CI | Mock tests + hardware tests marked #[ignore] |
| Connection stability | Retry logic with exponential backoff |

---

## Estimated Effort

- 10 tasks
- Complexity: High (platform-specific, async, hardware-dependent)
- Testing: ~15 new tests, some requiring BLE hardware

