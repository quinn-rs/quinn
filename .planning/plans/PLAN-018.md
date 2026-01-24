# Phase 3.1b: Real BLE I/O Implementation

**Phase**: 3.1b
**Name**: Real BLE I/O Implementation
**Depends On**: Phase 3.1 (BLE GATT Architecture)
**Status**: Planning

---

## Overview

Phase 3.1 delivered BLE architecture/scaffolding but with simulated I/O operations. This phase implements **real btleplug integration** for actual BLE hardware communication.

The review of Phase 3.1 graded it D+ because real BLE I/O was missing despite being a success criterion. This phase addresses those gaps before Phase 3.2 (Fragmentation).

---

## Success Criteria

1. Real btleplug scanning with event-driven device discovery
2. Real btleplug connection with service/characteristic discovery
3. Real send via TX characteristic write (WriteType::WithoutResponse)
4. Real receive via RX characteristic notification subscription
5. Background tasks for scan events and notification handling
6. Store Peripheral references in BleConnection for operations
7. Zero warnings, all existing tests pass, new hardware tests

---

## Technical Analysis

### Current State (Simulated)

From Phase 3.1 review:
- `start_scanning()` - sets state only, no btleplug adapter code
- `connect_to_device()` - no `Peripheral::connect()` call
- `send()` - no `Peripheral::write()` call (comment: "simulated")
- `inbound()` - `process_notification()` never called
- `start_advertising()` - framework only, no GATT server

### Target State (Real)

- Scanning discovers devices via btleplug `Adapter::start_scan()` + event stream
- Connection establishes via `Peripheral::connect()` + `discover_services()`
- Send uses `Peripheral::write(tx_char, data, WriteType::WithoutResponse)`
- Receive via `Peripheral::subscribe(rx_char)` + background notification task
- Peripheral references stored in BleConnection for all operations

### btleplug APIs Required

```rust
use btleplug::api::{
    Central,           // For adapter operations
    Manager,           // For adapter discovery
    Peripheral,        // For device operations
    Characteristic,    // For GATT characteristics
    WriteType,         // For WriteType::WithoutResponse
    ScanFilter,        // For filtering by service UUID
    CentralEvent,      // For scan/connect events
};
```

---

## Tasks

### Task 1: Add Peripheral storage and btleplug imports
**Files**: `src/transport/ble.rs`
**Changes**:
- Add missing btleplug imports (Peripheral, Characteristic, WriteType, ScanFilter)
- Add `peripheral: Option<Arc<dyn Peripheral>>` to BleConnection struct
- Add `adapter: Option<Arc<dyn Central>>` to BleTransport struct
- Add method to store peripheral reference during connection

### Task 2: Implement real btleplug scanning
**Files**: `src/transport/ble.rs`
**Changes**:
- Update `start_scanning()` to call `adapter.start_scan(filter)`
- Add ScanFilter with ANT_QUIC_SERVICE_UUID
- Spawn background task to consume adapter events stream
- Handle CentralEvent::DeviceDiscovered to populate discovered_devices
- Extract RSSI, local_name, service data from peripheral properties

### Task 3: Implement real btleplug connection
**Files**: `src/transport/ble.rs`
**Changes**:
- Update `connect_to_device()` to call `peripheral.connect()`
- Call `peripheral.discover_services()` after connection
- Find ant-quic service by UUID
- Extract TX and RX characteristics from service
- Store peripheral reference and characteristic handles in BleConnection

### Task 4: Implement real characteristic write for send()
**Files**: `src/transport/ble.rs`
**Changes**:
- Update `send()` to retrieve peripheral from connection
- Get TX characteristic handle
- Call `peripheral.write(tx_char, data, WriteType::WithoutResponse)`
- Handle write errors (connection lost, characteristic not found)
- Update stats on success

### Task 5: Implement real notification receiving
**Files**: `src/transport/ble.rs`
**Changes**:
- Subscribe to RX characteristic during connection via `peripheral.subscribe(rx_char)`
- Spawn background task consuming `peripheral.notifications()` stream
- For each notification, call `process_notification(device_id, data)`
- Add bytes_received stats update in process_notification
- Store notification task handle for cleanup

### Task 6: Update stats and integrate session caching
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `bytes_received` increment in process_notification
- Call `lookup_session()` during connection to check for cached session
- Call `cache_session()` after successful new connection
- Use config fields: scan_interval, connection_timeout

---

## Platform Considerations

- **Linux**: Full central mode support, test first
- **macOS**: Full central mode, may need entitlements
- **Windows**: Experimental support, test after Linux/macOS
- **Peripheral mode**: Deferred (requires platform-specific GATT server)

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| btleplug API instability | Pin to version 0.11, test thoroughly |
| Platform differences | CI matrix with platform-specific tests |
| No BLE hardware in CI | Hardware tests marked `#[ignore]` |
| Connection timeouts | Implement retry with exponential backoff |

---

## Estimated Effort

- 6 tasks
- Complexity: High (async, platform-specific, hardware-dependent)
- Testing: Extend existing 42 tests, add hardware tests

---

## Files to Modify

- `src/transport/ble.rs` - Main implementation (all tasks)
- `tests/ble_transport.rs` - Additional integration tests

---
