# Phase 3.3: BLE Session Caching

**Phase**: 3.3
**Name**: BLE Session Caching
**Depends On**: Phase 3.2 (BLE Fragmentation Integration)
**Status**: Planning

---

## Overview

Optimize PQC handshake overhead for BLE connections via session resumption. PQC handshakes are ~8KB which takes ~1 second on BLE's 125kbps bandwidth. Session caching allows reconnections using a 32-byte token instead.

Phase 3.2 delivered fragmentation. This phase makes repeated BLE connections fast by caching session keys.

---

## Success Criteria

1. Session lookup integrated into `connect_to_device()` flow
2. Automatic session caching after successful connections
3. Session persistence to disk (survives restarts)
4. Graceful fallback to full handshake on cache miss
5. Session pruning/expiry logic operational
6. Zero warnings, all existing tests pass, new tests

---

## Current State Analysis

**Already Implemented:**
- `CachedSession` struct with device_id, session_key, session_id, timestamps
- `ResumeToken` struct for 32-byte resumption token
- `lookup_session()` and `cache_session()` methods on BleTransport
- 24-hour default session_cache_duration in BleConfig
- Session cache stats (hits/misses)

**Missing:**
- Integration of lookup_session into connect_to_device flow
- Automatic cache_session after successful connection
- Persistence to disk
- Proper use of resumption token in connection establishment
- Touch/update last_active on session use
- Periodic cache cleanup

---

## Tasks

### Task 1: Integrate session lookup into connection flow
**Files**: `src/transport/ble.rs`
**Changes**:
- In `connect_to_device()`, call `lookup_session()` first
- If cache hit, use session for fast resumption path
- If cache miss, proceed with full connection (existing flow)
- Add `connection_type: SessionResumption | FullHandshake` tracking
- Update stats appropriately

### Task 2: Automatic session caching after connection
**Files**: `src/transport/ble.rs`
**Changes**:
- After successful connection establishment, extract session key
- Call `cache_session()` with derived session data
- Generate session_id from connection parameters
- Only cache for new connections (not resumed ones)

### Task 3: Session touch on activity
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `touch_session()` method to update last_active
- Call touch_session in `send()` and when receiving notifications
- Use last_active for LRU eviction decisions

### Task 4: Session persistence to disk
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `SessionPersistence` struct for file-based storage
- Add `persist_path` field to BleConfig (Option<PathBuf>)
- Load sessions from disk on transport creation
- Save sessions to disk periodically and on shutdown
- Use simple JSON or bincode format

### Task 5: Periodic session cleanup
**Files**: `src/transport/ble.rs`
**Changes**:
- Add `prune_expired_sessions()` method
- Remove sessions older than session_cache_duration
- Add optional max_sessions limit
- Call cleanup periodically (e.g., every 10 minutes)

### Task 6: Add session caching tests
**Files**: `src/transport/ble.rs`
**Changes**:
- Test session lookup integration in connect flow
- Test automatic caching after connection
- Test session expiry and cleanup
- Test persistence load/save
- Test graceful fallback on cache miss

---

## Technical Design

### Session Flow

```
connect_to_device(device_id)
    │
    ├─ lookup_session(device_id)
    │       │
    │       ├─ CACHE HIT → Use ResumeToken → Fast connection (~32 bytes)
    │       │                                      │
    │       │                                      └─ touch_session()
    │       │
    │       └─ CACHE MISS → Full PQC handshake (~8KB)
    │                              │
    │                              └─ cache_session()
    │
    └─ Return connection
```

### Persistence Format

```json
{
  "version": 1,
  "sessions": [
    {
      "device_id": "112233445566",
      "session_key_hash": "base64...",
      "session_id": 1234,
      "established_utc": "2026-01-24T12:00:00Z"
    }
  ]
}
```

Note: Store hash of session_key for security, not raw key. Raw key only in memory.

---

## Files to Modify

- `src/transport/ble.rs` - All changes in this file

---
