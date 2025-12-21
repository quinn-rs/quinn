# Claude Code Implementation Prompt: MASQUE Relay for ant-quic

## Task Overview

Implement MASQUE CONNECT-UDP Bind relay functionality in ant-quic to enable fully connectable P2P nodes. This implementation follows draft-ietf-masque-connect-udp-listen-10 and integrates with the existing QUIC-native NAT traversal.

## Context

You are working on `ant-quic`, a QUIC transport library with 100% post-quantum cryptography. The project is located at `~/Desktop/Devel/projects/ant-quic`.

### Key Files to Reference

Before starting, read these files to understand the existing architecture:

```bash
# Core architecture
cat src/relay/mod.rs
cat src/relay/connection.rs
cat src/relay/session_manager.rs

# NAT traversal
cat src/nat_traversal/frames.rs
cat src/nat_traversal_api.rs

# Frame encoding
cat src/frame.rs
cat src/coding.rs
cat src/varint.rs

# Documentation
cat ARCHITECTURE.md
cat API_GUIDE.md
```

### IETF Specifications in `rfcs/`

- `draft-seemann-quic-nat-traversal-02.txt` - NAT traversal frames
- `rfc9000.txt` - QUIC base specification

## Implementation Instructions

### Phase 1: Create MASQUE Capsule Types

**Create `src/masque/capsule.rs`:**

```rust
// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL-3.0

//! HTTP Capsule Protocol types for MASQUE CONNECT-UDP Bind
//!
//! Implements capsules per draft-ietf-masque-connect-udp-listen-10:
//! - COMPRESSION_ASSIGN (0x11)
//! - COMPRESSION_ACK (0x12) 
//! - COMPRESSION_CLOSE (0x13)

use bytes::{Buf, BufMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::coding::{self, Codec};
use crate::varint::VarInt;

/// Capsule type identifiers per draft-ietf-masque-connect-udp-listen-10
pub const CAPSULE_COMPRESSION_ASSIGN: u64 = 0x11;
pub const CAPSULE_COMPRESSION_ACK: u64 = 0x12;
pub const CAPSULE_COMPRESSION_CLOSE: u64 = 0x13;

/// COMPRESSION_ASSIGN Capsule
/// 
/// Registers a Context ID for either uncompressed or compressed operation.
/// IP Version 0 = uncompressed (no IP/port follows)
/// IP Version 4 = IPv4 compressed context
/// IP Version 6 = IPv6 compressed context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAssign {
    /// Context ID (clients allocate even, servers allocate odd)
    pub context_id: VarInt,
    /// IP Version: 0 = uncompressed, 4 = IPv4, 6 = IPv6
    pub ip_version: u8,
    /// Target IP address (None if ip_version == 0)
    pub ip_address: Option<IpAddr>,
    /// Target UDP port in network byte order (None if ip_version == 0)
    pub udp_port: Option<u16>,
}

impl CompressionAssign {
    /// Create an uncompressed context registration
    pub fn uncompressed(context_id: VarInt) -> Self {
        Self {
            context_id,
            ip_version: 0,
            ip_address: None,
            udp_port: None,
        }
    }
    
    /// Create a compressed context for IPv4 target
    pub fn compressed_v4(context_id: VarInt, addr: Ipv4Addr, port: u16) -> Self {
        Self {
            context_id,
            ip_version: 4,
            ip_address: Some(IpAddr::V4(addr)),
            udp_port: Some(port),
        }
    }
    
    /// Create a compressed context for IPv6 target  
    pub fn compressed_v6(context_id: VarInt, addr: Ipv6Addr, port: u16) -> Self {
        Self {
            context_id,
            ip_version: 6,
            ip_address: Some(IpAddr::V6(addr)),
            udp_port: Some(port),
        }
    }
    
    /// Check if this is an uncompressed context
    pub fn is_uncompressed(&self) -> bool {
        self.ip_version == 0
    }
}

impl Codec for CompressionAssign {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        
        if buf.remaining() < 1 {
            return Err(coding::UnexpectedEnd);
        }
        let ip_version = buf.get_u8();
        
        let (ip_address, udp_port) = if ip_version == 0 {
            (None, None)
        } else {
            let ip = match ip_version {
                4 => {
                    if buf.remaining() < 4 {
                        return Err(coding::UnexpectedEnd);
                    }
                    let mut octets = [0u8; 4];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    if buf.remaining() < 16 {
                        return Err(coding::UnexpectedEnd);
                    }
                    let mut octets = [0u8; 16];
                    buf.copy_to_slice(&mut octets);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(coding::UnexpectedEnd),
            };
            
            if buf.remaining() < 2 {
                return Err(coding::UnexpectedEnd);
            }
            let port = buf.get_u16();
            
            (Some(ip), Some(port))
        };
        
        Ok(Self {
            context_id,
            ip_version,
            ip_address,
            udp_port,
        })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
        buf.put_u8(self.ip_version);
        
        if let (Some(ip), Some(port)) = (&self.ip_address, self.udp_port) {
            match ip {
                IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
                IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
            }
            buf.put_u16(port);
        }
    }
}

/// COMPRESSION_ACK Capsule
///
/// Confirms registration of a Context ID received via COMPRESSION_ASSIGN
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAck {
    pub context_id: VarInt,
}

impl Codec for CompressionAck {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        Ok(Self { context_id })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
    }
}

/// COMPRESSION_CLOSE Capsule
///
/// Rejects a registration or closes an existing context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionClose {
    pub context_id: VarInt,
}

impl Codec for CompressionClose {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        Ok(Self { context_id })
    }
    
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.context_id.encode(buf);
    }
}

/// Generic capsule wrapper for encoding/decoding any capsule type
#[derive(Debug, Clone)]
pub enum Capsule {
    CompressionAssign(CompressionAssign),
    CompressionAck(CompressionAck),
    CompressionClose(CompressionClose),
    Unknown { capsule_type: VarInt, data: Vec<u8> },
}
```

### Phase 2: Create Context Manager

**Create `src/masque/context.rs`:**

```rust
//! Context ID management for MASQUE CONNECT-UDP Bind
//!
//! Per draft-ietf-masque-connect-udp-listen-10:
//! - Clients allocate even Context IDs
//! - Servers allocate odd Context IDs
//! - Context ID 0 is reserved for unextended UDP proxying
//! - Only one uncompressed context allowed at a time

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use crate::VarInt;

/// Context allocation and state management
pub struct ContextManager {
    /// Locally allocated contexts
    local_contexts: HashMap<VarInt, ContextInfo>,
    /// Remotely allocated contexts
    remote_contexts: HashMap<VarInt, ContextInfo>,
    /// Current uncompressed context (only one allowed)
    uncompressed_context: Option<VarInt>,
    /// Next local context ID to allocate
    next_local_id: u64,
    /// Whether we allocate even (client) or odd (server) IDs
    is_client: bool,
}

/// Information about a registered context
#[derive(Debug, Clone)]
pub struct ContextInfo {
    /// Target address (None for uncompressed)
    pub target: Option<SocketAddr>,
    /// Current state
    pub state: ContextState,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
}

/// Context lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextState {
    /// COMPRESSION_ASSIGN sent, awaiting ACK
    Pending,
    /// COMPRESSION_ACK received, context active
    Active,
    /// COMPRESSION_CLOSE sent or received
    Closing,
    /// Fully closed
    Closed,
}

impl ContextManager {
    /// Create a new context manager
    /// 
    /// `is_client`: true if we're the initiating endpoint (allocates even IDs)
    pub fn new(is_client: bool) -> Self {
        Self {
            local_contexts: HashMap::new(),
            remote_contexts: HashMap::new(),
            uncompressed_context: None,
            // Start at 2 for client (0 reserved), 1 for server
            next_local_id: if is_client { 2 } else { 1 },
            is_client,
        }
    }
    
    /// Allocate a new local context ID
    pub fn allocate_local(&mut self) -> Result<VarInt, ContextError> {
        let id = self.next_local_id;
        
        // Ensure we stay within VarInt bounds
        if id > VarInt::MAX.into_inner() {
            return Err(ContextError::IdSpaceExhausted);
        }
        
        // Increment by 2 to stay in our allocation space (even/odd)
        self.next_local_id += 2;
        
        Ok(VarInt::from_u64(id).unwrap())
    }
    
    /// Register a new uncompressed context
    pub fn register_uncompressed(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        if self.uncompressed_context.is_some() {
            return Err(ContextError::DuplicateUncompressed);
        }
        
        if context_id.into_inner() == 0 {
            return Err(ContextError::ReservedId);
        }
        
        let info = ContextInfo {
            target: None,
            state: ContextState::Pending,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        
        self.local_contexts.insert(context_id, info);
        self.uncompressed_context = Some(context_id);
        
        Ok(())
    }
    
    /// Register a new compressed context for a specific target
    pub fn register_compressed(
        &mut self,
        context_id: VarInt,
        target: SocketAddr,
    ) -> Result<(), ContextError> {
        // Check for duplicate target
        for (_, info) in self.local_contexts.iter().chain(self.remote_contexts.iter()) {
            if info.target == Some(target) && info.state != ContextState::Closed {
                return Err(ContextError::DuplicateTarget(target));
            }
        }
        
        let info = ContextInfo {
            target: Some(target),
            state: ContextState::Pending,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        
        self.local_contexts.insert(context_id, info);
        
        Ok(())
    }
    
    /// Handle received COMPRESSION_ACK
    pub fn handle_ack(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        let info = self.local_contexts.get_mut(&context_id)
            .ok_or(ContextError::UnknownContext)?;
        
        if info.state != ContextState::Pending {
            return Err(ContextError::InvalidState);
        }
        
        info.state = ContextState::Active;
        info.last_activity = Instant::now();
        
        Ok(())
    }
    
    /// Close a context
    pub fn close(&mut self, context_id: VarInt) -> Result<(), ContextError> {
        if let Some(info) = self.local_contexts.get_mut(&context_id) {
            info.state = ContextState::Closed;
        } else if let Some(info) = self.remote_contexts.get_mut(&context_id) {
            info.state = ContextState::Closed;
        } else {
            return Err(ContextError::UnknownContext);
        }
        
        if self.uncompressed_context == Some(context_id) {
            self.uncompressed_context = None;
        }
        
        Ok(())
    }
    
    /// Look up context by target address
    pub fn get_by_target(&self, target: SocketAddr) -> Option<VarInt> {
        for (id, info) in self.local_contexts.iter().chain(self.remote_contexts.iter()) {
            if info.target == Some(target) && info.state == ContextState::Active {
                return Some(*id);
            }
        }
        None
    }
    
    /// Get the uncompressed context ID if available
    pub fn uncompressed(&self) -> Option<VarInt> {
        self.uncompressed_context.filter(|id| {
            self.local_contexts.get(id)
                .or_else(|| self.remote_contexts.get(id))
                .map(|i| i.state == ContextState::Active)
                .unwrap_or(false)
        })
    }
}

/// Context management errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ContextError {
    #[error("context ID space exhausted")]
    IdSpaceExhausted,
    #[error("only one uncompressed context allowed")]
    DuplicateUncompressed,
    #[error("context ID 0 is reserved")]
    ReservedId,
    #[error("duplicate target address: {0}")]
    DuplicateTarget(SocketAddr),
    #[error("unknown context ID")]
    UnknownContext,
    #[error("invalid context state for operation")]
    InvalidState,
}
```

### Phase 3: Create Datagram Encoding

**Create `src/masque/datagram.rs`:**

```rust
//! HTTP Datagram encoding for MASQUE CONNECT-UDP Bind
//!
//! Two formats:
//! 1. Uncompressed: [Context ID][IP Version][IP Address][UDP Port][Payload]
//! 2. Compressed: [Context ID][Payload] (context provides target)

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use crate::coding::{self, Codec};
use crate::VarInt;

/// Uncompressed datagram format
#[derive(Debug, Clone)]
pub struct UncompressedDatagram {
    pub context_id: VarInt,
    pub target: SocketAddr,
    pub payload: Bytes,
}

/// Compressed datagram format  
#[derive(Debug, Clone)]
pub struct CompressedDatagram {
    pub context_id: VarInt,
    pub payload: Bytes,
}

impl UncompressedDatagram {
    pub fn new(context_id: VarInt, target: SocketAddr, payload: Bytes) -> Self {
        Self { context_id, target, payload }
    }
    
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        self.context_id.encode(&mut buf);
        
        match self.target.ip() {
            IpAddr::V4(v4) => {
                buf.put_u8(4);
                buf.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u8(6);
                buf.put_slice(&v6.octets());
            }
        }
        
        buf.put_u16(self.target.port());
        buf.put_slice(&self.payload);
        
        buf.freeze()
    }
    
    pub fn decode(buf: &mut impl Buf) -> coding::Result<Self> {
        let context_id = VarInt::decode(buf)?;
        
        let ip_version = buf.get_u8();
        let ip = match ip_version {
            4 => {
                if buf.remaining() < 4 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut octets = [0u8; 4];
                buf.copy_to_slice(&mut octets);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if buf.remaining() < 16 {
                    return Err(coding::UnexpectedEnd);
                }
                let mut octets = [0u8; 16];
                buf.copy_to_slice(&mut octets);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(coding::UnexpectedEnd),
        };
        
        if buf.remaining() < 2 {
            return Err(coding::UnexpectedEnd);
        }
        let port = buf.get_u16();
        
        let payload = buf.copy_to_bytes(buf.remaining());
        
        Ok(Self {
            context_id,
            target: SocketAddr::new(ip, port),
            payload,
        })
    }
}

impl CompressedDatagram {
    pub fn new(context_id: VarInt, payload: Bytes) -> Self {
        Self { context_id, payload }
    }
    
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.context_id.encode(&mut buf);
        buf.put_slice(&self.payload);
        buf.freeze()
    }
}
```

### Phase 4: Create Module Root

**Create `src/masque/mod.rs`:**

```rust
//! MASQUE CONNECT-UDP Bind Protocol Implementation
//!
//! This module implements the MASQUE relay mechanism per
//! draft-ietf-masque-connect-udp-listen-10 for enabling
//! fully connectable P2P nodes.

pub mod capsule;
pub mod context;
pub mod datagram;

pub use capsule::{
    Capsule, CompressionAssign, CompressionAck, CompressionClose,
    CAPSULE_COMPRESSION_ASSIGN, CAPSULE_COMPRESSION_ACK, CAPSULE_COMPRESSION_CLOSE,
};
pub use context::{ContextManager, ContextInfo, ContextState, ContextError};
pub use datagram::{UncompressedDatagram, CompressedDatagram};
```

### Phase 5: Update lib.rs

Add to `src/lib.rs`:

```rust
pub mod masque;
```

## Testing Requirements

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_context_allocation_client() {
        let mut mgr = ContextManager::new(true);
        let id1 = mgr.allocate_local().unwrap();
        assert_eq!(id1.into_inner(), 2); // Client starts at 2 (even)
        let id2 = mgr.allocate_local().unwrap();
        assert_eq!(id2.into_inner(), 4);
    }
    
    #[test]
    fn test_context_allocation_server() {
        let mut mgr = ContextManager::new(false);
        let id1 = mgr.allocate_local().unwrap();
        assert_eq!(id1.into_inner(), 1); // Server starts at 1 (odd)
    }
    
    #[test]
    fn test_uncompressed_context_limit() {
        let mut mgr = ContextManager::new(true);
        let id = mgr.allocate_local().unwrap();
        mgr.register_uncompressed(id).unwrap();
        
        let id2 = mgr.allocate_local().unwrap();
        assert!(mgr.register_uncompressed(id2).is_err());
    }
}
```

## Verification Checklist

- [ ] All capsule types encode/decode correctly
- [ ] Context manager enforces allocation rules (even/odd)
- [ ] Only one uncompressed context allowed
- [ ] Datagram encoding matches spec
- [ ] Unit tests pass
- [ ] `cargo clippy` has no warnings
- [ ] `cargo fmt` applied

## References

- draft-ietf-masque-connect-udp-listen-10
- RFC 9298 (CONNECT-UDP)
- RFC 9297 (HTTP Datagrams)

## Notes

- All cryptographic operations MUST use ML-KEM-768 and ML-DSA-65
- No classical algorithm fallback
- Integrate with existing rate limiting and authentication
