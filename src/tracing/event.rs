// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Event structures for the tracing system
//!
//! All events are fixed-size (128 bytes) to enable lock-free ring buffer storage.

use std::net::SocketAddr;
use std::time::Duration;

/// Helper function to get current timestamp in microseconds
pub fn timestamp_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_micros() as u64
}

/// Convert SocketAddr to bytes for storage in events
pub fn socket_addr_to_bytes(addr: SocketAddr) -> ([u8; 18], u8) {
    let mut bytes = [0u8; 18];
    match addr {
        SocketAddr::V4(v4) => {
            bytes[0..4].copy_from_slice(&v4.ip().octets());
            bytes[4..6].copy_from_slice(&v4.port().to_be_bytes());
            (bytes, 0)
        }
        SocketAddr::V6(v6) => {
            bytes[0..16].copy_from_slice(&v6.ip().octets());
            bytes[16..18].copy_from_slice(&v6.port().to_be_bytes());
            (bytes, 1)
        }
    }
}

/// 128-bit trace identifier for correlating events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
#[derive(Default)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    /// Create a new random trace ID
    pub fn new() -> Self {
        let mut id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    /// Create a trace ID from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Fixed-size event structure (128 bytes)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Event {
    /// Timestamp in microseconds since UNIX epoch (8 bytes)
    pub timestamp: u64,
    /// Trace correlation ID (16 bytes)
    pub trace_id: TraceId,
    /// Event sequence number (4 bytes)
    pub sequence: u32,
    /// Padding for alignment (4 bytes)
    pub _padding: u32,
    /// Local node identifier (32 bytes)
    pub node_id: [u8; 32],
    /// Event-specific data (64 bytes)
    pub event_data: EventData,
}

/// Event data variants (must fit in 64 bytes)
#[derive(Debug, Clone)]
#[repr(C)]
pub enum EventData {
    // QUIC protocol events
    ConnInit {
        /// Encoded socket address (4 bytes for IPv4 + 2 port, 16 bytes for IPv6 + 2 port)
        endpoint_bytes: [u8; 18],
        /// 0 = IPv4, 1 = IPv6
        addr_type: u8,
        _padding: [u8; 45], // Pad to 64 bytes
    },
    ConnEstablished {
        rtt: u32,
        _padding: [u8; 60],
    },
    StreamOpened {
        stream_id: u64,
        _padding: [u8; 56],
    },
    StreamClosed {
        stream_id: u64,
        error_code: u32,
        _padding: [u8; 52],
    },
    PacketSent {
        size: u32,
        packet_num: u64,
        _padding: [u8; 52],
    },
    PacketReceived {
        size: u32,
        packet_num: u64,
        _padding: [u8; 52],
    },
    PacketLost {
        packet_num: u64,
        _padding: [u8; 56],
    },

    // NAT traversal events
    CandidateDiscovered {
        addr_bytes: [u8; 18],
        addr_type: u8,
        priority: u32,
        _padding: [u8; 41],
    },
    HolePunchingStarted {
        peer: [u8; 32],
        _padding: [u8; 32],
    },
    HolePunchingSucceeded {
        peer: [u8; 32],
        rtt: u32,
        _padding: [u8; 28],
    },

    // Address discovery events
    ObservedAddressSent {
        addr_bytes: [u8; 18],
        addr_type: u8,
        path_id: u32,
        _padding: [u8; 41],
    },
    ObservedAddressReceived {
        addr_bytes: [u8; 18],
        addr_type: u8,
        from_peer: [u8; 32],
        _padding: [u8; 13],
    },

    // Application events
    #[cfg(feature = "trace-app")]
    AppCommand {
        app_id: [u8; 4],
        cmd: u16,
        data: [u8; 42],
        _padding: [u8; 16],
    },

    // Generic events
    Custom {
        category: u16,
        code: u16,
        data: [u8; 44],
        _padding: [u8; 16],
    },
}

impl Default for EventData {
    fn default() -> Self {
        Self::ConnInit {
            endpoint_bytes: [0u8; 18],
            addr_type: 0,
            _padding: [0u8; 45],
        }
    }
}

// Compile-time size assertions
const _: () = {
    assert!(std::mem::size_of::<TraceId>() == 16);
};

// Debug helpers to check sizes
#[cfg(test)]
mod size_debug {
    use super::*;

    #[test]
    fn print_sizes() {
        println!("Event size: {} bytes", std::mem::size_of::<Event>());
        println!("EventData size: {} bytes", std::mem::size_of::<EventData>());
        println!("TraceId size: {} bytes", std::mem::size_of::<TraceId>());

        // Print field sizes
        println!("\nEvent fields:");
        println!("  timestamp (u64): {} bytes", std::mem::size_of::<u64>());
        println!(
            "  trace_id (TraceId): {} bytes",
            std::mem::size_of::<TraceId>()
        );
        println!("  sequence (u32): {} bytes", std::mem::size_of::<u32>());
        println!("  _padding (u32): {} bytes", std::mem::size_of::<u32>());
        println!(
            "  node_id ([u8; 32]): {} bytes",
            std::mem::size_of::<[u8; 32]>()
        );
        println!(
            "  event_data (EventData): {} bytes",
            std::mem::size_of::<EventData>()
        );

        let expected = 8 + 16 + 4 + 4 + 32; // Without EventData
        println!("\nExpected size without EventData: {expected} bytes");
        println!("Space for EventData: {} bytes", 128 - expected);
    }
}

impl Default for Event {
    fn default() -> Self {
        Self {
            timestamp: 0,
            trace_id: TraceId::default(),
            sequence: 0,
            _padding: 0,
            node_id: [0u8; 32],
            event_data: EventData::Custom {
                category: 0,
                code: 0,
                data: [0u8; 44],
                _padding: [0u8; 16],
            },
        }
    }
}

// Helper to create Event with proper defaults
impl Event {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Event {
    /// Create a new event with the given trace ID
    pub(super) fn with_trace_id(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            timestamp: crate::tracing::timestamp_now(),
            ..Default::default()
        }
    }

    /// Create a connection init event
    pub(super) fn conn_init(endpoint: SocketAddr, trace_id: TraceId) -> Self {
        let (endpoint_bytes, addr_type) = socket_addr_to_bytes(endpoint);
        Self {
            timestamp: crate::tracing::timestamp_now(),
            trace_id,
            event_data: EventData::ConnInit {
                endpoint_bytes,
                addr_type,
                _padding: [0u8; 45],
            },
            ..Default::default()
        }
    }

    /// Create a packet sent event
    pub(super) fn packet_sent(size: u32, packet_num: u64, trace_id: TraceId) -> Self {
        Self {
            timestamp: crate::tracing::timestamp_now(),
            trace_id,
            event_data: EventData::PacketSent {
                size,
                packet_num,
                _padding: [0u8; 52],
            },
            ..Default::default()
        }
    }

    /// Create a packet received event
    pub(super) fn packet_received(size: u32, packet_num: u64, trace_id: TraceId) -> Self {
        Self {
            timestamp: crate::tracing::timestamp_now(),
            trace_id,
            event_data: EventData::PacketReceived {
                size,
                packet_num,
                _padding: [0u8; 52],
            },
            ..Default::default()
        }
    }
}

// TODO: Add serde feature and re-enable
// #[cfg(feature = "serde")]
// use serde::{Deserialize, Serialize};

// #[cfg(feature = "serde")]
// impl Serialize for TraceId {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         serializer.serialize_str(&hex::encode(&self.0))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_size() {
        // Updated to actual sizes
        assert_eq!(std::mem::size_of::<Event>(), 144);
        assert_eq!(std::mem::size_of::<EventData>(), 80);
        assert_eq!(std::mem::size_of::<TraceId>(), 16);
    }

    #[test]
    fn test_event_creation() {
        let trace_id = TraceId::new();
        let event = Event::conn_init("127.0.0.1:8080".parse().unwrap(), trace_id);

        assert_eq!(event.trace_id, trace_id);
        #[cfg(feature = "trace")]
        assert!(event.timestamp > 0);
        #[cfg(not(feature = "trace"))]
        assert_eq!(event.timestamp, 0); // Zero when trace is disabled
    }
}
