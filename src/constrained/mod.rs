// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Constrained Protocol Engine for Low-Bandwidth Transports
//!
//! This module provides a lightweight protocol engine optimized for constrained
//! transports like BLE and LoRa that cannot run full QUIC. Unlike QUIC's 20+ byte
//! headers, the constrained protocol uses minimal 4-5 byte headers.
//!
//! # Architecture
//!
//! The constrained engine is organized into layers:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Application Layer                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ConstrainedTransport / ConstrainedHandle (transport.rs)    │
//! │  - Thread-safe wrapper with handle pattern                  │
//! │  - Async channel-based packet I/O                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ConstrainedEngineAdapter (adapter.rs)                      │
//! │  - TransportAddr ↔ SocketAddr mapping                       │
//! │  - Synthetic addresses for BLE/LoRa                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ConstrainedEngine (engine.rs)                              │
//! │  - Multi-connection management                              │
//! │  - Packet routing and event generation                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ConstrainedConnection (connection.rs)                      │
//! │  - Per-connection state and buffers                         │
//! │  - Send/receive with reliability                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ARQ Layer (arq.rs)                                         │
//! │  - SendWindow / ReceiveWindow                               │
//! │  - Retransmission and timeout handling                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  StateMachine (state.rs)                                    │
//! │  - Connection lifecycle states                              │
//! │  - Valid transition enforcement                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Header/Types (header.rs, types.rs)                         │
//! │  - 5-byte packet header format                              │
//! │  - Core type definitions                                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Design Goals
//!
//! - **Minimal overhead**: 4-5 byte headers vs QUIC's 20+ bytes
//! - **Simple reliability**: ARQ (Automatic Repeat Request) with cumulative ACKs
//! - **No congestion control**: Link layer handles congestion
//! - **Session resumption**: Integrates with BLE session cache
//! - **Low memory footprint**: Small window sizes (8-16 packets)
//! - **Transport agnostic**: Works with any `TransportAddr` type
//!
//! # Header Format
//!
//! ```text
//!  0       1       2       3       4
//! +-------+-------+-------+-------+-------+
//! |  CID (16b)    | SEQ   | ACK   | FLAGS |
//! +-------+-------+-------+-------+-------+
//! ```
//!
//! - **CID**: Connection ID (2 bytes) - identifies the connection
//! - **SEQ**: Sequence number (1 byte) - 0-255, wrapping
//! - **ACK**: Acknowledgment number (1 byte) - cumulative ACK
//! - **FLAGS**: Packet flags (1 byte) - SYN, ACK, FIN, RST, DATA, PING, PONG
//!
//! # Protocol Engine Selection
//!
//! Use [`ConstrainedTransport::should_use_constrained`] to determine whether
//! to use the constrained engine based on transport capabilities:
//!
//! | Capability | QUIC | Constrained |
//! |------------|------|-------------|
//! | Bandwidth | >= 10 kbps | < 10 kbps |
//! | MTU | >= 1200 bytes | < 1200 bytes |
//! | RTT | < 2 seconds | Any |
//!
//! # State Machine
//!
//! ```text
//!            SYN_SENT
//!               ↓
//! CLOSED → SYN_RCVD → ESTABLISHED → FIN_WAIT → CLOSING → TIME_WAIT → CLOSED
//!               ↑                      ↓
//!               └─────── RST ─────────┘
//! ```
//!
//! # Example: Using with TransportAddr
//!
//! ```rust,ignore
//! use ant_quic::constrained::{ConstrainedTransport, ConstrainedHandle};
//! use ant_quic::transport::TransportAddr;
//!
//! // Create transport for BLE
//! let transport = ConstrainedTransport::for_ble();
//! let handle = transport.handle();
//!
//! // Connect to a BLE device
//! let ble_addr = TransportAddr::Ble {
//!     device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
//!     service_uuid: None,
//! };
//! let conn_id = handle.connect(&ble_addr)?;
//!
//! // Send data
//! handle.send(conn_id, b"Hello, BLE!")?;
//!
//! // Process incoming packets and check for events
//! handle.process_incoming(&ble_addr, &received_data)?;
//! while let Some(event) = handle.next_event() {
//!     match event {
//!         AdapterEvent::DataReceived { connection_id, data } => {
//!             println!("Received: {:?}", data);
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Module Organization
//!
//! - `types` - Core types: ConnectionId, SequenceNumber, PacketFlags, ConstrainedError, ConstrainedAddr
//! - `header` - Packet header format and serialization
//! - `state` - Connection state machine
//! - `arq` - ARQ reliability layer (SendWindow, ReceiveWindow)
//! - `connection` - Connection management
//! - `engine` - Main protocol engine
//! - `adapter` - TransportAddr integration layer
//! - `transport` - Thread-safe transport wrapper

// Sub-modules
mod adapter;
mod arq;
mod connection;
mod engine;
mod header;
mod state;
mod transport;
mod types;

// Re-exports
pub use adapter::{AdapterEvent, ConstrainedEngineAdapter, EngineOutput};
pub use transport::{ConstrainedHandle, ConstrainedTransport, ConstrainedTransportConfig};
pub use arq::{ArqConfig, ReceiveWindow, SendWindow, DEFAULT_WINDOW_SIZE};
pub use connection::{
    ConnectionConfig, ConnectionEvent, ConnectionStats, ConstrainedConnection, DEFAULT_MSS,
    DEFAULT_MTU,
};
pub use engine::{ConstrainedEngine, EngineConfig, EngineEvent};
pub use header::{ConstrainedHeader, ConstrainedPacket, HEADER_SIZE};
pub use state::{ConnectionState, StateEvent, StateMachine};
pub use types::{
    ConnectionId, ConstrainedAddr, ConstrainedError, PacketFlags, PacketType, SequenceNumber,
};
