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
//! # Design Goals
//!
//! - **Minimal overhead**: 4-5 byte headers vs QUIC's 20+ bytes
//! - **Simple reliability**: ARQ (Automatic Repeat Request) with cumulative ACKs
//! - **No congestion control**: Link layer handles congestion
//! - **Session resumption**: Integrates with BLE session cache
//! - **Low memory footprint**: Small window sizes (8-16 packets)
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
//! The [`ProtocolEngine`](crate::transport::ProtocolEngine) enum determines
//! whether to use QUIC or the constrained engine based on transport capabilities:
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
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::constrained::{ConstrainedEngine, ConstrainedConfig};
//! use ant_quic::transport::BleTransport;
//!
//! // Create engine with BLE transport
//! let transport = BleTransport::new().await?;
//! let config = ConstrainedConfig::default();
//! let engine = ConstrainedEngine::new(transport, config);
//!
//! // Open a connection
//! let conn_id = engine.connect(device_addr).await?;
//!
//! // Send data
//! engine.send(conn_id, b"Hello, BLE!").await?;
//!
//! // Receive data
//! let data = engine.receive(conn_id).await?;
//! ```
//!
//! # Modules
//!
//! - [`types`] - Core types: ConnectionId, SequenceNumber, PacketFlags, ConstrainedError
//! - [`header`] - Packet header format and serialization
//! - [`state`] - Connection state machine
//! - [`arq`] - ARQ reliability layer
//! - [`connection`] - Connection management
//! - [`engine`] - Main protocol engine

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
