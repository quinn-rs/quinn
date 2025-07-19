//! Core QUIC transport layer
//!
//! This module contains the essential QUIC protocol functionality needed for NAT traversal.
//! It is streamlined to include only the necessary components for the ant-quic implementation.

// Re-export essential types from the core QUIC implementation
pub use crate::connection::{
    Connection as QuicConnection,
    ConnectionError,
    ConnectionStats,
    Event as ConnectionEvent,
    PathStats,
    ShouldTransmit,
};

pub use crate::endpoint::{
    Endpoint as QuicEndpoint,
    ConnectionHandle,
    Incoming,
    AcceptError,
    ConnectError,
};

pub use crate::shared::{ConnectionId, EcnCodepoint};
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};
pub use crate::transport_parameters;

// Stream-related types
pub use crate::connection::{
    SendStream,
    RecvStream,
    Streams,
    StreamEvent,
    ReadError,
    WriteError,
    FinishError,
};

// Module-private imports
