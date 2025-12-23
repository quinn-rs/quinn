//! Peer Registry Module
//!
//! This module provides a central registry for peer discovery in the ant-quic
//! network test infrastructure. Nodes register with the registry on startup,
//! receive a list of other peers, and maintain their registration via heartbeats.
//!
//! # Architecture
//!
//! ```text
//!                     ┌─────────────────────────┐
//!                     │    Registry Server      │
//!                     │    (saorsa-1)           │
//!                     │                         │
//!                     │  POST /api/register     │
//!                     │  POST /api/heartbeat    │
//!                     │  GET  /api/peers        │
//!                     │  GET  /api/stats        │
//!                     │  WS   /ws/live          │
//!                     └───────────┬─────────────┘
//!                                 │
//!         ┌───────────────────────┼───────────────────────┐
//!         │                       │                       │
//!         ▼                       ▼                       ▼
//!    ┌─────────┐            ┌─────────┐            ┌─────────┐
//!    │ Node A  │◄──────────►│ Node B  │◄──────────►│ Node C  │
//!    └─────────┘            └─────────┘            └─────────┘
//! ```
//!
//! # Usage
//!
//! ## Running as Registry Server
//!
//! ```bash
//! ant-quic --registry --port 8080
//! ```
//!
//! ## Connecting as a Node
//!
//! ```rust,ignore
//! use ant_quic::registry::{RegistryClient, NodeRegistration};
//!
//! let client = RegistryClient::new("https://quic.saorsalabs.com");
//!
//! // Register with the network
//! let registration = NodeRegistration { /* ... */ };
//! let response = client.register(&registration).await?;
//!
//! // Get list of peers to connect to
//! let peers = response.peers;
//!
//! // Send periodic heartbeats
//! let heartbeat = NodeHeartbeat { /* ... */ };
//! client.heartbeat(&heartbeat).await?;
//! ```

mod api;
mod store;
mod types;

// Re-export main types
pub use api::{RegistryClient, RegistryConfig, start_registry_server};
pub use store::PeerStore;
pub use types::{
    ConnectionBreakdown, ConnectionMethod, NatStats, NatType, NetworkEvent, NetworkStats,
    NodeCapabilities, NodeHeartbeat, NodeRegistration, PeerInfo, RegistrationResponse,
};
