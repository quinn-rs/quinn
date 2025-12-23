//! ant-quic Test Network Infrastructure
//!
//! This crate provides the large-scale network testing infrastructure for ant-quic,
//! including:
//!
//! - **Registry Server**: Central peer discovery and network statistics
//! - **Terminal UI**: Interactive display of network status and connections
//! - **Test Protocol**: 5KB packet exchange for connectivity verification
//!
//! # "We will be legion!!"
//!
//! The goal is to prove that our quantum-secure NAT traversal P2P network works
//! at scale, with users simply downloading and running the binary.
//!
//! # Architecture
//!
//! ```text
//!                      ┌─────────────────────────┐
//!                      │    Registry Server      │
//!                      │    (saorsa-1)           │
//!                      │                         │
//!                      │  POST /api/register     │
//!                      │  POST /api/heartbeat    │
//!                      │  GET  /api/peers        │
//!                      │  GET  /api/stats        │
//!                      │  WS   /ws/live          │
//!                      └───────────┬─────────────┘
//!                                  │
//!        ┌─────────────────────────┼─────────────────────────┐
//!        │                         │                         │
//!        ▼                         ▼                         ▼
//!   ┌─────────┐             ┌─────────┐             ┌─────────┐
//!   │ Node A  │◄───────────►│ Node B  │◄───────────►│ Node C  │
//!   │  (TUI)  │   Direct/   │  (TUI)  │   Hole-     │  (TUI)  │
//!   │         │   Punched   │         │   Punched   │         │
//!   └─────────┘             └─────────┘             └─────────┘
//! ```
//!
//! # Usage
//!
//! ## As Registry Server (on saorsa-1)
//!
//! ```bash
//! ant-quic-test --registry --port 8080
//! ```
//!
//! ## As Test Node (on user machines)
//!
//! ```bash
//! ant-quic-test
//! ```
//!
//! The node will:
//! 1. Register with the central registry
//! 2. Receive a list of other peers
//! 3. Automatically connect to random peers
//! 4. Exchange 5KB test packets
//! 5. Display real-time statistics in TUI

pub mod dashboard;
pub mod node;
pub mod registry;
pub mod tui;

// Re-export key types for convenience
pub use registry::{
    ConnectionMethod, NatType, NetworkEvent, NetworkStats, NodeCapabilities, NodeHeartbeat,
    NodeRegistration, PeerInfo, PeerStore, RegistrationResponse, RegistryClient, RegistryConfig,
    start_registry_server,
};

pub use tui::{
    App, AppState, ConnectedPeer, ConnectionQuality, InputEvent, LocalNodeInfo,
    NetworkStatistics, TuiConfig, TuiEvent, run_tui,
};

pub use node::{GlobalStats, TestNode, TestNodeConfig, TestPacket, TestResult};

pub use dashboard::dashboard_routes;
