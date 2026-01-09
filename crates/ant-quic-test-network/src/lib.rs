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
pub mod epidemic_gossip;
pub mod gossip;
pub mod gossip_tests;
pub mod harness;
pub mod history;
pub mod node;
pub mod orchestrator;
pub mod peer_discovery;
pub mod registry;
pub mod tui;

// Re-export key types for convenience
pub use registry::{
    ConnectionMethod, NatType, NetworkEvent, NetworkStats, NodeCapabilities, NodeHeartbeat,
    NodeRegistration, PeerInfo, PeerStore, RegistrationResponse, RegistryClient, RegistryConfig,
    start_registry_server,
};

pub use tui::{
    App, AppState, ConnectedPeer, ConnectionQuality, InputEvent, LocalNodeInfo, NetworkStatistics,
    TuiConfig, TuiEvent, run_tui, send_tui_event,
};

pub use node::{GlobalStats, TestNode, TestNodeConfig, TestPacket, TestResult};

pub use gossip::{
    CacheStatus, CoordinatorAnnouncement, GossipConfig, GossipDiscovery, GossipEvent,
    GossipIntegration, GossipMetrics, PeerAnnouncement, PeerCapabilities, PeerConnectionQuery,
    PeerConnectionResponse, RelayAnnouncement, TOPIC_COORDINATORS, TOPIC_PEER_QUERY,
    TOPIC_PEER_RESPONSE, TOPIC_PEERS, TOPIC_RELAYS,
};

pub use dashboard::dashboard_routes;

pub use orchestrator::{
    OrchestratorConfig, OrchestratorStatus, PeerTestResult, TestCommand, TestOrchestrator,
    TestRound, TestTarget,
};

pub use gossip_tests::{
    CrateTestResult, GossipTestCoordinator, GossipTestResults, TestDetail, TestStatus,
};

pub use history::{
    ConnectivityStatus, GossipResults, GossipStatus, HistoryConfig, HistoryEntry, HistoryFile,
    HistoryManager, HistoryStorage, PeerConnectivity,
};

pub use harness::{
    AgentCapabilities, AgentClient, AgentInfo, AgentStatus, ApplyProfileRequest,
    ApplyProfileResponse, ArtifactBundle, ArtifactEntry, ArtifactManifest, ArtifactSpec,
    ArtifactType, AttemptResult, BarrierRequest, BarrierResponse, ClassifiedFailure,
    DimensionStats, FailureBreakdown, FailureCategory, FailureEvidence, FrameCounters,
    GetResultsRequest, GetResultsResponse, HandshakeRequest, HandshakeResponse,
    HealthCheckResponse, IpMode, NatBehaviorProfile, NatProfileSpec, RunProgress, RunStatus,
    RunStatusRequest, RunStatusResponse, RunSummary, ScenarioSpec, StartRunRequest,
    StartRunResponse, StopRunRequest, StopRunResponse, TechniqueResult, TestMatrixSpec,
    ThresholdSpec, TimingSpec, TopologySpec, TopologyType,
};
