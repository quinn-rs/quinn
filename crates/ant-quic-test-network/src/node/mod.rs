//! Test node implementation for the ant-quic network.
//!
//! This module provides the automatic peer connection and test traffic
//! functionality for the network testing infrastructure.

mod client;
mod test_protocol;

pub use client::{GlobalStats, TestNode, TestNodeConfig};
pub use test_protocol::{
    CanYouReachRequest, ConnectBackRequest, ConnectBackResponse, GossipMessage, PeerNetworkInfo,
    RELAY_MAGIC, ReachResponse, RelayAckResponse, RelayCandidate, RelayDataRequest, RelayMessage,
    RelayPunchMeNowRequest, RelayState, RelayedDataResponse, TestPacket, TestResult,
    connectivity_test::{ConnectivityMethod, ConnectivityTestPhase, PeerConnectivityResult},
};
