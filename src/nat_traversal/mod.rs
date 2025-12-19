// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! NAT Traversal Protocol Implementation
//!
//! This module implements the QUIC-native NAT traversal approach based on
//! draft-seemann-quic-nat-traversal-01. It focuses exclusively on the three
//! required QUIC extension frames and implements a clean state machine for
//! NAT traversal lifecycle.
//!
//! IMPORTANT: This implementation uses ONLY the QUIC-native approach and does NOT
//! include any STUN, ICE, or other external NAT traversal protocols. All NAT traversal
//! functionality is implemented as QUIC protocol extensions using custom frames and
//! transport parameters as defined in the draft specification.

// Re-export public NAT traversal API
pub use crate::nat_traversal_api::{
    BootstrapNode, CandidateAddress, NatTraversalConfig, NatTraversalEndpoint,
    NatTraversalError, NatTraversalEvent, NatTraversalStatistics, PeerId,
};

// Re-export NAT traversal types from connection module
// v0.13.0: NatTraversalRole removed - all nodes are symmetric P2P nodes
pub use crate::connection::nat_traversal::{CandidateSource, CandidateState};

// Submodules
pub mod rfc_migration;

// Module-private imports
// Note: The actual NAT traversal implementation is in src/connection/nat_traversal.rs
// This module only contains protocol-level types and RFC migration utilities
