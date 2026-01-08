//! Test Harness Infrastructure
//!
//! This module provides the comprehensive test harness schemas and types
//! for distributed P2P network testing across VPS and local nodes.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         ORCHESTRATION LAYER                              │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                     saorsa-testctl                               │   │
//! │  │  - Scenario planning & matrix generation                         │   │
//! │  │  - Distributed run coordination                                  │   │
//! │  │  - Result aggregation & trend analysis                           │   │
//! │  └──────────────────────────┬──────────────────────────────────────┘   │
//! │                              │                                          │
//! ├──────────────────────────────┼──────────────────────────────────────────┤
//! │                         EXECUTION LAYER                                  │
//! │  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐             │
//! │  │ test-agent  │      │ test-agent  │      │ test-agent  │             │
//! │  │ (VPS)       │      │ (VPS)       │      │ (local)     │             │
//! │  └─────────────┘      └─────────────┘      └─────────────┘             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

pub mod agent_api;
pub mod artifact_manifest;
pub mod attempt_result;
pub mod baseline;
pub mod debug_bundle;
pub mod failure_taxonomy;
pub mod harness_metrics;
pub mod replay_mode;
pub mod run_recovery;
pub mod scenario_spec;
pub mod structured_logging;
pub mod version_compat;
#[cfg(test)]
pub mod failure_oracle;
#[cfg(test)]
pub mod golden_fixtures;
#[cfg(test)]
pub mod self_tests;

pub use agent_api::*;
pub use artifact_manifest::*;
pub use attempt_result::*;
pub use baseline::*;
pub use debug_bundle::*;
pub use failure_taxonomy::*;
pub use harness_metrics::*;
pub use replay_mode::*;
pub use run_recovery::*;
pub use scenario_spec::*;
pub use structured_logging::*;
pub use version_compat::*;
