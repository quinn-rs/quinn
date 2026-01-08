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
pub mod failure_taxonomy;
pub mod scenario_spec;

pub use agent_api::*;
pub use artifact_manifest::*;
pub use attempt_result::*;
pub use failure_taxonomy::*;
pub use scenario_spec::*;
