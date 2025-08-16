//! TURN-style Relay Protocol Implementation
//!
//! This module implements a TURN-style relay protocol for NAT traversal fallback
//! when direct peer-to-peer connections cannot be established. The relay system
//! provides a fallback mechanism to ensure connectivity between peers through
//! trusted relay servers.
//!
//! # Protocol Overview
//!
//! The relay protocol uses QUIC extension frames for communication:
//! - `RELAY_REQUEST` (0x44): Request relay connection establishment
//! - `RELAY_RESPONSE` (0x45): Response to relay request with status
//! - `RELAY_DATA` (0x46): Bidirectional data forwarding through relay
//!
//! # Security
//!
//! All relay operations use Ed25519 cryptographic authentication with
//! anti-replay protection. Rate limiting prevents abuse and ensures
//! fair resource allocation among clients.

pub mod authenticator;
pub mod connection;
pub mod error;
pub mod rate_limiter;
pub mod session_manager;

pub use authenticator::{RelayAuthenticator, AuthToken};
pub use connection::{RelayConnection, RelayConnectionConfig, RelayEvent, RelayAction};
pub use error::{RelayError, RelayResult};
pub use rate_limiter::{RateLimiter, TokenBucket};
pub use session_manager::{
    SessionManager, SessionId, SessionState, SessionConfig, RelaySessionInfo,
};

use std::time::Duration;

/// Default relay session timeout (5 minutes)
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Default bandwidth limit per session (1 MB/s)
pub const DEFAULT_BANDWIDTH_LIMIT: u32 = 1_048_576;

/// Maximum number of concurrent relay sessions per client
pub const MAX_CONCURRENT_SESSIONS: usize = 10;

/// Maximum size of relay data frame payload (64 KB)
pub const MAX_RELAY_DATA_SIZE: usize = 65536;

/// Rate limiting: tokens per second (100 requests/second)
pub const RATE_LIMIT_TOKENS_PER_SECOND: u32 = 100;

/// Rate limiting: maximum burst size (500 tokens)
pub const RATE_LIMIT_BURST_SIZE: u32 = 500;

/// Anti-replay window size for authentication tokens
pub const ANTI_REPLAY_WINDOW_SIZE: u64 = 1000;

/// Session cleanup interval (check every 30 seconds)
pub const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);