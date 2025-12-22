// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Session Management
//!
//! Manages individual relay sessions for MASQUE CONNECT-UDP Bind connections.
//! Each session tracks context registrations, handles capsule exchange, and
//! forwards datagrams between the client and its targets.
//!
//! # Session Lifecycle
//!
//! ```text
//! New ──► Pending ──► Active ──► Closing ──► Closed
//!              │          │
//!              └──────────┴─► Error
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::relay_session::{RelaySession, RelaySessionConfig};
//! use std::net::SocketAddr;
//!
//! let config = RelaySessionConfig::default();
//! let public_addr = "203.0.113.50:9000".parse().unwrap();
//! let session = RelaySession::new(config, public_addr);
//! ```

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::VarInt;
use crate::masque::{
    Capsule, CompressionAck, CompressionAssign, CompressionClose, ContextError, ContextManager,
    ContextState, Datagram, UncompressedDatagram,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};

/// Configuration for relay sessions
#[derive(Debug, Clone)]
pub struct RelaySessionConfig {
    /// Maximum bandwidth per session in bytes per second
    pub bandwidth_limit: u64,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Maximum concurrent context registrations
    pub max_contexts: usize,
    /// Buffer size for datagrams
    pub datagram_buffer_size: usize,
}

impl Default for RelaySessionConfig {
    fn default() -> Self {
        Self {
            bandwidth_limit: 1_048_576, // 1 MB/s
            session_timeout: Duration::from_secs(300), // 5 minutes
            max_contexts: 100,
            datagram_buffer_size: 65536,
        }
    }
}

/// State of a relay session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySessionState {
    /// Session created but not yet active
    Pending,
    /// Session is active and can forward datagrams
    Active,
    /// Session is closing gracefully
    Closing,
    /// Session has terminated
    Closed,
    /// Session encountered an error
    Error,
}

/// Statistics for a relay session
#[derive(Debug, Default)]
pub struct RelaySessionStats {
    /// Bytes sent through this session
    pub bytes_sent: AtomicU64,
    /// Bytes received through this session
    pub bytes_received: AtomicU64,
    /// Datagrams forwarded
    pub datagrams_forwarded: AtomicU64,
    /// Capsules processed
    pub capsules_processed: AtomicU64,
    /// Contexts registered
    pub contexts_registered: AtomicU64,
}

impl RelaySessionStats {
    /// Create new session statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes received
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a forwarded datagram
    pub fn record_datagram(&self) {
        self.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a processed capsule
    pub fn record_capsule(&self) {
        self.capsules_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total bytes sent
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// A MASQUE relay session
///
/// Manages the lifecycle of a single relay connection, including context
/// registration, datagram forwarding, and session cleanup.
#[derive(Debug)]
pub struct RelaySession {
    /// Unique session identifier
    session_id: u64,
    /// Session configuration
    config: RelaySessionConfig,
    /// Current session state
    state: RelaySessionState,
    /// Public address advertised to the client
    public_address: SocketAddr,
    /// Client's address
    client_address: Option<SocketAddr>,
    /// Context manager for this session (server role - odd context IDs)
    context_manager: ContextManager,
    /// Reverse mapping: target address → context ID
    target_to_context: HashMap<SocketAddr, VarInt>,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Session statistics
    stats: Arc<RelaySessionStats>,
}

impl RelaySession {
    /// Create a new relay session
    pub fn new(session_id: u64, config: RelaySessionConfig, public_address: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            config,
            state: RelaySessionState::Pending,
            public_address,
            client_address: None,
            context_manager: ContextManager::new(false), // Server role (odd IDs)
            target_to_context: HashMap::new(),
            created_at: now,
            last_activity: now,
            stats: Arc::new(RelaySessionStats::new()),
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get current session state
    pub fn state(&self) -> RelaySessionState {
        self.state
    }

    /// Get public address for this session
    pub fn public_address(&self) -> SocketAddr {
        self.public_address
    }

    /// Set client address
    pub fn set_client_address(&mut self, addr: SocketAddr) {
        self.client_address = Some(addr);
    }

    /// Get client address if known
    pub fn client_address(&self) -> Option<SocketAddr> {
        self.client_address
    }

    /// Get session statistics
    pub fn stats(&self) -> Arc<RelaySessionStats> {
        Arc::clone(&self.stats)
    }

    /// Get session duration
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() > self.config.session_timeout
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == RelaySessionState::Active
    }

    /// Activate the session
    pub fn activate(&mut self) -> RelayResult<()> {
        match self.state {
            RelaySessionState::Pending => {
                self.state = RelaySessionState::Active;
                self.last_activity = Instant::now();
                Ok(())
            }
            _ => Err(RelayError::SessionError {
                session_id: Some(self.session_id as u32),
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("{:?}", self.state),
                    expected_state: "Pending".into(),
                },
            }),
        }
    }

    /// Process an incoming capsule
    ///
    /// Returns an optional response capsule to send back to the client.
    pub fn handle_capsule(&mut self, capsule: Capsule) -> RelayResult<Option<Capsule>> {
        if !self.is_active() {
            return Err(RelayError::SessionError {
                session_id: Some(self.session_id as u32),
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("{:?}", self.state),
                    expected_state: "Active".into(),
                },
            });
        }

        self.last_activity = Instant::now();
        self.stats.record_capsule();

        match capsule {
            Capsule::CompressionAssign(assign) => {
                self.handle_compression_assign(assign)
            }
            Capsule::CompressionAck(ack) => {
                self.handle_compression_ack(ack)
            }
            Capsule::CompressionClose(close) => {
                self.handle_compression_close(close)
            }
            Capsule::Unknown { capsule_type, .. } => {
                // Unknown capsules should be ignored per spec
                tracing::debug!(
                    session_id = self.session_id,
                    capsule_type = capsule_type.into_inner(),
                    "Ignoring unknown capsule type"
                );
                Ok(None)
            }
        }
    }

    /// Handle COMPRESSION_ASSIGN capsule from client
    fn handle_compression_assign(
        &mut self,
        assign: CompressionAssign,
    ) -> RelayResult<Option<Capsule>> {
        // Check context limit
        if self.context_manager.active_count() >= self.config.max_contexts {
            return Ok(Some(Capsule::CompressionClose(CompressionClose::new(
                assign.context_id,
            ))));
        }

        // Register the context
        let target = assign.target();

        // Check for duplicate target registration
        if let Some(t) = target {
            if self.target_to_context.contains_key(&t) {
                return Ok(Some(Capsule::CompressionClose(CompressionClose::new(
                    assign.context_id,
                ))));
            }
        }

        let result = self.context_manager
            .register_remote(assign.context_id, target)
            .map(|_| {
                if let Some(t) = target {
                    self.target_to_context.insert(t, assign.context_id);
                }
            });

        match result {
            Ok(_) => {
                self.stats.contexts_registered.fetch_add(1, Ordering::Relaxed);
                // Send ACK
                Ok(Some(Capsule::CompressionAck(CompressionAck::new(
                    assign.context_id,
                ))))
            }
            Err(e) => {
                tracing::warn!(
                    session_id = self.session_id,
                    context_id = assign.context_id.into_inner(),
                    error = %e,
                    "Failed to register context"
                );
                // Send CLOSE on error
                Ok(Some(Capsule::CompressionClose(CompressionClose::new(
                    assign.context_id,
                ))))
            }
        }
    }

    /// Handle COMPRESSION_ACK capsule (for our own context registrations)
    fn handle_compression_ack(&mut self, ack: CompressionAck) -> RelayResult<Option<Capsule>> {
        match self.context_manager.handle_ack(ack.context_id) {
            Ok(_) => Ok(None),
            Err(e) => {
                tracing::warn!(
                    session_id = self.session_id,
                    context_id = ack.context_id.into_inner(),
                    error = %e,
                    "Unexpected ACK for unknown context"
                );
                Ok(None)
            }
        }
    }

    /// Handle COMPRESSION_CLOSE capsule
    fn handle_compression_close(
        &mut self,
        close: CompressionClose,
    ) -> RelayResult<Option<Capsule>> {
        // Remove target mapping if this was a compressed context
        if let Some(target) = self.context_manager.get_target(close.context_id) {
            self.target_to_context.remove(&target);
        }

        // Close the context
        match self.context_manager.close(close.context_id) {
            Ok(_) | Err(ContextError::UnknownContext) => Ok(None),
            Err(e) => {
                tracing::warn!(
                    session_id = self.session_id,
                    context_id = close.context_id.into_inner(),
                    error = %e,
                    "Error closing context"
                );
                Ok(None)
            }
        }
    }

    /// Get the target address for a datagram based on context ID
    ///
    /// For compressed contexts, returns the registered target.
    /// For uncompressed contexts, the target is in the datagram itself.
    pub fn resolve_target(&self, datagram: &Datagram) -> Option<SocketAddr> {
        match datagram {
            Datagram::Compressed(d) => {
                self.context_manager.get_target(d.context_id)
            }
            Datagram::Uncompressed(d) => Some(d.target),
        }
    }

    /// Get or allocate a context ID for a target address
    ///
    /// Used when sending datagrams to a client - looks up existing context
    /// or allocates a new one if needed.
    pub fn context_for_target(&mut self, target: SocketAddr) -> RelayResult<VarInt> {
        // Check if we already have a context for this target
        if let Some(&ctx_id) = self.target_to_context.get(&target) {
            return Ok(ctx_id);
        }

        // Allocate a new context (server allocates odd IDs)
        let ctx_id = self.context_manager.allocate_local().map_err(|_| {
            RelayError::ResourceExhausted {
                resource_type: "contexts".into(),
                current_usage: self.context_manager.active_count() as u64,
                limit: self.config.max_contexts as u64,
            }
        })?;

        // Register the compressed context
        self.context_manager
            .register_compressed(ctx_id, target)
            .map_err(|_| RelayError::SessionError {
                session_id: Some(self.session_id as u32),
                kind: SessionErrorKind::InvalidState {
                    current_state: "context registration failed".into(),
                    expected_state: "registered".into(),
                },
            })?;

        self.target_to_context.insert(target, ctx_id);
        Ok(ctx_id)
    }

    /// Create a COMPRESSION_ASSIGN capsule for a new target
    pub fn create_assign_capsule(&self, ctx_id: VarInt, target: SocketAddr) -> Capsule {
        let assign = match target {
            SocketAddr::V4(v4) => CompressionAssign::compressed_v4(ctx_id, *v4.ip(), v4.port()),
            SocketAddr::V6(v6) => CompressionAssign::compressed_v6(ctx_id, *v6.ip(), v6.port()),
        };
        Capsule::CompressionAssign(assign)
    }

    /// Record bandwidth usage and check limits
    pub fn record_bandwidth(&self, bytes: u64) -> RelayResult<()> {
        let total = self.stats.total_bytes_sent() + self.stats.total_bytes_received();
        let duration = self.duration().as_secs_f64();

        if duration > 0.0 {
            let rate = total as f64 / duration;
            if rate > self.config.bandwidth_limit as f64 {
                return Err(RelayError::SessionError {
                    session_id: Some(self.session_id as u32),
                    kind: SessionErrorKind::BandwidthExceeded {
                        used: rate as u64,
                        limit: self.config.bandwidth_limit,
                    },
                });
            }
        }

        self.stats.record_bytes_sent(bytes);
        self.stats.record_datagram();
        Ok(())
    }

    /// Close the session gracefully
    pub fn close(&mut self) {
        match self.state {
            RelaySessionState::Closed | RelaySessionState::Error => {}
            _ => {
                self.state = RelaySessionState::Closing;
                // Clear all contexts
                self.target_to_context.clear();
                self.state = RelaySessionState::Closed;
            }
        }
    }

    /// Mark session as errored
    pub fn set_error(&mut self) {
        self.state = RelaySessionState::Error;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    #[test]
    fn test_session_creation() {
        let config = RelaySessionConfig::default();
        let public_addr = test_addr(9000);
        let session = RelaySession::new(1, config, public_addr);

        assert_eq!(session.session_id(), 1);
        assert_eq!(session.state(), RelaySessionState::Pending);
        assert_eq!(session.public_address(), public_addr);
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_activation() {
        let config = RelaySessionConfig::default();
        let session_id = 1;
        let mut session = RelaySession::new(session_id, config, test_addr(9000));

        assert!(session.activate().is_ok());
        assert!(session.is_active());
        assert_eq!(session.state(), RelaySessionState::Active);
    }

    #[test]
    fn test_session_activation_from_wrong_state() {
        let config = RelaySessionConfig::default();
        let mut session = RelaySession::new(1, config, test_addr(9000));

        session.activate().unwrap();
        // Try to activate again - should fail
        assert!(session.activate().is_err());
    }

    #[test]
    fn test_handle_compression_assign() {
        let config = RelaySessionConfig::default();
        let mut session = RelaySession::new(1, config, test_addr(9000));
        session.activate().unwrap();

        let assign = CompressionAssign::compressed_v4(
            VarInt::from_u32(2), // Client uses even IDs
            Ipv4Addr::new(192, 168, 1, 100),
            8080,
        );

        let capsule = Capsule::CompressionAssign(assign);
        let response = session.handle_capsule(capsule).unwrap();

        // Should receive ACK
        match response {
            Some(Capsule::CompressionAck(ack)) => {
                assert_eq!(ack.context_id, VarInt::from_u32(2));
            }
            _ => panic!("Expected CompressionAck"),
        }
    }

    #[test]
    fn test_context_limit() {
        let config = RelaySessionConfig {
            max_contexts: 2,
            ..Default::default()
        };
        let mut session = RelaySession::new(1, config, test_addr(9000));
        session.activate().unwrap();

        // Register 2 contexts
        for i in 0..2 {
            let assign = CompressionAssign::compressed_v4(
                VarInt::from_u32((i + 1) * 2), // Even IDs
                Ipv4Addr::new(192, 168, 1, i as u8),
                8080 + i as u16,
            );
            let capsule = Capsule::CompressionAssign(assign);
            let response = session.handle_capsule(capsule).unwrap();
            assert!(matches!(response, Some(Capsule::CompressionAck(_))));
        }

        // Third registration should be rejected (CLOSE)
        let assign = CompressionAssign::compressed_v4(
            VarInt::from_u32(6),
            Ipv4Addr::new(192, 168, 1, 3),
            8083,
        );
        let capsule = Capsule::CompressionAssign(assign);
        let response = session.handle_capsule(capsule).unwrap();
        assert!(matches!(response, Some(Capsule::CompressionClose(_))));
    }

    #[test]
    fn test_session_close() {
        let config = RelaySessionConfig::default();
        let mut session = RelaySession::new(1, config, test_addr(9000));
        session.activate().unwrap();

        session.close();
        assert_eq!(session.state(), RelaySessionState::Closed);
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_stats() {
        let config = RelaySessionConfig::default();
        let session = RelaySession::new(1, config, test_addr(9000));

        session.stats.record_bytes_sent(100);
        session.stats.record_bytes_received(50);
        session.stats.record_datagram();

        assert_eq!(session.stats.total_bytes_sent(), 100);
        assert_eq!(session.stats.total_bytes_received(), 50);
        assert_eq!(session.stats.datagrams_forwarded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_duplicate_target_rejected() {
        let config = RelaySessionConfig::default();
        let mut session = RelaySession::new(1, config, test_addr(9000));
        session.activate().unwrap();

        let target = Ipv4Addr::new(192, 168, 1, 100);
        let port = 8080u16;

        // First registration should succeed
        let assign1 = CompressionAssign::compressed_v4(VarInt::from_u32(2), target, port);
        let response1 = session.handle_capsule(Capsule::CompressionAssign(assign1)).unwrap();
        assert!(matches!(response1, Some(Capsule::CompressionAck(_))));

        // Second registration for same target should be rejected
        let assign2 = CompressionAssign::compressed_v4(VarInt::from_u32(4), target, port);
        let response2 = session.handle_capsule(Capsule::CompressionAssign(assign2)).unwrap();
        assert!(matches!(response2, Some(Capsule::CompressionClose(_))));
    }
}
