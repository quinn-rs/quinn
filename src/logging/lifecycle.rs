// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


/// Connection lifecycle logging
///
/// Tracks and logs the complete lifecycle of QUIC connections
use std::collections::HashMap;
use tracing::{Span, debug, info, warn};

use super::{ConnectionRole, LogEvent, logger};
use crate::{ConnectionId, Duration, Instant};

/// Connection lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection attempt initiated
    Initiated,
    /// Performing handshake
    Handshaking,
    /// Handshake complete, connection established
    Established,
    /// Connection is migrating to new path
    Migrating,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
    /// Connection was lost (timeout/error)
    Lost,
}

/// Connection lifecycle tracker
pub struct ConnectionLifecycle {
    pub conn_id: ConnectionId,
    pub role: ConnectionRole,
    pub state: ConnectionState,
    pub initiated_at: Instant,
    pub handshake_started_at: Option<Instant>,
    pub established_at: Option<Instant>,
    pub closed_at: Option<Instant>,
    pub close_reason: Option<String>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
}

impl ConnectionLifecycle {
    /// Create a new connection lifecycle tracker
    pub fn new(conn_id: ConnectionId, role: ConnectionRole) -> Self {
        Self {
            conn_id,
            role,
            state: ConnectionState::Initiated,
            initiated_at: Instant::now(),
            handshake_started_at: None,
            established_at: None,
            closed_at: None,
            close_reason: None,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_packets_sent: 0,
            total_packets_received: 0,
        }
    }

    /// Update connection state
    pub fn update_state(&mut self, new_state: ConnectionState) {
        let old_state = self.state;
        self.state = new_state;

        match new_state {
            ConnectionState::Handshaking => {
                self.handshake_started_at = Some(Instant::now());
            }
            ConnectionState::Established => {
                self.established_at = Some(Instant::now());
            }
            ConnectionState::Closed | ConnectionState::Lost => {
                self.closed_at = Some(Instant::now());
            }
            _ => {}
        }

        self.log_state_transition(old_state, new_state);
    }

    /// Log state transition
    fn log_state_transition(&self, old_state: ConnectionState, new_state: ConnectionState) {
        let mut fields = HashMap::new();
        fields.insert("conn_id".to_string(), format!("{:?}", self.conn_id));
        fields.insert("role".to_string(), format!("{:?}", self.role));
        fields.insert("old_state".to_string(), format!("{old_state:?}"));
        fields.insert("new_state".to_string(), format!("{new_state:?}"));

        // Add timing information
        if let Some(duration) = self.duration_in_state(old_state) {
            fields.insert("duration_ms".to_string(), duration.as_millis().to_string());
        }

        let level = match new_state {
            ConnectionState::Lost => tracing::Level::WARN,
            ConnectionState::Established => tracing::Level::INFO,
            _ => tracing::Level::DEBUG,
        };

        logger().log_event(LogEvent {
            timestamp: Instant::now(),
            level,
            target: "ant_quic::connection::lifecycle".to_string(),
            message: "connection_state_changed".to_string(),
            fields,
            span_id: None,
        });
    }

    /// Get duration in a specific state
    fn duration_in_state(&self, state: ConnectionState) -> Option<Duration> {
        match state {
            ConnectionState::Initiated => {
                let end = self.handshake_started_at.unwrap_or_else(Instant::now);
                Some(end.duration_since(self.initiated_at))
            }
            ConnectionState::Handshaking => {
                if let Some(start) = self.handshake_started_at {
                    let end = self.established_at.unwrap_or_else(Instant::now);
                    Some(end.duration_since(start))
                } else {
                    None
                }
            }
            ConnectionState::Established => {
                if let Some(start) = self.established_at {
                    let end = self.closed_at.unwrap_or_else(Instant::now);
                    Some(end.duration_since(start))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Log connection summary when closed
    pub fn log_summary(&self) {
        let total_duration = self
            .closed_at
            .unwrap_or_else(Instant::now)
            .duration_since(self.initiated_at);

        let mut fields = HashMap::new();
        fields.insert("conn_id".to_string(), format!("{:?}", self.conn_id));
        fields.insert("role".to_string(), format!("{:?}", self.role));
        fields.insert(
            "total_duration_ms".to_string(),
            total_duration.as_millis().to_string(),
        );
        fields.insert("bytes_sent".to_string(), self.total_bytes_sent.to_string());
        fields.insert(
            "bytes_received".to_string(),
            self.total_bytes_received.to_string(),
        );
        fields.insert(
            "packets_sent".to_string(),
            self.total_packets_sent.to_string(),
        );
        fields.insert(
            "packets_received".to_string(),
            self.total_packets_received.to_string(),
        );

        if let Some(handshake_duration) = self.duration_in_state(ConnectionState::Handshaking) {
            fields.insert(
                "handshake_duration_ms".to_string(),
                handshake_duration.as_millis().to_string(),
            );
        }

        if let Some(established_duration) = self.duration_in_state(ConnectionState::Established) {
            fields.insert(
                "established_duration_ms".to_string(),
                established_duration.as_millis().to_string(),
            );
        }

        if let Some(reason) = &self.close_reason {
            fields.insert("close_reason".to_string(), reason.clone());
        }

        logger().log_event(LogEvent {
            timestamp: Instant::now(),
            level: tracing::Level::INFO,
            target: "ant_quic::connection::lifecycle".to_string(),
            message: "connection_summary".to_string(),
            fields,
            span_id: None,
        });
    }
}

/// Log connection lifecycle events
pub fn log_connection_initiated(
    conn_id: &ConnectionId,
    role: ConnectionRole,
    remote_addr: std::net::SocketAddr,
) {
    info!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        role = ?role,
        remote_addr = %remote_addr,
        "Connection initiated"
    );
}

pub fn log_handshake_started(conn_id: &ConnectionId) {
    debug!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        "Handshake started"
    );
}

pub fn log_handshake_completed(conn_id: &ConnectionId, duration: Duration) {
    info!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        duration_ms = duration.as_millis(),
        "Handshake completed"
    );
}

pub fn log_connection_established(conn_id: &ConnectionId, negotiated_version: u32) {
    info!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        negotiated_version = format!("0x{:08x}", negotiated_version),
        "Connection established"
    );
}

pub fn log_connection_migration(conn_id: &ConnectionId, old_path: &str, new_path: &str) {
    info!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        old_path = old_path,
        new_path = new_path,
        "Connection migrated to new path"
    );
}

pub fn log_connection_closed(conn_id: &ConnectionId, reason: &str, error_code: Option<u64>) {
    let mut fields = HashMap::new();
    fields.insert("conn_id".to_string(), format!("{conn_id:?}"));
    fields.insert("reason".to_string(), reason.to_string());

    if let Some(code) = error_code {
        fields.insert("error_code".to_string(), format!("0x{code:x}"));
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: tracing::Level::DEBUG,
        target: "ant_quic::connection::lifecycle".to_string(),
        message: "connection_closed".to_string(),
        fields,
        span_id: None,
    });
}

pub fn log_connection_lost(conn_id: &ConnectionId, reason: &str) {
    warn!(
        target: "ant_quic::connection::lifecycle",
        conn_id = ?conn_id,
        reason = reason,
        "Connection lost"
    );
}

/// Create a span for the entire connection lifetime
pub fn create_connection_lifetime_span(conn_id: &ConnectionId, role: ConnectionRole) -> Span {
    tracing::span!(
        tracing::Level::INFO,
        "connection_lifetime",
        conn_id = %format!("{:?}", conn_id),
        role = ?role,
    )
}
