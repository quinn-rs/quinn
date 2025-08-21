// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Relay connection implementation for bidirectional data forwarding.

use crate::relay::{RelayError, RelayResult};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Configuration for relay connections
#[derive(Debug, Clone)]
pub struct RelayConnectionConfig {
    /// Maximum data frame size
    pub max_frame_size: usize,
    /// Buffer size for queued data
    pub buffer_size: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Maximum bandwidth per connection (bytes/sec)
    pub bandwidth_limit: u64,
}

impl Default for RelayConnectionConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 65536,                        // 64 KB
            buffer_size: 1048576,                         // 1 MB
            connection_timeout: Duration::from_secs(300), // 5 minutes
            keep_alive_interval: Duration::from_secs(30), // 30 seconds
            bandwidth_limit: 1048576,                     // 1 MB/s
        }
    }
}

/// Events that can occur during relay operation
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// Connection established successfully
    ConnectionEstablished {
        /// Unique session identifier
        session_id: u32,
        /// Remote peer network address
        peer_addr: SocketAddr,
    },
    /// Data received from peer
    DataReceived {
        /// Session the data belongs to
        session_id: u32,
        /// Payload bytes received
        data: Vec<u8>,
    },
    /// Connection terminated
    ConnectionTerminated {
        /// Identifier of the terminated session
        session_id: u32,
        /// Human-readable reason for termination
        reason: String,
    },
    /// Error occurred during relay operation
    Error {
        /// Optional session context for the error
        session_id: Option<u32>,
        /// Underlying error detail
        error: RelayError,
    },
    /// Bandwidth limit exceeded
    BandwidthLimitExceeded {
        /// Identifier of the session exceeding bandwidth
        session_id: u32,
        /// Current bandwidth usage (bytes) within the window
        current_usage: u64,
        /// Configured limit (bytes) for the window
        limit: u64,
    },
    /// Keep-alive signal
    KeepAlive {
        /// Identifier of the session emitting keep-alive
        session_id: u32,
    },
}

/// Actions that can be taken in response to relay events
#[derive(Debug, Clone)]
pub enum RelayAction {
    /// Send data to peer
    SendData {
        /// Target session
        session_id: u32,
        /// Payload to send
        data: Vec<u8>,
    },
    /// Terminate connection
    TerminateConnection {
        /// Target session to terminate
        session_id: u32,
        /// Reason for termination
        reason: String,
    },
    /// Update bandwidth limit
    UpdateBandwidthLimit {
        /// Target session
        session_id: u32,
        /// New bandwidth limit (bytes/sec)
        new_limit: u64,
    },
    /// Send keep-alive
    SendKeepAlive {
        /// Target session
        session_id: u32,
    },
}

/// Relay connection for bidirectional data forwarding
#[derive(Debug)]
pub struct RelayConnection {
    /// Unique session identifier
    session_id: u32,
    /// Peer address
    peer_addr: SocketAddr,
    /// Configuration
    config: RelayConnectionConfig,
    /// Connection state
    state: Arc<Mutex<ConnectionState>>,
    /// Event sender
    event_sender: mpsc::UnboundedSender<RelayEvent>,
    /// Action receiver
    action_receiver: mpsc::UnboundedReceiver<RelayAction>,
}

/// Internal connection state
#[derive(Debug)]
struct ConnectionState {
    /// Whether connection is active
    is_active: bool,
    /// Data queue for outgoing packets
    outgoing_queue: VecDeque<Vec<u8>>,
    /// Data queue for incoming packets
    incoming_queue: VecDeque<Vec<u8>>,
    /// Current buffer usage
    buffer_usage: usize,
    /// Bandwidth tracking
    bandwidth_tracker: BandwidthTracker,
    /// Last activity timestamp
    last_activity: Instant,
    /// Keep-alive timer
    next_keep_alive: Instant,
}

/// Bandwidth usage tracker
#[derive(Debug)]
struct BandwidthTracker {
    /// Bytes sent in current window
    bytes_sent: u64,
    /// Bytes received in current window
    bytes_received: u64,
    /// Window start time
    window_start: Instant,
    /// Window duration (1 second)
    window_duration: Duration,
    /// Rate limit
    limit: u64,
}

impl BandwidthTracker {
    fn new(limit: u64) -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            window_start: Instant::now(),
            window_duration: Duration::from_secs(1),
            limit,
        }
    }

    fn reset_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_duration {
            self.bytes_sent = 0;
            self.bytes_received = 0;
            self.window_start = now;
        }
    }

    fn can_send(&mut self, bytes: u64) -> bool {
        self.reset_if_needed();
        self.bytes_sent + bytes <= self.limit
    }

    fn record_sent(&mut self, bytes: u64) {
        self.reset_if_needed();
        self.bytes_sent += bytes;
    }

    fn record_received(&mut self, bytes: u64) {
        self.reset_if_needed();
        self.bytes_received += bytes;
    }

    fn current_usage(&mut self) -> u64 {
        self.reset_if_needed();
        self.bytes_sent + self.bytes_received
    }
}

impl RelayConnection {
    /// Create a new relay connection
    pub fn new(
        session_id: u32,
        peer_addr: SocketAddr,
        config: RelayConnectionConfig,
        event_sender: mpsc::UnboundedSender<RelayEvent>,
        action_receiver: mpsc::UnboundedReceiver<RelayAction>,
    ) -> Self {
        let now = Instant::now();
        let state = ConnectionState {
            is_active: true,
            outgoing_queue: VecDeque::new(),
            incoming_queue: VecDeque::new(),
            buffer_usage: 0,
            bandwidth_tracker: BandwidthTracker::new(config.bandwidth_limit),
            last_activity: now,
            next_keep_alive: now + config.keep_alive_interval,
        };

        Self {
            session_id,
            peer_addr,
            config,
            state: Arc::new(Mutex::new(state)),
            event_sender,
            action_receiver,
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Get peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.is_active
    }

    /// Send data through the relay
    pub fn send_data(&self, data: Vec<u8>) -> RelayResult<()> {
        if data.len() > self.config.max_frame_size {
            return Err(RelayError::ProtocolError {
                frame_type: 0x46, // RELAY_DATA
                reason: format!(
                    "Data size {} exceeds maximum {}",
                    data.len(),
                    self.config.max_frame_size
                ),
            });
        }

        let mut state = self.state.lock().unwrap();

        if !state.is_active {
            return Err(RelayError::SessionError {
                session_id: Some(self.session_id),
                kind: crate::relay::error::SessionErrorKind::Terminated,
            });
        }

        // Check bandwidth limit
        if !state.bandwidth_tracker.can_send(data.len() as u64) {
            let current_usage = state.bandwidth_tracker.current_usage();
            return Err(RelayError::SessionError {
                session_id: Some(self.session_id),
                kind: crate::relay::error::SessionErrorKind::BandwidthExceeded {
                    used: current_usage,
                    limit: self.config.bandwidth_limit,
                },
            });
        }

        // Check buffer space
        if state.buffer_usage + data.len() > self.config.buffer_size {
            return Err(RelayError::ResourceExhausted {
                resource_type: "buffer".to_string(),
                current_usage: state.buffer_usage as u64,
                limit: self.config.buffer_size as u64,
            });
        }

        // Queue data and update tracking
        state.bandwidth_tracker.record_sent(data.len() as u64);
        state.buffer_usage += data.len();
        state.outgoing_queue.push_back(data.clone());
        state.last_activity = Instant::now();

        // Send event
        let _ = self.event_sender.send(RelayEvent::DataReceived {
            session_id: self.session_id,
            data,
        });

        Ok(())
    }

    /// Receive data from the relay
    pub fn receive_data(&self, data: Vec<u8>) -> RelayResult<()> {
        let mut state = self.state.lock().unwrap();

        if !state.is_active {
            return Err(RelayError::SessionError {
                session_id: Some(self.session_id),
                kind: crate::relay::error::SessionErrorKind::Terminated,
            });
        }

        // Check buffer space
        if state.buffer_usage + data.len() > self.config.buffer_size {
            return Err(RelayError::ResourceExhausted {
                resource_type: "buffer".to_string(),
                current_usage: state.buffer_usage as u64,
                limit: self.config.buffer_size as u64,
            });
        }

        // Queue data and update tracking
        state.bandwidth_tracker.record_received(data.len() as u64);
        state.buffer_usage += data.len();
        state.incoming_queue.push_back(data.clone());
        state.last_activity = Instant::now();

        // Send event
        let _ = self.event_sender.send(RelayEvent::DataReceived {
            session_id: self.session_id,
            data,
        });

        Ok(())
    }

    /// Get next outgoing data packet
    pub fn next_outgoing(&self) -> Option<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        if let Some(data) = state.outgoing_queue.pop_front() {
            state.buffer_usage = state.buffer_usage.saturating_sub(data.len());
            Some(data)
        } else {
            None
        }
    }

    /// Get next incoming data packet
    pub fn next_incoming(&self) -> Option<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        if let Some(data) = state.incoming_queue.pop_front() {
            state.buffer_usage = state.buffer_usage.saturating_sub(data.len());
            Some(data)
        } else {
            None
        }
    }

    /// Check if connection has timed out
    pub fn check_timeout(&self) -> RelayResult<()> {
        let state = self.state.lock().unwrap();
        let now = Instant::now();

        if now.duration_since(state.last_activity) > self.config.connection_timeout {
            return Err(RelayError::SessionError {
                session_id: Some(self.session_id),
                kind: crate::relay::error::SessionErrorKind::Expired,
            });
        }

        Ok(())
    }

    /// Check if keep-alive should be sent
    pub fn should_send_keep_alive(&self) -> bool {
        let state = self.state.lock().unwrap();
        Instant::now() >= state.next_keep_alive
    }

    /// Send keep-alive
    pub fn send_keep_alive(&self) -> RelayResult<()> {
        let mut state = self.state.lock().unwrap();
        state.next_keep_alive = Instant::now() + self.config.keep_alive_interval;

        let _ = self.event_sender.send(RelayEvent::KeepAlive {
            session_id: self.session_id,
        });

        Ok(())
    }

    /// Terminate the connection
    pub fn terminate(&self, reason: String) -> RelayResult<()> {
        let mut state = self.state.lock().unwrap();
        state.is_active = false;

        let _ = self.event_sender.send(RelayEvent::ConnectionTerminated {
            session_id: self.session_id,
            reason: reason.clone(),
        });

        Ok(())
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> ConnectionStats {
        let state = self.state.lock().unwrap();
        ConnectionStats {
            session_id: self.session_id,
            peer_addr: self.peer_addr,
            is_active: state.is_active,
            bytes_sent: state.bandwidth_tracker.bytes_sent,
            bytes_received: state.bandwidth_tracker.bytes_received,
            buffer_usage: state.buffer_usage,
            outgoing_queue_size: state.outgoing_queue.len(),
            incoming_queue_size: state.incoming_queue.len(),
            last_activity: state.last_activity,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Unique session identifier
    pub session_id: u32,
    /// Remote peer address
    pub peer_addr: SocketAddr,
    /// Whether the connection is currently active
    pub is_active: bool,
    /// Total bytes sent in the current window
    pub bytes_sent: u64,
    /// Total bytes received in the current window
    pub bytes_received: u64,
    /// Current buffer usage (bytes)
    pub buffer_usage: usize,
    /// Number of queued outgoing packets
    pub outgoing_queue_size: usize,
    /// Number of queued incoming packets
    pub incoming_queue_size: usize,
    /// Timestamp of last activity
    pub last_activity: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_relay_connection_creation() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let connection = RelayConnection::new(
            123,
            test_addr(),
            RelayConnectionConfig::default(),
            event_tx,
            action_rx,
        );

        assert_eq!(connection.session_id(), 123);
        assert_eq!(connection.peer_addr(), test_addr());
        assert!(connection.is_active());
    }

    #[test]
    fn test_send_data_within_limits() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let connection = RelayConnection::new(
            123,
            test_addr(),
            RelayConnectionConfig::default(),
            event_tx,
            action_rx,
        );

        let data = vec![1, 2, 3, 4];
        assert!(connection.send_data(data.clone()).is_ok());

        // Check that data is queued
        assert_eq!(connection.next_outgoing(), Some(data));
    }

    #[test]
    fn test_send_data_exceeds_frame_size() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let mut config = RelayConnectionConfig::default();
        config.max_frame_size = 10;

        let connection = RelayConnection::new(123, test_addr(), config, event_tx, action_rx);

        let large_data = vec![0; 20];
        assert!(connection.send_data(large_data).is_err());
    }

    #[test]
    fn test_bandwidth_limiting() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let mut config = RelayConnectionConfig::default();
        config.bandwidth_limit = 100; // Very low limit

        let connection = RelayConnection::new(123, test_addr(), config, event_tx, action_rx);

        // First small packet should succeed
        assert!(connection.send_data(vec![0; 50]).is_ok());

        // Second packet should exceed bandwidth limit
        assert!(connection.send_data(vec![0; 60]).is_err());
    }

    #[test]
    fn test_buffer_size_limiting() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let mut config = RelayConnectionConfig::default();
        config.buffer_size = 100; // Very small buffer

        let connection = RelayConnection::new(123, test_addr(), config, event_tx, action_rx);

        // Fill buffer
        assert!(connection.send_data(vec![0; 80]).is_ok());

        // Should fail to add more data
        assert!(connection.send_data(vec![0; 30]).is_err());
    }

    #[test]
    fn test_connection_termination() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let connection = RelayConnection::new(
            123,
            test_addr(),
            RelayConnectionConfig::default(),
            event_tx,
            action_rx,
        );

        assert!(connection.is_active());

        let reason = "Test termination".to_string();
        assert!(connection.terminate(reason.clone()).is_ok());

        assert!(!connection.is_active());

        // Should not be able to send data after termination
        assert!(connection.send_data(vec![1, 2, 3]).is_err());
    }

    #[test]
    fn test_keep_alive() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let mut config = RelayConnectionConfig::default();
        config.keep_alive_interval = Duration::from_millis(1);

        let connection = RelayConnection::new(123, test_addr(), config, event_tx, action_rx);

        // Initially should not need keep-alive
        assert!(!connection.should_send_keep_alive());

        // Wait for keep-alive interval
        std::thread::sleep(Duration::from_millis(2));

        // Should need keep-alive now
        assert!(connection.should_send_keep_alive());

        // Send keep-alive
        assert!(connection.send_keep_alive().is_ok());

        // Should not need keep-alive immediately after sending
        assert!(!connection.should_send_keep_alive());
    }

    #[test]
    fn test_connection_stats() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (_action_tx, action_rx) = mpsc::unbounded_channel();

        let connection = RelayConnection::new(
            123,
            test_addr(),
            RelayConnectionConfig::default(),
            event_tx,
            action_rx,
        );

        // Send some data
        connection.send_data(vec![1, 2, 3]).unwrap();
        connection.receive_data(vec![4, 5, 6, 7]).unwrap();

        let stats = connection.get_stats();
        assert_eq!(stats.session_id, 123);
        assert_eq!(stats.peer_addr, test_addr());
        assert!(stats.is_active);
        assert_eq!(stats.bytes_sent, 3);
        assert_eq!(stats.bytes_received, 4);
        assert_eq!(stats.outgoing_queue_size, 1);
        assert_eq!(stats.incoming_queue_size, 1);
    }
}
