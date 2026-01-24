// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Constrained Protocol Engine
//!
//! The main protocol engine that manages multiple connections over constrained transports.
//! This integrates with the transport layer to provide reliable messaging over BLE, LoRa,
//! and other low-bandwidth transports.

use super::connection::{ConnectionConfig, ConnectionEvent, ConstrainedConnection};
use super::header::ConstrainedPacket;
use super::types::{ConnectionId, ConstrainedError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Configuration for the constrained protocol engine
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Default connection configuration
    pub connection_config: ConnectionConfig,
    /// How often to poll connections for maintenance
    pub poll_interval: Duration,
    /// Enable connection reuse after TIME_WAIT
    pub enable_connection_reuse: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_connections: 8,
            connection_config: ConnectionConfig::default(),
            poll_interval: Duration::from_millis(100),
            enable_connection_reuse: true,
        }
    }
}

impl EngineConfig {
    /// Create configuration for BLE transport
    pub fn for_ble() -> Self {
        Self {
            max_connections: 4,
            connection_config: ConnectionConfig::for_ble(),
            poll_interval: Duration::from_millis(50),
            enable_connection_reuse: true,
        }
    }

    /// Create configuration for LoRa transport
    pub fn for_lora() -> Self {
        Self {
            max_connections: 2,
            connection_config: ConnectionConfig::for_lora(),
            poll_interval: Duration::from_millis(500),
            enable_connection_reuse: true,
        }
    }
}

/// Events from the engine
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// New incoming connection accepted
    ConnectionAccepted {
        /// Connection ID
        connection_id: ConnectionId,
        /// Remote address
        remote_addr: SocketAddr,
    },
    /// Outbound connection established
    ConnectionEstablished {
        /// Connection ID
        connection_id: ConnectionId,
    },
    /// Data received on a connection
    DataReceived {
        /// Connection ID
        connection_id: ConnectionId,
        /// The data
        data: Vec<u8>,
    },
    /// Connection closed
    ConnectionClosed {
        /// Connection ID
        connection_id: ConnectionId,
    },
    /// Connection error
    ConnectionError {
        /// Connection ID
        connection_id: ConnectionId,
        /// Error message
        error: String,
    },
    /// Packet ready to transmit
    Transmit {
        /// Destination address
        remote_addr: SocketAddr,
        /// Packet data
        packet: Vec<u8>,
    },
}

/// The constrained protocol engine
///
/// Manages multiple connections and provides a simple API for sending/receiving data.
#[derive(Debug)]
pub struct ConstrainedEngine {
    /// Configuration
    config: EngineConfig,
    /// Active connections by ID
    connections: HashMap<ConnectionId, ConstrainedConnection>,
    /// Connection ID to remote address mapping
    addr_to_conn: HashMap<SocketAddr, ConnectionId>,
    /// Pending events
    events: Vec<EngineEvent>,
    /// Next connection ID to use
    next_conn_id: u16,
    /// Last poll time
    last_poll: Instant,
}

impl ConstrainedEngine {
    /// Create a new constrained protocol engine
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            addr_to_conn: HashMap::new(),
            events: Vec::new(),
            next_conn_id: 1,
            last_poll: Instant::now(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(EngineConfig::default())
    }

    /// Number of active connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if we can accept more connections
    pub fn can_accept_connection(&self) -> bool {
        self.connections.len() < self.config.max_connections
    }

    /// Generate a new connection ID
    fn generate_conn_id(&mut self) -> ConnectionId {
        let id = ConnectionId::new(self.next_conn_id);
        self.next_conn_id = self.next_conn_id.wrapping_add(1);
        if self.next_conn_id == 0 {
            self.next_conn_id = 1;
        }
        id
    }

    /// Initiate a connection to a remote address
    ///
    /// Returns the connection ID and a SYN packet to transmit.
    pub fn connect(&mut self, remote_addr: SocketAddr) -> Result<(ConnectionId, Vec<u8>), ConstrainedError> {
        if !self.can_accept_connection() {
            return Err(ConstrainedError::SendBufferFull);
        }

        // Check if we already have a connection to this address
        if self.addr_to_conn.contains_key(&remote_addr) {
            return Err(ConstrainedError::ConnectionExists(
                *self.addr_to_conn.get(&remote_addr).unwrap_or(&ConnectionId::new(0)),
            ));
        }

        let conn_id = self.generate_conn_id();
        let mut conn = ConstrainedConnection::new_outbound_with_config(
            conn_id,
            remote_addr,
            self.config.connection_config.clone(),
        );

        let syn_packet = conn.initiate()?;
        let packet_bytes = syn_packet.to_bytes();

        self.connections.insert(conn_id, conn);
        self.addr_to_conn.insert(remote_addr, conn_id);

        Ok((conn_id, packet_bytes))
    }

    /// Process an incoming packet
    ///
    /// Returns any response packets that need to be transmitted.
    pub fn process_incoming(&mut self, remote_addr: SocketAddr, data: &[u8]) -> Result<Vec<(SocketAddr, Vec<u8>)>, ConstrainedError> {
        let packet = ConstrainedPacket::from_bytes(data)?;
        let header = &packet.header;
        let mut responses = Vec::new();

        // Check if this is for an existing connection
        if let Some(conn) = self.connections.get_mut(&header.connection_id) {
            conn.process_packet(&packet)?;

            // Collect events from the connection
            while let Some(event) = conn.next_event() {
                match event {
                    ConnectionEvent::Connected => {
                        self.events.push(EngineEvent::ConnectionEstablished {
                            connection_id: header.connection_id,
                        });
                    }
                    ConnectionEvent::DataReceived(_) => {
                        // Data is retrieved separately via recv()
                    }
                    ConnectionEvent::Closed => {
                        self.events.push(EngineEvent::ConnectionClosed {
                            connection_id: header.connection_id,
                        });
                    }
                    ConnectionEvent::Reset => {
                        self.events.push(EngineEvent::ConnectionClosed {
                            connection_id: header.connection_id,
                        });
                    }
                    ConnectionEvent::Error(err) => {
                        self.events.push(EngineEvent::ConnectionError {
                            connection_id: header.connection_id,
                            error: err,
                        });
                    }
                    ConnectionEvent::Transmit(data) => {
                        responses.push((remote_addr, data));
                    }
                }
            }

            // Poll the connection for any outbound packets
            let packets = conn.poll();
            for pkt in packets {
                responses.push((remote_addr, pkt.to_bytes()));
            }
        } else if header.is_syn() && !header.is_ack() {
            // New incoming connection
            if !self.can_accept_connection() {
                // Send RST
                let rst = super::header::ConstrainedHeader::reset(header.connection_id);
                responses.push((remote_addr, super::header::ConstrainedPacket::control(rst).to_bytes()));
                return Ok(responses);
            }

            let mut conn = ConstrainedConnection::new_inbound_with_config(
                header.connection_id,
                remote_addr,
                self.config.connection_config.clone(),
            );

            let syn_ack = conn.accept(header.seq)?;
            responses.push((remote_addr, syn_ack.to_bytes()));

            self.connections.insert(header.connection_id, conn);
            self.addr_to_conn.insert(remote_addr, header.connection_id);

            self.events.push(EngineEvent::ConnectionAccepted {
                connection_id: header.connection_id,
                remote_addr,
            });
        }
        // Otherwise, packet for unknown connection - ignore

        Ok(responses)
    }

    /// Send data on a connection
    pub fn send(&mut self, connection_id: ConnectionId, data: &[u8]) -> Result<Vec<(SocketAddr, Vec<u8>)>, ConstrainedError> {
        let conn = self.connections.get_mut(&connection_id)
            .ok_or(ConstrainedError::ConnectionNotFound(connection_id))?;

        conn.send(data)?;

        let remote_addr = conn.remote_addr();
        let packets = conn.poll();

        Ok(packets.into_iter().map(|p| (remote_addr, p.to_bytes())).collect())
    }

    /// Receive data from a connection
    pub fn recv(&mut self, connection_id: ConnectionId) -> Option<Vec<u8>> {
        self.connections.get_mut(&connection_id)?.recv()
    }

    /// Close a connection gracefully
    pub fn close(&mut self, connection_id: ConnectionId) -> Result<Vec<(SocketAddr, Vec<u8>)>, ConstrainedError> {
        let conn = self.connections.get_mut(&connection_id)
            .ok_or(ConstrainedError::ConnectionNotFound(connection_id))?;

        let fin = conn.close()?;
        let remote_addr = conn.remote_addr();

        Ok(vec![(remote_addr, fin.to_bytes())])
    }

    /// Reset a connection immediately
    pub fn reset(&mut self, connection_id: ConnectionId) -> Result<Vec<(SocketAddr, Vec<u8>)>, ConstrainedError> {
        let conn = self.connections.get_mut(&connection_id)
            .ok_or(ConstrainedError::ConnectionNotFound(connection_id))?;

        let rst = conn.reset();
        let remote_addr = conn.remote_addr();

        // Remove the connection immediately
        self.connections.remove(&connection_id);
        self.addr_to_conn.retain(|_, id| *id != connection_id);

        Ok(vec![(remote_addr, rst.to_bytes())])
    }

    /// Poll the engine for maintenance tasks
    ///
    /// This should be called periodically. Returns packets that need to be transmitted.
    pub fn poll(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        if now.duration_since(self.last_poll) < self.config.poll_interval {
            return Vec::new();
        }
        self.last_poll = now;

        let mut responses = Vec::new();
        let mut to_remove = Vec::new();

        for (conn_id, conn) in &mut self.connections {
            // Poll connection for retransmissions and keepalives
            let packets = conn.poll();
            let remote_addr = conn.remote_addr();

            for pkt in packets {
                responses.push((remote_addr, pkt.to_bytes()));
            }

            // Check for events
            while let Some(event) = conn.next_event() {
                match event {
                    ConnectionEvent::Closed | ConnectionEvent::Reset => {
                        to_remove.push(*conn_id);
                        self.events.push(EngineEvent::ConnectionClosed {
                            connection_id: *conn_id,
                        });
                    }
                    ConnectionEvent::Error(err) => {
                        to_remove.push(*conn_id);
                        self.events.push(EngineEvent::ConnectionError {
                            connection_id: *conn_id,
                            error: err,
                        });
                    }
                    _ => {}
                }
            }

            // Check if connection should be cleaned up
            if conn.is_closed() {
                to_remove.push(*conn_id);
            }
        }

        // Clean up closed connections
        for conn_id in to_remove {
            if let Some(conn) = self.connections.remove(&conn_id) {
                self.addr_to_conn.remove(&conn.remote_addr());
            }
        }

        responses
    }

    /// Get next pending event
    pub fn next_event(&mut self) -> Option<EngineEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// Check if a connection exists
    pub fn has_connection(&self, connection_id: ConnectionId) -> bool {
        self.connections.contains_key(&connection_id)
    }

    /// Get connection by remote address
    pub fn connection_for_addr(&self, addr: &SocketAddr) -> Option<ConnectionId> {
        self.addr_to_conn.get(addr).copied()
    }

    /// Get list of active connection IDs
    pub fn active_connections(&self) -> Vec<ConnectionId> {
        self.connections.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_engine_new() {
        let engine = ConstrainedEngine::with_defaults();
        assert_eq!(engine.connection_count(), 0);
        assert!(engine.can_accept_connection());
    }

    #[test]
    fn test_engine_connect() {
        let mut engine = ConstrainedEngine::with_defaults();
        let (conn_id, packet) = engine.connect(test_addr(8080)).expect("connect");

        assert_eq!(engine.connection_count(), 1);
        assert!(engine.has_connection(conn_id));
        assert!(!packet.is_empty());

        // Verify it's a SYN packet
        let pkt = ConstrainedPacket::from_bytes(&packet).expect("parse");
        assert!(pkt.header.is_syn());
        assert!(!pkt.header.is_ack());
    }

    #[test]
    fn test_engine_connect_duplicate() {
        let mut engine = ConstrainedEngine::with_defaults();
        let addr = test_addr(8080);

        engine.connect(addr).expect("first connect");
        let result = engine.connect(addr);

        assert!(result.is_err());
    }

    #[test]
    fn test_engine_max_connections() {
        let config = EngineConfig {
            max_connections: 2,
            ..Default::default()
        };
        let mut engine = ConstrainedEngine::new(config);

        engine.connect(test_addr(8080)).expect("connect 1");
        engine.connect(test_addr(8081)).expect("connect 2");

        // Third should fail
        let result = engine.connect(test_addr(8082));
        assert!(result.is_err());
    }

    #[test]
    fn test_engine_accept_connection() {
        let mut engine = ConstrainedEngine::with_defaults();

        // Create a SYN packet
        let syn = ConstrainedPacket::control(
            super::super::header::ConstrainedHeader::syn(ConnectionId::new(0x1234)),
        );

        let responses = engine.process_incoming(test_addr(8080), &syn.to_bytes())
            .expect("process SYN");

        // Should have a SYN-ACK response
        assert_eq!(responses.len(), 1);
        let syn_ack = ConstrainedPacket::from_bytes(&responses[0].1).expect("parse");
        assert!(syn_ack.header.is_syn_ack());

        // Check event
        let event = engine.next_event();
        assert!(matches!(event, Some(EngineEvent::ConnectionAccepted { .. })));
    }

    #[test]
    fn test_engine_handshake() {
        let mut initiator = ConstrainedEngine::with_defaults();
        let mut responder = ConstrainedEngine::with_defaults();

        let initiator_addr = test_addr(8080);
        let responder_addr = test_addr(9090);

        // Initiator sends SYN
        let (conn_id, syn_packet) = initiator.connect(responder_addr).expect("connect");

        // Responder receives SYN, sends SYN-ACK
        let responses = responder.process_incoming(initiator_addr, &syn_packet)
            .expect("process SYN");
        assert_eq!(responses.len(), 1);

        // Initiator receives SYN-ACK
        let responses = initiator.process_incoming(responder_addr, &responses[0].1)
            .expect("process SYN-ACK");

        // Should have ACK response (from poll)
        assert!(!responses.is_empty());

        // Check initiator got connected event
        let event = initiator.next_event();
        assert!(matches!(event, Some(EngineEvent::ConnectionEstablished { connection_id }) if connection_id == conn_id));
    }

    #[test]
    fn test_engine_config_for_ble() {
        let config = EngineConfig::for_ble();
        assert_eq!(config.max_connections, 4);
        assert_eq!(config.connection_config.mss, 235);
    }

    #[test]
    fn test_engine_config_for_lora() {
        let config = EngineConfig::for_lora();
        assert_eq!(config.max_connections, 2);
        assert_eq!(config.connection_config.mss, 50);
    }

    #[test]
    fn test_engine_close_not_found() {
        let mut engine = ConstrainedEngine::with_defaults();

        // Try to close a non-existent connection
        let result = engine.close(ConnectionId::new(0x9999));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConstrainedError::ConnectionNotFound(_))
        ));
    }

    #[test]
    fn test_engine_reset() {
        let mut engine = ConstrainedEngine::with_defaults();
        let (conn_id, _) = engine.connect(test_addr(8080)).expect("connect");

        let responses = engine.reset(conn_id).expect("reset");

        assert_eq!(responses.len(), 1);
        let rst = ConstrainedPacket::from_bytes(&responses[0].1).expect("parse");
        assert!(rst.header.is_rst());

        // Connection should be removed
        assert!(!engine.has_connection(conn_id));
    }

    #[test]
    fn test_engine_poll() {
        let mut engine = ConstrainedEngine::with_defaults();
        engine.connect(test_addr(8080)).expect("connect");

        // Poll should work without panicking
        let _ = engine.poll();
    }

    #[test]
    fn test_engine_active_connections() {
        let mut engine = ConstrainedEngine::with_defaults();
        let (id1, _) = engine.connect(test_addr(8080)).expect("connect 1");
        let (id2, _) = engine.connect(test_addr(8081)).expect("connect 2");

        let active = engine.active_connections();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&id1));
        assert!(active.contains(&id2));
    }
}
