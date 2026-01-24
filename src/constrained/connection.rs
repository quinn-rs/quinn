// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Constrained protocol connection management
//!
//! This module provides the [`ConstrainedConnection`] struct which combines
//! the state machine, ARQ layer, and packet handling into a cohesive connection.

use super::arq::{ArqConfig, ReceiveWindow, SendWindow};
use super::header::{ConstrainedHeader, ConstrainedPacket};
use super::state::{ConnectionState, StateEvent, StateMachine};
use super::types::{ConnectionId, ConstrainedError, SequenceNumber};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Maximum segment size for constrained protocol
/// BLE: 247 - L2CAP(4) - ATT(3) - HEADER(5) = 235 bytes
pub const DEFAULT_MSS: usize = 235;

/// Default maximum transmission unit
pub const DEFAULT_MTU: usize = 247;

/// Connection configuration for constrained protocol
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// ARQ configuration
    pub arq: ArqConfig,
    /// Maximum segment size (payload only)
    pub mss: usize,
    /// Maximum transmission unit (header + payload)
    pub mtu: usize,
    /// Keep-alive interval (0 = disabled)
    pub keepalive_interval: Duration,
    /// Maximum idle time before connection timeout
    pub idle_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            arq: ArqConfig::default(),
            mss: DEFAULT_MSS,
            mtu: DEFAULT_MTU,
            keepalive_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

impl ConnectionConfig {
    /// Create configuration optimized for BLE
    pub fn for_ble() -> Self {
        Self {
            arq: ArqConfig::for_ble(),
            mss: 235,
            mtu: 247,
            keepalive_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(120),
        }
    }

    /// Create configuration optimized for LoRa
    pub fn for_lora() -> Self {
        Self {
            arq: ArqConfig::for_lora(),
            mss: 50,  // LoRa has very small packets
            mtu: 55,
            keepalive_interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

/// Events emitted by the connection
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Connection established
    Connected,
    /// Data received
    DataReceived(Vec<u8>),
    /// Connection closed normally
    Closed,
    /// Connection reset
    Reset,
    /// Connection error
    Error(String),
    /// Packet to transmit
    Transmit(Vec<u8>),
}

/// A constrained protocol connection
///
/// Manages the full lifecycle of a connection including:
/// - State machine transitions
/// - Reliable delivery via ARQ
/// - Packet serialization/deserialization
/// - Keep-alive management
#[derive(Debug)]
pub struct ConstrainedConnection {
    /// Connection identifier
    connection_id: ConnectionId,
    /// Remote peer address
    remote_addr: SocketAddr,
    /// Connection state machine
    state: StateMachine,
    /// Send window for ARQ
    send_window: SendWindow,
    /// Receive window for ARQ
    receive_window: ReceiveWindow,
    /// Configuration
    config: ConnectionConfig,
    /// Outbound packet queue
    outbound: VecDeque<ConstrainedPacket>,
    /// Inbound data queue
    inbound: VecDeque<Vec<u8>>,
    /// Last activity time
    last_activity: Instant,
    /// Last keepalive sent
    last_keepalive: Option<Instant>,
    /// Pending events
    events: VecDeque<ConnectionEvent>,
    /// Local next sequence number
    local_seq: SequenceNumber,
    /// Whether we initiated the connection
    is_initiator: bool,
}

impl ConstrainedConnection {
    /// Create a new outbound connection (initiator)
    pub fn new_outbound(connection_id: ConnectionId, remote_addr: SocketAddr) -> Self {
        Self::new(connection_id, remote_addr, ConnectionConfig::default(), true)
    }

    /// Create a new outbound connection with config
    pub fn new_outbound_with_config(
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        config: ConnectionConfig,
    ) -> Self {
        Self::new(connection_id, remote_addr, config, true)
    }

    /// Create a new inbound connection (responder)
    pub fn new_inbound(connection_id: ConnectionId, remote_addr: SocketAddr) -> Self {
        Self::new(connection_id, remote_addr, ConnectionConfig::default(), false)
    }

    /// Create a new inbound connection with config
    pub fn new_inbound_with_config(
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        config: ConnectionConfig,
    ) -> Self {
        Self::new(connection_id, remote_addr, config, false)
    }

    /// Internal constructor
    fn new(
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        config: ConnectionConfig,
        is_initiator: bool,
    ) -> Self {
        Self {
            connection_id,
            remote_addr,
            state: StateMachine::new(),
            send_window: SendWindow::new(config.arq.clone()),
            receive_window: ReceiveWindow::new(config.arq.window_size),
            config,
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            last_activity: Instant::now(),
            last_keepalive: None,
            events: VecDeque::new(),
            local_seq: SequenceNumber::new(0),
            is_initiator,
        }
    }

    /// Get the connection ID
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Get the remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state.state()
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.state.state().is_established()
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        self.state.state().is_closed()
    }

    /// Check if we can send data
    pub fn can_send(&self) -> bool {
        self.state.can_send_data() && !self.send_window.is_full()
    }

    /// Initiate connection (for outbound connections)
    ///
    /// Returns a SYN packet to transmit.
    pub fn initiate(&mut self) -> Result<ConstrainedPacket, ConstrainedError> {
        if !self.is_initiator {
            return Err(ConstrainedError::InvalidStateTransition {
                from: "inbound".to_string(),
                to: "initiating".to_string(),
            });
        }

        self.state.transition(StateEvent::Open)?;

        let syn = ConstrainedPacket::control(ConstrainedHeader::syn(self.connection_id));

        self.last_activity = Instant::now();
        Ok(syn)
    }

    /// Accept a connection (for inbound connections after receiving SYN)
    ///
    /// Returns a SYN-ACK packet to transmit.
    pub fn accept(&mut self, syn_seq: SequenceNumber) -> Result<ConstrainedPacket, ConstrainedError> {
        if self.is_initiator {
            return Err(ConstrainedError::InvalidStateTransition {
                from: "outbound".to_string(),
                to: "accepting".to_string(),
            });
        }

        self.state.transition(StateEvent::RecvSyn)?;

        let syn_ack = ConstrainedPacket::control(
            ConstrainedHeader::syn_ack(self.connection_id, syn_seq.next()),
        );

        self.last_activity = Instant::now();
        Ok(syn_ack)
    }

    /// Send data
    ///
    /// Data may be fragmented if larger than MSS.
    pub fn send(&mut self, data: &[u8]) -> Result<(), ConstrainedError> {
        if !self.state.can_send_data() {
            return Err(ConstrainedError::ConnectionClosed);
        }

        // Fragment data if needed
        for chunk in data.chunks(self.config.mss) {
            if self.send_window.is_full() {
                return Err(ConstrainedError::SendBufferFull);
            }

            let seq = self.local_seq;
            self.local_seq = self.local_seq.next();

            self.send_window.add(seq, chunk.to_vec())?;

            let packet = ConstrainedPacket::data(
                self.connection_id,
                seq,
                self.receive_window.cumulative_ack(),
                chunk.to_vec(),
            );

            self.outbound.push_back(packet);
        }

        self.last_activity = Instant::now();
        Ok(())
    }

    /// Receive next available data
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.pop_front()
    }

    /// Close the connection gracefully
    pub fn close(&mut self) -> Result<ConstrainedPacket, ConstrainedError> {
        self.state.transition(StateEvent::Close)?;

        let fin = ConstrainedPacket::control(ConstrainedHeader::fin(
            self.connection_id,
            self.local_seq,
            self.receive_window.cumulative_ack(),
        ));

        self.last_activity = Instant::now();
        Ok(fin)
    }

    /// Reset the connection immediately
    pub fn reset(&mut self) -> ConstrainedPacket {
        // Force state to closed
        let _ = self.state.transition(StateEvent::RecvRst);

        ConstrainedPacket::control(ConstrainedHeader::reset(self.connection_id))
    }

    /// Process an incoming packet
    pub fn process_packet(&mut self, packet: &ConstrainedPacket) -> Result<(), ConstrainedError> {
        self.last_activity = Instant::now();
        let header = &packet.header;

        // Handle RST immediately
        if header.is_rst() {
            let _ = self.state.transition(StateEvent::RecvRst);
            self.events.push_back(ConnectionEvent::Reset);
            return Ok(());
        }

        // Process based on current state and packet type
        match self.state.state() {
            ConnectionState::Closed => {
                if header.is_syn() && !header.is_ack() {
                    // Incoming SYN - this would create a new connection
                    // Let the connection manager handle this
                }
            }

            ConnectionState::SynSent => {
                if header.is_syn_ack() {
                    self.state.transition(StateEvent::RecvSynAck)?;
                    self.receive_window.reset_with_seq(header.seq.next());

                    // Send ACK to complete handshake
                    let ack = ConstrainedPacket::control(ConstrainedHeader::ack(
                        self.connection_id,
                        self.local_seq,
                        header.seq.next(),
                    ));
                    self.outbound.push_back(ack);

                    self.events.push_back(ConnectionEvent::Connected);
                }
            }

            ConnectionState::SynReceived => {
                if header.is_ack() {
                    self.state.transition(StateEvent::RecvAck)?;
                    self.events.push_back(ConnectionEvent::Connected);
                }
            }

            ConnectionState::Established => {
                // Process ACK
                if header.is_ack() {
                    let acked = self.send_window.acknowledge(header.ack);
                    tracing::trace!(acked, ack = header.ack.value(), "Processed ACK");
                }

                // Process DATA
                if header.is_data() && !packet.payload.is_empty() {
                    if let Some(deliverable) = self.receive_window.receive(header.seq, packet.payload.clone()) {
                        for (_, data) in deliverable {
                            self.inbound.push_back(data);
                            self.events.push_back(ConnectionEvent::DataReceived(vec![]));
                        }

                        // Send ACK
                        let ack = ConstrainedPacket::control(ConstrainedHeader::ack(
                            self.connection_id,
                            self.local_seq,
                            self.receive_window.cumulative_ack(),
                        ));
                        self.outbound.push_back(ack);
                    }
                }

                // Process FIN
                if header.is_fin() {
                    self.state.transition(StateEvent::RecvFin)?;
                    let ack = ConstrainedPacket::control(ConstrainedHeader::ack(
                        self.connection_id,
                        self.local_seq,
                        header.seq.next(),
                    ));
                    self.outbound.push_back(ack);
                    self.events.push_back(ConnectionEvent::Closed);
                }

                // Process PING
                if header.is_ping() {
                    let pong = ConstrainedPacket::control(
                        ConstrainedHeader::pong(self.connection_id, header.seq),
                    );
                    self.outbound.push_back(pong);
                }
            }

            ConnectionState::FinWait => {
                if header.is_ack() {
                    self.state.transition(StateEvent::RecvAck)?;
                }
                if header.is_fin() {
                    self.state.transition(StateEvent::RecvFin)?;
                    self.events.push_back(ConnectionEvent::Closed);
                }
            }

            ConnectionState::Closing => {
                if header.is_ack() || header.is_fin() {
                    self.state.transition(StateEvent::RecvAck)?;
                }
            }

            ConnectionState::TimeWait => {
                // Ignore packets in TIME_WAIT
            }
        }

        Ok(())
    }

    /// Poll the connection for timeout handling and retransmissions
    ///
    /// Returns packets that need to be (re)transmitted.
    pub fn poll(&mut self) -> Vec<ConstrainedPacket> {
        let mut packets = Vec::new();

        // Check for state timeout
        if self.state.is_timed_out() {
            let _ = self.state.transition(StateEvent::Timeout);
            self.events.push_back(ConnectionEvent::Error("Connection timed out".to_string()));
            return packets;
        }

        // Check for idle timeout
        if self.last_activity.elapsed() > self.config.idle_timeout {
            let _ = self.state.transition(StateEvent::Timeout);
            self.events.push_back(ConnectionEvent::Error("Idle timeout".to_string()));
            return packets;
        }

        // Handle retransmissions
        match self.send_window.get_retransmissions() {
            Some(retransmit_data) => {
                for (seq, data) in retransmit_data {
                    let packet = ConstrainedPacket::data(
                        self.connection_id,
                        seq,
                        self.receive_window.cumulative_ack(),
                        data,
                    );
                    packets.push(packet);
                }
            }
            None => {
                // Max retries exceeded on at least one packet
                let _ = self.state.transition(StateEvent::Timeout);
                self.events.push_back(ConnectionEvent::Error(
                    "Maximum retransmissions exceeded".to_string(),
                ));
                return packets;
            }
        }

        // Handle keepalive
        if self.state.state().is_established() && self.config.keepalive_interval > Duration::ZERO {
            let should_ping = match self.last_keepalive {
                Some(last) => last.elapsed() > self.config.keepalive_interval,
                None => self.last_activity.elapsed() > self.config.keepalive_interval,
            };

            if should_ping {
                let ping = ConstrainedPacket::control(
                    ConstrainedHeader::ping(self.connection_id, self.local_seq),
                );
                packets.push(ping);
                self.last_keepalive = Some(Instant::now());
            }
        }

        // Drain outbound queue
        packets.extend(self.outbound.drain(..));

        packets
    }

    /// Get next pending event
    pub fn next_event(&mut self) -> Option<ConnectionEvent> {
        self.events.pop_front()
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            connection_id: self.connection_id,
            state: self.state.state(),
            remote_addr: self.remote_addr,
            is_initiator: self.is_initiator,
            send_window_used: self.send_window.len(),
            receive_buffer_len: self.inbound.len(),
            time_in_state: self.state.time_in_state(),
            last_activity: self.last_activity.elapsed(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Connection identifier
    pub connection_id: ConnectionId,
    /// Current state
    pub state: ConnectionState,
    /// Remote peer address
    pub remote_addr: SocketAddr,
    /// Whether we initiated
    pub is_initiator: bool,
    /// Send window utilization
    pub send_window_used: usize,
    /// Receive buffer length
    pub receive_buffer_len: usize,
    /// Time in current state
    pub time_in_state: Duration,
    /// Time since last activity
    pub last_activity: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_connection_new_outbound() {
        let conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        assert_eq!(conn.connection_id(), ConnectionId::new(0x1234));
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(!conn.is_established());
    }

    #[test]
    fn test_connection_initiate() {
        let mut conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());

        let syn = conn.initiate().expect("Should be able to initiate");
        assert!(syn.header.is_syn());
        assert!(!syn.header.is_ack());
        assert_eq!(conn.state(), ConnectionState::SynSent);
    }

    #[test]
    fn test_connection_accept() {
        let mut conn = ConstrainedConnection::new_inbound(ConnectionId::new(0x1234), test_addr());

        let syn_ack = conn.accept(SequenceNumber::new(0)).expect("Should accept");
        assert!(syn_ack.header.is_syn_ack());
        assert_eq!(conn.state(), ConnectionState::SynReceived);
    }

    #[test]
    fn test_connection_handshake() {
        // Initiator side
        let mut initiator = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        let syn = initiator.initiate().expect("initiate");

        // Responder side
        let mut responder = ConstrainedConnection::new_inbound(ConnectionId::new(0x1234), test_addr());
        let syn_ack = responder.accept(syn.header.seq).expect("accept");

        // Process SYN-ACK at initiator
        initiator.process_packet(&syn_ack).expect("process syn-ack");
        assert!(initiator.is_established());

        // Get ACK from initiator's outbound queue
        let packets = initiator.poll();
        assert!(!packets.is_empty());
        let ack = &packets[0];
        assert!(ack.header.is_ack());

        // Process ACK at responder
        responder.process_packet(ack).expect("process ack");
        assert!(responder.is_established());
    }

    #[test]
    fn test_connection_data_transfer() {
        // Set up connected pair
        let mut sender = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        sender.initiate().expect("initiate");

        let mut receiver = ConstrainedConnection::new_inbound(ConnectionId::new(0x1234), test_addr());
        let syn_ack = receiver.accept(SequenceNumber::new(0)).expect("accept");

        sender.process_packet(&syn_ack).expect("syn-ack");
        let packets = sender.poll();
        receiver.process_packet(&packets[0]).expect("ack");

        // Now send data
        sender.send(b"Hello, World!").expect("send");
        let data_packets = sender.poll();
        assert!(!data_packets.is_empty());

        let data_pkt = &data_packets[0];
        assert!(data_pkt.header.is_data());
        assert_eq!(data_pkt.payload, b"Hello, World!");

        // Process at receiver
        receiver.process_packet(data_pkt).expect("process data");
        let received = receiver.recv().expect("should have data");
        assert_eq!(received, b"Hello, World!");
    }

    #[test]
    fn test_connection_fragmentation() {
        let config = ConnectionConfig {
            mss: 10, // Very small MSS for testing
            ..Default::default()
        };

        let mut conn = ConstrainedConnection::new_outbound_with_config(
            ConnectionId::new(0x1234),
            test_addr(),
            config,
        );
        conn.initiate().expect("initiate");

        // Simulate established state
        conn.state.transition(StateEvent::RecvSynAck).expect("established");

        // Send data larger than MSS
        let data = b"Hello, this is a longer message!";
        conn.send(data).expect("send");

        let packets = conn.poll();
        // Should be fragmented into multiple packets
        assert!(packets.len() >= 3);
    }

    #[test]
    fn test_connection_close() {
        let mut conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        conn.initiate().expect("initiate");
        conn.state.transition(StateEvent::RecvSynAck).expect("established");

        let fin = conn.close().expect("close");
        assert!(fin.header.is_fin());
        assert_eq!(conn.state(), ConnectionState::FinWait);
    }

    #[test]
    fn test_connection_reset() {
        let mut conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        conn.initiate().expect("initiate");

        let rst = conn.reset();
        assert!(rst.header.is_rst());
        assert!(conn.is_closed());
    }

    #[test]
    fn test_connection_stats() {
        let conn = ConstrainedConnection::new_outbound(ConnectionId::new(0xABCD), test_addr());
        let stats = conn.stats();

        assert_eq!(stats.connection_id, ConnectionId::new(0xABCD));
        assert_eq!(stats.state, ConnectionState::Closed);
        assert!(stats.is_initiator);
        assert_eq!(stats.send_window_used, 0);
    }

    #[test]
    fn test_config_for_ble() {
        let config = ConnectionConfig::for_ble();
        assert_eq!(config.mss, 235);
        assert_eq!(config.mtu, 247);
        assert_eq!(config.arq.window_size, 4);
    }

    #[test]
    fn test_config_for_lora() {
        let config = ConnectionConfig::for_lora();
        assert_eq!(config.mss, 50);
        assert_eq!(config.mtu, 55);
        assert!(config.keepalive_interval >= Duration::from_secs(60));
    }

    #[test]
    fn test_process_ping_pong() {
        let mut conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        conn.initiate().expect("initiate");
        conn.state.transition(StateEvent::RecvSynAck).expect("established");

        let ping = ConstrainedPacket::control(
            ConstrainedHeader::ping(ConnectionId::new(0x1234), SequenceNumber::new(5)),
        );

        conn.process_packet(&ping).expect("process ping");

        let packets = conn.poll();
        let pong = packets.iter().find(|p| p.header.is_pong());
        assert!(pong.is_some());
    }

    #[test]
    fn test_process_rst() {
        let mut conn = ConstrainedConnection::new_outbound(ConnectionId::new(0x1234), test_addr());
        conn.initiate().expect("initiate");

        let rst = ConstrainedPacket::control(ConstrainedHeader::reset(ConnectionId::new(0x1234)));

        conn.process_packet(&rst).expect("process rst");
        assert!(conn.is_closed());

        let event = conn.next_event();
        assert!(matches!(event, Some(ConnectionEvent::Reset)));
    }
}
