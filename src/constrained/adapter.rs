// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Engine Adapter for Transport Integration
//!
//! This module provides the adapter layer that connects the constrained protocol engine
//! to transport providers. It abstracts the engine interface for easy integration.

use super::engine::{ConstrainedEngine, EngineConfig, EngineEvent};
use super::state::ConnectionState;
use super::types::{ConnectionId, ConstrainedAddr, ConstrainedError};
use crate::transport::TransportAddr;
use std::net::SocketAddr;

/// Output from the engine to be transmitted
#[derive(Debug, Clone)]
pub struct EngineOutput {
    /// Destination address
    pub destination: TransportAddr,
    /// Packet data to send
    pub data: Vec<u8>,
}

impl EngineOutput {
    /// Create a new engine output
    pub fn new(destination: TransportAddr, data: Vec<u8>) -> Self {
        Self { destination, data }
    }
}

/// Adapter that wraps ConstrainedEngine for transport integration
///
/// This provides a transport-agnostic interface for the constrained engine,
/// handling address translation between `TransportAddr` and `SocketAddr`.
#[derive(Debug)]
pub struct ConstrainedEngineAdapter {
    /// The underlying engine
    engine: ConstrainedEngine,
    /// Mapping from TransportAddr to internal SocketAddr
    /// (for non-UDP transports that need a synthetic address)
    addr_map: std::collections::HashMap<TransportAddr, SocketAddr>,
    /// Reverse mapping from SocketAddr to TransportAddr
    reverse_map: std::collections::HashMap<SocketAddr, TransportAddr>,
    /// Next synthetic address counter (for BLE/LoRa)
    next_synthetic: u32,
}

impl ConstrainedEngineAdapter {
    /// Create a new adapter with the given configuration
    pub fn new(config: EngineConfig) -> Self {
        Self {
            engine: ConstrainedEngine::new(config),
            addr_map: std::collections::HashMap::new(),
            reverse_map: std::collections::HashMap::new(),
            next_synthetic: 1,
        }
    }

    /// Create adapter with BLE configuration
    pub fn for_ble() -> Self {
        Self::new(EngineConfig::for_ble())
    }

    /// Create adapter with LoRa configuration
    pub fn for_lora() -> Self {
        Self::new(EngineConfig::for_lora())
    }

    /// Get or create a synthetic SocketAddr for a TransportAddr
    ///
    /// For non-UDP transports (BLE, LoRa, etc.), we create a synthetic
    /// SocketAddr that maps to the real transport address.
    fn get_or_create_socket_addr(&mut self, addr: &TransportAddr) -> SocketAddr {
        if let TransportAddr::Udp(socket_addr) = addr {
            // UDP addresses can be used directly
            return *socket_addr;
        }

        // For other transports, use existing mapping or create new synthetic address
        if let Some(socket_addr) = self.addr_map.get(addr) {
            return *socket_addr;
        }

        // Create synthetic address in the 127.x.x.x range
        let ip = std::net::Ipv4Addr::new(
            127,
            ((self.next_synthetic >> 16) & 0xFF) as u8,
            ((self.next_synthetic >> 8) & 0xFF) as u8,
            (self.next_synthetic & 0xFF) as u8,
        );
        let socket_addr = SocketAddr::new(std::net::IpAddr::V4(ip), (self.next_synthetic % 65535) as u16);
        self.next_synthetic += 1;

        self.addr_map.insert(addr.clone(), socket_addr);
        self.reverse_map.insert(socket_addr, addr.clone());

        socket_addr
    }

    /// Convert a SocketAddr back to TransportAddr
    fn socket_to_transport(&self, socket_addr: &SocketAddr) -> TransportAddr {
        self.reverse_map
            .get(socket_addr)
            .cloned()
            .unwrap_or(TransportAddr::Udp(*socket_addr))
    }

    /// Initiate a connection to a remote address
    pub fn connect(&mut self, remote: &TransportAddr) -> Result<(ConnectionId, Vec<EngineOutput>), ConstrainedError> {
        let socket_addr = self.get_or_create_socket_addr(remote);
        let (conn_id, packet) = self.engine.connect(socket_addr)?;
        let output = EngineOutput::new(remote.clone(), packet);
        Ok((conn_id, vec![output]))
    }

    /// Process an incoming packet from a transport
    pub fn process_incoming(
        &mut self,
        source: &TransportAddr,
        data: &[u8],
    ) -> Result<Vec<EngineOutput>, ConstrainedError> {
        let socket_addr = self.get_or_create_socket_addr(source);
        let responses = self.engine.process_incoming(socket_addr, data)?;

        Ok(responses
            .into_iter()
            .map(|(addr, packet)| {
                let dest = self.socket_to_transport(&addr);
                EngineOutput::new(dest, packet)
            })
            .collect())
    }

    /// Send data on an established connection
    pub fn send(
        &mut self,
        connection_id: ConnectionId,
        data: &[u8],
    ) -> Result<Vec<EngineOutput>, ConstrainedError> {
        let responses = self.engine.send(connection_id, data)?;

        Ok(responses
            .into_iter()
            .map(|(addr, packet)| {
                let dest = self.socket_to_transport(&addr);
                EngineOutput::new(dest, packet)
            })
            .collect())
    }

    /// Receive data from a connection (if available)
    pub fn recv(&mut self, connection_id: ConnectionId) -> Option<Vec<u8>> {
        self.engine.recv(connection_id)
    }

    /// Close a connection
    pub fn close(&mut self, connection_id: ConnectionId) -> Result<Vec<EngineOutput>, ConstrainedError> {
        let responses = self.engine.close(connection_id)?;

        Ok(responses
            .into_iter()
            .map(|(addr, packet)| {
                let dest = self.socket_to_transport(&addr);
                EngineOutput::new(dest, packet)
            })
            .collect())
    }

    /// Poll for timeouts and retransmissions
    pub fn poll(&mut self) -> Vec<EngineOutput> {
        let responses = self.engine.poll();

        responses
            .into_iter()
            .map(|(addr, packet)| {
                let dest = self.socket_to_transport(&addr);
                EngineOutput::new(dest, packet)
            })
            .collect()
    }

    /// Get the next event from the engine
    pub fn next_event(&mut self) -> Option<AdapterEvent> {
        self.engine.next_event().map(|event| match event {
            EngineEvent::ConnectionAccepted { connection_id, remote_addr } => {
                let addr = self.socket_to_transport(&remote_addr);
                AdapterEvent::ConnectionAccepted {
                    connection_id,
                    remote_addr: ConstrainedAddr::new(addr),
                }
            }
            EngineEvent::ConnectionEstablished { connection_id } => {
                AdapterEvent::ConnectionEstablished { connection_id }
            }
            EngineEvent::DataReceived { connection_id, data } => {
                AdapterEvent::DataReceived { connection_id, data }
            }
            EngineEvent::ConnectionClosed { connection_id } => {
                AdapterEvent::ConnectionClosed { connection_id }
            }
            EngineEvent::ConnectionError { connection_id, error } => {
                AdapterEvent::ConnectionError { connection_id, error }
            }
            EngineEvent::Transmit { remote_addr, packet } => {
                let addr = self.socket_to_transport(&remote_addr);
                AdapterEvent::Transmit {
                    destination: addr,
                    packet,
                }
            }
        })
    }

    /// Get the number of active connections
    pub fn connection_count(&self) -> usize {
        self.engine.connection_count()
    }

    /// Get the underlying engine (for advanced use)
    pub fn engine(&self) -> &ConstrainedEngine {
        &self.engine
    }

    /// Get mutable access to the underlying engine
    pub fn engine_mut(&mut self) -> &mut ConstrainedEngine {
        &mut self.engine
    }

    /// Get the state of a specific connection
    pub fn connection_state(&self, connection_id: ConnectionId) -> Option<ConnectionState> {
        self.engine.connection_state(connection_id)
    }

    /// Get all active connection IDs
    pub fn active_connections(&self) -> Vec<ConnectionId> {
        self.engine.active_connections()
    }
}

/// Events from the adapter (transport-agnostic)
#[derive(Debug, Clone)]
pub enum AdapterEvent {
    /// New incoming connection accepted
    ConnectionAccepted {
        /// Connection ID
        connection_id: ConnectionId,
        /// Remote address
        remote_addr: ConstrainedAddr,
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
        destination: TransportAddr,
        /// Packet data
        packet: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let adapter = ConstrainedEngineAdapter::for_ble();
        assert_eq!(adapter.connection_count(), 0);
    }

    #[test]
    fn test_adapter_connect_udp() {
        let mut adapter = ConstrainedEngineAdapter::for_ble();
        let addr = TransportAddr::Udp("192.168.1.100:8080".parse().unwrap());

        let result = adapter.connect(&addr);
        assert!(result.is_ok());

        let (_conn_id, outputs) = result.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].destination, addr);
        assert!(!outputs[0].data.is_empty());
        assert_eq!(adapter.connection_count(), 1);
    }

    #[test]
    fn test_adapter_connect_ble() {
        let mut adapter = ConstrainedEngineAdapter::for_ble();
        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let result = adapter.connect(&addr);
        assert!(result.is_ok());

        let (_conn_id, outputs) = result.unwrap();
        assert_eq!(outputs.len(), 1);
        // For BLE, the destination should be preserved
        assert_eq!(outputs[0].destination, addr);
        assert!(!outputs[0].data.is_empty());
    }

    #[test]
    fn test_adapter_synthetic_address_reuse() {
        let mut adapter = ConstrainedEngineAdapter::for_ble();
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        // Get synthetic address twice - should be the same
        let socket1 = adapter.get_or_create_socket_addr(&addr);
        let socket2 = adapter.get_or_create_socket_addr(&addr);
        assert_eq!(socket1, socket2);
    }

    #[test]
    fn test_adapter_different_addresses() {
        let mut adapter = ConstrainedEngineAdapter::for_ble();

        let addr1 = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };
        let addr2 = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let socket1 = adapter.get_or_create_socket_addr(&addr1);
        let socket2 = adapter.get_or_create_socket_addr(&addr2);

        // Different BLE devices should get different synthetic addresses
        assert_ne!(socket1, socket2);
    }

    #[test]
    fn test_adapter_poll() {
        let mut adapter = ConstrainedEngineAdapter::for_ble();

        // Poll should return empty when no connections
        let outputs = adapter.poll();
        assert!(outputs.is_empty());
    }
}
