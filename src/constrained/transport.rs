// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Constrained Transport Wrapper
//!
//! This module provides a wrapper that integrates the constrained protocol engine
//! with any transport provider. It handles the routing of packets through the
//! constrained engine for reliable delivery over low-bandwidth transports.

use super::adapter::{AdapterEvent, ConstrainedEngineAdapter, EngineOutput};
use super::engine::EngineConfig;
use super::types::{ConnectionId, ConstrainedError};
use crate::transport::{TransportAddr, TransportCapabilities};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Configuration for the constrained transport wrapper
#[derive(Debug, Clone)]
pub struct ConstrainedTransportConfig {
    /// Engine configuration
    pub engine_config: EngineConfig,
    /// Channel buffer size for outbound packets
    pub outbound_buffer_size: usize,
    /// Channel buffer size for events
    pub event_buffer_size: usize,
}

impl Default for ConstrainedTransportConfig {
    fn default() -> Self {
        Self {
            engine_config: EngineConfig::default(),
            outbound_buffer_size: 64,
            event_buffer_size: 32,
        }
    }
}

impl ConstrainedTransportConfig {
    /// Create config for BLE transport
    pub fn for_ble() -> Self {
        Self {
            engine_config: EngineConfig::for_ble(),
            outbound_buffer_size: 32,
            event_buffer_size: 16,
        }
    }

    /// Create config for LoRa transport
    pub fn for_lora() -> Self {
        Self {
            engine_config: EngineConfig::for_lora(),
            outbound_buffer_size: 8,
            event_buffer_size: 8,
        }
    }
}

/// Handle for sending data through the constrained transport
#[derive(Clone, Debug)]
pub struct ConstrainedHandle {
    /// Shared adapter
    adapter: Arc<Mutex<ConstrainedEngineAdapter>>,
    /// Channel for outbound packets
    outbound_tx: mpsc::Sender<EngineOutput>,
}

impl ConstrainedHandle {
    /// Initiate a connection to a remote address
    pub fn connect(&self, remote: &TransportAddr) -> Result<ConnectionId, ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        let (conn_id, outputs) = adapter.connect(remote)?;

        // Queue outputs for transmission
        for output in outputs {
            let _ = self.outbound_tx.try_send(output);
        }

        Ok(conn_id)
    }

    /// Send data on an established connection
    pub fn send(&self, connection_id: ConnectionId, data: &[u8]) -> Result<(), ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        let outputs = adapter.send(connection_id, data)?;

        for output in outputs {
            let _ = self.outbound_tx.try_send(output);
        }

        Ok(())
    }

    /// Receive data from a connection
    pub fn recv(&self, connection_id: ConnectionId) -> Result<Option<Vec<u8>>, ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        Ok(adapter.recv(connection_id))
    }

    /// Close a connection
    pub fn close(&self, connection_id: ConnectionId) -> Result<(), ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        let outputs = adapter.close(connection_id)?;

        for output in outputs {
            let _ = self.outbound_tx.try_send(output);
        }

        Ok(())
    }

    /// Get the number of active connections
    pub fn connection_count(&self) -> usize {
        self.adapter.lock().map(|a| a.connection_count()).unwrap_or(0)
    }

    /// Process an incoming packet
    pub fn process_incoming(&self, source: &TransportAddr, data: &[u8]) -> Result<(), ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        let outputs = adapter.process_incoming(source, data)?;

        for output in outputs {
            let _ = self.outbound_tx.try_send(output);
        }

        Ok(())
    }

    /// Poll for timeouts and get any pending outputs
    pub fn poll(&self) -> Vec<EngineOutput> {
        let mut adapter = match self.adapter.lock() {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };

        adapter.poll()
    }

    /// Get the next event from the engine
    pub fn next_event(&self) -> Option<AdapterEvent> {
        self.adapter.lock().ok().and_then(|mut a| a.next_event())
    }

    /// Get the state of a specific connection
    pub fn connection_state(
        &self,
        connection_id: ConnectionId,
    ) -> Option<crate::constrained::ConnectionState> {
        self.adapter
            .lock()
            .ok()
            .and_then(|a| a.connection_state(connection_id))
    }

    /// Get all active connection IDs
    pub fn active_connections(&self) -> Vec<ConnectionId> {
        self.adapter
            .lock()
            .ok()
            .map(|a| a.active_connections())
            .unwrap_or_default()
    }
}

/// Constrained transport wrapper
///
/// Combines a constrained engine adapter with channels for packet I/O.
/// This is designed to be integrated with a transport provider.
pub struct ConstrainedTransport {
    /// Shared adapter
    adapter: Arc<Mutex<ConstrainedEngineAdapter>>,
    /// Channel for outbound packets
    outbound_tx: mpsc::Sender<EngineOutput>,
    /// Receiver for outbound packets (to be consumed by transport)
    outbound_rx: mpsc::Receiver<EngineOutput>,
    /// Configuration
    config: ConstrainedTransportConfig,
}

impl ConstrainedTransport {
    /// Create a new constrained transport wrapper
    pub fn new(config: ConstrainedTransportConfig) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_buffer_size);
        let adapter = ConstrainedEngineAdapter::new(config.engine_config.clone());

        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            outbound_tx,
            outbound_rx,
            config,
        }
    }

    /// Create for BLE transport
    pub fn for_ble() -> Self {
        Self::new(ConstrainedTransportConfig::for_ble())
    }

    /// Create for LoRa transport
    pub fn for_lora() -> Self {
        Self::new(ConstrainedTransportConfig::for_lora())
    }

    /// Get a handle for sending/receiving data
    pub fn handle(&self) -> ConstrainedHandle {
        ConstrainedHandle {
            adapter: Arc::clone(&self.adapter),
            outbound_tx: self.outbound_tx.clone(),
        }
    }

    /// Get the outbound packet receiver
    ///
    /// The transport provider should poll this to get packets to send.
    pub fn take_outbound_rx(&mut self) -> mpsc::Receiver<EngineOutput> {
        let (new_tx, new_rx) = mpsc::channel(self.config.outbound_buffer_size);

        // Swap the sender and receiver
        let _ = std::mem::replace(&mut self.outbound_tx, new_tx);
        std::mem::replace(&mut self.outbound_rx, new_rx)
    }

    /// Process an incoming packet
    pub fn process_incoming(&self, source: &TransportAddr, data: &[u8]) -> Result<(), ConstrainedError> {
        let mut adapter = self.adapter.lock().map_err(|_| {
            ConstrainedError::Transport("adapter lock poisoned".into())
        })?;

        let outputs = adapter.process_incoming(source, data)?;

        for output in outputs {
            let _ = self.outbound_tx.try_send(output);
        }

        Ok(())
    }

    /// Poll for timeouts and retransmissions
    pub fn poll(&self) {
        if let Ok(mut adapter) = self.adapter.lock() {
            let outputs = adapter.poll();
            for output in outputs {
                let _ = self.outbound_tx.try_send(output);
            }
        }
    }

    /// Check if a transport should use the constrained engine
    pub fn should_use_constrained(capabilities: &TransportCapabilities) -> bool {
        !capabilities.supports_full_quic()
    }
}

impl std::fmt::Debug for ConstrainedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConstrainedTransport")
            .field("config", &self.config)
            .field("connection_count", &self.adapter.lock().map(|a| a.connection_count()).unwrap_or(0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constrained_transport_creation() {
        let transport = ConstrainedTransport::for_ble();
        let handle = transport.handle();
        assert_eq!(handle.connection_count(), 0);
    }

    #[test]
    fn test_constrained_handle_connect() {
        let transport = ConstrainedTransport::for_ble();
        let handle = transport.handle();

        let addr = TransportAddr::Ble {
            device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            service_uuid: None,
        };

        let result = handle.connect(&addr);
        assert!(result.is_ok());
        assert_eq!(handle.connection_count(), 1);
    }

    #[test]
    fn test_constrained_config_presets() {
        let ble_config = ConstrainedTransportConfig::for_ble();
        assert_eq!(ble_config.outbound_buffer_size, 32);

        let lora_config = ConstrainedTransportConfig::for_lora();
        assert_eq!(lora_config.outbound_buffer_size, 8);
    }

    #[test]
    fn test_should_use_constrained() {
        use crate::transport::TransportCapabilities;

        // BLE should use constrained (MTU < 1200)
        let ble_caps = TransportCapabilities::ble();
        assert!(ConstrainedTransport::should_use_constrained(&ble_caps));

        // LoRa should use constrained
        let lora_caps = TransportCapabilities::lora_long_range();
        assert!(ConstrainedTransport::should_use_constrained(&lora_caps));

        // Broadband (UDP-like) should NOT use constrained
        let broadband_caps = TransportCapabilities::broadband();
        assert!(!ConstrainedTransport::should_use_constrained(&broadband_caps));
    }

    #[tokio::test]
    async fn test_handle_clone() {
        let transport = ConstrainedTransport::for_ble();
        let handle1 = transport.handle();
        let handle2 = transport.handle();

        // Both handles should see the same state
        let addr = TransportAddr::Ble {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            service_uuid: None,
        };

        let _ = handle1.connect(&addr);
        assert_eq!(handle1.connection_count(), 1);
        assert_eq!(handle2.connection_count(), 1);
    }
}
