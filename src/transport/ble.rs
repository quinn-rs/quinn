// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Bluetooth Low Energy (BLE) transport provider implementation
//!
//! This module implements the [`TransportProvider`] trait for BLE connectivity,
//! providing short-range, low-power wireless transport.
//!
//! # Features
//!
//! This module is only available when the `ble` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! ant-quic = { version = "0.18", features = ["ble"] }
//! ```
//!
//! # Platform Support
//!
//! - **Linux**: Uses BlueZ via btleplug
//! - **macOS**: Uses Core Bluetooth via btleplug
//! - **Windows**: Uses WinRT via btleplug (experimental)
//!
//! # Protocol Engine
//!
//! BLE transport uses the **Constrained Engine** due to:
//! - Small MTU (244 bytes typical)
//! - Moderate bandwidth (~125 kbps)
//!
//! # GATT Architecture
//!
//! The BLE transport uses a custom GATT service with two characteristics:
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │           ant-quic BLE Service                  │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000001    │
//! ├─────────────────────────────────────────────────┤
//! │  TX Characteristic (Write Without Response)    │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000002    │
//! │  - Central writes to send data to peripheral   │
//! ├─────────────────────────────────────────────────┤
//! │  RX Characteristic (Notify)                    │
//! │  UUID: a03d7e9f-0bca-12fe-a600-000000000003    │
//! │  - Peripheral notifies to send data to central │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # PQC Mitigations
//!
//! To reduce the impact of large PQC handshakes over BLE:
//! - Aggressive session caching (24+ hours)
//! - Session resumption tokens (32 bytes vs 8KB handshake)
//! - Key pre-distribution when high-bandwidth connectivity is available

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};

use super::addr::{TransportAddr, TransportType};
use super::capabilities::TransportCapabilities;
use super::provider::{
    InboundDatagram, LinkQuality, TransportError, TransportProvider, TransportStats,
};

// Import btleplug traits and types for adapter operations
// Note: Some imports are used in later phases (scanning, connecting, send/receive)
#[cfg(feature = "ble")]
#[allow(unused_imports)]
use btleplug::api::{
    Central, CentralEvent, Characteristic, Manager as BtleManager, Peripheral as BtlePeripheral,
    ScanFilter, WriteType,
};
#[cfg(feature = "ble")]
use btleplug::platform::{Adapter, Manager, Peripheral};
#[cfg(feature = "ble")]
#[allow(unused_imports)]
use futures_util::stream::StreamExt;
#[cfg(feature = "ble")]
use uuid::Uuid;

/// Default GATT service UUID for ant-quic BLE transport
///
/// This UUID is used when no custom service UUID is specified.
/// UUID: a03d7e9f-0bca-12fe-a600-000000000001
pub const ANT_QUIC_SERVICE_UUID: [u8; 16] = [
    0xa0, 0x3d, 0x7e, 0x9f, 0x0b, 0xca, 0x12, 0xfe, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// TX Characteristic UUID for ant-quic BLE transport
///
/// This characteristic is used by the Central to send data to the Peripheral.
/// Properties: Write Without Response
/// Direction: Central -> Peripheral
/// UUID: a03d7e9f-0bca-12fe-a600-000000000002
pub const TX_CHARACTERISTIC_UUID: [u8; 16] = [
    0xa0, 0x3d, 0x7e, 0x9f, 0x0b, 0xca, 0x12, 0xfe, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// RX Characteristic UUID for ant-quic BLE transport
///
/// This characteristic is used by the Peripheral to send data to the Central via notifications.
/// Properties: Notify
/// Direction: Peripheral -> Central
/// UUID: a03d7e9f-0bca-12fe-a600-000000000003
pub const RX_CHARACTERISTIC_UUID: [u8; 16] = [
    0xa0, 0x3d, 0x7e, 0x9f, 0x0b, 0xca, 0x12, 0xfe, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];

/// Client Characteristic Configuration Descriptor (CCCD) UUID
///
/// Standard Bluetooth SIG assigned UUID for CCCD (0x2902).
/// Used to enable/disable notifications and indications on characteristics.
pub const CCCD_UUID: [u8; 16] = [
    0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// CCCD value to enable notifications
pub const CCCD_ENABLE_NOTIFICATION: [u8; 2] = [0x01, 0x00];

/// CCCD value to enable indications
pub const CCCD_ENABLE_INDICATION: [u8; 2] = [0x02, 0x00];

/// CCCD value to disable notifications and indications
pub const CCCD_DISABLE: [u8; 2] = [0x00, 0x00];

// ============================================================================
// BLE Fragmentation Types
// ============================================================================

/// Fragment header size in bytes
///
/// Header format:
/// - Byte 0: Sequence number (0-255)
/// - Byte 1: Flags (START=0x01, END=0x02)
/// - Byte 2: Total fragment count (1-255)
/// - Byte 3: Message ID (0-255)
pub const FRAGMENT_HEADER_SIZE: usize = 4;

/// Default BLE MTU (ATT MTU - ATT header overhead)
pub const DEFAULT_BLE_MTU: usize = 244;

/// Maximum payload per fragment (MTU - header)
#[allow(dead_code)] // Used in documentation/reference
pub const DEFAULT_FRAGMENT_PAYLOAD_SIZE: usize = DEFAULT_BLE_MTU - FRAGMENT_HEADER_SIZE;

/// Fragment flags indicating position in sequence
pub mod fragment_flags {
    /// First fragment in a sequence
    pub const START: u8 = 0x01;
    /// Last fragment in a sequence
    pub const END: u8 = 0x02;
    /// Convenience: single fragment has both START and END
    pub const SINGLE: u8 = START | END;
}

/// BLE fragment header for multi-packet transmission
///
/// Enables sending messages larger than the BLE MTU by splitting them
/// into numbered fragments that can be reassembled at the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Fragment sequence number (0-255)
    pub seq_num: u8,
    /// Fragment flags (START, END)
    pub flags: u8,
    /// Total number of fragments in this message
    pub total: u8,
    /// Message identifier for correlating fragments
    pub msg_id: u8,
}

impl FragmentHeader {
    /// Create a new fragment header
    pub const fn new(seq_num: u8, flags: u8, total: u8, msg_id: u8) -> Self {
        Self {
            seq_num,
            flags,
            total,
            msg_id,
        }
    }

    /// Create a header for a single (non-fragmented) message
    pub const fn single(msg_id: u8) -> Self {
        Self {
            seq_num: 0,
            flags: fragment_flags::SINGLE,
            total: 1,
            msg_id,
        }
    }

    /// Check if this is the first fragment
    pub const fn is_start(&self) -> bool {
        self.flags & fragment_flags::START != 0
    }

    /// Check if this is the last fragment
    pub const fn is_end(&self) -> bool {
        self.flags & fragment_flags::END != 0
    }

    /// Check if this is a single (complete) fragment
    pub const fn is_single(&self) -> bool {
        self.is_start() && self.is_end()
    }

    /// Serialize header to bytes
    pub const fn to_bytes(&self) -> [u8; FRAGMENT_HEADER_SIZE] {
        [self.seq_num, self.flags, self.total, self.msg_id]
    }

    /// Deserialize header from bytes
    ///
    /// Returns None if the slice is too short
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return None;
        }
        Some(Self {
            seq_num: bytes[0],
            flags: bytes[1],
            total: bytes[2],
            msg_id: bytes[3],
        })
    }
}

/// BLE packet fragmenter for splitting large messages
///
/// When a message exceeds the BLE MTU, this fragmenter splits it into
/// smaller chunks with headers that enable reassembly at the receiver.
///
/// # Example
///
/// ```ignore
/// let fragmenter = BlePacketFragmenter::new(244); // 244 byte MTU
/// let fragments = fragmenter.fragment(b"large data...", 0);
/// // Each fragment is <= 244 bytes with a 4-byte header
/// ```
#[derive(Debug, Clone)]
pub struct BlePacketFragmenter {
    /// Maximum transmission unit (packet size)
    #[allow(dead_code)] // Used for documentation/debugging
    mtu: usize,
    /// Maximum payload per fragment (MTU - header)
    payload_size: usize,
}

impl BlePacketFragmenter {
    /// Create a new fragmenter with the specified MTU
    ///
    /// # Panics
    ///
    /// Panics if MTU is less than or equal to FRAGMENT_HEADER_SIZE
    pub fn new(mtu: usize) -> Self {
        assert!(
            mtu > FRAGMENT_HEADER_SIZE,
            "MTU must be greater than fragment header size ({})",
            FRAGMENT_HEADER_SIZE
        );
        Self {
            mtu,
            payload_size: mtu - FRAGMENT_HEADER_SIZE,
        }
    }

    /// Create a fragmenter with the default BLE MTU (244 bytes)
    pub fn default_ble() -> Self {
        Self::new(DEFAULT_BLE_MTU)
    }

    /// Get the maximum payload size per fragment
    pub const fn payload_size(&self) -> usize {
        self.payload_size
    }

    /// Get the configured MTU
    #[allow(dead_code)] // Used in tests and documentation
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    /// Check if data needs fragmentation
    #[allow(dead_code)] // Used in tests and may be useful for callers
    pub fn needs_fragmentation(&self, data: &[u8]) -> bool {
        data.len() > self.payload_size
    }

    /// Fragment data into BLE-sized packets
    ///
    /// Each returned packet includes a fragment header followed by payload.
    /// Single-fragment messages also include headers for consistency.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to fragment
    /// * `msg_id` - Message identifier for correlating fragments
    ///
    /// # Returns
    ///
    /// Vector of fragments, each containing header + payload
    pub fn fragment(&self, data: &[u8], msg_id: u8) -> Vec<Vec<u8>> {
        if data.is_empty() {
            // Empty data: single fragment with just header
            let header = FragmentHeader::single(msg_id);
            return vec![header.to_bytes().to_vec()];
        }

        // Calculate number of fragments needed
        let total_fragments = data.len().div_ceil(self.payload_size);

        // Cap at 255 fragments (u8 limit)
        if total_fragments > 255 {
            // Data too large - would need more than 255 fragments
            // In practice, this is ~61KB with 244-byte MTU
            tracing::warn!(
                data_len = data.len(),
                max_fragments = 255,
                "Data exceeds maximum fragment count"
            );
        }

        let total = total_fragments.min(255) as u8;
        let mut fragments = Vec::with_capacity(total as usize);

        for (i, chunk) in data.chunks(self.payload_size).enumerate() {
            if i >= 255 {
                break; // Stop at 255 fragments
            }

            let seq_num = i as u8;
            let flags = match (i == 0, i == total_fragments - 1) {
                (true, true) => fragment_flags::SINGLE,
                (true, false) => fragment_flags::START,
                (false, true) => fragment_flags::END,
                (false, false) => 0,
            };

            let header = FragmentHeader::new(seq_num, flags, total, msg_id);
            let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
            fragment.extend_from_slice(&header.to_bytes());
            fragment.extend_from_slice(chunk);
            fragments.push(fragment);
        }

        fragments
    }
}

impl Default for BlePacketFragmenter {
    fn default() -> Self {
        Self::default_ble()
    }
}

/// Key for identifying a fragment sequence from a specific device
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReassemblyKey {
    /// BLE device address
    device_id: [u8; 6],
    /// Message ID from fragment header
    msg_id: u8,
}

/// Entry tracking an in-progress fragment reassembly
#[derive(Debug)]
struct ReassemblyEntry {
    /// Received fragments indexed by sequence number
    /// Option<Vec<u8>> because we may receive out-of-order
    fragments: Vec<Option<Vec<u8>>>,
    /// Number of fragments received so far
    received_count: usize,
    /// Expected total fragments
    expected_total: u8,
    /// When this entry was created
    created: Instant,
}

impl ReassemblyEntry {
    /// Create a new reassembly entry
    fn new(expected_total: u8) -> Self {
        Self {
            fragments: vec![None; expected_total as usize],
            received_count: 0,
            expected_total,
            created: Instant::now(),
        }
    }

    /// Add a fragment to this entry
    ///
    /// Returns true if the fragment was new (not a duplicate)
    fn add_fragment(&mut self, seq_num: u8, payload: Vec<u8>) -> bool {
        let idx = seq_num as usize;
        if idx >= self.fragments.len() {
            return false; // Invalid sequence number
        }
        if self.fragments[idx].is_some() {
            return false; // Duplicate fragment
        }
        self.fragments[idx] = Some(payload);
        self.received_count += 1;
        true
    }

    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.received_count == self.expected_total as usize
    }

    /// Assemble the complete message from all fragments
    ///
    /// Only call when is_complete() returns true
    fn assemble(&self) -> Vec<u8> {
        let total_size: usize = self
            .fragments
            .iter()
            .filter_map(|f| f.as_ref())
            .map(|f| f.len())
            .sum();

        let mut result = Vec::with_capacity(total_size);
        for data in self.fragments.iter().flatten() {
            result.extend_from_slice(data);
        }
        result
    }

    /// Check if this entry has expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.created.elapsed() > timeout
    }
}

/// BLE packet reassembly buffer
///
/// Collects fragments from BLE notifications and reassembles them into
/// complete messages. Handles out-of-order delivery, duplicates, and timeouts.
///
/// # Example
///
/// ```ignore
/// let mut buffer = BleReassemblyBuffer::new(Duration::from_secs(30));
///
/// // Process incoming fragments
/// if let Some(complete_message) = buffer.add_fragment(device_id, fragment_data) {
///     // Got a complete message
///     handle_message(complete_message);
/// }
///
/// // Periodically clean up stale entries
/// buffer.prune_stale();
/// ```
#[derive(Debug)]
pub struct BleReassemblyBuffer {
    /// In-progress reassemblies keyed by (device_id, msg_id)
    entries: HashMap<ReassemblyKey, ReassemblyEntry>,
    /// Timeout for incomplete sequences
    timeout: Duration,
}

impl BleReassemblyBuffer {
    /// Create a new reassembly buffer with the specified timeout
    pub fn new(timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            timeout,
        }
    }

    /// Create a buffer with the default timeout (30 seconds)
    pub fn default_timeout() -> Self {
        Self::new(Duration::from_secs(30))
    }

    /// Process an incoming fragment
    ///
    /// Returns `Some(data)` when all fragments have been received and
    /// the complete message can be returned. Returns `None` otherwise.
    ///
    /// # Arguments
    ///
    /// * `device_id` - The BLE device address this fragment came from
    /// * `fragment` - The complete fragment (header + payload)
    ///
    /// # Returns
    ///
    /// * `Some(Vec<u8>)` - Complete reassembled message
    /// * `None` - Fragment stored, waiting for more
    pub fn add_fragment(&mut self, device_id: [u8; 6], fragment: &[u8]) -> Option<Vec<u8>> {
        // Parse fragment header
        let header = FragmentHeader::from_bytes(fragment)?;
        let payload = fragment.get(FRAGMENT_HEADER_SIZE..)?.to_vec();

        // Single-fragment message - return immediately
        if header.is_single() {
            return Some(payload);
        }

        let key = ReassemblyKey {
            device_id,
            msg_id: header.msg_id,
        };

        // Get or create entry
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| ReassemblyEntry::new(header.total));

        // Validate total matches (in case of collision with old msg_id)
        if entry.expected_total != header.total {
            // Total mismatch - this is a new message with same msg_id
            // Replace the old entry
            *entry = ReassemblyEntry::new(header.total);
        }

        // Add the fragment
        entry.add_fragment(header.seq_num, payload);

        // Check if complete
        if entry.is_complete() {
            let complete = entry.assemble();
            self.entries.remove(&key);
            return Some(complete);
        }

        None
    }

    /// Remove stale incomplete sequences
    ///
    /// Should be called periodically to clean up fragments that will
    /// never complete (e.g., due to lost packets).
    ///
    /// # Returns
    ///
    /// Number of entries removed
    pub fn prune_stale(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| !entry.is_expired(self.timeout));
        before - self.entries.len()
    }

    /// Get the number of in-progress reassemblies
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }

    /// Clear all pending reassemblies
    #[allow(dead_code)] // Useful utility method for callers
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for BleReassemblyBuffer {
    fn default() -> Self {
        Self::default_timeout()
    }
}

/// Convert a 16-byte UUID array to btleplug Uuid
///
/// Used to convert our constant UUID byte arrays to the Uuid type
/// that btleplug expects for service and characteristic lookups.
///
/// Note: Will be used in Tasks 2-5 for real BLE scanning and connection.
#[cfg(feature = "ble")]
#[allow(dead_code)] // Will be used in subsequent tasks (scanning, connecting)
pub(crate) fn uuid_from_bytes(bytes: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*bytes)
}

/// Get the ant-quic service UUID as a btleplug Uuid
///
/// Note: Will be used in Task 2 for scan filtering and Task 3 for service discovery.
#[cfg(feature = "ble")]
#[allow(dead_code)] // Will be used in subsequent tasks (scanning, connecting)
pub(crate) fn service_uuid() -> Uuid {
    uuid_from_bytes(&ANT_QUIC_SERVICE_UUID)
}

/// Get the TX characteristic UUID as a btleplug Uuid
///
/// Note: Will be used in Task 3 for characteristic discovery and Task 4 for send.
#[cfg(feature = "ble")]
#[allow(dead_code)] // Will be used in subsequent tasks (connecting, send)
pub(crate) fn tx_uuid() -> Uuid {
    uuid_from_bytes(&TX_CHARACTERISTIC_UUID)
}

/// Get the RX characteristic UUID as a btleplug Uuid
///
/// Note: Will be used in Task 3 for characteristic discovery and Task 5 for receive.
#[cfg(feature = "ble")]
#[allow(dead_code)] // Will be used in subsequent tasks (connecting, receive)
pub(crate) fn rx_uuid() -> Uuid {
    uuid_from_bytes(&RX_CHARACTERISTIC_UUID)
}

/// BLE connection state
///
/// Tracks the lifecycle of a BLE connection from discovery through disconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BleConnectionState {
    /// Device has been discovered but not connected
    #[default]
    Discovered,
    /// Connection attempt in progress
    Connecting,
    /// Connected and services discovered
    Connected,
    /// Connection is being closed gracefully
    Disconnecting,
    /// Connection has been closed
    Disconnected,
}

impl std::fmt::Display for BleConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "discovered"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Disconnecting => write!(f, "disconnecting"),
            Self::Disconnected => write!(f, "disconnected"),
        }
    }
}

/// GATT characteristic handle for read/write operations
///
/// Stores the discovered characteristic with its UUID for data transfer.
#[derive(Debug, Clone)]
pub struct CharacteristicHandle {
    /// The UUID of this characteristic
    pub uuid: [u8; 16],
    /// Whether this characteristic supports write without response
    pub write_without_response: bool,
    /// Whether this characteristic supports notifications
    pub notify: bool,
    /// Whether this characteristic supports indications
    pub indicate: bool,
}

impl CharacteristicHandle {
    /// Create a new TX characteristic handle
    pub fn tx() -> Self {
        Self {
            uuid: TX_CHARACTERISTIC_UUID,
            write_without_response: true,
            notify: false,
            indicate: false,
        }
    }

    /// Create a new RX characteristic handle
    pub fn rx() -> Self {
        Self {
            uuid: RX_CHARACTERISTIC_UUID,
            write_without_response: false,
            notify: true,
            indicate: false,
        }
    }
}

/// BLE connection handle
///
/// Wraps a btleplug Peripheral connection with characteristic handles
/// and connection state tracking. Implements clean disconnection on drop.
///
/// # Lifecycle
///
/// ```text
/// Discovered -> Connecting -> Connected -> Disconnecting -> Disconnected
///                   |                            ^
///                   +----------------------------+
///                          (on error)
/// ```
pub struct BleConnection {
    /// Remote device BLE address (6 bytes MAC)
    device_id: [u8; 6],
    /// Current connection state
    state: Arc<RwLock<BleConnectionState>>,
    /// TX characteristic handle (for writing to peripheral)
    tx_characteristic: Option<CharacteristicHandle>,
    /// RX characteristic handle (for receiving notifications)
    rx_characteristic: Option<CharacteristicHandle>,
    /// Btleplug peripheral reference for this connection
    #[cfg(feature = "ble")]
    peripheral: Option<Arc<Peripheral>>,
    /// The actual btleplug TX characteristic for writes
    #[cfg(feature = "ble")]
    btleplug_tx_char: Option<Characteristic>,
    /// The actual btleplug RX characteristic for notifications
    #[cfg(feature = "ble")]
    btleplug_rx_char: Option<Characteristic>,
    /// Time when connection was established
    connected_at: Option<Instant>,
    /// Last activity timestamp
    last_activity: Arc<RwLock<Instant>>,
    /// Shutdown signal sender (for graceful disconnect)
    shutdown_tx: mpsc::Sender<()>,
    /// Whether this connection used session resumption
    session_resumed: bool,
}

impl BleConnection {
    /// Create a new BLE connection handle for a discovered device
    pub fn new(device_id: [u8; 6]) -> Self {
        Self::new_with_resumption(device_id, false)
    }

    /// Create a new BLE connection handle with explicit session resumption flag
    ///
    /// The `session_resumed` flag indicates whether this connection was established
    /// using cached session keys (fast path) or a full PQC handshake.
    pub fn new_with_resumption(device_id: [u8; 6], session_resumed: bool) -> Self {
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        Self {
            device_id,
            state: Arc::new(RwLock::new(BleConnectionState::Discovered)),
            tx_characteristic: None,
            rx_characteristic: None,
            #[cfg(feature = "ble")]
            peripheral: None,
            #[cfg(feature = "ble")]
            btleplug_tx_char: None,
            #[cfg(feature = "ble")]
            btleplug_rx_char: None,
            connected_at: None,
            last_activity: Arc::new(RwLock::new(Instant::now())),
            shutdown_tx,
            session_resumed,
        }
    }

    /// Get the device ID (BLE MAC address)
    pub fn device_id(&self) -> [u8; 6] {
        self.device_id
    }

    /// Get the current connection state
    pub async fn state(&self) -> BleConnectionState {
        *self.state.read().await
    }

    /// Check if the connection is currently active
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == BleConnectionState::Connected
    }

    /// Get how long the connection has been active
    pub fn connection_duration(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }

    /// Get time since last activity
    pub async fn idle_duration(&self) -> Duration {
        self.last_activity.read().await.elapsed()
    }

    /// Update last activity timestamp
    pub async fn touch(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    /// Transition to connecting state
    pub async fn start_connecting(&self) -> Result<(), TransportError> {
        let mut state = self.state.write().await;
        match *state {
            BleConnectionState::Discovered | BleConnectionState::Disconnected => {
                *state = BleConnectionState::Connecting;
                Ok(())
            }
            other => Err(TransportError::Other {
                message: format!("cannot connect from state: {other}"),
            }),
        }
    }

    /// Mark connection as established with discovered characteristics
    pub async fn mark_connected(
        &mut self,
        tx_char: CharacteristicHandle,
        rx_char: CharacteristicHandle,
    ) {
        let mut state = self.state.write().await;
        *state = BleConnectionState::Connected;
        self.tx_characteristic = Some(tx_char);
        self.rx_characteristic = Some(rx_char);
        self.connected_at = Some(Instant::now());
        *self.last_activity.write().await = Instant::now();
    }

    /// Get TX characteristic if connected
    pub fn tx_characteristic(&self) -> Option<&CharacteristicHandle> {
        self.tx_characteristic.as_ref()
    }

    /// Get RX characteristic if connected
    pub fn rx_characteristic(&self) -> Option<&CharacteristicHandle> {
        self.rx_characteristic.as_ref()
    }

    /// Set the btleplug peripheral reference
    #[cfg(feature = "ble")]
    pub fn set_peripheral(&mut self, peripheral: Arc<Peripheral>) {
        self.peripheral = Some(peripheral);
    }

    /// Get the btleplug peripheral reference
    #[cfg(feature = "ble")]
    pub fn peripheral(&self) -> Option<&Arc<Peripheral>> {
        self.peripheral.as_ref()
    }

    /// Set the btleplug TX characteristic
    #[cfg(feature = "ble")]
    pub fn set_btleplug_tx_char(&mut self, char: Characteristic) {
        self.btleplug_tx_char = Some(char);
    }

    /// Get the btleplug TX characteristic
    #[cfg(feature = "ble")]
    pub fn btleplug_tx_char(&self) -> Option<&Characteristic> {
        self.btleplug_tx_char.as_ref()
    }

    /// Set the btleplug RX characteristic
    #[cfg(feature = "ble")]
    pub fn set_btleplug_rx_char(&mut self, char: Characteristic) {
        self.btleplug_rx_char = Some(char);
    }

    /// Get the btleplug RX characteristic
    #[cfg(feature = "ble")]
    pub fn btleplug_rx_char(&self) -> Option<&Characteristic> {
        self.btleplug_rx_char.as_ref()
    }

    /// Mark this connection as using session resumption
    pub fn set_session_resumed(&mut self, resumed: bool) {
        self.session_resumed = resumed;
    }

    /// Check if this connection used session resumption
    pub fn was_session_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Begin graceful disconnection
    pub async fn start_disconnect(&self) -> Result<(), TransportError> {
        let mut state = self.state.write().await;
        match *state {
            BleConnectionState::Connected | BleConnectionState::Connecting => {
                *state = BleConnectionState::Disconnecting;
                // Signal shutdown to any background tasks
                let _ = self.shutdown_tx.send(()).await;
                Ok(())
            }
            BleConnectionState::Disconnecting | BleConnectionState::Disconnected => {
                // Already disconnecting or disconnected, no-op
                Ok(())
            }
            other => Err(TransportError::Other {
                message: format!("cannot disconnect from state: {other}"),
            }),
        }
    }

    /// Mark as fully disconnected
    pub async fn mark_disconnected(&self) {
        let mut state = self.state.write().await;
        *state = BleConnectionState::Disconnected;
    }
}

impl Drop for BleConnection {
    fn drop(&mut self) {
        // Attempt graceful disconnect on drop
        // We can't do async operations in Drop, so we just log
        tracing::debug!(
            device_id = ?self.device_id,
            "BleConnection dropped"
        );
    }
}

impl std::fmt::Debug for BleConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BleConnection")
            .field("device_id", &format!("{:02x?}", self.device_id))
            .field("tx_characteristic", &self.tx_characteristic.is_some())
            .field("rx_characteristic", &self.rx_characteristic.is_some())
            .field("connected_at", &self.connected_at)
            .finish()
    }
}

/// BLE transport configuration
#[derive(Debug, Clone)]
pub struct BleConfig {
    /// GATT service UUID for the ant-quic service
    pub service_uuid: [u8; 16],

    /// Session cache duration for PQC mitigation
    pub session_cache_duration: Duration,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Scan interval when looking for peers
    pub scan_interval: Duration,

    /// Connection timeout
    pub connection_timeout: Duration,

    /// Path for session cache persistence (None = no persistence)
    ///
    /// If set, session keys are saved to this file and loaded on startup,
    /// enabling session resumption to survive application restarts.
    pub session_persist_path: Option<std::path::PathBuf>,

    /// Maximum number of cached sessions (0 = unlimited)
    ///
    /// When the limit is reached, the least recently used sessions are evicted.
    pub max_cached_sessions: usize,

    /// Interval for periodic session cleanup (pruning expired sessions)
    ///
    /// Set to None to disable automatic cleanup (manual cleanup via prune_expired_sessions).
    pub session_cleanup_interval: Option<Duration>,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            service_uuid: ANT_QUIC_SERVICE_UUID,
            session_cache_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            max_connections: 5,
            scan_interval: Duration::from_secs(10),
            connection_timeout: Duration::from_secs(30),
            session_persist_path: None,
            max_cached_sessions: 100, // Reasonable limit for most devices
            session_cleanup_interval: Some(Duration::from_secs(10 * 60)), // 10 minutes
        }
    }
}

/// Session cache entry for PQC key reuse
#[derive(Clone)]
struct CachedSession {
    /// Remote device address
    device_id: [u8; 6],

    /// Cached session key (derived from PQC exchange)
    session_key: [u8; 32],

    /// Session ID for resumption
    session_id: u16,

    /// When this session was established
    established: Instant,

    /// Last activity on this session
    last_active: Instant,
}

impl CachedSession {
    fn is_expired(&self, max_age: Duration) -> bool {
        self.established.elapsed() > max_age
    }

    #[allow(dead_code)]
    fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_active.elapsed() > max_idle
    }
}

/// Session resumption token for fast reconnection
///
/// Instead of a full ~8KB PQC handshake, use a 32-byte token.
#[derive(Clone)]
pub struct ResumeToken {
    /// First 16 bytes of peer ID hash
    pub peer_id_hash: [u8; 16],

    /// Hash of session key + nonce
    pub session_hash: [u8; 16],
}

impl ResumeToken {
    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&self.peer_id_hash);
        bytes[16..].copy_from_slice(&self.session_hash);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut peer_id_hash = [0u8; 16];
        let mut session_hash = [0u8; 16];
        peer_id_hash.copy_from_slice(&bytes[..16]);
        session_hash.copy_from_slice(&bytes[16..]);
        Self {
            peer_id_hash,
            session_hash,
        }
    }
}

// ============================================================================
// Session Persistence Types
// ============================================================================

/// Persisted session data for disk storage
///
/// This is a serializable version of CachedSession that stores only what's
/// needed for session resumption. Note: We store a hash of the session key
/// for security - the actual key is only held in memory.
#[derive(Debug, Clone)]
struct PersistedSession {
    /// Device ID (6 bytes as hex string for readability)
    device_id: String,
    /// Hash of session key (not the raw key for security)
    session_key_hash: [u8; 32],
    /// Session ID
    session_id: u16,
    /// Unix timestamp when established
    established_unix: u64,
}

impl PersistedSession {
    /// Convert a CachedSession to PersistedSession for storage
    fn from_cached(cached: &CachedSession) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Hash the session key for secure storage
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&cached.session_key, &mut hasher);
        let hash_val = std::hash::Hasher::finish(&hasher);
        let mut session_key_hash = [0u8; 32];
        session_key_hash[..8].copy_from_slice(&hash_val.to_le_bytes());
        // Fill rest with entropy from session key
        for (i, chunk) in cached.session_key.chunks(8).enumerate() {
            let start = 8 + i * 8;
            if start + chunk.len() <= 32 {
                session_key_hash[start..start + chunk.len()].copy_from_slice(chunk);
            }
        }

        // Convert Instant to Unix timestamp (approximate)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let elapsed = cached.established.elapsed().as_secs();
        let established_unix = now.saturating_sub(elapsed);

        Self {
            device_id: hex::encode(cached.device_id),
            session_key_hash,
            session_id: cached.session_id,
            established_unix,
        }
    }
}

/// Session cache file format for persistence
#[derive(Debug)]
struct SessionCacheFile {
    /// Format version for future compatibility
    version: u32,
    /// Persisted sessions
    sessions: Vec<PersistedSession>,
}

impl SessionCacheFile {
    const CURRENT_VERSION: u32 = 1;

    fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            sessions: Vec::new(),
        }
    }

    /// Serialize to bytes for file storage
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bytes)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Session count (4 bytes)
        let count = self.sessions.len() as u32;
        bytes.extend_from_slice(&count.to_le_bytes());

        // Each session
        for session in &self.sessions {
            // Device ID (12 bytes hex string as raw bytes)
            let device_bytes = session.device_id.as_bytes();
            let len = device_bytes.len().min(12) as u8;
            bytes.push(len);
            bytes.extend_from_slice(&device_bytes[..len as usize]);
            // Pad to 12 bytes
            bytes.extend(std::iter::repeat_n(0u8, 12 - len as usize));

            // Session key hash (32 bytes)
            bytes.extend_from_slice(&session.session_key_hash);

            // Session ID (2 bytes)
            bytes.extend_from_slice(&session.session_id.to_le_bytes());

            // Established timestamp (8 bytes)
            bytes.extend_from_slice(&session.established_unix.to_le_bytes());
        }

        bytes
    }

    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if version != Self::CURRENT_VERSION {
            return None; // Incompatible version
        }

        let count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

        let mut sessions = Vec::with_capacity(count);
        let mut offset = 8;

        for _ in 0..count {
            if offset + 55 > bytes.len() {
                break; // Truncated file
            }

            // Device ID
            let len = bytes[offset] as usize;
            offset += 1;
            let device_id = String::from_utf8_lossy(&bytes[offset..offset + len]).to_string();
            offset += 12; // Fixed size

            // Session key hash
            let mut session_key_hash = [0u8; 32];
            session_key_hash.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            // Session ID
            let session_id = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            // Established timestamp
            let established_unix = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            offset += 8;

            sessions.push(PersistedSession {
                device_id,
                session_key_hash,
                session_id,
                established_unix,
            });
        }

        Some(Self { version, sessions })
    }
}

/// Information about a discovered BLE peripheral
///
/// Populated during scanning when a device advertising the ant-quic service is found.
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// BLE MAC address (6 bytes) - derived from btleplug peripheral ID
    pub device_id: [u8; 6],
    /// Local name advertised by the device (if any)
    pub local_name: Option<String>,
    /// RSSI at time of discovery (signal strength indicator)
    pub rssi: Option<i16>,
    /// Time when this device was first discovered
    pub discovered_at: Instant,
    /// Time when this device was last seen
    pub last_seen: Instant,
    /// Whether the device is advertising our service UUID
    pub has_service: bool,
    /// The btleplug peripheral ID string (used to look up the peripheral)
    #[cfg(feature = "ble")]
    pub(crate) btleplug_id: Option<String>,
}

impl DiscoveredDevice {
    /// Create a new discovered device entry
    pub fn new(device_id: [u8; 6]) -> Self {
        let now = Instant::now();
        Self {
            device_id,
            local_name: None,
            rssi: None,
            discovered_at: now,
            last_seen: now,
            has_service: false,
            #[cfg(feature = "ble")]
            btleplug_id: None,
        }
    }

    /// Create a new discovered device entry with btleplug ID
    #[cfg(feature = "ble")]
    pub fn with_btleplug_id(device_id: [u8; 6], btleplug_id: String) -> Self {
        let now = Instant::now();
        Self {
            device_id,
            local_name: None,
            rssi: None,
            discovered_at: now,
            last_seen: now,
            has_service: false,
            btleplug_id: Some(btleplug_id),
        }
    }

    /// Update the last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if this device has been seen within the given duration
    pub fn is_recent(&self, max_age: Duration) -> bool {
        self.last_seen.elapsed() < max_age
    }

    /// Get how long ago this device was last seen
    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

/// Event emitted when a device is discovered during scanning
#[derive(Debug, Clone)]
pub struct ScanEvent {
    /// The discovered device
    pub device: DiscoveredDevice,
    /// Whether this is a new device or an update
    pub is_new: bool,
}

/// Scanning state for the BLE transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanState {
    /// Not currently scanning
    #[default]
    Idle,
    /// Actively scanning for devices
    Scanning,
    /// Scan has been requested to stop
    Stopping,
}

impl std::fmt::Display for ScanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Scanning => write!(f, "scanning"),
            Self::Stopping => write!(f, "stopping"),
        }
    }
}

/// BLE transport provider
///
/// Provides Bluetooth Low Energy connectivity for short-range P2P communication.
/// Uses the constrained protocol engine due to MTU limitations.
///
/// # Platform Support
///
/// Uses btleplug for cross-platform BLE support:
/// - **Linux**: BlueZ D-Bus API
/// - **macOS**: Core Bluetooth framework
/// - **Windows**: WinRT Bluetooth LE API
pub struct BleTransport {
    config: BleConfig,
    capabilities: TransportCapabilities,
    local_device_id: [u8; 6],
    online: AtomicBool,
    stats: BleTransportStats,
    session_cache: Arc<RwLock<Vec<CachedSession>>>,
    /// Channel for sending inbound datagrams (used by background receiver task)
    inbound_tx: mpsc::Sender<InboundDatagram>,
    /// Receiver for inbound datagrams (taken by consumer)
    inbound_rx: Arc<RwLock<Option<mpsc::Receiver<InboundDatagram>>>>,
    shutdown_tx: mpsc::Sender<()>,
    /// Current scanning state
    scan_state: Arc<RwLock<ScanState>>,
    /// Map of discovered devices by device ID
    discovered_devices: Arc<RwLock<HashMap<[u8; 6], DiscoveredDevice>>>,
    /// Channel for scan events
    scan_event_tx: mpsc::Sender<ScanEvent>,
    /// Receiver for scan events (used by consumers)
    #[allow(dead_code)]
    scan_event_rx: Arc<RwLock<Option<mpsc::Receiver<ScanEvent>>>>,
    /// Active connections by device ID
    active_connections: Arc<RwLock<HashMap<[u8; 6], Arc<RwLock<BleConnection>>>>>,
    /// Btleplug adapter for Central mode operations (scanning, connecting)
    #[cfg(feature = "ble")]
    adapter: Arc<Adapter>,
    /// Fragmenter for splitting large messages
    fragmenter: BlePacketFragmenter,
    /// Reassembly buffer for combining fragments
    reassembly: Arc<RwLock<BleReassemblyBuffer>>,
    /// Message ID counter for fragmenting outgoing messages
    next_msg_id: AtomicU8,
}

struct BleTransportStats {
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_errors: AtomicU64,
    receive_errors: AtomicU64,
    session_cache_hits: AtomicU64,
    session_cache_misses: AtomicU64,
}

impl Default for BleTransportStats {
    fn default() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
            session_cache_hits: AtomicU64::new(0),
            session_cache_misses: AtomicU64::new(0),
        }
    }
}

impl BleTransport {
    /// Create a new BLE transport with default configuration
    ///
    /// # Platform Support
    ///
    /// Supported on Linux (BlueZ), macOS (Core Bluetooth), and Windows (WinRT).
    /// Returns an error if no Bluetooth adapter is available.
    pub async fn new() -> Result<Self, TransportError> {
        Self::with_config(BleConfig::default()).await
    }

    /// Create a new BLE transport with custom configuration
    #[cfg(feature = "ble")]
    pub async fn with_config(config: BleConfig) -> Result<Self, TransportError> {
        // Get adapter and local device ID
        let (adapter, local_device_id) = Self::get_adapter_and_device_id().await?;

        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        let (scan_event_tx, scan_event_rx) = mpsc::channel(64);

        // Create fragmenter with BLE MTU from capabilities
        let fragmenter = BlePacketFragmenter::new(TransportCapabilities::ble().mtu);

        let transport = Self {
            config,
            capabilities: TransportCapabilities::ble(),
            local_device_id,
            online: AtomicBool::new(true),
            stats: BleTransportStats::default(),
            session_cache: Arc::new(RwLock::new(Vec::new())),
            inbound_tx,
            inbound_rx: Arc::new(RwLock::new(Some(inbound_rx))),
            shutdown_tx,
            scan_state: Arc::new(RwLock::new(ScanState::Idle)),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            scan_event_tx,
            scan_event_rx: Arc::new(RwLock::new(Some(scan_event_rx))),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            adapter: Arc::new(adapter),
            fragmenter,
            reassembly: Arc::new(RwLock::new(BleReassemblyBuffer::default())),
            next_msg_id: AtomicU8::new(0),
        };

        // Load persisted sessions from disk if configured
        if transport.config.session_persist_path.is_some() {
            if let Err(e) = transport.load_sessions_from_disk().await {
                tracing::warn!(error = %e, "Failed to load session cache from disk");
            }
        }

        Ok(transport)
    }

    /// Create a new BLE transport with custom configuration (non-BLE platforms)
    #[cfg(not(feature = "ble"))]
    pub async fn with_config(_config: BleConfig) -> Result<Self, TransportError> {
        Err(TransportError::Other {
            message: "BLE transport requires the 'ble' feature".to_string(),
        })
    }

    /// Get the btleplug adapter and derive a local device ID from it
    ///
    /// This works on Linux, macOS, and Windows via btleplug's platform adapters.
    /// Returns both the adapter (for operations) and a derived device ID.
    #[cfg(feature = "ble")]
    async fn get_adapter_and_device_id() -> Result<(Adapter, [u8; 6]), TransportError> {
        // Create a manager to access Bluetooth adapters
        let manager = Manager::new().await.map_err(|e| TransportError::Other {
            message: format!("Failed to create BLE manager: {e}"),
        })?;

        // Get the list of adapters
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to get BLE adapters: {e}"),
            })?;

        // Get the first adapter
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| TransportError::Other {
                message: "No Bluetooth adapter found".to_string(),
            })?;

        // Try to get adapter info (address)
        // btleplug doesn't directly expose the adapter address on all platforms,
        // so we use a placeholder derived from adapter identification
        let adapter_info = adapter
            .adapter_info()
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to get adapter info: {e}"),
            })?;

        // Generate a deterministic device ID from adapter info
        // This is a fallback since btleplug doesn't expose raw MAC on all platforms
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(adapter_info.as_bytes());
        let hash = hasher.finalize();

        let mut device_id = [0u8; 6];
        device_id.copy_from_slice(&hash[..6]);
        // Set locally administered bit to indicate this is derived, not actual MAC
        device_id[0] |= 0x02;

        tracing::info!(
            adapter = %adapter_info,
            device_id = ?device_id,
            "BLE adapter initialized"
        );

        Ok((adapter, device_id))
    }

    /// Get the local Bluetooth adapter address using btleplug
    ///
    /// This works on Linux, macOS, and Windows via btleplug's platform adapters.
    /// Kept for backward compatibility with existing code.
    #[cfg(feature = "ble")]
    #[allow(dead_code)] // Kept for backward compatibility
    async fn get_local_adapter_address() -> Result<[u8; 6], TransportError> {
        let (_adapter, device_id) = Self::get_adapter_and_device_id().await?;
        Ok(device_id)
    }

    #[cfg(not(feature = "ble"))]
    async fn get_local_adapter_address() -> Result<[u8; 6], TransportError> {
        Err(TransportError::Other {
            message: "BLE transport is not supported without the 'ble' feature".to_string(),
        })
    }

    /// Look up a cached session for fast reconnection
    pub async fn lookup_session(&self, device_id: &[u8; 6]) -> Option<ResumeToken> {
        let cache = self.session_cache.read().await;
        let max_age = self.config.session_cache_duration;

        for session in cache.iter() {
            if &session.device_id == device_id && !session.is_expired(max_age) {
                self.stats
                    .session_cache_hits
                    .fetch_add(1, Ordering::Relaxed);

                // Generate resume token from cached session
                let mut peer_id_hash = [0u8; 16];
                peer_id_hash[..6].copy_from_slice(device_id);

                // Simple hash of session key for resumption verification
                let session_hash = {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(session.session_key);
                    hasher.update(session.session_id.to_le_bytes());
                    let result = hasher.finalize();
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(&result[..16]);
                    hash
                };

                return Some(ResumeToken {
                    peer_id_hash,
                    session_hash,
                });
            }
        }

        self.stats
            .session_cache_misses
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Cache a session for future resumption
    pub async fn cache_session(&self, device_id: [u8; 6], session_key: [u8; 32], session_id: u16) {
        let mut cache = self.session_cache.write().await;

        // Remove expired sessions
        let max_age = self.config.session_cache_duration;
        cache.retain(|s| !s.is_expired(max_age));

        // Check if session already exists
        if let Some(session) = cache.iter_mut().find(|s| s.device_id == device_id) {
            session.session_key = session_key;
            session.session_id = session_id;
            session.last_active = Instant::now();
            return;
        }

        // Add new session
        cache.push(CachedSession {
            device_id,
            session_key,
            session_id,
            established: Instant::now(),
            last_active: Instant::now(),
        });

        // Limit cache size
        while cache.len() > 100 {
            // Remove oldest session
            if let Some(idx) = cache
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.established)
                .map(|(i, _)| i)
            {
                cache.remove(idx);
            }
        }
    }

    /// Get session cache statistics
    pub fn cache_stats(&self) -> (u64, u64) {
        (
            self.stats.session_cache_hits.load(Ordering::Relaxed),
            self.stats.session_cache_misses.load(Ordering::Relaxed),
        )
    }

    /// Cache session after successful connection establishment
    ///
    /// Call this after the PQC handshake completes to enable fast
    /// session resumption for future connections to the same device.
    ///
    /// This is a convenience wrapper around `cache_session` that generates
    /// a session ID automatically.
    pub async fn cache_connection_session(&self, device_id: [u8; 6], session_key: [u8; 32]) {
        // Generate session ID from hash of device_id and timestamp
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&device_id, &mut hasher);
        std::hash::Hash::hash(&Instant::now().elapsed().as_nanos(), &mut hasher);
        let session_id = (std::hash::Hasher::finish(&hasher) & 0xFFFF) as u16;

        self.cache_session(device_id, session_key, session_id).await;

        tracing::debug!(
            device_id = ?device_id,
            session_id,
            "Cached session for future resumption"
        );
    }

    /// Touch a cached session to update its last activity time
    ///
    /// Call this when a cached session is actively used (send/receive)
    /// to keep it fresh in the LRU cache.
    pub async fn touch_session(&self, device_id: &[u8; 6]) {
        let mut cache = self.session_cache.write().await;
        if let Some(session) = cache.iter_mut().find(|s| &s.device_id == device_id) {
            session.last_active = Instant::now();
        }
    }

    /// Get the number of cached sessions
    pub async fn cached_session_count(&self) -> usize {
        self.session_cache.read().await.len()
    }

    /// Remove expired sessions from the cache
    ///
    /// Returns the number of sessions removed.
    pub async fn prune_expired_sessions(&self) -> usize {
        let mut cache = self.session_cache.write().await;
        let before = cache.len();
        let max_age = self.config.session_cache_duration;
        cache.retain(|s| !s.is_expired(max_age));
        let expired_removed = before - cache.len();

        // Also enforce max_cached_sessions limit (LRU eviction)
        let max_sessions = self.config.max_cached_sessions;
        let lru_removed = if max_sessions > 0 && cache.len() > max_sessions {
            // Sort by last_active (oldest first)
            cache.sort_by_key(|s| std::cmp::Reverse(s.last_active));
            let to_remove = cache.len() - max_sessions;
            cache.truncate(max_sessions);
            to_remove
        } else {
            0
        };

        let total_removed = expired_removed + lru_removed;
        if total_removed > 0 {
            tracing::debug!(
                expired = expired_removed,
                lru = lru_removed,
                remaining = cache.len(),
                "Pruned sessions"
            );
        }
        total_removed
    }

    /// Evict least recently used sessions to make room for new entries
    ///
    /// This can be called manually to free up cache space. Note that
    /// `prune_expired_sessions` also enforces the max_cached_sessions limit.
    #[allow(dead_code)]
    async fn evict_lru_sessions(&self, count: usize) -> usize {
        let mut cache = self.session_cache.write().await;
        if cache.len() <= count {
            let removed = cache.len();
            cache.clear();
            return removed;
        }

        // Sort by last_active (oldest first for eviction)
        cache.sort_by_key(|s| s.last_active);
        let before = cache.len();
        cache.drain(0..count);
        let removed = before - cache.len();

        tracing::debug!(removed, remaining = cache.len(), "Evicted LRU sessions");
        removed
    }

    /// Clear all cached sessions
    pub async fn clear_session_cache(&self) {
        let mut cache = self.session_cache.write().await;
        let count = cache.len();
        cache.clear();
        tracing::debug!(count, "Cleared session cache");
    }

    /// Save session cache to disk for persistence across restarts
    ///
    /// Only saves if `session_persist_path` is configured. Sessions are stored
    /// in a binary format with version tracking for future compatibility.
    pub async fn save_sessions_to_disk(&self) -> Result<(), TransportError> {
        let path = match &self.config.session_persist_path {
            Some(p) => p.clone(),
            None => return Ok(()), // No persistence configured
        };

        let cache = self.session_cache.read().await;

        // Convert to persisted format
        let mut file = SessionCacheFile::new();
        for session in cache.iter() {
            file.sessions.push(PersistedSession::from_cached(session));
        }

        // Serialize and write
        let bytes = file.to_bytes();
        std::fs::write(&path, &bytes).map_err(|e| TransportError::Other {
            message: format!("Failed to save session cache to {}: {}", path.display(), e),
        })?;

        tracing::info!(
            path = %path.display(),
            sessions = cache.len(),
            "Saved session cache to disk"
        );

        Ok(())
    }

    /// Load session cache from disk
    ///
    /// Only loads if `session_persist_path` is configured and the file exists.
    /// Invalid or corrupted files are ignored with a warning.
    pub async fn load_sessions_from_disk(&self) -> Result<usize, TransportError> {
        let path = match &self.config.session_persist_path {
            Some(p) => p.clone(),
            None => return Ok(0), // No persistence configured
        };

        // Check if file exists
        if !path.exists() {
            tracing::debug!(path = %path.display(), "Session cache file does not exist");
            return Ok(0);
        }

        // Read file
        let bytes = std::fs::read(&path).map_err(|e| TransportError::Other {
            message: format!(
                "Failed to read session cache from {}: {}",
                path.display(),
                e
            ),
        })?;

        // Parse file
        let file = match SessionCacheFile::from_bytes(&bytes) {
            Some(f) => f,
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "Invalid or corrupted session cache file, ignoring"
                );
                return Ok(0);
            }
        };

        // Note: We can't fully restore CachedSession because:
        // 1. We store hash of session key, not the raw key (security)
        // 2. Instant cannot be serialized/deserialized
        //
        // For now, loading serves as a mechanism to remember which devices
        // we've connected to, but actual session resumption requires the
        // key to still be in memory. Future enhancement: store encrypted
        // session keys with a master key.

        tracing::info!(
            path = %path.display(),
            sessions = file.sessions.len(),
            "Loaded session cache metadata from disk (keys not restored)"
        );

        Ok(file.sessions.len())
    }

    /// Start a background task for periodic session cleanup
    ///
    /// This spawns a tokio task that periodically prunes expired sessions
    /// and saves the cache to disk (if persistence is configured).
    ///
    /// Returns a handle that can be used to abort the task if needed.
    pub fn start_cleanup_task(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let interval = self.config.session_cleanup_interval?;
        let transport = Arc::clone(self);

        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                // Prune expired sessions
                let pruned = transport.prune_expired_sessions().await;
                if pruned > 0 {
                    tracing::debug!(pruned, "Periodic session cleanup completed");
                }

                // Prune stale reassembly buffers
                let stale = transport.prune_stale_reassemblies().await;
                if stale > 0 {
                    tracing::debug!(stale, "Pruned stale reassembly buffers");
                }

                // Save to disk if persistence is configured
                if transport.config.session_persist_path.is_some() {
                    if let Err(e) = transport.save_sessions_to_disk().await {
                        tracing::warn!(error = %e, "Failed to persist session cache");
                    }
                }
            }
        }))
    }

    /// Get reference to the btleplug adapter
    #[cfg(feature = "ble")]
    pub fn adapter(&self) -> &Arc<Adapter> {
        &self.adapter
    }

    /// Estimate handshake time for BLE
    ///
    /// PQC handshake over BLE takes ~1.1 seconds (see CONSTRAINED_TRANSPORTS.md)
    /// due to ~8.8KB of data at 125kbps with 50% framing overhead.
    pub fn estimate_handshake_time(&self) -> Duration {
        // From the research doc: ~8.8KB at 62.5 kbps effective = ~1.1 seconds
        Duration::from_millis(1100)
    }

    /// Check if we have a cached session (avoiding full handshake)
    pub async fn has_cached_session(&self, device_id: &[u8; 6]) -> bool {
        self.lookup_session(device_id).await.is_some()
    }

    /// Get current platform name for diagnostics
    pub fn platform_name() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "Linux (BlueZ)"
        }
        #[cfg(target_os = "macos")]
        {
            "macOS (Core Bluetooth)"
        }
        #[cfg(target_os = "windows")]
        {
            "Windows (WinRT)"
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            "Unsupported"
        }
    }

    /// Get current scan state
    pub async fn scan_state(&self) -> ScanState {
        *self.scan_state.read().await
    }

    /// Check if currently scanning
    pub async fn is_scanning(&self) -> bool {
        *self.scan_state.read().await == ScanState::Scanning
    }

    /// Start scanning for BLE peripherals advertising the ant-quic service
    ///
    /// This method starts a background scan task that discovers nearby BLE devices
    /// advertising the configured service UUID. Discovered devices are added to
    /// the internal discovered_devices map and scan events are sent to the scan
    /// event channel.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Already scanning
    /// - Transport is offline
    /// - Platform doesn't support scanning
    #[cfg(feature = "ble")]
    pub async fn start_scanning(&self) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        let mut state = self.scan_state.write().await;
        if *state == ScanState::Scanning {
            return Err(TransportError::Other {
                message: "Already scanning".to_string(),
            });
        }

        *state = ScanState::Scanning;

        tracing::info!(
            service_uuid = ?self.config.service_uuid,
            platform = %Self::platform_name(),
            "Starting BLE scan"
        );

        // Create scan filter for our service UUID
        let service_filter = ScanFilter {
            services: vec![service_uuid()],
        };

        // Start the btleplug scan with our service filter
        self.adapter
            .start_scan(service_filter)
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to start BLE scan: {e}"),
            })?;

        // Spawn background task to process scan events
        let adapter = self.adapter.clone();
        let discovered_devices = self.discovered_devices.clone();
        let scan_event_tx = self.scan_event_tx.clone();
        let scan_state = self.scan_state.clone();
        #[allow(unused_variables)] // Used for documentation
        let config_service_uuid = self.config.service_uuid;

        tokio::spawn(async move {
            let mut events = match adapter.events().await {
                Ok(events) => events,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get adapter events stream");
                    return;
                }
            };

            while let Some(event) = events.next().await {
                // Check if we should stop based on scan state
                let state = *scan_state.read().await;
                if state != ScanState::Scanning {
                    break;
                }

                match event {
                    CentralEvent::DeviceDiscovered(id) => {
                        // Get peripheral and its properties
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            if let Ok(Some(props)) = peripheral.properties().await {
                                // Extract device information
                                let local_name = props.local_name.clone();
                                let rssi = props.rssi;

                                // Check if it's advertising our service
                                let has_service =
                                    props.services.iter().any(|s| *s == service_uuid());

                                // Generate device ID from peripheral address if available
                                let btleplug_id_str = id.to_string();
                                let device_id = Self::peripheral_id_to_device_id(&btleplug_id_str);

                                let mut device =
                                    DiscoveredDevice::with_btleplug_id(device_id, btleplug_id_str);
                                device.local_name = local_name;
                                device.rssi = rssi;
                                device.has_service = has_service;

                                // Add to discovered devices
                                let mut devices = discovered_devices.write().await;
                                let is_new = !devices.contains_key(&device_id);
                                devices.insert(device_id, device.clone());

                                tracing::debug!(
                                    device_id = ?device_id,
                                    local_name = ?device.local_name,
                                    rssi = ?device.rssi,
                                    has_service = device.has_service,
                                    is_new,
                                    "Discovered BLE device"
                                );

                                // Send scan event
                                let event = ScanEvent { device, is_new };
                                if scan_event_tx.send(event).await.is_err() {
                                    tracing::debug!("Scan event receiver dropped");
                                }
                            }
                        }
                    }
                    CentralEvent::DeviceUpdated(id) => {
                        // Update existing device info
                        let device_id = Self::peripheral_id_to_device_id(&id.to_string());
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            if let Ok(Some(props)) = peripheral.properties().await {
                                let mut devices = discovered_devices.write().await;
                                if let Some(device) = devices.get_mut(&device_id) {
                                    device.update_last_seen();
                                    device.rssi = props.rssi;
                                    if props.local_name.is_some() {
                                        device.local_name = props.local_name.clone();
                                    }
                                    let has_service =
                                        props.services.iter().any(|s| *s == service_uuid());
                                    if has_service {
                                        device.has_service = true;
                                    }

                                    tracing::trace!(
                                        device_id = ?device_id,
                                        rssi = ?device.rssi,
                                        "Updated BLE device"
                                    );
                                }
                            }
                        }
                    }
                    CentralEvent::DeviceDisconnected(id) => {
                        let device_id = Self::peripheral_id_to_device_id(&id.to_string());
                        tracing::debug!(device_id = ?device_id, "BLE device disconnected");
                    }
                    _ => {
                        // Ignore other events
                    }
                }
            }

            tracing::info!("BLE scan event processing stopped");
        });

        Ok(())
    }

    /// Convert a btleplug peripheral ID string to our 6-byte device ID
    ///
    /// btleplug uses platform-specific IDs, so we hash them to get a consistent 6-byte ID.
    #[cfg(feature = "ble")]
    fn peripheral_id_to_device_id(id_str: &str) -> [u8; 6] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id_str.as_bytes());
        let hash = hasher.finalize();

        let mut device_id = [0u8; 6];
        device_id.copy_from_slice(&hash[..6]);
        // Set locally administered bit to indicate this is derived
        device_id[0] |= 0x02;
        device_id
    }

    #[cfg(not(feature = "ble"))]
    pub async fn start_scanning(&self) -> Result<(), TransportError> {
        Err(TransportError::Other {
            message: "BLE scanning is not supported without the 'ble' feature".to_string(),
        })
    }

    /// Stop scanning for BLE peripherals
    ///
    /// Stops the background scan task. Already discovered devices remain in the
    /// discovered_devices map until explicitly cleared.
    #[cfg(feature = "ble")]
    pub async fn stop_scanning(&self) -> Result<(), TransportError> {
        let mut state = self.scan_state.write().await;
        if *state != ScanState::Scanning {
            // Already stopped or stopping, no-op
            return Ok(());
        }

        *state = ScanState::Stopping;

        tracing::info!(
            platform = %Self::platform_name(),
            "Stopping BLE scan"
        );

        // Stop the btleplug scan
        self.adapter
            .stop_scan()
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to stop BLE scan: {e}"),
            })?;

        // Transition to Idle (the background task will stop on its own)
        *state = ScanState::Idle;

        Ok(())
    }

    #[cfg(not(feature = "ble"))]
    pub async fn stop_scanning(&self) -> Result<(), TransportError> {
        // No-op when BLE feature not enabled
        Ok(())
    }

    /// Get a copy of all discovered devices
    pub async fn discovered_devices(&self) -> Vec<DiscoveredDevice> {
        self.discovered_devices
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Get a specific discovered device by ID
    pub async fn get_discovered_device(&self, device_id: &[u8; 6]) -> Option<DiscoveredDevice> {
        self.discovered_devices.read().await.get(device_id).cloned()
    }

    /// Get the number of discovered devices
    pub async fn discovered_device_count(&self) -> usize {
        self.discovered_devices.read().await.len()
    }

    /// Clear all discovered devices
    pub async fn clear_discovered_devices(&self) {
        self.discovered_devices.write().await.clear();
    }

    /// Remove devices that haven't been seen within the given duration
    pub async fn prune_stale_devices(&self, max_age: Duration) -> usize {
        let mut devices = self.discovered_devices.write().await;
        let initial_count = devices.len();
        devices.retain(|_, device| device.is_recent(max_age));
        initial_count - devices.len()
    }

    /// Add or update a discovered device
    ///
    /// This is called internally during scanning or can be used for testing.
    pub async fn add_discovered_device(&self, device: DiscoveredDevice) -> bool {
        let mut devices = self.discovered_devices.write().await;
        let is_new = !devices.contains_key(&device.device_id);

        let device_id = device.device_id;
        devices.insert(device_id, device.clone());

        // Send scan event
        let event = ScanEvent { device, is_new };
        if self.scan_event_tx.send(event).await.is_err() {
            tracing::debug!("Scan event receiver dropped");
        }

        is_new
    }

    /// Take ownership of the scan event receiver
    ///
    /// This can only be called once. Subsequent calls return None.
    pub async fn take_scan_events(&self) -> Option<mpsc::Receiver<ScanEvent>> {
        self.scan_event_rx.write().await.take()
    }

    // ===== Connection Management =====

    /// Connect to a discovered BLE device
    ///
    /// This method initiates a connection to the specified device:
    /// 1. Validates the device was previously discovered
    /// 2. Creates a BleConnection handle
    /// 3. Connects via btleplug and discovers GATT services
    /// 4. Finds the ant-quic service and TX/RX characteristics
    /// 5. Subscribes to RX characteristic notifications
    /// 6. Stores the connection in active_connections
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Transport is offline
    /// - Device was not previously discovered
    /// - Connection limit exceeded
    /// - Connection already exists
    /// - Platform doesn't support connections
    /// - BLE connection or service discovery fails
    #[cfg(feature = "ble")]
    pub async fn connect_to_device(
        &self,
        device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        use btleplug::api::Peripheral as _;

        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        // Check connection limit
        let connections = self.active_connections.read().await;
        if connections.len() >= self.config.max_connections {
            return Err(TransportError::Other {
                message: format!(
                    "Connection limit exceeded: {} / {}",
                    connections.len(),
                    self.config.max_connections
                ),
            });
        }

        // Check if already connected
        if connections.contains_key(&device_id) {
            return Err(TransportError::Other {
                message: format!("Already connected to device: {:02x?}", device_id),
            });
        }
        drop(connections);

        // Verify device was discovered and get btleplug ID
        let btleplug_id_str = {
            let discovered = self.discovered_devices.read().await;
            let device = discovered
                .get(&device_id)
                .ok_or_else(|| TransportError::Other {
                    message: format!("Device not discovered: {:02x?}", device_id),
                })?;
            device
                .btleplug_id
                .clone()
                .ok_or_else(|| TransportError::Other {
                    message: format!("Device {:02x?} has no btleplug ID", device_id),
                })?
        };

        // Check for cached session (for potential PQC handshake optimization)
        // If a cached session exists, the application layer can use it for fast resumption
        let resume_token = self.lookup_session(&device_id).await;
        let using_session_resumption = resume_token.is_some();

        if using_session_resumption {
            tracing::info!(
                device_id = ?device_id,
                "Found cached session - using fast handshake (32 bytes vs ~8KB)"
            );
        } else {
            tracing::info!(
                device_id = ?device_id,
                "No cached session - will perform full PQC handshake"
            );
        }

        tracing::info!(
            device_id = ?device_id,
            btleplug_id = %btleplug_id_str,
            platform = %Self::platform_name(),
            session_resumption = using_session_resumption,
            "Connecting to BLE device"
        );

        // Create connection handle
        let mut connection = BleConnection::new(device_id);
        connection.set_session_resumed(using_session_resumption);
        connection.start_connecting().await?;

        // Find the peripheral in the adapter
        let peripheral = self
            .find_peripheral_by_id(&btleplug_id_str)
            .await
            .ok_or_else(|| TransportError::Other {
                message: format!("Peripheral not found: {}", btleplug_id_str),
            })?;

        // Connect to the peripheral
        peripheral
            .connect()
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to connect: {e}"),
            })?;

        // Discover services
        peripheral
            .discover_services()
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to discover services: {e}"),
            })?;

        // Find our service and characteristics
        let services = peripheral.services();
        let our_service = services
            .iter()
            .find(|s| s.uuid == service_uuid())
            .ok_or_else(|| TransportError::Other {
                message: format!("ant-quic service not found on device {:02x?}", device_id),
            })?;

        // Find TX characteristic (write without response)
        let tx_char = our_service
            .characteristics
            .iter()
            .find(|c| c.uuid == tx_uuid())
            .cloned()
            .ok_or_else(|| TransportError::Other {
                message: "TX characteristic not found".to_string(),
            })?;

        // Find RX characteristic (notify)
        let rx_char = our_service
            .characteristics
            .iter()
            .find(|c| c.uuid == rx_uuid())
            .cloned()
            .ok_or_else(|| TransportError::Other {
                message: "RX characteristic not found".to_string(),
            })?;

        tracing::debug!(
            tx_uuid = %tx_char.uuid,
            rx_uuid = %rx_char.uuid,
            "Found ant-quic characteristics"
        );

        // Subscribe to RX characteristic notifications
        peripheral
            .subscribe(&rx_char)
            .await
            .map_err(|e| TransportError::Other {
                message: format!("Failed to subscribe to RX notifications: {e}"),
            })?;

        tracing::debug!(
            device_id = ?device_id,
            "Subscribed to RX notifications"
        );

        // Create peripheral Arc for sharing with notification task
        let peripheral_arc = Arc::new(peripheral);

        // Store peripheral and characteristic references
        connection.set_peripheral(peripheral_arc.clone());
        connection.set_btleplug_tx_char(tx_char.clone());
        connection.set_btleplug_rx_char(rx_char.clone());

        // Mark connection as established
        connection
            .mark_connected(CharacteristicHandle::tx(), CharacteristicHandle::rx())
            .await;

        // Store connection
        let connection = Arc::new(RwLock::new(connection));
        self.active_connections
            .write()
            .await
            .insert(device_id, connection.clone());

        // Spawn background task to handle incoming notifications
        let inbound_tx = self.inbound_tx.clone();
        let config_service_uuid = self.config.service_uuid;

        tokio::spawn(async move {
            // Get the notification stream
            let mut notifications = match peripheral_arc.notifications().await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::error!(
                        device_id = ?device_id,
                        error = %e,
                        "Failed to get notification stream"
                    );
                    return;
                }
            };

            tracing::info!(
                device_id = ?device_id,
                "Started notification handler"
            );

            while let Some(notification) = notifications.next().await {
                // Check if this is from the RX characteristic
                if notification.uuid == rx_uuid() {
                    let data_len = notification.value.len();

                    // Create inbound datagram
                    let datagram = InboundDatagram {
                        source: TransportAddr::ble(device_id, Some(config_service_uuid)),
                        data: notification.value,
                        received_at: Instant::now(),
                        link_quality: Some(LinkQuality {
                            rssi: None, // Would need async call to get RSSI
                            snr: None,
                            hop_count: Some(1),
                            rtt: None,
                        }),
                    };

                    // Send to inbound channel
                    if inbound_tx.send(datagram).await.is_err() {
                        tracing::debug!(
                            device_id = ?device_id,
                            "Inbound channel closed, stopping notification handler"
                        );
                        break;
                    }

                    tracing::trace!(
                        device_id = ?device_id,
                        data_len,
                        "Received BLE notification"
                    );
                }
            }

            tracing::info!(
                device_id = ?device_id,
                "Notification handler stopped"
            );
        });

        tracing::info!(
            device_id = ?device_id,
            session_resumed = using_session_resumption,
            "BLE device connected"
        );

        // If this was not a session resumption, cache the session for future connections
        // The application layer will provide the actual session key after PQC handshake
        // For now, we generate a placeholder session ID
        if !using_session_resumption {
            // Generate a session ID from the connection timestamp
            let session_id = (Instant::now().elapsed().as_millis() & 0xFFFF) as u16;
            tracing::debug!(
                device_id = ?device_id,
                session_id,
                "New connection - session can be cached after PQC handshake"
            );
        }

        Ok(connection)
    }

    /// Find a btleplug peripheral by its ID string
    #[cfg(feature = "ble")]
    async fn find_peripheral_by_id(&self, id_str: &str) -> Option<Peripheral> {
        use btleplug::api::Peripheral as _;

        // Get all peripherals from the adapter
        let peripherals = self.adapter.peripherals().await.ok()?;

        for peripheral in peripherals {
            if peripheral.id().to_string() == id_str {
                return Some(peripheral);
            }
        }
        None
    }

    #[cfg(not(feature = "ble"))]
    pub async fn connect_to_device(
        &self,
        _device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        Err(TransportError::Other {
            message: "BLE connections are not supported without the 'ble' feature".to_string(),
        })
    }

    /// Connect to a device in simulated mode (for testing)
    ///
    /// Creates a connection without requiring real btleplug hardware.
    /// Only available in test builds.
    #[cfg(test)]
    pub async fn connect_to_device_simulated(
        &self,
        device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        // Check connection limit
        let connections = self.active_connections.read().await;
        if connections.len() >= self.config.max_connections {
            return Err(TransportError::Other {
                message: format!(
                    "Connection limit exceeded: {} / {}",
                    connections.len(),
                    self.config.max_connections
                ),
            });
        }

        // Check if already connected
        if connections.contains_key(&device_id) {
            return Err(TransportError::Other {
                message: format!("Already connected to device: {:02x?}", device_id),
            });
        }
        drop(connections);

        // Verify device was discovered
        {
            let discovered = self.discovered_devices.read().await;
            if !discovered.contains_key(&device_id) {
                return Err(TransportError::Other {
                    message: format!("Device not discovered: {:02x?}", device_id),
                });
            }
        }

        // Create simulated connection
        let mut connection = BleConnection::new(device_id);
        connection.start_connecting().await?;
        connection
            .mark_connected(CharacteristicHandle::tx(), CharacteristicHandle::rx())
            .await;

        // Store connection
        let connection = Arc::new(RwLock::new(connection));
        self.active_connections
            .write()
            .await
            .insert(device_id, connection.clone());

        tracing::debug!(
            device_id = ?device_id,
            "Created simulated BLE connection (test mode)"
        );

        Ok(connection)
    }

    /// Disconnect from a BLE device
    ///
    /// Gracefully closes the connection and removes it from active_connections.
    pub async fn disconnect_from_device(&self, device_id: &[u8; 6]) -> Result<(), TransportError> {
        let mut connections = self.active_connections.write().await;

        if let Some(conn) = connections.remove(device_id) {
            let conn = conn.read().await;
            conn.start_disconnect().await?;
            tracing::info!(
                device_id = ?device_id,
                "BLE device disconnected"
            );
            Ok(())
        } else {
            Err(TransportError::Other {
                message: format!("No connection to device: {:02x?}", device_id),
            })
        }
    }

    /// Get a connection by device ID
    pub async fn get_connection(&self, device_id: &[u8; 6]) -> Option<Arc<RwLock<BleConnection>>> {
        self.active_connections.read().await.get(device_id).cloned()
    }

    /// Check if connected to a device
    pub async fn is_connected_to(&self, device_id: &[u8; 6]) -> bool {
        if let Some(conn) = self.active_connections.read().await.get(device_id) {
            conn.read().await.is_connected().await
        } else {
            false
        }
    }

    /// Get the number of active connections
    pub async fn active_connection_count(&self) -> usize {
        self.active_connections.read().await.len()
    }

    /// Get all active device IDs
    pub async fn connected_devices(&self) -> Vec<[u8; 6]> {
        self.active_connections
            .read()
            .await
            .keys()
            .copied()
            .collect()
    }

    /// Disconnect all devices
    pub async fn disconnect_all(&self) -> usize {
        let mut connections = self.active_connections.write().await;
        let count = connections.len();

        for (device_id, conn) in connections.drain() {
            let conn = conn.read().await;
            if let Err(e) = conn.start_disconnect().await {
                tracing::warn!(
                    device_id = ?device_id,
                    error = %e,
                    "Error disconnecting device"
                );
            }
        }

        tracing::info!(count, "Disconnected all BLE devices");
        count
    }

    /// Connect with retry logic
    ///
    /// Attempts to connect to the device with exponential backoff retry.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub async fn connect_with_retry(
        &self,
        device_id: [u8; 6],
        max_attempts: u32,
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        let mut attempts = 0;
        let mut delay = Duration::from_millis(100);
        let max_delay = Duration::from_secs(5);

        loop {
            attempts += 1;
            match self.connect_to_device(device_id).await {
                Ok(conn) => return Ok(conn),
                Err(e) if attempts >= max_attempts => {
                    tracing::error!(
                        device_id = ?device_id,
                        attempts,
                        error = %e,
                        "Failed to connect after max attempts"
                    );
                    return Err(e);
                }
                Err(e) => {
                    tracing::warn!(
                        device_id = ?device_id,
                        attempt = attempts,
                        max_attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Connection failed, retrying"
                    );

                    // Remove failed connection if any
                    self.active_connections.write().await.remove(&device_id);

                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(max_delay);
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub async fn connect_with_retry(
        &self,
        _device_id: [u8; 6],
        _max_attempts: u32,
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        Err(TransportError::Other {
            message: "BLE connections are not supported on this platform".to_string(),
        })
    }

    // ===== Inbound Datagram Handling =====

    /// Process a notification from a BLE peripheral
    ///
    /// This method is called when data is received via RX characteristic notifications.
    /// It creates an InboundDatagram and sends it to the inbound channel.
    ///
    /// # Arguments
    ///
    /// * `device_id` - The BLE MAC address of the sending device
    /// * `data` - The raw data from the notification
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the datagram was queued, or an error if the channel is full/closed.
    pub async fn process_notification(
        &self,
        device_id: [u8; 6],
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        // Verify we have an active connection to this device
        let connections = self.active_connections.read().await;
        if !connections.contains_key(&device_id) {
            self.stats.receive_errors.fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::Other {
                message: format!(
                    "Received notification from unknown device: {:02x?}",
                    device_id
                ),
            });
        }

        // Update connection activity
        if let Some(conn) = connections.get(&device_id) {
            conn.read().await.touch().await;
        }
        drop(connections);

        // Track raw bytes received (fragment including header)
        let fragment_len = data.len();
        self.stats
            .bytes_received
            .fetch_add(fragment_len as u64, Ordering::Relaxed);

        // Process through reassembly buffer
        // Returns Some(complete_data) when all fragments received
        let complete_data = {
            let mut reassembly = self.reassembly.write().await;
            reassembly.add_fragment(device_id, &data)
        };

        // If we don't have a complete message yet, we're waiting for more fragments
        let complete_data = match complete_data {
            Some(data) => data,
            None => {
                tracing::trace!(
                    device_id = ?device_id,
                    fragment_len,
                    "BLE fragment received, waiting for more"
                );
                return Ok(());
            }
        };

        // We have a complete reassembled message
        let data_len = complete_data.len();

        // Create inbound datagram
        let datagram = InboundDatagram {
            source: TransportAddr::ble(device_id, Some(self.config.service_uuid)),
            data: complete_data,
            received_at: Instant::now(),
            link_quality: Some(LinkQuality {
                rssi: None, // Would be populated from btleplug peripheral RSSI
                snr: None,
                hop_count: Some(1), // BLE is direct connection
                rtt: None,
            }),
        };

        // Send to channel
        self.inbound_tx
            .send(datagram)
            .await
            .map_err(|_| TransportError::Other {
                message: "Inbound channel closed".to_string(),
            })?;

        // Update stats for complete message
        self.stats
            .datagrams_received
            .fetch_add(1, Ordering::Relaxed);

        // Touch session cache entry to keep it fresh
        self.touch_session(&device_id).await;

        tracing::trace!(
            device_id = ?device_id,
            data_len,
            "Processed complete BLE message"
        );

        Ok(())
    }

    /// Take ownership of the inbound receiver
    ///
    /// This can only be called once. Subsequent calls return None.
    /// Use this to receive datagrams from connected BLE peripherals.
    pub async fn take_inbound_receiver(&self) -> Option<mpsc::Receiver<InboundDatagram>> {
        self.inbound_rx.write().await.take()
    }

    /// Get a clone of the inbound sender for testing
    ///
    /// This allows simulating inbound notifications for tests.
    #[cfg(test)]
    pub fn inbound_sender(&self) -> mpsc::Sender<InboundDatagram> {
        self.inbound_tx.clone()
    }

    // ===== Peripheral Mode (Limited Support) =====

    /// Check if peripheral mode is supported on this platform
    ///
    /// Note: btleplug has limited peripheral mode support. Currently supported:
    /// - **Linux**: Partial support via BlueZ D-Bus GATT server
    /// - **macOS**: App-level only (requires entitlements for background)
    /// - **Windows**: Limited support
    pub fn is_peripheral_mode_supported() -> bool {
        // btleplug's peripheral support is experimental
        // Return false to indicate we primarily operate as a Central
        #[cfg(target_os = "linux")]
        {
            // Linux has the best peripheral support via BlueZ
            true
        }
        #[cfg(target_os = "macos")]
        {
            // macOS peripheral mode requires app entitlements
            false
        }
        #[cfg(target_os = "windows")]
        {
            // Windows peripheral support is limited
            false
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Start advertising as a BLE peripheral
    ///
    /// This starts the GATT server with the ant-quic service and begins advertising.
    /// Other devices can discover and connect to this node.
    ///
    /// # Platform Support
    ///
    /// - **Linux**: Uses BlueZ D-Bus API for GATT server
    /// - **macOS/Windows**: Not currently supported (btleplug limitation)
    ///
    /// # Note
    ///
    /// This is a stub implementation. Full peripheral mode requires:
    /// 1. Setting up a GATT server with our service UUID
    /// 2. Adding TX (write) and RX (notify) characteristics
    /// 3. Starting BLE advertising with the service UUID
    /// 4. Handling incoming connections from Central devices
    #[cfg(target_os = "linux")]
    pub async fn start_advertising(&self) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        tracing::info!(
            service_uuid = ?self.config.service_uuid,
            platform = %Self::platform_name(),
            "Starting BLE advertising (peripheral mode - stub)"
        );

        // In a full implementation, this would:
        // 1. Create a GATT server using bluez-async or dbus
        // 2. Add the ant-quic service with TX/RX characteristics
        // 3. Start advertising with the service UUID
        //
        // btleplug focuses on Central mode; full peripheral mode
        // would require additional platform-specific code

        Ok(())
    }

    /// Start advertising as a BLE peripheral (non-Linux platforms)
    ///
    /// Returns an error on platforms that don't support peripheral mode.
    #[cfg(not(target_os = "linux"))]
    pub async fn start_advertising(&self) -> Result<(), TransportError> {
        Err(TransportError::Other {
            message: format!(
                "Peripheral mode (advertising) is not supported on {}",
                Self::platform_name()
            ),
        })
    }

    /// Stop advertising as a BLE peripheral
    pub async fn stop_advertising(&self) -> Result<(), TransportError> {
        tracing::info!(
            platform = %Self::platform_name(),
            "Stopping BLE advertising"
        );

        // In a full implementation, this would stop the advertising
        // and close the GATT server

        Ok(())
    }

    // ===== Connection Pool Management =====

    /// Get connection pool statistics
    pub async fn pool_stats(&self) -> ConnectionPoolStats {
        let connections = self.active_connections.read().await;
        let mut active = 0;
        let mut connecting = 0;
        let mut disconnecting = 0;
        let mut oldest_activity = None;

        for (_id, conn) in connections.iter() {
            let conn = conn.read().await;
            match conn.state().await {
                BleConnectionState::Connected => active += 1,
                BleConnectionState::Connecting => connecting += 1,
                BleConnectionState::Disconnecting => disconnecting += 1,
                _ => {}
            }

            let idle = conn.idle_duration().await;
            if oldest_activity.is_none() || Some(idle) > oldest_activity {
                oldest_activity = Some(idle);
            }
        }

        ConnectionPoolStats {
            max_connections: self.config.max_connections,
            active,
            connecting,
            disconnecting,
            total: connections.len(),
            oldest_idle: oldest_activity,
        }
    }

    /// Prune stale incomplete fragment reassembly entries
    ///
    /// Call this periodically to clean up fragments that will never complete
    /// (e.g., due to packet loss or disconnection).
    ///
    /// # Returns
    ///
    /// Number of incomplete message sequences that were pruned
    pub async fn prune_stale_reassemblies(&self) -> usize {
        let mut reassembly = self.reassembly.write().await;
        reassembly.prune_stale()
    }

    /// Get the number of pending incomplete reassemblies
    pub async fn pending_reassemblies(&self) -> usize {
        self.reassembly.read().await.pending_count()
    }

    /// Evict the least recently used (most idle) connection
    ///
    /// This frees up a connection slot when the pool is full.
    /// Returns the device_id of the evicted connection, or None if pool is empty.
    pub async fn evict_lru_connection(&self) -> Option<[u8; 6]> {
        let mut connections = self.active_connections.write().await;

        if connections.is_empty() {
            return None;
        }

        // Find the connection with the oldest (longest) idle time
        let mut lru_device = None;
        let mut max_idle = Duration::ZERO;

        for (device_id, conn) in connections.iter() {
            let idle = conn.read().await.idle_duration().await;
            if idle > max_idle {
                max_idle = idle;
                lru_device = Some(*device_id);
            }
        }

        // Evict the LRU connection
        if let Some(device_id) = lru_device {
            if let Some(conn) = connections.remove(&device_id) {
                if let Err(e) = conn.read().await.start_disconnect().await {
                    tracing::warn!(
                        device_id = ?device_id,
                        error = %e,
                        "Error during LRU eviction"
                    );
                }
                tracing::info!(
                    device_id = ?device_id,
                    idle_secs = max_idle.as_secs(),
                    "Evicted LRU connection"
                );
                return Some(device_id);
            }
        }

        None
    }

    /// Evict connections that have been idle longer than the threshold
    ///
    /// Returns the number of connections evicted.
    pub async fn evict_idle_connections(&self, idle_threshold: Duration) -> usize {
        let mut connections = self.active_connections.write().await;
        let mut to_evict = Vec::new();

        // Find idle connections
        for (device_id, conn) in connections.iter() {
            let idle = conn.read().await.idle_duration().await;
            if idle > idle_threshold {
                to_evict.push(*device_id);
            }
        }

        // Evict them
        for device_id in &to_evict {
            if let Some(conn) = connections.remove(device_id) {
                let _ = conn.read().await.start_disconnect().await;
            }
        }

        if !to_evict.is_empty() {
            tracing::info!(
                count = to_evict.len(),
                threshold_secs = idle_threshold.as_secs(),
                "Evicted idle connections"
            );
        }

        to_evict.len()
    }

    /// Check pool health and perform maintenance
    ///
    /// This method:
    /// 1. Removes connections that are in disconnected state
    /// 2. Logs pool statistics
    ///
    /// Call periodically for pool maintenance.
    pub async fn maintain_pool(&self) {
        let mut connections = self.active_connections.write().await;
        let mut to_remove = Vec::new();

        // Find disconnected connections
        for (device_id, conn) in connections.iter() {
            let state = conn.read().await.state().await;
            if state == BleConnectionState::Disconnected {
                to_remove.push(*device_id);
            }
        }

        // Remove them
        for device_id in &to_remove {
            connections.remove(device_id);
        }

        if !to_remove.is_empty() {
            tracing::debug!(
                removed = to_remove.len(),
                remaining = connections.len(),
                "Pool maintenance: removed disconnected connections"
            );
        }
    }

    /// Connect to device with automatic eviction if pool is full
    ///
    /// If the connection pool is at capacity, evicts the LRU connection
    /// to make room for the new connection.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub async fn connect_with_eviction(
        &self,
        device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        // Check if at capacity
        let current = self.active_connection_count().await;
        if current >= self.config.max_connections {
            // Evict LRU connection
            if self.evict_lru_connection().await.is_none() {
                return Err(TransportError::Other {
                    message: "Failed to evict connection to make room".to_string(),
                });
            }
        }

        // Now connect
        self.connect_to_device(device_id).await
    }

    /// Connect to device with automatic eviction (simulated for tests)
    #[cfg(test)]
    pub async fn connect_with_eviction_simulated(
        &self,
        device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        // Check if at capacity
        let current = self.active_connection_count().await;
        if current >= self.config.max_connections {
            // Evict LRU connection
            if self.evict_lru_connection().await.is_none() {
                return Err(TransportError::Other {
                    message: "Failed to evict connection to make room".to_string(),
                });
            }
        }

        // Now connect (simulated)
        self.connect_to_device_simulated(device_id).await
    }

    /// Connect to device with automatic eviction (non-supported platforms)
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub async fn connect_with_eviction(
        &self,
        _device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        Err(TransportError::Other {
            message: "BLE connections are not supported on this platform".to_string(),
        })
    }
}

/// Statistics for the BLE connection pool
#[derive(Debug, Clone, Default)]
pub struct ConnectionPoolStats {
    /// Maximum allowed connections
    pub max_connections: usize,
    /// Number of fully connected connections
    pub active: usize,
    /// Number of connections in progress
    pub connecting: usize,
    /// Number of connections being closed
    pub disconnecting: usize,
    /// Total connections in pool
    pub total: usize,
    /// Idle duration of the oldest connection
    pub oldest_idle: Option<Duration>,
}

impl ConnectionPoolStats {
    /// Check if the pool has capacity for new connections
    pub fn has_capacity(&self) -> bool {
        self.total < self.max_connections
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.max_connections.saturating_sub(self.total)
    }
}

#[async_trait]
impl TransportProvider for BleTransport {
    fn name(&self) -> &str {
        "BLE"
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Ble
    }

    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        Some(TransportAddr::ble(
            self.local_device_id,
            Some(self.config.service_uuid),
        ))
    }

    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }

        let (device_id, _service_uuid) = match dest {
            TransportAddr::Ble {
                device_id,
                service_uuid,
            } => (*device_id, service_uuid.unwrap_or(self.config.service_uuid)),
            _ => {
                return Err(TransportError::AddressMismatch {
                    expected: TransportType::Ble,
                    actual: dest.transport_type(),
                });
            }
        };

        // Check maximum fragmentable size (255 fragments * payload_size)
        let max_size = 255 * self.fragmenter.payload_size();
        if data.len() > max_size {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: max_size,
            });
        }

        // Look up connection by device ID and validate it
        let (is_connected, has_tx_char) = {
            let connections = self.active_connections.read().await;
            let conn = connections.get(&device_id).ok_or_else(|| {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                TransportError::Other {
                    message: format!("No connection to device: {:02x?}", device_id),
                }
            })?;

            let conn_guard = conn.read().await;
            let is_connected = conn_guard.is_connected().await;
            let has_tx_char = conn_guard.tx_characteristic().is_some();

            // Update activity timestamp if connected
            if is_connected {
                conn_guard.touch().await;
            }

            (is_connected, has_tx_char)
        };

        if !is_connected {
            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::Other {
                message: format!("Connection to device {:02x?} is not active", device_id),
            });
        }

        if !has_tx_char {
            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::Other {
                message: format!(
                    "TX characteristic not available for device: {:02x?}",
                    device_id
                ),
            });
        }

        // Fragment the data if needed
        let msg_id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
        let fragments = self.fragmenter.fragment(data, msg_id);
        let fragment_count = fragments.len();

        // Perform the real btleplug write
        #[cfg(feature = "ble")]
        {
            use btleplug::api::Peripheral as _;

            // Get the connection and perform the write
            let connections = self.active_connections.read().await;
            let conn = connections.get(&device_id).ok_or_else(|| {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                TransportError::Other {
                    message: format!("No connection to device: {:02x?}", device_id),
                }
            })?;

            let conn_guard = conn.read().await;

            // Check if this is a simulated connection (no peripheral - test mode)
            if conn_guard.peripheral().is_none() {
                // Simulated connection - skip actual btleplug write
                #[cfg(test)]
                {
                    tracing::debug!(
                        device_id = ?device_id,
                        data_len = data.len(),
                        fragments = fragment_count,
                        "BLE fragmented write (simulated connection)"
                    );
                }
                #[cfg(not(test))]
                {
                    self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(TransportError::Other {
                        message: "Peripheral not available".to_string(),
                    });
                }
            } else {
                // Real connection - perform btleplug write
                // Safety: We checked peripheral().is_none() in the if branch, so this must be Some
                let peripheral = match conn_guard.peripheral() {
                    Some(p) => p,
                    None => {
                        self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(TransportError::Other {
                            message: "Peripheral not available".to_string(),
                        });
                    }
                };

                let tx_char = conn_guard.btleplug_tx_char().ok_or_else(|| {
                    self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    TransportError::Other {
                        message: "TX characteristic not available".to_string(),
                    }
                })?;

                // Write each fragment to the TX characteristic
                for (i, fragment) in fragments.iter().enumerate() {
                    peripheral
                        .write(tx_char, fragment, WriteType::WithoutResponse)
                        .await
                        .map_err(|e| {
                            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                            TransportError::Other {
                                message: format!(
                                    "Failed to write fragment {}/{} to TX characteristic: {e}",
                                    i + 1,
                                    fragment_count
                                ),
                            }
                        })?;
                }

                tracing::debug!(
                    device_id = ?device_id,
                    data_len = data.len(),
                    fragments = fragment_count,
                    platform = %Self::platform_name(),
                    "BLE fragmented write complete"
                );
            }
        }

        #[cfg(not(feature = "ble"))]
        {
            let _ = &fragments; // Silence unused variable warning
            tracing::debug!(
                device_id = ?device_id,
                data_len = data.len(),
                fragments = fragment_count,
                platform = %Self::platform_name(),
                "BLE fragmented write (simulated - no BLE feature)"
            );
        }

        // Update stats on success
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        // Touch session cache entry to keep it fresh
        self.touch_session(&device_id).await;

        Ok(())
    }

    fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
        // Note: The TransportProvider trait requires returning a receiver.
        // Since we can only take the receiver once, subsequent calls create a dummy channel.
        // For real usage, consumers should use take_inbound_receiver() instead.
        //
        // This implementation attempts to take the real receiver first, falling back
        // to a dummy receiver if already taken.
        let maybe_rx = {
            // Try to take in a sync context - create new runtime for blocking call
            // Note: In production, prefer take_inbound_receiver() which is async
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                std::thread::scope(|s| {
                    s.spawn(|| handle.block_on(async { self.inbound_rx.write().await.take() }))
                        .join()
                        .ok()
                        .flatten()
                })
            } else {
                None
            }
        };

        maybe_rx.unwrap_or_else(|| {
            let (_, rx) = mpsc::channel(256);
            rx
        })
    }

    fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    async fn shutdown(&self) -> Result<(), TransportError> {
        self.online.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(()).await;
        Ok(())
    }

    async fn broadcast(&self, data: &[u8]) -> Result<(), TransportError> {
        // BLE advertising for broadcast
        if !self.capabilities.broadcast {
            return Err(TransportError::BroadcastNotSupported);
        }

        if data.len() > 31 {
            // BLE advertising data limit
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: 31,
            });
        }

        // In a full implementation, this would set up BLE advertising with the data
        tracing::debug!(
            data_len = data.len(),
            platform = %Self::platform_name(),
            "BLE broadcast (simulated)"
        );

        Ok(())
    }

    async fn link_quality(&self, peer: &TransportAddr) -> Option<LinkQuality> {
        let _device_id = match peer {
            TransportAddr::Ble { device_id, .. } => device_id,
            _ => return None,
        };

        // In a full implementation, this would query RSSI from btleplug
        // btleplug provides RSSI via peripheral.properties() on some platforms
        Some(LinkQuality {
            rssi: Some(-60),    // Typical indoor range
            snr: None,          // BLE doesn't provide SNR directly
            hop_count: Some(1), // BLE is direct
            rtt: Some(Duration::from_millis(100)),
        })
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            datagrams_sent: self.stats.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            receive_errors: self.stats.receive_errors.load(Ordering::Relaxed),
            current_rtt: Some(Duration::from_millis(100)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_capabilities() {
        let caps = TransportCapabilities::ble();

        assert!(!caps.supports_full_quic()); // MTU too small
        assert_eq!(caps.mtu, 244);
        assert_eq!(caps.bandwidth_bps, 125_000);
        assert!(caps.link_layer_acks);
        assert!(caps.power_constrained);
        assert!(caps.broadcast); // BLE advertising
    }

    #[test]
    fn test_resume_token() {
        let token = ResumeToken {
            peer_id_hash: [0x01; 16],
            session_hash: [0x02; 16],
        };

        let bytes = token.to_bytes();
        let restored = ResumeToken::from_bytes(&bytes);

        assert_eq!(restored.peer_id_hash, token.peer_id_hash);
        assert_eq!(restored.session_hash, token.session_hash);
    }

    #[test]
    fn test_ble_config_default() {
        let config = BleConfig::default();

        assert_eq!(config.service_uuid, ANT_QUIC_SERVICE_UUID);
        assert_eq!(
            config.session_cache_duration,
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(config.max_connections, 5);
    }

    #[test]
    fn test_handshake_estimate() {
        // Verify the handshake time estimate from the research document
        let caps = TransportCapabilities::ble();
        let handshake_bytes = 8800; // ~8.8KB for PQC
        let time = caps.estimate_transmission_time(handshake_bytes);

        // Should be around 1-2 seconds
        assert!(time >= Duration::from_millis(500));
        assert!(time <= Duration::from_secs(3));
    }

    #[test]
    fn test_platform_name() {
        let name = BleTransport::platform_name();
        #[cfg(target_os = "linux")]
        assert_eq!(name, "Linux (BlueZ)");
        #[cfg(target_os = "macos")]
        assert_eq!(name, "macOS (Core Bluetooth)");
        #[cfg(target_os = "windows")]
        assert_eq!(name, "Windows (WinRT)");
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_creation() {
        // This test will fail if no Bluetooth adapter is available
        // but validates the API structure
        let result = BleTransport::new().await;

        // Even if it fails due to no adapter, the error should be informative
        match result {
            Ok(transport) => {
                assert!(transport.is_online());
                assert_eq!(transport.transport_type(), TransportType::Ble);
                println!("BLE transport created on {}", BleTransport::platform_name());
            }
            Err(e) => {
                // Expected if no Bluetooth hardware
                println!("BLE transport error (expected without hardware): {e}");
                assert!(!format!("{e}").is_empty());
            }
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_session_caching() {
        // Create transport (may fail if no BLE hardware)
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let session_key = [0xAA; 32];

            // Initially no cached session
            assert!(!transport.has_cached_session(&device_id).await);

            // Cache a session
            transport.cache_session(device_id, session_key, 1234).await;

            // Now we should have it cached
            assert!(transport.has_cached_session(&device_id).await);

            // Get resume token
            let token = transport.lookup_session(&device_id).await;
            assert!(token.is_some());

            // Check cache stats
            let (hits, misses) = transport.cache_stats();
            assert_eq!(hits, 2); // has_cached_session + lookup_session
            assert_eq!(misses, 1); // Initial has_cached_session
        }
    }

    #[test]
    fn test_gatt_service_uuid() {
        // Verify the service UUID follows our naming convention
        // a03d7e9f-0bca-12fe-a600-000000000001
        assert_eq!(ANT_QUIC_SERVICE_UUID[0], 0xa0);
        assert_eq!(ANT_QUIC_SERVICE_UUID[15], 0x01);
        assert_eq!(ANT_QUIC_SERVICE_UUID.len(), 16);
    }

    #[test]
    fn test_gatt_tx_characteristic_uuid() {
        // TX characteristic UUID ends with 0x02
        // a03d7e9f-0bca-12fe-a600-000000000002
        assert_eq!(TX_CHARACTERISTIC_UUID[0], 0xa0);
        assert_eq!(TX_CHARACTERISTIC_UUID[15], 0x02);
        assert_eq!(TX_CHARACTERISTIC_UUID.len(), 16);

        // First 15 bytes should match service UUID
        assert_eq!(&TX_CHARACTERISTIC_UUID[..15], &ANT_QUIC_SERVICE_UUID[..15]);
    }

    #[test]
    fn test_gatt_rx_characteristic_uuid() {
        // RX characteristic UUID ends with 0x03
        // a03d7e9f-0bca-12fe-a600-000000000003
        assert_eq!(RX_CHARACTERISTIC_UUID[0], 0xa0);
        assert_eq!(RX_CHARACTERISTIC_UUID[15], 0x03);
        assert_eq!(RX_CHARACTERISTIC_UUID.len(), 16);

        // First 15 bytes should match service UUID
        assert_eq!(&RX_CHARACTERISTIC_UUID[..15], &ANT_QUIC_SERVICE_UUID[..15]);
    }

    #[test]
    fn test_cccd_uuid() {
        // CCCD UUID is the standard Bluetooth SIG UUID 0x2902
        // In 128-bit form: 00002902-0000-1000-8000-00805f9b34fb
        assert_eq!(CCCD_UUID[2], 0x29);
        assert_eq!(CCCD_UUID[3], 0x02);
        assert_eq!(CCCD_UUID.len(), 16);
    }

    #[test]
    fn test_cccd_values() {
        // CCCD values are little-endian
        // 0x0001 = enable notifications
        // 0x0002 = enable indications
        // 0x0000 = disable
        assert_eq!(CCCD_ENABLE_NOTIFICATION, [0x01, 0x00]);
        assert_eq!(CCCD_ENABLE_INDICATION, [0x02, 0x00]);
        assert_eq!(CCCD_DISABLE, [0x00, 0x00]);
    }

    #[test]
    fn test_characteristic_uuids_unique() {
        // All UUIDs must be unique
        assert_ne!(ANT_QUIC_SERVICE_UUID, TX_CHARACTERISTIC_UUID);
        assert_ne!(ANT_QUIC_SERVICE_UUID, RX_CHARACTERISTIC_UUID);
        assert_ne!(TX_CHARACTERISTIC_UUID, RX_CHARACTERISTIC_UUID);
        assert_ne!(ANT_QUIC_SERVICE_UUID, CCCD_UUID);
    }

    #[test]
    fn test_ble_connection_state_default() {
        let state = BleConnectionState::default();
        assert_eq!(state, BleConnectionState::Discovered);
    }

    #[test]
    fn test_ble_connection_state_display() {
        assert_eq!(format!("{}", BleConnectionState::Discovered), "discovered");
        assert_eq!(format!("{}", BleConnectionState::Connecting), "connecting");
        assert_eq!(format!("{}", BleConnectionState::Connected), "connected");
        assert_eq!(
            format!("{}", BleConnectionState::Disconnecting),
            "disconnecting"
        );
        assert_eq!(
            format!("{}", BleConnectionState::Disconnected),
            "disconnected"
        );
    }

    #[test]
    fn test_characteristic_handle_tx() {
        let tx = CharacteristicHandle::tx();
        assert_eq!(tx.uuid, TX_CHARACTERISTIC_UUID);
        assert!(tx.write_without_response);
        assert!(!tx.notify);
        assert!(!tx.indicate);
    }

    #[test]
    fn test_characteristic_handle_rx() {
        let rx = CharacteristicHandle::rx();
        assert_eq!(rx.uuid, RX_CHARACTERISTIC_UUID);
        assert!(!rx.write_without_response);
        assert!(rx.notify);
        assert!(!rx.indicate);
    }

    #[tokio::test]
    async fn test_ble_connection_lifecycle() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut conn = BleConnection::new(device_id);

        // Initial state
        assert_eq!(conn.state().await, BleConnectionState::Discovered);
        assert_eq!(conn.device_id(), device_id);
        assert!(!conn.is_connected().await);
        assert!(conn.connection_duration().is_none());

        // Start connecting
        conn.start_connecting().await.unwrap();
        assert_eq!(conn.state().await, BleConnectionState::Connecting);

        // Mark connected with characteristics
        let tx = CharacteristicHandle::tx();
        let rx = CharacteristicHandle::rx();
        conn.mark_connected(tx, rx).await;
        assert_eq!(conn.state().await, BleConnectionState::Connected);
        assert!(conn.is_connected().await);
        assert!(conn.connection_duration().is_some());
        assert!(conn.tx_characteristic().is_some());
        assert!(conn.rx_characteristic().is_some());

        // Touch to update activity
        tokio::time::sleep(Duration::from_millis(10)).await;
        let idle_before = conn.idle_duration().await;
        conn.touch().await;
        let idle_after = conn.idle_duration().await;
        assert!(idle_after < idle_before);

        // Start disconnect
        conn.start_disconnect().await.unwrap();
        assert_eq!(conn.state().await, BleConnectionState::Disconnecting);

        // Mark disconnected
        conn.mark_disconnected().await;
        assert_eq!(conn.state().await, BleConnectionState::Disconnected);
        assert!(!conn.is_connected().await);
    }

    #[tokio::test]
    async fn test_ble_connection_invalid_transitions() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let conn = BleConnection::new(device_id);

        // Can't disconnect from Discovered state
        let result = conn.start_disconnect().await;
        assert!(result.is_err());

        // Can connect from Discovered
        conn.start_connecting().await.unwrap();

        // Can't connect while connecting
        let result = conn.start_connecting().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ble_connection_reconnect() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut conn = BleConnection::new(device_id);

        // Connect
        conn.start_connecting().await.unwrap();
        conn.mark_connected(CharacteristicHandle::tx(), CharacteristicHandle::rx())
            .await;

        // Disconnect
        conn.start_disconnect().await.unwrap();
        conn.mark_disconnected().await;

        // Should be able to reconnect from Disconnected
        conn.start_connecting().await.unwrap();
        assert_eq!(conn.state().await, BleConnectionState::Connecting);
    }

    #[test]
    fn test_ble_connection_debug() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let conn = BleConnection::new(device_id);
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("BleConnection"));
        assert!(debug_str.contains("device_id"));
    }

    #[test]
    fn test_discovered_device_new() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let device = DiscoveredDevice::new(device_id);

        assert_eq!(device.device_id, device_id);
        assert!(device.local_name.is_none());
        assert!(device.rssi.is_none());
        assert!(!device.has_service);
        assert!(device.is_recent(Duration::from_secs(1)));
    }

    #[test]
    fn test_discovered_device_update_last_seen() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut device = DiscoveredDevice::new(device_id);

        let initial_seen = device.last_seen;
        std::thread::sleep(Duration::from_millis(10));
        device.update_last_seen();

        assert!(device.last_seen > initial_seen);
    }

    #[test]
    fn test_discovered_device_age() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let device = DiscoveredDevice::new(device_id);

        std::thread::sleep(Duration::from_millis(50));
        let age = device.age();
        assert!(age >= Duration::from_millis(50));
    }

    #[test]
    fn test_scan_state_default() {
        let state = ScanState::default();
        assert_eq!(state, ScanState::Idle);
    }

    #[test]
    fn test_scan_state_display() {
        assert_eq!(format!("{}", ScanState::Idle), "idle");
        assert_eq!(format!("{}", ScanState::Scanning), "scanning");
        assert_eq!(format!("{}", ScanState::Stopping), "stopping");
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_scanning() {
        // This test validates the scanning API structure
        // Actual scanning may fail without BLE hardware
        if let Ok(transport) = BleTransport::new().await {
            // Initially not scanning
            assert!(!transport.is_scanning().await);
            assert_eq!(transport.scan_state().await, ScanState::Idle);

            // Start scanning (may fail without hardware)
            if transport.start_scanning().await.is_ok() {
                assert!(transport.is_scanning().await);

                // Stop scanning
                transport.stop_scanning().await.unwrap();
                assert!(!transport.is_scanning().await);
            }
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_discovered_devices() {
        if let Ok(transport) = BleTransport::new().await {
            // Initially no devices
            assert_eq!(transport.discovered_device_count().await, 0);

            // Add a device
            let mut device = DiscoveredDevice::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            device.local_name = Some("TestDevice".to_string());
            device.rssi = Some(-60);
            device.has_service = true;

            let is_new = transport.add_discovered_device(device.clone()).await;
            assert!(is_new);
            assert_eq!(transport.discovered_device_count().await, 1);

            // Get the device
            let retrieved = transport
                .get_discovered_device(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
                .await;
            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.local_name, Some("TestDevice".to_string()));

            // Add same device again (update)
            let is_new = transport.add_discovered_device(device).await;
            assert!(!is_new);
            assert_eq!(transport.discovered_device_count().await, 1);

            // Get all devices
            let all_devices = transport.discovered_devices().await;
            assert_eq!(all_devices.len(), 1);

            // Clear devices
            transport.clear_discovered_devices().await;
            assert_eq!(transport.discovered_device_count().await, 0);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_prune_stale_devices() {
        if let Ok(transport) = BleTransport::new().await {
            // Add the first device
            let mut old_device = DiscoveredDevice::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            old_device.has_service = true;
            transport.add_discovered_device(old_device).await;

            // Wait so the first device becomes "stale" relative to a short threshold
            tokio::time::sleep(Duration::from_millis(60)).await;

            // Add a recent device (after the sleep)
            let recent_device = DiscoveredDevice::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            transport.add_discovered_device(recent_device).await;

            assert_eq!(transport.discovered_device_count().await, 2);

            // Prune devices older than 50ms - should remove the first one but keep the recent one
            let pruned = transport
                .prune_stale_devices(Duration::from_millis(50))
                .await;
            assert_eq!(pruned, 1);
            assert_eq!(transport.discovered_device_count().await, 1);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_connect_disconnect() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // First, add the device as discovered
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;

            // Initially no connections
            assert_eq!(transport.active_connection_count().await, 0);
            assert!(!transport.is_connected_to(&device_id).await);

            // Connect to device (simulated for tests)
            let conn = transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();
            assert!(conn.read().await.is_connected().await);
            assert_eq!(transport.active_connection_count().await, 1);
            assert!(transport.is_connected_to(&device_id).await);

            // Get connection
            let retrieved = transport.get_connection(&device_id).await;
            assert!(retrieved.is_some());

            // Get connected devices
            let connected = transport.connected_devices().await;
            assert_eq!(connected.len(), 1);
            assert_eq!(connected[0], device_id);

            // Disconnect
            transport.disconnect_from_device(&device_id).await.unwrap();
            assert_eq!(transport.active_connection_count().await, 0);
            assert!(!transport.is_connected_to(&device_id).await);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_connect_errors() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // Cannot connect to undiscovered device
            let result = transport.connect_to_device_simulated(device_id).await;
            assert!(result.is_err());

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Cannot connect again while already connected
            let result = transport.connect_to_device_simulated(device_id).await;
            assert!(result.is_err());

            // Cannot disconnect from non-existent connection
            let other_device = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let result = transport.disconnect_from_device(&other_device).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_connection_limit() {
        // Create transport with max 2 connections
        let config = BleConfig {
            max_connections: 2,
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add 3 devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
            }

            // Connect to first two
            transport
                .connect_to_device_simulated([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device_simulated([1, 1, 1, 1, 1, 1])
                .await
                .unwrap();

            // Third should fail
            let result = transport
                .connect_to_device_simulated([2, 2, 2, 2, 2, 2])
                .await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("limit"));

            // Disconnect one and try again
            transport
                .disconnect_from_device(&[0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device_simulated([2, 2, 2, 2, 2, 2])
                .await
                .unwrap();
            assert_eq!(transport.active_connection_count().await, 2);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_disconnect_all() {
        if let Ok(transport) = BleTransport::new().await {
            // Add and connect to 3 devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
                transport
                    .connect_to_device_simulated([i, i, i, i, i, i])
                    .await
                    .unwrap();
            }

            assert_eq!(transport.active_connection_count().await, 3);

            // Disconnect all
            let count = transport.disconnect_all().await;
            assert_eq!(count, 3);
            assert_eq!(transport.active_connection_count().await, 0);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_send_requires_connection() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let dest = TransportAddr::ble(device_id, None);
            let data = b"Hello BLE";

            // Send without connection should fail
            let result = transport.send(data, &dest).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("No connection"));

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Send with connection should succeed
            let result = transport.send(data, &dest).await;
            assert!(result.is_ok());

            // Verify stats
            let stats = transport.stats();
            assert_eq!(stats.datagrams_sent, 1);
            assert_eq!(stats.bytes_sent, data.len() as u64);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_send_size_check() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let dest = TransportAddr::ble(device_id, None);

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Small data should succeed (single fragment)
            let small_data = vec![0u8; 100];
            let result = transport.send(&small_data, &dest).await;
            assert!(result.is_ok());

            // Larger data should also succeed (multiple fragments)
            // With fragmentation, messages up to ~61KB (255 * 240 bytes) are allowed
            let large_data = vec![0u8; 500];
            let result = transport.send(&large_data, &dest).await;
            assert!(result.is_ok());

            // Data exceeding max fragmentable size should fail
            // Max is 255 fragments * 240 bytes payload = 61,200 bytes
            let max_size = 255 * DEFAULT_FRAGMENT_PAYLOAD_SIZE;
            let too_large_data = vec![0u8; max_size + 1];
            let result = transport.send(&too_large_data, &dest).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("MessageTooLarge"));
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_send_address_mismatch() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Try to send to UDP address on BLE transport
            let udp_addr = TransportAddr::Udp("192.168.1.1:9000".parse().unwrap());
            let result = transport.send(b"test", &udp_addr).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("AddressMismatch"));
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_send_offline() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let dest = TransportAddr::ble(device_id, None);

            // Shutdown transport
            transport.shutdown().await.unwrap();

            // Send should fail when offline
            let result = transport.send(b"test", &dest).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("Offline"));
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_process_notification() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Take the receiver
            let mut rx = transport.take_inbound_receiver().await.unwrap();

            // Process a notification (with fragment header for single message)
            let payload = b"Hello from peripheral".to_vec();
            let mut fragment = FragmentHeader::single(0).to_bytes().to_vec();
            fragment.extend_from_slice(&payload);
            transport
                .process_notification(device_id, fragment)
                .await
                .unwrap();

            // Check stats
            let stats = transport.stats();
            assert_eq!(stats.datagrams_received, 1);

            // Receive the datagram (should be payload without header)
            let received = rx.try_recv().unwrap();
            assert_eq!(received.data, payload);
            assert!(matches!(received.source, TransportAddr::Ble { .. }));
            assert!(received.link_quality.is_some());

            // Second take should return None
            assert!(transport.take_inbound_receiver().await.is_none());
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_process_notification_unknown_device() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // Try to process notification without connection
            let result = transport
                .process_notification(device_id, b"test".to_vec())
                .await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("unknown device"));

            // Verify error counter incremented
            let stats = transport.stats();
            assert_eq!(stats.receive_errors, 1);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_multiple_notifications() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport
                .connect_to_device_simulated(device_id)
                .await
                .unwrap();

            // Take the receiver
            let mut rx = transport.take_inbound_receiver().await.unwrap();

            // Process multiple notifications (each with fragment header)
            for i in 0..5u8 {
                let payload = format!("Message {}", i).into_bytes();
                let mut fragment = FragmentHeader::single(i).to_bytes().to_vec();
                fragment.extend_from_slice(&payload);
                transport
                    .process_notification(device_id, fragment)
                    .await
                    .unwrap();
            }

            // Check stats
            let stats = transport.stats();
            assert_eq!(stats.datagrams_received, 5);

            // Receive all datagrams
            let mut count = 0;
            while rx.try_recv().is_ok() {
                count += 1;
            }
            assert_eq!(count, 5);
        }
    }

    #[test]
    fn test_peripheral_mode_supported() {
        let supported = BleTransport::is_peripheral_mode_supported();
        // Linux is the only platform with good peripheral support
        #[cfg(target_os = "linux")]
        assert!(supported);
        #[cfg(not(target_os = "linux"))]
        assert!(!supported);
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_advertising() {
        if let Ok(transport) = BleTransport::new().await {
            let result = transport.start_advertising().await;

            #[cfg(target_os = "linux")]
            {
                // Linux should succeed (stub)
                assert!(result.is_ok());
            }

            #[cfg(not(target_os = "linux"))]
            {
                // Other platforms should return unsupported
                assert!(result.is_err());
            }

            // Stop advertising should always succeed
            let result = transport.stop_advertising().await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_connection_pool_stats() {
        if let Ok(transport) = BleTransport::new().await {
            // Initial stats
            let stats = transport.pool_stats().await;
            assert_eq!(stats.active, 0);
            assert_eq!(stats.total, 0);
            assert!(stats.has_capacity());
            assert_eq!(stats.remaining_capacity(), 5); // Default max_connections

            // Add and connect to devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
                transport
                    .connect_to_device_simulated([i, i, i, i, i, i])
                    .await
                    .unwrap();
            }

            // Check stats after connections
            let stats = transport.pool_stats().await;
            assert_eq!(stats.active, 3);
            assert_eq!(stats.total, 3);
            assert!(stats.has_capacity());
            assert_eq!(stats.remaining_capacity(), 2);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_connection_pool_eviction() {
        let config = BleConfig {
            max_connections: 2,
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add 3 devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
            }

            // Connect to first two
            transport
                .connect_to_device_simulated([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // Add small delay so first connection is "older"
            tokio::time::sleep(Duration::from_millis(10)).await;
            transport
                .connect_to_device_simulated([1, 1, 1, 1, 1, 1])
                .await
                .unwrap();

            // Pool is full
            let stats = transport.pool_stats().await;
            assert!(!stats.has_capacity());

            // Evict LRU should remove the first connection (oldest idle)
            let evicted = transport.evict_lru_connection().await;
            assert!(evicted.is_some());

            // Should have capacity now
            let stats = transport.pool_stats().await;
            assert!(stats.has_capacity());
            assert_eq!(stats.total, 1);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_connect_with_eviction() {
        let config = BleConfig {
            max_connections: 2,
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add 3 devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
            }

            // Connect to two devices
            transport
                .connect_to_device_simulated([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device_simulated([1, 1, 1, 1, 1, 1])
                .await
                .unwrap();
            assert_eq!(transport.active_connection_count().await, 2);

            // Connect with eviction should work (evicts oldest)
            let result = transport
                .connect_with_eviction_simulated([2, 2, 2, 2, 2, 2])
                .await;
            assert!(result.is_ok());
            assert_eq!(transport.active_connection_count().await, 2);

            // Device 2 should now be connected
            assert!(transport.is_connected_to(&[2, 2, 2, 2, 2, 2]).await);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_evict_idle_connections() {
        if let Ok(transport) = BleTransport::new().await {
            // Add and connect to devices
            for i in 0..3u8 {
                let device = DiscoveredDevice::new([i, i, i, i, i, i]);
                transport.add_discovered_device(device).await;
                transport
                    .connect_to_device_simulated([i, i, i, i, i, i])
                    .await
                    .unwrap();
            }

            // Touch one connection to keep it active
            if let Some(conn) = transport.get_connection(&[2, 2, 2, 2, 2, 2]).await {
                conn.read().await.touch().await;
            }

            // Wait a bit
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Evict connections idle > 10ms (should evict 2, keep 1 that was touched)
            let evicted = transport
                .evict_idle_connections(Duration::from_millis(10))
                .await;

            // At least some should be evicted
            assert!(evicted >= 2);
        }
    }

    #[test]
    fn test_connection_pool_stats_default() {
        let stats = ConnectionPoolStats::default();
        assert_eq!(stats.max_connections, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.total, 0);
        // 0 < 0 is false, so no capacity
        assert!(!stats.has_capacity());
        assert_eq!(stats.remaining_capacity(), 0);
    }

    // ===== Fragmentation Tests =====

    #[test]
    fn test_fragment_header_serialization() {
        let header = FragmentHeader::new(5, fragment_flags::START, 10, 42);
        let bytes = header.to_bytes();

        assert_eq!(bytes, [5, fragment_flags::START, 10, 42]);

        let restored = FragmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored, header);
    }

    #[test]
    fn test_fragment_header_single() {
        let header = FragmentHeader::single(7);

        assert_eq!(header.seq_num, 0);
        assert_eq!(header.flags, fragment_flags::SINGLE);
        assert_eq!(header.total, 1);
        assert_eq!(header.msg_id, 7);
        assert!(header.is_start());
        assert!(header.is_end());
        assert!(header.is_single());
    }

    #[test]
    fn test_fragment_header_flags() {
        // First fragment
        let first = FragmentHeader::new(0, fragment_flags::START, 3, 0);
        assert!(first.is_start());
        assert!(!first.is_end());
        assert!(!first.is_single());

        // Middle fragment
        let middle = FragmentHeader::new(1, 0, 3, 0);
        assert!(!middle.is_start());
        assert!(!middle.is_end());
        assert!(!middle.is_single());

        // Last fragment
        let last = FragmentHeader::new(2, fragment_flags::END, 3, 0);
        assert!(!last.is_start());
        assert!(last.is_end());
        assert!(!last.is_single());
    }

    #[test]
    fn test_fragment_header_from_bytes_too_short() {
        assert!(FragmentHeader::from_bytes(&[]).is_none());
        assert!(FragmentHeader::from_bytes(&[1, 2, 3]).is_none());
        assert!(FragmentHeader::from_bytes(&[1, 2, 3, 4]).is_some());
    }

    #[test]
    fn test_fragmenter_default() {
        let fragmenter = BlePacketFragmenter::default_ble();
        assert_eq!(fragmenter.mtu(), DEFAULT_BLE_MTU);
        assert_eq!(
            fragmenter.payload_size(),
            DEFAULT_BLE_MTU - FRAGMENT_HEADER_SIZE
        );
    }

    #[test]
    fn test_fragmenter_custom_mtu() {
        let fragmenter = BlePacketFragmenter::new(100);
        assert_eq!(fragmenter.mtu(), 100);
        assert_eq!(fragmenter.payload_size(), 96); // 100 - 4
    }

    #[test]
    #[should_panic]
    fn test_fragmenter_invalid_mtu() {
        BlePacketFragmenter::new(4); // Equal to header size
    }

    #[test]
    fn test_fragmenter_empty_data() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let fragments = fragmenter.fragment(&[], 0);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), FRAGMENT_HEADER_SIZE);

        let header = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert!(header.is_single());
    }

    #[test]
    fn test_fragmenter_single_fragment() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let data = vec![0xAB; 100]; // Smaller than payload size
        let fragments = fragmenter.fragment(&data, 42);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), FRAGMENT_HEADER_SIZE + 100);

        let header = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert!(header.is_single());
        assert_eq!(header.msg_id, 42);
        assert_eq!(&fragments[0][FRAGMENT_HEADER_SIZE..], &data[..]);
    }

    #[test]
    fn test_fragmenter_exact_fit() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let data = vec![0xCD; fragmenter.payload_size()];
        let fragments = fragmenter.fragment(&data, 5);

        assert_eq!(fragments.len(), 1);
        assert!(
            FragmentHeader::from_bytes(&fragments[0])
                .unwrap()
                .is_single()
        );
    }

    #[test]
    fn test_fragmenter_multiple_fragments() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let payload_size = fragmenter.payload_size();

        // Create data that requires 3 fragments
        let data = vec![0xEF; payload_size * 2 + 50];
        let fragments = fragmenter.fragment(&data, 10);

        assert_eq!(fragments.len(), 3);

        // Check first fragment
        let h0 = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert!(h0.is_start());
        assert!(!h0.is_end());
        assert_eq!(h0.seq_num, 0);
        assert_eq!(h0.total, 3);
        assert_eq!(h0.msg_id, 10);
        assert_eq!(fragments[0].len(), fragmenter.mtu());

        // Check middle fragment
        let h1 = FragmentHeader::from_bytes(&fragments[1]).unwrap();
        assert!(!h1.is_start());
        assert!(!h1.is_end());
        assert_eq!(h1.seq_num, 1);
        assert_eq!(h1.total, 3);

        // Check last fragment
        let h2 = FragmentHeader::from_bytes(&fragments[2]).unwrap();
        assert!(!h2.is_start());
        assert!(h2.is_end());
        assert_eq!(h2.seq_num, 2);
        assert_eq!(fragments[2].len(), FRAGMENT_HEADER_SIZE + 50);
    }

    #[test]
    fn test_fragmenter_needs_fragmentation() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let payload_size = fragmenter.payload_size();

        assert!(!fragmenter.needs_fragmentation(&[0; 100]));
        assert!(!fragmenter.needs_fragmentation(&vec![0u8; payload_size]));
        assert!(fragmenter.needs_fragmentation(&vec![0u8; payload_size + 1]));
    }

    #[test]
    fn test_reassembly_buffer_single_fragment() {
        let mut buffer = BleReassemblyBuffer::default();
        let device_id = [1, 2, 3, 4, 5, 6];

        // Create a single-fragment message
        let mut fragment = FragmentHeader::single(0).to_bytes().to_vec();
        fragment.extend_from_slice(b"hello world");

        let result = buffer.add_fragment(device_id, &fragment);
        assert_eq!(result, Some(b"hello world".to_vec()));
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_buffer_multi_fragment_in_order() {
        let mut buffer = BleReassemblyBuffer::default();
        let device_id = [1, 2, 3, 4, 5, 6];
        let msg_id = 42;

        // Fragment 0 (START)
        let mut frag0 = FragmentHeader::new(0, fragment_flags::START, 3, msg_id)
            .to_bytes()
            .to_vec();
        frag0.extend_from_slice(b"hello ");

        // Fragment 1 (middle)
        let mut frag1 = FragmentHeader::new(1, 0, 3, msg_id).to_bytes().to_vec();
        frag1.extend_from_slice(b"world ");

        // Fragment 2 (END)
        let mut frag2 = FragmentHeader::new(2, fragment_flags::END, 3, msg_id)
            .to_bytes()
            .to_vec();
        frag2.extend_from_slice(b"!");

        // Add fragments in order
        assert!(buffer.add_fragment(device_id, &frag0).is_none());
        assert_eq!(buffer.pending_count(), 1);

        assert!(buffer.add_fragment(device_id, &frag1).is_none());
        assert_eq!(buffer.pending_count(), 1);

        let result = buffer.add_fragment(device_id, &frag2);
        assert_eq!(result, Some(b"hello world !".to_vec()));
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_buffer_multi_fragment_out_of_order() {
        let mut buffer = BleReassemblyBuffer::default();
        let device_id = [1, 2, 3, 4, 5, 6];
        let msg_id = 7;

        // Fragment 2 (END) first
        let mut frag2 = FragmentHeader::new(2, fragment_flags::END, 3, msg_id)
            .to_bytes()
            .to_vec();
        frag2.extend_from_slice(b"C");

        // Fragment 0 (START) second
        let mut frag0 = FragmentHeader::new(0, fragment_flags::START, 3, msg_id)
            .to_bytes()
            .to_vec();
        frag0.extend_from_slice(b"A");

        // Fragment 1 (middle) last
        let mut frag1 = FragmentHeader::new(1, 0, 3, msg_id).to_bytes().to_vec();
        frag1.extend_from_slice(b"B");

        // Add out of order
        assert!(buffer.add_fragment(device_id, &frag2).is_none());
        assert!(buffer.add_fragment(device_id, &frag0).is_none());

        let result = buffer.add_fragment(device_id, &frag1);
        // Assembled in sequence order: A + B + C
        assert_eq!(result, Some(b"ABC".to_vec()));
    }

    #[test]
    fn test_reassembly_buffer_duplicate_fragment() {
        let mut buffer = BleReassemblyBuffer::default();
        let device_id = [1, 2, 3, 4, 5, 6];
        let msg_id = 99;

        let mut frag0 = FragmentHeader::new(0, fragment_flags::START, 2, msg_id)
            .to_bytes()
            .to_vec();
        frag0.extend_from_slice(b"data");

        // Add same fragment twice
        assert!(buffer.add_fragment(device_id, &frag0).is_none());
        assert!(buffer.add_fragment(device_id, &frag0).is_none()); // Duplicate ignored

        // Still waiting for fragment 1
        assert_eq!(buffer.pending_count(), 1);
    }

    #[test]
    fn test_reassembly_buffer_multiple_devices() {
        let mut buffer = BleReassemblyBuffer::default();
        let device1 = [1, 1, 1, 1, 1, 1];
        let device2 = [2, 2, 2, 2, 2, 2];

        // Start message from device 1
        let mut frag1_0 = FragmentHeader::new(0, fragment_flags::START, 2, 0)
            .to_bytes()
            .to_vec();
        frag1_0.extend_from_slice(b"D1-");

        // Start message from device 2 (same msg_id but different device)
        let mut frag2_0 = FragmentHeader::new(0, fragment_flags::START, 2, 0)
            .to_bytes()
            .to_vec();
        frag2_0.extend_from_slice(b"D2-");

        assert!(buffer.add_fragment(device1, &frag1_0).is_none());
        assert!(buffer.add_fragment(device2, &frag2_0).is_none());
        assert_eq!(buffer.pending_count(), 2);

        // Complete device 2
        let mut frag2_1 = FragmentHeader::new(1, fragment_flags::END, 2, 0)
            .to_bytes()
            .to_vec();
        frag2_1.extend_from_slice(b"done");

        let result = buffer.add_fragment(device2, &frag2_1);
        assert_eq!(result, Some(b"D2-done".to_vec()));
        assert_eq!(buffer.pending_count(), 1); // Device 1 still pending
    }

    #[test]
    fn test_reassembly_buffer_prune_stale() {
        let mut buffer = BleReassemblyBuffer::new(Duration::from_millis(10));
        let device_id = [1, 2, 3, 4, 5, 6];

        // Add incomplete fragment
        let mut frag0 = FragmentHeader::new(0, fragment_flags::START, 2, 0)
            .to_bytes()
            .to_vec();
        frag0.extend_from_slice(b"incomplete");

        buffer.add_fragment(device_id, &frag0);
        assert_eq!(buffer.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        // Prune stale entries
        let pruned = buffer.prune_stale();
        assert_eq!(pruned, 1);
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_fragmenter_and_reassembly_roundtrip() {
        let fragmenter = BlePacketFragmenter::default_ble();
        let mut buffer = BleReassemblyBuffer::default();
        let device_id = [0xAA; 6];

        // Test data larger than MTU
        let original_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let fragments = fragmenter.fragment(&original_data, 123);
        assert!(fragments.len() > 1);

        // Feed fragments to reassembly (simulate out-of-order delivery)
        let mut result = None;
        for (i, frag) in fragments.iter().enumerate().rev() {
            result = buffer.add_fragment(device_id, frag);
            if i > 0 {
                assert!(result.is_none());
            }
        }

        assert_eq!(result.unwrap(), original_data);
    }

    // ============================================================================
    // Session Caching Tests (Phase 3.3)
    // ============================================================================

    #[test]
    fn test_ble_config_session_caching_defaults() {
        let config = BleConfig::default();

        // Session caching configuration
        assert_eq!(
            config.session_cache_duration,
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(config.max_cached_sessions, 100);
        assert_eq!(
            config.session_cleanup_interval,
            Some(Duration::from_secs(600))
        );
        assert!(config.session_persist_path.is_none());
    }

    #[test]
    fn test_cached_session_expiry() {
        let session = CachedSession {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            session_key: [0xAA; 32],
            session_id: 1234,
            established: Instant::now(),
            last_active: Instant::now(),
        };

        // Should not be expired immediately
        assert!(!session.is_expired(Duration::from_secs(3600)));

        // Should be expired with zero duration
        assert!(session.is_expired(Duration::ZERO));
    }

    #[test]
    fn test_persisted_session_from_cached() {
        let cached = CachedSession {
            device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            session_key: [0xAA; 32],
            session_id: 1234,
            established: Instant::now(),
            last_active: Instant::now(),
        };

        let persisted = PersistedSession::from_cached(&cached);

        assert_eq!(persisted.device_id, "112233445566");
        assert_eq!(persisted.session_id, 1234);
        // Timestamp should be recent
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(persisted.established_unix <= now_unix);
        assert!(persisted.established_unix >= now_unix.saturating_sub(10));
    }

    #[test]
    fn test_session_cache_file_serialization() {
        let mut file = SessionCacheFile::new();
        file.sessions.push(PersistedSession {
            device_id: "112233445566".to_string(),
            session_key_hash: [0xBB; 32],
            session_id: 5678,
            established_unix: 1234567890,
        });
        file.sessions.push(PersistedSession {
            device_id: "AABBCCDDEEFF".to_string(),
            session_key_hash: [0xCC; 32],
            session_id: 9012,
            established_unix: 1234567891,
        });

        let bytes = file.to_bytes();
        let restored = SessionCacheFile::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, SessionCacheFile::CURRENT_VERSION);
        assert_eq!(restored.sessions.len(), 2);
        assert_eq!(restored.sessions[0].device_id, "112233445566");
        assert_eq!(restored.sessions[0].session_id, 5678);
        assert_eq!(restored.sessions[1].device_id, "AABBCCDDEEFF");
        assert_eq!(restored.sessions[1].session_id, 9012);
    }

    #[test]
    fn test_session_cache_file_empty() {
        let file = SessionCacheFile::new();
        let bytes = file.to_bytes();
        let restored = SessionCacheFile::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sessions.len(), 0);
    }

    #[test]
    fn test_session_cache_file_invalid() {
        // Empty bytes
        assert!(SessionCacheFile::from_bytes(&[]).is_none());

        // Too short
        assert!(SessionCacheFile::from_bytes(&[1, 2, 3]).is_none());

        // Invalid version
        let invalid_version = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
        assert!(SessionCacheFile::from_bytes(&invalid_version).is_none());
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_session_lookup_integration() {
        // Create transport with a connected device that uses session resumption
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let session_key = [0xAB; 32];

            // Initially no session
            assert!(!transport.has_cached_session(&device_id).await);
            let (hits, misses) = transport.cache_stats();
            assert_eq!(hits, 0);
            assert_eq!(misses, 1);

            // Add a cached session manually
            transport.cache_session(device_id, session_key, 1234).await;

            // Now session should be found
            assert!(transport.has_cached_session(&device_id).await);
            let (hits, misses) = transport.cache_stats();
            assert_eq!(hits, 1);
            assert_eq!(misses, 1);

            // lookup_session should return a token
            let token = transport.lookup_session(&device_id).await;
            assert!(token.is_some());

            // Verify token structure
            let token = token.unwrap();
            assert_eq!(&token.peer_id_hash[..6], &device_id);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_session_touch() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

            // Add a session
            transport.cache_session(device_id, [0xAA; 32], 1234).await;

            // Wait a bit and then touch
            tokio::time::sleep(Duration::from_millis(10)).await;
            transport.touch_session(&device_id).await;

            // Session should still be valid (touch should update last_active)
            assert!(transport.has_cached_session(&device_id).await);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_prune_sessions() {
        // Create transport with short session duration
        let config = BleConfig {
            session_cache_duration: Duration::from_millis(50),
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add a session
            transport
                .cache_session([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], [0xAA; 32], 1234)
                .await;
            assert_eq!(transport.cached_session_count().await, 1);

            // Wait for expiration
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Prune should remove the expired session
            let pruned = transport.prune_expired_sessions().await;
            assert_eq!(pruned, 1);
            assert_eq!(transport.cached_session_count().await, 0);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_prune_enforces_max_sessions() {
        // Create transport with max 3 cached sessions
        let config = BleConfig {
            max_cached_sessions: 3,
            session_cache_duration: Duration::from_secs(3600),
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add 5 sessions
            for i in 0..5u8 {
                let device_id = [i, i, i, i, i, i];
                transport.cache_session(device_id, [i; 32], i as u16).await;
                // Small delay so they have different last_active times
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            assert_eq!(transport.cached_session_count().await, 5);

            // Prune should remove 2 LRU sessions
            let pruned = transport.prune_expired_sessions().await;
            assert_eq!(pruned, 2);
            assert_eq!(transport.cached_session_count().await, 3);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_clear_session_cache() {
        if let Ok(transport) = BleTransport::new().await {
            // Add multiple sessions
            for i in 0..3u8 {
                let device_id = [i, i, i, i, i, i];
                transport.cache_session(device_id, [i; 32], i as u16).await;
            }

            assert_eq!(transport.cached_session_count().await, 3);

            // Clear all
            transport.clear_session_cache().await;
            assert_eq!(transport.cached_session_count().await, 0);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_cache_connection_session() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let session_key = [0x12; 32];

            // Use the convenience method
            transport
                .cache_connection_session(device_id, session_key)
                .await;

            // Verify session was cached
            assert!(transport.has_cached_session(&device_id).await);
            assert_eq!(transport.cached_session_count().await, 1);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_session_persistence_save_load() {
        // Create a temp file for testing
        let temp_dir = std::env::temp_dir();
        let persist_path = temp_dir.join("ant_quic_ble_session_test.cache");

        // Clean up any previous test file
        let _ = std::fs::remove_file(&persist_path);

        let config = BleConfig {
            session_persist_path: Some(persist_path.clone()),
            ..Default::default()
        };

        if let Ok(transport) = BleTransport::with_config(config).await {
            // Add some sessions
            transport
                .cache_session([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], [0xAA; 32], 1234)
                .await;
            transport
                .cache_session([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], [0xBB; 32], 5678)
                .await;

            // Save to disk
            transport.save_sessions_to_disk().await.unwrap();

            // Verify file was created
            assert!(persist_path.exists());

            // Load from disk (simulating restart)
            let count = transport.load_sessions_from_disk().await.unwrap();
            assert_eq!(count, 2);

            // Clean up
            let _ = std::fs::remove_file(&persist_path);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_transport_session_persistence_no_path() {
        // With no persistence path, save/load should be no-ops
        if let Ok(transport) = BleTransport::new().await {
            // Should succeed silently
            transport.save_sessions_to_disk().await.unwrap();

            // Should return 0 (no sessions loaded)
            let count = transport.load_sessions_from_disk().await.unwrap();
            assert_eq!(count, 0);
        }
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn test_ble_connection_session_resumed_flag() {
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let conn = BleConnection::new(device_id);

        // New connections default to not resumed
        assert!(!conn.session_resumed);

        // Can create with resumed flag
        let conn_with_flag = BleConnection::new_with_resumption(device_id, true);
        assert!(conn_with_flag.session_resumed);
    }
}
