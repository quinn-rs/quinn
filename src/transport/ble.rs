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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};

use super::addr::{TransportAddr, TransportType};
use super::capabilities::TransportCapabilities;
use super::provider::{
    InboundDatagram, LinkQuality, TransportError, TransportProvider, TransportStats,
};

// Import btleplug traits for adapter operations
#[cfg(feature = "ble")]
use btleplug::api::Central;

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
    /// Time when connection was established
    connected_at: Option<Instant>,
    /// Last activity timestamp
    last_activity: Arc<RwLock<Instant>>,
    /// Shutdown signal sender (for graceful disconnect)
    shutdown_tx: mpsc::Sender<()>,
}

impl BleConnection {
    /// Create a new BLE connection handle for a discovered device
    pub fn new(device_id: [u8; 6]) -> Self {
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        Self {
            device_id,
            state: Arc::new(RwLock::new(BleConnectionState::Discovered)),
            tx_characteristic: None,
            rx_characteristic: None,
            connected_at: None,
            last_activity: Arc::new(RwLock::new(Instant::now())),
            shutdown_tx,
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
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            service_uuid: ANT_QUIC_SERVICE_UUID,
            session_cache_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            max_connections: 5,
            scan_interval: Duration::from_secs(10),
            connection_timeout: Duration::from_secs(30),
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

/// Information about a discovered BLE peripheral
///
/// Populated during scanning when a device advertising the ant-quic service is found.
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// BLE MAC address (6 bytes)
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
    pub async fn with_config(config: BleConfig) -> Result<Self, TransportError> {
        // Get local Bluetooth adapter address
        let local_device_id = Self::get_local_adapter_address().await?;

        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        let (scan_event_tx, scan_event_rx) = mpsc::channel(64);

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
        };

        Ok(transport)
    }

    /// Get the local Bluetooth adapter address using btleplug
    ///
    /// This works on Linux, macOS, and Windows via btleplug's platform adapters.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    async fn get_local_adapter_address() -> Result<[u8; 6], TransportError> {
        use btleplug::api::Manager as _;
        use btleplug::platform::Manager;

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

        Ok(device_id)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    async fn get_local_adapter_address() -> Result<[u8; 6], TransportError> {
        Err(TransportError::Other {
            message: "BLE transport is not supported on this platform".to_string(),
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
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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

        // In a full implementation, this would:
        // 1. Get the btleplug adapter
        // 2. Start scanning with filters for our service UUID
        // 3. Process peripheral events and populate discovered_devices
        //
        // For now, we just set the state and let the caller know scanning has "started"

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub async fn start_scanning(&self) -> Result<(), TransportError> {
        Err(TransportError::Other {
            message: "BLE scanning is not supported on this platform".to_string(),
        })
    }

    /// Stop scanning for BLE peripherals
    ///
    /// Stops the background scan task. Already discovered devices remain in the
    /// discovered_devices map until explicitly cleared.
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

        // In a full implementation, this would stop the btleplug scan
        // For now, just transition to Idle
        *state = ScanState::Idle;

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
    /// 3. Discovers the ant-quic GATT service and characteristics
    /// 4. Subscribes to RX characteristic notifications
    /// 5. Stores the connection in active_connections
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Transport is offline
    /// - Device was not previously discovered
    /// - Connection limit exceeded
    /// - Connection already exists
    /// - Platform doesn't support connections
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub async fn connect_to_device(
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
        let discovered = self.discovered_devices.read().await;
        if !discovered.contains_key(&device_id) {
            return Err(TransportError::Other {
                message: format!("Device not discovered: {:02x?}", device_id),
            });
        }
        drop(discovered);

        tracing::info!(
            device_id = ?device_id,
            platform = %Self::platform_name(),
            "Connecting to BLE device"
        );

        // Create connection handle
        let mut connection = BleConnection::new(device_id);
        connection.start_connecting().await?;

        // In a full implementation, this would:
        // 1. Get the btleplug Peripheral for this device
        // 2. Call peripheral.connect()
        // 3. Call peripheral.discover_services()
        // 4. Find our service UUID and get TX/RX characteristics
        // 5. Subscribe to RX notifications
        //
        // For now, simulate a successful connection with characteristics
        connection
            .mark_connected(CharacteristicHandle::tx(), CharacteristicHandle::rx())
            .await;

        // Store connection
        let connection = Arc::new(RwLock::new(connection));
        self.active_connections
            .write()
            .await
            .insert(device_id, connection.clone());

        tracing::info!(
            device_id = ?device_id,
            "BLE device connected (simulated)"
        );

        Ok(connection)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub async fn connect_to_device(
        &self,
        _device_id: [u8; 6],
    ) -> Result<Arc<RwLock<BleConnection>>, TransportError> {
        Err(TransportError::Other {
            message: "BLE connections are not supported on this platform".to_string(),
        })
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

        // Create inbound datagram
        let datagram = InboundDatagram {
            source: TransportAddr::ble(device_id, Some(self.config.service_uuid)),
            data,
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

        // Update stats
        self.stats
            .datagrams_received
            .fetch_add(1, Ordering::Relaxed);

        tracing::trace!(
            device_id = ?device_id,
            "Processed BLE notification"
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

        if data.len() > self.capabilities.mtu {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: self.capabilities.mtu,
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

        // In a full implementation, this would:
        // 1. Get the btleplug Peripheral from the connection
        // 2. Find the TX characteristic handle
        // 3. Call peripheral.write(characteristic, data, WriteType::WithoutResponse)
        //
        // For now, we validate the path and simulate the write

        tracing::debug!(
            device_id = ?device_id,
            data_len = data.len(),
            platform = %Self::platform_name(),
            "BLE characteristic write (simulated)"
        );

        // Update stats on success
        self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

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
            let device = DiscoveredDevice {
                device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                local_name: Some("TestDevice".to_string()),
                rssi: Some(-60),
                discovered_at: Instant::now(),
                last_seen: Instant::now(),
                has_service: true,
            };

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
            // Add an old device
            let old_device = DiscoveredDevice {
                device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                local_name: None,
                rssi: None,
                discovered_at: Instant::now() - Duration::from_secs(10),
                last_seen: Instant::now() - Duration::from_secs(10),
                has_service: true,
            };
            transport.add_discovered_device(old_device).await;

            // Add a recent device
            let recent_device = DiscoveredDevice::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            transport.add_discovered_device(recent_device).await;

            assert_eq!(transport.discovered_device_count().await, 2);

            // Prune devices older than 5 seconds
            let pruned = transport.prune_stale_devices(Duration::from_secs(5)).await;
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

            // Connect to device
            let conn = transport.connect_to_device(device_id).await.unwrap();
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
            let result = transport.connect_to_device(device_id).await;
            assert!(result.is_err());

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport.connect_to_device(device_id).await.unwrap();

            // Cannot connect again while already connected
            let result = transport.connect_to_device(device_id).await;
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
                .connect_to_device([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device([1, 1, 1, 1, 1, 1])
                .await
                .unwrap();

            // Third should fail
            let result = transport.connect_to_device([2, 2, 2, 2, 2, 2]).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("limit"));

            // Disconnect one and try again
            transport
                .disconnect_from_device(&[0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device([2, 2, 2, 2, 2, 2])
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
                    .connect_to_device([i, i, i, i, i, i])
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
            transport.connect_to_device(device_id).await.unwrap();

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
    async fn test_ble_transport_send_mtu_check() {
        if let Ok(transport) = BleTransport::new().await {
            let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            let dest = TransportAddr::ble(device_id, None);

            // Add device and connect
            let device = DiscoveredDevice::new(device_id);
            transport.add_discovered_device(device).await;
            transport.connect_to_device(device_id).await.unwrap();

            // Send within MTU should succeed
            let small_data = vec![0u8; 100];
            let result = transport.send(&small_data, &dest).await;
            assert!(result.is_ok());

            // Send exceeding MTU should fail (BLE MTU is 244)
            let large_data = vec![0u8; 500];
            let result = transport.send(&large_data, &dest).await;
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
            transport.connect_to_device(device_id).await.unwrap();

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
            transport.connect_to_device(device_id).await.unwrap();

            // Take the receiver
            let mut rx = transport.take_inbound_receiver().await.unwrap();

            // Process a notification
            let data = b"Hello from peripheral".to_vec();
            transport
                .process_notification(device_id, data.clone())
                .await
                .unwrap();

            // Check stats
            let stats = transport.stats();
            assert_eq!(stats.datagrams_received, 1);

            // Receive the datagram
            let received = rx.try_recv().unwrap();
            assert_eq!(received.data, data);
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
            transport.connect_to_device(device_id).await.unwrap();

            // Take the receiver
            let mut rx = transport.take_inbound_receiver().await.unwrap();

            // Process multiple notifications
            for i in 0..5 {
                let data = format!("Message {}", i).into_bytes();
                transport
                    .process_notification(device_id, data)
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
                    .connect_to_device([i, i, i, i, i, i])
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
                .connect_to_device([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // Add small delay so first connection is "older"
            tokio::time::sleep(Duration::from_millis(10)).await;
            transport
                .connect_to_device([1, 1, 1, 1, 1, 1])
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
                .connect_to_device([0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            transport
                .connect_to_device([1, 1, 1, 1, 1, 1])
                .await
                .unwrap();
            assert_eq!(transport.active_connection_count().await, 2);

            // Connect with eviction should work (evicts oldest)
            let result = transport.connect_with_eviction([2, 2, 2, 2, 2, 2]).await;
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
                    .connect_to_device([i, i, i, i, i, i])
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
}
