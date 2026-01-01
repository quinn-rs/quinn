//! Persistent storage for experiment data.
//!
//! This module provides JSON-based persistence for all experiment data,
//! ensuring that historical records are preserved across registry restarts.
//!
//! # Design for Long-Running Experiments
//!
//! - **In-memory buffering**: Records are kept in memory until thresholds are reached
//! - **Record-count based saves**: Data is saved when buffer reaches threshold (not time-based)
//! - **File rotation**: Large files are rotated to new versions (events.jsonl -> events.1.jsonl)
//! - **Append-only**: Events are always appended, never overwritten
//!
//! # Data Files
//!
//! - `experiment_summary.json` - Current experiment summary (overwritten each save)
//! - `nodes.json` - All node registrations (active and historical)
//! - `connections.json` - All connection records
//! - `events.jsonl` - Append-only event log (JSON Lines format)
//! - `events.N.jsonl` - Rotated event logs when size exceeded
//! - `stats_snapshots.json` - Network statistics snapshots

use crate::registry::types::{
    ConnectionBreakdown, ConnectionRecord, ExperimentResults, NatStats, NetworkEvent, NetworkStats,
    PeerInfo,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Maximum events to keep in memory before flushing to disk.
const EVENT_BUFFER_THRESHOLD: usize = 500;

/// Maximum file size before rotation (10MB).
const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum events per file before rotation (100k).
const MAX_EVENTS_PER_FILE: usize = 100_000;

/// Maximum stats snapshots to keep in memory before saving.
const STATS_BUFFER_THRESHOLD: usize = 100;

/// Persistent data store configuration.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Directory to store data files.
    pub data_dir: PathBuf,
    /// Whether to enable persistence.
    pub enabled: bool,
    /// Events in memory before flush (default: 500).
    pub event_buffer_size: usize,
    /// Max file size before rotation (default: 10MB).
    pub max_file_size: u64,
    /// Max events per file before rotation (default: 100k).
    pub max_events_per_file: usize,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            enabled: true,
            event_buffer_size: EVENT_BUFFER_THRESHOLD,
            max_file_size: MAX_FILE_SIZE_BYTES,
            max_events_per_file: MAX_EVENTS_PER_FILE,
        }
    }
}

/// A snapshot of network statistics at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Unix timestamp of this snapshot.
    pub timestamp: u64,
    /// Network statistics at this time.
    pub stats: NetworkStats,
}

/// Persisted experiment data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedData {
    /// Experiment start time (Unix timestamp).
    pub start_time: u64,
    /// Last save time (Unix timestamp).
    pub last_save_time: u64,
    /// All nodes (active and historical).
    pub nodes: Vec<PeerInfo>,
    /// All connection records.
    pub connections: Vec<ConnectionRecord>,
    /// Statistics snapshots over time.
    pub stats_snapshots: Vec<StatsSnapshot>,
    /// Aggregate NAT statistics.
    pub nat_stats: NatStats,
    /// Connection breakdown by method.
    pub connection_breakdown: ConnectionBreakdown,
    /// Total unique nodes ever seen.
    pub total_unique_nodes: usize,
    /// Peak concurrent nodes.
    pub peak_concurrent_nodes: usize,
    /// IPv4 connection count.
    pub ipv4_connections: u64,
    /// IPv6 connection count.
    pub ipv6_connections: u64,
}

/// Event log entry with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEvent {
    /// Unix timestamp.
    pub timestamp: u64,
    /// The event.
    pub event: NetworkEvent,
}

/// Tracks state for file rotation.
struct EventLogState {
    /// Current file writer.
    writer: BufWriter<File>,
    /// Current file path.
    path: PathBuf,
    /// Events written to current file.
    event_count: usize,
}

/// Persistent storage manager with buffering and rotation.
pub struct PersistentStorage {
    /// Configuration.
    config: PersistenceConfig,
    /// Current persisted data.
    data: RwLock<PersistedData>,
    /// Buffered events (not yet flushed).
    event_buffer: RwLock<Vec<TimestampedEvent>>,
    /// Event log state.
    event_log: RwLock<Option<EventLogState>>,
    /// Buffered stats snapshots.
    stats_buffer: RwLock<Vec<StatsSnapshot>>,
    /// Flag indicating if data has changed since last save.
    dirty: RwLock<bool>,
}

impl PersistentStorage {
    /// Create a new persistent storage with the given configuration.
    pub fn new(config: PersistenceConfig) -> Arc<Self> {
        let storage = Arc::new(Self {
            config: config.clone(),
            data: RwLock::new(PersistedData::default()),
            event_buffer: RwLock::new(Vec::with_capacity(EVENT_BUFFER_THRESHOLD)),
            event_log: RwLock::new(None),
            stats_buffer: RwLock::new(Vec::with_capacity(STATS_BUFFER_THRESHOLD)),
            dirty: RwLock::new(false),
        });

        if config.enabled {
            // Initialize storage directory and load existing data
            if let Err(e) = storage.initialize_sync() {
                error!("Failed to initialize persistent storage: {}", e);
            }
        }

        storage
    }

    /// Initialize storage synchronously (for constructor).
    fn initialize_sync(&self) -> Result<(), String> {
        // Create data directory if it doesn't exist
        fs::create_dir_all(&self.config.data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;

        info!(
            "Persistent storage initialized at {:?}",
            self.config.data_dir
        );

        Ok(())
    }

    /// Initialize and load existing data.
    pub async fn initialize(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Create data directory if it doesn't exist
        fs::create_dir_all(&self.config.data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;

        // Load existing data
        self.load_data().await?;

        // Open event log for appending
        self.open_event_log().await?;

        info!(
            "Persistent storage initialized at {:?}",
            self.config.data_dir
        );

        Ok(())
    }

    /// Load existing data from disk.
    async fn load_data(&self) -> Result<(), String> {
        let summary_path = self.config.data_dir.join("experiment_summary.json");

        let mut data = self.data.write().await;

        // Try to load experiment summary
        if summary_path.exists() {
            match fs::read_to_string(&summary_path) {
                Ok(content) => match serde_json::from_str::<PersistedData>(&content) {
                    Ok(loaded) => {
                        *data = loaded;
                        info!(
                            "Loaded experiment data: {} nodes, {} connections, {} snapshots",
                            data.nodes.len(),
                            data.connections.len(),
                            data.stats_snapshots.len()
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to parse experiment summary, starting fresh: {}", e);
                    }
                },
                Err(e) => {
                    warn!("Failed to read experiment summary: {}", e);
                }
            }
        }

        // Set start time if not set
        if data.start_time == 0 {
            data.start_time = current_timestamp();
        }

        Ok(())
    }

    /// Find the next rotation number for event logs.
    fn find_next_rotation(&self) -> usize {
        let mut max_rotation = 0;
        if let Ok(entries) = fs::read_dir(&self.config.data_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("events.") && name_str.ends_with(".jsonl") {
                    // Extract rotation number from events.N.jsonl
                    if let Some(num_str) = name_str
                        .strip_prefix("events.")
                        .and_then(|s| s.strip_suffix(".jsonl"))
                    {
                        if let Ok(num) = num_str.parse::<usize>() {
                            max_rotation = max_rotation.max(num);
                        }
                    }
                }
            }
        }
        max_rotation + 1
    }

    /// Open event log for appending.
    async fn open_event_log(&self) -> Result<(), String> {
        let log_path = self.config.data_dir.join("events.jsonl");

        // Check if we need to rotate on startup
        if log_path.exists() {
            let metadata = fs::metadata(&log_path).ok();
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

            if size >= self.config.max_file_size {
                // Rotate the current file
                let rotation = self.find_next_rotation();
                let rotated_path = self
                    .config
                    .data_dir
                    .join(format!("events.{}.jsonl", rotation));
                if let Err(e) = fs::rename(&log_path, &rotated_path) {
                    warn!("Failed to rotate event log: {}", e);
                } else {
                    info!("Rotated event log to {:?}", rotated_path);
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("Failed to open event log: {}", e))?;

        // Count existing events in the file
        let event_count = if log_path.exists() {
            BufReader::new(
                File::open(&log_path).unwrap_or_else(|_| File::open("/dev/null").unwrap()),
            )
            .lines()
            .count()
        } else {
            0
        };

        let state = EventLogState {
            writer: BufWriter::new(file),
            path: log_path,
            event_count,
        };

        *self.event_log.write().await = Some(state);

        debug!("Event log opened with {} existing events", event_count);
        Ok(())
    }

    /// Rotate event log if needed.
    async fn maybe_rotate_event_log(&self) -> Result<(), String> {
        let log_guard = self.event_log.write().await;

        if let Some(ref state) = *log_guard {
            let needs_rotation = state.event_count >= self.config.max_events_per_file
                || fs::metadata(&state.path)
                    .map(|m| m.len() >= self.config.max_file_size)
                    .unwrap_or(false);

            if needs_rotation {
                drop(log_guard);
                // Flush and close current file
                if let Some(ref mut state) = *self.event_log.write().await {
                    let _ = state.writer.flush();
                }
                *self.event_log.write().await = None;

                // Open new file (will rotate the old one)
                self.open_event_log().await?;
            }
        }

        Ok(())
    }

    /// Save all data to disk (only if dirty or forced).
    pub async fn save(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Flush event buffer first
        self.flush_event_buffer().await?;

        // Flush stats buffer
        self.flush_stats_buffer().await;

        let mut data = self.data.write().await;
        data.last_save_time = current_timestamp();

        // Save experiment summary (complete data)
        let summary_path = self.config.data_dir.join("experiment_summary.json");
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| format!("Failed to serialize data: {}", e))?;
        fs::write(&summary_path, content)
            .map_err(|e| format!("Failed to write experiment_summary.json: {}", e))?;

        // Save individual files for easier analysis
        let nodes_path = self.config.data_dir.join("nodes.json");
        let nodes_content = serde_json::to_string_pretty(&data.nodes)
            .map_err(|e| format!("Failed to serialize nodes: {}", e))?;
        fs::write(&nodes_path, nodes_content)
            .map_err(|e| format!("Failed to write nodes.json: {}", e))?;

        let connections_path = self.config.data_dir.join("connections.json");
        let connections_content = serde_json::to_string_pretty(&data.connections)
            .map_err(|e| format!("Failed to serialize connections: {}", e))?;
        fs::write(&connections_path, connections_content)
            .map_err(|e| format!("Failed to write connections.json: {}", e))?;

        // Save stats snapshots
        let snapshots_path = self.config.data_dir.join("stats_snapshots.json");
        let snapshots_content = serde_json::to_string_pretty(&data.stats_snapshots)
            .map_err(|e| format!("Failed to serialize snapshots: {}", e))?;
        fs::write(&snapshots_path, snapshots_content)
            .map_err(|e| format!("Failed to write stats_snapshots.json: {}", e))?;

        *self.dirty.write().await = false;

        debug!(
            "Saved {} nodes, {} connections, {} snapshots",
            data.nodes.len(),
            data.connections.len(),
            data.stats_snapshots.len()
        );

        Ok(())
    }

    /// Save only if data has changed (call this from periodic tasks).
    pub async fn save_if_dirty(&self) -> Result<(), String> {
        if *self.dirty.read().await {
            self.save().await
        } else {
            Ok(())
        }
    }

    /// Flush buffered events to disk.
    async fn flush_event_buffer(&self) -> Result<(), String> {
        let mut buffer = self.event_buffer.write().await;

        if buffer.is_empty() {
            return Ok(());
        }

        // Check for rotation before writing
        self.maybe_rotate_event_log().await?;

        if let Some(ref mut state) = *self.event_log.write().await {
            for event in buffer.drain(..) {
                if let Ok(line) = serde_json::to_string(&event) {
                    if writeln!(state.writer, "{}", line).is_ok() {
                        state.event_count += 1;
                    }
                }
            }
            let _ = state.writer.flush();
        }

        Ok(())
    }

    /// Flush buffered stats snapshots to main data.
    async fn flush_stats_buffer(&self) {
        let mut buffer = self.stats_buffer.write().await;

        if buffer.is_empty() {
            return;
        }

        let mut data = self.data.write().await;
        data.stats_snapshots.append(&mut *buffer);

        // Update peak concurrent nodes
        if let Some(max_active) = data
            .stats_snapshots
            .iter()
            .map(|s| s.stats.active_nodes)
            .max()
        {
            if max_active > data.peak_concurrent_nodes {
                data.peak_concurrent_nodes = max_active;
            }
        }
    }

    /// Log an event (buffered, auto-flushes when threshold reached).
    pub async fn log_event(&self, event: NetworkEvent) {
        if !self.config.enabled {
            return;
        }

        let timestamped = TimestampedEvent {
            timestamp: current_timestamp(),
            event,
        };

        let mut buffer = self.event_buffer.write().await;
        buffer.push(timestamped);

        // Flush if buffer is full
        if buffer.len() >= self.config.event_buffer_size {
            drop(buffer);
            if let Err(e) = self.flush_event_buffer().await {
                warn!("Failed to flush event buffer: {}", e);
            }
        }
    }

    /// Update nodes data.
    pub async fn update_nodes(&self, nodes: Vec<PeerInfo>) {
        if !self.config.enabled {
            return;
        }

        let mut data = self.data.write().await;
        data.nodes = nodes;
        data.total_unique_nodes = data.nodes.len();

        *self.dirty.write().await = true;
    }

    /// Update connections data.
    pub async fn update_connections(&self, connections: Vec<ConnectionRecord>) {
        if !self.config.enabled {
            return;
        }

        let mut data = self.data.write().await;
        data.connections = connections;

        // Update connection breakdown
        let mut breakdown = ConnectionBreakdown::default();
        let mut ipv4 = 0u64;
        let mut ipv6 = 0u64;

        for conn in &data.connections {
            match conn.method {
                crate::registry::types::ConnectionMethod::Direct => breakdown.direct += 1,
                crate::registry::types::ConnectionMethod::HolePunched => {
                    breakdown.hole_punched += 1
                }
                crate::registry::types::ConnectionMethod::Relayed => breakdown.relayed += 1,
            }
            if conn.is_ipv6 {
                ipv6 += 1;
            } else {
                ipv4 += 1;
            }
        }

        data.connection_breakdown = breakdown;
        data.ipv4_connections = ipv4;
        data.ipv6_connections = ipv6;

        *self.dirty.write().await = true;
    }

    /// Add a statistics snapshot (buffered).
    pub async fn add_stats_snapshot(&self, stats: NetworkStats) {
        if !self.config.enabled {
            return;
        }

        let snapshot = StatsSnapshot {
            timestamp: current_timestamp(),
            stats,
        };

        let mut buffer = self.stats_buffer.write().await;
        buffer.push(snapshot);

        // Flush if buffer is full
        if buffer.len() >= STATS_BUFFER_THRESHOLD {
            drop(buffer);
            self.flush_stats_buffer().await;
            *self.dirty.write().await = true;
        }
    }

    /// Update NAT statistics.
    pub async fn update_nat_stats(&self, nat_stats: NatStats) {
        if !self.config.enabled {
            return;
        }

        let mut data = self.data.write().await;
        data.nat_stats = nat_stats;

        *self.dirty.write().await = true;
    }

    /// Get persisted data for export.
    pub async fn get_data(&self) -> PersistedData {
        // Flush buffers first to get complete data
        self.flush_stats_buffer().await;
        self.data.read().await.clone()
    }

    /// Get experiment results from persisted data.
    pub async fn get_experiment_results(&self) -> ExperimentResults {
        // Flush buffers first
        self.flush_stats_buffer().await;

        let data = self.data.read().await;

        // Build geographic distribution from nodes
        let mut geographic_distribution = std::collections::HashMap::new();
        for node in &data.nodes {
            if let Some(ref cc) = node.country_code {
                *geographic_distribution.entry(cc.clone()).or_insert(0) += 1;
            }
        }

        // Filter historical nodes
        let historical_nodes: Vec<PeerInfo> = data
            .nodes
            .iter()
            .filter(|n| n.status == crate::registry::types::PeerStatus::Historical)
            .cloned()
            .collect();

        ExperimentResults {
            start_time: data.start_time,
            duration_secs: current_timestamp().saturating_sub(data.start_time),
            total_nodes_seen: data.total_unique_nodes,
            peak_concurrent_nodes: data.peak_concurrent_nodes,
            connections: data.connections.clone(),
            nat_stats: data.nat_stats.clone(),
            connection_breakdown: data.connection_breakdown.clone(),
            ipv4_connections: data.ipv4_connections,
            ipv6_connections: data.ipv6_connections,
            geographic_distribution,
            historical_nodes,
        }
    }

    /// Read all events from the event log (current and rotated files).
    pub fn read_events(&self) -> Result<Vec<TimestampedEvent>, String> {
        let mut all_events = Vec::new();

        // Read rotated files first (oldest first)
        let mut rotated_files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.config.data_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("events.")
                    && name_str.ends_with(".jsonl")
                    && name_str != "events.jsonl"
                {
                    rotated_files.push(entry.path());
                }
            }
        }
        rotated_files.sort();

        // Read rotated files
        for path in rotated_files {
            if let Ok(events) = self.read_events_from_file(&path) {
                all_events.extend(events);
            }
        }

        // Read current file
        let current_path = self.config.data_dir.join("events.jsonl");
        if current_path.exists() {
            if let Ok(events) = self.read_events_from_file(&current_path) {
                all_events.extend(events);
            }
        }

        Ok(all_events)
    }

    /// Read events from a single file.
    fn read_events_from_file(&self, path: &Path) -> Result<Vec<TimestampedEvent>, String> {
        let file =
            File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;

        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<TimestampedEvent>(&line) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.config.data_dir
    }

    /// Check if persistence is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Force flush all buffers (call before shutdown).
    pub async fn flush_all(&self) -> Result<(), String> {
        self.flush_event_buffer().await?;
        self.flush_stats_buffer().await;
        self.save().await
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_persistence_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            data_dir: temp_dir.path().to_path_buf(),
            enabled: true,
            ..Default::default()
        };

        let storage = PersistentStorage::new(config.clone());
        storage.initialize().await.unwrap();

        // Add some test data
        let nodes = vec![PeerInfo {
            peer_id: "test123".to_string(),
            addresses: vec![],
            nat_type: crate::registry::types::NatType::Unknown,
            country_code: Some("US".to_string()),
            latitude: 40.0,
            longitude: -74.0,
            last_seen: 12345,
            connection_success_rate: 0.95,
            capabilities: Default::default(),
            version: "0.14.13".to_string(),
            is_active: true,
            status: crate::registry::types::PeerStatus::Active,
            bytes_sent: 1000,
            bytes_received: 2000,
            connected_peers: 5,
            gossip_stats: None,
            full_mesh_probes: None,
        }];

        storage.update_nodes(nodes).await;
        storage.save().await.unwrap();

        // Create new storage and verify data was loaded
        let storage2 = PersistentStorage::new(config);
        storage2.initialize().await.unwrap();

        let data = storage2.get_data().await;
        assert_eq!(data.nodes.len(), 1);
        assert_eq!(data.nodes[0].peer_id, "test123");
    }

    #[tokio::test]
    async fn test_event_logging_and_buffering() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            data_dir: temp_dir.path().to_path_buf(),
            enabled: true,
            event_buffer_size: 5, // Small buffer for testing
            ..Default::default()
        };

        let storage = PersistentStorage::new(config);
        storage.initialize().await.unwrap();

        // Log events (less than buffer size)
        for i in 0..3 {
            storage
                .log_event(NetworkEvent::NodeRegistered {
                    peer_id: format!("peer{}", i),
                    country_code: Some("US".to_string()),
                    latitude: 40.0,
                    longitude: -74.0,
                })
                .await;
        }

        // Buffer should still hold events
        assert_eq!(storage.event_buffer.read().await.len(), 3);

        // Add more to trigger flush
        for i in 3..6 {
            storage
                .log_event(NetworkEvent::NodeRegistered {
                    peer_id: format!("peer{}", i),
                    country_code: Some("US".to_string()),
                    latitude: 40.0,
                    longitude: -74.0,
                })
                .await;
        }

        // Buffer should be flushed
        assert!(storage.event_buffer.read().await.len() < 5);

        // Force flush and read back
        storage.flush_all().await.unwrap();
        let events = storage.read_events().unwrap();
        assert_eq!(events.len(), 6);
    }

    #[tokio::test]
    async fn test_dirty_flag() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            data_dir: temp_dir.path().to_path_buf(),
            enabled: true,
            ..Default::default()
        };

        let storage = PersistentStorage::new(config);
        storage.initialize().await.unwrap();

        // Initially not dirty
        assert!(!*storage.dirty.read().await);

        // Update nodes makes it dirty
        storage.update_nodes(vec![]).await;
        assert!(*storage.dirty.read().await);

        // Save clears dirty flag
        storage.save().await.unwrap();
        assert!(!*storage.dirty.read().await);
    }
}
