//! Persistent storage for experiment data.
//!
//! This module provides JSON-based persistence for all experiment data,
//! ensuring that historical records are preserved across registry restarts.
//!
//! # Data Files
//!
//! - `nodes.json` - All node registrations (active and historical)
//! - `connections.json` - All connection records
//! - `events.jsonl` - Append-only event log (JSON Lines format)
//! - `stats_snapshots.json` - Periodic network statistics snapshots
//! - `experiment_summary.json` - Current experiment summary

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

/// Interval between automatic saves (in seconds).
const AUTO_SAVE_INTERVAL_SECS: u64 = 60;

/// Interval between statistics snapshots (in seconds).
const STATS_SNAPSHOT_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Persistent data store configuration.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Directory to store data files.
    pub data_dir: PathBuf,
    /// Whether to enable persistence.
    pub enabled: bool,
    /// Auto-save interval in seconds.
    pub save_interval_secs: u64,
    /// Stats snapshot interval in seconds.
    pub snapshot_interval_secs: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            enabled: true,
            save_interval_secs: AUTO_SAVE_INTERVAL_SECS,
            snapshot_interval_secs: STATS_SNAPSHOT_INTERVAL_SECS,
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

/// Persistent storage manager.
pub struct PersistentStorage {
    /// Configuration.
    config: PersistenceConfig,
    /// Current persisted data.
    data: RwLock<PersistedData>,
    /// Event log file handle.
    event_log: RwLock<Option<BufWriter<File>>>,
}

impl PersistentStorage {
    /// Create a new persistent storage with the given configuration.
    pub fn new(config: PersistenceConfig) -> Arc<Self> {
        let storage = Arc::new(Self {
            config: config.clone(),
            data: RwLock::new(PersistedData::default()),
            event_log: RwLock::new(None),
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
        let nodes_path = self.config.data_dir.join("nodes.json");
        let connections_path = self.config.data_dir.join("connections.json");
        let snapshots_path = self.config.data_dir.join("stats_snapshots.json");
        let summary_path = self.config.data_dir.join("experiment_summary.json");

        let mut data = self.data.write().await;

        // Try to load experiment summary first
        if summary_path.exists() {
            match fs::read_to_string(&summary_path) {
                Ok(content) => match serde_json::from_str::<PersistedData>(&content) {
                    Ok(loaded) => {
                        *data = loaded;
                        info!(
                            "Loaded experiment data: {} nodes, {} connections",
                            data.nodes.len(),
                            data.connections.len()
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

        // Load individual files if summary doesn't exist
        if nodes_path.exists() {
            match fs::read_to_string(&nodes_path) {
                Ok(content) => match serde_json::from_str::<Vec<PeerInfo>>(&content) {
                    Ok(nodes) => {
                        data.nodes = nodes;
                        info!("Loaded {} nodes from disk", data.nodes.len());
                    }
                    Err(e) => warn!("Failed to parse nodes.json: {}", e),
                },
                Err(e) => warn!("Failed to read nodes.json: {}", e),
            }
        }

        if connections_path.exists() {
            match fs::read_to_string(&connections_path) {
                Ok(content) => match serde_json::from_str::<Vec<ConnectionRecord>>(&content) {
                    Ok(connections) => {
                        data.connections = connections;
                        info!("Loaded {} connections from disk", data.connections.len());
                    }
                    Err(e) => warn!("Failed to parse connections.json: {}", e),
                },
                Err(e) => warn!("Failed to read connections.json: {}", e),
            }
        }

        if snapshots_path.exists() {
            match fs::read_to_string(&snapshots_path) {
                Ok(content) => match serde_json::from_str::<Vec<StatsSnapshot>>(&content) {
                    Ok(snapshots) => {
                        data.stats_snapshots = snapshots;
                        info!(
                            "Loaded {} stats snapshots from disk",
                            data.stats_snapshots.len()
                        );
                    }
                    Err(e) => warn!("Failed to parse stats_snapshots.json: {}", e),
                },
                Err(e) => warn!("Failed to read stats_snapshots.json: {}", e),
            }
        }

        // Set start time if not set
        if data.start_time == 0 {
            data.start_time = current_timestamp();
        }

        Ok(())
    }

    /// Open event log for appending.
    async fn open_event_log(&self) -> Result<(), String> {
        let log_path = self.config.data_dir.join("events.jsonl");

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("Failed to open event log: {}", e))?;

        let writer = BufWriter::new(file);
        *self.event_log.write().await = Some(writer);

        debug!("Event log opened at {:?}", log_path);
        Ok(())
    }

    /// Save all data to disk.
    pub async fn save(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        data.last_save_time = current_timestamp();

        // Save experiment summary (complete data)
        let summary_path = self.config.data_dir.join("experiment_summary.json");
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| format!("Failed to serialize data: {}", e))?;
        fs::write(&summary_path, content)
            .map_err(|e| format!("Failed to write experiment_summary.json: {}", e))?;

        // Also save individual files for easier access
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

        let snapshots_path = self.config.data_dir.join("stats_snapshots.json");
        let snapshots_content = serde_json::to_string_pretty(&data.stats_snapshots)
            .map_err(|e| format!("Failed to serialize snapshots: {}", e))?;
        fs::write(&snapshots_path, snapshots_content)
            .map_err(|e| format!("Failed to write stats_snapshots.json: {}", e))?;

        // Flush event log
        if let Some(ref mut writer) = *self.event_log.write().await {
            let _ = writer.flush();
        }

        debug!(
            "Saved {} nodes, {} connections, {} snapshots",
            data.nodes.len(),
            data.connections.len(),
            data.stats_snapshots.len()
        );

        Ok(())
    }

    /// Log an event to the append-only event log.
    pub async fn log_event(&self, event: NetworkEvent) {
        if !self.config.enabled {
            return;
        }

        let timestamped = TimestampedEvent {
            timestamp: current_timestamp(),
            event,
        };

        if let Some(ref mut writer) = *self.event_log.write().await {
            if let Ok(line) = serde_json::to_string(&timestamped) {
                let _ = writeln!(writer, "{}", line);
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
    }

    /// Add a statistics snapshot.
    pub async fn add_stats_snapshot(&self, stats: NetworkStats) {
        if !self.config.enabled {
            return;
        }

        let snapshot = StatsSnapshot {
            timestamp: current_timestamp(),
            stats,
        };

        let mut data = self.data.write().await;
        data.stats_snapshots.push(snapshot);

        // Update peak if needed
        if data
            .stats_snapshots
            .last()
            .map(|s| s.stats.active_nodes)
            .unwrap_or(0)
            > data.peak_concurrent_nodes
        {
            data.peak_concurrent_nodes = data
                .stats_snapshots
                .last()
                .map(|s| s.stats.active_nodes)
                .unwrap_or(0);
        }
    }

    /// Update NAT statistics.
    pub async fn update_nat_stats(&self, nat_stats: NatStats) {
        if !self.config.enabled {
            return;
        }

        let mut data = self.data.write().await;
        data.nat_stats = nat_stats;
    }

    /// Get persisted data for export.
    pub async fn get_data(&self) -> PersistedData {
        self.data.read().await.clone()
    }

    /// Get experiment results from persisted data.
    pub async fn get_experiment_results(&self) -> ExperimentResults {
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

    /// Read all events from the event log.
    pub fn read_events(&self) -> Result<Vec<TimestampedEvent>, String> {
        let log_path = self.config.data_dir.join("events.jsonl");

        if !log_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&log_path).map_err(|e| format!("Failed to open event log: {}", e))?;

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
            save_interval_secs: 60,
            snapshot_interval_secs: 300,
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
            version: "0.14.12".to_string(),
            is_active: true,
            status: crate::registry::types::PeerStatus::Active,
            bytes_sent: 1000,
            bytes_received: 2000,
            connected_peers: 5,
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
    async fn test_event_logging() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            data_dir: temp_dir.path().to_path_buf(),
            enabled: true,
            save_interval_secs: 60,
            snapshot_interval_secs: 300,
        };

        let storage = PersistentStorage::new(config);
        storage.initialize().await.unwrap();

        // Log some events
        storage
            .log_event(NetworkEvent::NodeRegistered {
                peer_id: "peer1".to_string(),
                country_code: Some("US".to_string()),
                latitude: 40.0,
                longitude: -74.0,
            })
            .await;

        storage.save().await.unwrap();

        // Read events back
        let events = storage.read_events().unwrap();
        assert_eq!(events.len(), 1);
    }
}
