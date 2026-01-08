//! Storage implementation for history persistence.
//!
//! Handles reading/writing JSON files and managing the rolling window.

use super::{GossipResults, HistoryConfig, HistoryFile, PeerConnectivity};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

/// A single connectivity test entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// When this test was performed.
    pub timestamp: DateTime<Utc>,
    /// Peer ID that was tested.
    pub peer_id: String,
    /// Connectivity results for this peer.
    pub connectivity: PeerConnectivity,
    /// Whether any connection method succeeded.
    pub overall_success: bool,
}

impl HistoryEntry {
    /// Create a new history entry.
    pub fn new(peer_id: &str, connectivity: PeerConnectivity) -> Self {
        let overall_success = connectivity.any_success();
        Self {
            timestamp: Utc::now(),
            peer_id: peer_id.to_string(),
            connectivity,
            overall_success,
        }
    }
}

/// Low-level storage operations for history files.
pub struct HistoryStorage {
    base_dir: PathBuf,
}

impl HistoryStorage {
    /// Create a new storage instance.
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Ensure the base directory exists.
    pub fn ensure_dir(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.base_dir)
    }

    /// Get the path for a history file.
    pub fn file_path(&self, hour: &str) -> PathBuf {
        self.base_dir.join(format!("history-{}.json", hour))
    }

    /// List all history files in the directory.
    pub fn list_files(&self) -> std::io::Result<Vec<String>> {
        let mut hours = Vec::new();

        if !self.base_dir.exists() {
            return Ok(hours);
        }

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("history-") && name.ends_with(".json") {
                    // Extract the hour part: history-YYYY-MM-DD-HH.json -> YYYY-MM-DD-HH
                    let hour = name
                        .strip_prefix("history-")
                        .and_then(|s| s.strip_suffix(".json"));

                    if let Some(h) = hour {
                        hours.push(h.to_string());
                    }
                }
            }
        }

        hours.sort();
        Ok(hours)
    }

    /// Load a history file.
    pub fn load(&self, hour: &str) -> std::io::Result<HistoryFile> {
        let path = self.file_path(hour);
        let file = fs::File::open(&path)?;
        let reader = BufReader::new(file);
        let history: HistoryFile =
            serde_json::from_reader(reader).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(history)
    }

    /// Save a history file.
    pub fn save(&self, history: &HistoryFile) -> std::io::Result<()> {
        self.ensure_dir()?;
        let path = self.file_path(&history.hour);
        let file = fs::File::create(&path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, history)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }

    /// Delete a history file.
    pub fn delete(&self, hour: &str) -> std::io::Result<()> {
        let path = self.file_path(hour);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// High-level manager for history with rolling window.
pub struct HistoryManager {
    config: HistoryConfig,
    storage: HistoryStorage,
    node_id: String,
    /// Current hour's history file (cached).
    current_file: Option<HistoryFile>,
    /// All loaded history entries (for quick access).
    entries: Vec<HistoryEntry>,
    /// Most recent gossip results.
    gossip_results: Option<GossipResults>,
    /// Whether there are unsaved changes.
    dirty: bool,
}

impl HistoryManager {
    /// Create a new history manager.
    pub fn new(config: HistoryConfig, node_id: &str) -> Self {
        let storage = HistoryStorage::new(config.base_dir.clone());
        Self {
            config,
            storage,
            node_id: node_id.to_string(),
            current_file: None,
            entries: Vec::new(),
            gossip_results: None,
            dirty: false,
        }
    }

    /// Initialize and load history from disk.
    pub fn init(&mut self) -> std::io::Result<()> {
        // Ensure directory exists
        self.storage.ensure_dir()?;

        // Load all recent files
        self.load_recent()?;

        // Prune old files
        self.prune_old()?;

        // Create or load current hour's file
        let current_hour = Utc::now().format("%Y-%m-%d-%H").to_string();
        match self.storage.load(&current_hour) {
            Ok(file) => {
                self.current_file = Some(file);
            }
            Err(_) => {
                // Create new file for current hour
                let file = HistoryFile::new(&self.node_id);
                self.current_file = Some(file);
                self.dirty = true;
            }
        }

        info!(
            "History initialized: {} entries loaded, {} files in rolling window",
            self.entries.len(),
            self.storage.list_files().unwrap_or_default().len()
        );

        Ok(())
    }

    /// Load all files within the retention window.
    fn load_recent(&mut self) -> std::io::Result<()> {
        let cutoff = Utc::now() - Duration::hours(self.config.retention_hours as i64);
        let files = self.storage.list_files()?;

        for hour in files {
            // Parse the hour string to check if it's within retention
            if let Ok(file_time) = chrono::NaiveDateTime::parse_from_str(
                &format!("{}-00-00", hour),
                "%Y-%m-%d-%H-%M-%S",
            ) {
                let file_utc = DateTime::<Utc>::from_naive_utc_and_offset(file_time, Utc);
                if file_utc >= cutoff {
                    match self.storage.load(&hour) {
                        Ok(history) => {
                            for entry in history.entries {
                                self.entries.push(entry);
                            }
                            // Keep the most recent gossip results
                            if history.gossip_results.is_some() {
                                self.gossip_results = history.gossip_results;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to load history file {}: {}", hour, e);
                        }
                    }
                }
            }
        }

        // Sort entries by timestamp
        self.entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(())
    }

    /// Remove files older than the retention window.
    fn prune_old(&self) -> std::io::Result<()> {
        let cutoff = Utc::now() - Duration::hours(self.config.retention_hours as i64);
        let files = self.storage.list_files()?;

        for hour in files {
            if let Ok(file_time) = chrono::NaiveDateTime::parse_from_str(
                &format!("{}-00-00", hour),
                "%Y-%m-%d-%H-%M-%S",
            ) {
                let file_utc = DateTime::<Utc>::from_naive_utc_and_offset(file_time, Utc);
                if file_utc < cutoff {
                    debug!("Pruning old history file: {}", hour);
                    if let Err(e) = self.storage.delete(&hour) {
                        warn!("Failed to delete old history file {}: {}", hour, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a connectivity test entry.
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        let current_hour = Utc::now().format("%Y-%m-%d-%H").to_string();

        // Check if we need to roll to a new hour
        if let Some(ref mut file) = self.current_file {
            if file.hour != current_hour {
                // Save current file before rolling
                if self.dirty {
                    if let Err(e) = self.storage.save(file) {
                        error!("Failed to save history before roll: {}", e);
                    }
                }
                // Create new file
                let mut new_file = HistoryFile::new(&self.node_id);
                new_file.gossip_results = self.gossip_results.clone();
                self.current_file = Some(new_file);
            }
        } else {
            let mut new_file = HistoryFile::new(&self.node_id);
            new_file.gossip_results = self.gossip_results.clone();
            self.current_file = Some(new_file);
        }

        // Add to current file and entries list
        if let Some(ref mut file) = self.current_file {
            file.entries.push(entry.clone());
        }
        self.entries.push(entry);

        self.dirty = true;

        // Auto-save if configured
        if self.config.auto_save {
            if let Err(e) = self.save() {
                error!("Failed to auto-save history: {}", e);
            }
        }
    }

    /// Update gossip results.
    pub fn update_gossip(&mut self, results: GossipResults) {
        self.gossip_results = Some(results.clone());

        if let Some(ref mut file) = self.current_file {
            file.gossip_results = Some(results);
        }

        self.dirty = true;

        if self.config.auto_save {
            if let Err(e) = self.save() {
                error!("Failed to auto-save gossip results: {}", e);
            }
        }
    }

    /// Save current file to disk.
    pub fn save(&mut self) -> std::io::Result<()> {
        if let Some(ref file) = self.current_file {
            self.storage.save(file)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Get all entries.
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// Get entries count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get success rate across all entries.
    pub fn success_rate(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let successes = self.entries.iter().filter(|e| e.overall_success).count();
        (successes as f64 / self.entries.len() as f64) * 100.0
    }

    /// Get unique peers tested.
    pub fn unique_peers(&self) -> usize {
        let mut peers: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for entry in &self.entries {
            peers.insert(&entry.peer_id);
        }
        peers.len()
    }

    /// Get gossip results.
    pub fn gossip_results(&self) -> Option<&GossipResults> {
        self.gossip_results.as_ref()
    }

    /// Get summary statistics.
    pub fn summary(&self) -> HistorySummary {
        HistorySummary {
            total_entries: self.entries.len(),
            unique_peers: self.unique_peers(),
            success_rate: self.success_rate(),
            gossip_passed: self
                .gossip_results
                .as_ref()
                .map(|r| r.passed_count())
                .unwrap_or(0),
            gossip_total: 9,
            oldest_entry: self.entries.first().map(|e| e.timestamp),
            newest_entry: self.entries.last().map(|e| e.timestamp),
        }
    }
}

/// Summary of history data.
#[derive(Debug, Clone)]
pub struct HistorySummary {
    pub total_entries: usize,
    pub unique_peers: usize,
    pub success_rate: f64,
    pub gossip_passed: usize,
    pub gossip_total: usize,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_history_entry_creation() {
        let connectivity = PeerConnectivity::default();
        let entry = HistoryEntry::new("peer123", connectivity);

        assert_eq!(entry.peer_id, "peer123");
        assert!(!entry.overall_success);
    }

    #[test]
    fn test_history_storage_operations() {
        let dir = tempdir().unwrap();
        let storage = HistoryStorage::new(dir.path().to_path_buf());

        // Ensure directory
        storage.ensure_dir().unwrap();
        assert!(dir.path().exists());

        // Create and save a file
        let mut file = HistoryFile::new("test_node");
        file.entries
            .push(HistoryEntry::new("peer1", PeerConnectivity::default()));

        storage.save(&file).unwrap();

        // List files
        let files = storage.list_files().unwrap();
        assert_eq!(files.len(), 1);

        // Load file
        let loaded = storage.load(&file.hour).unwrap();
        assert_eq!(loaded.node_id, "test_node");
        assert_eq!(loaded.entries.len(), 1);

        // Delete file
        storage.delete(&file.hour).unwrap();
        let files = storage.list_files().unwrap();
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn test_history_manager_init() {
        let dir = tempdir().unwrap();
        let config = HistoryConfig {
            base_dir: dir.path().to_path_buf(),
            retention_hours: 24,
            auto_save: false,
        };

        let mut manager = HistoryManager::new(config, "test_node");
        manager.init().unwrap();

        assert_eq!(manager.entry_count(), 0);
        assert_eq!(manager.success_rate(), 0.0);
    }

    #[test]
    fn test_history_manager_add_entry() {
        let dir = tempdir().unwrap();
        let config = HistoryConfig {
            base_dir: dir.path().to_path_buf(),
            retention_hours: 24,
            auto_save: false,
        };

        let mut manager = HistoryManager::new(config, "test_node");
        manager.init().unwrap();

        // Add entry with success
        let connectivity = PeerConnectivity {
            ipv4_direct: super::super::ConnectivityStatus::Success { rtt_ms: 50 },
            ..Default::default()
        };

        manager.add_entry(HistoryEntry::new("peer1", connectivity));

        assert_eq!(manager.entry_count(), 1);
        assert_eq!(manager.success_rate(), 100.0);
        assert_eq!(manager.unique_peers(), 1);

        // Add failed entry
        manager.add_entry(HistoryEntry::new("peer2", PeerConnectivity::default()));

        assert_eq!(manager.entry_count(), 2);
        assert_eq!(manager.success_rate(), 50.0);
        assert_eq!(manager.unique_peers(), 2);
    }

    #[test]
    fn test_history_summary() {
        let dir = tempdir().unwrap();
        let config = HistoryConfig {
            base_dir: dir.path().to_path_buf(),
            retention_hours: 24,
            auto_save: false,
        };

        let mut manager = HistoryManager::new(config, "test_node");
        manager.init().unwrap();

        let summary = manager.summary();
        assert_eq!(summary.total_entries, 0);
        assert_eq!(summary.unique_peers, 0);
        assert_eq!(summary.gossip_passed, 0);
        assert_eq!(summary.gossip_total, 9);
    }
}
