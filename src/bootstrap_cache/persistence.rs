//! Cache persistence with file locking.

use super::entry::CachedPeer;
use crate::nat_traversal_api::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Serializable cache data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheData {
    /// Cache format version for migration
    pub version: u32,

    /// Instance ID that last wrote this cache
    pub instance_id: String,

    /// Timestamp of last write (Unix epoch seconds)
    pub timestamp: u64,

    /// Peer entries keyed by peer ID bytes
    #[serde(with = "peer_map_serde")]
    pub peers: HashMap<[u8; 32], CachedPeer>,

    /// Checksum for integrity verification
    pub checksum: u64,
}

impl CacheData {
    /// Current cache format version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create new empty cache data
    pub fn new(instance_id: String) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            instance_id,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            peers: HashMap::new(),
            checksum: 0,
        }
    }

    /// Calculate checksum of peer data
    pub fn calculate_checksum(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.version.hash(&mut hasher);
        self.peers.len().hash(&mut hasher);

        // Hash peer IDs in sorted order for determinism
        let mut ids: Vec<_> = self.peers.keys().collect();
        ids.sort();
        for id in ids {
            id.hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Update checksum before saving
    pub fn finalize(&mut self) {
        self.timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.checksum = self.calculate_checksum();
    }

    /// Verify integrity
    pub fn verify(&self) -> bool {
        self.checksum == self.calculate_checksum()
    }
}

/// File-based persistence with optional locking
pub struct CachePersistence {
    cache_file: PathBuf,
    lock_file: PathBuf,
    instance_id: String,
    enable_locking: bool,
}

impl CachePersistence {
    /// Create new persistence layer
    pub fn new(cache_dir: &Path, enable_locking: bool) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let cache_file = cache_dir.join("bootstrap_cache.json");
        let lock_file = cache_dir.join("bootstrap_cache.lock");
        let instance_id = generate_instance_id();

        Ok(Self {
            cache_file,
            lock_file,
            instance_id,
            enable_locking,
        })
    }

    /// Load cache from disk
    pub fn load(&self) -> io::Result<CacheData> {
        if !self.cache_file.exists() {
            debug!("No existing cache file, starting fresh");
            return Ok(CacheData::new(self.instance_id.clone()));
        }

        let _lock = if self.enable_locking {
            Some(self.acquire_shared_lock()?)
        } else {
            None
        };

        let data = fs::read_to_string(&self.cache_file)?;
        let cache: CacheData = serde_json::from_str(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Verify integrity
        if !cache.verify() {
            warn!("Cache checksum mismatch, data may be corrupted");
            // Return empty cache rather than corrupted data
            return Ok(CacheData::new(self.instance_id.clone()));
        }

        // Handle version migration if needed
        if cache.version < CacheData::CURRENT_VERSION {
            info!(
                "Migrating cache from version {} to {}",
                cache.version,
                CacheData::CURRENT_VERSION
            );
            // Future: add migration logic here
        }

        info!("Loaded {} peers from cache", cache.peers.len());
        Ok(cache)
    }

    /// Save cache to disk atomically
    pub fn save(&self, cache: &mut CacheData) -> io::Result<()> {
        let _lock = if self.enable_locking {
            Some(self.acquire_exclusive_lock()?)
        } else {
            None
        };

        cache.instance_id.clone_from(&self.instance_id);
        cache.finalize();

        // Write to temp file first
        let temp_file = self.cache_file.with_extension("tmp");
        let data = serde_json::to_string_pretty(cache)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        fs::write(&temp_file, data)?;

        // Atomic rename
        fs::rename(&temp_file, &self.cache_file)?;

        debug!("Saved {} peers to cache", cache.peers.len());
        Ok(())
    }

    /// Merge another cache file into current data
    #[allow(dead_code)]
    pub fn merge(&self, cache: &mut CacheData, other_path: &Path) -> io::Result<usize> {
        let other_data = fs::read_to_string(other_path)?;
        let other: CacheData = serde_json::from_str(&other_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if !other.verify() {
            warn!("Merge source has invalid checksum, skipping");
            return Ok(0);
        }

        let mut merged_count = 0;
        for (id, peer) in other.peers {
            cache
                .peers
                .entry(id)
                .and_modify(|existing| {
                    // Keep newer data
                    if peer.last_seen > existing.last_seen {
                        *existing = peer.clone();
                        merged_count += 1;
                    }
                })
                .or_insert_with(|| {
                    merged_count += 1;
                    peer
                });
        }

        info!(
            "Merged {} peers from {}",
            merged_count,
            other_path.display()
        );
        Ok(merged_count)
    }

    /// Get the cache file path
    #[allow(dead_code)]
    pub fn cache_file(&self) -> &Path {
        &self.cache_file
    }

    #[cfg(unix)]
    fn acquire_shared_lock(&self) -> io::Result<FileLock> {
        use std::os::unix::io::AsRawFd;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_file)?;

        // Try non-blocking lock first
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };

        if result != 0 {
            let err = io::Error::last_os_error();
            // If would block, try blocking lock with timeout
            if err.kind() == io::ErrorKind::WouldBlock {
                // Fall back to blocking lock
                let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else {
                return Err(err);
            }
        }

        Ok(FileLock { file })
    }

    #[cfg(unix)]
    fn acquire_exclusive_lock(&self) -> io::Result<FileLock> {
        use std::os::unix::io::AsRawFd;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_file)?;

        // Try non-blocking lock first
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };

        if result != 0 {
            let err = io::Error::last_os_error();
            // If would block, try blocking lock
            if err.kind() == io::ErrorKind::WouldBlock {
                let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else {
                return Err(err);
            }
        }

        Ok(FileLock { file })
    }

    #[cfg(not(unix))]
    fn acquire_shared_lock(&self) -> io::Result<FileLock> {
        // Windows: simplified lock (no flock equivalent without winapi)
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_file)?;
        Ok(FileLock { file })
    }

    #[cfg(not(unix))]
    fn acquire_exclusive_lock(&self) -> io::Result<FileLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_file)?;
        Ok(FileLock { file })
    }
}

/// RAII file lock
struct FileLock {
    #[allow(dead_code)]
    file: File,
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn generate_instance_id() -> String {
    format!(
        "{}_{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    )
}

/// Serde helper for HashMap with [u8; 32] keys
mod peer_map_serde {
    use super::*;
    use serde::ser::SerializeMap;

    pub fn serialize<S>(
        map: &HashMap<[u8; 32], CachedPeer>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map_ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            map_ser.serialize_entry(&hex::encode(k), v)?;
        }
        map_ser.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<[u8; 32], CachedPeer>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::MapAccess;

        struct MapVisitor;

        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = HashMap<[u8; 32], CachedPeer>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map with hex-encoded 32-byte keys")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::new();
                while let Some((key, value)) = access.next_entry::<String, CachedPeer>()? {
                    let bytes = hex::decode(&key).map_err(serde::de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(serde::de::Error::custom("key must be 32 bytes"));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    map.insert(arr, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_cache::entry::PeerSource;
    use tempfile::TempDir;

    #[test]
    fn test_cache_data_new() {
        let data = CacheData::new("test_instance".to_string());
        assert_eq!(data.version, CacheData::CURRENT_VERSION);
        assert_eq!(data.instance_id, "test_instance");
        assert!(data.peers.is_empty());
    }

    #[test]
    fn test_checksum() {
        let mut data = CacheData::new("test".to_string());
        data.finalize();

        let checksum1 = data.checksum;
        assert!(data.verify());

        // Add a peer
        let peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        data.peers.insert(peer.peer_id.0, peer);
        data.finalize();

        let checksum2 = data.checksum;
        assert_ne!(checksum1, checksum2);
        assert!(data.verify());
    }

    #[test]
    fn test_persistence_load_save() {
        let temp_dir = TempDir::new().unwrap();
        let persistence = CachePersistence::new(temp_dir.path(), false).unwrap();

        // Save some data
        let mut data = CacheData::new("test".to_string());
        let peer = CachedPeer::new(
            PeerId([42u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        data.peers.insert(peer.peer_id.0, peer);
        persistence.save(&mut data).unwrap();

        // Load and verify
        let loaded = persistence.load().unwrap();
        assert_eq!(loaded.peers.len(), 1);
        assert!(loaded.peers.contains_key(&[42u8; 32]));
    }

    #[test]
    fn test_persistence_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let persistence = CachePersistence::new(temp_dir.path(), false).unwrap();

        // Load from non-existent file
        let data = persistence.load().unwrap();
        assert!(data.peers.is_empty());
    }

    #[test]
    fn test_merge() {
        let temp_dir = TempDir::new().unwrap();
        let persistence = CachePersistence::new(temp_dir.path(), false).unwrap();

        // Create and save first cache
        let mut data1 = CacheData::new("first".to_string());
        let peer1 = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9001".parse().unwrap()],
            PeerSource::Seed,
        );
        data1.peers.insert(peer1.peer_id.0, peer1);
        persistence.save(&mut data1).unwrap();

        // Create second cache file
        let other_path = temp_dir.path().join("other_cache.json");
        let mut data2 = CacheData::new("second".to_string());
        let peer2 = CachedPeer::new(
            PeerId([2u8; 32]),
            vec!["127.0.0.1:9002".parse().unwrap()],
            PeerSource::Seed,
        );
        data2.peers.insert(peer2.peer_id.0, peer2);
        data2.finalize();
        let json = serde_json::to_string(&data2).unwrap();
        fs::write(&other_path, json).unwrap();

        // Merge
        let merged = persistence.merge(&mut data1, &other_path).unwrap();
        assert_eq!(merged, 1);
        assert_eq!(data1.peers.len(), 2);
    }
}
