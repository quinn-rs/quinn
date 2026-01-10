// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Cache persistence with file locking and optional encryption (ADR-007).
//!
//! This module provides persistence for the bootstrap cache with:
//! - Atomic file writes using rename
//! - File locking for multi-process coordination
//! - Optional encryption using ChaCha20-Poly1305 (via HostIdentity cache key)
//!
//! # Encrypted Persistence
//!
//! When a cache encryption key is provided (derived from HostIdentity), the cache
//! is encrypted at rest using ChaCha20-Poly1305. The file format is:
//!
//! ```text
//! [version: 1 byte][nonce: 12 bytes][ciphertext+tag: N bytes]
//! ```
//!
//! The ciphertext contains the JSON-serialized CacheData.

use super::entry::CachedPeer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

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
#[derive(Debug)]
pub struct CachePersistence {
    cache_file: PathBuf,
    lock_file: PathBuf,
    instance_id: String,
    enable_locking: bool,
}

impl CachePersistence {
    /// Create new persistence layer with default filename
    pub fn new(cache_dir: &Path, enable_locking: bool) -> io::Result<Self> {
        Self::new_with_filename(cache_dir, "bootstrap_cache.json", enable_locking)
    }

    /// Create new persistence layer with custom filename
    pub fn new_with_filename(
        cache_dir: &Path,
        filename: &str,
        enable_locking: bool,
    ) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let cache_file = cache_dir.join(filename);
        let lock_file = cache_dir.join(format!("{}.lock", filename));
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

// =============================================================================
// Encrypted Cache Persistence (ADR-007)
// =============================================================================

/// Encrypted file format version
const ENCRYPTED_CACHE_VERSION: u8 = 1;

/// Encrypted cache persistence using ChaCha20-Poly1305
///
/// Wraps the standard CachePersistence with at-rest encryption using
/// a key derived from the HostIdentity (see ADR-007).
pub struct EncryptedCachePersistence {
    inner: CachePersistence,
    encryption_key: [u8; 32],
}

impl EncryptedCachePersistence {
    /// Create new encrypted persistence layer
    ///
    /// # Arguments
    /// * `cache_dir` - Directory for cache files
    /// * `enable_locking` - Whether to use file locking for coordination
    /// * `encryption_key` - 32-byte key from HostIdentity::derive_cache_key()
    pub fn new(
        cache_dir: &Path,
        enable_locking: bool,
        encryption_key: [u8; 32],
    ) -> io::Result<Self> {
        let inner =
            CachePersistence::new_with_filename(cache_dir, "bootstrap_cache.enc", enable_locking)?;
        Ok(Self {
            inner,
            encryption_key,
        })
    }

    /// Load encrypted cache from disk
    pub fn load(&self) -> io::Result<CacheData> {
        if !self.inner.cache_file.exists() {
            debug!("No existing encrypted cache file, starting fresh");
            return Ok(CacheData::new(self.inner.instance_id.clone()));
        }

        let _lock = if self.inner.enable_locking {
            Some(self.inner.acquire_shared_lock()?)
        } else {
            None
        };

        let encrypted_data = fs::read(&self.inner.cache_file)?;
        let json_data = self.decrypt(&encrypted_data)?;

        let cache: CacheData = serde_json::from_slice(&json_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if !cache.verify() {
            warn!("Encrypted cache checksum mismatch, data may be corrupted");
            return Ok(CacheData::new(self.inner.instance_id.clone()));
        }

        info!("Loaded {} peers from encrypted cache", cache.peers.len());
        Ok(cache)
    }

    /// Save cache to disk with encryption
    pub fn save(&self, cache: &mut CacheData) -> io::Result<()> {
        let _lock = if self.inner.enable_locking {
            Some(self.inner.acquire_exclusive_lock()?)
        } else {
            None
        };

        cache.instance_id.clone_from(&self.inner.instance_id);
        cache.finalize();

        let json_data =
            serde_json::to_vec(cache).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let encrypted_data = self.encrypt(&json_data)?;

        // Write atomically
        let temp_file = self.inner.cache_file.with_extension("tmp");
        fs::write(&temp_file, &encrypted_data)?;
        fs::rename(&temp_file, &self.inner.cache_file)?;

        debug!("Saved {} peers to encrypted cache", cache.peers.len());
        Ok(())
    }

    /// Check if encrypted cache file exists
    pub fn exists(&self) -> bool {
        self.inner.cache_file.exists()
    }

    /// Encrypt data using ChaCha20-Poly1305
    fn encrypt(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::{
            self, Aad, BoundKey, CHACHA20_POLY1305, Nonce, NonceSequence, UnboundKey,
        };

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce_bytes)
            .map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;

        // Create sealing key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.encryption_key)
            .map_err(|e| io::Error::other(format!("Key creation failed: {e}")))?;

        struct SingleNonce(Option<[u8; 12]>);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
                self.0
                    .take()
                    .map(Nonce::assume_unique_for_key)
                    .ok_or(aws_lc_rs::error::Unspecified)
            }
        }

        let mut sealing_key = aead::SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        // Encrypt in-place
        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|e| io::Error::other(format!("Encryption failed: {e}")))?;

        // Build output: version || nonce || ciphertext+tag
        let mut result = Vec::with_capacity(1 + 12 + in_out.len());
        result.push(ENCRYPTED_CACHE_VERSION);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    fn decrypt(&self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        use aws_lc_rs::aead::{
            self, Aad, BoundKey, CHACHA20_POLY1305, Nonce, NonceSequence, UnboundKey,
        };

        if ciphertext.len() < 1 + 12 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ciphertext too short",
            ));
        }

        let version = ciphertext[0];
        if version != ENCRYPTED_CACHE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported encrypted cache version: {version}"),
            ));
        }

        let nonce_bytes: [u8; 12] = ciphertext[1..13]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid nonce"))?;

        // Create opening key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.encryption_key)
            .map_err(|e| io::Error::other(format!("Key creation failed: {e}")))?;

        struct SingleNonce(Option<[u8; 12]>);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
                self.0
                    .take()
                    .map(Nonce::assume_unique_for_key)
                    .ok_or(aws_lc_rs::error::Unspecified)
            }
        }

        let mut opening_key = aead::OpeningKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        // Decrypt in-place
        let mut in_out = ciphertext[13..].to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Decryption failed - wrong key or corrupted",
                )
            })?;

        Ok(plaintext.to_vec())
    }
}

impl Drop for EncryptedCachePersistence {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
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
    use crate::PeerId;
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

    // =========================================================================
    // Encrypted Persistence Tests
    // =========================================================================

    #[test]
    fn test_encrypted_persistence_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let key = [0x42u8; 32];
        let persistence = EncryptedCachePersistence::new(temp_dir.path(), false, key).unwrap();

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
    fn test_encrypted_persistence_wrong_key() {
        let temp_dir = TempDir::new().unwrap();
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        // Save with key1
        let persistence1 = EncryptedCachePersistence::new(temp_dir.path(), false, key1).unwrap();
        let mut data = CacheData::new("test".to_string());
        let peer = CachedPeer::new(
            PeerId([1u8; 32]),
            vec!["127.0.0.1:9000".parse().unwrap()],
            PeerSource::Seed,
        );
        data.peers.insert(peer.peer_id.0, peer);
        persistence1.save(&mut data).unwrap();

        // Try to load with key2 - should fail
        let persistence2 = EncryptedCachePersistence::new(temp_dir.path(), false, key2).unwrap();
        let result = persistence2.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_persistence_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let key = [0x42u8; 32];
        let persistence = EncryptedCachePersistence::new(temp_dir.path(), false, key).unwrap();

        // Load from non-existent file - should return empty cache
        let data = persistence.load().unwrap();
        assert!(data.peers.is_empty());
    }

    #[test]
    fn test_encrypted_persistence_exists() {
        let temp_dir = TempDir::new().unwrap();
        let key = [0x42u8; 32];
        let persistence = EncryptedCachePersistence::new(temp_dir.path(), false, key).unwrap();

        assert!(!persistence.exists());

        let mut data = CacheData::new("test".to_string());
        persistence.save(&mut data).unwrap();

        assert!(persistence.exists());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let key = [0xAB; 32];
        let persistence = EncryptedCachePersistence::new(temp_dir.path(), false, key).unwrap();

        let plaintext = b"Hello, encrypted cache!";
        let ciphertext = persistence.encrypt(plaintext).unwrap();

        // Ciphertext should be larger (version + nonce + tag)
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = persistence.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
