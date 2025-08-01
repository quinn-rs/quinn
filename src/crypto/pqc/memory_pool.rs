//! Memory pool for efficient PQC object allocation
//!
//! Post-quantum cryptographic operations require significantly larger buffers
//! than classical cryptography. This module provides a thread-safe memory pool
//! to reduce allocation overhead and improve performance.
//!
//! # Example
//!
//! ```
//! use ant_quic::crypto::pqc::memory_pool::{PqcMemoryPool, PoolConfig};
//!
//! let pool = PqcMemoryPool::new(PoolConfig::default());
//!
//! // Acquire a buffer for ML-KEM public key
//! let guard = pool.acquire_ml_kem_public_key().unwrap();
//! // Buffer is automatically returned to pool when guard is dropped
//! ```

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto::pqc::types::*;

/// Configuration for memory pool behavior
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Initial number of objects to pre-allocate
    pub initial_size: usize,
    /// Maximum number of objects the pool can hold
    pub max_size: usize,
    /// Number of objects to allocate when pool is empty
    pub growth_increment: usize,
    /// Timeout when acquiring objects from pool
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            initial_size: 4,
            max_size: 100,
            growth_increment: 4,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

/// Statistics for pool monitoring
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total allocations from pool
    pub allocations: AtomicU64,
    /// Total deallocations to pool
    pub deallocations: AtomicU64,
    /// Cache hits (object available in pool)
    pub hits: AtomicU64,
    /// Cache misses (had to allocate new object)
    pub misses: AtomicU64,
    /// Current pool size
    pub current_size: AtomicUsize,
}

impl PoolStats {
    /// Get hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let total = hits + self.misses.load(Ordering::Relaxed) as f64;
        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }
}

/// Buffer types for pooling
#[derive(Clone)]
pub struct MlKemPublicKeyBuffer(pub Box<[u8; ML_KEM_768_PUBLIC_KEY_SIZE]>);

#[derive(Clone)]
pub struct MlKemSecretKeyBuffer(pub Box<[u8; ML_KEM_768_SECRET_KEY_SIZE]>);

#[derive(Clone)]
pub struct MlKemCiphertextBuffer(pub Box<[u8; ML_KEM_768_CIPHERTEXT_SIZE]>);

#[derive(Clone)]
pub struct MlDsaPublicKeyBuffer(pub Box<[u8; ML_DSA_65_PUBLIC_KEY_SIZE]>);

#[derive(Clone)]
pub struct MlDsaSecretKeyBuffer(pub Box<[u8; ML_DSA_65_SECRET_KEY_SIZE]>);

#[derive(Clone)]
pub struct MlDsaSignatureBuffer(pub Box<[u8; ML_DSA_65_SIGNATURE_SIZE]>);

/// Trait for buffer cleanup before returning to pool
pub trait BufferCleanup {
    fn cleanup(&mut self);
}

// Default implementation for non-sensitive buffers
impl BufferCleanup for MlKemPublicKeyBuffer {
    fn cleanup(&mut self) {}
}

impl BufferCleanup for MlKemCiphertextBuffer {
    fn cleanup(&mut self) {}
}

impl BufferCleanup for MlDsaPublicKeyBuffer {
    fn cleanup(&mut self) {}
}

impl BufferCleanup for MlDsaSignatureBuffer {
    fn cleanup(&mut self) {}
}

// Secret keys need zeroization
impl BufferCleanup for MlKemSecretKeyBuffer {
    fn cleanup(&mut self) {
        self.0.fill(0);
    }
}

impl BufferCleanup for MlDsaSecretKeyBuffer {
    fn cleanup(&mut self) {
        self.0.fill(0);
    }
}

/// Generic object pool implementation
struct ObjectPool<T: BufferCleanup> {
    available: Arc<Mutex<Vec<T>>>,
    config: PoolConfig,
    stats: Arc<PoolStats>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T: BufferCleanup> ObjectPool<T> {
    fn new<F>(config: PoolConfig, stats: Arc<PoolStats>, factory: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let mut available = Vec::with_capacity(config.initial_size);

        // Pre-allocate initial objects
        for _ in 0..config.initial_size {
            available.push(factory());
        }

        stats
            .current_size
            .store(config.initial_size, Ordering::Relaxed);

        Self {
            available: Arc::new(Mutex::new(available)),
            config,
            stats,
            factory: Box::new(factory),
        }
    }

    fn acquire(&self) -> Result<PoolGuard<T>, PqcError> {
        let mut available = self
            .available
            .lock()
            .map_err(|_| PqcError::PoolError("Failed to lock pool".to_string()))?;

        self.stats.allocations.fetch_add(1, Ordering::Relaxed);

        let object = if let Some(obj) = available.pop() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            obj
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);

            // Check if we can grow the pool
            let current_size = self.stats.current_size.load(Ordering::Relaxed);
            if current_size >= self.config.max_size {
                return Err(PqcError::PoolError("Pool at maximum capacity".to_string()));
            }

            // Allocate new object
            self.stats.current_size.fetch_add(1, Ordering::Relaxed);
            (self.factory)()
        };

        Ok(PoolGuard {
            object: Some(object),
            pool: self.available.clone(),
            stats: self.stats.clone(),
        })
    }

    fn available_count(&self) -> usize {
        self.available.lock().map(|guard| guard.len()).unwrap_or(0)
    }
}

/// RAII guard for pooled objects
pub struct PoolGuard<T: BufferCleanup> {
    object: Option<T>,
    pool: Arc<Mutex<Vec<T>>>,
    stats: Arc<PoolStats>,
}

impl<T: BufferCleanup> PoolGuard<T> {
    /// Get a reference to the pooled object
    pub fn as_ref(&self) -> &T {
        // SAFETY: PoolGuard is constructed with Some(object) and only consumed on drop
        // The object is guaranteed to exist until drop
        self.object
            .as_ref()
            .expect("PoolGuard object must exist until drop")
    }

    /// Get a mutable reference to the pooled object
    pub fn as_mut(&mut self) -> &mut T {
        // SAFETY: PoolGuard is constructed with Some(object) and only consumed on drop
        // The object is guaranteed to exist until drop
        self.object
            .as_mut()
            .expect("PoolGuard object must exist until drop")
    }
}

impl<T: BufferCleanup> Drop for PoolGuard<T> {
    fn drop(&mut self) {
        if let Some(mut object) = self.object.take() {
            // Clean up the buffer before returning to pool
            object.cleanup();

            self.stats.deallocations.fetch_add(1, Ordering::Relaxed);

            // Return object to pool
            if let Ok(mut available) = self.pool.lock() {
                available.push(object);
            }
        }
    }
}

// Implement zeroization for sensitive buffers
impl Drop for MlKemSecretKeyBuffer {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

impl Drop for MlDsaSecretKeyBuffer {
    fn drop(&mut self) {
        self.0.as_mut().fill(0);
    }
}

/// Main PQC memory pool
pub struct PqcMemoryPool {
    ml_kem_public_keys: ObjectPool<MlKemPublicKeyBuffer>,
    ml_kem_secret_keys: ObjectPool<MlKemSecretKeyBuffer>,
    ml_kem_ciphertexts: ObjectPool<MlKemCiphertextBuffer>,
    ml_dsa_public_keys: ObjectPool<MlDsaPublicKeyBuffer>,
    ml_dsa_secret_keys: ObjectPool<MlDsaSecretKeyBuffer>,
    ml_dsa_signatures: ObjectPool<MlDsaSignatureBuffer>,
    stats: Arc<PoolStats>,
}

impl PqcMemoryPool {
    /// Create a new PQC memory pool with the given configuration
    pub fn new(config: PoolConfig) -> Self {
        let stats = Arc::new(PoolStats::default());

        Self {
            ml_kem_public_keys: ObjectPool::new(config.clone(), stats.clone(), || {
                MlKemPublicKeyBuffer(Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]))
            }),
            ml_kem_secret_keys: ObjectPool::new(config.clone(), stats.clone(), || {
                MlKemSecretKeyBuffer(Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]))
            }),
            ml_kem_ciphertexts: ObjectPool::new(config.clone(), stats.clone(), || {
                MlKemCiphertextBuffer(Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]))
            }),
            ml_dsa_public_keys: ObjectPool::new(config.clone(), stats.clone(), || {
                MlDsaPublicKeyBuffer(Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]))
            }),
            ml_dsa_secret_keys: ObjectPool::new(config.clone(), stats.clone(), || {
                MlDsaSecretKeyBuffer(Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]))
            }),
            ml_dsa_signatures: ObjectPool::new(config, stats.clone(), || {
                MlDsaSignatureBuffer(Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]))
            }),
            stats,
        }
    }

    /// Acquire a buffer for ML-KEM public key
    pub fn acquire_ml_kem_public_key(&self) -> Result<PoolGuard<MlKemPublicKeyBuffer>, PqcError> {
        self.ml_kem_public_keys.acquire()
    }

    /// Acquire a buffer for ML-KEM secret key
    pub fn acquire_ml_kem_secret_key(&self) -> Result<PoolGuard<MlKemSecretKeyBuffer>, PqcError> {
        self.ml_kem_secret_keys.acquire()
    }

    /// Acquire a buffer for ML-KEM ciphertext
    pub fn acquire_ml_kem_ciphertext(&self) -> Result<PoolGuard<MlKemCiphertextBuffer>, PqcError> {
        self.ml_kem_ciphertexts.acquire()
    }

    /// Acquire a buffer for ML-DSA public key
    pub fn acquire_ml_dsa_public_key(&self) -> Result<PoolGuard<MlDsaPublicKeyBuffer>, PqcError> {
        self.ml_dsa_public_keys.acquire()
    }

    /// Acquire a buffer for ML-DSA secret key
    pub fn acquire_ml_dsa_secret_key(&self) -> Result<PoolGuard<MlDsaSecretKeyBuffer>, PqcError> {
        self.ml_dsa_secret_keys.acquire()
    }

    /// Acquire a buffer for ML-DSA signature
    pub fn acquire_ml_dsa_signature(&self) -> Result<PoolGuard<MlDsaSignatureBuffer>, PqcError> {
        self.ml_dsa_signatures.acquire()
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Get available count for ML-KEM public keys (for testing)
    #[cfg(test)]
    pub fn available_count(&self) -> usize {
        self.ml_kem_public_keys.available_count()
    }
}

impl fmt::Debug for PqcMemoryPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcMemoryPool")
            .field(
                "ml_kem_public_keys",
                &self.ml_kem_public_keys.available_count(),
            )
            .field(
                "ml_kem_secret_keys",
                &self.ml_kem_secret_keys.available_count(),
            )
            .field(
                "ml_kem_ciphertexts",
                &self.ml_kem_ciphertexts.available_count(),
            )
            .field(
                "ml_dsa_public_keys",
                &self.ml_dsa_public_keys.available_count(),
            )
            .field(
                "ml_dsa_secret_keys",
                &self.ml_dsa_secret_keys.available_count(),
            )
            .field(
                "ml_dsa_signatures",
                &self.ml_dsa_signatures.available_count(),
            )
            .field("hit_rate", &format!("{:.1}%", self.stats.hit_rate()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_pool_reuses_objects() {
        let pool = PqcMemoryPool::new(PoolConfig::default());

        // Acquire and get pointer
        let guard1 = pool.acquire_ml_kem_public_key().unwrap();
        let ptr1 = guard1.as_ref().0.as_ptr();
        drop(guard1);

        // Acquire again - should get same buffer
        let guard2 = pool.acquire_ml_kem_public_key().unwrap();
        let ptr2 = guard2.as_ref().0.as_ptr();

        assert_eq!(ptr1, ptr2, "Pool should reuse the same buffer");
    }

    #[tokio::test]
    async fn test_concurrent_pool_access() {
        let pool = Arc::new(PqcMemoryPool::new(PoolConfig {
            initial_size: 2,
            max_size: 10,
            growth_increment: 1,
            acquire_timeout: Duration::from_secs(1),
        }));

        let mut handles = vec![];

        // Spawn 10 concurrent tasks
        for _ in 0..10 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                let _guard = pool_clone.acquire_ml_kem_secret_key().unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }));
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Check that pool grew to accommodate all requests
        let current_size = pool.stats().current_size.load(Ordering::Relaxed);
        assert_eq!(current_size, 10, "Pool should have grown to 10 objects");
    }

    #[test]
    fn test_guard_auto_returns_on_drop() {
        let pool = PqcMemoryPool::new(PoolConfig::default());

        // Initially pool has initial_size objects
        let initial_available = pool.available_count();

        {
            let _guard = pool.acquire_ml_kem_ciphertext().unwrap();
            // One less available while guard is held
            assert_eq!(
                pool.ml_kem_ciphertexts.available_count(),
                initial_available - 1
            );
        } // guard dropped here

        // Object should be returned to pool
        assert_eq!(pool.ml_kem_ciphertexts.available_count(), initial_available);
    }

    #[test]
    fn test_pool_respects_max_size() {
        let pool = PqcMemoryPool::new(PoolConfig {
            initial_size: 1,
            max_size: 2,
            growth_increment: 1,
            acquire_timeout: Duration::from_secs(1),
        });

        // Acquire all available objects
        let _guard1 = pool.acquire_ml_dsa_signature().unwrap();
        let _guard2 = pool.acquire_ml_dsa_signature().unwrap();

        // Third acquisition should fail
        let result = pool.acquire_ml_dsa_signature();
        assert!(result.is_err());
        assert!(matches!(result, Err(PqcError::PoolError(_))));
    }

    #[test]
    fn test_pool_statistics() {
        let pool = PqcMemoryPool::new(PoolConfig {
            initial_size: 2,
            max_size: 10,
            growth_increment: 1,
            acquire_timeout: Duration::from_secs(1),
        });

        // First two acquisitions should be hits
        let guard1 = pool.acquire_ml_kem_public_key().unwrap();
        let guard2 = pool.acquire_ml_kem_public_key().unwrap();

        assert_eq!(pool.stats().hits.load(Ordering::Relaxed), 2);
        assert_eq!(pool.stats().misses.load(Ordering::Relaxed), 0);

        // Third acquisition should be a miss (need to allocate)
        let _guard3 = pool.acquire_ml_kem_public_key().unwrap();

        assert_eq!(pool.stats().hits.load(Ordering::Relaxed), 2);
        assert_eq!(pool.stats().misses.load(Ordering::Relaxed), 1);

        // Return all guards
        drop(guard1);
        drop(guard2);

        // Check deallocation count
        assert_eq!(pool.stats().deallocations.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_secret_key_zeroization() {
        let pool = PqcMemoryPool::new(PoolConfig::default());

        // ML-KEM secret key
        {
            let mut guard = pool.acquire_ml_kem_secret_key().unwrap();
            // Fill with non-zero data
            guard.as_mut().0.fill(0xFF);
            // Buffer will be zeroized on drop
        }

        // ML-DSA secret key
        {
            let mut guard = pool.acquire_ml_dsa_secret_key().unwrap();
            // Fill with non-zero data
            guard.as_mut().0.fill(0xFF);
            // Buffer will be zeroized on drop
        }

        // Verify by acquiring again - should get zeroed buffer
        let guard = pool.acquire_ml_kem_secret_key().unwrap();
        assert!(
            guard.as_ref().0.iter().all(|&b| b == 0),
            "Secret key buffer should be zeroed"
        );
    }

    #[test]
    fn test_all_buffer_types() {
        let pool = PqcMemoryPool::new(PoolConfig::default());

        // Test each buffer type can be acquired and used
        let ml_kem_pk = pool.acquire_ml_kem_public_key().unwrap();
        assert_eq!(ml_kem_pk.as_ref().0.len(), ML_KEM_768_PUBLIC_KEY_SIZE);

        let ml_kem_sk = pool.acquire_ml_kem_secret_key().unwrap();
        assert_eq!(ml_kem_sk.as_ref().0.len(), ML_KEM_768_SECRET_KEY_SIZE);

        let ml_kem_ct = pool.acquire_ml_kem_ciphertext().unwrap();
        assert_eq!(ml_kem_ct.as_ref().0.len(), ML_KEM_768_CIPHERTEXT_SIZE);

        let ml_dsa_pk = pool.acquire_ml_dsa_public_key().unwrap();
        assert_eq!(ml_dsa_pk.as_ref().0.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let ml_dsa_sk = pool.acquire_ml_dsa_secret_key().unwrap();
        assert_eq!(ml_dsa_sk.as_ref().0.len(), ML_DSA_65_SECRET_KEY_SIZE);

        let ml_dsa_sig = pool.acquire_ml_dsa_signature().unwrap();
        assert_eq!(ml_dsa_sig.as_ref().0.len(), ML_DSA_65_SIGNATURE_SIZE);
    }

    #[test]
    fn test_hit_rate_calculation() {
        let pool = PqcMemoryPool::new(PoolConfig {
            initial_size: 2,
            max_size: 10,
            growth_increment: 1,
            acquire_timeout: Duration::from_secs(1),
        });

        // Two hits
        let _g1 = pool.acquire_ml_kem_public_key().unwrap();
        let _g2 = pool.acquire_ml_kem_public_key().unwrap();

        // One miss
        let _g3 = pool.acquire_ml_kem_public_key().unwrap();

        // Hit rate should be 66.7%
        let hit_rate = pool.stats().hit_rate();
        assert!(
            (hit_rate - 66.7).abs() < 0.1,
            "Hit rate should be approximately 66.7%"
        );
    }
}

// Benchmark tests (to be run with `cargo bench`)
#[cfg(all(test, not(debug_assertions)))]
mod benches {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_pool_allocation(b: &mut Bencher) {
        let pool = PqcMemoryPool::new(PoolConfig::default());

        b.iter(|| {
            let _guard = pool.acquire_ml_kem_public_key().unwrap();
            // Guard automatically returned on drop
        });
    }

    #[bench]
    fn bench_direct_allocation(b: &mut Bencher) {
        b.iter(|| {
            let _buffer = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
        });
    }
}
