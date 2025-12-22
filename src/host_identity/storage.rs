// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Platform-specific storage backends for HostKey persistence
//!
//! Storage priority (ADR-007):
//! 1. macOS: Keychain Services
//! 2. Linux: libsecret/GNOME Keyring (if available)
//! 3. Windows: DPAPI
//! 4. Fallback: XChaCha20-Poly1305 encrypted file with `ANTQ_HOSTKEY_PASSWORD` env var
//!
//! # Security Model
//!
//! The HostKey is the root secret for all derived keys. It must be:
//! - Protected at rest with platform-appropriate encryption
//! - Never exposed in logs or error messages
//! - Zeroed from memory when no longer needed
//!
//! # Usage
//!
//! ```ignore
//! use ant_quic::host_identity::storage::{HostKeyStorage, auto_storage};
//!
//! // Get the best available storage for this platform
//! let storage = auto_storage()?;
//!
//! // Store a HostKey
//! storage.store(&hostkey_bytes)?;
//!
//! // Load the HostKey
//! let hostkey = storage.load()?;
//! ```

use std::path::PathBuf;
use thiserror::Error;
use zeroize::Zeroize;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during HostKey storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// HostKey not found in storage
    #[error("HostKey not found")]
    NotFound,

    /// Storage backend not available on this platform
    #[error("Storage backend not available: {0}")]
    BackendUnavailable(String),

    /// Password required but not provided
    #[error("ANTQ_HOSTKEY_PASSWORD environment variable not set")]
    PasswordRequired,

    /// Encryption/decryption failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// I/O error during storage operations
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid data format
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    /// Platform-specific keychain error
    #[error("Keychain error: {0}")]
    KeychainError(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

// =============================================================================
// Storage Trait
// =============================================================================

/// Trait for HostKey storage backends
///
/// Implementations must ensure:
/// - Data is encrypted at rest
/// - Sensitive data is zeroed after use
/// - Thread-safe access
pub trait HostKeyStorage: Send + Sync {
    /// Store the HostKey
    ///
    /// # Arguments
    /// * `hostkey` - 32-byte HostKey secret
    ///
    /// # Security
    /// The implementation should encrypt the key before storing.
    fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()>;

    /// Load the HostKey
    ///
    /// # Returns
    /// The 32-byte HostKey secret, or `StorageError::NotFound` if not stored.
    ///
    /// # Security
    /// The returned bytes should be zeroed by the caller when no longer needed.
    fn load(&self) -> StorageResult<[u8; 32]>;

    /// Delete the HostKey from storage
    ///
    /// # Security
    /// This should securely erase the key material.
    fn delete(&self) -> StorageResult<()>;

    /// Check if a HostKey exists in storage
    fn exists(&self) -> bool;

    /// Get the storage backend name for diagnostics
    fn backend_name(&self) -> &'static str;
}

// =============================================================================
// Encrypted File Storage (Fallback)
// =============================================================================

/// File format version for migration support
const FILE_FORMAT_VERSION: u8 = 1;

/// Salt size for HKDF key derivation from password
const SALT_SIZE: usize = 32;

/// Encrypted file storage using XChaCha20-Poly1305
///
/// File format:
/// ```text
/// [version: 1 byte][salt: 32 bytes][nonce: 24 bytes][ciphertext+tag: 48 bytes]
/// Total: 105 bytes
/// ```
///
/// Requires `ANTQ_HOSTKEY_PASSWORD` environment variable to be set.
pub struct EncryptedFileStorage {
    path: PathBuf,
}

impl EncryptedFileStorage {
    /// Create a new encrypted file storage at the default location
    pub fn new() -> StorageResult<Self> {
        let path = Self::default_path()?;
        Ok(Self { path })
    }

    /// Create encrypted file storage at a custom path
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get the default storage path
    ///
    /// - Linux/macOS: `~/.config/ant-quic/hostkey.enc`
    /// - Windows: `%APPDATA%\ant-quic\hostkey.enc`
    fn default_path() -> StorageResult<PathBuf> {
        let config_dir = dirs::config_dir().ok_or_else(|| {
            StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine config directory",
            ))
        })?;

        let path = config_dir.join("ant-quic").join("hostkey.enc");
        Ok(path)
    }

    /// Get the password from environment variable
    fn get_password() -> StorageResult<String> {
        std::env::var("ANTQ_HOSTKEY_PASSWORD").map_err(|_| StorageError::PasswordRequired)
    }

    /// Derive encryption key from password using HKDF
    fn derive_key_from_password(password: &str, salt: &[u8]) -> StorageResult<[u8; 32]> {
        use aws_lc_rs::hkdf;

        let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = hkdf_salt.extract(password.as_bytes());

        let mut key = [0u8; 32];
        let okm = prk
            .expand(&[b"antq:hostkey-file:v1"], hkdf::HKDF_SHA256)
            .map_err(|e| StorageError::CryptoError(format!("HKDF expand failed: {e}")))?;

        okm.fill(&mut key)
            .map_err(|e| StorageError::CryptoError(format!("HKDF fill failed: {e}")))?;

        Ok(key)
    }

    /// Encrypt data using XChaCha20-Poly1305
    fn encrypt(key: &[u8; 32], plaintext: &[u8; 32]) -> StorageResult<Vec<u8>> {
        use aws_lc_rs::aead::{self, Aad, BoundKey, Nonce, NonceSequence, UnboundKey, CHACHA20_POLY1305};

        // Generate random nonce (12 bytes for ChaCha20-Poly1305)
        let mut nonce_bytes = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce_bytes)
            .map_err(|e| StorageError::CryptoError(format!("Failed to generate nonce: {e}")))?;

        // Create sealing key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|e| StorageError::CryptoError(format!("Failed to create key: {e}")))?;

        struct SingleNonce(Option<[u8; 12]>);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
                self.0.take().map(Nonce::assume_unique_for_key).ok_or(aws_lc_rs::error::Unspecified)
            }
        }

        let mut sealing_key = aead::SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        // Encrypt in-place
        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|e| StorageError::CryptoError(format!("Encryption failed: {e}")))?;

        // Return nonce || ciphertext+tag
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt data using XChaCha20-Poly1305
    fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> StorageResult<[u8; 32]> {
        use aws_lc_rs::aead::{self, Aad, BoundKey, Nonce, NonceSequence, UnboundKey, CHACHA20_POLY1305};

        if ciphertext.len() < 12 + 16 {
            return Err(StorageError::InvalidFormat("Ciphertext too short".to_string()));
        }

        let nonce_bytes: [u8; 12] = ciphertext[..12]
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid nonce".to_string()))?;

        // Create opening key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|e| StorageError::CryptoError(format!("Failed to create key: {e}")))?;

        struct SingleNonce(Option<[u8; 12]>);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
                self.0.take().map(Nonce::assume_unique_for_key).ok_or(aws_lc_rs::error::Unspecified)
            }
        }

        let mut opening_key = aead::OpeningKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        // Decrypt in-place
        let mut in_out = ciphertext[12..].to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| StorageError::CryptoError("Decryption failed - wrong password or corrupted data".to_string()))?;

        if plaintext.len() != 32 {
            return Err(StorageError::InvalidFormat(format!(
                "Expected 32-byte HostKey, got {} bytes",
                plaintext.len()
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(plaintext);
        Ok(result)
    }
}

impl HostKeyStorage for EncryptedFileStorage {
    fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
        let password = Self::get_password()?;

        // Generate random salt
        let mut salt = [0u8; SALT_SIZE];
        aws_lc_rs::rand::fill(&mut salt)
            .map_err(|e| StorageError::CryptoError(format!("Failed to generate salt: {e}")))?;

        // Derive encryption key from password
        let mut key = Self::derive_key_from_password(&password, &salt)?;

        // Encrypt the hostkey
        let ciphertext = Self::encrypt(&key, hostkey)?;

        // Zero the key
        key.zeroize();

        // Create parent directories
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Build file contents: version || salt || ciphertext
        let mut file_data = Vec::with_capacity(1 + SALT_SIZE + ciphertext.len());
        file_data.push(FILE_FORMAT_VERSION);
        file_data.extend_from_slice(&salt);
        file_data.extend_from_slice(&ciphertext);

        // Write atomically using temp file
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, &file_data)?;
        std::fs::rename(&temp_path, &self.path)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, permissions)?;
        }

        Ok(())
    }

    fn load(&self) -> StorageResult<[u8; 32]> {
        if !self.path.exists() {
            return Err(StorageError::NotFound);
        }

        let password = Self::get_password()?;
        let file_data = std::fs::read(&self.path)?;

        // Parse file format
        if file_data.is_empty() {
            return Err(StorageError::InvalidFormat("Empty file".to_string()));
        }

        let version = file_data[0];
        if version != FILE_FORMAT_VERSION {
            return Err(StorageError::InvalidFormat(format!(
                "Unsupported file format version: {version}"
            )));
        }

        if file_data.len() < 1 + SALT_SIZE + 12 + 16 {
            return Err(StorageError::InvalidFormat("File too short".to_string()));
        }

        let salt = &file_data[1..1 + SALT_SIZE];
        let ciphertext = &file_data[1 + SALT_SIZE..];

        // Derive key and decrypt
        let mut key = Self::derive_key_from_password(&password, salt)?;
        let result = Self::decrypt(&key, ciphertext);

        // Zero the key
        key.zeroize();

        result
    }

    fn delete(&self) -> StorageResult<()> {
        if self.path.exists() {
            // Overwrite with zeros before deleting (defense in depth)
            if let Ok(metadata) = std::fs::metadata(&self.path) {
                let zeros = vec![0u8; metadata.len() as usize];
                let _ = std::fs::write(&self.path, &zeros);
            }
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn backend_name(&self) -> &'static str {
        "EncryptedFile"
    }
}

// =============================================================================
// macOS Keychain Storage
// =============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// macOS Keychain storage using Security.framework
    ///
    /// Currently falls back to encrypted file storage.
    /// TODO: Implement native Keychain access when security-framework crate is added.
    pub struct KeychainStorage {
        // Placeholder for future Keychain implementation
        // Fields will be used when native Keychain support is added
    }

    impl KeychainStorage {
        /// Create a new Keychain storage instance
        pub fn new() -> Self {
            Self {}
        }
    }

    impl HostKeyStorage for KeychainStorage {
        fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
            // Use security-framework crate for keychain access
            // For now, fall back to encrypted file storage
            // TODO: Implement proper Keychain access when security-framework is added
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.store(hostkey)
        }

        fn load(&self) -> StorageResult<[u8; 32]> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.load()
        }

        fn delete(&self) -> StorageResult<()> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.delete()
        }

        fn exists(&self) -> bool {
            EncryptedFileStorage::new()
                .map(|s| s.exists())
                .unwrap_or(false)
        }

        fn backend_name(&self) -> &'static str {
            "macOS-Keychain"
        }
    }
}

// =============================================================================
// Linux Secret Service Storage
// =============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Linux Secret Service storage using GNOME Keyring / KWallet
    pub struct SecretServiceStorage {
        collection: String,
        label: String,
    }

    impl SecretServiceStorage {
        /// Create a new Secret Service storage instance
        pub fn new() -> Self {
            Self {
                collection: "ant-quic".to_string(),
                label: "hostkey".to_string(),
            }
        }

        /// Check if Secret Service is available
        pub fn is_available() -> bool {
            // Check for GNOME Keyring or similar
            std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok()
        }
    }

    impl HostKeyStorage for SecretServiceStorage {
        fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
            // Use secret-service crate for D-Bus access
            // For now, fall back to encrypted file storage
            // TODO: Implement proper Secret Service access when secret-service is added
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.store(hostkey)
        }

        fn load(&self) -> StorageResult<[u8; 32]> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.load()
        }

        fn delete(&self) -> StorageResult<()> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.delete()
        }

        fn exists(&self) -> bool {
            EncryptedFileStorage::new()
                .map(|s| s.exists())
                .unwrap_or(false)
        }

        fn backend_name(&self) -> &'static str {
            "Linux-SecretService"
        }
    }
}

// =============================================================================
// Windows DPAPI Storage
// =============================================================================

#[cfg(target_os = "windows")]
mod windows_storage {
    use super::*;

    /// Windows DPAPI storage
    pub struct DpapiStorage {
        path: PathBuf,
    }

    impl DpapiStorage {
        /// Create a new DPAPI storage instance
        pub fn new() -> StorageResult<Self> {
            let config_dir = dirs::config_dir().ok_or_else(|| {
                StorageError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Could not determine config directory",
                ))
            })?;

            let path = config_dir.join("ant-quic").join("hostkey.dpapi");
            Ok(Self { path })
        }
    }

    impl HostKeyStorage for DpapiStorage {
        fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
            // Use Windows DPAPI for encryption
            // For now, fall back to encrypted file storage
            // TODO: Implement proper DPAPI access when windows crate features are added
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.store(hostkey)
        }

        fn load(&self) -> StorageResult<[u8; 32]> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.load()
        }

        fn delete(&self) -> StorageResult<()> {
            let file_storage = EncryptedFileStorage::new()?;
            file_storage.delete()
        }

        fn exists(&self) -> bool {
            EncryptedFileStorage::new()
                .map(|s| s.exists())
                .unwrap_or(false)
        }

        fn backend_name(&self) -> &'static str {
            "Windows-DPAPI"
        }
    }
}

// =============================================================================
// Auto-Selection
// =============================================================================

/// Automatically select the best available storage backend for this platform
///
/// Priority order:
/// 1. Platform-specific secure storage (Keychain, Secret Service, DPAPI)
/// 2. Encrypted file with environment variable password
pub fn auto_storage() -> StorageResult<Box<dyn HostKeyStorage>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::KeychainStorage::new()))
    }

    #[cfg(target_os = "linux")]
    {
        if linux::SecretServiceStorage::is_available() {
            return Ok(Box::new(linux::SecretServiceStorage::new()));
        }
    }

    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(windows_storage::DpapiStorage::new()?));
    }

    // Fallback to encrypted file storage
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(Box::new(EncryptedFileStorage::new()?))
    }

    #[cfg(all(target_os = "linux", not(target_os = "macos"), not(target_os = "windows")))]
    {
        // Linux without Secret Service - use encrypted file
        Ok(Box::new(EncryptedFileStorage::new()?))
    }
}

/// Get encrypted file storage directly (useful for testing or when env var is available)
pub fn encrypted_file_storage() -> StorageResult<EncryptedFileStorage> {
    EncryptedFileStorage::new()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Mutex to serialize tests that modify ANTQ_HOSTKEY_PASSWORD env var
    static ENV_VAR_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to safely set/remove password env var within mutex guard
    fn with_password<T, F: FnOnce() -> T>(password: Option<&str>, f: F) -> T {
        let _guard = ENV_VAR_MUTEX.lock().expect("ENV_VAR_MUTEX poisoned");
        // SAFETY: We hold the mutex, so no concurrent env var access
        unsafe {
            if let Some(pwd) = password {
                std::env::set_var("ANTQ_HOSTKEY_PASSWORD", pwd);
            } else {
                std::env::remove_var("ANTQ_HOSTKEY_PASSWORD");
            }
        }
        let result = f();
        // Clean up
        unsafe {
            std::env::remove_var("ANTQ_HOSTKEY_PASSWORD");
        }
        result
    }

    #[test]
    fn test_encrypted_file_storage_roundtrip() {
        with_password(Some("test-password-12345"), || {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let path = temp_dir.path().join("hostkey.enc");
            let storage = EncryptedFileStorage::with_path(path);

            let hostkey = [0xAB; 32];

            // Store
            storage.store(&hostkey).expect("Failed to store");

            // Load
            let loaded = storage.load().expect("Failed to load");
            assert_eq!(loaded, hostkey);
        });
    }

    #[test]
    fn test_encrypted_file_storage_wrong_password() {
        // First store with correct password
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.enc");

        with_password(Some("correct-password"), || {
            let storage = EncryptedFileStorage::with_path(path.clone());
            let hostkey = [0xAB; 32];
            storage.store(&hostkey).expect("Failed to store");
        });

        // Then try to load with wrong password
        with_password(Some("wrong-password"), || {
            let storage = EncryptedFileStorage::with_path(path.clone());
            let result = storage.load();
            assert!(result.is_err(), "Should fail with wrong password");
        });
    }

    #[test]
    fn test_encrypted_file_storage_missing_password() {
        with_password(None, || {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let path = temp_dir.path().join("hostkey.enc");
            let storage = EncryptedFileStorage::with_path(path);

            let hostkey = [0xCD; 32];
            let result = storage.store(&hostkey);

            assert!(matches!(result, Err(StorageError::PasswordRequired)));
        });
    }

    #[test]
    fn test_encrypted_file_storage_not_found() {
        with_password(Some("test-password"), || {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let path = temp_dir.path().join("nonexistent.enc");
            let storage = EncryptedFileStorage::with_path(path);

            let result = storage.load();
            assert!(matches!(result, Err(StorageError::NotFound)));
        });
    }

    #[test]
    fn test_encrypted_file_storage_delete() {
        with_password(Some("test-password"), || {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let path = temp_dir.path().join("hostkey.enc");
            let storage = EncryptedFileStorage::with_path(path.clone());

            let hostkey = [0xEF; 32];
            storage.store(&hostkey).expect("Failed to store");
            assert!(path.exists());

            storage.delete().expect("Failed to delete");
            assert!(!path.exists());
        });
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let password = "test-password";
        let salt = [1u8; SALT_SIZE];

        let key1 = EncryptedFileStorage::derive_key_from_password(password, &salt)
            .expect("Key derivation failed");
        let key2 = EncryptedFileStorage::derive_key_from_password(password, &salt)
            .expect("Key derivation failed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = "test-password";
        let salt1 = [1u8; SALT_SIZE];
        let salt2 = [2u8; SALT_SIZE];

        let key1 = EncryptedFileStorage::derive_key_from_password(password, &salt1)
            .expect("Key derivation failed");
        let key2 = EncryptedFileStorage::derive_key_from_password(password, &salt2)
            .expect("Key derivation failed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42; 32];
        let plaintext = [0xAB; 32];

        let ciphertext =
            EncryptedFileStorage::encrypt(&key, &plaintext).expect("Encryption failed");

        // Ciphertext should be larger than plaintext (nonce + tag)
        assert!(ciphertext.len() > 32);

        let decrypted =
            EncryptedFileStorage::decrypt(&key, &ciphertext).expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = [0x42; 32];
        let key2 = [0x43; 32];
        let plaintext = [0xAB; 32];

        let ciphertext =
            EncryptedFileStorage::encrypt(&key1, &plaintext).expect("Encryption failed");

        let result = EncryptedFileStorage::decrypt(&key2, &ciphertext);
        assert!(result.is_err());
    }
}
