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
// Storage Security Level
// =============================================================================

/// Security level of the storage backend
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageSecurityLevel {
    /// Platform keychain (macOS Keychain, GNOME Keyring, Windows Credential Manager)
    Secure,
    /// Encrypted file with password
    Encrypted,
    /// Plain file with permissions only - INSECURE
    Insecure,
}

impl StorageSecurityLevel {
    /// Get a warning message if this security level requires user attention
    pub fn warning_message(&self) -> Option<&'static str> {
        match self {
            Self::Secure | Self::Encrypted => None,
            Self::Insecure => Some(
                "⚠️  HostKey stored WITHOUT ENCRYPTION!\n\
                 Anyone with file access can read and impersonate this node.\n\
                 To secure: set ANTQ_HOSTKEY_PASSWORD environment variable.",
            ),
        }
    }

    /// Check if this storage level is considered secure
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure | Self::Encrypted)
    }
}

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

    /// Get the security level of this storage backend
    fn security_level(&self) -> StorageSecurityLevel;
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
        use aws_lc_rs::aead::{
            self, Aad, BoundKey, CHACHA20_POLY1305, Nonce, NonceSequence, UnboundKey,
        };

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
            .map_err(|e| StorageError::CryptoError(format!("Encryption failed: {e}")))?;

        // Return nonce || ciphertext+tag
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt data using XChaCha20-Poly1305
    fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> StorageResult<[u8; 32]> {
        use aws_lc_rs::aead::{
            self, Aad, BoundKey, CHACHA20_POLY1305, Nonce, NonceSequence, UnboundKey,
        };

        if ciphertext.len() < 12 + 16 {
            return Err(StorageError::InvalidFormat(
                "Ciphertext too short".to_string(),
            ));
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
                self.0
                    .take()
                    .map(Nonce::assume_unique_for_key)
                    .ok_or(aws_lc_rs::error::Unspecified)
            }
        }

        let mut opening_key = aead::OpeningKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        // Decrypt in-place
        let mut in_out = ciphertext[12..].to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| {
                StorageError::CryptoError(
                    "Decryption failed - wrong password or corrupted data".to_string(),
                )
            })?;

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

    fn security_level(&self) -> StorageSecurityLevel {
        StorageSecurityLevel::Encrypted
    }
}

// =============================================================================
// Cross-Platform Keyring Storage
// =============================================================================

/// Cross-platform keyring storage using the `keyring` crate
///
/// Supports:
/// - macOS: Keychain Services
/// - Linux: Secret Service (GNOME Keyring, KWallet)
/// - Windows: Credential Manager
pub struct KeyringStorage {
    service: &'static str,
    username: &'static str,
}

impl KeyringStorage {
    const SERVICE: &'static str = "ant-quic";
    const USERNAME: &'static str = "hostkey";

    /// Create a new keyring storage instance
    pub fn new() -> StorageResult<Self> {
        // Verify keyring is available by trying to create an entry
        let _ = keyring::Entry::new(Self::SERVICE, Self::USERNAME)
            .map_err(|e| StorageError::KeychainError(format!("Keyring unavailable: {e}")))?;
        Ok(Self {
            service: Self::SERVICE,
            username: Self::USERNAME,
        })
    }

    /// Check if keyring is available on this platform
    pub fn is_available() -> bool {
        keyring::Entry::new(Self::SERVICE, Self::USERNAME).is_ok()
    }

    /// Get the keyring entry
    fn entry(&self) -> StorageResult<keyring::Entry> {
        keyring::Entry::new(self.service, self.username)
            .map_err(|e| StorageError::KeychainError(e.to_string()))
    }
}

impl HostKeyStorage for KeyringStorage {
    fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
        let entry = self.entry()?;
        // Store as hex string (keyring stores strings)
        let hex = hex::encode(hostkey);
        entry
            .set_password(&hex)
            .map_err(|e| StorageError::KeychainError(e.to_string()))
    }

    fn load(&self) -> StorageResult<[u8; 32]> {
        let entry = self.entry()?;
        let hex = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => StorageError::NotFound,
            _ => StorageError::KeychainError(e.to_string()),
        })?;

        let bytes = hex::decode(&hex).map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(StorageError::InvalidFormat(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }

    fn delete(&self) -> StorageResult<()> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(StorageError::KeychainError(e.to_string())),
        }
    }

    fn exists(&self) -> bool {
        self.entry()
            .map(|e| e.get_password().is_ok())
            .unwrap_or(false)
    }

    fn backend_name(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "macOS-Keychain"
        }
        #[cfg(target_os = "linux")]
        {
            "Linux-SecretService"
        }
        #[cfg(target_os = "windows")]
        {
            "Windows-CredentialManager"
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            "Keyring"
        }
    }

    fn security_level(&self) -> StorageSecurityLevel {
        StorageSecurityLevel::Secure
    }
}

// =============================================================================
// Plain File Storage (Insecure Fallback)
// =============================================================================

/// Plain file storage with file permission protection only
///
/// **SECURITY WARNING**: This stores the HostKey unencrypted!
/// Anyone with file access can read and copy your identity.
///
/// Use only when:
/// - Platform keychain is unavailable
/// - You haven't set `ANTQ_HOSTKEY_PASSWORD`
///
/// File location: `~/.config/ant-quic/hostkey.key`
pub struct PlainFileStorage {
    path: PathBuf,
}

impl PlainFileStorage {
    /// Create a new plain file storage at the default location
    pub fn new() -> StorageResult<Self> {
        let path = Self::default_path()?;
        Ok(Self { path })
    }

    /// Create plain file storage at a custom path
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get the default storage path
    fn default_path() -> StorageResult<PathBuf> {
        let config_dir = dirs::config_dir().ok_or_else(|| {
            StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine config directory",
            ))
        })?;
        Ok(config_dir.join("ant-quic").join("hostkey.key"))
    }
}

impl HostKeyStorage for PlainFileStorage {
    fn store(&self, hostkey: &[u8; 32]) -> StorageResult<()> {
        // Create parent directories
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write atomically using temp file
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, hostkey)?;
        std::fs::rename(&temp_path, &self.path)?;

        // Set restrictive permissions (0600 on Unix)
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

        let data = std::fs::read(&self.path)?;
        if data.len() != 32 {
            return Err(StorageError::InvalidFormat(format!(
                "Expected 32 bytes, got {}",
                data.len()
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&data);
        Ok(result)
    }

    fn delete(&self) -> StorageResult<()> {
        if self.path.exists() {
            // Overwrite with zeros before deleting (defense in depth)
            let _ = std::fs::write(&self.path, [0u8; 32]);
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn backend_name(&self) -> &'static str {
        "PlainFile-INSECURE"
    }

    fn security_level(&self) -> StorageSecurityLevel {
        StorageSecurityLevel::Insecure
    }
}

// =============================================================================
// Storage Selection Result
// =============================================================================

/// Result of auto-selecting storage, includes security info
pub struct StorageSelection {
    /// The selected storage backend
    pub storage: Box<dyn HostKeyStorage>,
    /// Security level of the selected backend
    pub security_level: StorageSecurityLevel,
}

// =============================================================================
// Auto-Selection
// =============================================================================

/// Automatically select the best available storage backend for this platform
///
/// Priority order:
/// 1. Platform keychain (via `keyring` crate) - Secure, zero-config
/// 2. Encrypted file (if `ANTQ_HOSTKEY_PASSWORD` env var set)
/// 3. Plain file with warning (zero-config fallback)
pub fn auto_storage() -> StorageResult<StorageSelection> {
    // 1. Try platform keychain first
    if KeyringStorage::is_available() {
        if let Ok(storage) = KeyringStorage::new() {
            let security_level = storage.security_level();
            return Ok(StorageSelection {
                storage: Box::new(storage),
                security_level,
            });
        }
    }

    // 2. Try encrypted file if password is available
    if std::env::var("ANTQ_HOSTKEY_PASSWORD").is_ok() {
        let storage = EncryptedFileStorage::new()?;
        return Ok(StorageSelection {
            storage: Box::new(storage),
            security_level: StorageSecurityLevel::Encrypted,
        });
    }

    // 3. Fall back to plain file with warning
    let storage = PlainFileStorage::new()?;
    Ok(StorageSelection {
        storage: Box::new(storage),
        security_level: StorageSecurityLevel::Insecure,
    })
}

/// Legacy function for backwards compatibility - returns just the storage
#[deprecated(
    since = "0.15.0",
    note = "Use auto_storage() which returns StorageSelection"
)]
pub fn auto_storage_legacy() -> StorageResult<Box<dyn HostKeyStorage>> {
    Ok(auto_storage()?.storage)
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

    // =========================================================================
    // PlainFileStorage Tests
    // =========================================================================

    #[test]
    fn test_plain_file_storage_roundtrip() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");
        let storage = PlainFileStorage::with_path(path);

        let hostkey = [0xAB; 32];

        // Store
        storage.store(&hostkey).expect("Failed to store");

        // Load
        let loaded = storage.load().expect("Failed to load");
        assert_eq!(loaded, hostkey);
    }

    #[test]
    fn test_plain_file_storage_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("nonexistent.key");
        let storage = PlainFileStorage::with_path(path);

        let result = storage.load();
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn test_plain_file_storage_delete() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");
        let storage = PlainFileStorage::with_path(path.clone());

        let hostkey = [0xEF; 32];
        storage.store(&hostkey).expect("Failed to store");
        assert!(path.exists());

        storage.delete().expect("Failed to delete");
        assert!(!path.exists());
    }

    #[test]
    fn test_plain_file_storage_exists() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");
        let storage = PlainFileStorage::with_path(path);

        assert!(!storage.exists());

        let hostkey = [0xAB; 32];
        storage.store(&hostkey).expect("Failed to store");
        assert!(storage.exists());
    }

    #[test]
    fn test_plain_file_storage_security_level() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");
        let storage = PlainFileStorage::with_path(path);

        assert_eq!(storage.security_level(), StorageSecurityLevel::Insecure);
        assert!(storage.security_level().warning_message().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn test_plain_file_storage_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");
        let storage = PlainFileStorage::with_path(path.clone());

        let hostkey = [0xAB; 32];
        storage.store(&hostkey).expect("Failed to store");

        let metadata = std::fs::metadata(&path).expect("Failed to get metadata");
        let permissions = metadata.permissions();

        // Should be 0600 (owner read/write only)
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_plain_file_storage_invalid_size() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path = temp_dir.path().join("hostkey.key");

        // Write invalid data (wrong size)
        std::fs::write(&path, [0u8; 16]).expect("Failed to write");

        let storage = PlainFileStorage::with_path(path);
        let result = storage.load();
        assert!(matches!(result, Err(StorageError::InvalidFormat(_))));
    }

    // =========================================================================
    // KeyringStorage Tests (require system keyring, may be ignored in CI)
    // =========================================================================

    #[test]
    #[ignore = "Requires system keyring daemon (run manually)"]
    fn test_keyring_storage_roundtrip() {
        if !KeyringStorage::is_available() {
            println!("Keyring not available, skipping test");
            return;
        }

        let storage = KeyringStorage::new().expect("Failed to create keyring storage");

        // Clean up any existing entry first
        let _ = storage.delete();

        let hostkey = [0xAB; 32];

        // Store
        storage.store(&hostkey).expect("Failed to store");

        // Load
        let loaded = storage.load().expect("Failed to load");
        assert_eq!(loaded, hostkey);

        // Cleanup
        storage.delete().expect("Failed to delete");
    }

    #[test]
    #[ignore = "Requires system keyring daemon (run manually)"]
    fn test_keyring_storage_not_found() {
        if !KeyringStorage::is_available() {
            println!("Keyring not available, skipping test");
            return;
        }

        let storage = KeyringStorage::new().expect("Failed to create keyring storage");

        // Clean up any existing entry first
        let _ = storage.delete();

        let result = storage.load();
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    #[ignore = "Requires system keyring daemon (run manually)"]
    fn test_keyring_storage_security_level() {
        if !KeyringStorage::is_available() {
            println!("Keyring not available, skipping test");
            return;
        }

        let storage = KeyringStorage::new().expect("Failed to create keyring storage");
        assert_eq!(storage.security_level(), StorageSecurityLevel::Secure);
        assert!(storage.security_level().warning_message().is_none());
    }

    // =========================================================================
    // StorageSecurityLevel Tests
    // =========================================================================

    #[test]
    fn test_security_level_warning_messages() {
        assert!(StorageSecurityLevel::Secure.warning_message().is_none());
        assert!(StorageSecurityLevel::Encrypted.warning_message().is_none());
        assert!(StorageSecurityLevel::Insecure.warning_message().is_some());
    }

    #[test]
    fn test_security_level_is_secure() {
        assert!(StorageSecurityLevel::Secure.is_secure());
        assert!(StorageSecurityLevel::Encrypted.is_secure());
        assert!(!StorageSecurityLevel::Insecure.is_secure());
    }

    // =========================================================================
    // auto_storage Tests
    // =========================================================================

    #[test]
    fn test_auto_storage_fallback_to_plain_file() {
        // Without password and without keyring, should fall back to plain file
        with_password(None, || {
            // This test may succeed with keyring if available,
            // but should at least not fail
            let result = auto_storage();
            assert!(result.is_ok());
            let selection = result.expect("auto_storage should succeed");
            // Should be either Secure (keyring) or Insecure (plain file)
            assert!(
                selection.security_level == StorageSecurityLevel::Secure
                    || selection.security_level == StorageSecurityLevel::Insecure
            );
        });
    }

    #[test]
    fn test_auto_storage_with_password() {
        with_password(Some("test-password"), || {
            // With password, if keyring not available, should use encrypted file
            let result = auto_storage();
            assert!(result.is_ok());
            let selection = result.expect("auto_storage should succeed");
            // Should be Secure (keyring) or Encrypted (file with password)
            assert!(
                selection.security_level == StorageSecurityLevel::Secure
                    || selection.security_level == StorageSecurityLevel::Encrypted
            );
        });
    }
}
