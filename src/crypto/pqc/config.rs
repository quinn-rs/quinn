// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configuration for Post-Quantum Cryptography (PQC) in QUIC
//!
//! v0.13.0+: PQC is always enabled. ML-KEM-768 is used for key encapsulation
//! on every connection. There is no classical-only or hybrid mode.
//!
//! This module provides configuration for algorithm selection and
//! performance tuning parameters.

use std::fmt;

/// Configuration for Post-Quantum Cryptography behavior
///
/// v0.13.0+: PQC is always enabled. This configuration controls which
/// specific PQC algorithms are used and performance tuning parameters.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PqcConfig {
    /// Enable ML-KEM-768 for key encapsulation
    pub ml_kem_enabled: bool,
    /// Enable ML-DSA-65 for digital signatures
    pub ml_dsa_enabled: bool,
    /// Size of the memory pool for PQC objects
    pub memory_pool_size: usize,
    /// Multiplier for handshake timeout to account for larger PQC messages
    pub handshake_timeout_multiplier: f32,
}

/// Error type for PQC configuration
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// No PQC algorithms enabled
    NoPqcAlgorithmsEnabled,
    /// Invalid memory pool size
    InvalidMemoryPoolSize(usize),
    /// Invalid timeout multiplier
    InvalidTimeoutMultiplier(f32),
    /// Conflicting configuration options
    ConflictingOptions(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoPqcAlgorithmsEnabled => {
                write!(f, "At least one PQC algorithm must be enabled")
            }
            ConfigError::InvalidMemoryPoolSize(size) => {
                write!(
                    f,
                    "Invalid memory pool size {}: must be between 1 and 1000",
                    size
                )
            }
            ConfigError::InvalidTimeoutMultiplier(mult) => {
                write!(
                    f,
                    "Invalid timeout multiplier {}: must be between 1.0 and 10.0",
                    mult
                )
            }
            ConfigError::ConflictingOptions(msg) => {
                write!(f, "Conflicting configuration options: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            // v0.13.0+: Both ML-KEM and ML-DSA enabled by default
            ml_kem_enabled: true,
            ml_dsa_enabled: true,
            memory_pool_size: 10,
            handshake_timeout_multiplier: 2.0,
        }
    }
}

impl PqcConfig {
    /// Create a new PqcConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing PqcConfig
    pub fn builder() -> PqcConfigBuilder {
        PqcConfigBuilder::new()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // At least one PQC algorithm must be enabled
        if !self.ml_kem_enabled && !self.ml_dsa_enabled {
            return Err(ConfigError::NoPqcAlgorithmsEnabled);
        }

        // Validate memory pool size
        if self.memory_pool_size == 0 || self.memory_pool_size > 1000 {
            return Err(ConfigError::InvalidMemoryPoolSize(self.memory_pool_size));
        }

        // Validate timeout multiplier
        if self.handshake_timeout_multiplier < 1.0 || self.handshake_timeout_multiplier > 10.0 {
            return Err(ConfigError::InvalidTimeoutMultiplier(
                self.handshake_timeout_multiplier,
            ));
        }

        Ok(())
    }
}

/// Builder for PqcConfig
#[derive(Debug, Clone)]
pub struct PqcConfigBuilder {
    ml_kem_enabled: bool,
    ml_dsa_enabled: bool,
    memory_pool_size: usize,
    handshake_timeout_multiplier: f32,
}

impl Default for PqcConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PqcConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        let default = PqcConfig::default();
        Self {
            ml_kem_enabled: default.ml_kem_enabled,
            ml_dsa_enabled: default.ml_dsa_enabled,
            memory_pool_size: default.memory_pool_size,
            handshake_timeout_multiplier: default.handshake_timeout_multiplier,
        }
    }

    /// Enable or disable ML-KEM-768
    pub fn ml_kem(mut self, enabled: bool) -> Self {
        self.ml_kem_enabled = enabled;
        self
    }

    /// Enable or disable ML-DSA-65
    pub fn ml_dsa(mut self, enabled: bool) -> Self {
        self.ml_dsa_enabled = enabled;
        self
    }

    /// Set the memory pool size
    pub fn memory_pool_size(mut self, size: usize) -> Self {
        self.memory_pool_size = size;
        self
    }

    /// Set the handshake timeout multiplier
    pub fn handshake_timeout_multiplier(mut self, multiplier: f32) -> Self {
        self.handshake_timeout_multiplier = multiplier;
        self
    }

    /// Build the PqcConfig, validating all settings
    pub fn build(self) -> Result<PqcConfig, ConfigError> {
        let config = PqcConfig {
            ml_kem_enabled: self.ml_kem_enabled,
            ml_dsa_enabled: self.ml_dsa_enabled,
            memory_pool_size: self.memory_pool_size,
            handshake_timeout_multiplier: self.handshake_timeout_multiplier,
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PqcConfig::default();
        // v0.13.0+: Both ML-KEM and ML-DSA enabled by default
        assert!(config.ml_kem_enabled);
        assert!(config.ml_dsa_enabled);
        assert_eq!(config.memory_pool_size, 10);
        assert_eq!(config.handshake_timeout_multiplier, 2.0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_basic() {
        let config = PqcConfig::builder()
            .ml_kem(true)
            .ml_dsa(true)
            .build()
            .unwrap();

        assert!(config.ml_kem_enabled);
        assert!(config.ml_dsa_enabled);
    }

    #[test]
    fn test_requires_at_least_one_algorithm() {
        // Should fail with no algorithms
        let result = PqcConfig::builder().ml_kem(false).ml_dsa(false).build();

        assert!(matches!(result, Err(ConfigError::NoPqcAlgorithmsEnabled)));

        // Should succeed with at least one algorithm
        let config = PqcConfig::builder()
            .ml_kem(true)
            .ml_dsa(false)
            .build()
            .unwrap();

        assert!(config.ml_kem_enabled);
        assert!(!config.ml_dsa_enabled);
    }

    #[test]
    fn test_memory_pool_validation() {
        // Zero should fail
        let result = PqcConfig::builder().memory_pool_size(0).build();

        assert!(matches!(result, Err(ConfigError::InvalidMemoryPoolSize(0))));

        // Too large should fail
        let result = PqcConfig::builder().memory_pool_size(1001).build();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidMemoryPoolSize(1001))
        ));

        // Valid range should succeed
        let config = PqcConfig::builder().memory_pool_size(100).build().unwrap();

        assert_eq!(config.memory_pool_size, 100);
    }

    #[test]
    fn test_timeout_multiplier_validation() {
        // Too small should fail
        let result = PqcConfig::builder()
            .handshake_timeout_multiplier(0.5)
            .build();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidTimeoutMultiplier(_))
        ));

        // Too large should fail
        let result = PqcConfig::builder()
            .handshake_timeout_multiplier(11.0)
            .build();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidTimeoutMultiplier(_))
        ));

        // Valid range should succeed
        let config = PqcConfig::builder()
            .handshake_timeout_multiplier(3.0)
            .build()
            .unwrap();

        assert_eq!(config.handshake_timeout_multiplier, 3.0);
    }
}
