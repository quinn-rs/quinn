//! Placeholder for Extension Handlers
//!
//! Note: rustls 0.23.x already includes built-in RFC 7250 Raw Public Keys support,
//! so we don't need custom extension handlers. This module is kept as a placeholder
//! for future extensions if needed.

use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig};

use super::tls_extensions::CertificateTypePreferences;

/// Configure client with certificate type preferences
pub fn configure_client(_config: &mut ClientConfig, _preferences: Arc<CertificateTypePreferences>) {
    // rustls 0.23.x handles RFC 7250 internally
}

/// Configure server with certificate type preferences  
pub fn configure_server(_config: &mut ServerConfig, _preferences: Arc<CertificateTypePreferences>) {
    // rustls 0.23.x handles RFC 7250 internally
}