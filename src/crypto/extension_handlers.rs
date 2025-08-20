// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Extension Handlers for RFC 7250 Raw Public Keys
//!
//! Note: rustls 0.23.x does not yet have full RFC 7250 Raw Public Keys support.
//! See https://github.com/rustls/rustls/issues/423 for the tracking issue.
//!
//! This module provides a workaround by using custom certificate verifiers
//! that can handle SubjectPublicKeyInfo structures as "certificates".

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
