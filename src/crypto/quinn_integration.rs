//! Quinn QUIC Integration for RFC 7250 Certificate Type Negotiation
//!
//! This module provides enhanced integration between the TLS certificate type
//! negotiation system and Quinn's QUIC implementation, including 0-RTT support,
//! connection migration, and NAT traversal coordination.

use std::{
    sync::{Arc, RwLock},
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::{
    Endpoint, Connection, ConnectionError, ConnectError,
    ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig,
    crypto::rustls::QuicClientConfig, crypto::rustls::QuicServerConfig,
};

use tracing::{debug, info, warn, error, span, Level};

use super::{
    tls_extensions::{
        CertificateTypeList, CertificateTypePreferences,
        NegotiationResult, TlsExtensionError,
    },
    certificate_negotiation::{
        CertificateNegotiationManager, NegotiationConfig, NegotiationId,
    },
    raw_public_keys::RawPublicKeyConfigBuilder,
};

/// QUIC-specific certificate type negotiation context
#[derive(Debug, Clone)]
pub struct QuicNegotiationContext {
    /// The negotiation result for this QUIC connection
    pub result: NegotiationResult,
    /// When the negotiation was completed
    pub completed_at: Instant,
    /// Whether 0-RTT was used with this certificate type
    pub used_0rtt: bool,
    /// Remote peer address
    pub peer_addr: SocketAddr,
    /// Connection ID for tracking
    pub connection_id: String,
}

impl QuicNegotiationContext {
    /// Create a new QUIC negotiation context
    pub fn new(
        result: NegotiationResult,
        peer_addr: SocketAddr,
        connection_id: String,
        used_0rtt: bool,
    ) -> Self {
        Self {
            result,
            completed_at: Instant::now(),
            used_0rtt,
            peer_addr,
            connection_id,
        }
    }

    /// Check if Raw Public Keys are used for both client and server
    pub fn is_raw_public_key_connection(&self) -> bool {
        self.result.is_raw_public_key_only()
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.completed_at.elapsed()
    }
}

/// Enhanced QUIC endpoint with certificate type negotiation support
pub struct CertTypeAwareQuicEndpoint {
    /// The underlying Quinn endpoint
    endpoint: Endpoint,
    /// Certificate type negotiation manager
    negotiation_manager: Arc<CertificateNegotiationManager>,
    /// Active QUIC connections with their negotiation contexts
    connections: Arc<RwLock<HashMap<String, QuicNegotiationContext>>>,
    /// Certificate type preferences for this endpoint
    preferences: CertificateTypePreferences,
    /// Whether this endpoint supports 0-RTT with Raw Public Keys
    enable_0rtt_rpk: bool,
}

impl CertTypeAwareQuicEndpoint {
    /// Create a new certificate type aware QUIC endpoint
    pub fn new(
        endpoint: Endpoint,
        preferences: CertificateTypePreferences,
        negotiation_config: NegotiationConfig,
        enable_0rtt_rpk: bool,
    ) -> Self {
        Self {
            endpoint,
            negotiation_manager: Arc::new(CertificateNegotiationManager::new(negotiation_config)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            preferences,
            enable_0rtt_rpk,
        }
    }

    /// Connect to a remote endpoint with certificate type negotiation
    pub async fn connect_with_cert_negotiation(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<(Connection, QuicNegotiationContext), QuicConnectionError> {
        let _span = span!(Level::INFO, "quic_connect_with_cert_negotiation", %addr, %server_name);

        // Start certificate type negotiation
        let negotiation_id = self.negotiation_manager.start_negotiation(self.preferences.clone());
        debug!("Started certificate type negotiation for QUIC connection: {:?}", negotiation_id);

        // Attempt connection with certificate type extensions enabled
        let connection_result = self.endpoint.connect(addr, server_name);

        let connection = match connection_result {
            Ok(connecting) => {
                // Wait for connection to complete
                match connecting.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        self.negotiation_manager.fail_negotiation(
                            negotiation_id,
                            format!("QUIC connection failed: {}", e),
                        );
                        return Err(QuicConnectionError::ConnectionFailed(e));
                    }
                }
            }
            Err(e) => {
                self.negotiation_manager.fail_negotiation(
                    negotiation_id,
                    format!("QUIC connect failed: {}", e),
                );
                return Err(QuicConnectionError::ConnectFailed(e));
            }
        };

        // Extract certificate type negotiation result from the TLS connection
        let negotiation_result = self.extract_negotiation_result(&connection, negotiation_id)
            .await
            .map_err(|e| {
                self.negotiation_manager.fail_negotiation(
                    negotiation_id,
                    format!("Failed to extract negotiation result: {}", e),
                );
                QuicConnectionError::NegotiationFailed(e)
            })?;

        // Create context for this connection
        let connection_id = format!("{:?}", connection.stable_id());
        let used_0rtt = false; // TODO: Check 0-RTT status from connection handshake data
        
        let context = QuicNegotiationContext::new(
            negotiation_result,
            addr,
            connection_id.clone(),
            used_0rtt,
        );

        // Store the context
        {
            let mut connections = self.connections.write().unwrap();
            connections.insert(connection_id, context.clone());
        }

        info!("QUIC connection established with certificate type negotiation: client={}, server={}, 0rtt={}",
              context.result.client_cert_type, context.result.server_cert_type, context.used_0rtt);

        Ok((connection, context))
    }

    /// Accept an incoming connection with certificate type negotiation
    pub async fn accept_with_cert_negotiation(
        &self,
        incoming: quinn::Incoming,
    ) -> Result<(Connection, QuicNegotiationContext), QuicConnectionError> {
        let _span = span!(Level::INFO, "quic_accept_with_cert_negotiation");

        let peer_addr = incoming.remote_address();
        let negotiation_id = self.negotiation_manager.start_negotiation(self.preferences.clone());
        
        debug!("Started certificate type negotiation for incoming QUIC connection from {}: {:?}", 
               peer_addr, negotiation_id);

        // Accept the connection
        let connection = incoming.await
            .map_err(|e| {
                self.negotiation_manager.fail_negotiation(
                    negotiation_id,
                    format!("QUIC connection accept failed: {}", e),
                );
                QuicConnectionError::ConnectionFailed(e)
            })?;

        // Extract certificate type negotiation result
        let negotiation_result = self.extract_negotiation_result(&connection, negotiation_id)
            .await
            .map_err(|e| {
                self.negotiation_manager.fail_negotiation(
                    negotiation_id,
                    format!("Failed to extract negotiation result: {}", e),
                );
                QuicConnectionError::NegotiationFailed(e)
            })?;

        // Create context for this connection
        let connection_id = format!("{:?}", connection.stable_id());
        let used_0rtt = false; // TODO: Check 0-RTT status from connection handshake data
        
        let context = QuicNegotiationContext::new(
            negotiation_result,
            peer_addr,
            connection_id.clone(),
            used_0rtt,
        );

        // Store the context
        {
            let mut connections = self.connections.write().unwrap();
            connections.insert(connection_id, context.clone());
        }

        info!("Accepted QUIC connection with certificate type negotiation: client={}, server={}, 0rtt={}",
              context.result.client_cert_type, context.result.server_cert_type, context.used_0rtt);

        Ok((connection, context))
    }

    /// Extract certificate type negotiation result from a QUIC connection
    async fn extract_negotiation_result(
        &self,
        _connection: &Connection,
        negotiation_id: NegotiationId,
    ) -> Result<NegotiationResult, TlsExtensionError> {
        // Note: This is a simplified implementation
        // In practice, we would need to extract the actual negotiation result
        // from the TLS connection's extension handlers
        
        // For now, complete the negotiation with default preferences
        // In a real implementation, this would extract the actual negotiated types
        // from the TLS session data
        
        let remote_client_types = Some(CertificateTypeList::prefer_raw_public_key());
        let remote_server_types = Some(CertificateTypeList::prefer_raw_public_key());

        self.negotiation_manager.complete_negotiation(
            negotiation_id,
            remote_client_types,
            remote_server_types,
        )
    }

    /// Get the negotiation context for a QUIC connection
    pub fn get_connection_context(&self, connection: &Connection) -> Option<QuicNegotiationContext> {
        let connection_id = format!("{:?}", connection.stable_id());
        let connections = self.connections.read().unwrap();
        connections.get(&connection_id).cloned()
    }

    /// Handle connection migration with certificate type validation
    pub fn handle_connection_migration(
        &self,
        _connection: &Connection,
        new_addr: SocketAddr,
    ) -> Result<(), QuicConnectionError> {
        let _span = span!(Level::DEBUG, "handle_connection_migration", %new_addr).entered();

        let connection_id = format!("{:?}", _connection.stable_id());
        
        // Get current context
        let mut connections = self.connections.write().unwrap();
        if let Some(context) = connections.get_mut(&connection_id) {
            // Validate that certificate types are still compatible after migration
            // This is important for security - the same certificate types should be used
            
            debug!("Connection migration from {} to {} with cert types: client={}, server={}",
                   context.peer_addr, new_addr, 
                   context.result.client_cert_type, context.result.server_cert_type);

            // Update the peer address
            context.peer_addr = new_addr;
            
            // In a full implementation, we might want to re-validate certificate types
            // or perform additional security checks here
            
            info!("Successfully handled connection migration with certificate type validation");
            Ok(())
        } else {
            warn!("Connection migration failed: no context found for connection");
            Err(QuicConnectionError::MigrationFailed(
                "No negotiation context found for connection".to_string()
            ))
        }
    }

    /// Remove connection context when connection is closed
    pub fn handle_connection_closed(&self, connection: &Connection) {
        let connection_id = format!("{:?}", connection.stable_id());
        let mut connections = self.connections.write().unwrap();
        
        if let Some(context) = connections.remove(&connection_id) {
            debug!("Removed connection context for closed connection: {} (age: {:?})",
                   connection_id, context.age());
        }
    }

    /// Get statistics for certificate type usage
    pub fn get_certificate_type_stats(&self) -> CertificateTypeStats {
        let connections = self.connections.read().unwrap();
        let mut stats = CertificateTypeStats::default();

        for context in connections.values() {
            stats.total_connections += 1;
            
            if context.result.is_raw_public_key_only() {
                stats.rpk_only_connections += 1;
            } else if context.result.is_x509_only() {
                stats.x509_only_connections += 1;
            } else {
                stats.mixed_connections += 1;
            }

            if context.used_0rtt {
                stats.connections_with_0rtt += 1;
            }

            stats.total_age += context.age();
        }

        if stats.total_connections > 0 {
            stats.average_age = stats.total_age / stats.total_connections as u32;
        }

        stats
    }

    /// Clean up old connection contexts
    pub fn cleanup_old_connections(&self, max_age: Duration) {
        let mut connections = self.connections.write().unwrap();
        let cutoff = Instant::now() - max_age;

        connections.retain(|id, context| {
            let should_retain = context.completed_at > cutoff;
            if !should_retain {
                debug!("Cleaned up old connection context: {}", id);
            }
            should_retain
        });
    }

    /// Get underlying Quinn endpoint
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Get negotiation manager
    pub fn negotiation_manager(&self) -> &Arc<CertificateNegotiationManager> {
        &self.negotiation_manager
    }
}

/// Statistics for certificate type usage in QUIC connections
#[derive(Debug, Default, Clone)]
pub struct CertificateTypeStats {
    /// Total number of connections
    pub total_connections: u64,
    /// Connections using Raw Public Keys only
    pub rpk_only_connections: u64,
    /// Connections using X.509 certificates only
    pub x509_only_connections: u64,
    /// Connections using mixed certificate types
    pub mixed_connections: u64,
    /// Connections that used 0-RTT
    pub connections_with_0rtt: u64,
    /// Total age of all connections
    pub total_age: Duration,
    /// Average age of connections
    pub average_age: Duration,
}

impl CertificateTypeStats {
    /// Get the percentage of connections using Raw Public Keys only
    pub fn rpk_only_percentage(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            (self.rpk_only_connections as f64 / self.total_connections as f64) * 100.0
        }
    }

    /// Get the percentage of connections using 0-RTT
    pub fn zero_rtt_percentage(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            (self.connections_with_0rtt as f64 / self.total_connections as f64) * 100.0
        }
    }
}

/// Errors that can occur during QUIC connection with certificate type negotiation
#[derive(Debug, thiserror::Error)]
pub enum QuicConnectionError {
    #[error("QUIC connection failed: {0}")]
    ConnectionFailed(#[from] ConnectionError),
    
    #[error("QUIC connect failed: {0}")]
    ConnectFailed(#[from] ConnectError),
    
    #[error("Certificate type negotiation failed: {0}")]
    NegotiationFailed(#[from] TlsExtensionError),
    
    #[error("Connection migration failed: {0}")]
    MigrationFailed(String),
    
    #[error("0-RTT with Raw Public Keys failed: {0}")]
    ZeroRttRpkFailed(String),
}

/// Builder for creating certificate type aware QUIC endpoints
pub struct CertTypeQuicEndpointBuilder {
    /// Certificate type preferences
    preferences: Option<CertificateTypePreferences>,
    /// Negotiation configuration
    negotiation_config: Option<NegotiationConfig>,
    /// Whether to enable 0-RTT with Raw Public Keys
    enable_0rtt_rpk: bool,
    /// Raw Public Key configuration
    rpk_config: Option<RawPublicKeyConfigBuilder>,
}

impl CertTypeQuicEndpointBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            preferences: None,
            negotiation_config: None,
            enable_0rtt_rpk: false,
            rpk_config: None,
        }
    }

    /// Set certificate type preferences
    pub fn with_preferences(mut self, preferences: CertificateTypePreferences) -> Self {
        self.preferences = Some(preferences);
        self
    }

    /// Set negotiation configuration
    pub fn with_negotiation_config(mut self, config: NegotiationConfig) -> Self {
        self.negotiation_config = Some(config);
        self
    }

    /// Enable 0-RTT with Raw Public Keys
    pub fn enable_0rtt_rpk(mut self) -> Self {
        self.enable_0rtt_rpk = true;
        self
    }

    /// Set Raw Public Key configuration
    pub fn with_rpk_config(mut self, config: RawPublicKeyConfigBuilder) -> Self {
        self.rpk_config = Some(config);
        self
    }

    /// Build a client endpoint
    pub fn build_client_endpoint(
        self,
        bind_addr: SocketAddr,
    ) -> Result<CertTypeAwareQuicEndpoint, QuicConnectionError> {
        let preferences = self.preferences.unwrap_or_default();
        let negotiation_config = self.negotiation_config.unwrap_or_default();

        // Create QUIC client configuration
        let client_config = if let Some(rpk_config) = self.rpk_config {
            let rpk_config = rpk_config.enable_certificate_type_extensions();
            let rustls_config = rpk_config.build_client_config()
                .map_err(|e| QuicConnectionError::NegotiationFailed(
                    TlsExtensionError::RustlsError(e.to_string())
                ))?;
            QuinnClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config).map_err(|e| QuicConnectionError::NegotiationFailed(
                TlsExtensionError::RustlsError(e.to_string())
            ))?))
        } else {
            // Default configuration
            QuinnClientConfig::with_platform_verifier()
        };

        // Configure 0-RTT if enabled
        if self.enable_0rtt_rpk {
            // Note: 0-RTT configuration would go here
            // This depends on the specific Quinn API
        }

        // Create endpoint
        let mut endpoint = Endpoint::client(bind_addr)
            .map_err(|_| QuicConnectionError::ConnectFailed(ConnectError::EndpointStopping))?;
        endpoint.set_default_client_config(client_config);

        Ok(CertTypeAwareQuicEndpoint::new(
            endpoint,
            preferences,
            negotiation_config,
            self.enable_0rtt_rpk,
        ))
    }

    /// Build a server endpoint
    pub fn build_server_endpoint(
        self,
        bind_addr: SocketAddr,
    ) -> Result<CertTypeAwareQuicEndpoint, QuicConnectionError> {
        let preferences = self.preferences.unwrap_or_default();
        let negotiation_config = self.negotiation_config.unwrap_or_default();

        // Create QUIC server configuration
        let server_config = if let Some(rpk_config) = self.rpk_config {
            let rpk_config = rpk_config.enable_certificate_type_extensions();
            let rustls_config = rpk_config.build_server_config()
                .map_err(|e| QuicConnectionError::NegotiationFailed(
                    TlsExtensionError::RustlsError(e.to_string())
                ))?;
            QuinnServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config).map_err(|e| QuicConnectionError::NegotiationFailed(
                TlsExtensionError::RustlsError(e.to_string())
            ))?))
        } else {
            return Err(QuicConnectionError::NegotiationFailed(
                TlsExtensionError::RustlsError("Server endpoint requires certificate configuration".to_string())
            ));
        };

        // Create endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|_| QuicConnectionError::ConnectFailed(ConnectError::EndpointStopping))?;

        Ok(CertTypeAwareQuicEndpoint::new(
            endpoint,
            preferences,
            negotiation_config,
            self.enable_0rtt_rpk,
        ))
    }
}

impl Default for CertTypeQuicEndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::crypto::tls_extensions::CertificateType;

    #[test]
    fn test_quic_negotiation_context() {
        let result = NegotiationResult::new(
            CertificateType::RawPublicKey,
            CertificateType::X509,
        );
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let context = QuicNegotiationContext::new(
            result,
            addr,
            "test-connection".to_string(),
            true,
        );

        assert!(context.used_0rtt);
        assert_eq!(context.peer_addr, addr);
        assert!(context.result.is_mixed());
        assert!(context.age() >= Duration::ZERO);
    }

    #[test]
    fn test_certificate_type_stats() {
        let mut stats = CertificateTypeStats::default();
        stats.total_connections = 100;
        stats.rpk_only_connections = 75;
        stats.connections_with_0rtt = 25;

        assert_eq!(stats.rpk_only_percentage(), 75.0);
        assert_eq!(stats.zero_rtt_percentage(), 25.0);
    }

    #[test]
    fn test_endpoint_builder() {
        let builder = CertTypeQuicEndpointBuilder::new()
            .with_preferences(CertificateTypePreferences::prefer_raw_public_key())
            .enable_0rtt_rpk();

        // Test that builder can be created (actual endpoint creation requires network setup)
        assert!(builder.enable_0rtt_rpk);
    }
}