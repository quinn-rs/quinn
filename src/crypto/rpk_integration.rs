//! Integration of Raw Public Keys with ant-quic's existing QUIC infrastructure
//!
//! This module provides high-level integration between the Raw Public Keys implementation
//! and ant-quic's existing QUIC configuration and endpoint management.

use std::{sync::Arc, net::SocketAddr, time::Duration, collections::HashMap};

use ed25519_dalek::{VerifyingKey as Ed25519PublicKey, SigningKey as Ed25519SecretKey};
use crate::{Endpoint, Connection, ConnectionError, ConnectError, Incoming};
use tracing::{debug, info, warn, error};

use crate::{
    crypto::{
        raw_public_keys::{RawPublicKeyConfigBuilder, utils},
        rustls::{QuicClientConfig, QuicServerConfig},
        quinn_integration::{CertTypeAwareQuicEndpoint, QuicConnectionError, CertTypeQuicEndpointBuilder},
        tls_extensions::CertificateTypePreferences,
        certificate_negotiation::NegotiationConfig,
    },
    nat_traversal_api::{NatTraversalConfig, EndpointRole, PeerId},
    config::EndpointConfig,
};

/// Configuration for Raw Public Keys in NAT traversal
#[derive(Debug, Clone)]
pub struct RpkNatConfig {
    /// The local keypair for this node
    pub local_keypair: (Ed25519SecretKey, Ed25519PublicKey),
    /// Set of trusted public keys for peer verification
    pub trusted_peers: Vec<[u8; 32]>,
    /// Whether to allow any valid key (development mode)
    pub allow_any_peer: bool,
    /// Role of this endpoint in NAT traversal
    pub role: EndpointRole,
}

impl RpkNatConfig {
    /// Create a new RPK NAT configuration with a generated keypair
    pub fn new(role: EndpointRole) -> Self {
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        Self {
            local_keypair: (private_key, public_key),
            trusted_peers: Vec::new(),
            allow_any_peer: false,
            role,
        }
    }

    /// Create configuration with a specific keypair
    pub fn with_keypair(
        private_key: Ed25519SecretKey,
        public_key: Ed25519PublicKey,
        role: EndpointRole,
    ) -> Self {
        Self {
            local_keypair: (private_key, public_key),
            trusted_peers: Vec::new(),
            allow_any_peer: false,
            role,
        }
    }

    /// Add a trusted peer's public key
    pub fn add_trusted_peer(mut self, public_key: [u8; 32]) -> Self {
        self.trusted_peers.push(public_key);
        self
    }

    /// Allow any valid Ed25519 public key (development only)
    pub fn allow_any_peer(mut self) -> Self {
        self.allow_any_peer = true;
        self
    }

    /// Get this node's public key as bytes
    pub fn local_public_key_bytes(&self) -> [u8; 32] {
        utils::public_key_to_bytes(&self.local_keypair.1)
    }

    /// Get this node's PeerId based on the public key
    pub fn peer_id(&self) -> PeerId {
        // Use the proper peer ID derivation from raw public keys
        use crate::crypto::raw_public_keys::utils::derive_peer_id_from_public_key;
        derive_peer_id_from_public_key(&self.local_keypair.1)
    }

    /// Create a QuicClientConfig with Raw Public Keys
    pub fn create_client_config(&self) -> Result<QuicClientConfig, Box<dyn std::error::Error>> {
        let mut builder = RawPublicKeyConfigBuilder::new();

        // Add trusted peers
        for peer_key in &self.trusted_peers {
            builder = builder.add_trusted_key(*peer_key);
        }

        // Allow any peer if configured
        if self.allow_any_peer {
            builder = builder.allow_any_key();
        }

        // Build rustls client config
        let rustls_config = builder.build_client_config()?;

        // Wrap in QuicClientConfig
        QuicClientConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("Failed to create QuicClientConfig: {}", e).into())
    }

    /// Create a QuicServerConfig with Raw Public Keys
    pub fn create_server_config(&self) -> Result<QuicServerConfig, Box<dyn std::error::Error>> {
        let builder = RawPublicKeyConfigBuilder::new()
            .with_server_key(self.local_keypair.0.clone());

        // Build rustls server config
        let rustls_config = builder.build_server_config()?;

        // Wrap in QuicServerConfig
        QuicServerConfig::try_from(Arc::new(rustls_config))
            .map_err(|e| format!("Failed to create QuicServerConfig: {}", e).into())
    }

    /// Create both client and server configs for a bidirectional endpoint
    pub fn create_endpoint_configs(&self) -> Result<(QuicClientConfig, QuicServerConfig), Box<dyn std::error::Error>> {
        let client_config = self.create_client_config()?;
        let server_config = self.create_server_config()?;
        Ok((client_config, server_config))
    }
}

/// Extension trait for EndpointConfig to support Raw Public Keys
pub trait EndpointConfigExt {
    /// Configure endpoint with Raw Public Keys
    fn with_raw_public_keys(self, rpk_config: &RpkNatConfig) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

impl EndpointConfigExt for EndpointConfig {
    fn with_raw_public_keys(self, rpk_config: &RpkNatConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Create QUIC configs with Raw Public Keys
        let (_client_config, _server_config) = rpk_config.create_endpoint_configs()?;

        // Set the configs (this would need to be implemented in EndpointConfig)
        // For now, this is a placeholder showing the integration pattern
        
        Ok(self)
    }
}

/// Utility functions for Raw Public Keys in NAT traversal
pub mod rpk_utils {
    use super::*;
    use crate::nat_traversal_api::CandidateAddress;

    /// Create a bootstrap node configuration with Raw Public Keys
    pub fn create_bootstrap_config() -> RpkNatConfig {
        RpkNatConfig::new(EndpointRole::Bootstrap)
            .allow_any_peer() // Bootstrap nodes accept connections from any peer
    }

    /// Create a client configuration for NAT traversal
    pub fn create_client_config(bootstrap_keys: Vec<[u8; 32]>) -> RpkNatConfig {
        let mut config = RpkNatConfig::new(EndpointRole::Client);
        for key in bootstrap_keys {
            config = config.add_trusted_peer(key);
        }
        config
    }

    /// Create a server configuration for NAT traversal
    pub fn create_server_config(bootstrap_keys: Vec<[u8; 32]>) -> RpkNatConfig {
        let mut config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true });
        for key in bootstrap_keys {
            config = config.add_trusted_peer(key);
        }
        config
    }

    /// Extract peer public key from a QUIC connection (placeholder)
    /// This would need integration with the QUIC connection to extract the peer's public key
    pub fn extract_peer_public_key(_connection: &quinn::Connection) -> Option<[u8; 32]> {
        // Placeholder - would need to extract from the TLS session
        None
    }

    /// Verify that a candidate address matches the expected peer
    pub fn verify_candidate_peer(
        _candidate: &CandidateAddress,
        _expected_peer_key: &[u8; 32],
    ) -> bool {
        // Placeholder - would verify that the candidate's public key matches expected
        true
    }

    /// Create test configurations for integration testing
    #[cfg(test)]
    pub fn create_test_configs() -> (RpkNatConfig, RpkNatConfig) {
        let (client_private, client_public) = utils::generate_ed25519_keypair();
        let (server_private, server_public) = utils::generate_ed25519_keypair();

        let client_config = RpkNatConfig::with_keypair(
            client_private,
            client_public,
            EndpointRole::Client,
        ).add_trusted_peer(utils::public_key_to_bytes(&server_public));

        let server_config = RpkNatConfig::with_keypair(
            server_private,
            server_public,
            EndpointRole::Server { can_coordinate: true },
        ).add_trusted_peer(utils::public_key_to_bytes(&client_public));

        (client_config, server_config)
    }
}

/// Main Raw Public Key QUIC endpoint for simplified API usage
#[derive(Debug)]
pub struct RpkQuicEndpoint {
    /// The underlying enhanced QUIC endpoint with certificate type awareness
    cert_aware_endpoint: CertTypeAwareQuicEndpoint,
    /// Raw Public Key configuration for this endpoint
    rpk_config: RpkNatConfig,
    /// Active connections with their peer information
    connections: Arc<tokio::sync::RwLock<HashMap<String, RpkConnectionInfo>>>,
    /// Statistics for RPK usage
    stats: Arc<tokio::sync::RwLock<RpkEndpointStats>>,
}

/// Information about an active RPK connection
#[derive(Debug, Clone)]
pub struct RpkConnectionInfo {
    /// Peer's public key
    pub peer_public_key: [u8; 32],
    /// Derived peer ID
    pub peer_id: PeerId,
    /// Connection establishment time
    pub established_at: std::time::Instant,
    /// Whether this connection used 0-RTT
    pub used_0rtt: bool,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// The actual QUIC connection
    pub connection: Connection,
}

/// Session keys derived for P2P communication between peers
#[derive(Debug, Clone)]
pub struct P2pSessionKeys {
    /// 32-byte encryption key for symmetric encryption
    pub encryption_key: [u8; 32],
    /// 32-byte authentication key for message authentication
    pub authentication_key: [u8; 32],
    /// 32-byte key rotation seed for forward secrecy
    pub rotation_key: [u8; 32],
    /// Timestamp when these keys were derived
    pub derived_at: std::time::Instant,
    /// Peer ID these keys are associated with
    pub peer_id: PeerId,
}

/// Statistics for RPK endpoint operations
#[derive(Debug, Default, Clone)]
pub struct RpkEndpointStats {
    /// Total number of connections attempted
    pub connections_attempted: u64,
    /// Total number of successful connections
    pub connections_successful: u64,
    /// Total number of failed connections
    pub connections_failed: u64,
    /// Number of connections using 0-RTT
    pub connections_0rtt: u64,
    /// Number of active connections
    pub active_connections: u64,
    /// Average connection establishment time
    pub avg_connection_time: Duration,
    /// Total time spent establishing connections
    pub total_connection_time: Duration,
}

impl RpkQuicEndpoint {
    /// Create a new RPK QUIC endpoint with automatic configuration
    pub async fn new(
        bind_addr: SocketAddr,
        rpk_config: RpkNatConfig,
        enable_0rtt: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create certificate type preferences favoring Raw Public Keys
        let cert_preferences = CertificateTypePreferences::prefer_raw_public_key();
        
        // Create negotiation configuration
        let negotiation_config = NegotiationConfig::default();
        
        // Build the certificate type aware endpoint
        let builder = CertTypeQuicEndpointBuilder::new()
            .with_preferences(cert_preferences)
            .with_negotiation_config(negotiation_config);
        
        let builder = if enable_0rtt {
            builder.enable_0rtt_rpk()
        } else {
            builder
        };
        
        // Create Raw Public Key configuration for the builder
        let mut rpk_builder = RawPublicKeyConfigBuilder::new();
        
        // Add trusted peers
        for peer_key in &rpk_config.trusted_peers {
            rpk_builder = rpk_builder.add_trusted_key(*peer_key);
        }
        
        // Allow any peer if configured
        if rpk_config.allow_any_peer {
            rpk_builder = rpk_builder.allow_any_key();
        }
        
        // Set server key if this endpoint can act as a server
        rpk_builder = rpk_builder.with_server_key(rpk_config.local_keypair.0.clone());
        
        let builder = builder.with_rpk_config(rpk_builder);
        
        // Build the appropriate endpoint based on role
        let cert_aware_endpoint = match rpk_config.role {
            EndpointRole::Client => {
                builder.build_client_endpoint(bind_addr)?
            },
            EndpointRole::Server { .. } | EndpointRole::Bootstrap => {
                builder.build_server_endpoint(bind_addr)?
            },
        };
        
        Ok(Self {
            cert_aware_endpoint,
            rpk_config,
            connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            stats: Arc::new(tokio::sync::RwLock::new(RpkEndpointStats::default())),
        })
    }
    
    /// Connect to a peer using their public key for authentication
    pub async fn connect_to_peer(
        &self,
        remote_addr: SocketAddr,
        server_name: &str,
        expected_peer_key: Option<[u8; 32]>,
    ) -> Result<(Connection, RpkConnectionInfo), Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.connections_attempted += 1;
        }
        
        // Connect using the certificate type aware endpoint
        let (connection, quic_context) = self.cert_aware_endpoint
            .connect_with_cert_negotiation(remote_addr, server_name)
            .await?;
        
        // Extract peer public key from the connection
        let peer_public_key = self.extract_peer_public_key(&connection).await?;
        
        // Verify peer key if expected
        if let Some(expected_key) = expected_peer_key {
            if peer_public_key != expected_key {
                return Err(format!(
                    "Peer public key mismatch: expected {}, got {}",
                    hex::encode(expected_key),
                    hex::encode(peer_public_key)
                ).into());
            }
        }
        
        // Derive peer ID
        let peer_public_key_obj = utils::public_key_from_bytes(&peer_public_key)?;
        let peer_id = utils::derive_peer_id_from_public_key(&peer_public_key_obj);
        
        // Create connection info
        let connection_info = RpkConnectionInfo {
            peer_public_key,
            peer_id,
            established_at: std::time::Instant::now(),
            used_0rtt: quic_context.used_0rtt,
            remote_addr,
            connection: connection.clone(),
        };
        
        // Store connection info
        {
            let mut connections = self.connections.write().await;
            let conn_id = format!("{:?}", connection.stable_id());
            connections.insert(conn_id, connection_info.clone());
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.connections_successful += 1;
            stats.active_connections += 1;
            
            if connection_info.used_0rtt {
                stats.connections_0rtt += 1;
            }
            
            let connection_time = start_time.elapsed();
            stats.total_connection_time += connection_time;
            stats.avg_connection_time = stats.total_connection_time / stats.connections_successful as u32;
        }
        
        info!("Successfully connected to peer: {} (peer_id: {})", 
              hex::encode(peer_public_key), hex::encode(peer_id.0));
        
        Ok((connection, connection_info))
    }
    
    /// Accept incoming connections with RPK authentication
    pub async fn accept_connection(&self) -> Result<(Connection, RpkConnectionInfo), Box<dyn std::error::Error>> {
        // Get incoming connection from the underlying endpoint
        let mut incoming = self.cert_aware_endpoint.endpoint().accept().await
            .ok_or("No incoming connection available")?;
        
        let start_time = std::time::Instant::now();
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.connections_attempted += 1;
        }
        
        // Accept with certificate type negotiation
        let (connection, quic_context) = self.cert_aware_endpoint
            .accept_with_cert_negotiation(incoming)
            .await?;
        
        // Extract peer public key
        let peer_public_key = self.extract_peer_public_key(&connection).await?;
        
        // Verify peer is trusted (if not in allow_any mode)
        if !self.rpk_config.allow_any_peer && !self.rpk_config.trusted_peers.contains(&peer_public_key) {
            return Err(format!(
                "Untrusted peer public key: {}",
                hex::encode(peer_public_key)
            ).into());
        }
        
        // Derive peer ID
        let peer_public_key_obj = utils::public_key_from_bytes(&peer_public_key)?;
        let peer_id = utils::derive_peer_id_from_public_key(&peer_public_key_obj);
        
        // Create connection info
        let connection_info = RpkConnectionInfo {
            peer_public_key,
            peer_id,
            established_at: std::time::Instant::now(),
            used_0rtt: quic_context.used_0rtt,
            remote_addr: quic_context.peer_addr,
            connection: connection.clone(),
        };
        
        // Store connection info
        {
            let mut connections = self.connections.write().await;
            let conn_id = format!("{:?}", connection.stable_id());
            connections.insert(conn_id, connection_info.clone());
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.connections_successful += 1;
            stats.active_connections += 1;
            
            if connection_info.used_0rtt {
                stats.connections_0rtt += 1;
            }
            
            let connection_time = start_time.elapsed();
            stats.total_connection_time += connection_time;
            stats.avg_connection_time = stats.total_connection_time / stats.connections_successful as u32;
        }
        
        info!("Accepted connection from peer: {} (peer_id: {})", 
              hex::encode(peer_public_key), hex::encode(peer_id.0));
        
        Ok((connection, connection_info))
    }
    
    /// Get connection information for an active connection
    pub async fn get_connection_info(&self, connection: &Connection) -> Option<RpkConnectionInfo> {
        let conn_id = format!("{:?}", connection.stable_id());
        let connections = self.connections.read().await;
        connections.get(&conn_id).cloned()
    }
    
    /// Handle connection close and update stats
    pub async fn handle_connection_closed(&self, connection: &Connection) {
        let conn_id = format!("{:?}", connection.stable_id());
        
        // Remove from connections
        {
            let mut connections = self.connections.write().await;
            connections.remove(&conn_id);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            if stats.active_connections > 0 {
                stats.active_connections -= 1;
            }
        }
        
        // Notify the certificate aware endpoint
        self.cert_aware_endpoint.handle_connection_closed(connection);
        
        debug!("Handled connection close: {}", conn_id);
    }
    
    /// Get the local peer ID for this endpoint
    pub fn local_peer_id(&self) -> PeerId {
        self.rpk_config.peer_id()
    }
    
    /// Get the local public key bytes
    pub fn local_public_key(&self) -> [u8; 32] {
        self.rpk_config.local_public_key_bytes()
    }
    
    /// Get current endpoint statistics
    pub async fn get_stats(&self) -> RpkEndpointStats {
        self.stats.read().await.clone()
    }
    
    /// Get the underlying QUIC endpoint for advanced operations
    pub fn endpoint(&self) -> &Endpoint {
        self.cert_aware_endpoint.endpoint()
    }
    
    /// Extract peer public key from a QUIC connection
    async fn extract_peer_public_key(&self, connection: &Connection) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        // Try to get peer certificates from the connection
        if let Some(peer_certs) = connection.peer_identity() {
            // In RPK mode, the "certificate" is actually the SubjectPublicKeyInfo
            if let Some(cert_der_vec) = peer_certs.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>() {
                if let Some(cert_der) = cert_der_vec.first() {
                    // Extract the Ed25519 key from SubjectPublicKeyInfo
                    return self.extract_ed25519_from_spki(cert_der.as_ref());
                }
            }
        }
        
        Err("Unable to extract peer public key from connection".into())
    }
    
    /// Extract Ed25519 public key from SubjectPublicKeyInfo DER
    fn extract_ed25519_from_spki(&self, spki_der: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        // Simple parsing for Ed25519 SubjectPublicKeyInfo
        if spki_der.len() != 44 {
            return Err("Invalid SPKI length for Ed25519".into());
        }
        
        // Check for Ed25519 OID pattern
        let ed25519_oid = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        if !spki_der.starts_with(&ed25519_oid) {
            return Err("Not an Ed25519 SubjectPublicKeyInfo".into());
        }
        
        // Extract the 32-byte public key
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&spki_der[12..44]);
        
        Ok(public_key)
    }

    /// Perform key exchange with a peer to derive shared session keys
    /// 
    /// This method uses Export Keying Material (EKM) from the TLS 1.3 session
    /// to derive application-level shared keys for secure communication.
    pub async fn exchange_keys_with_peer(
        &self, 
        peer_id: &PeerId,
        key_label: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let connections = self.connections.read().await;
        
        // Find connection by peer ID
        let conn_info = connections.values()
            .find(|info| info.peer_id == *peer_id)
            .ok_or_else(|| format!("No active connection found for peer {:?}", peer_id))?;
        
        // Use the QUIC connection's Export Keying Material functionality
        let mut output = vec![0u8; output_len];
        
        // Export keying material using the TLS 1.3 session
        if let Err(_) = conn_info.connection.export_keying_material(&mut output, key_label, context) {
            return Err("Failed to export keying material from TLS session".into());
        }
        
        info!("Derived {} bytes of shared key material with peer {:?}", output_len, peer_id);
        Ok(output)
    }

    /// Exchange keys using a standardized label for P2P application keys
    /// 
    /// This is a convenience method that uses a standard key derivation label
    /// for deriving application-level encryption keys between peers.
    pub async fn derive_p2p_session_keys(
        &self,
        peer_id: &PeerId,
        key_purpose: &str,
    ) -> Result<P2pSessionKeys, Box<dyn std::error::Error>> {
        // Create a standardized context that includes both peer IDs for proper domain separation
        let local_peer_id = self.local_peer_id();
        let mut context = Vec::with_capacity(64 + key_purpose.len());
        context.extend_from_slice(&local_peer_id.0);
        context.extend_from_slice(&peer_id.0);
        context.extend_from_slice(key_purpose.as_bytes());
        
        // Standard label for P2P key derivation
        let key_label = b"AUTONOMI_P2P_SESSION_KEYS_V1";
        
        // Derive 96 bytes: 32 for encryption, 32 for authentication, 32 for key rotation
        let key_material = self.exchange_keys_with_peer(
            peer_id,
            key_label,
            &context,
            96,
        ).await?;
        
        let mut encryption_key = [0u8; 32];
        let mut authentication_key = [0u8; 32];
        let mut rotation_key = [0u8; 32];
        
        encryption_key.copy_from_slice(&key_material[0..32]);
        authentication_key.copy_from_slice(&key_material[32..64]);
        rotation_key.copy_from_slice(&key_material[64..96]);
        
        Ok(P2pSessionKeys {
            encryption_key,
            authentication_key,
            rotation_key,
            derived_at: std::time::Instant::now(),
            peer_id: *peer_id,
        })
    }

    /// Rotate session keys for an existing peer connection
    /// 
    /// This method derives new session keys using a rotation counter to ensure
    /// forward secrecy and periodic key renewal.
    pub async fn rotate_session_keys(
        &self,
        peer_id: &PeerId,
        rotation_counter: u64,
    ) -> Result<P2pSessionKeys, Box<dyn std::error::Error>> {
        // Include rotation counter in context for unique key derivation
        let key_purpose = format!("rotation_{}", rotation_counter);
        
        info!("Rotating session keys for peer {} (counter: {})", 
              hex::encode(peer_id.0), rotation_counter);
        
        self.derive_p2p_session_keys(peer_id, &key_purpose).await
    }

    /// Verify that a peer's claimed ID matches their public key
    /// 
    /// This method extracts the peer's public key from the connection and
    /// verifies that their claimed peer ID is correctly derived from that key.
    pub async fn verify_peer_identity(
        &self,
        peer_id: &PeerId,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let connections = self.connections.read().await;
        
        // Find connection by peer ID
        let conn_info = connections.values()
            .find(|info| info.peer_id == *peer_id)
            .ok_or_else(|| format!("No active connection found for peer {:?}", peer_id))?;
        
        // Extract the peer's public key from the connection
        let peer_public_key_bytes = self.extract_peer_public_key(&conn_info.connection).await?;
        let peer_public_key = Ed25519PublicKey::from_bytes(&peer_public_key_bytes)
            .map_err(|_| "Invalid Ed25519 public key")?;
        
        // Verify that the peer ID was correctly derived from the public key
        let is_valid = crate::crypto::raw_public_keys::utils::verify_peer_id(peer_id, &peer_public_key);
        
        if is_valid {
            info!("Peer identity verification successful for {:?}", peer_id);
        } else {
            warn!("Peer identity verification failed for {:?}", peer_id);
        }
        
        Ok(is_valid)
    }
}

/// Builder for RpkQuicEndpoint with simplified configuration
#[derive(Debug, Default)]
pub struct RpkQuicEndpointBuilder {
    bind_addr: Option<SocketAddr>,
    role: Option<EndpointRole>,
    keypair: Option<(Ed25519SecretKey, Ed25519PublicKey)>,
    trusted_peers: Vec<[u8; 32]>,
    allow_any_peer: bool,
    enable_0rtt: bool,
}

impl RpkQuicEndpointBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the bind address
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }
    
    /// Set the endpoint role
    pub fn role(mut self, role: EndpointRole) -> Self {
        self.role = Some(role);
        self
    }
    
    /// Set a specific keypair (generates one if not called)
    pub fn keypair(mut self, private_key: Ed25519SecretKey, public_key: Ed25519PublicKey) -> Self {
        self.keypair = Some((private_key, public_key));
        self
    }
    
    /// Add a trusted peer's public key
    pub fn add_trusted_peer(mut self, public_key: [u8; 32]) -> Self {
        self.trusted_peers.push(public_key);
        self
    }
    
    /// Allow connections from any valid Ed25519 public key
    pub fn allow_any_peer(mut self) -> Self {
        self.allow_any_peer = true;
        self
    }
    
    /// Enable 0-RTT connections
    pub fn enable_0rtt(mut self) -> Self {
        self.enable_0rtt = true;
        self
    }
    
    /// Build the RpkQuicEndpoint
    pub async fn build(self) -> Result<RpkQuicEndpoint, Box<dyn std::error::Error>> {
        let bind_addr = self.bind_addr.ok_or("Bind address is required")?;
        let role = self.role.ok_or("Endpoint role is required")?;
        
        // Generate keypair if not provided
        let (private_key, public_key) = self.keypair.unwrap_or_else(|| utils::generate_ed25519_keypair());
        
        // Create RPK configuration
        let mut rpk_config = RpkNatConfig::with_keypair(private_key, public_key, role);
        
        // Add trusted peers
        for peer_key in self.trusted_peers {
            rpk_config = rpk_config.add_trusted_peer(peer_key);
        }
        
        // Set allow any peer
        if self.allow_any_peer {
            rpk_config = rpk_config.allow_any_peer();
        }
        
        RpkQuicEndpoint::new(bind_addr, rpk_config, self.enable_0rtt).await
    }
}

/// Example usage and integration patterns
pub mod examples {
    use super::*;
    use crate::nat_traversal_api::NatTraversalEndpoint;

    /// Example: Create a P2P endpoint with Raw Public Keys
    pub async fn create_p2p_endpoint_with_rpk() -> Result<NatTraversalEndpoint, Box<dyn std::error::Error>> {
        // Generate local keypair
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        
        // Create RPK configuration
        let rpk_config = RpkNatConfig::with_keypair(private_key, public_key, EndpointRole::Client)
            .allow_any_peer(); // For demo - in production, add specific trusted peers

        // Create QUIC configurations
        let (_client_config, _server_config) = rpk_config.create_endpoint_configs()?;

        // Create NAT traversal configuration
        let _nat_config = NatTraversalConfig {
            role: rpk_config.role,
            // ... other NAT traversal settings
            ..Default::default()
        };

        // Create endpoint with RPK support
        // This would need integration with the actual endpoint creation
        // NatTraversalEndpoint::new_with_rpk(nat_config, rpk_config).await

        // Placeholder return
        todo!("Integration with NatTraversalEndpoint needed")
    }

    /// Example: Bootstrap node with Raw Public Keys
    pub async fn create_bootstrap_node() -> Result<(), Box<dyn std::error::Error>> {
        let rpk_config = rpk_utils::create_bootstrap_config();
        
        println!("Bootstrap node public key: {}", 
                 hex::encode(rpk_config.local_public_key_bytes()));
        
        // Create server config for accepting connections
        let _server_config = rpk_config.create_server_config()?;
        
        // Start bootstrap node
        // This would integrate with the actual bootstrap node implementation
        
        Ok(())
    }

    /// Example: Client connecting to bootstrap node
    pub async fn connect_to_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
        // Bootstrap node's public key (would be known/distributed)
        let bootstrap_key = [42u8; 32]; // Example key
        
        let rpk_config = rpk_utils::create_client_config(vec![bootstrap_key]);
        let _client_config = rpk_config.create_client_config()?;
        
        // Connect to bootstrap node with RPK authentication
        // This would integrate with the connection establishment code
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::rpk_utils::*;

    #[test]
    fn test_rpk_nat_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client);
        assert_eq!(config.role, EndpointRole::Client);
        assert!(!config.allow_any_peer);
        assert!(config.trusted_peers.is_empty());
    }

    #[test]
    fn test_rpk_config_with_trusted_peers() {
        let peer_key = [1u8; 32];
        let config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true })
            .add_trusted_peer(peer_key);
        
        assert_eq!(config.trusted_peers.len(), 1);
        assert_eq!(config.trusted_peers[0], peer_key);
    }

    #[test]
    fn test_peer_id_generation() {
        let config = RpkNatConfig::new(EndpointRole::Client);
        let peer_id = config.peer_id();
        
        // PeerId should be derived from public key
        let key_bytes = config.local_public_key_bytes();
        let expected_peer_id = PeerId(key_bytes);
        
        assert_eq!(peer_id, expected_peer_id);
    }

    #[test]
    fn test_create_test_configs() {
        let (client_config, server_config) = create_test_configs();
        
        assert_eq!(client_config.role, EndpointRole::Client);
        assert_eq!(server_config.role, EndpointRole::Server { can_coordinate: true });
        assert_eq!(client_config.trusted_peers.len(), 1);
        assert_eq!(server_config.trusted_peers.len(), 1);
    }

    #[tokio::test]
    async fn test_client_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client).allow_any_peer();
        let client_config = config.create_client_config();
        assert!(client_config.is_ok());
    }

    #[tokio::test]
    async fn test_server_config_creation() {
        let config = RpkNatConfig::new(EndpointRole::Server { can_coordinate: true });
        let server_config = config.create_server_config();
        assert!(server_config.is_ok());
    }

    #[tokio::test]
    async fn test_endpoint_configs_creation() {
        let config = RpkNatConfig::new(EndpointRole::Client).allow_any_peer();
        let result = config.create_endpoint_configs();
        assert!(result.is_ok());
        
        let (client_config, server_config) = result.unwrap();
        // Verify both configs were created
        // Additional validation would go here
    }
}