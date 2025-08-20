// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! TLS Extension Simulation for RFC 7250 Raw Public Keys
//!
//! Since rustls 0.23.x doesn't expose APIs for custom TLS extensions,
//! this module simulates the RFC 7250 certificate type negotiation
//! through alternative mechanisms that work within rustls constraints.

use crate::crypto::{ClientConfig as QuicClientConfig, ServerConfig as QuicServerConfig};
use rustls::{ClientConfig, ServerConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::tls_extensions::{
    CertificateTypeList, CertificateTypePreferences, NegotiationResult, TlsExtensionError,
};

/// Trait for hooking into TLS handshake events
pub trait TlsExtensionHooks: Send + Sync {
    /// Called when the handshake is complete
    fn on_handshake_complete(&self, conn_id: &str, is_client: bool);

    /// Called to get extension data for ClientHello
    fn get_client_hello_extensions(&self, conn_id: &str) -> Vec<(u16, Vec<u8>)>;

    /// Called to process ServerHello extensions
    fn process_server_hello_extensions(
        &self,
        conn_id: &str,
        extensions: &[(u16, Vec<u8>)],
    ) -> Result<(), TlsExtensionError>;

    /// Get the negotiation result for a connection
    fn get_negotiation_result(&self, conn_id: &str) -> Option<NegotiationResult>;
}

/// Simulated TLS extension context for certificate type negotiation
#[derive(Debug)]
pub struct SimulatedExtensionContext {
    /// Active negotiations indexed by connection ID
    negotiations: Arc<Mutex<HashMap<String, NegotiationState>>>,
    /// Local preferences for this endpoint
    local_preferences: CertificateTypePreferences,
}

#[derive(Debug, Clone)]
struct NegotiationState {
    local_preferences: CertificateTypePreferences,
    remote_client_types: Option<CertificateTypeList>,
    remote_server_types: Option<CertificateTypeList>,
    result: Option<NegotiationResult>,
}

impl SimulatedExtensionContext {
    /// Create a new simulated extension context
    pub fn new(preferences: CertificateTypePreferences) -> Self {
        Self {
            negotiations: Arc::new(Mutex::new(HashMap::new())),
            local_preferences: preferences,
        }
    }

    /// Simulate sending certificate type preferences
    /// In reality, this would be sent in ClientHello/ServerHello extensions
    pub fn simulate_send_preferences(&self, conn_id: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let mut negotiations = self.negotiations.lock().unwrap();

        let state = NegotiationState {
            local_preferences: self.local_preferences.clone(),
            remote_client_types: None,
            remote_server_types: None,
            result: None,
        };

        negotiations.insert(conn_id.to_string(), state);

        // Simulate extension data that would be sent
        let client_ext_data = self.local_preferences.client_types.to_bytes();
        let server_ext_data = self.local_preferences.server_types.to_bytes();

        (Some(client_ext_data), Some(server_ext_data))
    }

    /// Simulate receiving certificate type preferences from peer
    pub fn simulate_receive_preferences(
        &self,
        conn_id: &str,
        client_types_data: Option<&[u8]>,
        server_types_data: Option<&[u8]>,
    ) -> Result<(), TlsExtensionError> {
        let mut negotiations = self.negotiations.lock().unwrap();

        let state = negotiations.get_mut(conn_id).ok_or_else(|| {
            TlsExtensionError::InvalidExtensionData(format!(
                "No negotiation state for connection {conn_id}"
            ))
        })?;

        if let Some(data) = client_types_data {
            state.remote_client_types = Some(CertificateTypeList::from_bytes(data)?);
        }

        if let Some(data) = server_types_data {
            state.remote_server_types = Some(CertificateTypeList::from_bytes(data)?);
        }

        Ok(())
    }

    /// Complete the negotiation and get the result
    pub fn complete_negotiation(
        &self,
        conn_id: &str,
    ) -> Result<NegotiationResult, TlsExtensionError> {
        let mut negotiations = self.negotiations.lock().unwrap();

        let state = negotiations.get_mut(conn_id).ok_or_else(|| {
            TlsExtensionError::InvalidExtensionData(format!(
                "No negotiation state for connection {conn_id}"
            ))
        })?;

        if let Some(result) = &state.result {
            return Ok(result.clone());
        }

        let result = state.local_preferences.negotiate(
            state.remote_client_types.as_ref(),
            state.remote_server_types.as_ref(),
        )?;

        state.result = Some(result.clone());
        Ok(result)
    }

    /// Clean up negotiation state for a connection
    pub fn cleanup_connection(&self, conn_id: &str) {
        let mut negotiations = self.negotiations.lock().unwrap();
        negotiations.remove(conn_id);
    }
}

impl TlsExtensionHooks for SimulatedExtensionContext {
    fn on_handshake_complete(&self, conn_id: &str, _is_client: bool) {
        // Try to complete negotiation if not already done
        let _ = self.complete_negotiation(conn_id);
    }

    fn get_client_hello_extensions(&self, conn_id: &str) -> Vec<(u16, Vec<u8>)> {
        let (client_types, server_types) = self.simulate_send_preferences(conn_id);

        let mut extensions = Vec::new();

        if let Some(data) = client_types {
            extensions.push((47, data)); // client_certificate_type
        }

        if let Some(data) = server_types {
            extensions.push((48, data)); // server_certificate_type
        }

        extensions
    }

    fn process_server_hello_extensions(
        &self,
        conn_id: &str,
        extensions: &[(u16, Vec<u8>)],
    ) -> Result<(), TlsExtensionError> {
        let mut client_types_data = None;
        let mut server_types_data = None;

        for (ext_id, data) in extensions {
            match *ext_id {
                47 => client_types_data = Some(data.as_slice()),
                48 => server_types_data = Some(data.as_slice()),
                _ => {}
            }
        }

        self.simulate_receive_preferences(conn_id, client_types_data, server_types_data)
    }

    fn get_negotiation_result(&self, conn_id: &str) -> Option<NegotiationResult> {
        self.complete_negotiation(conn_id).ok()
    }
}

/// Wrapper for ClientConfig that simulates RFC 7250 extension behavior
pub struct Rfc7250ClientConfig {
    inner: Arc<ClientConfig>,
    extension_context: Arc<SimulatedExtensionContext>,
}

impl Rfc7250ClientConfig {
    /// Create a new RFC 7250 aware client configuration
    pub fn new(base_config: ClientConfig, preferences: CertificateTypePreferences) -> Self {
        Self {
            inner: Arc::new(base_config),
            extension_context: Arc::new(SimulatedExtensionContext::new(preferences)),
        }
    }

    /// Get the inner rustls ClientConfig
    pub fn inner(&self) -> &Arc<ClientConfig> {
        &self.inner
    }

    /// Get the extension context for negotiation
    pub fn extension_context(&self) -> &Arc<SimulatedExtensionContext> {
        &self.extension_context
    }

    /// Simulate the ClientHello extension data
    pub fn get_client_hello_extensions(&self, conn_id: &str) -> Vec<(u16, Vec<u8>)> {
        let (client_types, server_types) =
            self.extension_context.simulate_send_preferences(conn_id);

        let mut extensions = Vec::new();

        if let Some(data) = client_types {
            extensions.push((47, data)); // client_certificate_type
        }

        if let Some(data) = server_types {
            extensions.push((48, data)); // server_certificate_type
        }

        extensions
    }
}

/// Wrapper for ServerConfig that simulates RFC 7250 extension behavior
pub struct Rfc7250ServerConfig {
    inner: Arc<ServerConfig>,
    extension_context: Arc<SimulatedExtensionContext>,
}

impl Rfc7250ServerConfig {
    /// Create a new RFC 7250 aware server configuration
    pub fn new(base_config: ServerConfig, preferences: CertificateTypePreferences) -> Self {
        Self {
            inner: Arc::new(base_config),
            extension_context: Arc::new(SimulatedExtensionContext::new(preferences)),
        }
    }

    /// Get the inner rustls ServerConfig
    pub fn inner(&self) -> &Arc<ServerConfig> {
        &self.inner
    }

    /// Get the extension context for negotiation
    pub fn extension_context(&self) -> &Arc<SimulatedExtensionContext> {
        &self.extension_context
    }

    /// Process ClientHello extensions and prepare ServerHello response
    pub fn process_client_hello_extensions(
        &self,
        conn_id: &str,
        client_extensions: &[(u16, Vec<u8>)],
    ) -> Result<Vec<(u16, Vec<u8>)>, TlsExtensionError> {
        // First, register this connection
        self.extension_context.simulate_send_preferences(conn_id);

        // Process client's certificate type preferences
        let mut client_types_data = None;
        let mut server_types_data = None;

        for (ext_id, data) in client_extensions {
            match *ext_id {
                47 => client_types_data = Some(data.as_slice()),
                48 => server_types_data = Some(data.as_slice()),
                _ => {}
            }
        }

        // Store remote preferences
        self.extension_context.simulate_receive_preferences(
            conn_id,
            client_types_data,
            server_types_data,
        )?;

        // Complete negotiation
        let result = self.extension_context.complete_negotiation(conn_id)?;

        // Prepare ServerHello extensions with negotiated types
        let mut response_extensions = Vec::new();

        // Send back single negotiated type for each extension
        response_extensions.push((47, vec![1, result.client_cert_type.to_u8()]));
        response_extensions.push((48, vec![1, result.server_cert_type.to_u8()]));

        Ok(response_extensions)
    }
}

/// Helper to determine if we should use Raw Public Key based on negotiation
pub fn should_use_raw_public_key(negotiation_result: &NegotiationResult, is_client: bool) -> bool {
    if is_client {
        negotiation_result.client_cert_type.is_raw_public_key()
    } else {
        negotiation_result.server_cert_type.is_raw_public_key()
    }
}

/// Create a connection identifier for simulation purposes
pub fn create_connection_id(local_addr: &str, remote_addr: &str) -> String {
    format!("{local_addr}-{remote_addr}")
}

/// Wrapper for TlsSession that integrates with TlsExtensionHooks
pub struct ExtensionAwareTlsSession {
    /// The underlying TLS session
    inner_session: Box<dyn crate::crypto::Session>,
    /// Extension hooks for certificate type negotiation
    extension_hooks: Arc<dyn TlsExtensionHooks>,
    /// Connection identifier
    conn_id: String,
    /// Whether this is a client session
    is_client: bool,
    /// Whether handshake is complete
    handshake_complete: bool,
}

impl ExtensionAwareTlsSession {
    /// Create a new extension-aware TLS session
    pub fn new(
        inner_session: Box<dyn crate::crypto::Session>,
        extension_hooks: Arc<dyn TlsExtensionHooks>,
        conn_id: String,
        is_client: bool,
    ) -> Self {
        Self {
            inner_session,
            extension_hooks,
            conn_id,
            is_client,
            handshake_complete: false,
        }
    }

    /// Get the negotiation result if available
    pub fn get_negotiation_result(&self) -> Option<NegotiationResult> {
        self.extension_hooks.get_negotiation_result(&self.conn_id)
    }
}

/// Implement the crypto::Session trait for our wrapper
impl crate::crypto::Session for ExtensionAwareTlsSession {
    fn initial_keys(
        &self,
        dst_cid: &crate::ConnectionId,
        side: crate::Side,
    ) -> crate::crypto::Keys {
        self.inner_session.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner_session.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner_session.peer_identity()
    }

    fn early_crypto(
        &self,
    ) -> Option<(
        Box<dyn crate::crypto::HeaderKey>,
        Box<dyn crate::crypto::PacketKey>,
    )> {
        self.inner_session.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner_session.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner_session.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, crate::TransportError> {
        let result = self.inner_session.read_handshake(buf)?;

        // Check if handshake is complete
        if result && !self.handshake_complete && !self.is_handshaking() {
            self.handshake_complete = true;
            self.extension_hooks
                .on_handshake_complete(&self.conn_id, self.is_client);
        }

        Ok(result)
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<crate::transport_parameters::TransportParameters>, crate::TransportError>
    {
        self.inner_session.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crate::crypto::Keys> {
        self.inner_session.write_handshake(buf)
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Option<crate::crypto::KeyPair<Box<dyn crate::crypto::PacketKey>>> {
        self.inner_session.next_1rtt_keys()
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &crate::ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        self.inner_session
            .is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crate::crypto::ExportKeyingMaterialError> {
        self.inner_session
            .export_keying_material(output, label, context)
    }
}

/// Enhanced QUIC client config with RFC 7250 support
pub struct Rfc7250QuicClientConfig {
    /// Base QUIC client config
    base_config: Arc<dyn QuicClientConfig>,
    /// Extension context for certificate type negotiation
    extension_context: Arc<SimulatedExtensionContext>,
}

impl Rfc7250QuicClientConfig {
    /// Create a new RFC 7250 aware QUIC client config
    pub fn new(
        base_config: Arc<dyn QuicClientConfig>,
        preferences: CertificateTypePreferences,
    ) -> Self {
        Self {
            base_config,
            extension_context: Arc::new(SimulatedExtensionContext::new(preferences)),
        }
    }
}

impl QuicClientConfig for Rfc7250QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &crate::transport_parameters::TransportParameters,
    ) -> Result<Box<dyn crate::crypto::Session>, crate::ConnectError> {
        // Create the base session
        let inner_session = self
            .base_config
            .clone()
            .start_session(version, server_name, params)?;

        // Create connection ID for this session
        let conn_id = format!(
            "client-{}-{}",
            server_name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Create wrapper with extension hooks
        Ok(Box::new(ExtensionAwareTlsSession::new(
            inner_session,
            self.extension_context.clone() as Arc<dyn TlsExtensionHooks>,
            conn_id,
            true, // is_client
        )))
    }
}

/// Enhanced QUIC server config with RFC 7250 support
pub struct Rfc7250QuicServerConfig {
    /// Base QUIC server config
    base_config: Arc<dyn QuicServerConfig>,
    /// Extension context for certificate type negotiation
    extension_context: Arc<SimulatedExtensionContext>,
}

impl Rfc7250QuicServerConfig {
    /// Create a new RFC 7250 aware QUIC server config
    pub fn new(
        base_config: Arc<dyn QuicServerConfig>,
        preferences: CertificateTypePreferences,
    ) -> Self {
        Self {
            base_config,
            extension_context: Arc::new(SimulatedExtensionContext::new(preferences)),
        }
    }
}

impl QuicServerConfig for Rfc7250QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &crate::transport_parameters::TransportParameters,
    ) -> Box<dyn crate::crypto::Session> {
        // Create the base session
        let inner_session = self.base_config.clone().start_session(version, params);

        // Create connection ID for this session
        let conn_id = format!(
            "server-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Create wrapper with extension hooks
        Box::new(ExtensionAwareTlsSession::new(
            inner_session,
            self.extension_context.clone() as Arc<dyn TlsExtensionHooks>,
            conn_id,
            false, // is_client = false for server
        ))
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &crate::ConnectionId,
    ) -> Result<crate::crypto::Keys, crate::crypto::UnsupportedVersion> {
        self.base_config.initial_keys(version, dst_cid)
    }

    fn retry_tag(
        &self,
        version: u32,
        orig_dst_cid: &crate::ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        self.base_config.retry_tag(version, orig_dst_cid, packet)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tls_extensions::CertificateType;
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    // Ensure crypto provider is installed for tests
    fn ensure_crypto_provider() {
        INIT.call_once(|| {
            // Install the crypto provider if not already installed
            #[cfg(feature = "rustls-aws-lc-rs")]
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            #[cfg(feature = "rustls-ring")]
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_simulated_negotiation_flow() {
        // Client side
        let client_prefs = CertificateTypePreferences::prefer_raw_public_key();
        let client_ctx = SimulatedExtensionContext::new(client_prefs);

        // Server side
        let server_prefs = CertificateTypePreferences::raw_public_key_only();
        let server_ctx = SimulatedExtensionContext::new(server_prefs);

        let conn_id = "test-connection";

        // Client sends preferences
        let (client_types, server_types) = client_ctx.simulate_send_preferences(conn_id);
        assert!(client_types.is_some());
        assert!(server_types.is_some());

        // Server receives and processes
        server_ctx.simulate_send_preferences(conn_id);
        server_ctx
            .simulate_receive_preferences(conn_id, client_types.as_deref(), server_types.as_deref())
            .unwrap();

        // Server completes negotiation
        let server_result = server_ctx.complete_negotiation(conn_id).unwrap();
        assert!(server_result.is_raw_public_key_only());

        // Client receives server's response (simulated)
        let server_response_client = vec![1, CertificateType::RawPublicKey.to_u8()];
        let server_response_server = vec![1, CertificateType::RawPublicKey.to_u8()];

        client_ctx
            .simulate_receive_preferences(
                conn_id,
                Some(&server_response_client),
                Some(&server_response_server),
            )
            .unwrap();

        // Client completes negotiation
        let client_result = client_ctx.complete_negotiation(conn_id).unwrap();
        assert_eq!(client_result, server_result);
    }

    #[test]
    fn test_wrapper_configs() {
        ensure_crypto_provider();
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                crate::crypto::raw_public_keys::RawPublicKeyVerifier::new(Vec::new()),
            ))
            .with_no_client_auth();

        let client_prefs = CertificateTypePreferences::prefer_raw_public_key();
        let wrapped_client = Rfc7250ClientConfig::new(client_config, client_prefs);

        let conn_id = "test-conn";
        let extensions = wrapped_client.get_client_hello_extensions(conn_id);

        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].0, 47); // client_certificate_type
        assert_eq!(extensions[1].0, 48); // server_certificate_type
    }
}
