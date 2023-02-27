use crate::crypto;
use crate::tests::certs::{Leaf, CLIENT_CERT, SERVER_CERT};
use crate::tests::provider_rustls::RustlsProvider;
use std::any::Any;
use std::sync::Arc;

/// Return the [CryptoProvider] to be use for the client.
pub fn client() -> Arc<dyn CryptoProvider> {
    Arc::new(RustlsProvider {})
}

/// Return the [CryptoProvider] to be used for the server.
pub fn server() -> Arc<dyn CryptoProvider> {
    Arc::new(RustlsProvider {})
}

/// Configuration for client-side endpoints.
pub struct ClientConfig {
    /// The certificate for the client.
    pub cert: Leaf,

    /// The list of allowed peers for validation.
    pub allowed_peers: Vec<Leaf>,

    /// The ALPN protocols offered by the client.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// If true, the client will present its certificate to the server.
    pub enable_client_auth: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            cert: CLIENT_CERT.clone(),
            allowed_peers: vec![SERVER_CERT.clone()],
            alpn_protocols: default_alpn(),
            enable_client_auth: false,
        }
    }
}

/// Configuration for server-side endpoints.
pub struct ServerConfig {
    /// The certificate for the server.
    pub cert: Leaf,

    /// The ALPN protocols accepted by the server.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// If true, the server will verify the certificate presented by the client against
    /// the value in [allowed_peers].
    pub enable_client_auth: bool,

    /// The list of allowed peers for validation. Only used if [enable_client_auth] is `true`.
    pub allowed_peers: Vec<Leaf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            cert: SERVER_CERT.clone(),
            allowed_peers: vec![CLIENT_CERT.clone()],
            alpn_protocols: default_alpn(),
            enable_client_auth: false,
        }
    }
}

/// A provider for crypto config for client and server test endpoints.
pub trait CryptoProvider {
    /// Creates the crypto config for a client-side endpoint.
    fn new_client(&self, cfg: ClientConfig) -> Box<dyn crypto::ClientConfig>;

    /// Creates two clients that share the same underlying session cache.
    fn new_clients_with_shared_session_cache(
        &self,
        cfg1: ClientConfig,
        cfg2: ClientConfig,
    ) -> (Box<dyn crypto::ClientConfig>, Box<dyn crypto::ClientConfig>);

    /// Creates the crypto config for a server-side endpoint.
    fn new_server(&self, cfg: ServerConfig) -> Box<dyn crypto::ServerConfig>;

    /// Creates a new random HMAC key.
    fn new_hmac_key(&self) -> Arc<dyn crypto::HmacKey>;

    /// Extracts the selected alpn protocol from handshake data.
    fn handshake_data_alpn(&self, handshake_data: Option<Box<dyn Any>>) -> Vec<u8>;
}

fn default_alpn() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}
