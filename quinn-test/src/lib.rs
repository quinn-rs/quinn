pub mod cert;
pub mod rustls;
pub mod suite;

mod endpoint;

use lazy_static::lazy_static;
use quinn_proto::{crypto, Transmit};
use std::cmp;
use std::ops::RangeFrom;
use std::sync::{Arc, Mutex};

/// Configuration for client-side endpoints.
pub struct ClientConfig {
    /// The certificate for the client.
    pub cert: cert::Leaf,

    /// The list of allowed peers for validation.
    pub allowed_peers: Vec<cert::Leaf>,

    /// The ALPN protocols offered by the client.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// If true, the client will present its certificate to the server.
    pub enable_client_auth: bool,
}

// impl ClientConfig {
//     pub fn new() -> Self {
//         Self {
//             cert: cert::Leaf::new(),
//             allowed_peers: Vec::new(),
//             alpn_protocols: Vec::new(),
//             enable_client_auth: false,
//         }
//     }
// }

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            cert: cert::CLIENT_CERT.clone(),
            allowed_peers: vec![cert::SERVER_CERT.clone()],
            alpn_protocols: default_alpn(),
            enable_client_auth: false,
        }
    }
}

/// Configuration for server-side endpoints.
pub struct ServerConfig {
    /// The certificate for the server.
    pub cert: cert::Leaf,

    /// The ALPN protocols accepted by the server.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// If true, the server will verify the certificate presented by the client against
    /// the value in [allowed_peers].
    pub enable_client_auth: bool,

    /// The list of allowed peers for validation. Only used if [enable_client_auth] is `true`.
    pub allowed_peers: Vec<cert::Leaf>,
}

// impl ServerConfig {
//     pub fn new() -> Self {
//         Self {
//             cert: cert::Leaf::new(),
//             allowed_peers: Vec::new(),
//             alpn_protocols: Vec::new(),
//             enable_client_auth: false,
//         }
//     }
// }

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            cert: cert::SERVER_CERT.clone(),
            allowed_peers: vec![cert::CLIENT_CERT.clone()],
            alpn_protocols: default_alpn(),
            enable_client_auth: false,
        }
    }
}

/// A provider for crypto config for client and server test endpoints.
pub trait CryptoProvider {
    /// Creates the crypto config for a client-side endpoint.
    fn new_client(&self, cfg: ClientConfig) -> Box<dyn crypto::ClientConfig>;

    /// Creates the crypto config for a client-side endpoint. The generated
    /// config reuses the same underlying session cache from the previous configuration.
    fn new_client_reuse_session(
        &self,
        cfg: ClientConfig,
        prev: &Box<dyn crypto::ClientConfig>,
    ) -> Box<dyn crypto::ClientConfig>;

    /// Creates the crypto config for a server-side endpoint.
    fn new_server(&self, cfg: ServerConfig) -> Box<dyn crypto::ServerConfig>;

    /// Creates a new random HMAC key.
    fn new_hmac_key(&self) -> Arc<dyn crypto::HmacKey>;
}

pub(crate) fn default_alpn() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}

pub(crate) fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}

pub(crate) fn split_transmit(transmit: Transmit) -> Vec<Transmit> {
    let segment_size = match transmit.segment_size {
        Some(segment_size) => segment_size,
        _ => return vec![transmit],
    };

    let mut offset = 0;
    let mut transmits = Vec::new();
    while offset < transmit.contents.len() {
        let end = (offset + segment_size).min(transmit.contents.len());

        let contents = transmit.contents[offset..end].to_vec();
        transmits.push(Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        });

        offset = end;
    }

    transmits
}

lazy_static! {
    pub(crate) static ref SERVER_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(4433..);
    pub(crate) static ref CLIENT_PORTS: Mutex<RangeFrom<u16>> = Mutex::new(44433..);
}
