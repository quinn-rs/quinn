use crate::cert::Leaf;
use crate::suite::Suite;
use crate::{ClientConfig, CryptoProvider, ServerConfig};
use quinn_proto::crypto;
use rand::RngCore;
use ring;
use std::sync::Arc;

/// Creates a new rustls-based [CryptoProvider]
pub fn new_provider() -> Arc<dyn CryptoProvider> {
    Arc::new(RustlsProvider())
}

/// Creates a new test [Suite] that uses the rustls [CryptoProvider] for both client and server.
pub fn suite() -> Suite {
    Suite::new(new_provider(), new_provider())
}

struct RustlsProvider();

impl CryptoProvider for RustlsProvider {
    fn new_client(&self, cfg: ClientConfig) -> Box<dyn crypto::ClientConfig> {
        Box::new(new_rustls_client(cfg))
    }

    fn new_client_reuse_session(
        &self,
        cfg: ClientConfig,
        prev: &Box<dyn crypto::ClientConfig>,
    ) -> Box<dyn crypto::ClientConfig> {
        let prev = prev
            .as_any()
            .downcast_ref::<rustls::ClientConfig>()
            .unwrap();
        let mut out = new_rustls_client(cfg);
        out.session_storage = prev.session_storage.clone();
        Box::new(out)
    }

    fn new_server(&self, cfg: ServerConfig) -> Box<dyn crypto::ServerConfig> {
        Box::new(new_rustls_server(cfg))
    }

    fn new_hmac_key(&self) -> Arc<dyn crypto::HmacKey> {
        Arc::new(new_ring_hmac_key())
    }
}

/// Underlying method for creating the crypto configuration.
pub fn new_rustls_client(in_: ClientConfig) -> rustls::ClientConfig {
    // Create the cert store containing the server certs.
    let mut server_certs = rustls::RootCertStore::empty();
    for allowed_cert in peer_certs(in_.allowed_peers) {
        server_certs.add(&allowed_cert).unwrap();
    }

    let builder = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(server_certs);

    let mut out = if in_.enable_client_auth {
        let key = rustls::PrivateKey(in_.cert.private_key.clone());
        let mut certs = Vec::new();
        for cert in in_.cert.chain {
            certs.push(rustls::Certificate(cert.clone()));
        }
        builder.with_single_cert(certs, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };

    out.key_log = Arc::new(rustls::KeyLogFile::new());
    out.alpn_protocols = in_.alpn_protocols;
    out.enable_early_data = true;
    out
}

pub fn new_rustls_server(in_: ServerConfig) -> rustls::ServerConfig {
    let key = rustls::PrivateKey(in_.cert.private_key);
    let mut certs = Vec::new();
    for cert in in_.cert.chain {
        certs.push(rustls::Certificate(cert.clone()));
    }
    let mut out = if in_.enable_client_auth {
        rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier({
                let mut store = rustls::RootCertStore::empty();
                for allowed_cert in peer_certs(in_.allowed_peers) {
                    store.add(&allowed_cert).unwrap();
                }
                rustls::server::AllowAnyAuthenticatedClient::new(store)
            })
            .with_single_cert(certs, key)
            .unwrap()
    } else {
        // Client auth is disabled: allow all clients.
        let mut out = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        out.max_early_data_size = u32::MAX;
        out
    };
    out.alpn_protocols = in_.alpn_protocols;
    out
}

pub fn new_ring_hmac_key() -> ring::hmac::Key {
    let mut reset_key = vec![0; 64];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut reset_key);
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &reset_key)
}

fn peer_certs(peers: Vec<Leaf>) -> Vec<rustls::Certificate> {
    let mut out = Vec::new();
    for allowed_peer in peers {
        for cert in allowed_peer.chain {
            out.push(rustls::Certificate(cert.clone()));
        }
    }
    out
}
