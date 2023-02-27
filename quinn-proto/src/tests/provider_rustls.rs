use crate::crypto;
use crate::tests::certs::Leaf;
use crate::tests::provider::{ClientConfig, CryptoProvider, ServerConfig};
use rand::RngCore;
use ring;
use std::any::Any;
use std::sync::Arc;

/// A rustls-based [CryptoProvider]
pub struct RustlsProvider;

impl CryptoProvider for RustlsProvider {
    fn new_client(&self, cfg: ClientConfig) -> Box<dyn crypto::ClientConfig> {
        Box::new(new_rustls_client(cfg))
    }

    fn new_clients_with_shared_session_cache(
        &self,
        cfg1: ClientConfig,
        cfg2: ClientConfig,
    ) -> (Box<dyn crypto::ClientConfig>, Box<dyn crypto::ClientConfig>) {
        let out1 = new_rustls_client(cfg1);
        let mut out2 = new_rustls_client(cfg2);
        out2.session_storage = out1.session_storage.clone();
        (Box::new(out1), Box::new(out2))
    }

    fn new_server(&self, cfg: ServerConfig) -> Box<dyn crypto::ServerConfig> {
        Box::new(new_rustls_server(cfg))
    }

    fn new_hmac_key(&self) -> Arc<dyn crypto::HmacKey> {
        Arc::new(new_ring_hmac_key())
    }

    fn handshake_data_alpn(&self, hd: Option<Box<dyn Any>>) -> Vec<u8> {
        hd.unwrap()
            .downcast::<crypto::rustls::HandshakeData>()
            .unwrap()
            .protocol
            .as_ref()
            .unwrap()
            .clone()
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
