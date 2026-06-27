use std::{error::Error, sync::Arc};

use quinn::{ClientConfig, crypto::rustls::QuicClientConfig};
use rustls::{
    client::danger,
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};

#[allow(unused_variables)]
fn main() {
    let (self_signed_certs, self_signed_key) = generate_self_signed_cert().unwrap();
    let (certs, key) = read_certs_from_file().unwrap();
    let server_config = quinn::ServerConfig::with_single_cert(certs, key);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(self_signed_certs).unwrap();
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
}

#[allow(dead_code)] // Included in `certificate.md`
fn configure_client() -> Result<ClientConfig, Box<dyn Error>> {
    let crypto = rustls::ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth()?;

    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        crypto,
    )?)))
}

// Implementation of `ServerVerifier` that verifies everything as trustworthy.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER)))
    }
}

impl danger::ServerVerifier for SkipServerVerification {
    fn verify_identity(
        &self,
        _identity: &danger::ServerIdentity<'_>,
    ) -> Result<danger::PeerVerified, rustls::Error> {
        Ok(danger::PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        input: &danger::SignatureVerificationInput<'_>,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(input, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        input: &danger::SignatureVerificationInput<'_>,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(input, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::crypto::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, _h: &mut dyn std::hash::Hasher) {}
}

fn generate_self_signed_cert()
-> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((cert_der, key))
}

fn read_certs_from_file()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error>> {
    let certs = CertificateDer::pem_file_iter("./fullchain.pem")
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file("./privkey.pem").unwrap();
    Ok((certs, key))
}
