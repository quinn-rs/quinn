use std::{error::Error, sync::Arc};

use quinn::{
    ClientConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger,
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime, pem::PemObject,
    },
};

#[allow(unused_variables)]
fn main() {
    let (self_signed_certs, self_signed_key) = generate_self_signed_cert().unwrap();
    let (certs, key) = read_certs_from_file().unwrap();
    let server_config = quinn::ServerConfig::with_single_cert(certs, key);
    let client_config = quinn::ClientConfig::with_platform_verifier();
}

#[allow(dead_code)] // Included in `certificate.md`
fn configure_client() -> Result<ClientConfig, NoInitialCipherSuite> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        crypto,
    )?)))
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn generate_self_signed_cert()
-> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
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
