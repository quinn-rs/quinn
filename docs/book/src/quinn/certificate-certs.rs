use std::error::Error;

use rustls::{client, pki_types::pem::PemObject};

fn read_certs_from_file() -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn Error>,
> {
    let certs = rustls::pki_types::CertificateDer::pem_file_iter("./fullchain.pem")
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file("./privkey.pem").unwrap();
    Ok((certs, key))
}

fn generate_self_signed_cert() -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivatePkcs8KeyDer<'static>,
    ),
    Box<dyn Error>,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Ok((cert_der, key))
}

fn main() {
    let (self_signed_certs, self_signed_key) = generate_self_signed_cert().unwrap();
    let (certs, key) = read_certs_from_file().unwrap();
    let server_config = quinn::ServerConfig::with_single_cert(certs, key);
    let client_config = quinn::ClientConfig::with_platform_verifier();
}
