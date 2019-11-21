use std::{fs, io, path::PathBuf};

use anyhow::{bail, Context, Result};
use quinn::{Certificate, CertificateChain, PrivateKey};
use tracing::info;

pub fn build_certs(
    key: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> Result<(CertificateChain, Certificate, PrivateKey)> {
    if let (Some(ref key_path), Some(ref cert_path)) = (key, cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert = quinn::Certificate::from_der(&cert_chain)?;
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert.clone()]);
        Ok((cert_chain, cert, key))
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(&path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, &key).context("failed to write private key")?;
                (cert, key)
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert = quinn::Certificate::from_der(&cert)?;
        Ok((
            quinn::CertificateChain::from_certs(vec![cert.clone()]),
            cert,
            key,
        ))
    }
}
