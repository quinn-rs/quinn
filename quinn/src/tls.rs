use std::fmt;

use rustls::{self, internal::pemfile};

/// A chain of signed TLS certificates ending the one to be used by a server
pub struct CertificateChain {
    pub(crate) certs: Vec<rustls::Certificate>,
}

impl CertificateChain {
    /// Parse a PEM-formatted certificate chain
    ///
    /// ```no_run
    /// let pem = std::fs::read("fullchain.pem").expect("error reading certificates");
    /// let cert_chain = quinn::PrivateKey::from_pem(&pem).expect("error parsing certificates");
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {
            certs: pemfile::certs(&mut &pem[..])
                .map_err(|()| ParseError("malformed certificate chain"))?,
        })
    }
}

/// The private key of a TLS certificate to be used by a server
pub struct PrivateKey {
    pub(crate) inner: rustls::PrivateKey,
}

impl PrivateKey {
    /// Parse a PEM-formatted private key
    ///
    /// ```no_run
    /// let pem = std::fs::read("key.pem").expect("error reading key");
    /// let key = quinn::PrivateKey::from_pem(&pem).expect("error parsing key");
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self, ParseError> {
        let pkcs8 = pemfile::pkcs8_private_keys(&mut &pem[..])
            .map_err(|()| ParseError("malformed PKCS #8 private key"))?;
        if let Some(x) = pkcs8.into_iter().next() {
            return Ok(Self { inner: x });
        }
        let rsa = pemfile::rsa_private_keys(&mut &pem[..])
            .map_err(|()| ParseError("malformed PKCS #1 private key"))?;
        if let Some(x) = rsa.into_iter().next() {
            return Ok(Self { inner: x });
        }
        Err(ParseError("no private key found"))
    }
}

#[derive(Debug, Clone)]
pub struct ParseError(&'static str);

impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad(self.0)
    }
}
