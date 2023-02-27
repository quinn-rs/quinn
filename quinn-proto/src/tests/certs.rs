use lazy_static::lazy_static;
use rcgen::{BasicConstraints, CertificateParams, IsCa};

/// Certificate Authority utility that can create new leaf certs.
pub struct Ca(rcgen::Certificate);

impl Ca {
    /// Creates a new CA.
    pub fn new() -> Self {
        let mut params = CertificateParams::new(&[] as &[String]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self(rcgen::Certificate::from_params(params).unwrap())
    }

    /// Gets this CA's certificate.
    pub fn cert(&self) -> Vec<u8> {
        self.0.serialize_der().unwrap()
    }

    /// Creates a new leaf cert signed by this CA.
    pub fn new_leaf(&self, subject_alt_names: impl Into<Vec<String>>) -> Leaf {
        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let private_key = cert.serialize_private_key_der();
        let cert = cert.serialize_der_with_signer(&self.0).unwrap();
        Leaf {
            private_key,
            chain: vec![cert, self.cert()],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Leaf {
    /// The certificate chain, starting with the leaf certificate and ending with the root CA.
    pub chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}

impl Leaf {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            private_key: Vec::new(),
        }
    }
}

lazy_static! {
    pub static ref CA: Ca = Ca::new();
    pub static ref SERVER_CERT: Leaf = CA.new_leaf(vec!["localhost".into()]);
    pub static ref CLIENT_CERT: Leaf = CA.new_leaf(vec!["client.com".into()]);

    /// Generate a big fat certificate that can't fit inside the initial anti-amplification limit
    pub static ref BIG_CERT: Leaf = CA.new_leaf(Some("localhost".into())
            .into_iter()
            .chain((0..1000).map(|x| format!("foo_{}", x)))
            .collect::<Vec<_>>());
}
