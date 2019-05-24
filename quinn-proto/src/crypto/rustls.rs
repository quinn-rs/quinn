use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{io, str};

use rustls::quic::{ClientQuicExt, ServerQuicExt};
use rustls::ProtocolVersion;
pub use rustls::TLSError;
use rustls::{self, NoClientAuth, Session};
use webpki::DNSNameRef;

use super::ring::{Crypto, RingHeaderCrypto};
use super::{CryptoClientConfig, CryptoServerConfig, CryptoSession};
use crate::transport_parameters::TransportParameters;
use crate::{ConnectError, Side, TransportError};

pub enum TlsSession {
    Client(rustls::ClientSession),
    Server(rustls::ServerSession),
}

impl TlsSession {
    fn side(&self) -> Side {
        match self {
            TlsSession::Client(_) => Side::Client,
            TlsSession::Server(_) => Side::Server,
        }
    }
}

impl CryptoSession for TlsSession {
    type ClientConfig = ClientConfig;
    type Crypto = Crypto;
    type HeaderCrypto = RingHeaderCrypto;
    type ServerConfig = ServerConfig;

    fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    fn early_crypto(&self) -> Option<Crypto> {
        self.get_early_secret()
            .map(|secret| Crypto::new_0rtt(secret))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self {
            TlsSession::Client(session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Client(session) => session.is_handshaking(),
            TlsSession::Server(session) => session.is_handshaking(),
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.get_alert() {
                TransportError::crypto(alert.get_u8(), e.to_string())
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {}", e))
            }
        })
    }

    fn sni_hostname(&self) -> Option<&str> {
        match self {
            TlsSession::Client(_) => None,
            TlsSession::Server(session) => session.get_sni_hostname(),
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.get_quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Crypto> {
        let secrets = self.write_hs(buf)?;
        let suite = self
            .get_negotiated_ciphersuite()
            .expect("should not get secrets without cipher suite");
        Some(Crypto::new(
            self.side(),
            suite.get_hash(),
            suite.get_aead_alg(),
            secrets.client,
            secrets.server,
        ))
    }

    fn update_keys(&self, crypto: &Crypto) -> Crypto {
        let (client_secret, server_secret) = match self.side() {
            Side::Client => (&crypto.local_secret, &crypto.remote_secret),
            Side::Server => (&crypto.remote_secret, &crypto.local_secret),
        };

        let secrets = self.update_secrets(client_secret, server_secret);
        let suite = self.get_negotiated_ciphersuite().unwrap();
        Crypto::new(
            self.side(),
            suite.get_hash(),
            suite.get_aead_alg(),
            secrets.client,
            secrets.server,
        )
    }
}

impl Deref for TlsSession {
    type Target = dyn rustls::Session;
    fn deref(&self) -> &Self::Target {
        match *self {
            TlsSession::Client(ref session) => session,
            TlsSession::Server(ref session) => session,
        }
    }
}

impl DerefMut for TlsSession {
    fn deref_mut(&mut self) -> &mut (dyn rustls::Session + 'static) {
        match *self {
            TlsSession::Client(ref mut session) => session,
            TlsSession::Server(ref mut session) => session,
        }
    }
}

/// rustls configuration for client sessions
#[derive(Clone)]
pub struct ClientConfig(#[doc(hidden)] pub Arc<rustls::ClientConfig>);

impl Default for ClientConfig {
    fn default() -> ClientConfig {
        let mut cfg = rustls::ClientConfig::new();
        cfg.versions = vec![ProtocolVersion::TLSv1_3];
        cfg.enable_early_data = true;
        Self(Arc::new(cfg))
    }
}

impl Deref for ClientConfig {
    type Target = Arc<rustls::ClientConfig>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClientConfig {
    fn deref_mut(&mut self) -> &mut Arc<rustls::ClientConfig> {
        &mut self.0
    }
}

impl CryptoClientConfig for ClientConfig {
    type Session = TlsSession;
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Self::Session, ConnectError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(server_name)
            .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?;
        Ok(TlsSession::Client(rustls::ClientSession::new_quic(
            &self.0,
            pki_server_name,
            to_vec(params),
        )))
    }
}

#[derive(Clone)]
pub struct ServerConfig(#[doc(hidden)] pub Arc<rustls::ServerConfig>);

impl Default for ServerConfig {
    fn default() -> Self {
        let mut cfg = rustls::ServerConfig::new(NoClientAuth::new());
        cfg.versions = vec![ProtocolVersion::TLSv1_3];
        cfg.max_early_data_size = u32::max_value();
        Self(Arc::new(cfg))
    }
}

impl CryptoServerConfig for ServerConfig {
    type Session = TlsSession;
    fn start_session(&self, params: &TransportParameters) -> Self::Session {
        TlsSession::Server(rustls::ServerSession::new_quic(&self.0, to_vec(params)))
    }
}

impl Deref for ServerConfig {
    type Target = Arc<rustls::ServerConfig>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ServerConfig {
    fn deref_mut(&mut self) -> &mut Arc<rustls::ServerConfig> {
        &mut self.0
    }
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}
