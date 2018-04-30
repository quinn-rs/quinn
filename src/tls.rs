use rustls::internal::msgs::{base::PayloadU16, codec::Codec};
use rustls::internal::msgs::quic::Parameter;
use rustls::internal::msgs::quic::{ClientTransportParameters, ServerTransportParameters};
use rustls::{ClientConfig, NoClientAuth, ProtocolVersion};
use rustls::quic::{ClientSession, QuicSecret, ServerSession, TLSResult};

use std::mem;
use std::sync::Arc;

use crypto::{expanded_handshake_secret, AES_128_GCM, PacketKey, SHA256};
use packet::{DRAFT_10, Header, LongType};
use types::TransportParameter;

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::{Certificate, PrivateKey, ServerConfig, SupportedCipherSuite, TLSError};

pub struct ClientTls {
    pub session: ClientSession,
    secret: Secret,
    prev_secret: Option<Secret>,
}

impl ClientTls {
    pub fn new(secret: Secret) -> Self {
        Self::with_config(Self::build_config(None), secret)
    }

    pub fn with_config(config: ClientConfig, secret: Secret) -> Self {
        Self {
            session: ClientSession::new(&Arc::new(config)),
            secret,
            prev_secret: None,
        }
    }

    pub fn build_config(anchors: Option<&TLSServerTrustAnchors>) -> ClientConfig {
        let mut config = ClientConfig::new();
        let anchors = anchors.unwrap_or(&webpki_roots::TLS_SERVER_ROOTS);
        config.root_store.add_server_trust_anchors(anchors);
        config.versions = vec![ProtocolVersion::TLSv1_3];
        config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
        config
    }

    pub(crate) fn encode_key(&self, h: &Header) -> PacketKey {
        if let Some(LongType::Handshake) = h.ptype() {
            if let Some(Secret::Handshake(_)) = self.prev_secret {
                return self.prev_secret.as_ref().unwrap().build_key(Side::Client);
            }
        }
        self.secret.build_key(Side::Client)
    }

    pub(crate) fn decode_key(&self, _: &Header) -> PacketKey {
        self.secret.build_key(Side::Server)
    }

    pub fn get_handshake(&mut self, hostname: &str) -> Result<Vec<u8>, TLSError> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(hostname).unwrap();
        let params = ClientTransportParameters {
            initial_version: 1,
            parameters: encode_transport_parameters(&vec![
                TransportParameter::InitialMaxStreamData(131072),
                TransportParameter::InitialMaxData(1048576),
                TransportParameter::IdleTimeout(300),
            ]),
        };

        let res = self.session.get_handshake(pki_server_name, params)?;
        let TLSResult { messages, key_ready } = res;
        if let Some((suite, secret)) = key_ready {
            let old = mem::replace(&mut self.secret, Secret::Shared(suite, secret));
            self.prev_secret = Some(old);
        }
        Ok(messages)
    }

    pub fn process_handshake_messages(&mut self, data: &[u8]) -> Result<Vec<u8>, TLSError> {
        let res = self.session.process_handshake_messages(data)?;
        let TLSResult { messages, key_ready } = res;
        if let Some((suite, secret)) = key_ready {
            let old = mem::replace(&mut self.secret, Secret::Shared(suite, secret));
            self.prev_secret = Some(old);
        }
        Ok(messages)
    }
}

pub struct ServerTls {
    session: ServerSession,
    secret: Secret,
    prev_secret: Option<Secret>,
}

impl ServerTls {
    pub fn with_config(config: &Arc<ServerConfig>, secret: Secret) -> Self {
        Self {
            session: ServerSession::new(
                config,
                ServerTransportParameters {
                    negotiated_version: DRAFT_10,
                    supported_versions: vec![DRAFT_10],
                    parameters: encode_transport_parameters(&vec![
                        TransportParameter::InitialMaxStreamData(131072),
                        TransportParameter::InitialMaxData(1048576),
                        TransportParameter::IdleTimeout(300),
                    ]),
                },
            ),
            secret,
            prev_secret: None,
        }
    }

    pub fn build_config(cert_chain: Vec<Certificate>, key: PrivateKey) -> ServerConfig {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_protocols(&[ALPN_PROTOCOL.into()]);
        config.set_single_cert(cert_chain, key);
        config
    }

    pub(crate) fn encode_key(&self, _: &Header) -> PacketKey {
        self.secret.build_key(Side::Server)
    }

    pub(crate) fn decode_key(&self, _: &Header) -> PacketKey {
        self.secret.build_key(Side::Client)
    }

    pub fn get_handshake(&mut self, input: &[u8]) -> Result<Vec<u8>, TLSError> {
        let res = self.session.get_handshake(input)?;
        let TLSResult { messages, key_ready } = res;
        if let Some((suite, secret)) = key_ready {
            let old = mem::replace(&mut self.secret, Secret::Shared(suite, secret));
            self.prev_secret = Some(old);
        }
        Ok(messages)
    }
}

pub fn encode_transport_parameters(params: &[TransportParameter]) -> Vec<Parameter> {
    use self::TransportParameter::*;
    let mut ret = Vec::new();
    for param in params {
        let mut bytes = Vec::new();
        match *param {
            InitialMaxStreamData(v)
            | InitialMaxData(v)
            | InitialMaxStreamIdBidi(v)
            | InitialMaxStreamIdUni(v) => {
                v.encode(&mut bytes);
            }
            IdleTimeout(v) | MaxPacketSize(v) => {
                v.encode(&mut bytes);
            }
            OmitConnectionId => {}
            StatelessResetToken(ref v) => {
                bytes.extend_from_slice(&v);
            }
            AckDelayExponent(v) => {
                v.encode(&mut bytes);
            }
        }
        ret.push((tag(param), PayloadU16::new(bytes)));
    }
    ret
}

fn tag(param: &TransportParameter) -> u16 {
    use self::TransportParameter::*;
    match *param {
        InitialMaxStreamData(_) => 0,
        InitialMaxData(_) => 1,
        InitialMaxStreamIdBidi(_) => 2,
        IdleTimeout(_) => 3,
        OmitConnectionId => 4,
        MaxPacketSize(_) => 5,
        StatelessResetToken(_) => 6,
        AckDelayExponent(_) => 7,
        InitialMaxStreamIdUni(_) => 8,
    }
}

const ALPN_PROTOCOL: &'static str = "hq-10";

pub enum Secret {
    Handshake(u64),
    Shared(&'static SupportedCipherSuite, QuicSecret),
}

impl Secret {
    pub fn build_key(&self, side: Side) -> PacketKey {
        match *self {
            Secret::Handshake(cid) => {
                let label = if side == Side::Client {
                    b"client hs"
                } else {
                    b"server hs"
                };
                PacketKey::new(
                    &AES_128_GCM,
                    &SHA256,
                    &expanded_handshake_secret(cid, label),
                )
            },
            Secret::Shared(suite, QuicSecret::For1RTT(ref secret)) => {
                PacketKey::new(suite.get_aead_alg(), suite.get_hash(), secret)
            }
        }
    }
}

#[derive(PartialEq)]
pub enum Side {
    Client,
    Server,
}
