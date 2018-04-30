use rustls::internal::msgs::{base::PayloadU16, codec::Codec};
use rustls::internal::msgs::quic::Parameter;
use rustls::internal::msgs::quic::{ClientTransportParameters, ServerTransportParameters};
use rustls::{ClientConfig, NoClientAuth, ProtocolVersion};
use rustls::quic::{ClientSession, ServerSession};

use std::io;
use std::sync::Arc;

use crypto::PacketKey;
use packet::{DRAFT_10, PartialDecode};
use types::TransportParameter;

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::{Certificate, PrivateKey, ServerConfig, TLSError};

pub struct ClientTls {
    pub session: ClientSession,
    secret: Secret,
}

impl ClientTls {
    pub fn new(secret: Secret) -> Self {
        Self::with_config(Self::build_config(None), secret)
    }

    pub fn with_config(config: ClientConfig, secret: Secret) -> Self {
        Self {
            session: ClientSession::new(&Arc::new(config)),
            secret,
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

    pub(crate) fn encode_key(&self) -> PacketKey {
        match self.secret {
            Secret::Handshake(cid) => PacketKey::for_client_handshake(cid),
        }
    }

    pub(crate) fn decode_key(&self, _: &PartialDecode) -> PacketKey {
        match self.secret {
            Secret::Handshake(cid) => PacketKey::for_server_handshake(cid),
        }
    }

    pub fn get_handshake(&mut self, hostname: &str) -> io::Result<Vec<u8>> {
        let pki_server_name = DNSNameRef::try_from_ascii_str(hostname).unwrap();
        let params = ClientTransportParameters {
            initial_version: 1,
            parameters: encode_transport_parameters(&vec![
                TransportParameter::InitialMaxStreamData(131072),
                TransportParameter::InitialMaxData(1048576),
                TransportParameter::IdleTimeout(300),
            ]),
        };
        self.session.get_handshake(pki_server_name, params)
    }

    pub fn process_handshake_messages(&mut self, data: &[u8]) -> Result<Vec<u8>, TLSError> {
        self.session.process_handshake_messages(data)
    }
}

pub struct ServerTls {
    session: ServerSession,
    secret: Secret,
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
        }
    }

    pub fn build_config(cert_chain: Vec<Certificate>, key: PrivateKey) -> ServerConfig {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_protocols(&[ALPN_PROTOCOL.into()]);
        config.set_single_cert(cert_chain, key);
        config
    }

    pub(crate) fn encode_key(&self) -> PacketKey {
        match self.secret {
            Secret::Handshake(cid) => PacketKey::for_server_handshake(cid),
        }
    }

    pub(crate) fn decode_key(&self, _: &PartialDecode) -> PacketKey {
        match self.secret {
            Secret::Handshake(cid) => PacketKey::for_client_handshake(cid),
        }
    }

    pub fn get_handshake(&mut self, input: &[u8]) -> Result<Vec<u8>, TLSError> {
        self.session.get_handshake(input)
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
}
