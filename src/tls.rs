use rustls::internal::msgs::{base::PayloadU16, codec::Codec};
use rustls::internal::msgs::quic::ClientTransportParameters;
use rustls::{ClientConfig, NoClientAuth, ProtocolVersion};
use rustls::quic::ClientSession;

use std::io;
use std::sync::Arc;

use types::TransportParameter;

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::internal::msgs::quic::{Parameter, ServerTransportParameters};
pub use rustls::{Certificate, PrivateKey, ServerConfig, Session, TLSError};
pub use rustls::quic::ServerSession;

pub struct Client {
    pub session: ClientSession,
}

impl Client {
    pub fn new() -> Client {
        Self::with_config(build_client_config(None))
    }

    pub fn with_config(config: ClientConfig) -> Client {
        Client {
            session: ClientSession::new(&Arc::new(config)),
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

pub fn build_client_config(anchors: Option<&TLSServerTrustAnchors>) -> ClientConfig {
    let mut config = ClientConfig::new();
    let anchors = anchors.unwrap_or(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store.add_server_trust_anchors(anchors);
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
    config
}

pub fn build_server_config(cert_chain: Vec<Certificate>, key: PrivateKey) -> ServerConfig {
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_protocols(&[ALPN_PROTOCOL.into()]);
    config.set_single_cert(cert_chain, key);
    config
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
