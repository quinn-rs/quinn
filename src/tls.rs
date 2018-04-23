use rustls::internal::msgs::{base::PayloadU16, codec::Codec, handshake::ClientExtension,
                             quic::{ClientTransportParameters, Parameter}};
use rustls::{ClientConfig, ClientSession, ProtocolVersion, Session};

use std::sync::Arc;

use types::TransportParameter;

use webpki::DNSNameRef;
use webpki_roots;

pub struct Client {
    pub session: ClientSession,
}

impl Client {
    pub fn new(hostname: &str) -> Client {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.versions = vec![ProtocolVersion::TLSv1_3];
        config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
        let tls_config = Arc::new(config);

        let pki_server_name = DNSNameRef::try_from_ascii_str(hostname).unwrap();
        Client {
            session: ClientSession::with_handshake_exts(
                &tls_config,
                pki_server_name,
                vec![
                    ClientExtension::TransportParameters(ClientTransportParameters {
                        initial_version: 1,
                        parameters: encode_transport_parameters(&vec![
                            TransportParameter::InitialMaxStreamData(131072),
                            TransportParameter::InitialMaxData(1048576),
                            TransportParameter::IdleTimeout(300),
                        ]),
                    }),
                ],
            ),
        }
    }

    pub fn get_handshake(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.session.write_tls(&mut buf).unwrap();
        buf
    }
}

fn encode_transport_parameters(params: &[TransportParameter]) -> Vec<Parameter> {
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
