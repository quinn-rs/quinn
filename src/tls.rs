use rustls::internal::msgs::codec::{self, Codec};
use rustls::{ClientConfig, NoClientAuth, ProtocolVersion, TLSError};

use std::io::Cursor;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crypto::Secret;
use types::{DRAFT_11, TransportParameters};

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::quic::{QuicClientTls, QuicServerTls};
pub use rustls::{Certificate, PrivateKey, ServerConfig, Session};

pub fn client_session(config: Option<ClientConfig>) -> QuicClientTls {
    QuicClientTls::new(&Arc::new(config.unwrap_or(build_client_config(None))))
}

pub fn build_client_config(anchors: Option<&TLSServerTrustAnchors>) -> ClientConfig {
    let mut config = ClientConfig::new();
    let anchors = anchors.unwrap_or(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store.add_server_trust_anchors(anchors);
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
    config
}

pub fn start_handshake(tls: &mut QuicClientTls, hostname: &str) -> Result<TlsResult, TLSError> {
    let pki_server_name = DNSNameRef::try_from_ascii_str(hostname).unwrap();
    let params = ClientTransportParameters {
        initial_version: 1,
        parameters: TransportParameters::default(),
    };
    tls.start_handshake(pki_server_name, to_vec(params));
    process_handshake_messages(tls, None)
}

pub fn server_session(config: &Arc<ServerConfig>) -> QuicServerTls {
    QuicServerTls::new(
        config,
        to_vec(ServerTransportParameters {
            negotiated_version: DRAFT_11,
            supported_versions: vec![DRAFT_11],
            parameters: TransportParameters::default(),
        }),
    )
}

pub fn build_server_config(cert_chain: Vec<Certificate>, key: PrivateKey) -> ServerConfig {
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_protocols(&[ALPN_PROTOCOL.into()]);
    config.set_single_cert(cert_chain, key);
    config
}

pub fn process_handshake_messages<T, S>(
    session: &mut T,
    msgs: Option<&[u8]>,
) -> Result<TlsResult, TLSError>
where
    T: DerefMut + Deref<Target = S>,
    S: Session,
{
    if let Some(data) = msgs {
        let mut read = Cursor::new(data);
        let did_read = session.read_tls(&mut read).unwrap();
        debug_assert_eq!(did_read, data.len());
        session.process_new_packets()?;
    }

    let key_ready = if !session.is_handshaking() {
        let suite = session
            .get_negotiated_ciphersuite()
            .ok_or(TLSError::HandshakeNotComplete)
            .unwrap();

        let mut secret = vec![0u8; suite.enc_key_len];
        session.export_keying_material(&mut secret, b"EXPORTER-QUIC client 1rtt", None)?;
        Some((suite, secret))
    } else {
        None
    };

    let mut messages = Vec::new();
    loop {
        let size = session.write_tls(&mut messages).unwrap();
        if size == 0 {
            break;
        }
    }

    let secret = if let Some((suite, secret)) = key_ready {
        let (aead_alg, hash_alg) = (suite.get_aead_alg(), suite.get_hash());
        Some(Secret::For1Rtt(aead_alg, hash_alg, secret))
    } else {
        None
    };

    Ok((messages, secret))
}

type TlsResult = (Vec<u8>, Option<Secret>);

macro_rules! try_ret(
    ($e:expr) => (match $e { Some(e) => e, None => return None })
);

#[derive(Clone, Debug, PartialEq)]
pub struct ClientTransportParameters {
    pub initial_version: u32,
    pub parameters: TransportParameters,
}

impl codec::Codec for ClientTransportParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.initial_version.encode(bytes);
        self.parameters.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(ClientTransportParameters {
            initial_version: try_ret!(u32::read(r)),
            parameters: try_ret!(TransportParameters::read(r)),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerTransportParameters {
    pub negotiated_version: u32,
    pub supported_versions: Vec<u32>,
    pub parameters: TransportParameters,
}

impl codec::Codec for ServerTransportParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.negotiated_version.encode(bytes);
        codec::encode_vec_u8(bytes, &self.supported_versions);
        self.parameters.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(ServerTransportParameters {
            negotiated_version: try_ret!(u32::read(r)),
            supported_versions: try_ret!(codec::read_vec_u8(r)),
            parameters: try_ret!(TransportParameters::read(r)),
        })
    }
}

impl Codec for TransportParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut tmp = Vec::new();
        let mut buf = Vec::new();

        0u16.encode(&mut tmp);
        self.max_stream_data.encode(&mut buf);
        (buf.len() as u16).encode(&mut tmp);
        tmp.append(&mut buf);

        1u16.encode(&mut tmp);
        self.max_data.encode(&mut buf);
        (buf.len() as u16).encode(&mut tmp);
        tmp.append(&mut buf);

        3u16.encode(&mut tmp);
        self.idle_timeout.encode(&mut buf);
        (buf.len() as u16).encode(&mut tmp);
        tmp.append(&mut buf);

        if self.max_streams_bidi > 0 {
            2u16.encode(&mut tmp);
            self.max_streams_bidi.encode(&mut buf);
            (buf.len() as u16).encode(&mut tmp);
            tmp.append(&mut buf);
        }

        if self.max_packet_size != 65527 {
            5u16.encode(&mut tmp);
            self.max_packet_size.encode(&mut buf);
            (buf.len() as u16).encode(&mut tmp);
            tmp.append(&mut buf);
        }

        if self.ack_delay_exponent != 3 {
            7u16.encode(&mut tmp);
            self.ack_delay_exponent.encode(&mut buf);
            (buf.len() as u16).encode(&mut tmp);
            tmp.append(&mut buf);
        }

        if self.max_stream_id_uni > 0 {
            8u16.encode(&mut tmp);
            self.max_stream_id_uni.encode(&mut buf);
            (buf.len() as u16).encode(&mut tmp);
            tmp.append(&mut buf);
        }

        if let Some(token) = self.stateless_reset_token {
            6u16.encode(&mut tmp);
            16u16.encode(&mut tmp);
            tmp.extend_from_slice(&token);
        }

        (tmp.len() as u16).encode(bytes);
        bytes.append(&mut tmp);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let mut params = TransportParameters::default();
        let num = try_ret!(u16::read(r));
        let mut sub = try_ret!(r.sub(num as usize));
        while sub.any_left() {
            let tag = try_ret!(u16::read(&mut sub));
            let size = try_ret!(u16::read(&mut sub));
            match tag {
                0 => {
                    debug_assert_eq!(size, 4);
                    params.max_stream_data = try_ret!(u32::read(&mut sub));
                }
                1 => {
                    debug_assert_eq!(size, 4);
                    params.max_data = try_ret!(u32::read(&mut sub));
                }
                2 => {
                    debug_assert_eq!(size, 4);
                    params.max_streams_bidi = try_ret!(u32::read(&mut sub));
                }
                3 => {
                    debug_assert_eq!(size, 2);
                    params.idle_timeout = try_ret!(u16::read(&mut sub));
                }
                5 => {
                    debug_assert_eq!(size, 2);
                    params.max_packet_size = try_ret!(u16::read(&mut sub));
                }
                6 => {
                    debug_assert_eq!(size, 16);
                    let mut token = [0; 16];
                    token.as_mut().copy_from_slice(try_ret!(sub.take(16)));
                    params.stateless_reset_token = Some(token);
                }
                7 => {
                    debug_assert_eq!(size, 1);
                    params.ack_delay_exponent = try_ret!(u8::read(&mut sub));
                }
                8 => {
                    debug_assert_eq!(size, 4);
                    params.max_stream_id_uni = try_ret!(u32::read(&mut sub));
                }
                t => panic!("invalid transport parameter tag {}", t),
            }
        }
        Some(params)
    }
}

fn to_vec<T: Codec>(val: T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.encode(&mut bytes);
    bytes
}

const ALPN_PROTOCOL: &'static str = "hq-10";

#[cfg(test)]
mod tests {
    use super::{codec, ClientTransportParameters, Codec, ServerTransportParameters};
    use super::TransportParameters;

    fn round_trip<T: Codec + PartialEq>(t: T) {
        let buf = {
            let mut ret = Vec::new();
            t.encode(&mut ret);
            ret
        };
        let mut r = codec::Reader::init(&buf);
        assert_eq!(Some(t), T::read(&mut r));
    }

    #[test]
    fn test_client_transport_parameters() {
        round_trip(ClientTransportParameters {
            initial_version: 1,
            parameters: TransportParameters {
                max_stream_data: 0,
                max_data: 1234,
                idle_timeout: 26,
                ..Default::default()
            },
        });
    }

    #[test]
    fn test_server_transport_parameters() {
        round_trip(ServerTransportParameters {
            negotiated_version: 1,
            supported_versions: vec![1, 2, 3],
            parameters: TransportParameters {
                stateless_reset_token: Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                ..Default::default()
            },
        });
    }
}
