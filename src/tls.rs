use rustls::quic::{ClientQuicExt, ServerQuicExt};
use rustls::{ClientConfig, NoClientAuth, ProtocolVersion, TLSError};

use std::io::Cursor;
use std::sync::Arc;

use bytes::{Buf, BufMut};

use super::{QuicError, QuicResult};
use codec::Codec;
use crypto::Secret;
use types::{DRAFT_11, TransportParameters};

use webpki::{DNSNameRef, TLSServerTrustAnchors};
use webpki_roots;

pub use rustls::{Certificate, ClientSession, PrivateKey, ServerConfig, ServerSession, Session};

pub fn client_session(config: Option<ClientConfig>, hostname: &str) -> QuicResult<ClientSession> {
    let pki_server_name = DNSNameRef::try_from_ascii_str(hostname)
        .map_err(|_| QuicError::InvalidDnsName(hostname.into()))?;
    let params = ClientTransportParameters {
        initial_version: 1,
        parameters: TransportParameters::default(),
    };
    Ok(ClientSession::new_quic(
        &Arc::new(config.unwrap_or(build_client_config(None))),
        pki_server_name,
        to_vec(params),
    ))
}

pub fn build_client_config(anchors: Option<&TLSServerTrustAnchors>) -> ClientConfig {
    let mut config = ClientConfig::new();
    let anchors = anchors.unwrap_or(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store.add_server_trust_anchors(anchors);
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec![ALPN_PROTOCOL.into()];
    config
}

pub fn server_session(config: &Arc<ServerConfig>) -> ServerSession {
    ServerSession::new_quic(
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

pub fn process_handshake_messages<T>(session: &mut T, msgs: Option<&[u8]>) -> QuicResult<TlsResult>
where
    T: Session,
{
    if let Some(data) = msgs {
        let mut read = Cursor::new(data);
        let did_read = session.read_tls(&mut read)?;
        debug_assert_eq!(did_read, data.len());
        session.process_new_packets()?;
    }

    let key_ready = if !session.is_handshaking() {
        Some(session
            .get_negotiated_ciphersuite()
            .ok_or(TLSError::HandshakeNotComplete)?)
    } else {
        None
    };

    let mut messages = Vec::new();
    loop {
        let size = session.write_tls(&mut messages)?;
        if size == 0 {
            break;
        }
    }

    let secret = if let Some(suite) = key_ready {
        let mut client_secret = vec![0u8; suite.enc_key_len];
        session.export_keying_material(&mut client_secret, b"EXPORTER-QUIC client 1rtt", None)?;
        let mut server_secret = vec![0u8; suite.enc_key_len];
        session.export_keying_material(&mut server_secret, b"EXPORTER-QUIC server 1rtt", None)?;

        let (aead_alg, hash_alg) = (suite.get_aead_alg(), suite.get_hash());
        Some(Secret::For1Rtt(
            aead_alg,
            hash_alg,
            client_secret,
            server_secret,
        ))
    } else {
        None
    };

    Ok((messages, secret))
}

type TlsResult = (Vec<u8>, Option<Secret>);

#[derive(Clone, Debug, PartialEq)]
pub struct ClientTransportParameters {
    pub initial_version: u32,
    pub parameters: TransportParameters,
}

impl Codec for ClientTransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u32_be(self.initial_version);
        self.parameters.encode(buf);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        ClientTransportParameters {
            initial_version: buf.get_u32_be(),
            parameters: TransportParameters::decode(buf),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerTransportParameters {
    pub negotiated_version: u32,
    pub supported_versions: Vec<u32>,
    pub parameters: TransportParameters,
}

impl Codec for ServerTransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u32_be(self.negotiated_version);
        buf.put_u8((4 * self.supported_versions.len()) as u8);
        for v in self.supported_versions.iter() {
            buf.put_u32_be(*v);
        }
        self.parameters.encode(buf);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        ServerTransportParameters {
            negotiated_version: buf.get_u32_be(),
            supported_versions: {
                let mut supported_versions = vec![];
                let supported_bytes = buf.get_u8() as usize;
                let mut sub = buf.take(supported_bytes);
                while sub.has_remaining() {
                    supported_versions.push(sub.get_u32_be());
                }
                supported_versions
            },
            parameters: TransportParameters::decode(buf),
        }
    }
}

impl Codec for TransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let mut tmp = vec![];
        let mut val = vec![];

        tmp.put_u16_be(0);
        val.put_u32_be(self.max_stream_data);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        tmp.put_u16_be(1);
        val.put_u32_be(self.max_data);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        tmp.put_u16_be(3);
        val.put_u16_be(self.idle_timeout);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        if self.max_streams_bidi > 0 {
            tmp.put_u16_be(2);
            val.put_u16_be(self.max_streams_bidi);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.max_packet_size != 65527 {
            tmp.put_u16_be(5);
            val.put_u16_be(self.max_packet_size);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.ack_delay_exponent != 3 {
            tmp.put_u16_be(7);
            val.put_u8(self.ack_delay_exponent);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.max_stream_id_uni > 0 {
            tmp.put_u16_be(8);
            val.put_u16_be(self.max_stream_id_uni);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if let Some(token) = self.stateless_reset_token {
            tmp.put_u16_be(6);
            tmp.put_u16_be(16);
            tmp.extend_from_slice(&token);
        }

        buf.put_u16_be(tmp.len() as u16);
        buf.put_slice(&tmp);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let mut params = TransportParameters::default();
        let num = buf.get_u16_be();
        let mut sub = buf.take(num as usize);
        while sub.has_remaining() {
            let tag = sub.get_u16_be();
            let size = sub.get_u16_be();
            match tag {
                0 => {
                    debug_assert_eq!(size, 4);
                    params.max_stream_data = sub.get_u32_be();
                }
                1 => {
                    debug_assert_eq!(size, 4);
                    params.max_data = sub.get_u32_be();
                }
                2 => {
                    debug_assert_eq!(size, 2);
                    params.max_streams_bidi = sub.get_u16_be();
                }
                3 => {
                    debug_assert_eq!(size, 2);
                    params.idle_timeout = sub.get_u16_be();
                }
                5 => {
                    debug_assert_eq!(size, 2);
                    params.max_packet_size = sub.get_u16_be();
                }
                6 => {
                    debug_assert_eq!(size, 16);
                    let mut token = [0; 16];
                    sub.copy_to_slice(&mut token);
                    params.stateless_reset_token = Some(token);
                }
                7 => {
                    debug_assert_eq!(size, 1);
                    params.ack_delay_exponent = sub.get_u8();
                }
                8 => {
                    debug_assert_eq!(size, 2);
                    params.max_stream_id_uni = sub.get_u16_be();
                }
                t => panic!("invalid transport parameter tag {}", t),
            }
        }
        params
    }
}

fn to_vec<T: Codec>(val: T) -> Vec<u8> {
    let mut bytes = Vec::new();
    val.encode(&mut bytes);
    bytes
}

const ALPN_PROTOCOL: &'static str = "hq-11";

#[cfg(test)]
mod tests {
    use super::TransportParameters;
    use super::{ClientTransportParameters, Codec, ServerTransportParameters};
    use std::fmt::Debug;
    use std::io::Cursor;

    fn round_trip<T: Codec + PartialEq + Debug>(t: T) {
        let buf = {
            let mut ret = Vec::new();
            t.encode(&mut ret);
            ret
        };
        let mut read = Cursor::new(&buf);
        assert_eq!(t, T::decode(&mut read));
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
