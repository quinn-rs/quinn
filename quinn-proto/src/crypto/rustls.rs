use std::{any::Any, convert::TryInto, io, str, sync::Arc};

use bytes::BytesMut;
use ring::aead;
pub use rustls::Error;
use rustls::{
    self,
    quic::{
        ClientQuicExt, HeaderProtectionKey, KeyChange, PacketKey, QuicExt, Secrets, ServerQuicExt,
        Version,
    },
    Connection,
};

use crate::{
    crypto::{self, CryptoError, ExportKeyingMaterialError, KeyPair, Keys},
    transport_parameters::TransportParameters,
    CertificateChain, ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
};

/// A rustls TLS session
pub struct TlsSession {
    using_alpn: bool,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    type ClientConfig = Arc<rustls::ClientConfig>;
    type HeaderKey = HeaderProtectionKey;
    type ServerConfig = Arc<rustls::ServerConfig>;

    fn initial_keys(dst_cid: &ConnectionId, side: Side) -> Keys<Self> {
        let keys = rustls::quic::Keys::initial(Version::V1Draft, dst_cid, side.is_client());
        Keys {
            header: KeyPair {
                local: keys.local.header,
                remote: keys.remote.header,
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: match self.inner {
                Connection::Client(_) => None,
                Connection::Server(ref session) => session.sni_hostname().map(|x| x.into()),
            },
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner
            .peer_certificates()
            .map(|v| -> Box<dyn Any> { Box::new(CertificateChain::from(v.to_vec())) })
    }

    fn early_crypto(&self) -> Option<(Self::HeaderKey, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((keys.header, Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.get_u8()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {}", e))
            }
        })?;
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.sni_hostname().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                if self.using_alpn && self.inner.alpn_protocol().is_none() {
                    // rustls ignores total ALPN failure for compat, but QUIC gets a fresh start
                    return Err(TransportError {
                        code: TransportErrorCode::crypto(0x78),
                        frame: None,
                        reason: "ALPN negotiation failed".into(),
                    });
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys<Self>> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: keys.local.header,
                remote: keys.remote.header,
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn retry_tag(orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }

    fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner
            .export_keying_material(output, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

impl crypto::HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// Authentication data for (rustls) TLS session
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
}

impl crypto::ClientConfig<TlsSession> for Arc<rustls::ClientConfig> {
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<TlsSession, ConnectError> {
        Ok(TlsSession {
            using_alpn: !self.alpn_protocols.is_empty(),
            got_handshake_data: false,
            next_secrets: None,
            inner: Connection::Client(
                rustls::ClientConnection::new_quic(
                    self.clone(),
                    Version::V1Draft,
                    server_name
                        .try_into()
                        .map_err(|_| ConnectError::InvalidDnsName(server_name.into()))?,
                    to_vec(params),
                )
                .unwrap(),
            ),
        })
    }
}

impl crypto::ServerConfig<TlsSession> for Arc<rustls::ServerConfig> {
    fn start_session(&self, params: &TransportParameters) -> TlsSession {
        TlsSession {
            using_alpn: !self.alpn_protocols.is_empty(),
            got_handshake_data: false,
            next_secrets: None,
            inner: Connection::Server(
                rustls::ServerConnection::new_quic(self.clone(), Version::V1Draft, to_vec(params))
                    .unwrap(),
            ),
        }
    }
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self.encrypt_in_place(packet, &*header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, &*header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit()
    }
}
