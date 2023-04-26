use std::sync::Arc;

use bytes::BytesMut;

use quinn_proto::{
    crypto::{self, CryptoError},
    transport_parameters, ConnectionId, Side, TransportError,
};

/// A rustls TLS session which does not perform packet encryption/decryption (for debugging purpose)
struct NoProtectionSession {
    inner: Box<dyn crypto::Session>,
}

impl NoProtectionSession {
    fn new(tls: Box<dyn crypto::Session>) -> Self {
        Self { inner: tls }
    }

    /// Wraps the provided keys in `NoProtectionPacketKey` to disable packet encryption / decryption
    fn wrap_packet_keys(
        keys: crypto::KeyPair<Box<dyn crypto::PacketKey>>,
    ) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
        crypto::KeyPair {
            local: Box::new(NoProtectionPacketKey::new(keys.local)),
            remote: Box::new(NoProtectionPacketKey::new(keys.remote)),
        }
    }
}

struct NoProtectionPacketKey {
    inner: Box<dyn crypto::PacketKey>,
}

impl NoProtectionPacketKey {
    fn new(key: Box<dyn crypto::PacketKey>) -> Self {
        Self { inner: key }
    }
}

pub struct NoProtectionClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

impl NoProtectionClientConfig {
    pub fn new(config: Arc<rustls::ClientConfig>) -> Self {
        Self { inner: config }
    }
}

pub struct NoProtectionServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

impl NoProtectionServerConfig {
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self { inner: config }
    }
}

// forward all calls to inner except those related to packet encryption/decryption
impl crypto::Session for NoProtectionSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let (hkey, pkey) = self.inner.early_crypto()?;

        // use wrapper type to disable packet encryption/decryption
        Some((hkey, Box::new(NoProtectionPacketKey::new(pkey))))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<transport_parameters::TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        let keys = self.inner.write_handshake(buf)?;

        Some(crypto::Keys {
            header: keys.header,
            packet: Self::wrap_packet_keys(keys.packet),
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        let keys = self.inner.next_1rtt_keys()?;
        Some(Self::wrap_packet_keys(keys))
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

impl crypto::ClientConfig for NoProtectionClientConfig {
    fn start_session(
        self: std::sync::Arc<Self>,
        version: u32,
        server_name: &str,
        params: &transport_parameters::TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, quinn::ConnectError> {
        let tls = self
            .inner
            .clone()
            .start_session(version, server_name, params)?;

        Ok(Box::new(NoProtectionSession::new(tls)))
    }
}

impl crypto::ServerConfig for NoProtectionServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.inner.initial_keys(version, dst_cid, side)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &transport_parameters::TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let tls = self.inner.clone().start_session(version, params);

        Box::new(NoProtectionSession::new(tls))
    }
}

// forward all calls to inner except those related to packet encryption/decryption
impl crypto::PacketKey for NoProtectionPacketKey {
    fn encrypt(&self, _packet: u64, buf: &mut [u8], header_len: usize) {
        let (_header, payload_tag) = buf.split_at_mut(header_len);
        let (_payload, tag_storage) =
            payload_tag.split_at_mut(payload_tag.len() - self.inner.tag_len());
        // packet = identity(packet)
        tag_storage.fill(42);
    }

    fn decrypt(
        &self,
        _packet: u64,
        _header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain_len = payload.len() - self.inner.tag_len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.inner.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.inner.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.inner.integrity_limit()
    }
}
