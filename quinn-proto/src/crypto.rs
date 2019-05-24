use std::str;

use bytes::BytesMut;

use crate::shared::ConnectionId;
use crate::transport_parameters::TransportParameters;
use crate::{ConnectError, Side, TransportError};

/// Cryptography interface based on *ring*
pub mod ring;
/// TLS interface based on rustls
pub mod rustls;

pub(crate) trait Session {
    type ClientConfig: ClientConfig;
    type Keys: Keys;
    type HeaderKeys: HeaderKeys;
    type ServerConfig: ServerConfig;

    fn alpn_protocol(&self) -> Option<&[u8]>;
    fn early_crypto(&self) -> Option<Self::Keys>;
    fn early_data_accepted(&self) -> Option<bool>;
    fn is_handshaking(&self) -> bool;
    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError>;
    fn sni_hostname(&self) -> Option<&str>;
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Self::Keys>;
    fn update_keys(&self, keys: &Self::Keys) -> Self::Keys;
}

pub(crate) trait ClientConfig {
    type Session: Session;
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Self::Session, ConnectError>;
}

pub(crate) trait ServerConfig {
    type Session: Session;
    fn start_session(&self, params: &TransportParameters) -> Self::Session;
}

pub(crate) trait Keys {
    type HeaderKeys: HeaderKeys;

    fn new_initial(id: &ConnectionId, side: Side) -> Self;
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()>;
    fn header_keys(&self) -> Self::HeaderKeys;
    fn tag_len(&self) -> usize;
}

pub(crate) trait HeaderKeys {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    fn sample_size(&self) -> usize;
}
