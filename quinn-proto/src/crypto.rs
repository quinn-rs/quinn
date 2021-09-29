//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic in Quinn is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::str;

use bytes::BytesMut;

use crate::{
    config::ConfigError, shared::ConnectionId, transport_parameters::TransportParameters,
    ConnectError, Side, TransportError,
};

/// Cryptography interface based on *ring*
#[cfg(feature = "ring")]
pub(crate) mod ring;
/// TLS interface based on rustls
#[cfg(feature = "rustls")]
pub mod rustls;
/// Public interface TLS types
#[cfg(feature = "rustls")]
pub(crate) mod types;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sized {
    /// Parameters determined when the handshake begins, e.g. server name and/or application
    /// protocol
    type HandshakeData;
    /// Cryptographic identity of the peer
    type Identity: Sized;
    /// Type used to hold configuration for client sessions
    type ClientConfig: ClientConfig<Self>;
    /// Type used to sign various values
    type HmacKey: HmacKey;
    /// Key used to generate one-time-use handshake token keys
    type HandshakeTokenKey: HandshakeTokenKey;
    /// Type of keys used to protect packet headers
    type HeaderKey: HeaderKey;
    /// Type used to represent packet protection keys
    type PacketKey: PacketKey;
    /// Type used to hold configuration for server sessions
    type ServerConfig: ServerConfig<Self>;

    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(dst_cid: &ConnectionId, side: Side) -> Keys<Self>;

    /// Get data negotiated during the handshake, if available
    ///
    /// Returns `None` until the connection emits `HandshakeDataReady`.
    fn handshake_data(&self) -> Option<Self::HandshakeData>;

    /// Get the peer's identity, if available
    fn peer_identity(&self) -> Option<Self::Identity>;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Self::HeaderKey, Self::PacketKey)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer.
    ///
    /// On success, returns `true` iff `self.handshake_data()` has been populated.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys<Self>>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Self::PacketKey>>;

    /// Generate the integrity tag for a retry packet
    fn retry_tag(orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16];

    /// Verify the integrity of a retry packet
    fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool;

    /// Fill `output` with `output.len()` bytes of keying material derived
    /// from the [Session]'s secrets, using `label` and `context` for domain
    /// separation.
    ///
    /// This function will fail, returning [ExportKeyingMaterialError],
    /// if the requested output length is too large.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError>;
}

/// A pair of keys for bidirectional communication
pub struct KeyPair<T> {
    /// Key for encrypting data
    pub local: T,
    /// Key for decrypting data
    pub remote: T,
}

/// A complete set of keys for a certain packet space
pub struct Keys<S>
where
    S: Session,
{
    /// Header protection keys
    pub header: KeyPair<S::HeaderKey>,
    /// Packet protection keys
    pub packet: KeyPair<S::PacketKey>,
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig<S>: Clone
where
    S: Session,
{
    /// Start a client session with this configuration
    fn start_session(
        &self,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<S, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig<S>: Clone + Send + Sync
where
    S: Session,
{
    /// Start a server session with this configuration
    fn start_session(&self, params: &TransportParameters) -> S;
}

/// Keys used to protect packet payloads
pub trait PacketKey: Send {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers
pub trait HeaderKey: Send {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

/// A key for signing with HMAC-based algorithms
pub trait HmacKey: Send + Sized + Sync {
    /// Length of the key input
    const KEY_LEN: usize;
    /// Type of the signatures created by `sign()`
    type Signature: AsRef<[u8]>;

    /// Method for creating a key
    fn new(key: &[u8]) -> Result<Self, ConfigError>;
    /// Method for signing a message
    fn sign(&self, data: &[u8]) -> Self::Signature;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// A pseudo random key for HKDF
pub trait HandshakeTokenKey: Send + Sized + Sync {
    /// AEAD key type
    type AeadKey: AeadKey;

    /// Derive AEAD using hkdf
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Self::AeadKey;
    /// Method to build pseudo random key from existing bytes
    fn from_secret(secret: &[u8]) -> Self;
}

/// A key for sealing data with AEAD-based algorithms
pub trait AeadKey {
    /// Length of AEAD Key
    const KEY_LEN: usize;

    // fn from_hkdf(master_key: &impl PseudoRandomKey, random_bytes: &[u8]) -> Self;
    /// Method for sealing message `data`
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError>;
    /// Method for opening a sealed message `data`
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError>;
}

/// Generic crypto errors
#[derive(Debug)]
pub struct CryptoError;
