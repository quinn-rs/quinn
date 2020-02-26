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
    shared::{ConfigError, ConnectionId},
    transport_parameters::TransportParameters,
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
    /// Data conveyed by the peer during the handshake, including cryptographic identity
    type AuthenticationData: Sized;
    /// Type used to hold configuration for client sessions
    type ClientConfig: ClientConfig<Self>;
    /// Type used to sign various values
    type HmacKey: HmacKey;
    /// Type used to represent packet protection keys
    type Keys: Keys;
    /// Type used to hold configuration for server sessions
    type ServerConfig: ServerConfig<Self>;

    /// Get the data agreed upon during the cryptographic handshake
    ///
    /// For TLS, this includes the peer's certificates, the negotiated protocol and the hostname
    /// indicated by the client. Note that this data may be incomplete while the handshake is still
    /// in progress; only call it after the connection is established to get the full data.
    fn authentication_data(&self) -> Self::AuthenticationData;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<Self::Keys>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<(), TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Self::Keys>;

    /// Update the given set of keys
    fn update_keys(&self, keys: &Self::Keys) -> Self::Keys;
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig<S>: Clone
where
    S: Session,
{
    /// Construct the default configuration
    fn new() -> Self
    where
        Self: Sized;

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
    /// Construct the default configuration
    fn new() -> Self
    where
        Self: Sized;

    /// Start a server session with this configuration
    fn start_session(&self, params: &TransportParameters) -> S;
}

/// Keys used to protect packet payloads
pub trait Keys: Send {
    /// Type used for header protection keys
    type HeaderKeys: HeaderKeys;

    /// Create the initial set of keys given the initial ConnectionId
    fn new_initial(id: &ConnectionId, side: Side) -> Self;
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), ()>;
    /// Derive the header protection keys from these packet protection keys
    fn header_keys(&self) -> Self::HeaderKeys;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
}

/// Keys used to protect packet headers
pub trait HeaderKeys: Send {
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
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ()>;
}
