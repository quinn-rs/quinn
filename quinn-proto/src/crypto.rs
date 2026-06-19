//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic in Quinn is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{any::Any, str, sync::Arc};

use bytes::BytesMut;

use crate::{
    ConnectError, Side, TransportError, VarInt, shared::ConnectionId,
    transport_parameters::TransportParameters,
};

/// Packet protection nonce input.
///
/// This is an implementation detail of Quinn's crypto abstraction, exposed only so custom
/// [`PacketKey`] implementations can support internally-negotiated multipath packet protection.
/// Existing providers that only implement [`PacketKey::encrypt`] and [`PacketKey::decrypt`] remain
/// source-compatible: the default nonce-aware methods handle ordinary packet-number nonces and
/// reject nonzero multipath path IDs with [`CryptoError`].
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PacketNonce(PacketNonceInner);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PacketNonceInner {
    PacketNumber(u64),
    PathAndPacketNumber { path_id: u32, packet_number: u64 },
}

impl PacketNonce {
    /// Construct a standard packet-number nonce input.
    pub fn packet_number(packet_number: u64) -> Self {
        Self(PacketNonceInner::PacketNumber(packet_number))
    }

    /// Construct a multipath path-and-packet-number nonce input.
    pub fn path(path_id: u32, packet_number: u64) -> Result<Self, PacketNonceError> {
        if packet_number > VarInt::MAX.into_inner() {
            return Err(PacketNonceError);
        }
        Ok(Self(PacketNonceInner::PathAndPacketNumber {
            path_id,
            packet_number,
        }))
    }

    /// Return the packet number encoded by this nonce input.
    pub fn packet_number_value(self) -> u64 {
        match self.0 {
            PacketNonceInner::PacketNumber(packet_number)
            | PacketNonceInner::PathAndPacketNumber { packet_number, .. } => packet_number,
        }
    }

    /// Return the path ID encoded by this nonce input, if any.
    pub fn path_id(self) -> Option<u32> {
        match self.0 {
            PacketNonceInner::PacketNumber(_) => None,
            PacketNonceInner::PathAndPacketNumber { path_id, .. } => Some(path_id),
        }
    }
}

/// Error returned when a multipath packet number cannot be encoded into a nonce input.
#[doc(hidden)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PacketNonceError;

/// Cryptography interface based on *ring*
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub mod rustls;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sync + 'static {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, dst_cid: ConnectionId, side: Side) -> Keys;

    /// Get data negotiated during the handshake, if available
    ///
    /// Returns `None` until the connection emits `HandshakeDataReady`.
    fn handshake_data(&self) -> Option<Box<dyn Any>>;

    /// Get the peer's identity, if available
    fn peer_identity(&self) -> Option<Box<dyn Any>>;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
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
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>>;

    /// Verify the integrity of a retry packet
    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool;

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
pub struct Keys {
    /// Header protection keys
    pub header: KeyPair<Box<dyn HeaderKey>>,
    /// Packet protection keys
    pub packet: KeyPair<Box<dyn PacketKey>>,
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, version: u32, dst_cid: ConnectionId)
    -> Result<Keys, UnsupportedVersion>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16];

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session>;
}

/// Keys used to protect packet payloads
///
/// Quinn's internal multipath support uses [`PacketNonce`] for nonzero paths. Packet key
/// implementations that do not override the nonce-aware methods remain compatible with standard
/// QUIC and report [`CryptoError`] for nonzero path IDs.
pub trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Encrypt the packet payload with the given packet protection nonce input
    #[doc(hidden)]
    fn encrypt_with_nonce(
        &self,
        nonce: PacketNonce,
        buf: &mut [u8],
        header_len: usize,
    ) -> Result<(), CryptoError> {
        match nonce.path_id() {
            None | Some(0) => {
                self.encrypt(nonce.packet_number_value(), buf, header_len);
                Ok(())
            }
            Some(_) => Err(CryptoError),
        }
    }
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// Decrypt the packet payload with the given packet protection nonce input
    #[doc(hidden)]
    fn decrypt_with_nonce(
        &self,
        nonce: PacketNonce,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        match nonce.path_id() {
            None | Some(0) => self.decrypt(nonce.packet_number_value(), header, payload),
            Some(_) => Err(CryptoError),
        }
    }
    /// Whether this key implementation can safely use draft-21 96-bit path-and-packet-number
    /// nonces.
    ///
    /// Implementations must leave this as `false` unless their AEAD nonce construction supports at
    /// least 12-byte nonce inputs and their nonce-aware encrypt/decrypt methods enforce the
    /// path-and-packet-number layout used by multipath QUIC.
    #[doc(hidden)]
    fn supports_multipath_nonce(&self) -> bool {
        false
    }
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers
pub trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

/// A key for signing with HMAC-based algorithms
pub trait HmacKey: Send + Sync {
    /// Method for signing a message
    fn sign(&self, data: &[u8], signature_out: &mut [u8]);
    /// Length of `sign`'s output
    fn signature_len(&self) -> usize;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// A pseudo random key for HKDF
pub trait HandshakeTokenKey: Send + Sync {
    /// Derive AEAD using hkdf
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey>;
}

/// A key for sealing data with AEAD-based algorithms
pub trait AeadKey {
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

#[cfg(test)]
mod tests {
    use super::{CryptoError, PacketKey, PacketNonce, PacketNonceError};
    use crate::VarInt;
    use bytes::BytesMut;

    struct LegacyPacketKey;

    impl PacketKey for LegacyPacketKey {
        fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

        fn decrypt(
            &self,
            _packet: u64,
            _header: &[u8],
            _payload: &mut BytesMut,
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn tag_len(&self) -> usize {
            0
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            u64::MAX
        }
    }

    struct MultipathPacketKey;

    impl PacketKey for MultipathPacketKey {
        fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

        fn encrypt_with_nonce(
            &self,
            nonce: PacketNonce,
            _buf: &mut [u8],
            _header_len: usize,
        ) -> Result<(), CryptoError> {
            if nonce.path_id() == Some(1) {
                Ok(())
            } else {
                Err(CryptoError)
            }
        }

        fn decrypt(
            &self,
            _packet: u64,
            _header: &[u8],
            _payload: &mut BytesMut,
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn tag_len(&self) -> usize {
            0
        }

        fn supports_multipath_nonce(&self) -> bool {
            true
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            u64::MAX
        }
    }

    #[test]
    fn packet_nonce_accepts_multipath_boundaries() {
        let path_zero = PacketNonce::path(0, 0).unwrap();
        assert_eq!(path_zero.path_id(), Some(0));
        assert_eq!(path_zero.packet_number_value(), 0);

        let path_one = PacketNonce::path(1, 0).unwrap();
        assert_eq!(path_one.path_id(), Some(1));
        assert_eq!(path_one.packet_number_value(), 0);

        let max_path = PacketNonce::path(u32::MAX, VarInt::MAX.into_inner()).unwrap();
        assert_eq!(max_path.path_id(), Some(u32::MAX));
        assert_eq!(max_path.packet_number_value(), VarInt::MAX.into_inner());
    }

    #[test]
    fn packet_nonce_rejects_invalid_packet_number() {
        assert_eq!(
            PacketNonce::path(0, VarInt::MAX.into_inner() + 1),
            Err(PacketNonceError)
        );
    }

    #[test]
    fn default_packet_key_rejects_nonzero_path_nonce() {
        let key = LegacyPacketKey;
        let mut packet = [];

        assert!(
            key.encrypt_with_nonce(PacketNonce::path(0, 7).unwrap(), &mut packet, 0)
                .is_ok()
        );
        assert!(
            key.encrypt_with_nonce(PacketNonce::path(1, 7).unwrap(), &mut packet, 0)
                .is_err()
        );
    }

    #[test]
    fn packet_key_multipath_nonce_support_is_explicit() {
        assert!(!LegacyPacketKey.supports_multipath_nonce());
        assert!(MultipathPacketKey.supports_multipath_nonce());
    }

    #[test]
    fn custom_packet_key_can_accept_nonzero_path_nonce() {
        let key = MultipathPacketKey;
        let mut packet = [];

        assert!(
            key.encrypt_with_nonce(PacketNonce::path(1, 7).unwrap(), &mut packet, 0)
                .is_ok()
        );
    }
}

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub struct UnsupportedVersion;

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
