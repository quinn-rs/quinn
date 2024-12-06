use std::{
    fmt, io,
    mem::size_of,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut};
use rand::Rng;
use tracing::*;

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    packet::InitialHeader,
    shared::ConnectionId,
    Duration, ServerConfig, SystemTime, RESET_TOKEN_SIZE, UNIX_EPOCH,
};

/// Error for when a validation token may have been reused
pub struct TokenReuseError;

/// Responsible for limiting clients' ability to reuse validation tokens
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
///
/// `TokenLog` pertains only to tokens provided in NEW_TOKEN frames.
pub trait TokenLog: Send + Sync {
    /// Record that the token was used and, ideally, return a token reuse error if the token was
    /// already used previously
    ///
    /// False negatives and false positives are both permissible. Called when a client uses an
    /// address validation token.
    ///
    /// Parameters:
    /// - `rand`: A server-generated random unique value for the token.
    /// - `issued`: The time the server issued the token.
    /// - `lifetime`: The expiration time of address validation tokens sent via NEW_TOKEN frames,
    ///   as configured by [`ServerConfig::validation_token_lifetime`][1].
    ///
    /// [1]: crate::ServerConfig::validation_token_lifetime
    fn check_and_insert(
        &self,
        rand: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// State in an `Incoming` determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingTokenState {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
    pub(crate) validated: bool,
}

impl IncomingTokenState {
    /// Construct for an `Incoming` which is not validated by a token
    pub(crate) fn default(header: &InitialHeader) -> Self {
        Self {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
            validated: false,
        }
    }
}

/// An address validation / retry token
///
/// The data in this struct is encoded and encrypted in the context of not only a handshake token
/// key, but also a client socket address.
pub(crate) struct Token {
    /// Randomly generated value, which must be unique, and is visible to the client
    pub(crate) rand: u128,
    /// Content which is encrypted from the client
    pub(crate) inner: TokenInner,
}

impl Token {
    /// Construct with newly sampled randomness
    pub(crate) fn new<R: Rng>(rng: &mut R, inner: TokenInner) -> Self {
        Self {
            rand: rng.gen(),
            inner,
        }
    }

    /// Encode and encrypt
    pub(crate) fn encode(&self, key: &dyn HandshakeTokenKey, address: &SocketAddr) -> Vec<u8> {
        let mut buf = Vec::new();

        self.inner.encode(&mut buf, address);
        let aead_key = key.aead_from_hkdf(&self.rand.to_le_bytes());
        aead_key.seal(&mut buf, &[]).unwrap();

        buf.extend(&self.rand.to_le_bytes());
        buf
    }

    pub(crate) fn decode(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        raw_token_bytes: &[u8],
    ) -> Result<Self, ValidationError> {
        let rand_slice_start = raw_token_bytes
            .len()
            .checked_sub(size_of::<u128>())
            .ok_or(ValidationError::Ignore)?;
        let mut rand_bytes = [0; size_of::<u128>()];
        rand_bytes.copy_from_slice(&raw_token_bytes[rand_slice_start..]);
        let rand = u128::from_le_bytes(rand_bytes);

        let aead_key = key.aead_from_hkdf(&rand_bytes);
        let mut sealed_inner = raw_token_bytes[..rand_slice_start].to_vec();
        let encoded = aead_key.open(&mut sealed_inner, &[])?;

        let mut cursor = io::Cursor::new(encoded);
        let inner = TokenInner::decode(&mut cursor, address)?;
        if cursor.has_remaining() {
            return Err(ValidationError::Ignore);
        }

        Ok(Self { rand, inner })
    }

    /// Ensure that this token validates an `Incoming`, and construct its token state
    pub(crate) fn validate(
        &self,
        header: &InitialHeader,
        server_config: &ServerConfig,
    ) -> Result<IncomingTokenState, ValidationError> {
        self.inner.validate(self.rand, header, server_config)
    }
}

/// Content of [`Token`] depending on how token originated that is encrypted from the client
pub(crate) enum TokenInner {
    Retry(RetryTokenInner),
    Validation(ValidationTokenInner),
}

impl TokenInner {
    /// Encode without encryption
    fn encode(&self, buf: &mut Vec<u8>, address: &SocketAddr) {
        match *self {
            Self::Retry(ref inner) => {
                buf.push(0);
                inner.encode(buf, address);
            }
            Self::Validation(ref inner) => {
                buf.push(1);
                inner.encode(buf, address);
            }
        }
    }

    /// Try to decode without encryption, but do validate that the address is acceptable
    fn decode<B: Buf>(buf: &mut B, address: &SocketAddr) -> Result<Self, ValidationError> {
        match buf.get::<u8>().ok().ok_or(ValidationError::Ignore)? {
            0 => RetryTokenInner::decode(buf, address).map(Self::Retry),
            1 => ValidationTokenInner::decode(buf, address).map(Self::Validation),
            _ => Err(ValidationError::Ignore),
        }
    }

    /// Ensure that this token validates an `Incoming`, and construct its token state
    pub(crate) fn validate(
        &self,
        rand: u128,
        header: &InitialHeader,
        server_config: &ServerConfig,
    ) -> Result<IncomingTokenState, ValidationError> {
        match *self {
            Self::Retry(ref inner) => inner.validate(header, server_config),
            Self::Validation(ref inner) => inner.validate(rand, header, server_config),
        }
    }
}

/// Content of [`Token`] originating from Retry packet that is encrypted from the client
pub(crate) struct RetryTokenInner {
    /// The destination connection ID set in the very first packet from the client
    pub(crate) orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl RetryTokenInner {
    /// Encode without encryption
    fn encode(&self, buf: &mut Vec<u8>, address: &SocketAddr) {
        encode_socket_addr(buf, address);
        self.orig_dst_cid.encode_long(buf);
        encode_time(buf, self.issued);
    }

    /// Try to decode without encryption, but do validate that the address is acceptable
    fn decode<B: Buf>(buf: &mut B, address: &SocketAddr) -> Result<Self, ValidationError> {
        let token_address = decode_socket_addr(buf).ok_or(ValidationError::Ignore)?;
        if token_address != *address {
            return Err(ValidationError::InvalidRetry);
        }
        let orig_dst_cid = ConnectionId::decode_long(buf).ok_or(ValidationError::Ignore)?;
        let issued = decode_time(buf).ok_or(ValidationError::Ignore)?;
        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }

    /// Ensure that this token validates an `Incoming`, and construct its token state
    pub(crate) fn validate(
        &self,
        header: &InitialHeader,
        server_config: &ServerConfig,
    ) -> Result<IncomingTokenState, ValidationError> {
        if self.issued + server_config.retry_token_lifetime > SystemTime::now() {
            Ok(IncomingTokenState {
                retry_src_cid: Some(header.dst_cid),
                orig_dst_cid: self.orig_dst_cid,
                validated: true,
            })
        } else {
            Err(ValidationError::InvalidRetry)
        }
    }
}

/// Content of [`Token`] originating from NEW_TOKEN frame that is encrypted from the client
pub(crate) struct ValidationTokenInner {
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl ValidationTokenInner {
    /// Encode without encryption
    fn encode(&self, buf: &mut Vec<u8>, address: &SocketAddr) {
        encode_ip_addr(buf, &address.ip());
        encode_time(buf, self.issued);
    }

    /// Try to decode without encryption, but do validate that the address is acceptable
    fn decode<B: Buf>(buf: &mut B, address: &SocketAddr) -> Result<Self, ValidationError> {
        let token_address = decode_ip_addr(buf).ok_or(ValidationError::Ignore)?;
        if token_address != address.ip() {
            return Err(ValidationError::Ignore);
        }
        let issued = decode_time(buf).ok_or(ValidationError::Ignore)?;
        Ok(Self { issued })
    }

    /// Ensure that this token validates an `Incoming`, and construct its token state
    pub(crate) fn validate(
        &self,
        rand: u128,
        header: &InitialHeader,
        server_config: &ServerConfig,
    ) -> Result<IncomingTokenState, ValidationError> {
        let Some(ref log) = server_config.validation_token_log else {
            return Err(ValidationError::Ignore);
        };
        let log_result =
            log.check_and_insert(rand, self.issued, server_config.validation_token_lifetime);
        if log_result.is_err() {
            debug!("rejecting token from NEW_TOKEN frame because detected as reuse");
            Err(ValidationError::Ignore)
        } else if self.issued + server_config.validation_token_lifetime < SystemTime::now() {
            Err(ValidationError::Ignore)
        } else {
            Ok(IncomingTokenState {
                retry_src_cid: None,
                orig_dst_cid: header.dst_cid,
                validated: true,
            })
        }
    }
}

fn encode_socket_addr(buf: &mut Vec<u8>, address: &SocketAddr) {
    encode_ip_addr(buf, &address.ip());
    buf.put_u16(address.port());
}

fn encode_ip_addr(buf: &mut Vec<u8>, address: &IpAddr) {
    match address {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
}

fn decode_socket_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip_addr(buf)?;
    let port = buf.get::<u16>().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn decode_ip_addr<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    Some(match buf.get::<u8>().ok()? {
        0 => IpAddr::V4(buf.get().ok()?),
        1 => IpAddr::V6(buf.get().ok()?),
        _ => return None,
    })
}

fn encode_time(buf: &mut Vec<u8>, time: SystemTime) {
    let unix_secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    buf.write::<u64>(unix_secs);
}

fn decode_time<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::from_secs(buf.get::<u64>().ok()?))
}

/// Error for a token failing to validate a client's address
#[derive(Debug, Copy, Clone)]
pub(crate) enum ValidationError {
    /// Token may have come from a NEW_TOKEN frame (including from a different server or a previous
    /// run of this server with different keys), and was not valid
    ///
    /// It should be silently ignored.
    ///
    /// In cases where a token cannot be decrypted/decoded, we must allow for the possibility that
    /// this is caused not by client malfeasance, but by the token having been generated by an
    /// incompatible endpoint, e.g. a different version or a neighbor behind the same load
    /// balancer. In such cases we proceed as if there was no token.
    ///
    /// [_RFC 9000 § 8.1.3:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3-10)
    ///
    /// > If the token is invalid, then the server SHOULD proceed as if the client did not have a
    /// > validated address, including potentially sending a Retry packet.
    ///
    /// That said, this may also be used when a token _can_ be unambiguously decrypted/decoded as a
    /// token from a NEW_TOKEN frame, but is simply not valid.
    Ignore,
    /// Token was unambiguously from a Retry packet, and was not valid
    ///
    /// The connection cannot be established.
    InvalidRetry,
}

impl From<CryptoError> for ValidationError {
    fn from(CryptoError: CryptoError) -> Self {
        Self::Ignore
    }
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derived_hash_with_manual_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: &ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(id, &mut signature);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod test {
    use super::*;
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    use aws_lc_rs::hkdf;
    use rand::prelude::*;
    #[cfg(feature = "ring")]
    use ring::hkdf;

    fn token_round_trip(inner: TokenInner) -> TokenInner {
        let rng = &mut rand::thread_rng();
        let token = Token::new(rng, inner);
        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);
        let addr = SocketAddr::new(rng.gen::<u128>().to_ne_bytes().into(), rng.gen::<u16>());
        let encoded = token.encode(&prk, &addr);
        let decoded = Token::decode(&prk, &addr, &encoded).expect("token didn't decrypt / decode");
        assert_eq!(token.rand, decoded.rand);
        decoded.inner
    }

    fn retry_token_sanity() {
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;
        use crate::{Duration, UNIX_EPOCH};

        let orig_dst_cid_1 = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let issued_1 = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost

        let inner_1 = TokenInner::Retry(RetryTokenInner {
            orig_dst_cid: orig_dst_cid_1,
            issued: issued_1,
        });
        let inner_2 = token_round_trip(inner_1);
        let TokenInner::Retry(RetryTokenInner {
            orig_dst_cid: orig_dst_cid_2,
            issued: issued_2,
        }) = inner_2
        else {
            panic!("token decoded as wrong variant")
        };

        assert_eq!(orig_dst_cid_1, orig_dst_cid_2);
        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn validation_token_sanity() {
        use crate::{Duration, UNIX_EPOCH};

        let issued_1 = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost

        let inner_1 = TokenInner::Validation(ValidationTokenInner { issued: issued_1 });
        let inner_2 = token_round_trip(inner_1);
        let TokenInner::Validation(ValidationTokenInner { issued: issued_2 }) = inner_2 else {
            panic!("token decoded as wrong variant")
        };

        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn invalid_token_returns_err() {
        use super::*;
        use rand::RngCore;
        use std::net::Ipv6Addr;

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(Token::decode(&prk, &addr, &invalid_token).is_err());
    }
}
