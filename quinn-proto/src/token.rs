use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut};

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    packet::InitialHeader,
    shared::ConnectionId,
    Duration, ServerConfig, SystemTime, RESET_TOKEN_SIZE, UNIX_EPOCH,
};

/// State in an `Incoming` determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingToken {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
}

impl IncomingToken {
    /// Construct for an `Incoming` given the first packet header, or error if the connection
    /// cannot be established
    pub(crate) fn from_header(
        header: &InitialHeader,
        server_config: &ServerConfig,
        remote_address: SocketAddr,
    ) -> Result<Self, InvalidRetryTokenError> {
        let unvalidated = Self {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
        };

        if header.token.is_empty() {
            return Ok(unvalidated);
        }

        let result = RetryToken::decode(
            &*server_config.token_key,
            remote_address,
            header.dst_cid,
            &header.token,
        );

        let retry = match result {
            Ok(retry) => retry,
            Err(ValidationError::Unusable) => return Ok(unvalidated),
            Err(ValidationError::InvalidRetry) => return Err(InvalidRetryTokenError),
        };

        if retry.issued + server_config.retry_token_lifetime < server_config.time_source.now() {
            return Err(InvalidRetryTokenError);
        }

        Ok(Self {
            retry_src_cid: Some(header.dst_cid),
            orig_dst_cid: retry.orig_dst_cid,
        })
    }
}

/// Error for a token being unambiguously from a Retry packet, and not valid
///
/// The connection cannot be established.
pub(crate) struct InvalidRetryTokenError;

pub(crate) struct RetryToken {
    /// The destination connection ID set in the very first packet from the client
    pub(crate) orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl RetryToken {
    pub(crate) fn encode(
        &self,
        key: &dyn HandshakeTokenKey,
        address: SocketAddr,
        retry_src_cid: ConnectionId,
    ) -> Vec<u8> {
        let aead_key = key.aead_from_hkdf(&retry_src_cid);

        let mut buf = Vec::new();
        encode_addr(&mut buf, address);
        self.orig_dst_cid.encode_long(&mut buf);
        buf.write::<u64>(
            self.issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );

        aead_key.seal(&mut buf, &[]).unwrap();

        buf
    }

    fn decode(
        key: &dyn HandshakeTokenKey,
        address: SocketAddr,
        retry_src_cid: ConnectionId,
        raw_token_bytes: &[u8],
    ) -> Result<Self, ValidationError> {
        let aead_key = key.aead_from_hkdf(&retry_src_cid);
        let mut sealed_token = raw_token_bytes.to_vec();

        let data = aead_key.open(&mut sealed_token, &[])?;
        let mut reader = io::Cursor::new(data);
        let token_addr = decode_addr(&mut reader).ok_or(ValidationError::Unusable)?;
        if token_addr != address {
            return Err(ValidationError::InvalidRetry);
        }
        let orig_dst_cid =
            ConnectionId::decode_long(&mut reader).ok_or(ValidationError::Unusable)?;
        let issued = UNIX_EPOCH
            + Duration::new(
                reader.get::<u64>().map_err(|_| ValidationError::Unusable)?,
                0,
            );

        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }
}

fn encode_addr(buf: &mut Vec<u8>, address: SocketAddr) {
    encode_ip(buf, address.ip());
    buf.put_u16(address.port());
}

fn decode_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip(buf)?;
    let port = buf.get_u16();
    Some(SocketAddr::new(ip, port))
}

fn encode_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
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

fn decode_ip<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    match buf.get_u8() {
        0 => buf.get().ok().map(IpAddr::V4),
        1 => buf.get().ok().map(IpAddr::V6),
        _ => None,
    }
}

/// Error for a token failing to validate a client's address
#[derive(Debug, Copy, Clone)]
enum ValidationError {
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
    Unusable,
    /// Token was unambiguously from a Retry packet, and was not valid
    ///
    /// The connection cannot be established.
    InvalidRetry,
}

impl From<CryptoError> for ValidationError {
    fn from(CryptoError: CryptoError) -> Self {
        Self::Unusable
    }
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derived_hash_with_manual_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(&id, &mut signature);
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
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    use aws_lc_rs::hkdf;
    #[cfg(feature = "ring")]
    use ring::hkdf;

    #[test]
    fn token_sanity() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;
        use crate::{Duration, UNIX_EPOCH};

        use rand::RngCore;
        use std::net::Ipv6Addr;

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let token = RetryToken {
            orig_dst_cid: RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid(),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&prk, addr, retry_src_cid);

        let decoded =
            RetryToken::decode(&prk, addr, retry_src_cid, &encoded).expect("token didn't validate");
        assert_eq!(token.orig_dst_cid, decoded.orig_dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }

    #[test]
    fn invalid_token_returns_err() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;
        use rand::RngCore;
        use std::net::Ipv6Addr;

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(RetryToken::decode(&prk, addr, retry_src_cid, &invalid_token).is_err());
    }
}
