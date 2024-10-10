use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut};

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    shared::ConnectionId,
    RESET_TOKEN_SIZE,
};

/// Address validation token
pub(crate) enum Token {
    /// From a retry packet
    Retry {
        /// The destination connection ID set in the very first packet from the client
        orig_dst_cid: ConnectionId,
        /// The time at which this token was issued
        issued: SystemTime,
    },
    /// From a NEW_TOKEN frame
    NewToken(NewTokenToken),
}

/// Address validation token from a NEW_TOKEN frame
pub(crate) struct NewTokenToken {
    /// Randomly generated unique value
    pub(crate) rand: u128,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
}

impl Token {
    pub(crate) fn encode(
        &self,
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        match self {
            &Token::Retry {
                orig_dst_cid,
                issued,
            } => {
                let aead_key = key.aead_from_hkdf(retry_src_cid);

                let mut buf = Vec::new();
                encode_socket_addr(&mut buf, address);
                orig_dst_cid.encode_long(&mut buf);
                encode_time(&mut buf, issued);

                aead_key.seal(&mut buf, &[0]).unwrap();
                buf.push(0);
                buf
            }
            &Token::NewToken(ref token) => token.encode(key, &address.ip()),
        }
    }

    pub(crate) fn from_bytes(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        raw_token_bytes: &[u8],
    ) -> Result<Self, TokenDecodeError> {
        let last_idx = raw_token_bytes
            .len()
            .checked_sub(1)
            .ok_or(TokenDecodeError::InvalidMaybeNewToken)?;
        Ok(match raw_token_bytes[last_idx] {
            0 => {
                let aead_key = key.aead_from_hkdf(retry_src_cid);
                let mut sealed_token = raw_token_bytes[..last_idx].to_vec();

                let data = aead_key.open(&mut sealed_token, &[0])?;
                let mut reader = io::Cursor::new(data);
                let token_addr = decode_socket_addr(&mut reader)
                    .ok_or(TokenDecodeError::InvalidMaybeNewToken)?;
                if token_addr != *address {
                    return Err(TokenDecodeError::InvalidRetry);
                }
                let orig_dst_cid = ConnectionId::decode_long(&mut reader)
                    .ok_or(TokenDecodeError::InvalidMaybeNewToken)?;
                let issued =
                    decode_time(&mut reader).ok_or(TokenDecodeError::InvalidMaybeNewToken)?;

                Self::Retry {
                    orig_dst_cid,
                    issued,
                }
            }
            1 => {
                let aead_key = key.aead_from_hkdf(&[]);
                let mut sealed_token = raw_token_bytes[..last_idx].to_vec();

                let data = aead_key.open(&mut sealed_token, &[1])?;
                let mut reader = io::Cursor::new(data);
                let rand = reader.get_u128();
                let token_addr =
                    decode_ip_addr(&mut reader).ok_or(TokenDecodeError::InvalidMaybeNewToken)?;
                if token_addr != address.ip() {
                    return Err(TokenDecodeError::InvalidMaybeNewToken);
                }
                let issued =
                    decode_time(&mut reader).ok_or(TokenDecodeError::InvalidMaybeNewToken)?;

                Self::NewToken(NewTokenToken { rand, issued })
            }
            _ => return Err(TokenDecodeError::InvalidMaybeNewToken),
        })
    }
}

impl NewTokenToken {
    pub(crate) fn encode(&self, key: &dyn HandshakeTokenKey, address: &IpAddr) -> Vec<u8> {
        let aead_key = key.aead_from_hkdf(&[]);

        let mut buf = Vec::new();
        buf.put_u128(self.rand);
        encode_ip_addr(&mut buf, address);
        encode_time(&mut buf, self.issued);

        aead_key.seal(&mut buf, &[1]).unwrap();
        buf.push(1);

        buf
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
    let port = buf.get_u16();
    Some(SocketAddr::new(ip, port))
}

fn decode_ip_addr<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    Some(match buf.get_u8() {
        0 => IpAddr::V4(buf.get().ok()?),
        1 => IpAddr::V6(buf.get().ok()?),
        _ => return None,
    })
}

fn encode_time(buf: &mut Vec<u8>, time: SystemTime) {
    buf.write::<u64>(
        time.duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0),
    );
}

fn decode_time<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::new(buf.get::<u64>().ok()?, 0))
}

/// Error for an address validation token failing to validate a client's address
#[derive(Debug, Copy, Clone)]
pub(crate) enum TokenDecodeError {
    /// Token may have come from a NEW_TOKEN frame (including from a different server or a previous
    /// run of this server with different keys), and was not valid
    ///
    /// It should be silently ignored.
    InvalidMaybeNewToken,
    /// Token was unambiguously from a retry packet, and was not valid.
    ///
    /// The connection cannot be established.
    InvalidRetry,
}

impl From<CryptoError> for TokenDecodeError {
    fn from(CryptoError: CryptoError) -> Self {
        Self::InvalidMaybeNewToken
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
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    use aws_lc_rs::hkdf;
    #[cfg(feature = "ring")]
    use ring::hkdf;

    #[test]
    fn token_sanity() {
        use super::*;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::MAX_CID_SIZE;

        use rand::RngCore;
        use std::{
            net::Ipv6Addr,
            time::{Duration, UNIX_EPOCH},
        };

        let rng = &mut rand::thread_rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let orig_dst_cid_1 = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let issued_1 = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost
        let token = Token::Retry {
            orig_dst_cid: orig_dst_cid_1,
            issued: issued_1,
        };
        let encoded = token.encode(&prk, &addr, &retry_src_cid);

        match Token::from_bytes(&prk, &addr, &retry_src_cid, &encoded)
            .expect("token didn't validate")
        {
            Token::Retry {
                orig_dst_cid: orig_dst_cid_2,
                issued: issued_2,
            } => {
                assert_eq!(orig_dst_cid_1, orig_dst_cid_2);
                assert_eq!(issued_1, issued_2);
            }
            _ => panic!("token decoded as wrong variant"),
        }
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
        assert!(Token::from_bytes(&prk, &addr, &retry_src_cid, &invalid_token).is_err());
    }
}
