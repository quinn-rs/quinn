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
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        let aead_key = key.aead_from_hkdf(retry_src_cid);

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

    pub(crate) fn from_bytes(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        raw_token_bytes: &[u8],
    ) -> Result<Self, TokenDecodeError> {
        let aead_key = key.aead_from_hkdf(retry_src_cid);
        let mut sealed_token = raw_token_bytes.to_vec();

        let data = aead_key.open(&mut sealed_token, &[])?;
        let mut reader = io::Cursor::new(data);
        let token_addr = decode_addr(&mut reader).ok_or(TokenDecodeError::UnknownToken)?;
        if token_addr != *address {
            return Err(TokenDecodeError::WrongAddress);
        }
        let orig_dst_cid =
            ConnectionId::decode_long(&mut reader).ok_or(TokenDecodeError::UnknownToken)?;
        let issued = UNIX_EPOCH
            + Duration::new(
                reader
                    .get::<u64>()
                    .map_err(|_| TokenDecodeError::UnknownToken)?,
                0,
            );

        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }
}

fn encode_addr(buf: &mut Vec<u8>, address: &SocketAddr) {
    match address.ip() {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
    buf.put_u16(address.port());
}

fn decode_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = match buf.get_u8() {
        0 => IpAddr::V4(buf.get().ok()?),
        1 => IpAddr::V6(buf.get().ok()?),
        _ => return None,
    };
    let port = buf.get_u16();
    Some(SocketAddr::new(ip, port))
}

/// Reasons why a retry token might fail to validate a client's address
#[derive(Debug, Copy, Clone)]
pub(crate) enum TokenDecodeError {
    /// Token was not recognized. It should be silently ignored.
    UnknownToken,
    /// Token was well-formed but associated with an incorrect address. The connection cannot be
    /// established.
    WrongAddress,
}

impl From<CryptoError> for TokenDecodeError {
    fn from(CryptoError: CryptoError) -> Self {
        Self::UnknownToken
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

#[cfg(test)]
mod test {
    #[cfg(feature = "ring")]
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

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let token = RetryToken {
            orig_dst_cid: RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid(),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&prk, &addr, &retry_src_cid);

        let decoded = RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &encoded)
            .expect("token didn't validate");
        assert_eq!(token.orig_dst_cid, decoded.orig_dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }

    #[cfg(feature = "ring")]
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

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &invalid_token).is_err());
    }
}
