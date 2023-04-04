use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::BufMut;

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    shared::ConnectionId,
    RESET_TOKEN_SIZE,
};

pub(crate) struct RetryToken<'a> {
    /// The destination connection ID set in the very first packet from the client
    pub(crate) orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub(crate) issued: SystemTime,
    /// Random bytes for deriving AEAD key
    pub(crate) random_bytes: &'a [u8],
}

impl<'a> RetryToken<'a> {
    pub(crate) fn encode(
        &self,
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        let aead_key = key.aead_from_hkdf(self.random_bytes);

        let mut buf = Vec::new();
        self.orig_dst_cid.encode_long(&mut buf);
        buf.write::<u64>(
            self.issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );

        let mut additional_data = [0u8; Self::MAX_ADDITIONAL_DATA_SIZE];
        let additional_data =
            Self::put_additional_data(address, retry_src_cid, &mut additional_data);
        aead_key.seal(&mut buf, additional_data).unwrap();

        let mut token = Vec::new();
        token.put_slice(self.random_bytes);
        token.put_slice(&buf);
        token
    }

    pub(crate) fn from_bytes(
        key: &dyn HandshakeTokenKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        raw_token_bytes: &'a [u8],
    ) -> Result<Self, CryptoError> {
        if raw_token_bytes.len() < Self::RANDOM_BYTES_LEN {
            // Invalid length
            return Err(CryptoError);
        }

        let random_bytes = &raw_token_bytes[..Self::RANDOM_BYTES_LEN];
        let aead_key = key.aead_from_hkdf(random_bytes);
        let mut sealed_token = raw_token_bytes[Self::RANDOM_BYTES_LEN..].to_vec();

        let mut additional_data = [0u8; Self::MAX_ADDITIONAL_DATA_SIZE];
        let additional_data =
            Self::put_additional_data(address, retry_src_cid, &mut additional_data);
        let data = aead_key.open(&mut sealed_token, additional_data)?;

        let mut reader = io::Cursor::new(data);
        let orig_dst_cid = ConnectionId::decode_long(&mut reader).ok_or(CryptoError)?;
        let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().map_err(|_| CryptoError)?, 0);

        Ok(Self {
            orig_dst_cid,
            issued,
            random_bytes,
        })
    }

    fn put_additional_data<'b>(
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        additional_data: &'b mut [u8],
    ) -> &'b [u8] {
        let mut cursor = &mut *additional_data;
        match address.ip() {
            IpAddr::V4(x) => cursor.put_slice(&x.octets()),
            IpAddr::V6(x) => cursor.put_slice(&x.octets()),
        }
        cursor.write(address.port());
        retry_src_cid.encode_long(&mut cursor);

        let size = Self::MAX_ADDITIONAL_DATA_SIZE - cursor.len();
        &additional_data[..size]
    }

    const MAX_ADDITIONAL_DATA_SIZE: usize = 39; // max(ipv4, ipv6) + port + retry_src_cid
    pub(crate) const RANDOM_BYTES_LEN: usize = 32;
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

        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes);

        let mut master_key = vec![0u8; 64];
        rng.fill_bytes(&mut master_key);

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let token = RetryToken {
            orig_dst_cid: RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid(),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
            random_bytes: &random_bytes,
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

        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes);

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();

        let mut invalid_token = Vec::new();
        invalid_token.put_slice(&random_bytes);

        let mut random_data = [0; 32];
        rand::thread_rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data with valid random bytes returns err
        assert!(RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &invalid_token).is_err());

        let invalid_token = [0; 31];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        // Assert: completely invalid retry token returns error
        assert!(RetryToken::from_bytes(&prk, &addr, &retry_src_cid, &invalid_token).is_err());
    }
}
