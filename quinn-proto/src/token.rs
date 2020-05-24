use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::BufMut;

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::HmacKey,
    shared::ConnectionId,
    RESET_TOKEN_SIZE,
};

// TODO: Use AEAD to hide token details from clients for better stability guarantees:
// - ticket consists of (random, aead-encrypted-data)
// - AEAD encryption key is HKDF(master-key, random)
// - AEAD nonce is always set to 0
// in other words, for each ticket, use different key derived from random using HKDF

pub struct RetryToken {
    /// The destination connection ID set in the very first packet from the client
    pub orig_dst_cid: ConnectionId,
    /// The time at which this token was issued
    pub issued: SystemTime,
}

impl RetryToken {
    pub fn encode(
        &self,
        key: &impl HmacKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        self.orig_dst_cid.encode_long(&mut buf);
        buf.write::<u64>(
            self.issued
                .duration_since(UNIX_EPOCH)
                .map(|x| x.as_secs())
                .unwrap_or(0),
        );

        let signature_pos = buf.len();
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());
        retry_src_cid.encode_long(&mut buf);

        let signature = key.sign(&buf);
        // No reason to actually encode the IP in the token, since we always have the remote addr for an incoming packet.
        buf.truncate(signature_pos);
        buf.extend_from_slice(signature.as_ref());
        buf
    }

    pub fn from_bytes(
        key: &impl HmacKey,
        address: &SocketAddr,
        retry_src_cid: &ConnectionId,
        data: &[u8],
    ) -> Result<Self, ()> {
        let mut reader = io::Cursor::new(data);

        let orig_dst_cid = ConnectionId::decode_long(&mut reader).ok_or(())?;
        let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().map_err(|_| ())?, 0);

        let signature_start = reader.position() as usize;
        let mut buf = Vec::new();
        buf.put_slice(&data[0..signature_start]);
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());
        retry_src_cid.encode_long(&mut buf);

        key.verify(&buf, &data[signature_start..]).map_err(|_| ())?;
        Ok(Self {
            orig_dst_cid,
            issued,
        })
    }
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derive_hash_xor_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &impl HmacKey, id: &ConnectionId) -> Self {
        let signature = key.sign(id);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature.as_ref()[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &ResetToken) -> bool {
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
            write!(f, "{:02x}", byte)?;
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
        use crate::MAX_CID_SIZE;
        use rand::RngCore;
        use ring::hmac;
        use std::{
            net::Ipv6Addr,
            time::{Duration, UNIX_EPOCH},
        };

        let mut key = [0; 64];
        rand::thread_rng().fill_bytes(&mut key);
        let key = <hmac::Key as HmacKey>::new(&key).unwrap();
        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let retry_src_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let token = RetryToken {
            orig_dst_cid: ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&key, &addr, &retry_src_cid);
        let decoded = RetryToken::from_bytes(&key, &addr, &retry_src_cid, &encoded)
            .expect("token didn't validate");
        assert_eq!(token.orig_dst_cid, decoded.orig_dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }
}
