use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut};

use crate::{
    coding::{BufExt, BufMutExt},
    crypto::HmacKey,
    shared::ConnectionId,
    MAX_CID_SIZE,
};

// TODO: Use AEAD to hide token details from clients for better stability guarantees:
// - ticket consists of (random, aead-encrypted-data)
// - AEAD encryption key is HKDF(master-key, random)
// - AEAD nonce is always set to 0
// in other words, for each ticket, use different key derived from random using HKDF

pub struct RetryToken {
    pub src_cid: ConnectionId,
    pub dst_cid: ConnectionId,
    pub issued: SystemTime,
}

impl RetryToken {
    pub fn encode(&self, key: &impl HmacKey, address: &SocketAddr) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.write(self.src_cid.len() as u8);
        buf.put_slice(&self.src_cid);

        buf.write(self.dst_cid.len() as u8);
        buf.put_slice(&self.dst_cid);

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
        let signature = key.sign(&buf);
        // No reason to actually encode the IP in the token, since we always have the remote addr for an incoming packet.
        buf.truncate(signature_pos);
        buf.extend_from_slice(signature.as_ref());
        buf
    }

    pub fn from_bytes(key: &impl HmacKey, address: &SocketAddr, data: &[u8]) -> Result<Self, ()> {
        let mut reader = io::Cursor::new(data);
        let src_cid_len = reader.get::<u8>().map_err(|_| ())? as usize;
        if src_cid_len > reader.remaining() || src_cid_len > MAX_CID_SIZE {
            return Err(());
        }
        let src_cid = ConnectionId::new(&reader.bytes()[..src_cid_len]);
        reader.advance(src_cid_len);

        let dst_cid_len = reader.get::<u8>().map_err(|_| ())? as usize;
        if dst_cid_len > reader.remaining() || dst_cid_len > MAX_CID_SIZE {
            return Err(());
        }
        let dst_cid = ConnectionId::new(&reader.bytes()[..dst_cid_len]);
        reader.advance(dst_cid_len);

        let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().map_err(|_| ())?, 0);
        let signature_start = reader.position() as usize;

        let mut buf = Vec::new();
        buf.put_slice(&data[0..signature_start]);
        match address.ip() {
            IpAddr::V4(x) => buf.put_slice(&x.octets()),
            IpAddr::V6(x) => buf.put_slice(&x.octets()),
        }
        buf.write(address.port());

        key.verify(&buf, &data[signature_start..]).map_err(|_| ())?;
        Ok(Self {
            src_cid,
            dst_cid,
            issued,
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ring")]
    #[test]
    fn token_sanity() {
        use super::*;
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
        let token = RetryToken {
            src_cid: ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE),
            dst_cid: ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE),
            issued: UNIX_EPOCH + Duration::new(42, 0), // Fractional seconds would be lost
        };
        let encoded = token.encode(&key, &addr);
        let decoded = RetryToken::from_bytes(&key, &addr, &encoded).expect("token didn't validate");
        assert_eq!(token.src_cid, decoded.src_cid);
        assert_eq!(token.dst_cid, decoded.dst_cid);
        assert_eq!(token.issued, decoded.issued);
    }
}
