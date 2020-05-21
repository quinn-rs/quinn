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

pub fn generate<K>(
    key: &K,
    address: &SocketAddr,
    src_cid: &ConnectionId,
    dst_cid: &ConnectionId,
    issued: SystemTime,
) -> Vec<u8>
where
    K: HmacKey,
{
    let mut buf = Vec::new();

    buf.write(src_cid.len() as u8);
    buf.put_slice(src_cid);

    buf.write(dst_cid.len() as u8);
    buf.put_slice(dst_cid);

    buf.write::<u64>(
        issued
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

pub fn check<K>(
    key: &K,
    address: &SocketAddr,
    data: &[u8],
) -> Option<(ConnectionId, ConnectionId, SystemTime)>
where
    K: HmacKey,
{
    let mut reader = io::Cursor::new(data);
    let src_cid_len = reader.get::<u8>().ok()? as usize;
    if src_cid_len > reader.remaining() || src_cid_len > MAX_CID_SIZE {
        return None;
    }
    let src_cid = ConnectionId::new(&reader.bytes()[..src_cid_len]);
    reader.advance(src_cid_len);

    let dst_cid_len = reader.get::<u8>().ok()? as usize;
    if dst_cid_len > reader.remaining() || dst_cid_len > MAX_CID_SIZE {
        return None;
    }
    let dst_cid = ConnectionId::new(&reader.bytes()[..dst_cid_len]);
    reader.advance(dst_cid_len);

    let issued = UNIX_EPOCH + Duration::new(reader.get::<u64>().ok()?, 0);
    let signature_start = reader.position() as usize;

    let mut buf = Vec::new();
    buf.put_slice(&data[0..signature_start]);
    match address.ip() {
        IpAddr::V4(x) => buf.put_slice(&x.octets()),
        IpAddr::V6(x) => buf.put_slice(&x.octets()),
    }
    buf.write(address.port());

    key.verify(&buf, &data[signature_start..]).ok()?;
    Some((src_cid, dst_cid, issued))
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ring")]
    #[test]
    fn token_sanity() {
        use super::*;
        use crate::crypto::HmacKey;
        use ring::hmac;
        use std::{
            net::Ipv6Addr,
            time::{Duration, UNIX_EPOCH},
        };

        let mut key = [0; 64];
        rand::thread_rng().fill_bytes(&mut key);
        let key = <hmac::Key as HmacKey>::new(&key).unwrap();
        let addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let src_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let dst_cid = ConnectionId::random(&mut rand::thread_rng(), MAX_CID_SIZE);
        let issued = UNIX_EPOCH + Duration::new(42, 0); // Fractional seconds would be lost
        let token = token::generate(&key, &addr, &src_cid, &dst_cid, issued);
        let (src_cid2, dst_cid2, issued2) =
            token::check(&key, &addr, &token).expect("token didn't validate");
        assert_eq!(src_cid, src_cid2);
        assert_eq!(dst_cid, dst_cid2);
        assert_eq!(issued, issued2);
    }
}
