use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::pkey::PKey;

use bytes::{BufMut, BigEndian};

pub fn extract(algo: MessageDigest, salt: &[u8], ikm: &[u8]) -> Box<[u8]> {
    let key = PKey::hmac(salt).unwrap();
    let mut signer = Signer::new(algo, &key).unwrap();
    signer.update(ikm).unwrap();
    signer.sign_to_vec().unwrap().into()
}

fn expand(algo: MessageDigest, prk: &[u8], info: &[u8], length: usize) -> Box<[u8]> {
    let size = algo.size();
    let prk = PKey::hmac(prk).unwrap();
    let mut t = Vec::new();
    let mut okm = Vec::new();
    okm.reserve_exact(length);
    if length > 255 * size { panic!("length too large"); }
    for i in 1.. {
        let mut signer = Signer::new(algo, &prk).unwrap();
        signer.update(&t).unwrap();
        t.resize(size, 0);
        signer.update(info).unwrap();
        signer.update(&[i as u8]).unwrap();
        let n = signer.sign(&mut t).unwrap();
        debug_assert_eq!(n, size);
        let remaining = length - okm.len();
        if remaining > size {
            okm.extend_from_slice(&t);
        } else {
            okm.extend_from_slice(&t[0..remaining]);
            return okm.into();
        }
    }
    unreachable!()
}

pub fn qexpand(algo: MessageDigest, prk: &[u8], label: &[u8], length: u16) -> Box<[u8]> {
    const PREFIX: &[u8] = b"QUIC ";
    assert!(label.len() < u8::max_value() as usize - PREFIX.len());
    let mut info = Vec::new();
    info.put_u16::<BigEndian>(length);
    info.put_u8(PREFIX.len() as u8 + label.len() as u8);
    info.put_slice(PREFIX);
    info.put_slice(label);
    info.put_u8(0);             // Null terminator for label
    expand(algo, prk, &info, length as usize)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn case1() {
        let algo = MessageDigest::sha256();
        const IKM: [u8; 22] = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const SALT: [u8; 13] = hex!("000102030405060708090a0b0c");
        const INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");
        const L: usize = 42;
        let prk = extract(algo, &SALT, &IKM);
        assert_eq!(&prk[..], &hex!("077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5")[..]);
        let okm = expand(algo, &prk, &INFO, L);
        assert_eq!(okm.len(), L);
        assert_eq!(&okm[..], &hex!("3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf 34007208d5b887185865")[..]);
    }
}
