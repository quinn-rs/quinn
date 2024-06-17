#![no_main]

extern crate proto;

use libfuzzer_sys::fuzz_target;
use proto::{
    fuzzing::{PacketParams, PartialDecode},
    ConnectionIdParser, RandomConnectionIdGenerator, ZeroLengthConnectionIdParser,
    DEFAULT_SUPPORTED_VERSIONS,
};

fuzz_target!(|data: PacketParams| {
    let len = data.buf.len();
    let supported_versions = DEFAULT_SUPPORTED_VERSIONS.to_vec();
    let cid_gen;
    if let Ok(decoded) = PartialDecode::new(
        data.buf,
        match data.local_cid_len {
            0 => &ZeroLengthConnectionIdParser as &dyn ConnectionIdParser,
            _ => {
                cid_gen = RandomConnectionIdGenerator::new(data.local_cid_len);
                &cid_gen as &dyn ConnectionIdParser
            }
        },
        &supported_versions,
        data.grease_quic_bit,
    ) {
        match decoded.1 {
            Some(x) => assert_eq!(len, decoded.0.len() + x.len()),
            None => assert_eq!(len, decoded.0.len()),
        }
    }
});
