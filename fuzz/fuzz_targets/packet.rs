#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate proto;
use proto::fuzzing::{PacketParams, PartialDecode};

fuzz_target!(|data: PacketParams| {
    let len = data.buf.len();
    if let Ok(decoded) = PartialDecode::new(data.buf, data.local_cid_len) {
        assert_eq!(len, decoded.0.len());
    }
});
