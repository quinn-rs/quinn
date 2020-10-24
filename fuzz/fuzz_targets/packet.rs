#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate proto;
use proto::fuzzing::{PacketParams, PartialDecode};

fuzz_target!(|data: PacketParams| {
    let decode = PartialDecode::new(data.buf, data.cid).unwrap();
});
