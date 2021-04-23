#![no_main]

extern crate proto;

use libfuzzer_sys::fuzz_target;
use proto::{
    fuzzing::{PacketParams, PartialDecode},
    DEFAULT_SUPPORTED_VERSIONS,
};

fuzz_target!(|data: PacketParams| {
    let len = data.buf.len();
    if let Ok(decoded) =
        PartialDecode::new(data.buf, data.local_cid_len, DEFAULT_SUPPORTED_VERSIONS)
    {
        match decoded.1 {
            Some(x) => assert_eq!(len, decoded.0.len() + x.len()),
            None => assert_eq!(len, decoded.0.len()),
        }
    }
});
