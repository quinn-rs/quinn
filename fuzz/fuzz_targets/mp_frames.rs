#![no_main]

extern crate proto;

use libfuzzer_sys::fuzz_target;
use proto::fuzzing::{Bytes, exercise_multipath_frame_payload};

fuzz_target!(|data: &[u8]| {
    let _ = exercise_multipath_frame_payload(Bytes::copy_from_slice(data));
});
