#![no_main]
#[cfg(fuzzing)]
use arbitrary::Arbitrary;
#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

extern crate proto;
#[cfg(fuzzing)]
use proto::{Dir, Side, StreamId};

#[cfg(fuzzing)]
#[derive(Arbitrary, Debug)]
struct StreamIdParams {
    side: Side,
    dir: Dir,
    index: u64,
}

#[cfg(fuzzing)]
fuzz_target!(|data: StreamIdParams| {
    let s = StreamId::new(data.side, data.dir, data.index);
    assert_eq!(s.initiator(), data.side);
    assert_eq!(s.dir(), data.dir);
});
