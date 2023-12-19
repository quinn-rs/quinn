#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

pub(crate) use imp::{decode, Aligned, Encoder, Iter};
