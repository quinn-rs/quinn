use std::ffi::{c_int, c_uchar};

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

pub(crate) use imp::{decode, Aligned, Encoder, Iter};

// Helper traits for native types for control messages
pub(crate) trait MsgHdr {
    type ControlMessage: CMsgHdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage;

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage;

    fn set_control_len(&mut self, len: usize);

    fn control_len(&self) -> usize;
}

pub(crate) trait CMsgHdr {
    fn cmsg_len(length: usize) -> usize;

    fn cmsg_space(length: usize) -> usize;

    fn cmsg_data(&self) -> *mut c_uchar;

    fn set(&mut self, level: c_int, ty: c_int, len: usize);

    fn len(&self) -> usize;
}
