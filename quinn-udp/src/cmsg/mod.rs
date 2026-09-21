use std::{
    ffi::{c_int, c_uchar},
    ptr::{self, NonNull},
};

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

pub(crate) use imp::Aligned;

/// Helper to encode a series of control messages (native "cmsgs") to a buffer for use in `sendmsg`
//  like API.
///
/// The operation must be "finished" for the native msghdr to be usable, either by calling `finish`
/// explicitly or by dropping the `Encoder`.
pub(crate) struct Encoder<'a, M: MsgHdr> {
    hdr: &'a mut M,
    cmsg: Option<NonNull<M::ControlMessage>>,
    len: usize,
}

impl<'a, M: MsgHdr> Encoder<'a, M> {
    /// # Safety
    /// - `hdr` must contain a suitably aligned pointer to a big enough buffer to hold control messages
    ///   bytes. All bytes of this buffer can be safely written.
    /// - The `Encoder` must be dropped before `hdr` is passed to a system call, and must not be leaked.
    pub(crate) unsafe fn new(hdr: &'a mut M) -> Self {
        Self {
            // `hdr` is a reference to the message header, not to a control message header, and
            // `cmsg_first_hdr` yields the control buffer pointer it stores, so the resulting
            // pointer has provenance over the whole control buffer.
            cmsg: NonNull::new(hdr.cmsg_first_hdr()),
            hdr,
            len: 0,
        }
    }

    /// Append a control message to the buffer.
    ///
    /// # Panics
    /// - If insufficient buffer space remains.
    pub(crate) fn push<T: Copy>(&mut self, level: c_int, ty: c_int, value: T) {
        let space = M::ControlMessage::cmsg_space(size_of_val(&value));
        assert!(
            self.hdr.control_len() >= self.len + space,
            "control message buffer too small. Required: {}, Available: {}",
            self.len + space,
            self.hdr.control_len()
        );
        let cmsg = self
            .cmsg
            .take()
            .expect("no control buffer space remaining")
            .as_ptr();
        // SAFETY: `cmsg` points into the control buffer, which the caller of `new` guaranteed to be
        // writable, and the assertion above ensures that both the header and the payload fit.
        unsafe {
            (*cmsg).set(level, ty, M::ControlMessage::cmsg_len(size_of_val(&value)));
            // The payload is only guaranteed to be aligned for `M::ControlMessage`, so write it
            // without relying on the alignment of `T`, mirroring `CMsg::decode`.
            ptr::write_unaligned(M::ControlMessage::cmsg_data(cmsg).cast::<T>(), value);
            self.cmsg = NonNull::new(self.hdr.cmsg_nxt_hdr(cmsg));
        }
        self.len += space;
    }

    /// Finishes appending control messages to the buffer
    pub(crate) fn finish(self) {
        // Delegates to the `Drop` impl
    }
}

// Statically guarantees that the encoding operation is "finished" before the control buffer is read
// by `sendmsg` like API.
impl<M: MsgHdr> Drop for Encoder<'_, M> {
    fn drop(&mut self) {
        self.hdr.set_control_len(self.len as _);
    }
}

/// # Safety
///
/// `cmsg` must refer to a native cmsg containing a payload of type `T`
pub(crate) unsafe fn decode<T: Copy, C: CMsgHdr>(cmsg: &C) -> T {
    debug_assert_eq!(cmsg.len(), C::cmsg_len(size_of::<T>()));
    // The payload is only aligned for `C`, which on musl is less strict than payloads such as
    // `libc::timespec`, so it cannot be read through an aligned `ptr::read`.
    // SAFETY: caller guarantees that `cmsg_data()` points to a readable, initialized value of type `T`
    unsafe { ptr::read_unaligned(C::cmsg_data(cmsg).cast::<T>()) }
}

pub(crate) struct Iter<'a, M: MsgHdr> {
    hdr: &'a M,
    cmsg: Option<&'a M::ControlMessage>,
}

impl<'a, M: MsgHdr> Iter<'a, M> {
    /// # Safety
    ///
    /// `hdr` must hold a pointer to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of native cmsgs, i.e. is aligned
    //  for native `cmsghdr`, is fully initialized, and has correct internal links.
    pub(crate) unsafe fn new(hdr: &'a M) -> Self {
        Self {
            hdr,
            // SAFETY: pointer is convertible to a reference (aligned, non-null, a valid value)
            cmsg: unsafe { hdr.cmsg_first_hdr().as_ref() },
        }
    }
}

impl<'a, M: MsgHdr> Iterator for Iter<'a, M> {
    type Item = &'a M::ControlMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cmsg.take()?;
        self.cmsg = unsafe { self.hdr.cmsg_nxt_hdr(current).as_ref() };

        #[cfg(apple_fast)]
        {
            // On MacOS < 14 CMSG_NXTHDR might continuously return a zeroed cmsg. In
            // such case, return `None` instead, thus indicating the end of
            // the cmsghdr chain.
            if current.len() < size_of::<M::ControlMessage>() {
                return None;
            }
        }

        Some(current)
    }
}

// Helper traits for native types for control messages
pub(crate) trait MsgHdr {
    type ControlMessage: CMsgHdr;

    /// Returns a pointer to the first control message header, or null if there is no room for one
    ///
    /// The returned pointer is a copy of the control buffer pointer stored in this message
    /// header, so it has provenance over the whole control buffer rather than being derived from
    /// `&self`.
    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage;

    /// Returns a pointer to the control message following `cmsg`, or null if there is none
    ///
    /// # Safety
    ///
    /// `cmsg` must point to an initialized control message header inside this message's
    /// control buffer.
    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage;

    /// Sets the number of control messages added to this `struct msghdr`.
    ///
    /// Note that this is a destructive operation and should only be done as a finalisation
    /// step.
    fn set_control_len(&mut self, len: usize);

    fn control_len(&self) -> usize;
}

pub(crate) trait CMsgHdr {
    fn cmsg_len(length: usize) -> usize;

    fn cmsg_space(length: usize) -> usize;

    /// Returns a pointer to the payload following the header `this` points to
    ///
    /// # Safety
    ///
    /// `this` must point to a control message header inside a control buffer. The returned
    /// pointer inherits the provenance of `this`, so `this` must be derived from a pointer to
    /// the whole control buffer, not from a reference to the header.
    unsafe fn cmsg_data(this: *const Self) -> *mut c_uchar;

    fn set(&mut self, level: c_int, ty: c_int, len: usize);

    fn len(&self) -> usize;
}

#[cfg(unix)]
pub(crate) const LEN: usize = 96;

#[cfg(all(test, unix))]
mod tests {
    use std::mem;

    use super::*;

    /// Encode a few control messages and decode them again through the same buffer
    ///
    /// This exercises the pointer handling in `Encoder`, `Iter` and `decode` without needing a
    /// socket, so it can be run under Miri to check for aliasing violations.
    #[test]
    fn roundtrip() {
        let mut buf = Aligned([0u8; LEN]);
        let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
        hdr.msg_control = buf.0.as_mut_ptr() as _;
        hdr.msg_controllen = LEN as _;

        let mut encoder = unsafe { Encoder::new(&mut hdr) };
        encoder.push(1, 2, 0x1234_5678u32);
        encoder.push(3, 4, [0xabu8; 5]);
        encoder.push(5, 6, 0x0102u16);
        encoder.finish();
        assert!(hdr.msg_controllen > 0);

        let mut iter = unsafe { Iter::new(&hdr) };
        let cmsg = iter.next().unwrap();
        assert_eq!((cmsg.cmsg_level, cmsg.cmsg_type), (1, 2));
        assert_eq!(unsafe { decode::<u32, libc::cmsghdr>(cmsg) }, 0x1234_5678);

        let cmsg = iter.next().unwrap();
        assert_eq!((cmsg.cmsg_level, cmsg.cmsg_type), (3, 4));
        assert_eq!(unsafe { decode::<[u8; 5], libc::cmsghdr>(cmsg) }, [0xab; 5]);

        let cmsg = iter.next().unwrap();
        assert_eq!((cmsg.cmsg_level, cmsg.cmsg_type), (5, 6));
        assert_eq!(unsafe { decode::<u16, libc::cmsghdr>(cmsg) }, 0x0102);

        assert!(iter.next().is_none());
    }
}
