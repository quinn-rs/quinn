use std::{mem, ptr};

pub struct Encoder<'a> {
    hdr: &'a mut libc::msghdr,
    cmsg: Option<&'a mut libc::cmsghdr>,
    len: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(hdr: &'a mut libc::msghdr, buf: &'a mut [u8]) -> Self {
        hdr.msg_control = buf.as_mut_ptr() as _;
        hdr.msg_controllen = buf.len() as _;
        Self {
            cmsg: unsafe { libc::CMSG_FIRSTHDR(hdr).as_mut() },
            hdr,
            len: 0,
        }
    }

    pub fn push<T: Copy + ?Sized>(&mut self, level: libc::c_int, ty: libc::c_int, value: T) {
        assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
        let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(&value) as _) as usize };
        assert!(
            self.hdr.msg_controllen >= self.len + space,
            "control message buffer too small"
        );
        let cmsg = self.cmsg.take().expect("no control buffer space remaining");
        cmsg.cmsg_level = level;
        cmsg.cmsg_type = ty;
        cmsg.cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of_val(&value) as _) } as _;
        unsafe {
            ptr::write(libc::CMSG_DATA(cmsg) as *const T as *mut T, value);
        }
        self.len += space;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, cmsg).as_mut() };
    }

    pub fn finish(self) {
        self.hdr.msg_controllen = self.len;
    }
}

pub unsafe fn decode<T: Copy>(cmsg: &libc::cmsghdr) -> T {
    assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
    debug_assert_eq!(cmsg.cmsg_len, libc::CMSG_LEN(mem::size_of::<T>() as _) as _);
    ptr::read(libc::CMSG_DATA(cmsg) as *const T)
}

pub struct Iter<'a> {
    hdr: &'a libc::msghdr,
    cmsg: *const libc::cmsghdr,
}

impl<'a> Iter<'a> {
    /// # Safety
    ///
    /// `hdr.msg_control` must point to mutable memory containing at least `hdr.msg_controllen`
    /// bytes, which lives at least as long as `'a`.
    pub unsafe fn new(hdr: &'a libc::msghdr) -> Self {
        Self {
            hdr,
            cmsg: libc::CMSG_FIRSTHDR(hdr),
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a libc::cmsghdr;
    fn next(&mut self) -> Option<&'a libc::cmsghdr> {
        if self.cmsg.is_null() {
            return None;
        }
        let current = self.cmsg;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, self.cmsg) };
        Some(unsafe { &*current })
    }
}
