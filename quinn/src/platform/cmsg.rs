use std::{mem, ptr};

macro_rules! cmsgs {
    {$($level:ident { $($name:ident : $ty:ty;)* })*} => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, Copy, Clone)]
        pub enum Cmsg {
            $($($name($ty),)*)*
        }

        impl Cmsg {
            pub fn space(&self) -> usize {
                let x = match *self {
                    $($(Cmsg::$name(_) => unsafe { libc::CMSG_SPACE(mem::size_of::<$ty>() as _)},)*)*
                };
                x as usize
            }

            unsafe fn encode(&self, cmsg: &mut libc::cmsghdr) {
                match *self {
                    $($(Cmsg::$name(x) => {
                        cmsg.cmsg_level = libc::$level as _;
                        cmsg.cmsg_type = libc::$name as _;
                        cmsg.cmsg_len = libc::CMSG_LEN(mem::size_of::<$ty>() as _) as _;
                        ptr::write::<$ty>(libc::CMSG_DATA(cmsg) as *mut $ty, x);
                    })*)*
                }
            }

            unsafe fn decode(cmsg: &libc::cmsghdr) -> Option<Self> {
                Some(match cmsg.cmsg_level {
                    $(libc::$level => match cmsg.cmsg_type {
                        $(libc::$name => Cmsg::$name(ptr::read::<$ty>(libc::CMSG_DATA(cmsg) as *const $ty)),)*
                        _ => { return None; }
                    },)*
                    _ => { return None; }
                })
            }
        }
    }
}

cmsgs! {
    IPPROTO_IP {
        IP_TOS: u8;
    }
    IPPROTO_IPV6 {
        IPV6_TCLASS: libc::c_int;
    }
}

pub fn encode(hdr: &mut libc::msghdr, buf: &mut [u8], msgs: &[Cmsg]) {
    assert!(buf.len() >= msgs.iter().map(|msg| msg.space()).sum());
    hdr.msg_control = buf.as_mut_ptr() as _;
    hdr.msg_controllen = buf.len() as _;

    let mut len = 0;
    let mut cursor = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    for msg in msgs {
        unsafe {
            msg.encode(&mut *cursor);
        }
        len += msg.space();
        cursor = unsafe { libc::CMSG_NXTHDR(hdr, cursor) };
    }
    debug_assert!(len as usize <= buf.len());
    hdr.msg_controllen = len;
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
    type Item = Cmsg;
    fn next(&mut self) -> Option<Cmsg> {
        loop {
            if self.cmsg.is_null() {
                return None;
            }
            let current = self.cmsg;
            self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, self.cmsg) };
            if let Some(x) = unsafe { Cmsg::decode(&*current) } {
                return Some(x);
            }
        }
    }
}
