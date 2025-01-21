use std::ffi::{c_int, c_uchar};

use super::{CMsgHdr, MsgHdr};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<libc::cmsghdr>
pub(crate) struct Aligned<T>(pub(crate) T);

/// Helpers for [`libc::msghdr`]
impl MsgHdr for libc::msghdr {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        unsafe { libc::CMSG_FIRSTHDR(self) }
    }

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        unsafe { libc::CMSG_NXTHDR(self, cmsg) }
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
        if len == 0 {
            // netbsd is particular about this being a NULL pointer if there are no control
            // messages.
            self.msg_control = std::ptr::null_mut();
        }
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

#[cfg(apple_fast)]
impl MsgHdr for crate::imp::msghdr_x {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        unsafe { libc::CMSG_FIRSTHDR(selfp) }
    }

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        unsafe { libc::CMSG_NXTHDR(selfp, cmsg) }
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

/// Helpers for [`libc::cmsghdr`]
impl CMsgHdr for libc::cmsghdr {
    fn cmsg_len(length: usize) -> usize {
        unsafe { libc::CMSG_LEN(length as _) as usize }
    }

    fn cmsg_space(length: usize) -> usize {
        unsafe { libc::CMSG_SPACE(length as _) as usize }
    }

    fn cmsg_data(&self) -> *mut c_uchar {
        unsafe { libc::CMSG_DATA(self) }
    }

    fn set(&mut self, level: c_int, ty: c_int, len: usize) {
        self.cmsg_level = level as _;
        self.cmsg_type = ty as _;
        self.cmsg_len = len as _;
    }

    fn len(&self) -> usize {
        self.cmsg_len as _
    }
}

/// Set socket options for receiving ICMP error messages
pub(crate) fn set_socket_options(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024)?;

    // Enable receiving ICMP error messages
    socket.setsockopt(libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
    socket.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;

    Ok(())
}

/// Process ICMP error messages from control messages
pub(crate) fn process_icmp_error(cmsg: &impl CMsgHdr) -> Option<IcmpError> {
    match (cmsg.cmsg_level(), cmsg.cmsg_type()) {
        (libc::IPPROTO_IP, libc::IP_RECVERR) | (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) => {
            let icmp_err = unsafe { decode::<libc::sock_extended_err, _>(cmsg) };
            Some(IcmpError {
                code: icmp_err.ee_errno,
                origin: icmp_err.ee_origin,
                type_: icmp_err.ee_type,
                code_: icmp_err.ee_code,
            })
        }
        _ => None,
    }
}

/// Represents an ICMP error message
pub(crate) struct IcmpError {
    pub code: i32,
    pub origin: u8,
    pub type_: u8,
    pub code_: u8,
}
