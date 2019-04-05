use std::os::unix::io::AsRawFd;
use std::{
    io, mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr,
};

use mio::net::UdpSocket;

use quinn_proto::EcnCodepoint;

use super::cmsg;

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

impl super::UdpExt for UdpSocket {
    fn init_ext(&self) -> io::Result<()> {
        // Safety
        assert_eq!(
            mem::size_of::<SocketAddrV4>(),
            mem::size_of::<libc::sockaddr_in>()
        );
        assert_eq!(
            mem::size_of::<SocketAddrV6>(),
            mem::size_of::<libc::sockaddr_in6>()
        );
        assert!(
            CMSG_LEN >= unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as usize }
        );
        assert!(
            mem::align_of::<libc::cmsghdr>() <= mem::align_of::<cmsg::Aligned<[u8; 0]>>(),
            "control message buffers will be misaligned"
        );

        let addr = self.local_addr()?;

        // macos doesn't support IP_RECVTOS on dual-stack sockets :(
        if addr.is_ipv4() || (!cfg!(target_os = "macos") && !self.only_v6()?) {
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVTOS,
                    &on as *const _ as _,
                    mem::size_of_val(&on) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        if addr.is_ipv6() {
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVTCLASS,
                    &on as *const _ as _,
                    mem::size_of_val(&on) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn send_ext(
        &self,
        remote: &SocketAddr,
        ecn: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> io::Result<usize> {
        let (name, namelen) = match *remote {
            SocketAddr::V4(ref addr) => {
                (addr as *const _ as _, mem::size_of::<libc::sockaddr_in>())
            }
            SocketAddr::V6(ref addr) => {
                (addr as *const _ as _, mem::size_of::<libc::sockaddr_in6>())
            }
        };
        let ecn = ecn.map_or(0, |x| x as libc::c_int);
        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *const _ as *mut _,
            iov_len: msg.len(),
        };
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_name = name;
        hdr.msg_namelen = namelen as _;
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = ptr::null_mut();
        hdr.msg_controllen = 0;
        hdr.msg_flags = 0;
        let mut ctrl: cmsg::Aligned<[u8; CMSG_LEN]> =
            cmsg::Aligned(unsafe { mem::uninitialized() });
        let is_ipv4 = match remote {
            SocketAddr::V4(_) => true,
            SocketAddr::V6(ref addr) => addr.ip().segments().starts_with(&[0, 0, 0, 0, 0, 0xffff]),
        };
        let mut encoder = unsafe { cmsg::Encoder::new(&mut hdr, &mut ctrl.0) };
        if is_ipv4 {
            encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
        } else {
            encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
        }
        encoder.finish();
        loop {
            let n = unsafe { libc::sendmsg(self.as_raw_fd(), &hdr, 0) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(n as usize);
        }
    }

    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
        let mut name: libc::sockaddr_storage = unsafe { mem::uninitialized() };
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut ctrl: cmsg::Aligned<[u8; CMSG_LEN]> =
            cmsg::Aligned(unsafe { mem::uninitialized() });
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_name = &mut name as *mut _ as _;
        hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = ctrl.0.as_mut_ptr() as _;
        hdr.msg_controllen = CMSG_LEN as _;
        hdr.msg_flags = 0;
        let n = loop {
            let n = unsafe { libc::recvmsg(self.as_raw_fd(), &mut hdr, 0) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            break n;
        };
        let ecn_bits = match unsafe { cmsg::Iter::new(&hdr).next() } {
            Some(cmsg) => match (cmsg.cmsg_level, cmsg.cmsg_type) {
                // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
                (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                    cmsg::decode::<u8>(cmsg)
                },
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                    cmsg::decode::<libc::c_int>(cmsg) as u8
                },
                _ => 0,
            },
            None => 0,
        };
        let addr = match name.ss_family as libc::c_int {
            libc::AF_INET => unsafe { SocketAddr::V4(ptr::read(&name as *const _ as _)) },
            libc::AF_INET6 => unsafe { SocketAddr::V6(ptr::read(&name as *const _ as _)) },
            _ => unreachable!(),
        };
        Ok((n as usize, addr, EcnCodepoint::from_bits(ecn_bits)))
    }
}

const CMSG_LEN: usize = 24;
