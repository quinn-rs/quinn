use std::{
    io,
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::AsRawFd,
    ptr,
};

use mio::net::UdpSocket;
use proto::{EcnCodepoint, Transmit};

use super::cmsg;
use crate::udp::RecvMeta;

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

        // macos and ios do not support IP_RECVTOS on dual-stack sockets :(
        if addr.is_ipv4()
            || ((!cfg!(any(target_os = "macos", target_os = "ios"))) && !self.only_v6()?)
        {
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
        #[cfg(target_os = "linux")]
        {
            if addr.is_ipv4() {
                let rc = unsafe {
                    libc::setsockopt(
                        self.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_MTU_DISCOVER,
                        &libc::IP_PMTUDISC_PROBE as *const _ as _,
                        mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
                    )
                };
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
            } else if addr.is_ipv6() {
                let rc = unsafe {
                    libc::setsockopt(
                        self.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_MTU_DISCOVER,
                        &libc::IP_PMTUDISC_PROBE as *const _ as _,
                        mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
                    )
                };
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
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

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize> {
        use crate::udp::BATCH_SIZE;
        let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut cmsgs = [cmsg::Aligned(MaybeUninit::uninit()); BATCH_SIZE];
        for (i, transmit) in transmits.iter().enumerate().take(BATCH_SIZE) {
            prepare_msg(
                transmit,
                &mut msgs[i].msg_hdr,
                &mut iovecs[i],
                &mut cmsgs[i],
            );
        }
        loop {
            let n = unsafe {
                libc::sendmmsg(
                    self.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    transmits.len().min(crate::udp::BATCH_SIZE) as _,
                    0,
                )
            };
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

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize> {
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        let mut iov: libc::iovec = unsafe { mem::zeroed() };
        let mut ctrl = cmsg::Aligned(MaybeUninit::uninit());
        let mut sent = 0;
        while sent < transmits.len() {
            prepare_msg(&transmits[sent], &mut hdr, &mut iov, &mut ctrl);
            let n = unsafe { libc::sendmsg(self.as_raw_fd(), &hdr, 0) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if sent != 0 {
                    // We need to report that some packets were sent in this case, so we rely on
                    // errors being either harmlessly transient (in the case of WouldBlock) or
                    // recurring on the next call.
                    return Ok(sent);
                }
                return Err(e);
            } else {
                sent += 1;
            }
        }
        Ok(sent)
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        use crate::udp::BATCH_SIZE;
        let mut names = [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE];
        let mut ctrls = [cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit()); BATCH_SIZE];
        let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; BATCH_SIZE]>() };
        let max_msg_count = bufs.len().min(BATCH_SIZE);
        for i in 0..max_msg_count {
            prepare_recv(
                &mut bufs[i],
                &mut names[i],
                &mut ctrls[i],
                &mut hdrs[i].msg_hdr,
            );
        }
        let msg_count = loop {
            let n = unsafe {
                libc::recvmmsg(
                    self.as_raw_fd(),
                    hdrs.as_mut_ptr(),
                    bufs.len().min(BATCH_SIZE) as libc::c_uint,
                    0,
                    ptr::null_mut(),
                )
            };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            break n;
        };
        for i in 0..(msg_count as usize) {
            meta[i] = decode_recv(&names[i], &hdrs[i].msg_hdr, hdrs[i].msg_len as usize);
        }
        Ok(msg_count as usize)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
        let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
        let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
        prepare_recv(&mut bufs[0], &mut name, &mut ctrl, &mut hdr);
        let n = loop {
            let n = unsafe { libc::recvmsg(self.as_raw_fd(), &mut hdr, 0) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if hdr.msg_flags & libc::MSG_TRUNC != 0 {
                continue;
            }
            break n;
        };
        meta[0] = decode_recv(&name, &hdr, n as usize);
        Ok(1)
    }
}

const CMSG_LEN: usize = 24;

fn prepare_msg(
    transmit: &Transmit,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; CMSG_LEN]>>,
) {
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    let (name, namelen) = match transmit.destination {
        SocketAddr::V4(ref addr) => (addr as *const _ as _, mem::size_of::<libc::sockaddr_in>()),
        SocketAddr::V6(ref addr) => (addr as *const _ as _, mem::size_of::<libc::sockaddr_in6>()),
    };
    hdr.msg_name = name;
    hdr.msg_namelen = namelen as _;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
    if transmit.destination.is_ipv4() {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }
    encoder.finish();
}

fn prepare_recv(
    buf: &mut IoSliceMut,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; CMSG_LEN]>>,
    hdr: &mut libc::msghdr,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    hdr.msg_flags = 0;
}

fn decode_recv(
    name: &MaybeUninit<libc::sockaddr_storage>,
    hdr: &libc::msghdr,
    len: usize,
) -> RecvMeta {
    let name = unsafe { name.assume_init() };
    let ecn_bits = match unsafe { cmsg::Iter::new(&hdr).next() } {
        Some(cmsg) => match (cmsg.cmsg_level, cmsg.cmsg_type) {
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
            (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                cmsg::decode::<u8>(cmsg)
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                if cfg!(target_os = "macos")
                    && cmsg.cmsg_len as usize == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
                {
                    cmsg::decode::<u8>(cmsg)
                } else {
                    cmsg::decode::<libc::c_int>(cmsg) as u8
                }
            },
            _ => 0,
        },
        None => 0,
    };
    let addr = match libc::c_int::from(name.ss_family) {
        libc::AF_INET => unsafe { SocketAddr::V4(ptr::read(&name as *const _ as _)) },
        libc::AF_INET6 => unsafe { SocketAddr::V6(ptr::read(&name as *const _ as _)) },
        _ => unreachable!(),
    };
    RecvMeta {
        len,
        addr,
        ecn: EcnCodepoint::from_bits(ecn_bits),
    }
}
