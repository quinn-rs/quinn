use std::{
    io,
    mem::{self, MaybeUninit},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::AsRawFd,
    ptr,
};

use mio::net::UdpSocket;
use proto::{EcnCodepoint, Transmit};

use super::cmsg;

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

impl super::UdpExt for UdpSocket {
    fn init_ext(&self) -> io::Result<()> {
        // Safety
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

    #[cfg(not(target_os = "macos"))]
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize> {
        use crate::udp::BATCH_SIZE;
        let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut cmsgs = [cmsg::Aligned(MaybeUninit::uninit()); BATCH_SIZE];
        // This assume_init looks a bit weird because one might think it
        // assumes the SockAddr data to be initialized, but that call
        // refers to the whole array, which itself is made up of MaybeUninit
        // containers. Their presence protects the SockAddr inside from
        // being assumed as initialized by the assume_init call.
        // TODO: Replace this with uninit_array once it becomes MSRV-stable
        let mut addrs: [MaybeUninit<socket2::SockAddr>; BATCH_SIZE] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for (i, transmit) in transmits.iter().enumerate().take(BATCH_SIZE) {
            let dst_addr = unsafe {
                std::ptr::write(
                    addrs[i].as_mut_ptr(),
                    socket2::SockAddr::from(transmit.destination),
                );
                &*addrs[i].as_ptr()
            };
            prepare_msg(
                transmit,
                dst_addr,
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

    #[cfg(target_os = "macos")]
    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize> {
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        let mut iov: libc::iovec = unsafe { mem::zeroed() };
        let mut ctrl = cmsg::Aligned(MaybeUninit::uninit());
        let mut sent = 0;
        while sent < transmits.len() {
            let addr = socket2::SockAddr::from(transmits[sent].destination);
            prepare_msg(&transmits[sent], &addr, &mut hdr, &mut iov, &mut ctrl);
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

    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
        let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
        let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
        hdr.msg_name = name.as_mut_ptr() as _;
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
            if hdr.msg_flags & libc::MSG_TRUNC != 0 {
                continue;
            }
            break n;
        };
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
                        && cmsg.cmsg_len as usize
                            == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
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
        Ok((n as usize, addr, EcnCodepoint::from_bits(ecn_bits)))
    }
}

const CMSG_LEN: usize = 24;

fn prepare_msg(
    transmit: &Transmit,
    dst_addr: &socket2::SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; CMSG_LEN]>>,
) {
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    // SAFETY: Casting the pointer to a mutable one is legal,
    // as sendmsg is guaranteed to not alter the mutable pointer
    // as per the POSIX spec. See the section on the sys/socket.h
    // header for details. The type is only mutable in the first
    // place because it is reused by recvmsg as well.
    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
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
