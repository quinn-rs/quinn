use std::os::unix::io::AsRawFd;
use std::{
    io, mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr,
};

use mio::net::UdpSocket;

use quinn_proto::EcnCodepoint;

use super::cmsg;

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
        assert_eq!(CMSG_LEN, unsafe {
            libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as usize
        });

        let addr = self.local_addr()?;

        if addr.is_ipv4() || !self.only_v6()? {
            let rc = unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVTOS,
                    &true as *const _ as _,
                    1,
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
                    mem::size_of::<libc::c_int>() as _,
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
        let mut hdr = libc::msghdr {
            msg_name: name,
            msg_namelen: namelen as _,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let mut ctrl: [u8; CMSG_LEN] = unsafe { mem::uninitialized() };
        if remote.is_ipv4() {
            cmsg::encode(&mut hdr, &mut ctrl, libc::IPPROTO_IP, libc::IP_TOS, ecn);
        } else {
            cmsg::encode(
                &mut hdr,
                &mut ctrl,
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                ecn,
            );
        }
        let n = unsafe { libc::sendmsg(self.as_raw_fd(), &hdr, 0) };
        if n == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
        let mut name: libc::sockaddr_storage = unsafe { mem::uninitialized() };
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut ctrl: [u8; CMSG_LEN] = unsafe { mem::uninitialized() };
        let mut hdr = libc::msghdr {
            msg_name: &mut name as *mut _ as _,
            msg_namelen: mem::size_of::<libc::sockaddr_storage>() as _,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ctrl.as_mut_ptr() as _,
            msg_controllen: CMSG_LEN as _,
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(self.as_raw_fd(), &mut hdr, 0) };
        if n == -1 {
            return Err(io::Error::last_os_error());
        }
        let ecn_bits = if let Some(cmsg) = unsafe { cmsg::Iter::new(&hdr).next() } {
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_TOS) => unsafe { cmsg::decode::<u8>(cmsg) },
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                    cmsg::decode::<libc::c_int>(cmsg) as u8
                },
                _ => 0,
            }
        } else {
            0
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
