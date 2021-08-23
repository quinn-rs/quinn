use std::{
    io,
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
    ptr,
};

use proto::{EcnCodepoint, Transmit};
use crate::{cmsg, RecvMeta, SocketType};

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

pub fn init(io: &UdpSocket) -> io::Result<SocketType> {
    let mut cmsg_platform_space = 0;
    if cfg!(target_os = "linux") {
        cmsg_platform_space +=
            unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as _) as usize };
    }

    assert!(
        CMSG_LEN
            >= unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as usize }
                + cmsg_platform_space
    );
    assert!(
        mem::align_of::<libc::cmsghdr>() <= mem::align_of::<cmsg::Aligned<[u8; 0]>>(),
        "control message buffers will be misaligned"
    );

    let addr = io.local_addr()?;
    let only_v6 = if addr.is_ipv6() {
        let socket = socket2::SockRef::from(io);
        socket.only_v6()?
    } else {
        false
    };

    if addr.is_ipv4() || !only_v6 {
        // macos and ios do not support IP_RECVTOS on dual-stack sockets :(
        if !cfg!(any(target_os = "macos", target_os = "ios")) {
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    io.as_raw_fd(),
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

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let rc = unsafe {
                libc::setsockopt(
                    io.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    &libc::IP_PMTUDISC_PROBE as *const _ as _,
                    mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }

            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    io.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &on as *const _ as _,
                    mem::size_of_val(&on) as _,
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
                io.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &on as *const _ as _,
                mem::size_of_val(&on) as _,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let rc = unsafe {
                libc::setsockopt(
                    io.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    &libc::IP_PMTUDISC_PROBE as *const _ as _,
                    mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }

            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    io.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    &on as *const _ as _,
                    mem::size_of_val(&on) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(if addr.is_ipv4() {
        SocketType::Ipv4
    } else if only_v6 {
        SocketType::Ipv6Only
    } else {
        SocketType::Ipv6
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn send(io: &UdpSocket, transmits: &[Transmit]) -> io::Result<usize> {
    let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { mem::zeroed() };
    let mut cmsgs = [cmsg::Aligned([0u8; CMSG_LEN]); BATCH_SIZE];
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
                io.as_raw_fd(),
                msgs.as_mut_ptr(),
                transmits.len().min(BATCH_SIZE) as _,
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
pub fn send(io: &UdpSocket, transmits: &[Transmit]) -> io::Result<usize> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    let mut iov: libc::iovec = unsafe { mem::zeroed() };
    let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);
    let mut sent = 0;
    while sent < transmits.len() {
        let addr = socket2::SockAddr::from(transmits[sent].destination);
        prepare_msg(&transmits[sent], &addr, &mut hdr, &mut iov, &mut ctrl);
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) };
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
pub fn recv(
    io: &UdpSocket,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
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
                io.as_raw_fd(),
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
pub fn recv(
    io: &UdpSocket,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
    prepare_recv(&mut bufs[0], &mut name, &mut ctrl, &mut hdr);
    let n = loop {
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, 0) };
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

const CMSG_LEN: usize = 88;

fn prepare_msg(
    transmit: &Transmit,
    dst_addr: &socket2::SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; CMSG_LEN]>,
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

    #[cfg(target_os = "linux")]
    if let Some(segment_size) = transmit.segment_size {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size as u16);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(ip) = &transmit.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo);
            }
            IpAddr::V6(v6) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
            }
        }
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
    let mut ecn_bits = 0;
    let mut dst_ip = None;

    let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
    for cmsg in cmsg_iter {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
            (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                ecn_bits = cmsg::decode::<u8>(cmsg);
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                if cfg!(target_os = "macos")
                    && cmsg.cmsg_len as usize == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
                {
                    ecn_bits = cmsg::decode::<u8>(cmsg);
                } else {
                    ecn_bits = cmsg::decode::<libc::c_int>(cmsg) as u8;
                }
            },
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => unsafe {
                let pktinfo = cmsg::decode::<libc::in_pktinfo>(cmsg);
                dst_ip = Some(IpAddr::V4(ptr::read(&pktinfo.ipi_addr as *const _ as _)));
            },
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => unsafe {
                let pktinfo = cmsg::decode::<libc::in6_pktinfo>(cmsg);
                dst_ip = Some(IpAddr::V6(ptr::read(&pktinfo.ipi6_addr as *const _ as _)));
            },
            _ => {}
        }
    }

    let addr = match libc::c_int::from(name.ss_family) {
        libc::AF_INET => unsafe { SocketAddr::V4(ptr::read(&name as *const _ as _)) },
        libc::AF_INET6 => unsafe { SocketAddr::V6(ptr::read(&name as *const _ as _)) },
        _ => unreachable!(),
    };

    RecvMeta {
        addr,
        len,
        ecn: EcnCodepoint::from_bits(ecn_bits),
        dst_ip,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
// Chosen somewhat arbitrarily; might benefit from additional tuning.
pub const BATCH_SIZE: usize = 32;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const BATCH_SIZE: usize = 1;

#[cfg(target_os = "linux")]
pub fn max_gso_segments() -> io::Result<usize> {
    // Checks whether GSO support is availably by setting the UDP_SEGMENT
    // option on a socket.
    const GSO_SIZE: libc::c_int = 1500;
    let socket = UdpSocket::bind("[::]:0")?;
    let res = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            &GSO_SIZE as *const _ as _,
            mem::size_of_val(&GSO_SIZE) as _,
        )
    };
    Ok(if res != -1 {
        // As defined in linux/udp.h
        // #define UDP_MAX_SEGMENTS ........(1 << 6UL)
        64
    } else {
        1
    })
}

#[cfg(not(target_os = "linux"))]
pub fn max_gso_segments() -> io::Result<usize> {
    Ok(1)
}
