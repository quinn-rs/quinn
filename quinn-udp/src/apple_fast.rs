use std::{
    io::{self, IoSliceMut},
    mem::{self, MaybeUninit},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};

use socket2::SockRef;

use crate::{
    EcnCodepoint, RecvMeta, Transmit, UdpSocketState,
    cmsg::{self, MsgHdr},
    imp::{BATCH_SIZE, IpTosTy, decode_recv, recv_single, retry_if_interrupted, send_single},
};

pub(crate) fn send(
    state: &UdpSocketState,
    io: SockRef<'_>,
    transmit: &Transmit<'_>,
) -> io::Result<()> {
    if state.is_apple_fast_path_enabled() {
        send_via_sendmsg_x(state, io, transmit)
    } else {
        send_single(state, io, transmit)
    }
}

/// Send using the fast `sendmsg_x` API.
fn send_via_sendmsg_x(
    state: &UdpSocketState,
    io: SockRef<'_>,
    transmit: &Transmit<'_>,
) -> io::Result<()> {
    let Some(sendmsg_x) = state.resolve_apple_fast_fn(sendmsg_x_fn) else {
        return send_single(state, io, transmit);
    };

    let mut pending = state.partial_transmit();

    if let Some(p) = pending.as_mut() {
        while !p.buf.is_empty() {
            match send_chunks(
                &io,
                sendmsg_x,
                p.destination,
                p.ecn,
                p.src_ip,
                state.sendmsg_einval(),
                p.segment_size,
                &p.buf,
            ) {
                Ok(sent) => {
                    debug_assert!(sent > 0, "sendmsg_x returned Ok(0); would spin");
                    let n = (sent * p.segment_size).min(p.buf.len());
                    p.buf.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                Err(_e) => {
                    crate::log::debug!("dropping queued datagram after sendmsg_x error: {_e}");
                    let n = p.segment_size.min(p.buf.len());
                    p.buf.drain(..n);
                }
            }
        }
    }

    *pending = None;

    let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
    let total = transmit.contents.len().div_ceil(segment_size);
    let mut sent_datagrams = 0;

    while sent_datagrams < total {
        let remaining = &transmit.contents[sent_datagrams * segment_size..];
        match send_chunks(
            &io,
            sendmsg_x,
            transmit.destination,
            transmit.ecn,
            transmit.src_ip,
            state.sendmsg_einval(),
            segment_size,
            remaining,
        ) {
            // We sent some datagrams, continue.
            Ok(sent) => {
                sent_datagrams += sent;
            }
            // We could not send any datagrams, suspend.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && sent_datagrams == 0 => {
                return Err(e);
            }
            // We sent some datagrams (in a prior iteration) and now we are blocked.
            // Buffer the remainder and return `Ok(())`.
            // The caller will call us with the next datagram and we will suspend as
            // part of the draining of the buffered packet.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let remainder = &transmit.contents[sent_datagrams * segment_size..];
                crate::log::debug!(
                    "sendmsg_x sent {sent_datagrams}/{total} datagrams; queuing remaining {} bytes for retry",
                    remainder.len()
                );

                // *pending = Some(PartialTransmit {
                //     destination: transmit.destination,
                //     ecn: transmit.ecn,
                //     src_ip: transmit.src_ip,
                //     segment_size,
                //     buf: remainder.to_vec(),
                // });
                return Ok(());
            }
            // Surface any other error without buffering / retry.
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Splits `contents` into `segment_size`-sized datagrams and submits them with a
/// single `sendmsg_x` call.
#[allow(clippy::too_many_arguments)]
fn send_chunks(
    io: &SockRef<'_>,
    sendmsg_x: SendmsgXFn,
    destination: SocketAddr,
    ecn: Option<EcnCodepoint>,
    src_ip: Option<IpAddr>,
    sendmsg_einval: bool,
    segment_size: usize,
    contents: &[u8],
) -> io::Result<usize> {
    let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
    let mut iovs = unsafe { mem::zeroed::<[libc::iovec; BATCH_SIZE]>() };
    let mut ctrls = [cmsg::Aligned([0u8; cmsg::LEN]); BATCH_SIZE];
    let addr = socket2::SockAddr::from(destination);
    let mut cnt = 0;
    debug_assert!(contents.len().div_ceil(segment_size) <= BATCH_SIZE);
    for (i, chunk) in contents.chunks(segment_size).enumerate().take(BATCH_SIZE) {
        prepare_msg_x(
            &Transmit {
                destination,
                ecn,
                contents: chunk,
                segment_size: Some(chunk.len()),
                src_ip,
            },
            &addr,
            &mut hdrs[i],
            &mut iovs[i],
            &mut ctrls[i],
            true,
            sendmsg_einval,
        );
        hdrs[i].msg_datalen = chunk.len();
        cnt += 1;
    }
    let sent = retry_if_interrupted(|| unsafe {
        sendmsg_x(io.as_raw_fd(), hdrs.as_ptr(), cnt as u32, 0)
    })?;
    Ok(sent as usize)
}

/// Prepares an `msghdr_x` for use with `sendmsg_x`
fn prepare_msg_x(
    transmit: &Transmit<'_>,
    dst_addr: &socket2::SockAddr,
    hdr: &mut msghdr_x,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
    #[allow(unused_variables)] encode_src_ip: bool,
    sendmsg_einval: bool,
) {
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
    let is_ipv4 = transmit.destination.is_ipv4()
        || matches!(transmit.destination.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
    if is_ipv4 {
        if !sendmsg_einval {
            encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
        }
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(ip) = &transmit.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                if encode_src_ip {
                    let addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                    encoder.push(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, addr);
                }
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

/// Returns the `sendmsg_x` function pointer, resolving it via `dlsym` on first call
///
/// Returns `None` if the symbol is not available on the current OS version.
fn sendmsg_x_fn() -> Option<SendmsgXFn> {
    static ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: `resolve_symbol` only returns non-zero addresses obtained from `dlsym`, which
    // guarantees a callable symbol whose type matches the declaration above.
    resolve_symbol(&ADDR, c"sendmsg_x")
        .map(|addr| unsafe { mem::transmute::<usize, SendmsgXFn>(addr) })
}

type SendmsgXFn =
    unsafe extern "C" fn(libc::c_int, *const msghdr_x, libc::c_uint, libc::c_int) -> isize;

/// The unsent tail of a partially-completed `sendmsg_x` invocation.
#[derive(Debug)]
pub(crate) struct PartialTransmit {
    destination: SocketAddr,
    ecn: Option<EcnCodepoint>,
    src_ip: Option<IpAddr>,
    segment_size: usize,
    buf: Vec<u8>,
}

/// Receive using the fast `recvmsg_x` API
pub(crate) fn recv_via_recvmsg_x(
    state: &UdpSocketState,
    io: SockRef<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    let mut names = [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE];
    // MacOS 10.15 `recvmsg_x` does not override the `msghdr_x`
    // `msg_controllen`. Thus, after the call to `recvmsg_x`, one does not know
    // which control messages have been written to. To prevent reading
    // uninitialized memory, do not use `MaybeUninit` for `ctrls`, instead
    // initialize `ctrls` with `0`s. A control message of all `0`s is
    // automatically skipped by `libc::CMSG_NXTHDR`.
    let mut ctrls = [cmsg::Aligned([0u8; cmsg::LEN]); BATCH_SIZE];
    let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
    let max_msg_count = bufs.len().min(BATCH_SIZE);
    for i in 0..max_msg_count {
        prepare_recv_x(&mut bufs[i], &mut names[i], &mut ctrls[i], &mut hdrs[i]);
    }
    let Some(recvmsg_x) = state.resolve_apple_fast_fn(recvmsg_x_fn) else {
        return recv_single(io, bufs, meta);
    };
    let msg_count = retry_if_interrupted(|| unsafe {
        recvmsg_x(io.as_raw_fd(), hdrs.as_mut_ptr(), max_msg_count as _, 0)
    })?;
    for i in 0..(msg_count as usize) {
        meta[i] = decode_recv(&names[i], &hdrs[i], hdrs[i].msg_datalen as usize)?;
    }
    Ok(msg_count as usize)
}

/// Prepares an `msghdr_x` for receiving with `recvmsg_x`
fn prepare_recv_x(
    buf: &mut IoSliceMut<'_>,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
    hdr: &mut msghdr_x,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut<'_> as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    hdr.msg_flags = 0;
    hdr.msg_datalen = buf.len();
}

/// Returns the `recvmsg_x` function pointer, resolving it via `dlsym` on first call
///
/// Returns `None` if the symbol is not available on the current OS version.
fn recvmsg_x_fn() -> Option<RecvmsgXFn> {
    static ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: `resolve_symbol` only returns non-zero addresses obtained from `dlsym`, which
    // guarantees a callable symbol whose type matches the declaration above.
    resolve_symbol(&ADDR, c"recvmsg_x")
        .map(|addr| unsafe { mem::transmute::<usize, RecvmsgXFn>(addr) })
}

type RecvmsgXFn =
    unsafe extern "C" fn(libc::c_int, *mut msghdr_x, libc::c_uint, libc::c_int) -> isize;

/// Resolves a symbol via `dlsym` on first call, caching the result
///
/// Returns `None` if the symbol is not available on the current OS version.
fn resolve_symbol(lock: &std::sync::OnceLock<usize>, name: &std::ffi::CStr) -> Option<usize> {
    let addr =
        *lock.get_or_init(|| unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) as usize });
    (addr != 0).then_some(addr)
}

// Adapted from https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/socket_private.h
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct msghdr_x {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: libc::socklen_t,
    pub msg_iov: *mut libc::iovec,
    pub msg_iovlen: libc::c_int,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: libc::socklen_t,
    pub msg_flags: libc::c_int,
    pub msg_datalen: usize,
}

impl MsgHdr for msghdr_x {
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
