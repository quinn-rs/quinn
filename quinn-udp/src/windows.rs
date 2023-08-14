use std::{
    io::{self, IoSliceMut},
    mem,
    os::windows::io::AsRawSocket,
    sync::Mutex,
    time::Instant,
};

use windows_sys::Win32::Networking::WinSock;

use super::{log_sendmsg_error, RecvMeta, Transmit, UdpSockRef, IO_ERROR_LOG_INTERVAL};

/// QUIC-friendly UDP interface for Windows
#[derive(Debug)]
pub struct UdpSocketState {
    last_send_error: Mutex<Instant>,
}

impl UdpSocketState {
    pub fn new(socket: UdpSockRef<'_>) -> io::Result<Self> {
        socket.0.set_nonblocking(true)?;
        let addr = socket.0.local_addr()?;
        let is_ipv6 = addr.as_socket_ipv6().is_some();
        let v6only = unsafe {
            let mut result: u32 = 0;
            let mut len = mem::size_of_val(&result) as i32;
            let rc = WinSock::getsockopt(
                socket.0.as_raw_socket() as _,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_V6ONLY as _,
                &mut result as *mut _ as _,
                &mut len,
            );
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
            result != 0
        };
        let is_ipv4 = addr.as_socket_ipv4().is_some() || !v6only;

        let sock_true: u32 = 1;

        if is_ipv4 {
            let rc = unsafe {
                WinSock::setsockopt(
                    socket.0.as_raw_socket() as _,
                    WinSock::IPPROTO_IP as _,
                    WinSock::IP_DONTFRAGMENT as _,
                    &sock_true as *const _ as _,
                    mem::size_of_val(&sock_true) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        if is_ipv6 {
            let rc = unsafe {
                WinSock::setsockopt(
                    socket.0.as_raw_socket() as _,
                    WinSock::IPPROTO_IPV6 as _,
                    WinSock::IPV6_DONTFRAG as _,
                    &sock_true as *const _ as _,
                    mem::size_of_val(&sock_true) as _,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let now = Instant::now();
        Ok(Self {
            last_send_error: Mutex::new(now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now)),
        })
    }

    pub fn send(&self, socket: UdpSockRef<'_>, transmits: &[Transmit]) -> Result<usize, io::Error> {
        let mut sent = 0;
        for transmit in transmits {
            match socket.0.send_to(
                &transmit.contents,
                &socket2::SockAddr::from(transmit.destination),
            ) {
                Ok(_) => {
                    sent += 1;
                }
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                Err(_) if sent != 0 => return Ok(sent),
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        return Err(e);
                    }

                    // Other errors are ignored, since they will usually be handled
                    // by higher level retransmits and timeouts.
                    log_sendmsg_error(&self.last_send_error, e, transmit);
                    sent += 1;
                }
            }
        }
        Ok(sent)
    }

    pub fn recv(
        &self,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // Safety: both `IoSliceMut` and `MaybeUninitSlice` promise to have the
        // same layout, that of `iovec`/`WSABUF`. Furthermore `recv_vectored`
        // promises to not write unitialised bytes to the `bufs` and pass it
        // directly to the `recvmsg` system call, so this is safe.
        let bufs = unsafe {
            &mut *(bufs as *mut [IoSliceMut<'_>] as *mut [socket2::MaybeUninitSlice<'_>])
        };
        let (len, _flags, addr) = socket.0.recv_from_vectored(bufs)?;
        meta[0] = RecvMeta {
            len,
            stride: len,
            addr: addr.as_socket().unwrap(),
            ecn: None,
            dst_ip: None,
        };
        Ok(1)
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        1
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub fn gro_segments(&self) -> usize {
        1
    }

    #[inline]
    pub fn may_fragment(&self) -> bool {
        false
    }
}

pub(crate) const BATCH_SIZE: usize = 1;
