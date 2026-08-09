use std::{
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    sync::Mutex,
    time::Instant,
};

use super::{IO_ERROR_LOG_INTERVAL, RecvMeta, Transmit, UdpSockRef, log_sendmsg_error};

/// Fallback UDP socket interface that stubs out all special functionality
///
/// Used when a better implementation is not available for a particular target, at the cost of
/// reduced performance compared to that enabled by some target-specific interfaces.
#[derive(Debug)]
pub struct UdpSocketState {
    last_send_error: Mutex<Instant>,
}

impl UdpSocketState {
    pub fn new(socket: UdpSockRef<'_>) -> io::Result<Self> {
        socket.0.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(Self {
            last_send_error: Mutex::new(now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now)),
        })
    }

    /// Sends a [`Transmit`] on the given socket.
    ///
    /// This function will only ever return errors of kind [`io::ErrorKind::WouldBlock`].
    /// All other errors will be logged and converted to `Ok`.
    ///
    /// UDP transmission errors are considered non-fatal because higher-level protocols must
    /// employ retransmits and timeouts anyway in order to deal with UDP's unreliable nature.
    /// Thus, logging is most likely the only thing you can do with these errors.
    ///
    /// If you would like to handle these errors yourself, use [`UdpSocketState::try_send`]
    /// instead.
    pub fn send(&self, socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        match send(socket, transmit) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                log_sendmsg_error(&self.last_send_error, e, transmit);

                Ok(())
            }
        }
    }

    /// Sends a [`Transmit`] on the given socket without any additional error handling.
    pub fn try_send(&self, socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        send(socket, transmit)
    }

    pub fn recv(
        &self,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        if bufs.is_empty() || meta.is_empty() {
            return Ok(0);
        }

        // `recv_from_vectored` is not available on every target that uses this backend: socket2
        // gates it out on redox, wasi and horizon, since they have no `recvmsg`. We only ever
        // receive one datagram at a time here (`BATCH_SIZE` is 1), so read into the first buffer
        // with plain `recv_from` instead, which is available everywhere.
        //
        // Safety: `recv_from` takes `&mut [MaybeUninit<u8>]`, and `MaybeUninit<u8>` has the same
        // size and alignment as `u8`, so the pointer and length taken from `bufs[0]` describe a
        // valid slice of the same region. Treating initialised memory as possibly-uninitialised is
        // always sound, and `recv_from` promises not to write uninitialised bytes, so `bufs[0]`
        // stays fully initialised. The mutable borrow of `bufs` lasts for the whole call, so
        // nothing else can access the region while `buf` is alive.
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                bufs[0].as_mut_ptr().cast::<MaybeUninit<u8>>(),
                bufs[0].len(),
            )
        };
        let (len, addr) = socket.0.recv_from(buf)?;
        meta[0] = RecvMeta {
            len,
            stride: len,
            addr: addr.as_socket().unwrap(),
            ecn: None,
            dst_ip: None,
            interface_index: None,
            timestamp: None,
        };
        Ok(1)
    }

    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        1
    }

    #[inline]
    pub fn gro_segments(&self) -> usize {
        1
    }

    /// Resize the send buffer of `socket` to `bytes`
    #[inline]
    pub fn set_send_buffer_size(&self, socket: UdpSockRef<'_>, bytes: usize) -> io::Result<()> {
        socket.0.set_send_buffer_size(bytes)
    }

    /// Resize the receive buffer of `socket` to `bytes`
    #[inline]
    pub fn set_recv_buffer_size(&self, socket: UdpSockRef<'_>, bytes: usize) -> io::Result<()> {
        socket.0.set_recv_buffer_size(bytes)
    }

    /// Get the size of the `socket` send buffer
    #[inline]
    pub fn send_buffer_size(&self, socket: UdpSockRef<'_>) -> io::Result<usize> {
        socket.0.send_buffer_size()
    }

    /// Get the size of the `socket` receive buffer
    #[inline]
    pub fn recv_buffer_size(&self, socket: UdpSockRef<'_>) -> io::Result<usize> {
        socket.0.recv_buffer_size()
    }

    #[inline]
    pub fn may_fragment(&self) -> bool {
        true
    }
}

fn send(socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
    socket.0.send_to(
        transmit.contents,
        &socket2::SockAddr::from(transmit.destination),
    )?;
    Ok(())
}

pub(crate) const BATCH_SIZE: usize = 1;
