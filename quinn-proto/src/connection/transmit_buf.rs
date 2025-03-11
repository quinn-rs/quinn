use bytes::BufMut;

/// The buffer in which to write datagrams for [`Connection::poll_transmit`]
///
/// The `poll_transmit` function writes zero or more datagrams to a buffer. Multiple
/// datagrams are possible in case GSO (Generic Segmentation Offload) is supported.
///
/// This buffer tracks datagrams being written to it. There is always a "current" datagram,
/// which is started by calling [`TransmitBuf::start_new_datagram`]. Writing to the buffer
/// is done through the [`BufMut`] interface.
///
/// Usually a datagram contains one QUIC packet, though QUIC-TRANSPORT 12.2 Coalescing
/// Packets allows for placing multiple packets into a single datagram provided all but the
/// last packet uses long headers. This is normally used during connection setup where often
/// the initial, handshake and sometimes even a 1-RTT packet can be coalesced into a single
/// datagram.
///
/// Inside a single packet multiple QUIC frames are written.
///
/// The buffer managed here is passed straight to the OS' `sendmsg` call (or variant) once
/// `poll_transmit` returns.  So needs to contain the datagrams as they are sent on the
/// wire.
///
/// [`Connection::poll_transmit`]: super::Connection::poll_transmit
#[derive(Debug)]
pub(super) struct TransmitBuf<'a> {
    /// The buffer itself, packets are written to this buffer
    pub(super) buf: &'a mut Vec<u8>,
    /// Offset into the buffer at which the current datagram starts
    ///
    /// Note that when coalescing packets this might be before the start of the current
    /// packet.
    pub(super) datagram_start: usize,
    /// The maximum offset allowed to be used for the current datagram in the buffer
    ///
    /// The first and last datagram in a batch are allowed to be smaller then the maximum
    /// size. All datagrams in between need to be exactly this size.
    pub(super) buf_capacity: usize,
    /// The maximum number of datagrams allowed to write into [`TransmitBuf::buf`]
    pub(super) max_datagrams: usize,
    /// The number of datagrams already (partially) written into the buffer
    ///
    /// Incremented by a call to [`TransmitBuf::start_new_datagram`].
    pub(super) num_datagrams: usize,
    /// The segment size of this GSO batch
    ///
    /// The segment size is the size of each datagram in the GSO batch, only the last
    /// datagram in the batch may be smaller.
    ///
    /// For the first datagram this is set to the maximum size a datagram is allowed to be:
    /// the current path MTU. After the first datagram is finished this is reduced to the
    /// size of the first datagram and can no longer change.
    pub(super) segment_size: usize,
}

impl<'a> TransmitBuf<'a> {
    pub(super) fn new(buf: &'a mut Vec<u8>, max_datagrams: usize, mtu: usize) -> Self {
        Self {
            buf,
            datagram_start: 0,
            buf_capacity: 0,
            max_datagrams,
            num_datagrams: 0,
            segment_size: mtu,
        }
    }

    /// Returns `true` if the buffer did not have anything written into it
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of bytes written into the buffer so far
    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }
}

unsafe impl BufMut for TransmitBuf<'_> {
    fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt);
    }

    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.buf.chunk_mut()
    }
}
