use bytes::BufMut;

use crate::packet::BufOffset;

/// The buffer in which to write datagrams for [`Connection::poll_transmit`]
///
/// The `poll_transmit` function writes zero or more datagrams to a buffer.  Multiple
/// datagrams are possible in case GSO (Generic Segmentation Offload) is supported.
///
/// This buffer tracks datagrams being written to it.  There is always a "current" datagram,
/// which is started by calling [`TransmitBuf::start_new_datagram`].  Writing to the buffer
/// is done through the [`BufMut`] interface.
///
/// Usually a datagram contains one QUIC packet, though QUIC-TRANSPORT 12.2 Coalescing
/// Packets allows for placing multiple packets into a single datagram provided all but the
/// last packet uses long headers.  This is normally used during connection setup where
/// often the initial, handshake and sometimes even a 1-RTT packet can be coalesced into a
/// single datagram.
///
/// Inside a single packet multiple QUIC frames are written.
///
/// The buffer managed here is passed straight to the OS' `sendmsg` call (or variant) once
/// `poll_transmit` returns.  So needs to contain the datagrams as they are sent on the
/// wire.
#[derive(Debug)]
pub(super) struct TransmitBuf<'a> {
    /// The buffer itself, packets are written to this buffer
    buf: &'a mut Vec<u8>,
    /// Offset into the buffer at which the current datagram starts
    ///
    /// Note that when coalescing packets this might be before the start of the current
    /// packet.
    datagram_start: usize,
    /// The maximum offset allowed to be used for the current datagram in the buffer
    ///
    /// The first and last datagram in a batch are allowed to be smaller then the maximum
    /// size.  All datagrams in between need to be exactly this size.
    buf_capacity: usize,
    /// The maximum number of datagrams allowed to write into [`TransmitBuf::buf`]
    max_datagrams: usize,
    /// The number of datagrams already (partially) written into the buffer
    ///
    /// Incremented by a call to [`TransmitBuf::start_next_datagram`].
    num_datagrams: usize,
    /// The segment size of this GSO batch
    ///
    /// The segment size is the size of each datagram in the GSO batch, only the last
    /// datagram in the batch may be smaller.
    ///
    /// For the first datagram this is set to the maximum size a datagram is allowed to be:
    /// the current path MTU.  After the first datagram is finished this is reduced to the
    /// size of the first datagram and can no longer change.
    segment_size: usize,
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

    /// The number of bytes written into the buffer so far
    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer did not have anything written into it
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the GSO segment size
    ///
    /// This is also the maximum size datagrams are allowed to be.  The first and last
    /// datagram in a batch are allowed to be smaller however.  After the first datagram the
    /// segment size is clipped to the size of the first datagram.
    pub(super) fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// Returns the number of datagrams written into the buffer
    ///
    /// The last datagram is not necessarily finished yet.
    pub(super) fn num_datagrams(&self) -> usize {
        self.num_datagrams
    }

    /// Returns the start offset of the current datagram in the buffer
    ///
    /// In other words, this offset contains the first byte of the current datagram.
    pub(super) fn datagram_start_offset(&self) -> usize {
        self.datagram_start
    }

    /// Returns the maximum offset in the buffer allowed for the current datagram
    ///
    /// The first and last datagram in a batch are allowed to be smaller then the maximum
    /// size.  All datagrams in between need to be exactly this size.
    pub(super) fn datagram_max_offset(&self) -> usize {
        self.buf_capacity
    }

    /// Whether the buffer has capacity for another datagram after the current one
    pub(super) fn has_datagram_capacity(&self) -> bool {
        let max_buffer_size = self.segment_size * self.max_datagrams;
        self.buf_capacity < max_buffer_size
    }

    /// Clips the datagram size to the current size
    ///
    /// Only valid for the first datagram, when the datagram might be smaller than the
    /// segment size.  Needed before estimating the available space in the next datagram
    /// based on [`TransmitBuf::segment_size`].
    pub(super) fn clip_datagram_size(&mut self) {
        debug_assert_eq!(self.num_datagrams, 1);
        self.segment_size = self.buf.len();
    }

    /// Starts a new datagram in the transmit buffer
    ///
    /// If the underlying buffer does not have enough capacity yet this will allocate enough
    /// capacity for all the datagrams allowed in a single batch.  Use
    /// [`TransmitBuf::reserve`] to pre-allocate capacity if you know you will need less.
    ///
    /// If the next datagram is a loss probe the size of the next datagram will be clipped
    /// at [`INITIAL_MTU`].
    pub(super) fn start_new_datagram(&mut self) {
        if self.num_datagrams == 1 {
            // Set the segment size to the size of the first datagram.
            self.segment_size = self.buf.len();
        }
        self.datagram_start = self.buf.len();
        debug_assert_eq!(
            self.datagram_start % self.segment_size,
            0,
            "datagrams in a GSO batch must be aligned to the segment size"
        );
        self.buf_capacity = self.datagram_start + self.segment_size;
        if self.buf_capacity > self.buf.capacity() {
            // We reserve the maximum space for sending `max_datagrams` upfront to avoid
            // any reallocations if more datagrams have to be appended later on.
            // Benchmarks have shown a 5-10% throughput improvment compared to
            // continuously resizing the datagram buffer.  While this will lead to
            // over-allocation for small transmits (e.g. purely containing ACKs), modern
            // memory allocators (e.g. mimalloc and jemalloc) will pool certain
            // allocation sizes and therefore this is still rather efficient.
            self.buf
                .reserve_exact((self.max_datagrams * self.segment_size) - self.buf.capacity());
        }
        self.num_datagrams += 1;
    }

    /// Starts a single datagram with a custom datagram size
    ///
    /// This is a specialised version of [`TransmitBuf::start_new_datagram`] which sets the
    /// datagram size.  Useful for e.g. PATH_CHALLENGE, tail-loss probes or MTU probes.
    pub(super) fn start_new_datagram_with_size(&mut self, datagram_size: usize) {
        if self.num_datagrams == 1 {
            // Set the segment size to the size of the first datagram.
            self.segment_size = self.buf.len();
        }
        if self.num_datagrams >= 1 {
            debug_assert!(datagram_size <= self.segment_size);
        }
        self.datagram_start = self.buf.len();
        debug_assert_eq!(
            self.datagram_start % self.segment_size,
            0,
            "datagrams in a GSO batch must be aligned to the segment size"
        );
        self.buf_capacity = self.datagram_start + datagram_size;
        if self.buf_capacity > self.buf.capacity() {
            // Only reserve space for this datagram, usually it is the last one in the
            // batch.
            self.buf
                .reserve_exact(self.buf_capacity - self.buf.capacity());
        }
        self.num_datagrams += 1;
    }

    /// Returns the already written bytes in the buffer
    pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    /// Pad the buffer with *size* `0` bytes
    pub(super) fn put_padding(&mut self, size: usize) {
        self.buf.resize(self.buf.len() + size, 0)
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

impl BufOffset for TransmitBuf<'_> {
    fn offset(&self) -> usize {
        self.buf.len()
    }
}
