use std::ops::{Deref, DerefMut};

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
pub(super) struct TransmitBuilder<'a> {
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
    /// size. All datagrams in between need to be exactly this size.
    buf_capacity: usize,
    /// The maximum number of datagrams allowed to write into [`TransmitBuf::buf`]
    max_datagrams: usize,
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
    segment_size: usize,
}

impl<'a> TransmitBuilder<'a> {
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

    /// Starts a datagram with a custom datagram size
    ///
    /// This is a specialized version of [`TransmitBuf::start_new_datagram`] which sets the
    /// datagram size. Useful for e.g. PATH_CHALLENGE, tail-loss probes or MTU probes.
    ///
    /// After the first datagram you can never increase the segment size. If you decrease
    /// the size of a datagram in a batch, it must be the last datagram of the batch.
    pub(super) fn start_new_datagram_with_size(&mut self, datagram_size: usize) {
        // Only reserve space for this datagram, usually it is the last one in the batch.
        let max_capacity_hint = datagram_size;
        self.new_datagram_inner(datagram_size, max_capacity_hint)
    }

    /// Starts a new datagram in the transmit buffer
    ///
    /// If this starts the second datagram the segment size will be set to the size of the
    /// first datagram.
    ///
    /// If the underlying buffer does not have enough capacity yet this will allocate enough
    /// capacity for all the datagrams allowed in a single batch. Use
    /// [`TransmitBuf::start_new_datagram_with_size`] if you know you will need less.
    pub(super) fn start_new_datagram(&mut self) {
        // We reserve the maximum space for sending `max_datagrams` upfront to avoid any
        // reallocations if more datagrams have to be appended later on.  Benchmarks have
        // shown a 5-10% throughput improvement compared to continuously resizing the
        // datagram buffer. While this will lead to over-allocation for small transmits
        // (e.g. purely containing ACKs), modern memory allocators (e.g. mimalloc and
        // jemalloc) will pool certain allocation sizes and therefore this is still rather
        // efficient.
        let max_capacity_hint = self.max_datagrams * self.segment_size;
        self.new_datagram_inner(self.segment_size, max_capacity_hint)
    }

    fn new_datagram_inner(&mut self, datagram_size: usize, max_capacity_hint: usize) {
        debug_assert!(self.num_datagrams < self.max_datagrams);
        if self.num_datagrams == 1 {
            // Set the segment size to the size of the first datagram.
            self.segment_size = self.buf.len();
        }
        if self.num_datagrams >= 1 {
            debug_assert!(datagram_size <= self.segment_size);
            if datagram_size < self.segment_size {
                // If this is a GSO batch and this datagram is smaller than the segment
                // size, this must be the last datagram in the batch.
                self.max_datagrams = self.num_datagrams + 1;
            }
        }
        self.datagram_start = self.buf.len();
        debug_assert_eq!(
            self.datagram_start % self.segment_size,
            0,
            "datagrams in a GSO batch must be aligned to the segment size"
        );
        self.buf_capacity = self.datagram_start + datagram_size;
        if self.buf_capacity > self.buf.capacity() {
            self.buf
                .reserve_exact(max_capacity_hint.saturating_sub(self.buf.capacity()));
        }
        self.num_datagrams += 1;
    }

    /// Clips the datagram size to the current size
    ///
    /// Only valid for the first datagram, when the datagram might be smaller than the
    /// segment size. Needed before estimating the available space in the next datagram
    /// based on [`TransmitBuf::segment_size`].
    ///
    /// Use [`TransmitBuf::start_new_datagram_with_size`] if you need to reduce the size of
    /// the last datagram in a batch.
    pub(super) fn clip_datagram_size(&mut self) {
        debug_assert_eq!(self.num_datagrams, 1);
        self.segment_size = self.buf.len();
        self.buf_capacity = self.buf.len();
    }

    /// Returns a mutable buffer for the current datagram
    ///
    /// This buffer implements [`BufSlice`] and thus allows writing into the buffer using
    /// [`BufMut`] and both reading and modifying the already written data in the buffer
    /// using [`Deref`] and [`DerefMut`].  The buffer also enforces a maximum size.
    pub(super) fn datagram_mut(&mut self) -> DatagramBuffer<'_> {
        DatagramBuffer::new(
            self.buf,
            self.datagram_start,
            self.buf_capacity - self.datagram_start,
        )
    }

    /// Returns the bytes written into the current datagram
    pub(super) fn datagram(&self) -> &[u8] {
        &self.buf[self.datagram_start..]
    }

    /// Whether there is space for another datagram in this transmit
    pub(super) fn has_datagram_capacity(&self) -> bool {
        self.num_datagrams >= self.max_datagrams
    }

    /// The sum of the capacity of all started datagrams in the transmit
    ///
    /// This might be more than [`len`] when the current datagram is not yet fully
    /// written. In other words: this is the length of the transmit when the current
    /// datagram would fill the entire segment size.
    ///
    /// [`len`]: TransmitBuf::len
    pub(super) fn capacity(&self) -> usize {
        self.segment_size * self.num_datagrams
    }

    /// Whether the current datagram is the first in the transmit buffer
    pub(super) fn is_first_datagram(&self) -> bool {
        self.num_datagrams == 1
    }

    /// Returns the GSO segment size
    ///
    /// This is also the maximum size datagrams are allowed to be. The first and last
    /// datagram in a batch are allowed to be smaller however. After the first datagram the
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

    /// Returns `true` if there are no datagrams in this transmit
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the sum of the bytes for all datagrams in the builder
    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }
}

/// A [`BufSlice`] implementation for a datagram
#[derive(Debug)]
pub(crate) struct DatagramBuffer<'a> {
    /// The underlying storage the datagram buffer exists in
    buf: &'a mut Vec<u8>,
    /// The start offset of the datagram in the underlying buffer
    start_offset: usize,
    /// The maximum write offset in the underlying buffer for this datagram
    max_offset: usize,
}

impl<'a> DatagramBuffer<'a> {
    pub(crate) fn new(buf: &'a mut Vec<u8>, start_offset: usize, max_size: usize) -> Self {
        // Make sure that at least this datagram is allocated.  Does nothing if, like for a
        // transmit, already more has been allocated.
        buf.reserve(max_size);

        let max_offset = start_offset + max_size;
        DatagramBuffer {
            buf,
            start_offset,
            max_offset,
        }
    }
}

unsafe impl BufMut for DatagramBuffer<'_> {
    fn remaining_mut(&self) -> usize {
        self.max_offset - self.buf.len()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt);
    }

    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.buf.chunk_mut()
    }
}

impl Deref for DatagramBuffer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.start_offset..]
    }
}

impl DerefMut for DatagramBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[self.start_offset..]
    }
}

impl DatagramBuffer<'_> {
    /// Returns the maximum size of the buffer
    pub(crate) fn capacity(&self) -> usize {
        self.max_offset - self.start_offset
    }
}
