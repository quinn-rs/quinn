use bytes::BufMut;
use tracing::trace;

use crate::packet::BufLen;

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

    pub(super) fn set_segment_size(&mut self, mtu: usize) {
        debug_assert!(
            self.datagram_start == 0 && self.buf_capacity == 0 && self.num_datagrams == 0,
            "can only change the segment size if nothing has been written yet"
        );

        self.segment_size = mtu;
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
        if self.buf.len() < self.segment_size {
            trace!(
                segment_size = self.buf.len(),
                prev_segment_size = self.segment_size,
                "clipped datagram size"
            );
        }
        self.segment_size = self.buf.len();
        self.buf_capacity = self.buf.len();
    }

    /// Returns the GSO segment size
    ///
    /// This is also the maximum size datagrams are allowed to be. The first and last
    /// datagram in a batch are allowed to be smaller however. After the first datagram the
    /// segment size is clipped to the size of the first datagram.
    ///
    /// If the last datagram was created using [`TransmitBuf::start_new_datagram_with_size`]
    /// the the segment size will be greater than the current datagram is allowed to be.
    /// Thus [`TransmitBuf::datagram_remaining_mut`] should be used if you need to know the
    /// amount of data that can be written into the datagram.
    pub(super) fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// Returns the number of datagrams written into the buffer
    ///
    /// The last datagram is not necessarily finished yet.
    pub(super) fn num_datagrams(&self) -> usize {
        self.num_datagrams
    }

    /// Returns the maximum number of datagrams allowed to be written into the buffer
    pub(super) fn max_datagrams(&self) -> usize {
        self.max_datagrams
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
    /// size. All datagrams in between need to be exactly this size.
    pub(super) fn datagram_max_offset(&self) -> usize {
        self.buf_capacity
    }

    /// Returns the number of bytes that may still be written into this datagram
    pub(super) fn datagram_remaining_mut(&self) -> usize {
        self.buf_capacity.saturating_sub(self.buf.len())
    }

    /// Returns `true` if the buffer did not have anything written into it
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of bytes written into the buffer so far
    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns the already written bytes in the buffer
    pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

unsafe impl BufMut for TransmitBuf<'_> {
    fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.buf.advance_mut(cnt) };
    }

    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.buf.chunk_mut()
    }
}

impl BufLen for TransmitBuf<'_> {
    fn len(&self) -> usize {
        self.len()
    }
}
