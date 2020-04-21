use std::ops::Range;

use bytes::{Buf, BytesMut};

use crate::range_set::RangeSet;

/// Buffer of outgoing retransmittable stream data
#[derive(Default, Debug)]
pub struct SendBuffer {
    /// Data queued by the application but not yet acknowledged. May or may not have been sent.
    unacked: BytesMut,
    /// The first offset that hasn't been written by the application, i.e. the offset past the end of `unacked`
    offset: u64,
    /// The first offset that hasn't been sent
    ///
    /// Always lies in (offset - unacked.len())..offset
    unsent: u64,
    /// Acknowledged ranges which couldn't be discarded yet as they don't include the earliest
    /// offset in `unacked`
    // TODO: Recover storage from these by compacting (#700)
    acks: RangeSet,
    /// Previously transmitted ranges deemed lost
    retransmits: RangeSet,
}

impl SendBuffer {
    /// Construct an empty buffer at the initial offset
    pub fn new() -> Self {
        Self::default()
    }

    /// Append application data to the end of the stream
    pub fn write(&mut self, data: &[u8]) {
        self.unacked.extend_from_slice(data);
        self.offset += data.len() as u64;
    }

    /// Discard a range of acknowledged stream data
    ///
    /// Each offset must be acknowledged at most once.
    pub fn ack(&mut self, range: Range<u64>) {
        self.acks.insert(range);
        while self.acks.min() == Some(self.offset - self.unacked.len() as u64) {
            let prefix = self.acks.pop_min().unwrap();
            self.unacked.advance((prefix.end - prefix.start) as usize);
        }
    }

    /// Compute the next range to transmit on this stream and update state to account for that
    /// transmission
    pub fn poll_transmit(&mut self, max_len: usize) -> Range<u64> {
        if let Some(range) = self.retransmits.pop_min() {
            // Retransmit sent data
            let end = range.end.min((max_len as u64).saturating_add(range.start));
            if end != range.end {
                self.retransmits.insert(end..range.end);
            }
            return range.start..end;
        }
        // Transmit new data
        let end = self
            .offset
            .min((max_len as u64).saturating_add(self.unsent));
        let result = self.unsent..end;
        self.unsent = end;
        result
    }

    pub fn get(&self, offsets: Range<u64>) -> &[u8] {
        let base_offset = self.offset - self.unacked.len() as u64;
        let start = (offsets.start - base_offset) as usize;
        let end = (offsets.end - base_offset) as usize;
        &self.unacked[start..end]
    }

    /// Queue a range of sent but unacknowledged data to be retransmitted
    pub fn retransmit(&mut self, range: Range<u64>) {
        debug_assert!(range.end <= self.unsent, "unsent data can't be lost");
        self.retransmits.insert(range);
    }

    pub fn retransmit_all_for_0rtt(&mut self) {
        debug_assert_eq!(self.offset, self.unacked.len() as u64);
        self.unsent = 0;
    }

    /// First stream offset unwritten by the application, i.e. the offset that the next write will
    /// begin at
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether all sent data has been acknowledged
    pub fn is_fully_acked(&self) -> bool {
        self.unacked.is_empty()
    }

    /// Whether there's data to send
    ///
    /// There may be sent unacknowledged data even when this is false.
    pub fn has_unsent_data(&self) -> bool {
        self.unsent != self.offset || !self.retransmits.is_empty()
    }

    /// Compute the amount of data that hasn't been acknowledged
    pub fn unacked(&self) -> u64 {
        self.unacked.len() as u64 - self.acks.iter().map(|x| x.end - x.start).sum::<u64>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        buf.write(MSG);
        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.poll_transmit(MSG.len() - 5), 5..MSG.len() as u64);
        assert_eq!(buf.poll_transmit(42), MSG.len() as u64..MSG.len() as u64);
    }

    #[test]
    fn retransmit() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        buf.write(MSG);
        // Transmit two frames
        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.poll_transmit(2), 5..7);
        // Lose the first, but not the second
        buf.retransmit(0..5);
        // Ensure we only retransmit the lost frame, then continue sending fresh data
        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.poll_transmit(MSG.len() - 7), 7..MSG.len() as u64);
    }

    #[test]
    fn ack() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        buf.write(MSG);
        assert_eq!(buf.poll_transmit(5), 0..5);
        buf.ack(0..5);
        assert_eq!(buf.unacked, MSG[5..]);
    }

    #[test]
    fn reordered_ack() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        buf.write(MSG);
        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.poll_transmit(2), 5..7);
        buf.ack(5..7);
        assert_eq!(buf.unacked, MSG);
        buf.ack(0..5);
        assert_eq!(buf.unacked, MSG[7..]);
        assert!(buf.acks.is_empty());
    }
}
