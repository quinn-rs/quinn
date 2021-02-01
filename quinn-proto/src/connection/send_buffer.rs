use std::{collections::VecDeque, ops::Range};

use bytes::{Buf, Bytes};

use crate::range_set::RangeSet;

/// Buffer of outgoing retransmittable stream data
#[derive(Default, Debug)]
pub struct SendBuffer {
    /// Data queued by the application but not yet acknowledged. May or may not have been sent.
    unacked_segments: VecDeque<Bytes>,
    /// Total size of `unacked_segments`
    unacked_len: usize,
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
        let buf = Bytes::from(data.to_owned());
        self.unacked_segments.push_back(buf);
        self.unacked_len += data.len();
        self.offset += data.len() as u64;
    }

    /// Discard a range of acknowledged stream data
    pub fn ack(&mut self, mut range: Range<u64>) {
        // Clamp the range to data which is still tracked
        let base_offset = self.offset - self.unacked_len as u64;
        range.start = base_offset.max(range.start);
        range.end = base_offset.max(range.end);

        self.acks.insert(range);

        while self.acks.min() == Some(self.offset - self.unacked_len as u64) {
            let prefix = self.acks.pop_min().unwrap();
            let mut to_advance = (prefix.end - prefix.start) as usize;

            self.unacked_len -= to_advance;
            while to_advance > 0 {
                let front = self
                    .unacked_segments
                    .front_mut()
                    .expect("Expected buffered data");

                if front.len() <= to_advance {
                    to_advance -= front.len();
                    self.unacked_segments.pop_front();

                    if self.unacked_segments.len() * 4 < self.unacked_segments.capacity() {
                        self.unacked_segments.shrink_to_fit();
                    }
                } else {
                    front.advance(to_advance);
                    to_advance = 0;
                }
            }
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

    /// Returns data which is associated with a range
    ///
    /// This function can return a subset of the range, if the data is stored
    /// in noncontiguous fashion in the send buffer. In this case callers
    /// should call the function again with an incremented start offset to
    /// retrieve more data.
    pub fn get(&self, offsets: Range<u64>) -> &[u8] {
        let base_offset = self.offset - self.unacked_len as u64;

        let mut segment_offset = base_offset;
        for segment in self.unacked_segments.iter() {
            if offsets.start >= segment_offset
                && offsets.start < segment_offset + segment.len() as u64
            {
                let start = (offsets.start - segment_offset) as usize;
                let end = (offsets.end - segment_offset) as usize;

                return &segment[start..end.min(segment.len())];
            }
            segment_offset += segment.len() as u64;
        }

        &[]
    }

    /// Queue a range of sent but unacknowledged data to be retransmitted
    pub fn retransmit(&mut self, range: Range<u64>) {
        debug_assert!(range.end <= self.unsent, "unsent data can't be lost");
        self.retransmits.insert(range);
    }

    pub fn retransmit_all_for_0rtt(&mut self) {
        debug_assert_eq!(self.offset, self.unacked_len as u64);
        self.unsent = 0;
    }

    /// First stream offset unwritten by the application, i.e. the offset that the next write will
    /// begin at
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether all sent data has been acknowledged
    pub fn is_fully_acked(&self) -> bool {
        self.unacked_len == 0
    }

    /// Whether there's data to send
    ///
    /// There may be sent unacknowledged data even when this is false.
    pub fn has_unsent_data(&self) -> bool {
        self.unsent != self.offset || !self.retransmits.is_empty()
    }

    /// Compute the amount of data that hasn't been acknowledged
    pub fn unacked(&self) -> u64 {
        self.unacked_len as u64 - self.acks.iter().map(|x| x.end - x.start).sum::<u64>()
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
    fn multiple_segments() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        const MSG_LEN: u64 = MSG.len() as u64;

        const SEG1: &[u8] = b"He";
        buf.write(SEG1);
        const SEG2: &[u8] = b"llo,";
        buf.write(SEG2);
        const SEG3: &[u8] = b" ";
        buf.write(SEG3);
        const SEG4: &[u8] = b"wo";
        buf.write(SEG4);
        const SEG5: &[u8] = b"rld!";
        buf.write(SEG5);

        assert_eq!(aggregate_unacked(&buf), MSG);

        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.get(0..5), SEG1);
        assert_eq!(buf.get(2..5), &SEG2[0..3]);

        assert_eq!(buf.poll_transmit(MSG.len() - 5), 5..MSG_LEN);
        assert_eq!(buf.get(5..MSG_LEN), &SEG2[3..]);
        assert_eq!(buf.get(6..MSG_LEN), SEG3);
        assert_eq!(buf.get(7..MSG_LEN), SEG4);
        assert_eq!(buf.get(9..MSG_LEN), SEG5);

        assert_eq!(buf.poll_transmit(42), MSG_LEN..MSG_LEN);

        // Now drain the segments
        buf.ack(0..1);
        assert_eq!(aggregate_unacked(&buf), &MSG[1..]);
        buf.ack(0..3);
        assert_eq!(aggregate_unacked(&buf), &MSG[3..]);
        buf.ack(3..5);
        assert_eq!(aggregate_unacked(&buf), &MSG[5..]);
        buf.ack(7..9);
        assert_eq!(aggregate_unacked(&buf), &MSG[5..]);
        buf.ack(4..7);
        assert_eq!(aggregate_unacked(&buf), &MSG[9..]);
        buf.ack(0..MSG_LEN);
        assert_eq!(aggregate_unacked(&buf), &[]);
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
        assert_eq!(aggregate_unacked(&buf), &MSG[5..]);
    }

    #[test]
    fn reordered_ack() {
        let mut buf = SendBuffer::new();
        const MSG: &[u8] = b"Hello, world!";
        buf.write(MSG);
        assert_eq!(buf.poll_transmit(5), 0..5);
        assert_eq!(buf.poll_transmit(2), 5..7);
        buf.ack(5..7);
        assert_eq!(aggregate_unacked(&buf), MSG);
        buf.ack(0..5);
        assert_eq!(aggregate_unacked(&buf), &MSG[7..]);
        assert!(buf.acks.is_empty());
    }

    fn aggregate_unacked(buf: &SendBuffer) -> Vec<u8> {
        let mut result = Vec::new();
        for segment in buf.unacked_segments.iter() {
            result.extend_from_slice(&segment[..]);
        }
        result
    }
}
