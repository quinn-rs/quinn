use std::{
    fmt::{self, Write},
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use crate::{
    coding::{BufExt, BufMutExt},
    connection::{PacketTimestamp, ReceiverTimestamps},
    frame::{AckIter, Type},
    range_set::ArrayRangeSet,
};

use bytes::{Buf, BufMut, Bytes};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AckTimestampFrame {
    pub largest: u64,
    pub delay: u64,
    pub ranges: Bytes,
    pub timestamps: Bytes,
}

impl AckTimestampFrame {
    pub(crate) fn encode<W: BufMut>(
        delay: u64,
        ranges: &ArrayRangeSet,
        timestamps: &ReceiverTimestamps,
        timestamp_basis: Instant,
        timestamp_exponent: u64,
        max_timestamps: u64,
        buf: &mut W,
    ) {
        let mut rest = ranges.iter().rev();
        let first = rest.next().unwrap();
        let largest = first.end - 1;
        let first_size = first.end - first.start;
        buf.write(Type::ACK_RECEIVE_TIMESTAMPS);
        buf.write_var(largest);
        buf.write_var(delay);
        buf.write_var(ranges.len() as u64 - 1);
        buf.write_var(first_size - 1);
        let mut prev = first.start;
        for block in rest {
            let size = block.end - block.start;
            buf.write_var(prev - block.end - 1);
            buf.write_var(size - 1);
            prev = block.start;
        }

        Self::encode_timestamps(
            timestamps,
            largest,
            buf,
            timestamp_basis,
            timestamp_exponent,
            max_timestamps,
        );
    }

    // https://www.ietf.org/archive/id/draft-smith-quic-receive-ts-00.html#ts-ranges
    fn encode_timestamps<W: BufMut>(
        timestamps: &ReceiverTimestamps,
        mut largest: u64,
        buf: &mut W,
        mut basis: Instant,
        exponent: u64,
        max_timestamps: u64,
    ) {
        if timestamps.len() == 0 {
            buf.write_var(0);
            return;
        }
        let mut prev: Option<u64> = None;

        // segment_idx tracks the positions in `timestamps` in which a gap occurs.
        let mut segment_idxs = Vec::<usize>::new();
        // iterates from largest number to smallest
        for (i, pkt) in timestamps.iter().rev().enumerate() {
            if let Some(prev) = prev {
                if pkt.packet_number + 1 != prev {
                    segment_idxs.push(timestamps.len() - i);
                }
            }
            prev = Some(pkt.packet_number);
        }
        segment_idxs.push(0);
        // Timestamp Range Count
        buf.write_var(segment_idxs.len() as u64);

        let mut right = timestamps.len();
        let mut first = true;
        let mut counter = 0;

        for segment_idx in segment_idxs {
            let Some(elt) = timestamps.inner().get(right - 1) else {
                debug_assert!(
                    false,
                    "an invalid indexing occurred on the ReceiverTimestamps vector"
                );
                break;
            };
            // *Gap
            // For the first Timestamp Range: Gap is the difference between (a) the Largest Acknowledged packet number
            // in the frame and (b) the largest packet in the current (first) Timestamp Range.
            let gap = if first {
                debug_assert!(
                    elt.packet_number <= largest,
                    "largest packet number is less than what was found in timestamp vec"
                );
                largest - elt.packet_number
            } else {
                // For subsequent Timestamp Ranges: Gap is the difference between (a) the packet number two lower
                // than the smallest packet number in the previous Timestamp Range
                // and (b) the largest packet in the current Timestamp Range.
                largest - 2 - elt.packet_number
            };
            buf.write_var(gap);
            // *Timestamp Delta Count
            buf.write_var((right - segment_idx) as u64);
            // *Timestamp Deltas
            for pkt in timestamps.inner().range(segment_idx..right).rev() {
                let delta: u64 = if first {
                    first = false;
                    // For the first Timestamp Delta of the first Timestamp Range in the frame: the value
                    // is the difference between (a) the receive timestamp of the largest packet in the
                    // Timestamp Range (indicated by Gap) and (b) the session receive_timestamp_basis
                    pkt.timestamp.duration_since(basis).as_micros() as u64
                } else {
                    // For all other Timestamp Deltas: the value is the difference between
                    // (a) the receive timestamp specified by the previous Timestamp Delta and
                    // (b) the receive timestamp of the current packet in the Timestamp Range, decoded as described below.
                    basis.duration_since(pkt.timestamp).as_micros() as u64
                };
                buf.write_var(delta >> exponent);
                basis = pkt.timestamp;
                largest = pkt.packet_number;
                counter += 1;
            }

            right = segment_idx;
        }

        debug_assert!(
            counter <= max_timestamps,
            "the number of timestamps in an ack frame exceeded the max allowed"
        );
    }

    /// timestamp_iter returns an iterator that reads the timestamp records from newest to oldest
    /// (or highest packet number to smallest).
    pub(crate) fn timestamp_iter(&self, basis: Instant, exponent: u64) -> AckTimestampDecoder {
        AckTimestampDecoder::new(self.largest, basis, exponent, &self.timestamps[..])
    }

    pub(crate) fn iter(&self) -> AckIter<'_> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a AckTimestampFrame {
    type Item = RangeInclusive<u64>;
    type IntoIter = AckIter<'a>;

    fn into_iter(self) -> AckIter<'a> {
        AckIter::new(self.largest, &self.ranges[..])
    }
}

impl fmt::Debug for AckTimestampFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ranges = "[".to_string();
        let mut first = true;
        for range in self.iter() {
            if !first {
                ranges.push(',');
            }
            write!(ranges, "{range:?}").unwrap();
            first = false;
        }
        ranges.push(']');

        let timestamp_count = self.timestamp_iter(Instant::now(), 0).count();

        f.debug_struct("AckTimestamp")
            .field("largest", &self.largest)
            .field("delay", &self.delay)
            .field("ranges", &ranges)
            .field("timestamps_count", &timestamp_count)
            .finish()
    }
}

pub(crate) struct AckTimestampDecoder<'a> {
    timestamp_basis: u64,
    timestamp_exponent: u64,
    timestamp_instant_basis: Instant,
    data: &'a [u8],

    deltas_remaining: usize,
    first: bool,
    next_pn: u64,
}

impl<'a> AckTimestampDecoder<'a> {
    fn new(largest: u64, basis_instant: Instant, exponent: u64, mut data: &'a [u8]) -> Self {
        // We read and throw away the Timestamp Range Count value because
        // it was already used to properly slice the data.
        let _ = data.get_var().unwrap();
        AckTimestampDecoder {
            timestamp_basis: 0,
            timestamp_exponent: exponent,
            timestamp_instant_basis: basis_instant,
            data,
            deltas_remaining: 0,
            first: true,
            next_pn: largest,
        }
    }
}

impl<'a> Iterator for AckTimestampDecoder<'a> {
    type Item = PacketTimestamp;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.data.has_remaining() {
            debug_assert!(
                self.deltas_remaining == 0,
                "timestamp delta remaining should be 0"
            );
            return None;
        }
        if self.deltas_remaining == 0 {
            let gap = self.data.get_var().unwrap();
            self.deltas_remaining = self.data.get_var().unwrap() as usize;
            if self.first {
                self.next_pn -= gap;
            } else {
                self.next_pn -= gap + 2;
            }
        } else {
            self.next_pn -= 1;
        }

        let delta = self.data.get_var().unwrap();
        self.deltas_remaining -= 1;

        if self.first {
            self.timestamp_basis = delta << self.timestamp_exponent;
            self.first = false;
        } else {
            self.timestamp_basis -= delta << self.timestamp_exponent;
        }

        Some(PacketTimestamp {
            packet_number: self.next_pn,
            timestamp: self.timestamp_instant_basis + Duration::from_micros(self.timestamp_basis),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn timestamp_iter() {
        let mut timestamps = ReceiverTimestamps::new(100);
        let second = Duration::from_secs(1);
        let t0 = Instant::now();
        timestamps.add(1, t0 + second);
        timestamps.add(2, t0 + second * 2);
        timestamps.add(3, t0 + second * 3);
        let mut buf = bytes::BytesMut::new();

        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, 0, 10);

        // Manually decode and assert the values in the buffer.
        assert_eq!(1, buf.get_var().unwrap()); // timestamp_range_count
        assert_eq!(9, buf.get_var().unwrap()); // gap: 12-3
        assert_eq!(3, buf.get_var().unwrap()); // timestamp delta count
        assert_eq!(3_000_000, buf.get_var().unwrap()); // timestamp delta: 3_000_000 μs = 3 seconds = diff between largest timestamp and basis
        assert_eq!(1_000_000, buf.get_var().unwrap()); // timestamp delta: 1 second diff
        assert_eq!(1_000_000, buf.get_var().unwrap()); // timestamp delta: 1 second diff
        assert!(buf.get_var().is_err());
    }

    #[test]
    fn timestamp_iter_with_gaps() {
        let mut timestamps = ReceiverTimestamps::new(100);
        let one_second = Duration::from_secs(1);
        let t0 = Instant::now();
        vec![(1..=3), (5..=5), (10..=12)]
            .into_iter()
            .flatten()
            .for_each(|i| timestamps.add(i, t0 + one_second * i as u32));

        let mut buf = bytes::BytesMut::new();

        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, 0, 10);
        // Manually decode and assert the values in the buffer.
        assert_eq!(3, buf.get_var().unwrap()); // timestamp_range_count
                                               //
        assert_eq!(0, buf.get_var().unwrap()); // gap: 12 - 12 = 0
        assert_eq!(3, buf.get_var().unwrap()); // timestamp_delta_count
        assert_eq!(12_000_000, buf.get_var().unwrap()); // delta: 3_000_000 μs = 3 seconds = diff between largest timestamp and basis
        assert_eq!(1_000_000, buf.get_var().unwrap()); //  delta: 1 second diff
        assert_eq!(1_000_000, buf.get_var().unwrap()); // delta: 1 second diff
                                                       //
        assert_eq!(3, buf.get_var().unwrap()); // gap: 10 - 2 - 5 = 3
        assert_eq!(1, buf.get_var().unwrap()); // timestamp_delta_count
        assert_eq!(5_000_000, buf.get_var().unwrap()); //  delta: 1 second diff

        assert_eq!(0, buf.get_var().unwrap()); // gap
        assert_eq!(3, buf.get_var().unwrap()); // timestamp_delta_count
        assert_eq!(2_000_000, buf.get_var().unwrap()); // delta: 2 second diff
        assert_eq!(1_000_000, buf.get_var().unwrap()); // delta: 1 second diff
        assert_eq!(1_000_000, buf.get_var().unwrap()); // delta: 1 second diff

        // end
        assert!(buf.get_var().is_err());
    }

    #[test]
    fn timestamp_iter_with_exponent() {
        let mut timestamps = ReceiverTimestamps::new(100);
        let millisecond = Duration::from_millis(1);
        let t0 = Instant::now();
        timestamps.add(1, t0 + millisecond * 200);
        timestamps.add(2, t0 + millisecond * 300);
        let mut buf = bytes::BytesMut::new();

        let exponent = 2;
        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, exponent, 10);

        // values below are tested in another unit test
        buf.get_var().unwrap(); // timestamp_range_count
        buf.get_var().unwrap(); // gap
        buf.get_var().unwrap(); // timestamp_delta_count
        assert_eq!(300_000 >> exponent, buf.get_var().unwrap()); // 300ms diff
        assert_eq!(100_000 >> exponent, buf.get_var().unwrap()); // 100ms diff
        assert!(buf.get_var().is_err());
    }

    #[test]
    fn timestamp_encode_decode() {
        let mut timestamps = ReceiverTimestamps::new(100);
        let one_second = Duration::from_secs(1);
        let t0 = Instant::now();
        timestamps.add(1, t0 + one_second);
        timestamps.add(2, t0 + one_second * 2);
        timestamps.add(3, t0 + one_second * 3);

        let mut buf = bytes::BytesMut::new();

        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, 0, 10);

        let decoder = AckTimestampDecoder::new(12, t0, 0, &buf);

        let got: Vec<_> = decoder.collect();
        // [(3, _), (2, _), (1, _)]
        assert_eq!(3, got.len());
        assert_eq!(3, got[0].packet_number);
        assert_eq!(t0 + (3 * one_second), got[0].timestamp,);

        assert_eq!(2, got[1].packet_number);
        assert_eq!(t0 + (2 * one_second), got[1].timestamp,);

        assert_eq!(1, got[2].packet_number);
        assert_eq!(t0 + (1 * one_second), got[2].timestamp);
    }

    #[test]
    fn timestamp_encode_decode_with_gaps() {
        let mut timestamps = ReceiverTimestamps::new(100);
        let one_second = Duration::from_secs(1);
        let t0 = Instant::now();
        let expect: Vec<_> = vec![(1..=3), (5..=5), (10..=12)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|i| {
                let t = t0 + one_second * i as u32;
                timestamps.add(i, t);
                PacketTimestamp {
                    packet_number: i,
                    timestamp: t,
                }
            })
            .collect();

        let mut buf = bytes::BytesMut::new();

        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, 0, 10);

        let decoder = AckTimestampDecoder::new(12, t0, 0, &buf);
        let got: Vec<_> = decoder.collect();

        assert_eq!(7, got.len());
        assert_eq!(expect, got.into_iter().rev().collect::<Vec<_>>());
    }

    #[test]
    fn timestamp_encode_max_ack() {
        // fix this
        let mut timestamps = ReceiverTimestamps::new(2);
        let one_second = Duration::from_secs(1);
        let t0 = Instant::now();
        let expect: Vec<_> = vec![(1..=3), (5..=5), (10..=12)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|i| {
                let t = t0 + one_second * i as u32;
                timestamps.add(i, t);
                PacketTimestamp {
                    packet_number: i,
                    timestamp: t,
                }
            })
            .collect();

        let mut buf = bytes::BytesMut::new();

        AckTimestampFrame::encode_timestamps(&timestamps, 12, &mut buf, t0, 0, 2);
        let decoder = AckTimestampDecoder::new(12, t0, 0, &buf);
        let got: Vec<_> = decoder.collect();

        assert_eq!(2, got.len());
        assert_eq!(
            expect[expect.len() - 2..expect.len()], // the last 2 values
            got.into_iter().rev().collect::<Vec<_>>()
        );
    }
}
