use std::collections::VecDeque;
use std::time::Instant;

use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PacketTimestamp {
    pub packet_number: u64,
    pub timestamp: Instant,
}

impl Default for PacketTimestamp {
    fn default() -> Self {
        PacketTimestamp {
            packet_number: 0,
            timestamp: Instant::now(),
        }
    }
}

pub(crate) struct ReceiverTimestamps {
    data: VecDeque<PacketTimestamp>,
    max: usize,
}

impl std::fmt::Debug for ReceiverTimestamps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_list();
        let mut last: Option<(u64, Instant)> = None;
        for curr in self.data.iter() {
            if let Some(last) = last.take() {
                let s = format!(
                    "{}..{} diff_micros: {}",
                    last.0,
                    curr.packet_number,
                    curr.timestamp.duration_since(last.1).as_micros(),
                );
                l.entry(&s);
            }
            let _ = last.insert((curr.packet_number, curr.timestamp));
        }
        l.finish()
    }
}

impl ReceiverTimestamps {
    pub(crate) fn new(max: usize) -> Self {
        ReceiverTimestamps {
            data: VecDeque::with_capacity(max),
            max,
        }
    }

    pub(crate) fn add(&mut self, packet_number: u64, timestamp: Instant) {
        if self.data.len() == self.max {
            self.data.pop_front();
        }
        if let Some(v) = self.data.back() {
            if packet_number <= v.packet_number {
                warn!("out of order packets are not supported");
                return;
            }
        }
        self.data.push_back(PacketTimestamp {
            packet_number,
            timestamp,
        });
    }

    fn clear(&mut self) {
        self.data.clear()
    }

    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = PacketTimestamp> + '_ {
        self.data.iter().cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn inner(&self) -> &VecDeque<PacketTimestamp> {
        &self.data
    }

    pub(crate) fn subtract_below(&mut self, packet_number: u64) {
        if self.data.is_empty() {
            return;
        }
        let idx = self
            .data
            .partition_point(|v| v.packet_number < packet_number);
        if idx == self.data.len() {
            self.clear();
        } else {
            let _ = self.data.drain(0..=idx);
        }
    }
}

#[cfg(test)]
mod receiver_timestamp_tests {
    use super::*;

    #[test]
    fn subtract_below() {
        let mut ts = ReceiverTimestamps::new(10);
        let _ = ts.add(1, Instant::now());
        let _ = ts.add(2, Instant::now());
        let _ = ts.add(3, Instant::now());
        let _ = ts.add(4, Instant::now());
        ts.subtract_below(3);
        assert_eq!(1, ts.len());
    }

    #[test]
    fn subtract_below_everything() {
        let mut ts = ReceiverTimestamps::new(10);
        let _ = ts.add(5, Instant::now());
        ts.subtract_below(10);
        assert_eq!(0, ts.len());
    }

    #[test]
    fn receiver_timestamp_max() {
        let mut ts = ReceiverTimestamps::new(2);
        let _ = ts.add(1, Instant::now());
        let _ = ts.add(2, Instant::now());
        let _ = ts.add(3, Instant::now());
        let _ = ts.add(4, Instant::now());
        assert_eq!(2, ts.len());
        assert_eq!(3, ts.data.front().unwrap().packet_number);
        assert_eq!(4, ts.data.back().unwrap().packet_number);
    }
}
