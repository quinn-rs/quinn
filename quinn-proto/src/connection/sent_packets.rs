use std::collections::VecDeque;
use std::ops::{Bound, RangeBounds};

use super::spaces::SentPacket;

/// A sparse map from packet number to [`SentPacket`], backed by a ring buffer.
///
/// Indexed by `packet number - offset`, giving O(1) insert and lookup without
/// the per-entry allocation of the `BTreeMap` it replaces (#2720).
#[derive(Default)]
pub(super) struct SentPackets {
    /// Packet number of `slots.front()` when non-empty.
    offset: u64,
    /// `slots[i]` holds packet number `offset + i`, or `None` if removed or skipped.
    slots: VecDeque<Option<SentPacket>>,
}

impl SentPackets {
    /// Insert `value` at `pn`, which must exceed every previously inserted packet number.
    pub(super) fn insert(&mut self, pn: u64, value: SentPacket) {
        if self.slots.is_empty() {
            self.offset = pn;
        } else {
            debug_assert!(
                pn >= self.offset + self.slots.len() as u64,
                "packet numbers must be inserted in increasing order"
            );
        }
        let index = (pn - self.offset) as usize;
        // Pad skipped packet numbers.
        self.slots.resize(index, None);
        self.slots.push_back(Some(value));
    }

    /// Remove and return the entry for `pn`.
    pub(super) fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        let index = usize::try_from(pn.checked_sub(self.offset)?).ok()?;
        let value = self.slots.get_mut(index)?.take()?;
        // Reclaim leading vacant slots so the buffer tracks the live window.
        while let Some(None) = self.slots.front() {
            self.slots.pop_front();
            self.offset += 1;
        }
        Some(value)
    }

    /// Return the entry for `pn`.
    pub(super) fn get(&self, pn: u64) -> Option<&SentPacket> {
        let index = usize::try_from(pn.checked_sub(self.offset)?).ok()?;
        self.slots.get(index)?.as_ref()
    }

    /// Iterate present entries in `range`, in increasing packet-number order.
    pub(super) fn range(
        &self,
        range: impl RangeBounds<u64>,
    ) -> impl Iterator<Item = (u64, &SentPacket)> + '_ {
        let end = self.offset + self.slots.len() as u64;
        let lo = Ord::max(
            match range.start_bound() {
                Bound::Included(&n) => n,
                Bound::Excluded(&n) => n.saturating_add(1),
                Bound::Unbounded => self.offset,
            },
            self.offset,
        );
        let hi = Ord::min(
            match range.end_bound() {
                Bound::Included(&n) => n.saturating_add(1),
                Bound::Excluded(&n) => n,
                Bound::Unbounded => end,
            },
            end,
        );
        let start = (lo - self.offset) as usize;
        let stop = Ord::max(hi.saturating_sub(self.offset) as usize, start);
        (start..stop)
            .filter_map(move |i| self.slots[i].as_ref().map(|v| (self.offset + i as u64, v)))
    }

    /// Iterate present entries in increasing packet-number order.
    pub(super) fn values(&self) -> impl Iterator<Item = &SentPacket> + '_ {
        self.slots.iter().filter_map(Option::as_ref)
    }

    /// Mutably iterate present entries in increasing packet-number order.
    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut SentPacket> + '_ {
        self.slots.iter_mut().filter_map(Option::as_mut)
    }

    /// Consume the map, yielding present entries in increasing packet-number order.
    pub(super) fn into_values(self) -> impl Iterator<Item = SentPacket> {
        self.slots.into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instant;

    #[test]
    fn insert_get_and_order() {
        let mut m = SentPackets::default();
        for pn in 3..=6 {
            m.insert(pn, packet(pn as u16 * 10));
        }
        assert_eq!(m.get(3).map(|p| p.size), Some(30));
        assert_eq!(m.get(6).map(|p| p.size), Some(60));
        assert!(m.get(2).is_none());
        assert!(m.get(7).is_none());
        assert_eq!(m.get(5).map(|p| p.size), Some(50));
        assert_eq!(
            m.values().map(|p| p.size).collect::<Vec<_>>(),
            vec![30, 40, 50, 60]
        );
    }

    #[test]
    fn skipped_numbers_leave_gaps() {
        let mut m = SentPackets::default();
        m.insert(0, packet(0));
        m.insert(1, packet(1));
        m.insert(4, packet(4)); // 2 and 3 skipped
        assert!(m.get(2).is_none());
        assert!(m.get(3).is_none());
        assert_eq!(m.get(4).map(|p| p.size), Some(4));
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (4, 4)]);
    }

    #[test]
    fn remove_middle_leaves_hole_front_unchanged() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert!(m.remove(2).is_none());
        assert!(m.get(2).is_none());
        // Front intact: offset unchanged, iteration skips the hole.
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (3, 3), (4, 4)]);
    }

    #[test]
    fn remove_front_reclaims_leading_holes() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }
        // Removing the front also reclaims the already-vacated 1 and 2.
        assert_eq!(m.remove(1).map(|p| p.size), Some(1));
        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert_eq!(m.remove(0).map(|p| p.size), Some(0));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4)]);
        // A later insert still lands at the right packet number.
        m.insert(9, packet(9));
        assert_eq!(m.get(9).map(|p| p.size), Some(9));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4), (9, 9)]);
    }

    #[test]
    fn range_bounds() {
        let mut m = SentPackets::default();
        for pn in 10..20 {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(range_of(&m, 12..15), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(range_of(&m, 12..=14), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(
            range_of(&m, (Bound::Excluded(17), Bound::Unbounded)),
            vec![(18, 18), (19, 19)]
        );
        // "First entry after x", as used by `sent()`.
        assert_eq!(
            m.range((Bound::Excluded(15), Bound::Unbounded))
                .next()
                .map(|(pn, p)| (pn, p.size)),
            Some((16, 16))
        );
        // Out-of-window ranges are empty, not a panic.
        assert_eq!(range_of(&m, 0..5), vec![]);
        assert_eq!(range_of(&m, 100..200), vec![]);
    }

    #[test]
    fn values_mut_and_into_values() {
        let mut m = SentPackets::default();
        for pn in 0..4 {
            m.insert(pn, packet(pn as u16));
        }
        m.remove(1);
        for v in m.values_mut() {
            v.size += 100;
        }
        assert_eq!(m.get(0).map(|p| p.size), Some(100));
        assert_eq!(m.get(2).map(|p| p.size), Some(102));
        assert_eq!(
            m.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![100, 102, 103]
        );
    }

    #[test]
    fn take_resets() {
        let mut m = SentPackets::default();
        for pn in 5..8 {
            m.insert(pn, packet(pn as u16));
        }
        let taken = std::mem::take(&mut m);
        assert_eq!(
            taken.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(range_of(&m, ..), vec![]);
        // Reusable after take.
        m.insert(100, packet(100));
        assert_eq!(m.get(100).map(|p| p.size), Some(100));
    }

    /// A `SentPacket` identified by its `size`.
    fn packet(size: u16) -> SentPacket {
        SentPacket {
            path_generation: 0,
            time_sent: Instant::now(),
            size,
            ack_eliciting: false,
            largest_acked: None,
            retransmits: Default::default(),
            stream_frames: Default::default(),
        }
    }

    /// `(pn, size)` pairs from `range`.
    fn range_of<R: RangeBounds<u64>>(m: &SentPackets, r: R) -> Vec<(u64, u16)> {
        m.range(r).map(|(pn, v)| (pn, v.size)).collect()
    }
}
